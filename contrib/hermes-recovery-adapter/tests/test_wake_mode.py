"""Wake mode: continuation delivered as an ordinary queued message through
`ctx.inject_message(session_key=...)` (no Hermes, no Gatekeeper).

These prove the adapter's own mechanics only: what it injects, when, how
often, and that every turn it cannot match to a live continuation is inert
(all tools blocked, reply replaced). Gateway routing to the Telegram chat and
the gateway's serialization are Hermes behavior and need the live test.
"""

from __future__ import annotations

import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_adapter import env, journal_rows, ref  # noqa: E402,F401  (env is the shared fixture)

SESSION_KEY = "agent:main:telegram:dm:4711"
ROUTE = {"session_key": SESSION_KEY, "origin_platform": "telegram", "origin_chat_id": "4711",
         "origin_thread_id": ""}
EXHAUSTED = "max_iterations_reached(90/90)"


class FakeCtx:
    plugin_id = "gatekeeper-recovery"

    def __init__(self):
        self.injected: list[tuple[str, str]] = []
        self.result: object = True

    def inject_message(self, content, role="user", *, session_key=None, origin=None):
        if isinstance(self.result, Exception):
            raise self.result
        self.injected.append((session_key, content))
        return self.result


@pytest.fixture
def wake(env, monkeypatch):
    plugin, adapter, admitted = env
    monkeypatch.setattr(adapter, "DELIVERY", "wake")
    monkeypatch.setattr(plugin, "_gateway_route", lambda: dict(ROUTE))
    with plugin._inert_lock:
        plugin._inert.clear()
    plugin._user_stops.clear()
    return plugin, adapter, admitted, FakeCtx()


def exhausted_turn(plugin, session="s1", turn="t1"):
    """Bind in a gateway turn (route captured), then that turn exhausts."""
    plugin.pre_llm_call(session_id=session, turn_id=turn, user_message="Auftrag")
    out = json.loads(plugin.bind_task({"board_id": "default", "task_id": "t1"}, session_id=session))
    assert out["success"]
    plugin.on_session_end(session_id=session, turn_id=turn, completed=False, turn_exit_reason=EXHAUSTED)


def continue_(adapter, key="inc_1:1", seq=1):
    return adapter.handle_continue({**ref(), "idempotency_key": key, "incident_id": key.split(":")[0],
                                    "expected_turn_seq": seq, "guidance": "check_status_first"})


def start_wake_turn(plugin, ctx, turn="t-wake", index=-1):
    _, text = ctx.injected[index]
    return plugin.pre_llm_call(session_id="s1", turn_id=turn, user_message=text)


def row(plugin):
    [r] = journal_rows(plugin, "SELECT * FROM continuations")
    return r


# -- 1/2: exhausted turn -> one wake into the session's own gateway route -----------------

def test_exhausted_turn_is_woken_once_in_its_own_session(wake):
    plugin, adapter, admitted, ctx = wake
    exhausted_turn(plugin)
    code, body = continue_(adapter)
    assert code == 200 and body["accepted"] and admitted == []  # no Runs API call
    plugin.wake_once(ctx)
    plugin.wake_once(ctx)
    assert len(ctx.injected) == 1
    key, text = ctx.injected[0]
    assert key == SESSION_KEY
    assert f"[gatekeeper-continuation {body['continuation_id']}]" in text and "check_status_first" in text
    assert row(plugin)["state"] == "injected"
    assert start_wake_turn(plugin, ctx) is None
    assert row(plugin)["state"] == "started"
    corr = plugin.pre_tool_call(tool_name="mcp__gatekeeper__demo_read", args={}, session_id="s1",
                                turn_id="t-wake")
    assert corr["action"] == "modify"
    assert corr["args"]["_hermes_recovery"]["continuation_id"] == body["continuation_id"]
    assert plugin.transform_llm_output(response_text="ok", session_id="s1", turn_id="t-wake") is None


def test_continuation_view_reports_pending_wake_as_accepted(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    plugin.wake_once(ctx)
    view = adapter._continuation_view(row(plugin))
    assert view["state"] == "accepted" and view["delivery_state"] == "injected"


def test_session_without_gateway_route_is_not_woken(wake, monkeypatch):
    plugin, adapter, _, ctx = wake
    monkeypatch.setattr(plugin, "_gateway_route", lambda: None)  # API/CLI session
    exhausted_turn(plugin)
    assert continue_(adapter)[1] == {"accepted": False, "reason": "no_gateway_route"}
    plugin.wake_once(ctx)
    assert ctx.injected == []


# -- 3: competing user message -------------------------------------------------------------

def test_no_injection_while_a_turn_is_active(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    plugin.pre_llm_call(session_id="s1", turn_id="t-user", user_message="neue Nachricht")
    plugin.wake_once(ctx)
    assert ctx.injected == []
    plugin.on_session_end(session_id="s1", turn_id="t-user", completed=True,
                          turn_exit_reason="text_response(finish_reason=stop)")
    plugin.wake_once(ctx)
    assert ctx.injected == [] and row(plugin)["reason"] == "superseded"


def test_user_turn_between_injection_and_wake_makes_the_wake_inert(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    plugin.wake_once(ctx)
    # The user's message wins the gateway's session guard; the wake queues behind it.
    plugin.pre_llm_call(session_id="s1", turn_id="t-user", user_message="mach was anderes")
    plugin.on_session_end(session_id="s1", turn_id="t-user", completed=True,
                          turn_exit_reason="text_response(finish_reason=stop)")
    out = start_wake_turn(plugin, ctx)
    assert "superseded" in out["context"]
    for tool in ("mcp__gatekeeper__demo_write", "terminal", "kanban_complete"):
        blocked = plugin.pre_tool_call(tool_name=tool, args={}, session_id="s1", turn_id="t-wake")
        assert blocked["action"] == "block"
    reply = plugin.transform_llm_output(response_text="ich mache weiter", session_id="s1", turn_id="t-wake")
    assert "verworfen (superseded)" in reply
    assert row(plugin)["state"] == "lost" and row(plugin)["reason"] == "superseded"
    # The next ordinary turn is not affected.
    plugin.pre_llm_call(session_id="s1", turn_id="t-next", user_message="weiter")
    assert plugin.pre_tool_call(tool_name="terminal", args={}, session_id="s1", turn_id="t-next") is None


# -- 4: explicit user stop -----------------------------------------------------------------

def test_stop_of_a_running_turn_cancels_a_queued_wake(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    plugin.wake_once(ctx)
    # Hermes keeps a queued internal wake across /stop (run_agent_cache.py);
    # the stop is recorded, so the promoted wake runs inert.
    plugin.agent_loop_stopped(session_key=SESSION_KEY, reason="stop")
    assert row(plugin)["state"] == "lost" and row(plugin)["reason"] == "user_stopped"
    out = start_wake_turn(plugin, ctx)
    assert "state_lost" in out["context"]
    assert plugin.pre_tool_call(tool_name="terminal", args={}, session_id="s1", turn_id="t-wake")["action"] == "block"


def test_idle_stop_prevents_injection_and_later_continue(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    event = types.SimpleNamespace(text="/stop", source=types.SimpleNamespace(
        platform=types.SimpleNamespace(value="telegram"), chat_id="4711", thread_id=None))
    assert plugin.pre_gateway_dispatch(event=event) is None  # observer only
    plugin.wake_once(ctx)
    assert ctx.injected == [] and row(plugin)["reason"] == "user_stopped"
    assert continue_(adapter, key="inc_2:1")[1] == {"accepted": False, "reason": "user_stopped"}


def test_stop_in_another_chat_does_not_cancel(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    event = types.SimpleNamespace(text="/stop", source=types.SimpleNamespace(
        platform=types.SimpleNamespace(value="telegram"), chat_id="999", thread_id=None))
    plugin.pre_gateway_dispatch(event=event)
    plugin.wake_once(ctx)
    assert len(ctx.injected) == 1


def test_ordinary_user_turn_after_stop_clears_it(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    plugin.agent_loop_stopped(session_key=SESSION_KEY)
    plugin.pre_llm_call(session_id="s1", turn_id="t2", user_message="neuer Auftrag")
    plugin.on_session_end(session_id="s1", turn_id="t2", completed=False, turn_exit_reason=EXHAUSTED)
    assert continue_(adapter, seq=2)[1]["accepted"]


def test_stop_of_the_wake_turn_maps_to_user_stopped(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    plugin.wake_once(ctx)
    start_wake_turn(plugin, ctx)
    plugin.agent_loop_stopped(session_key=SESSION_KEY)  # gateway key, no session id in it
    plugin.on_session_end(session_id="s1", turn_id="t-wake", interrupted=True, turn_exit_reason="interrupted")
    [event] = [json.loads(r["payload"]) for r in journal_rows(plugin, "SELECT * FROM outbox")
               if json.loads(r["payload"])["turn_seq"] == 2]
    assert event["reason"] == "user_stopped"


# -- 5: duplicates -------------------------------------------------------------------------

def test_duplicate_continue_and_passes_inject_once(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    bodies = [continue_(adapter)[1] for _ in range(3)]
    assert len({b["continuation_id"] for b in bodies}) == 1
    for _ in range(5):
        plugin.wake_once(ctx)
    assert len(ctx.injected) == 1 and row(plugin)["deliveries"] == 1


def test_second_incident_while_one_is_open_is_rejected(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    assert continue_(adapter)[1]["accepted"]
    assert continue_(adapter, key="inc_2:1")[1] == {"accepted": False, "reason": "superseded"}


def test_replayed_wake_text_is_inert(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    plugin.wake_once(ctx)
    start_wake_turn(plugin, ctx)
    plugin.on_session_end(session_id="s1", turn_id="t-wake", completed=True,
                          turn_exit_reason="text_response(finish_reason=stop)")
    out = start_wake_turn(plugin, ctx, turn="t-again")  # same text a second time
    assert "state_finished" in out["context"]
    assert plugin.pre_tool_call(tool_name="terminal", args={}, session_id="s1", turn_id="t-again")["action"] == "block"


# -- 6: unknown delivery outcome is never retried blindly -----------------------------------

def test_inject_exception_is_never_reinjected_and_times_out(wake, monkeypatch):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    ctx.result = RuntimeError("boom")
    plugin.wake_once(ctx)
    ctx.result = True
    plugin.wake_once(ctx)
    assert ctx.injected == [] and row(plugin)["state"] == "injecting"
    monkeypatch.setattr(plugin, "WAKE_START_GRACE", -1.0)
    plugin.wake_once(ctx)
    assert row(plugin)["state"] == "lost" and row(plugin)["reason"] == "not_started"
    assert ctx.injected == []


def test_late_start_after_timeout_is_inert(wake, monkeypatch):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    plugin.wake_once(ctx)
    monkeypatch.setattr(plugin, "WAKE_START_GRACE", -1.0)
    plugin.wake_once(ctx)
    assert row(plugin)["reason"] == "not_started"
    assert "state_lost" in start_wake_turn(plugin, ctx)["context"]


def test_inject_false_means_not_scheduled(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    ctx.result = False
    plugin.wake_once(ctx)
    assert row(plugin)["state"] == "lost" and row(plugin)["reason"] == "not_scheduled"
    plugin.wake_once(ctx)
    assert len(ctx.injected) == 1


def test_gateway_restart_drops_handed_over_wakes(wake):
    plugin, adapter, _, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    plugin.wake_once(ctx)
    plugin._startup_reconcile()
    assert row(plugin)["state"] == "lost" and row(plugin)["reason"] == "gateway_restart"
    plugin.wake_once(ctx)
    assert len(ctx.injected) == 1


def test_runs_mode_reconcile_ignores_wake_rows(wake, monkeypatch):
    plugin, adapter, admitted, ctx = wake
    exhausted_turn(plugin)
    continue_(adapter)
    adapter.reconcile_once()
    assert admitted == [] and row(plugin)["state"] == "accepted"
