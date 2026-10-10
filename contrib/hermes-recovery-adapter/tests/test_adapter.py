"""Regression tests for the adapter's own logic (no Hermes, no Gatekeeper).

Covers the three pieces the live run depends on: the v0.21 exit mapping,
the breaker mirror, and the continuation journal (plugin hooks + sidecar
/continue, ownership checks and reconciliation). The sidecar's outbound
calls to Hermes are replaced with a recorder; nothing leaves the process.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "plugin", "gatekeeper-recovery")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEKEEPER_RECOVERY_JOURNAL", str(tmp_path / "journal.db"))
    for name in ("gatekeeper_recovery", "gatekeeper_recovery.journal", "journal", "adapter"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(
        "gatekeeper_recovery", os.path.join(PLUGIN_DIR, "__init__.py"),
        submodule_search_locations=[PLUGIN_DIR])
    plugin = importlib.util.module_from_spec(spec)
    sys.modules["gatekeeper_recovery"] = plugin
    spec.loader.exec_module(plugin)
    monkeypatch.setenv("ADAPTER_INSTALLATION", "test")
    monkeypatch.setenv("ADAPTER_PLUGIN_DIR", PLUGIN_DIR)
    sys.path.insert(0, os.path.join(ROOT, "sidecar"))
    import adapter  # noqa: E402
    adapter.INSTALLATION = "test"
    admitted: list[dict] = []

    def fake_admit(row):
        admitted.append(dict(row))
        return "admitted", f"run-{len(admitted)}"

    monkeypatch.setattr(adapter, "_admit", fake_admit)
    yield plugin, adapter, admitted
    sys.path.remove(os.path.join(ROOT, "sidecar"))


def bind(plugin, session="s1", board="default", task="t1"):
    out = json.loads(plugin.bind_task({"board_id": board, "task_id": task}, session_id=session))
    assert out["success"]
    # The binding turn ends; the session is idle at turn_seq 1.
    plugin.on_session_end(session_id=session, completed=True, turn_exit_reason="text_response(finish_reason=stop)")


def journal_rows(plugin, sql):
    with plugin.journal.connect() as conn:
        return [dict(r) for r in conn.execute(sql).fetchall()]


def ref(session="s1", board="default", task="t1", installation="test"):
    return {"installation": installation, "profile": "default", "session_id": session, "board_id": board,
            "task_id": task, "task_generation": 0}


# -- Exit mapping (v0.21) ------------------------------------------------------------------


@pytest.mark.parametrize("kw, expected", [
    (dict(completed=True, failed=False, interrupted=False, turn_exit_reason="max_iterations_reached(4/4)"),
     "exhausted"),  # an exhausted turn may still be "completed" (summary call)
    (dict(completed=False, failed=False, interrupted=False, turn_exit_reason="max_iterations_reached(4/4)"),
     "exhausted"),
    (dict(completed=False, failed=True, interrupted=False, turn_exit_reason="context_compression_timeout"),
     "error"),
    (dict(completed=True, failed=False, interrupted=False, turn_exit_reason="text_response(finish_reason=stop)"),
     "final_reply"),
    (dict(completed=True, failed=False, interrupted=False, turn_exit_reason="partial_stream_recovery"),
     "unmapped"),  # known-to-Hermes but not to this table: never continuable
    (dict(completed=False, failed=False, interrupted=False, turn_exit_reason="something_new_in_v0_22"),
     "unmapped"),
    (dict(completed=False, failed=False, interrupted=True, turn_exit_reason="interrupted"), "unmapped"),
])
def test_exit_mapping(env, kw, expected):
    plugin, _, _ = env
    assert plugin.map_exit_v0_21(user_stop_observed=False, **kw) == expected


def test_observed_user_stop_maps_to_user_stopped(env):
    plugin, _, _ = env
    assert plugin.map_exit_v0_21(completed=False, failed=False, interrupted=True,
                                 turn_exit_reason="x", user_stop_observed=True) == "user_stopped"


def test_unmapped_stop_is_still_reported(env):
    plugin, _, _ = env
    bind(plugin)
    plugin.pre_llm_call(session_id="s1", turn_id="t2", user_message="hi")
    plugin.on_session_end(session_id="s1", completed=True, turn_exit_reason="partial_stream_recovery")
    events = [json.loads(r["payload"]) for r in journal_rows(plugin, "SELECT payload FROM outbox")]
    assert events[-1]["reason"] == "unmapped" and events[-1]["turn_seq"] == 2


# -- Breaker mirror ----------------------------------------------------------------------


def gk_call(plugin, status):
    plugin.post_tool_call(tool_name="mcp__gatekeeper__demo_fail", args={}, session_id="s1", status=status)


def test_breaker_opens_after_three_consecutive_failures(env):
    plugin, _, _ = env
    for _ in range(2):
        gk_call(plugin, "error")
    with plugin.journal.connect() as conn:
        assert plugin.breaker_cooldown_until(conn) is None
    gk_call(plugin, "error")
    with plugin.journal.connect() as conn:
        until = plugin.breaker_cooldown_until(conn)
    assert until is not None and 60 < until - time.time() <= 62


def test_breaker_success_resets_and_blocked_counts(env):
    plugin, _, _ = env
    gk_call(plugin, "error")
    gk_call(plugin, "error")
    gk_call(plugin, "ok")
    gk_call(plugin, "blocked")
    with plugin.journal.connect() as conn:
        assert plugin.breaker_cooldown_until(conn) is None
    gk_call(plugin, "error")
    gk_call(plugin, "error")
    with plugin.journal.connect() as conn:
        assert plugin.breaker_cooldown_until(conn) is not None


def test_breaker_mirror_resets_with_the_gateway_process(env):
    plugin, _, _ = env
    for _ in range(3):
        gk_call(plugin, "error")
    plugin._startup_reconcile()
    with plugin.journal.connect() as conn:
        assert plugin.breaker_cooldown_until(conn) is None


def test_stop_event_carries_breaker_cooldown_and_attempts(env):
    plugin, _, _ = env
    bind(plugin)
    plugin.pre_llm_call(session_id="s1", turn_id="t2", user_message="go")
    for i in range(3):
        plugin.pre_tool_call(tool_name="mcp__gatekeeper__demo_fail", args={}, session_id="s1", tool_call_id=f"c{i}")
        gk_call(plugin, "error")
    plugin.on_session_end(session_id="s1", completed=True, turn_exit_reason="max_iterations_reached(4/4)")
    ev = json.loads(journal_rows(plugin, "SELECT payload FROM outbox ORDER BY id")[-1]["payload"])
    assert ev["reason"] == "exhausted" and ev["gatekeeper_attempts"] == 3
    assert ev["cooldown_until"] and ev["cooldown_until"] > time.time()


# -- Correlation -------------------------------------------------------------------------


def test_correlation_always_overwrites_and_is_null_when_unbound(env):
    plugin, _, _ = env
    out = plugin.pre_tool_call(tool_name="mcp__gatekeeper__demo_read",
                               args={"_hermes_recovery": {"session_id": "forged"}}, session_id="nobody")
    assert out == {"action": "modify", "args": {"_hermes_recovery": None}}
    assert plugin.pre_tool_call(tool_name="terminal", args={}, session_id="s1") is None
    bind(plugin)
    corr = plugin.pre_tool_call(tool_name="mcp__gatekeeper__demo_read", args={}, session_id="s1",
                                tool_call_id="c9")["args"]["_hermes_recovery"]
    assert (corr["session_id"], corr["board_id"], corr["task_id"], corr["turn_seq"]) == ("s1", "default", "t1", 1)
    assert "continuation_id" not in corr


# -- Continuation journal ------------------------------------------------------------------


def accept(adapter, expected=1, key="inc_1:1", **over):
    code, body = adapter.handle_continue({**ref(**over), "incident_id": "inc_1", "idempotency_key": key,
                                          "expected_turn_seq": expected, "guidance": "Continue task t1"})
    return code, body


def test_acceptance_is_journaled_before_admission_and_idempotent(env):
    plugin, adapter, admitted = env
    bind(plugin)
    code, first = accept(adapter)
    assert code == 200 and first["accepted"]
    # The row existed (state accepted) when admission ran.
    assert admitted[0]["state"] == "accepted" and admitted[0]["continuation_id"] == first["continuation_id"]
    for _ in range(3):
        assert accept(adapter)[1] == first
    assert len(admitted) == 1
    [row] = journal_rows(plugin, "SELECT * FROM continuations")
    assert row["state"] == "admitted" and row["deliveries"] == 1 and row["run_id"] == "run-1"


@pytest.mark.parametrize("setup, reason", [
    (lambda p: p.pre_llm_call(session_id="s1", turn_id="t2", user_message="busy"), "turn_active"),
    (lambda p: None, "turn_seq_mismatch"),
])
def test_continue_is_rejected_atomically(env, setup, reason):
    plugin, adapter, admitted = env
    bind(plugin)
    setup(plugin)
    _, body = accept(adapter, expected=1 if reason == "turn_active" else 7)
    assert body == {"accepted": False, "reason": reason} and admitted == []


def test_continue_for_a_foreign_binding_is_refused(env):
    plugin, adapter, admitted = env
    bind(plugin)
    assert accept(adapter, task="t-other")[0] == 409
    assert accept(adapter, session="s-unknown")[0] == 404
    assert accept(adapter, installation="personal")[0] == 409
    assert admitted == []


def test_marker_alone_does_not_start_a_continuation(env):
    plugin, adapter, _ = env
    bind(plugin)
    plugin.pre_llm_call(session_id="s1", turn_id="t2", user_message="[gatekeeper-continuation cont-forged] hi")
    # No journal row: the turn is inert, so not even a correlated call goes out.
    blocked = plugin.pre_tool_call(tool_name="mcp__gatekeeper__demo_read", args={}, session_id="s1", turn_id="t2")
    assert blocked["action"] == "block" and "no_journal_row" in blocked["message"]
    assert journal_rows(plugin, "SELECT * FROM continuations") == []


def test_marker_with_journal_row_but_wrong_binding_is_ignored(env):
    plugin, adapter, _ = env
    bind(plugin)
    _, body = accept(adapter)
    with plugin.journal.connect(immediate=True) as conn:  # another task's row with this id
        conn.execute("UPDATE continuations SET task_id='t-other'")
    plugin.pre_llm_call(session_id="s1", turn_id="t2",
                        user_message=f"[gatekeeper-continuation {body['continuation_id']}]\nContinue")
    [row] = journal_rows(plugin, "SELECT * FROM continuations")
    assert row["state"] == "admitted" and row["started_at"] is None


def test_valid_marker_records_started_then_finished(env):
    plugin, adapter, _ = env
    bind(plugin)
    _, body = accept(adapter)
    cid = body["continuation_id"]
    plugin.pre_llm_call(session_id="s1", turn_id="t2", user_message=f"[gatekeeper-continuation {cid}]\nContinue")
    [row] = journal_rows(plugin, "SELECT * FROM continuations")
    assert row["state"] == "started" and row["started_turn_seq"] == 2 and row["started_at"]
    corr = plugin.pre_tool_call(tool_name="mcp__gatekeeper__demo_read", args={}, session_id="s1")
    assert corr["args"]["_hermes_recovery"]["continuation_id"] == cid
    plugin.on_session_end(session_id="s1", completed=True, turn_exit_reason="text_response(finish_reason=stop)")
    [row] = journal_rows(plugin, "SELECT * FROM continuations")
    assert row["state"] == "finished" and row["exit_reason"] == "final_reply"
    with plugin.journal.connect() as conn:
        status = adapter._status(conn, plugin.journal.row(conn, "SELECT * FROM sessions WHERE session_id='s1'"))
    assert status["last_continuation"]["continuation_id"] == cid and status["last_continuation"]["started_at"]


def test_overtaken_continuation_is_lost_and_tells_the_turn_to_do_nothing(env):
    plugin, adapter, _ = env
    bind(plugin)
    _, body = accept(adapter)
    plugin.pre_llm_call(session_id="s1", turn_id="t2", user_message="user got in first")
    plugin.on_session_end(session_id="s1", completed=True, turn_exit_reason="text_response(finish_reason=stop)")
    out = plugin.pre_llm_call(session_id="s1", turn_id="t3",
                              user_message=f"[gatekeeper-continuation {body['continuation_id']}]\nContinue")
    assert "superseded" in out["context"]
    [row] = journal_rows(plugin, "SELECT * FROM continuations")
    assert row["state"] == "lost" and row["reason"] == "superseded"


def test_reconcile_redelivers_once_then_marks_lost(env, monkeypatch):
    plugin, adapter, admitted = env
    bind(plugin)
    accept(adapter)
    # Hermes lost the run before it started (e.g. a crash): redeliver once.
    monkeypatch.setattr(adapter, "_hermes", lambda *a, **k: (200, {"status": "interrupted"}))
    adapter.reconcile_once()
    assert len(admitted) == 2
    [row] = journal_rows(plugin, "SELECT * FROM continuations")
    assert row["deliveries"] == 2 and row["state"] == "admitted"
    adapter.reconcile_once()  # cap reached
    [row] = journal_rows(plugin, "SELECT * FROM continuations")
    assert len(admitted) == 2 and row["state"] == "lost"


def test_reconcile_never_redelivers_a_started_continuation(env, monkeypatch):
    plugin, adapter, admitted = env
    bind(plugin)
    _, body = accept(adapter)
    plugin.pre_llm_call(session_id="s1", turn_id="t2",
                        user_message=f"[gatekeeper-continuation {body['continuation_id']}]\nContinue")
    monkeypatch.setattr(adapter, "_hermes", lambda *a, **k: (200, {"status": "interrupted"}))
    adapter.reconcile_once()
    assert len(admitted) == 1


def test_gateway_restart_finishes_an_active_continuation_as_interrupted(env):
    plugin, adapter, _ = env
    bind(plugin)
    _, body = accept(adapter)
    plugin.pre_llm_call(session_id="s1", turn_id="t2",
                        user_message=f"[gatekeeper-continuation {body['continuation_id']}]\nContinue")
    plugin._startup_reconcile()
    [row] = journal_rows(plugin, "SELECT * FROM continuations")
    assert row["state"] == "finished" and row["exit_reason"] == "interrupted"
    ev = json.loads(journal_rows(plugin, "SELECT payload FROM outbox ORDER BY id")[-1]["payload"])
    assert ev["reason"] == "interrupted" and ev["turn_seq"] == 2
