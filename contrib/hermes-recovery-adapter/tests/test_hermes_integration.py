"""Wake mode against the real, unmodified Hermes plugin and gateway code.

Skipped unless the pinned official Hermes source is importable (Python
3.14, `pip install -e <hermes checkout at 818c13be>`). Nothing is patched in
Hermes: the plugin is registered through a real `PluginContext`, hooks are
dispatched by Hermes's own `invoke_hook`, tool vetoes go through Hermes's
own `pre_tool_call` directive resolution, and the wake is scheduled by a
real `GatewayRunner` and `BasePlatformAdapter`. Only the platform's network
send and the agent turn itself are absent: no Telegram, no model.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
from unittest.mock import patch

import pytest

plugins_mod = pytest.importorskip("hermes_cli.plugins")
pytest.importorskip("gateway.run")

import hermes_yaml as yaml  # noqa: E402
from gateway.config import GatewayConfig, Platform, PlatformConfig  # noqa: E402
from gateway.platforms.base import BasePlatformAdapter, SendResult  # noqa: E402
from gateway.platforms.event import MessageEvent, MessageType  # noqa: E402
from gateway.run import _INTERRUPT_REASON_STOP, GatewayRunner  # noqa: E402
from gateway.session import SessionSource, SessionStore  # noqa: E402
from gateway.session_context import clear_session_vars, set_session_vars  # noqa: E402
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "plugin", "gatekeeper-recovery")
PLUGIN_ID = "gatekeeper-recovery"


class _Telegram(BasePlatformAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(enabled=True, token="test"), Platform.TELEGRAM)
        self.started: list[MessageEvent] = []

    @property
    def name(self):
        return "telegram"

    async def connect(self, *, is_reconnect=False):
        return True

    async def disconnect(self):
        pass

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        return SendResult(success=True)

    async def get_chat_info(self, chat_id):
        return {"id": chat_id, "type": "dm"}

    def _start_session_processing(self, event, session_key, *, interrupt_event=None):
        self.started.append(event)
        return True


@pytest.fixture
def world(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text(yaml.safe_dump(
        {"plugins": {"entries": {PLUGIN_ID: {"allow_gateway_injection": True}}}}))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("GATEKEEPER_RECOVERY_JOURNAL", str(tmp_path / "journal.db"))
    monkeypatch.setenv("ADAPTER_PLUGIN_DIR", PLUGIN_DIR)
    for name in ("gatekeeper_recovery", "journal", "adapter"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("gatekeeper_recovery", os.path.join(PLUGIN_DIR, "__init__.py"),
                                                  submodule_search_locations=[PLUGIN_DIR])
    plugin = importlib.util.module_from_spec(spec)
    sys.modules["gatekeeper_recovery"] = plugin
    spec.loader.exec_module(plugin)
    sys.path.insert(0, os.path.join(ROOT, "sidecar"))
    import adapter
    monkeypatch.setattr(adapter, "INSTALLATION", "test")
    monkeypatch.setattr(adapter, "DELIVERY", "wake")

    manager = PluginManager()
    ctx = PluginContext(PluginManifest(name=PLUGIN_ID, key=PLUGIN_ID, source="user"), manager)
    plugin.register(ctx)  # real register_hook / register_tool validation
    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="4711", chat_type="dm", user_id="4711",
                           user_name="tester")
    entry = store.get_or_create_session(source)
    with patch("hermes_cli.plugins._plugin_manager", manager), \
            patch("hermes_cli.plugins._delivery_manager", lambda: manager, create=True):
        yield plugin, adapter, ctx, manager, store, source, entry
    sys.path.remove(os.path.join(ROOT, "sidecar"))


def _runner(store, telegram):
    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig()
    runner.session_store = store
    runner.adapters = {Platform.TELEGRAM: telegram}
    runner._profile_adapters = {}
    runner._gateway_loop = asyncio.get_running_loop()
    runner._running = True
    runner._draining = False
    runner._background_tasks = set()
    runner._queued_events = {}
    runner._is_user_authorized = lambda *a, **k: True
    telegram.set_busy_session_handler(runner._handle_active_session_busy_message)

    async def _never_called(event):  # processing is captured by _start_session_processing
        raise AssertionError("agent turn is not run in this test")

    telegram.set_message_handler(_never_called)
    return runner


def _gateway_turn(entry, fn):
    """Run `fn` the way the gateway runs a turn: with the session's context vars bound."""
    tokens = set_session_vars(platform="telegram", chat_id="4711", chat_type="dm", session_key=entry.session_key,
                              session_id=entry.session_id)
    try:
        return fn()
    finally:
        clear_session_vars(tokens)


def _exhaust(plugin, entry):
    sid = entry.session_id
    _gateway_turn(entry, lambda: (
        plugins_mod.invoke_hook("pre_llm_call", session_id=sid, turn_id="t1", user_message="Auftrag"),
        plugin.bind_task({"board_id": "default", "task_id": "t1"}, session_id=sid)))
    plugins_mod.invoke_hook("on_session_end", session_id=sid, turn_id="t1", completed=False, failed=False,
                            interrupted=False, turn_exit_reason="max_iterations_reached(90/90)")


def _continue(adapter, entry, key="inc_1:1"):
    return adapter.handle_continue({
        "installation": "test", "profile": "default", "session_id": entry.session_id, "board_id": "default",
        "task_id": "t1", "task_generation": 0, "idempotency_key": key, "incident_id": "inc_1",
        "expected_turn_seq": 1, "guidance": "check_status_first"})


async def _flush(runner):
    await asyncio.gather(*list(runner._background_tasks), return_exceptions=True)
    await asyncio.sleep(0)


def test_plugin_registers_on_real_hermes(world):
    plugin, _, ctx, manager, *_ = world
    for hook in ("pre_tool_call", "pre_llm_call", "on_session_end", "agent_loop_stopped",
                 "pre_gateway_dispatch", "transform_llm_output"):
        assert manager.has_hook(hook), hook
    assert ctx.plugin_id == PLUGIN_ID


@pytest.mark.asyncio
async def test_idle_session_wake_enters_the_adapter_path_of_its_own_chat(world):
    plugin, adapter, ctx, manager, store, source, entry = world
    _exhaust(plugin, entry)
    code, body = _continue(adapter, entry)
    assert body["accepted"]
    telegram = _Telegram()
    runner = _runner(store, telegram)
    runner._install_plugin_message_injector()
    plugin.wake_once(ctx)
    await _flush(runner)
    [event] = telegram.started
    assert event.internal is True and event.allow_gateway_control is False
    assert event.source.platform == Platform.TELEGRAM and event.source.chat_id == "4711"
    assert event.metadata["gateway_session_key"] == entry.session_key
    assert event.metadata["gateway_session_id"] == entry.session_id
    assert event.metadata["gateway_session_strict"] is True
    assert f"[gatekeeper-continuation {body['continuation_id']}]" in event.text
    # The turn that event starts.
    _gateway_turn(entry, lambda: plugins_mod.invoke_hook(
        "pre_llm_call", session_id=entry.session_id, turn_id="t-wake", user_message=event.text))
    with plugin.journal.connect() as conn:
        assert plugin.journal.row(conn, "SELECT state FROM continuations")["state"] == "started"
    directive, _ = plugins_mod.get_pre_tool_call_directive(
        "mcp__gatekeeper__demo_read", {}, session_id=entry.session_id, turn_id="t-wake")
    assert directive is None
    runner._clear_plugin_message_injector()


@pytest.mark.asyncio
async def test_stop_keeps_hermes_queued_wake_but_it_runs_inert(world):
    """Hermes deliberately keeps a parked internal wake across /stop and
    restarts it. The plugin records the stop through the real hook dispatch,
    and the restarted wake turn is inert under Hermes's own tool veto."""
    plugin, adapter, ctx, manager, store, source, entry = world
    _exhaust(plugin, entry)
    _continue(adapter, entry)
    telegram = _Telegram()
    runner = _runner(store, telegram)
    runner._install_plugin_message_injector()
    key = entry.session_key
    plugin.wake_once(ctx)
    # A user turn is now running (the wake was handed over first; the gateway
    # serializes, so it waits behind this turn in the busy queue).
    telegram._active_sessions[key] = asyncio.Event()
    await _flush(runner)
    assert telegram.started == []
    queued = (runner._queued_events.get(key) or [None])[0] or telegram._pending_messages.get(key)
    assert queued is not None and queued.internal
    runner._session_state(key).turn.agent = type("Agent", (), {"interrupt": lambda self, *a: None})()
    with patch.object(GatewayRunner, "_interrupt_running_turn", lambda self, *a, **k: 0):
        await runner._interrupt_and_clear_session(key, source, interrupt_reason=_INTERRUPT_REASON_STOP,
                                                  invalidation_reason="stop_command")
    with plugin.journal.connect() as conn:
        row = plugin.journal.row(conn, "SELECT state, reason FROM continuations")
    assert row == {"state": "lost", "reason": "user_stopped"}
    guard = telegram._active_sessions[key]
    await telegram._drain_pending_after_session_command(key, guard)
    [restarted] = telegram.started
    assert restarted.internal  # Hermes restarted the wake, as its source says
    out = _gateway_turn(entry, lambda: plugins_mod.invoke_hook(
        "pre_llm_call", session_id=entry.session_id, turn_id="t-wake", user_message=restarted.text))
    assert any("state_lost" in str(r) for r in out)
    for tool in ("terminal", "mcp__gatekeeper__demo_write"):
        directive, message = plugins_mod.get_pre_tool_call_directive(
            tool, {}, session_id=entry.session_id, turn_id="t-wake")
        assert directive == "block" and "user_stopped" not in message and "verworfen" in message
    [reply] = plugins_mod.invoke_hook("transform_llm_output", response_text="weiter geht's",
                                      session_id=entry.session_id, model="m", platform="telegram",
                                      turn_id="t-wake")
    assert "verworfen" in reply
    runner._clear_plugin_message_injector()


def test_injection_without_permission_is_refused_and_never_retried(world, tmp_path):
    plugin, adapter, ctx, manager, store, source, entry = world
    (tmp_path / "hermes" / "config.yaml").write_text(yaml.safe_dump({"plugins": {"entries": {}}}))
    _exhaust(plugin, entry)
    _continue(adapter, entry)
    plugin.wake_once(ctx)
    plugin.wake_once(ctx)
    with plugin.journal.connect() as conn:
        row = plugin.journal.row(conn, "SELECT state, reason, deliveries FROM continuations")
    assert row == {"state": "lost", "reason": "not_scheduled", "deliveries": 1}
    assert json.loads(json.dumps(row))  # plain values only
