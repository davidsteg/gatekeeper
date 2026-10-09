"""Recovery supervisor (recovery.py) -- acceptance cases 1-11.

Everything here runs against loopback fixtures: a fake Hermes recovery
adapter (status / continue, HMAC-verified) and a fake OpenAI-compatible
rescue provider. Failures are injected with harmless local tools (a python
one-liner that exits 3, one that sleeps past its timeout). No real Hermes,
no real model -- live integration evidence is a separate matter.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx2
import pytest
import yaml
from conftest import PYTHON, make_catalog
from mcp.client.client import Client, streamable_http_client

from gatekeeper.audit import AuditLog
from gatekeeper.errors import ConfigError, DenialReason, Denied
from gatekeeper.execute import OUTCOME_UNKNOWN
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.recovery import (
    IncidentStore,
    RecoverySupervisor,
    parse_config,
    scrub,
)
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

SECRETS = {
    "hermes-homelab-hmac": "homelab-hmac-secret",
    "hermes-personal-hmac": "personal-hmac-secret",
    "rescue-key": "rescue-api-key-value",
}
RESCUE_MODEL = "rescue-test-model"


# -- Loopback fixtures --------------------------------------------------------


class FakeHermes:
    """The Hermes side of the adapter contract, in memory."""

    def __init__(self, secret: str) -> None:
        self.secret = secret
        self.sessions: dict[tuple[str, str], dict] = {}
        self.status_calls: list[dict] = []
        self.continue_calls: list[dict] = []
        self.deliveries: dict[str, str] = {}
        self.bad_signatures = 0
        self.lock = threading.Lock()

    def session(self, session_id, task_id, **state):
        base = {"turn": "stopped", "turn_id": "turn-1", "task": "open",
                "last_progress_at": 0, "objective": "Restart stack media-jellyfin",
                "acceptance_criteria": "container healthy", "task_state": "in progress"}
        base.update(state)
        self.sessions[(session_id, task_id)] = base
        return base

    def handle(self, path: str, headers, body: bytes) -> tuple[int, dict]:
        ts = headers.get("X-Webhook-Timestamp", "")
        expected = hmac.new(self.secret.encode(), ts.encode() + b"." + body,
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, headers.get("X-Webhook-Signature-V2", "")):
            self.bad_signatures += 1
            return 401, {"error": "bad signature"}
        payload = json.loads(body)
        key = (payload["session_id"], payload["task_id"])
        with self.lock:
            state = self.sessions.get(key)
            if path.endswith("/status"):
                self.status_calls.append(payload)
                if state is None:
                    return 200, {"turn": "unknown", "task": "unknown"}
                return 200, dict(state)
            self.continue_calls.append(payload)
            if state is None:
                return 200, {"accepted": False, "reason": "no such session"}
            idem = payload["idempotency_key"]
            if idem not in self.deliveries:
                self.deliveries[idem] = f"dlv-{len(self.deliveries) + 1}"
                # Resume the *same* session: a new turn in it.
                n = int(state["turn_id"].split("-")[1]) + 1
                state.update(turn="active", turn_id=f"turn-{n}")
            return 200, {"accepted": True, "delivery_id": self.deliveries[idem]}


class FakeRescue:
    def __init__(self) -> None:
        self.mode = "ok"
        self.calls: list[dict] = []

    def handle(self, method: str, path: str, headers, body: bytes) -> tuple[int, dict]:
        if headers.get("Authorization") != f"Bearer {SECRETS['rescue-key']}":
            return 401, {"error": "bad key"}
        if method == "GET" and path.endswith("/models"):
            return 200, {"data": [{"id": RESCUE_MODEL}, {"id": "other"}]}
        self.calls.append(json.loads(body))
        if self.mode == "slow":
            time.sleep(3)
        if self.mode == "fail":
            return 500, {"error": "boom"}
        advice = {
            "likely_cause": "The target host is unreachable from this executor.",
            "next_step": "Check the stack state with demo.read instead of re-running demo.fail.",
            "required_checks": ["demo.read reports the stack"],
            "blocker": None,
        }
        return 200, {"choices": [{"message": {"content": json.dumps(advice)}}]}


def _serve(handler_fn):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _do(self, method):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            try:
                status, payload = handler_fn(method, self.path, self.headers, body)
            except Exception:  # pragma: no cover -- surfaces as a test failure
                status, payload = 500, {"error": "fixture crashed"}
            data = json.dumps(payload).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                pass  # the client gave up (rescue timeout test)

        def do_GET(self):
            self._do("GET")

        def do_POST(self):
            self._do("POST")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def hermes():
    homelab = FakeHermes(SECRETS["hermes-homelab-hmac"])
    personal = FakeHermes(SECRETS["hermes-personal-hmac"])
    servers = [
        _serve(lambda m, p, h, b: homelab.handle(p, h, b)),
        _serve(lambda m, p, h, b: personal.handle(p, h, b)),
    ]
    homelab.url = f"http://127.0.0.1:{servers[0].server_address[1]}/recovery"
    personal.url = f"http://127.0.0.1:{servers[1].server_address[1]}/recovery"
    yield {"homelab": homelab, "personal": personal}
    for server in servers:
        server.shutdown()


@pytest.fixture
def rescue():
    fake = FakeRescue()
    server = _serve(fake.handle)
    fake.url = f"http://127.0.0.1:{server.server_address[1]}/v1"
    yield fake
    server.shutdown()


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def _tools(sandbox):
    common = {"toolkit": "demo", "binary": PYTHON, "version": 1, "enabled": True,
              "max_output_bytes": 4096, "description": "test tool"}
    return [
        {**common, "id": "demo.fail", "title": "Fails", "category": "read",
         "idempotent": True, "timeout_seconds": 10,
         "argv": ["-c", "import sys; sys.stderr.write('connection refused to ' + sys.argv[1]"
                  " + ' api_token=supersecret123\\n'); sys.exit(3)", "{target}"],
         "parameters": {"target": {"type": "string", "required": True,
                                   "pattern": "^[a-z]+$", "description": "target"}},
         "required_scopes": []},
        {**common, "id": "demo.read", "title": "Reads", "category": "read",
         "idempotent": True, "timeout_seconds": 10,
         "argv": ["-c", "print('stack ok')"], "parameters": {}, "required_scopes": []},
        {**common, "id": "demo.slowwrite", "title": "Slow mutation", "category": "write",
         "idempotent": False, "timeout_seconds": 1,
         "argv": ["-c", "import time, sys; time.sleep(5); print(sys.argv[1])", "{stack}"],
         "parameters": {"stack": {"type": "string", "required": True,
                                  "pattern": "^[a-z-]+$", "description": "stack"}},
         "required_scopes": ["stack:{stack}"]},
        {**common, "id": "demo.limited", "title": "Rate limited", "category": "write_external",
         "idempotent": True, "timeout_seconds": 10,
         "argv": ["-c", "print('sent')"], "parameters": {}, "required_scopes": []},
    ]


@pytest.fixture
def env(tmp_path, sandbox, hermes, rescue):
    """A Service with recovery enabled, two installations, rescue configured."""

    def build(*, rescue_enabled=True, rescue_timeout=5, trigger_after=2, state=None,
              clock=None, ack_timeout=300, recovery_extra=None):
        recovery = {
            "enabled": True,
            "trigger_after": trigger_after,
            "max_recoveries_per_task": 3,
            "ack_timeout_seconds": ack_timeout,
            "tick_seconds": 0.05,
            "installations": {
                "homelab": {"identities": ["homelab-agent"],
                            "adapter_url": hermes["homelab"].url,
                            "credential": "hermes-homelab-hmac"},
                "personal": {"identities": ["personal-agent"],
                             "adapter_url": hermes["personal"].url,
                             "credential": "hermes-personal-hmac"},
            },
            "rescue": {"enabled": rescue_enabled, "base_url": rescue.url,
                       "model": RESCUE_MODEL, "reasoning_effort": "high",
                       "timeout_seconds": rescue_timeout, "max_tokens": 800,
                       "credential": "rescue-key"},
        }
        recovery.update(recovery_extra or {})
        path = tmp_path / "toolkits.yaml"
        path.write_text(yaml.safe_dump({
            "toolkits": {"demo": {
                "executor": "local", "binaries": [PYTHON], "path_roots": [str(sandbox)],
                "max_timeout_seconds": 30, "max_output_bytes": 8192,
            }},
            "rate_limits": {"write_external": {"count": 1, "window_seconds": 60}},
            "audit": {"dir": str(tmp_path / "logs")},
            "recovery": recovery,
        }), encoding="utf-8")
        tier1 = load_tier1(str(path))
        catalog = make_catalog(tmp_path, tier1, _tools(sandbox))
        tokens = {"homelab-agent": generate_token(), "personal-agent": generate_token()}
        ipath = tmp_path / "identities.yaml"
        ipath.write_text(yaml.safe_dump({"identities": [
            {"id": "homelab-agent", "role": "agent", "token_hash": hash_token(tokens["homelab-agent"]),
             "tools": ["demo.fail", "demo.read", "demo.slowwrite", "demo.limited"],
             "scopes": ["stack:*"]},
            {"id": "personal-agent", "role": "agent", "token_hash": hash_token(tokens["personal-agent"]),
             "tools": ["demo.read"], "scopes": []},
        ]}), encoding="utf-8")
        identities = load_identities(str(ipath))
        audit = AuditLog(str(tmp_path / "logs"))
        service = Service(tier1=tier1, catalog=catalog, audit=audit, identities=identities)
        service.recovery = make_supervisor(service, state or str(tmp_path / "recovery.yaml"), clock)
        return service, identities, tokens

    def make_supervisor(service, state_path, clock=None):
        return RecoverySupervisor(
            config_source=lambda: service.tier1.recovery,
            store=IncidentStore(state_path),
            audit=service.audit,
            secret_resolver=SECRETS.get,
            tools_for=lambda _id: [{"name": "demo.read", "idempotent": True}],
            clock=clock or time.time,
        )

    build.make_supervisor = make_supervisor
    return build


def _corr(service, identity, *, session="sess-1", task="task-1", turn="turn-1", **extra):
    return service.recovery.correlate(
        identity, {"hermes": {"session_id": session, "task_id": task, "turn_id": turn, **extra}}
    )


async def _call(service, identities, identity, tool, args=None, **corr):
    """(result-or-denial, recovery note)."""
    ident = identities.identities[identity]
    correlation = _corr(service, identity, **corr)
    try:
        result = await service.call(ident, tool, args or {}, correlation=correlation)
    except Denied as denial:
        return denial, getattr(denial, "recovery_note", None)
    return result, result.recovery_note


def _note(note):
    assert note and note.startswith("[gatekeeper recovery]"), note
    return json.loads(note.split("\n", 1)[1])["recovery"]


def _incidents(service):
    return service.recovery.store.read(lambda d: list(d["incidents"].values()))


def _stopped(**kw):
    payload = {"type": "turn_stopped", "session_id": "sess-1", "task_id": "task-1",
               "turn_id": "turn-1", "reason": "exhausted", "event_id": "evt-stop-1"}
    payload.update(kw)
    return payload


# -- Configuration ------------------------------------------------------------


def test_recovery_is_off_without_a_block(tier1):
    assert tier1.recovery.enabled is False


def test_flag_off_means_no_correlation_and_no_state(env, tmp_path):
    service, identities, _ = env(recovery_extra={"enabled": False})
    assert _corr(service, "homelab-agent") is None
    assert not (tmp_path / "recovery.yaml").exists()


def test_config_rejects_unsafe_shapes():
    with pytest.raises(ConfigError, match="both"):
        parse_config({"installations": {"a": {"identities": ["x"]}, "b": {"identities": ["x"]}}})
    with pytest.raises(ConfigError, match="no default rescue model"):
        parse_config({"rescue": {"enabled": True, "base_url": "http://x/v1", "credential": "c"}})
    with pytest.raises(ConfigError, match="signed"):
        parse_config({"installations": {"a": {"identities": ["x"], "adapter_url": "http://h"}}})


def test_recovery_credentials_count_as_references(env):
    service, _, _ = env()
    refs = service.tier1.credential_references()
    assert refs["hermes-homelab-hmac"] == ("recovery:homelab",)
    assert refs["rescue-key"] == ("recovery:rescue",)


# -- 1. Repeated failure: exactly one rescue, changed approach -----------------


async def test_repeated_failure_triggers_one_rescue_and_a_changed_approach(env, rescue, hermes):
    service, identities, _ = env()
    await service.recovery.startup_checks()
    hermes["homelab"].session("sess-1", "task-1", turn="active")

    _, first = await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    assert first is None  # one failure is not a pattern yet
    _, second = await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    body = _note(second)
    assert body["action"] == "change_approach"
    assert body["advice_source"] == "rescue model (untrusted advice)"
    assert "demo.read" in body["next_step"] and "demo.fail" in body["next_step"]
    assert len(rescue.calls) == 1
    sent = rescue.calls[0]
    assert sent["model"] == RESCUE_MODEL and sent["reasoning_effort"] == "high"
    assert "tools" not in sent  # diagnostic only: the model gets no tools
    context = json.loads(sent["messages"][1]["content"])
    assert context["objective"] == "Restart stack media-jellyfin"
    assert len(context["failed_attempts"]) == 2

    # Two more failures: no second consultation, the loop is closed instead.
    _, third = await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    _, fourth = await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    assert third is None
    assert _note(fourth)["action"] == "blocked"
    assert len(rescue.calls) == 1
    [incident] = _incidents(service)
    assert incident["outcome"] == "blocked:no_progress_after_guidance"
    assert incident["consultation"]["status"] == "ok"


# -- 2. Cooldown: one scheduled check, no probing -------------------------------


async def test_cooldown_schedules_one_check_then_continues(env, hermes):
    clock = Clock()
    service, identities, _ = env(clock=clock, rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")

    await _call(service, identities, "homelab-agent", "demo.limited")
    denial, note = await _call(service, identities, "homelab-agent", "demo.limited")
    assert isinstance(denial, Denied) and denial.reason is DenialReason.RATE_LIMITED
    body = _note(note)
    assert body["action"] == "wait_cooldown" and "cooldown_until" in body

    code, resp = await service.recovery.handle_event("homelab-agent", _stopped(reason="breaker_open"))
    assert (code, resp["action"]) == (200, "cooldown_pending")
    for _ in range(5):
        await service.recovery.tick()
    assert hermes["homelab"].status_calls == []  # no probing before the deadline
    assert hermes["homelab"].continue_calls == []

    clock.now += 61
    for _ in range(5):
        await service.recovery.tick()
    assert len(hermes["homelab"].continue_calls) == 1
    assert len([c for c in hermes["homelab"].status_calls]) == 2  # pre-continue + ack check
    [incident] = _incidents(service)
    assert incident["status"] == "awaiting_ack"


async def test_client_reported_breaker_cooldown_is_honoured(env, hermes):
    clock = Clock()
    service, identities, _ = env(clock=clock, rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    code, resp = await service.recovery.handle_event(
        "homelab-agent", _stopped(reason="breaker_open", cooldown_until=clock.now + 120))
    assert resp["action"] == "cooldown_scheduled"
    clock.now += 60
    await service.recovery.tick()
    assert hermes["homelab"].continue_calls == []
    clock.now += 61
    await service.recovery.tick()
    assert len(hermes["homelab"].continue_calls) == 1


# -- 3. Permission denial: no bypass --------------------------------------------


async def test_permission_denial_blocks_without_bypass(env, hermes, rescue):
    service, identities, _ = env()
    hermes["personal"].session("sess-p", "task-p")
    denial, note = await _call(service, identities, "personal-agent", "demo.fail",
                               {"target": "nas"}, session="sess-p", task="task-p")
    assert denial.reason is DenialReason.NOT_GRANTED
    body = _note(note)
    assert body["action"] == "blocked"
    assert "do not reach it through a different tool" in body["guidance"]
    assert "blocker" not in body  # FR-7.7: the precise reason stays internal

    # Unknown tool: indistinguishable guidance (no catalog oracle).
    _, other = await _call(service, identities, "personal-agent", "demo.nope",
                           session="sess-p", task="task-p")
    assert _note(other)["guidance"] == body["guidance"]

    # A stopped turn after a permission block is not resumed into a retry.
    _, resp = await service.recovery.handle_event(
        "personal-agent", _stopped(session_id="sess-p", task_id="task-p"))
    assert resp["action"] == "none"
    assert hermes["personal"].continue_calls == [] and rescue.calls == []
    incidents = _incidents(service)
    assert {i["outcome"] for i in incidents} == {"blocked:permission"}
    assert "not_granted" in incidents[0]["blocker"]  # operator-side detail


# -- 4. Timed-out, maybe-running mutation is not duplicated ---------------------


async def test_unknown_outcome_holds_an_exact_repeat_until_status_checked(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    result, note = await _call(service, identities, "homelab-agent", "demo.slowwrite",
                               {"stack": "media"})
    assert result.outcome == OUTCOME_UNKNOWN
    assert _note(note)["action"] == "check_status_first"

    denial, note = await _call(service, identities, "homelab-agent", "demo.slowwrite",
                               {"stack": "media"})
    assert isinstance(denial, Denied) and denial.reason is DenialReason.RECOVERY_HOLD
    assert "Do not run it again" in denial.agent_message
    # It never reached the executor: the audit shows one run, one denial.
    lines = [json.loads(line) for line in open(os.path.join(
        service.tier1.audit_dir, "audit.jsonl"), encoding="utf-8")]
    runs = [r for r in lines if r["kind"] == "call" and r["tool"] == "demo.slowwrite"]
    assert [r["outcome"] for r in runs] == ["unknown", "denied"]

    # A successful read on the same service is the status check; it releases the hold.
    await _call(service, identities, "homelab-agent", "demo.read")
    corr = _corr(service, "homelab-agent")
    assert service.recovery.hold(corr, tool_id="demo.slowwrite", scopes=["stack:media"]) is None


# -- 5. Stopped turn resumes the original task ----------------------------------


async def test_stopped_turn_is_continued_in_the_original_session(env, hermes, rescue):
    service, identities, _ = env()
    await service.recovery.startup_checks()
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    fake.sessions[("sess-1", "task-1")]["turn"] = "exhausted"

    code, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert (code, resp["action"]) == (200, "continued")
    [sent] = fake.continue_calls
    assert (sent["session_id"], sent["task_id"]) == ("sess-1", "task-1")
    assert resp["incident_id"] in sent["guidance"]
    assert "Suggested next step (untrusted advice)" in sent["guidance"]
    assert fake.bad_signatures == 0

    await service.recovery.tick()  # sees the new turn start
    [incident] = _incidents(service)
    assert incident["continuation"]["started"] is True
    assert incident["status"] == "awaiting_ack"

    await _call(service, identities, "homelab-agent", "demo.read", turn="turn-2")
    [incident] = _incidents(service)
    assert incident["outcome"] == "recovered"
    assert incident["continuation"]["delivery_id"] == "dlv-1"
    assert incident["continuation"]["ack_tool_id"] == "demo.read"

    # Structured trail: every transition is a `kind: recovery` audit record
    # carrying the ids an operator needs to follow it.
    records = [json.loads(line) for line in open(os.path.join(
        service.tier1.audit_dir, "audit.jsonl"), encoding="utf-8")]
    trail = [r for r in records if str(r.get("event", "")).startswith("recovery.")]
    assert all(r["kind"] == "recovery" for r in trail)
    events = [r["event"] for r in trail]
    for expected in ("recovery.incident_opened", "recovery.rescue_completed",
                     "recovery.guidance_issued", "recovery.continuation_sent",
                     "recovery.continuation_started", "recovery.continuation_acknowledged"):
        assert expected in events, events
    sent = next(r for r in trail if r["event"] == "recovery.continuation_sent")
    assert sent["delivery_id"] == "dlv-1" and sent["incident_id"] == incident["id"]
    consulted = next(r for r in trail if r["event"] == "recovery.rescue_completed")
    assert consulted["consultation_id"] == incident["consultation"]["id"]


# -- 6. Duplicate events: one recovery, one continuation -------------------------


async def test_duplicate_events_produce_one_recovery_and_one_continuation(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    for event in ("evt-a", "evt-a", "evt-b", "evt-b"):
        await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"},
                    event_id=event)
    [incident] = _incidents(service)
    assert len(incident["attempts"]) == 2

    results = await asyncio.gather(
        service.recovery.handle_event("homelab-agent", _stopped()),
        service.recovery.handle_event("homelab-agent", _stopped()),
        service.recovery.handle_event("homelab-agent", _stopped(event_id="evt-stop-2")),
    )
    actions = sorted(r[1]["action"] for r in results)
    assert actions.count("continued") == 1
    assert len(fake.continue_calls) == 1
    assert len(_incidents(service)) == 1


# -- 7. Restart preserves cooldowns and duplicate protection ----------------------


async def test_restart_preserves_cooldown_and_dedup(env, hermes, tmp_path):
    clock = Clock()
    state = str(tmp_path / "state" / "recovery.yaml")
    os.makedirs(os.path.dirname(state))
    service, identities, _ = env(clock=clock, rescue_enabled=False, state=state)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.limited", event_id="e1")
    await _call(service, identities, "homelab-agent", "demo.limited", event_id="e2")
    await service.recovery.handle_event("homelab-agent", _stopped())
    [before] = _incidents(service)
    assert before["status"] == "cooling"

    # "Restart": a brand-new supervisor over the same file.
    service.recovery = env.make_supervisor(service, state, clock)
    [after] = _incidents(service)
    assert after["cooldown_until"] == before["cooldown_until"]
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["duplicate"] is True
    _, note = await _call(service, identities, "homelab-agent", "demo.limited", event_id="e2")
    assert note is None  # replayed event, ignored

    await service.recovery.tick()
    assert fake.continue_calls == []  # cooldown still running after the restart
    clock.now += 61
    await service.recovery.tick()
    assert len(fake.continue_calls) == 1

    service.recovery = env.make_supervisor(service, state, clock)  # restart again
    clock.now += 5
    await service.recovery.tick()
    assert len(fake.continue_calls) == 1


# -- 8. Completed / cancelled tasks are not resumed ---------------------------------


async def test_completed_task_is_not_resumed(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    _, resp = await service.recovery.handle_event(
        "homelab-agent", {"type": "task_completed", "task_id": "task-1", "event_id": "evt-done"})
    assert resp["action"] == "suppressed"
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "none"
    _, note = await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    assert note is None
    assert fake.continue_calls == []


async def test_cancelled_task_reported_by_status_is_suppressed(env, hermes, rescue):
    service, identities, _ = env()
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", task="cancelled")
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    _, note = await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    assert note is None
    [incident] = _incidents(service)
    assert incident["outcome"] == "suppressed:cancelled"
    assert rescue.calls == [] and fake.continue_calls == []


# -- 9. Rescue failure ends within budget, accurately blocked ------------------------


async def test_rescue_failure_ends_within_budget_as_blocked(env, hermes, rescue):
    service, identities, _ = env(rescue_timeout=1)
    await service.recovery.startup_checks()
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    rescue.mode = "slow"
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    started = time.monotonic()
    _, note = await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    elapsed = time.monotonic() - started
    assert elapsed < 2.5, elapsed
    assert _note(note)["action"] == "blocked"
    [incident] = _incidents(service)
    assert incident["outcome"] == "blocked:rescue_failed"
    assert incident["consultation"]["status"] == "failed"
    assert "ReadTimeout" in incident["blocker"] or "TimeoutError" in incident["blocker"]


async def test_unlisted_rescue_model_disables_rescue(env, hermes, rescue):
    service, identities, _ = env(recovery_extra={})
    service.tier1 = service.tier1.__class__(**{
        **{f: getattr(service.tier1, f) for f in service.tier1.__dataclass_fields__},
        "recovery": parse_config({
            "enabled": True,
            "installations": {"homelab": {"identities": ["homelab-agent"]}},
            "rescue": {"enabled": True, "base_url": rescue.url, "model": "made-up-model",
                       "credential": "rescue-key"},
        }),
    })
    # No explicit startup check: the first consultation verifies the model itself.
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    _, note = await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    assert _note(note)["action"] == "change_approach"
    assert rescue.calls == []


# -- 10. Homelab and Personal stay apart ----------------------------------------------


async def test_installations_cannot_resume_each_other(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")
    hermes["personal"].session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})

    # Same ids, other installation: addresses nothing of homelab's.
    _, resp = await service.recovery.handle_event("personal-agent", _stopped())
    assert resp["action"] == "none"
    code, _ = await service.recovery.handle_event(
        "personal-agent", _stopped(installation="homelab", event_id="evt-x"))
    assert code == 403
    assert _corr(service, "personal-agent", installation="homelab") is None
    assert service.recovery.incidents_for("personal-agent") == []
    assert len(service.recovery.incidents_for("homelab-agent")) == 1
    assert hermes["homelab"].continue_calls == hermes["personal"].continue_calls == []

    # Homelab's own stop reaches homelab's adapter only.
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "continued"
    assert len(hermes["homelab"].continue_calls) == 1
    assert hermes["personal"].continue_calls == []


# -- 11. Acknowledgement needs an executed tool call ----------------------------------


async def test_ack_requires_an_executed_tool_call_in_the_new_turn(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    await service.recovery.handle_event("homelab-agent", _stopped())
    await service.recovery.tick()
    [incident] = _incidents(service)
    assert incident["continuation"]["started"] and incident["status"] == "awaiting_ack"

    # Old-turn traffic and denied calls are not acknowledgement.
    await _call(service, identities, "homelab-agent", "demo.read", turn="turn-1")
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "NAS!"},
                turn="turn-2")
    [incident] = _incidents(service)
    assert incident["status"] == "awaiting_ack"

    await _call(service, identities, "homelab-agent", "demo.read", turn="turn-2")
    assert _incidents(service)[0]["outcome"] == "recovered"


async def test_no_call_before_the_deadline_is_unacknowledged(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock, ack_timeout=30)
    hermes["homelab"].session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    await service.recovery.handle_event("homelab-agent", _stopped())
    clock.now += 31
    await service.recovery.tick()  # turn started, but the agent did nothing
    await service.recovery.tick()
    [incident] = _incidents(service)
    assert incident["outcome"] == "unacknowledged"
    assert "no tool call was executed" in incident["blocker"]


# -- Bounds, redaction -------------------------------------------------------------------


async def test_recoveries_per_task_are_bounded_across_incidents(env, hermes):
    service, identities, _ = env(rescue_enabled=False,
                                 recovery_extra={"max_recoveries_per_task": 1})
    fake = hermes["homelab"]
    state = fake.session("sess-1", "task-1", turn="active", last_progress_at=time.time() + 1e6)

    async def fail(target):
        return (await _call(service, identities, "homelab-agent", "demo.fail",
                            {"target": target}))[1]

    # Incident A: the task owner reports progress -> closed, no recovery spent.
    assert await fail("nas") is None and await fail("nas") is None
    state["last_progress_at"] = 0
    # Incident B: guidance, which spends the task's single recovery.
    assert await fail("nas") is None
    assert _note(await fail("nas"))["action"] == "change_approach"
    # Slightly different errors from here on cannot buy another round.
    assert await fail("abc") is None
    assert _note(await fail("abd"))["action"] == "blocked"
    assert await fail("abe") is None
    assert _note(await fail("abf"))["action"] == "blocked"
    outcomes = [i["outcome"] for i in sorted(_incidents(service), key=lambda i: i["created_at"])]
    assert outcomes == ["progressed", "blocked:recovery_budget_exhausted",
                        "blocked:recovery_budget_exhausted"]
    assert fake.continue_calls == []


async def test_secrets_never_reach_the_state_file(env, hermes, tmp_path):
    service, identities, _ = env(rescue_enabled=False)
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "nas"})
    text = (tmp_path / "recovery.yaml").read_text(encoding="utf-8")
    assert "supersecret123" not in text
    assert "api_token=***" in text


def test_scrub_masks_foreign_secret_shapes():
    out = scrub("Authorization: Bearer abcdefghijkl password=hunter22 sk-abcdefghijklmnop")
    assert "abcdefghijkl" not in out and "hunter22" not in out and "sk-abcdefgh" not in out


# -- End to end over MCP + HTTP --------------------------------------------------------


async def test_end_to_end_over_mcp_and_the_events_route(env, hermes):
    service, identities, tokens = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    app = build_app(service=service, identities=identities, audit=service.audit)
    base = "http://gatekeeper.test"
    headers = {"Authorization": f"Bearer {tokens['homelab-agent']}"}
    meta = {"hermes": {"session_id": "sess-1", "task_id": "task-1", "turn_id": "turn-1"}}
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),
                                      base_url=base, headers=headers, timeout=30) as http:
            transport = streamable_http_client(f"{base}/mcp", http_client=http)
            async with Client(transport) as client:
                await client.call_tool("demo.fail", {"target": "nas"}, meta=meta)
                second = await client.call_tool("demo.fail", {"target": "nas"}, meta=meta)
            text = second.content[0].text
            assert second.is_error and "[gatekeeper recovery]" in text
            assert '"action": "change_approach"' in text

            fake.sessions[("sess-1", "task-1")]["turn"] = "exhausted"
            response = await http.post("/recovery/events", json=_stopped())
            assert response.status_code == 200 and response.json()["action"] == "continued"
            listed = (await http.get("/recovery/incidents?task_id=task-1")).json()["incidents"]
            assert listed[0]["delivery_id"] == "dlv-1"

            # The scheduler runs in the lifespan and notices the new turn.
            for _ in range(40):
                await asyncio.sleep(0.05)
                if _incidents(service)[0]["continuation"].get("started"):
                    break
            assert _incidents(service)[0]["continuation"]["started"] is True

        anonymous = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=base)
        async with anonymous:
            assert (await anonymous.post("/recovery/events", json=_stopped())).status_code == 401
