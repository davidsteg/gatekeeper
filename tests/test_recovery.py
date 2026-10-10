"""Recovery supervisor (recovery.py) -- contract and acceptance tests.

MOCK EVIDENCE ONLY. Everything here runs against loopback fixtures: a fake
Hermes recovery adapter (status / continue / continuation, HMAC-verified,
with ownership checks and persisted idempotency) and a fake
OpenAI-compatible rescue provider. Failures are injected with harmless
local tools (a python one-liner that exits 3, one that sleeps past its
timeout). No real Hermes, no real model, no Jev -- live integration
evidence is a separate matter and is not claimed by any test here.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import itertools
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

from gatekeeper import recovery
from gatekeeper.audit import AuditLog
from gatekeeper.errors import ConfigError, DenialReason, Denied
from gatekeeper.execute import OUTCOME_UNKNOWN
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.recovery import IncidentStore, RecoverySupervisor, parse_config, scrub
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

SECRETS = {
    "hermes-homelab-hmac": "homelab-hmac-secret",
    "hermes-personal-hmac": "personal-hmac-secret",
    "rescue-key": "rescue-api-key-value",
}
RESCUE_MODEL = "rescue-test-model"
BOARD = "board-1"
_events = itertools.count(1)


# -- Loopback fixtures --------------------------------------------------------


class FakeHermes:
    """The Hermes side of the adapter contract, in memory.

    Mirrors what the contract demands of the real adapter: ownership is
    validated against (installation, profile, session, board, task); a
    continuation is accepted only for a stopped turn at the expected
    turn_seq; idempotency keys are remembered (persisted, in the real one).
    """

    def __init__(self, name: str, secret: str) -> None:
        self.name = name
        self.secret = secret
        self.sessions: dict[tuple[str, str, str], dict] = {}
        self.status_calls: list[dict] = []
        self.continue_calls: list[dict] = []
        self.query_calls: list[dict] = []
        self.deliveries: dict[str, dict] = {}
        self.bad_signatures = 0
        self.continue_delay = 0.0
        #: Simulates a user message landing between /status and /continue.
        self.user_turn_on_continue = False
        self.echo_override: dict = {}
        self.internal_recovery_until = None
        self.lock = threading.Lock()

    def session(self, session_id, task_id, board=BOARD, **state):
        base = {"turn": "stopped", "turn_seq": 1, "task": "open", "task_generation": 0,
                "stop_reason": "exhausted", "last_progress_at": 0, "continuation_id": None,
                "objective": "Restart stack media-jellyfin",
                "acceptance_criteria": "container healthy", "task_state": "in progress"}
        base.update(state)
        self.sessions[(session_id, board, task_id)] = base
        return base

    def state(self, session_id="sess-1", task_id="task-1", board=BOARD):
        return self.sessions[(session_id, board, task_id)]

    def handle(self, path: str, headers, body: bytes) -> tuple[int, dict]:
        ts = headers.get("X-Webhook-Timestamp", "")
        expected = hmac.new(self.secret.encode(), ts.encode() + b"." + body,
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, headers.get("X-Webhook-Signature-V2", "")):
            self.bad_signatures += 1
            return 401, {"error": "bad signature"}
        payload = json.loads(body)
        if payload.get("installation") != self.name:
            return 409, {"error": "wrong installation"}
        key = (payload["session_id"], payload["board_id"], payload["task_id"])
        with self.lock:
            state = self.sessions.get(key)
            if path.endswith("/status"):
                self.status_calls.append(payload)
                if state is None:
                    return 404, {"error": "session does not own this task"}
                return 200, {**state, "session_id": key[0], "board_id": key[1],
                             "task_id": key[2], **self.echo_override}
            if path.endswith("/continuation"):
                self.query_calls.append(payload)
                found = self.deliveries.get(payload["idempotency_key"])
                return 200, found or {"state": "none"}
            self.continue_calls.append(payload)
            if state is None:
                return 404, {"error": "session does not own this task"}
            idem = payload["idempotency_key"]
            if self.internal_recovery_until and idem not in self.deliveries:
                return 200, {"accepted": False, "reason": "internal_recovery",
                             "retry_after_until": self.internal_recovery_until}
            if idem not in self.deliveries:
                if self.user_turn_on_continue:
                    state.update(turn="active", turn_seq=state["turn_seq"] + 1)
                if state["turn"] == "active" or state["turn_seq"] != payload["expected_turn_seq"]:
                    self.deliveries[idem] = {"state": "rejected", "reason": "superseded"}
                elif state["task"] != "open":
                    self.deliveries[idem] = {"state": "rejected", "reason": "task_closed"}
                else:
                    cid = f"cont-{len(self.deliveries) + 1}"
                    state.update(turn="active", turn_seq=state["turn_seq"] + 1,
                                 continuation_id=cid, stop_reason=None)
                    self.deliveries[idem] = {"state": "accepted", "continuation_id": cid}
            found = self.deliveries[idem]
        if self.continue_delay:
            time.sleep(self.continue_delay)  # processed, but the reply is late
        if found["state"] == "accepted":
            return 200, {"accepted": True, "continuation_id": found["continuation_id"]}
        return 200, {"accepted": False, "reason": found["reason"]}


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
                pass  # the client gave up (timeout tests)

        def do_GET(self):
            self._do("GET")

        def do_POST(self):
            self._do("POST")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def hermes():
    fakes = {
        "homelab": FakeHermes("homelab", SECRETS["hermes-homelab-hmac"]),
        "personal": FakeHermes("personal", SECRETS["hermes-personal-hmac"]),
    }
    servers = []
    for fake in fakes.values():
        server = _serve(lambda m, p, h, b, f=fake: f.handle(p, h, b))
        fake.url = f"http://127.0.0.1:{server.server_address[1]}/recovery"
        servers.append(server)
    yield fakes
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
        self.now = time.time()

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

    def build(*, rescue_enabled=True, rescue_timeout=5, state=None, clock=None,
              recovery_extra=None, installations_extra=None):
        installations = {
            "homelab": {"identities": ["homelab-agent"], "profiles": ["orchestrator"],
                        "adapter_url": hermes["homelab"].url,
                        "credential": "hermes-homelab-hmac"},
            "personal": {"identities": ["personal-agent"],
                         "adapter_url": hermes["personal"].url,
                         "credential": "hermes-personal-hmac"},
        }
        installations.update(installations_extra or {})
        recovery_block = {
            "enabled": True, "trigger_after": 2, "max_recoveries_per_task": 3,
            "tick_seconds": 0.05, "status_poll_seconds": 1, "adapter_timeout_seconds": 2.0,
            "installations": installations,
            "rescue": {"enabled": rescue_enabled, "base_url": rescue.url,
                       "model": RESCUE_MODEL, "reasoning_effort": "high",
                       "timeout_seconds": rescue_timeout, "max_tokens": 800,
                       "credential": "rescue-key"},
        }
        recovery_block.update(recovery_extra or {})
        path = tmp_path / "toolkits.yaml"
        path.write_text(yaml.safe_dump({
            "toolkits": {"demo": {
                "executor": "local", "binaries": [PYTHON], "path_roots": [str(sandbox)],
                "max_timeout_seconds": 30, "max_output_bytes": 8192,
            }},
            "rate_limits": {"write_external": {"count": 1, "window_seconds": 60}},
            "audit": {"dir": str(tmp_path / "logs")},
            "recovery": recovery_block,
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

    def make_supervisor(service, state_path, clock=None, decision_provider=None):
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


def _meta(identity, *, session="sess-1", task="task-1", turn_seq=1, board=BOARD, **extra):
    meta = {"session_id": session, "board_id": board, "task_id": task,
            "turn_id": f"turn-{turn_seq}", "turn_seq": turn_seq,
            "event_id": f"evt-{next(_events)}"}
    if identity == "homelab-agent":
        meta["profile"] = "orchestrator"
    meta.update(extra)
    return {"hermes": meta}


def _corr(service, identity, **kw):
    return service.recovery.correlate(identity, _meta(identity, **kw))


async def _call(service, identities, identity, tool, args=None, **corr):
    """(result-or-denial, recovery note)."""
    ident = identities.identities[identity]
    correlation = _corr(service, identity, **corr)
    try:
        result = await service.call(ident, tool, args or {}, correlation=correlation)
    except Denied as denial:
        return denial, getattr(denial, "recovery_note", None)
    return result, result.recovery_note


async def _fail(service, identities, n=1, identity="homelab-agent", **corr):
    note = None
    for _ in range(n):
        _, note = await _call(service, identities, identity, "demo.fail", {"target": "nas"}, **corr)
    return note


def _note(note):
    assert note and note.startswith("[gatekeeper recovery]"), note
    return json.loads(note.split("\n", 1)[1])["recovery"]


def _incidents(service):
    return sorted(service.recovery.store.read(lambda d: list(d["incidents"].values())),
                  key=lambda i: i["created_at"])


def _stopped(**kw):
    payload = {"type": "turn_stopped", "session_id": "sess-1", "board_id": BOARD,
               "task_id": "task-1", "turn_seq": 1, "reason": "exhausted",
               "profile": "orchestrator", "event_id": f"stop-{next(_events)}"}
    payload.update(kw)
    return payload


def _event(type_, **kw):
    payload = {"type": type_, "board_id": BOARD, "task_id": "task-1",
               "profile": "orchestrator", "event_id": f"ev-{next(_events)}"}
    payload.update(kw)
    return payload


async def _continued(service, identities, hermes, clock=None):
    """Two failures, then a stop: returns the accepted incident."""
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    hermes["homelab"].state().update(turn="exhausted", stop_reason="exhausted")
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "continued", resp
    return _incidents(service)[-1]


# -- Configuration ------------------------------------------------------------


def test_recovery_is_off_without_a_block(tier1):
    assert tier1.recovery.enabled is False
    assert tier1.recovery.decision.enabled is False


def test_flag_off_means_no_correlation_and_no_state(env, tmp_path):
    service, _, _ = env(recovery_extra={"enabled": False})
    assert _corr(service, "homelab-agent") is None
    assert not (tmp_path / "recovery.yaml").exists()


def test_config_rejects_unsafe_shapes():
    with pytest.raises(ConfigError, match="both"):
        parse_config({"installations": {"a": {"identities": ["x"]}, "b": {"identities": ["x"]}}})
    with pytest.raises(ConfigError, match="no default rescue model"):
        parse_config({"rescue": {"enabled": True, "base_url": "http://x/v1", "credential": "c"}})
    with pytest.raises(ConfigError, match="signed"):
        parse_config({"installations": {"a": {"identities": ["x"], "adapter_url": "http://h"}}})
    with pytest.raises(ConfigError, match="not an implemented decision provider"):
        parse_config({"decision": {"enabled": True, "provider": "jev"}})


def test_installations_are_not_limited_to_two():
    config = parse_config({"enabled": True, "installations": {
        "homelab": {"identities": ["a"]}, "personal": {"identities": ["b"]},
        "media": {"identities": ["c"], "profiles": ["media-worker"]},
        "gatekeeper-bot": {"identities": ["d"]},
    }})
    assert config.installation_for("c").name == "media"
    assert config.installation_for("d").name == "gatekeeper-bot"


def test_recovery_credentials_count_as_references(env):
    service, _, _ = env()
    refs = service.tier1.credential_references()
    assert refs["hermes-homelab-hmac"] == ("recovery:homelab",)
    assert refs["rescue-key"] == ("recovery:rescue",)


# -- Correlation: ownership, scope, ordering ------------------------------------


def test_correlation_needs_board_turn_seq_event_and_allowed_profile(env):
    service, _, _ = env()
    assert _corr(service, "homelab-agent") is not None
    for missing in ("board_id", "turn_seq", "event_id", "task_id"):
        meta = _meta("homelab-agent")
        meta["hermes"].pop(missing)
        assert service.recovery.correlate("homelab-agent", meta) is None, missing
    assert _corr(service, "homelab-agent", profile="worker-x") is None
    assert _corr(service, "homelab-agent", turn_seq="7") is None  # opaque string, not an int
    assert _corr(service, "homelab-agent", installation="personal") is None
    # A turn with no Kanban task sends no `_meta.hermes`: nothing is fabricated.
    assert service.recovery.correlate("homelab-agent", {}) is None


async def test_wrong_session_board_profile_or_installation_is_refused(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    hermes["homelab"].state().update(turn="exhausted")

    _, resp = await service.recovery.handle_event("homelab-agent", _stopped(session_id="sess-other"))
    assert resp["reason"] == "different session"
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped(board_id="board-2"))
    assert resp["action"] == "none" and "no open incident" in resp["reason"]
    code, resp = await service.recovery.handle_event("homelab-agent", _stopped(profile="worker-x"))
    assert code == 403
    code, _ = await service.recovery.handle_event("homelab-agent", _stopped(installation="personal"))
    assert code == 403
    assert hermes["homelab"].continue_calls == []

    # The adapter is the authority on ownership: an unmapped session blocks,
    # it never falls back to some other session.
    del hermes["homelab"].sessions[("sess-1", BOARD, "task-1")]
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "blocked"
    assert _incidents(service)[0]["outcome"] == "blocked:session_mapping_failed"
    assert hermes["homelab"].continue_calls == []


async def test_delayed_events_and_calls_from_an_older_turn_are_ignored(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active", turn_seq=3)
    await _fail(service, identities, 1, turn_seq=3)
    await _fail(service, identities, 1, turn_seq=2)  # late call from turn 2
    [incident] = _incidents(service)
    assert len(incident["attempts"]) == 1
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped(turn_seq=2))
    assert resp["reason"] == "older turn"
    assert hermes["homelab"].continue_calls == []


# -- 1. Repeated failure: exactly one rescue, changed approach -----------------


async def test_repeated_failure_triggers_one_rescue_and_a_changed_approach(env, rescue, hermes):
    service, identities, _ = env()
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    assert await _fail(service, identities, 1) is None
    body = _note(await _fail(service, identities, 1))
    assert body["action"] == "change_approach"
    assert body["advice_source"] == "rescue model (untrusted advice)"
    assert "demo.read" in body["next_step"]
    assert len(rescue.calls) == 1
    sent = rescue.calls[0]
    assert sent["model"] == RESCUE_MODEL and sent["reasoning_effort"] == "high"
    assert "tools" not in sent
    context = json.loads(sent["messages"][1]["content"])
    assert context["objective"] == "Restart stack media-jellyfin"
    assert len(context["failed_attempts"]) == 2

    assert await _fail(service, identities, 1) is None
    assert _note(await _fail(service, identities, 1))["action"] == "blocked"
    assert len(rescue.calls) == 1
    [incident] = _incidents(service)
    assert incident["outcome"] == "blocked:no_progress_after_guidance"


# -- 2. Cooldown ----------------------------------------------------------------


async def test_cooldown_schedules_one_check_then_continues(env, hermes):
    clock = Clock()
    service, identities, _ = env(clock=clock, rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.limited")
    denial, note = await _call(service, identities, "homelab-agent", "demo.limited")
    assert denial.reason is DenialReason.RATE_LIMITED
    assert _note(note)["action"] == "wait_cooldown"

    _, resp = await service.recovery.handle_event("homelab-agent", _stopped(reason="breaker_open"))
    assert resp["action"] == "cooldown_pending"
    for _ in range(5):
        await service.recovery.tick()
    assert fake.status_calls == [] and fake.continue_calls == []

    clock.now += 61
    await service.recovery.tick()
    assert len(fake.continue_calls) == 1 and len(fake.status_calls) == 1
    await service.recovery.tick()
    assert len(fake.continue_calls) == 1


async def test_client_reported_breaker_cooldown_is_honoured(env, hermes):
    clock = Clock()
    service, identities, _ = env(clock=clock, rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")
    await _fail(service, identities, 1)
    _, resp = await service.recovery.handle_event(
        "homelab-agent", _stopped(reason="breaker_open", cooldown_until=clock.now + 120))
    assert resp["action"] == "cooldown_scheduled"
    clock.now += 60
    await service.recovery.tick()
    assert hermes["homelab"].continue_calls == []
    clock.now += 61
    await service.recovery.tick()
    assert len(hermes["homelab"].continue_calls) == 1


async def test_user_cancellation_during_cooldown_is_final(env, hermes):
    clock = Clock()
    service, identities, _ = env(clock=clock, rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.limited")
    await _call(service, identities, "homelab-agent", "demo.limited")
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped(reason="user_stopped"))
    assert resp["action"] == "suppressed"
    clock.now += 120
    await service.recovery.tick()
    assert hermes["homelab"].continue_calls == []
    assert _incidents(service)[0]["outcome"] == "suppressed:user_stopped"


async def test_status_reported_user_stop_is_never_overridden(env, hermes):
    clock = Clock()
    service, identities, _ = env(clock=clock, rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.limited")
    await _call(service, identities, "homelab-agent", "demo.limited")
    hermes["homelab"].state().update(stop_reason="user_stopped")  # stop event never arrived
    clock.now += 61
    await service.recovery.tick()
    assert hermes["homelab"].continue_calls == []
    assert _incidents(service)[0]["outcome"] == "suppressed:user_stopped"


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
    assert "blocker" not in body  # FR-7.7

    _, other = await _call(service, identities, "personal-agent", "demo.nope",
                           session="sess-p", task="task-p")
    assert _note(other)["guidance"] == body["guidance"]

    _, resp = await service.recovery.handle_event(
        "personal-agent", _stopped(session_id="sess-p", task_id="task-p"))
    assert resp["action"] == "none"
    assert hermes["personal"].continue_calls == [] and rescue.calls == []
    assert {i["outcome"] for i in _incidents(service)} == {"blocked:permission"}


# -- 4. Timed-out, maybe-running mutation is not duplicated ---------------------


async def test_unknown_outcome_holds_an_exact_repeat_until_status_checked(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    result, note = await _call(service, identities, "homelab-agent", "demo.slowwrite",
                               {"stack": "media"})
    assert result.outcome == OUTCOME_UNKNOWN
    assert _note(note)["action"] == "check_status_first"

    denial, _ = await _call(service, identities, "homelab-agent", "demo.slowwrite",
                            {"stack": "media"})
    assert denial.reason is DenialReason.RECOVERY_HOLD
    lines = [json.loads(line) for line in open(os.path.join(
        service.tier1.audit_dir, "audit.jsonl"), encoding="utf-8")]
    runs = [r for r in lines if r["kind"] == "call" and r["tool"] == "demo.slowwrite"]
    assert [r["outcome"] for r in runs] == ["unknown", "denied"]

    await _call(service, identities, "homelab-agent", "demo.read")
    corr = _corr(service, "homelab-agent")
    assert service.recovery.hold(corr, tool_id="demo.slowwrite", scopes=["stack:media"]) is None


# -- 5. Continuation: same session, staged evidence ------------------------------


async def test_continuation_resumes_the_original_session_with_staged_evidence(env, hermes, rescue):
    clock = Clock()
    service, identities, _ = env(clock=clock)
    fake = hermes["homelab"]
    incident = await _continued(service, identities, hermes)
    [sent] = fake.continue_calls
    assert (sent["session_id"], sent["board_id"], sent["task_id"]) == ("sess-1", BOARD, "task-1")
    assert sent["profile"] == "orchestrator" and sent["expected_turn_seq"] == 1
    assert "Suggested next step (untrusted advice)" in sent["guidance"]
    assert incident["status"] == "accepted"
    assert incident["continuation"]["continuation_id"] == "cont-1"

    await service.recovery.tick()  # started: status names our continuation_id
    assert _incidents(service)[0]["continuation"]["started_at"]

    # activity: an executed call carrying the continuation_id
    await _call(service, identities, "homelab-agent", "demo.read", turn_seq=2,
                continuation_id="cont-1")
    incident = _incidents(service)[0]
    assert incident["status"] == "active"  # activity is not recovery

    clock.now += 2
    await service.recovery.tick()
    assert _incidents(service)[0]["status"] == "active"  # no progress reported yet
    fake.state()["last_progress_at"] = clock.now + 1
    clock.now += 2
    await service.recovery.tick()
    assert _incidents(service)[0]["outcome"] == "recovered"

    _, resp = await service.recovery.handle_event("homelab-agent", _event("task_completed"))
    assert _incidents(service)[0]["outcome"] == "resolved"


async def test_activity_requires_the_continuation_id_on_an_executed_call(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    await _continued(service, identities, hermes)
    # A new turn without our continuation_id -- e.g. the user's own message.
    await _call(service, identities, "homelab-agent", "demo.read", turn_seq=3)
    # Our continuation_id, but denied: not execution.
    await _call(service, identities, "homelab-agent", "demo.fail", {"target": "NAS!"},
                turn_seq=2, continuation_id="cont-1")
    assert _incidents(service)[0]["status"] == "accepted"
    await _call(service, identities, "homelab-agent", "demo.read", turn_seq=3,
                continuation_id="cont-1")
    assert _incidents(service)[0]["status"] == "active"


async def test_no_executed_call_before_the_deadline_is_unacknowledged(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock,
                                 recovery_extra={"ack_timeout_seconds": 30})
    await _continued(service, identities, hermes)
    clock.now += 31
    await service.recovery.tick()
    assert _incidents(service)[0]["outcome"] == "unacknowledged"


async def test_activity_without_progress_hits_the_progress_deadline(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock,
                                 recovery_extra={"progress_timeout_seconds": 100})
    await _continued(service, identities, hermes)
    await _call(service, identities, "homelab-agent", "demo.read", turn_seq=2,
                continuation_id="cont-1")
    clock.now += 101
    await service.recovery.tick()
    assert _incidents(service)[0]["outcome"] == "blocked:no_progress_after_continuation"


# -- Races and ambiguous delivery ------------------------------------------------


async def test_user_message_before_continuation_wins(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    # The user typed something: a new turn is already running.
    fake.state().update(turn="active", turn_seq=2)
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "turn_active"
    assert fake.continue_calls == []
    assert _incidents(service)[0]["status"] == "guided"


async def test_user_message_racing_the_continuation_is_not_overridden(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="exhausted")
    fake.user_turn_on_continue = True  # lands between /status and /continue
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "turn_active"
    [incident] = _incidents(service)
    assert incident["status"] == "guided"
    assert incident["continuation"]["status"] == "superseded"
    ledger = service.recovery.store.read(lambda d: list(d["tasks"].values()))[0]
    assert ledger["recoveries"] == 1  # the guidance only; the rejected continue cost nothing


async def test_crash_after_processing_before_ack_queries_instead_of_resending(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock,
                                 recovery_extra={"adapter_timeout_seconds": 0.5})
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="exhausted")
    fake.continue_delay = 1.5  # Hermes processes it, the reply never arrives in time
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "uncertain"
    fake.continue_delay = 0
    clock.now += 1
    await service.recovery.tick()
    assert len(fake.query_calls) == 1
    assert len(fake.continue_calls) == 1  # asked, did not re-send
    incident = _incidents(service)[0]
    assert incident["status"] == "accepted"
    assert incident["continuation"]["continuation_id"] == "cont-1"


async def test_gatekeeper_crash_mid_send_resends_once_with_the_same_key(env, hermes, tmp_path):
    clock = Clock()
    state = str(tmp_path / "recovery.yaml")
    service, identities, _ = env(rescue_enabled=False, clock=clock, state=state)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="exhausted")
    inc_id = _incidents(service)[0]["id"]
    # Simulate: "sending" persisted, then the process died before the POST.
    service.recovery.store.mutate(lambda d: d["incidents"][inc_id].update(
        status="continuing", continuation={"status": "sending", "idempotency_key": f"{inc_id}:1",
                                           "expected_turn_seq": 1, "sent_at": clock.now,
                                           "resends": 0, "queries": 0}))
    service.recovery = env.make_supervisor(service, state, clock)
    clock.now += 3
    await service.recovery.tick()
    assert len(fake.query_calls) == 1 and len(fake.continue_calls) == 1
    assert fake.continue_calls[0]["idempotency_key"] == f"{inc_id}:1"
    assert _incidents(service)[0]["status"] == "accepted"


async def test_duplicate_continuation_after_restart_is_not_sent(env, hermes, tmp_path):
    state = str(tmp_path / "recovery.yaml")
    service, identities, _ = env(rescue_enabled=False, state=state)
    await _continued(service, identities, hermes)
    service.recovery = env.make_supervisor(service, state)  # restart
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "none" and resp["reason"] == "continuation in progress"
    await service.recovery.tick()
    assert len(hermes["homelab"].continue_calls) == 1


async def test_crash_without_a_stop_event_is_reconciled(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock,
                                 recovery_extra={"reconcile_after_seconds": 600})
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="stopped", stop_reason="error")  # Hermes died; no event
    await service.recovery.tick()
    assert fake.continue_calls == []
    clock.now += 601
    await service.recovery.tick()
    assert len(fake.continue_calls) == 1


# -- 6. Duplicate events ---------------------------------------------------------


async def test_duplicate_events_produce_one_recovery_and_one_continuation(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    for event in ("evt-a", "evt-a", "evt-b", "evt-b"):
        await _fail(service, identities, 1, event_id=event)
    [incident] = _incidents(service)
    assert len(incident["attempts"]) == 2

    stop = _stopped()
    results = await asyncio.gather(
        service.recovery.handle_event("homelab-agent", stop),
        service.recovery.handle_event("homelab-agent", dict(stop)),
        service.recovery.handle_event("homelab-agent", _stopped()),
    )
    assert sorted(r[1]["action"] for r in results).count("continued") == 1
    assert len(fake.continue_calls) == 1


# -- 7. Restart preserves cooldowns and duplicate protection ----------------------


async def test_restart_preserves_cooldown_and_dedup(env, hermes, tmp_path):
    clock = Clock()
    state = str(tmp_path / "recovery.yaml")
    service, identities, _ = env(clock=clock, rescue_enabled=False, state=state)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.limited", event_id="e1")
    await _call(service, identities, "homelab-agent", "demo.limited", event_id="e2")
    stop = _stopped()
    await service.recovery.handle_event("homelab-agent", stop)
    [before] = _incidents(service)
    assert before["status"] == "cooling"

    service.recovery = env.make_supervisor(service, state, clock)
    [after] = _incidents(service)
    assert after["cooldown_until"] == before["cooldown_until"]
    _, resp = await service.recovery.handle_event("homelab-agent", stop)
    assert resp["duplicate"] is True
    _, note = await _call(service, identities, "homelab-agent", "demo.limited", event_id="e2")
    assert note is None

    await service.recovery.tick()
    assert fake.continue_calls == []
    clock.now += 61
    await service.recovery.tick()
    assert len(fake.continue_calls) == 1
    service.recovery = env.make_supervisor(service, state, clock)
    clock.now += 5
    await service.recovery.tick()
    assert len(fake.continue_calls) == 1


# -- 8. Completed / cancelled / reopened ------------------------------------------


async def test_completed_task_is_not_resumed(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")
    await _fail(service, identities, 1)
    _, resp = await service.recovery.handle_event("homelab-agent", _event("task_completed"))
    assert resp["action"] == "suppressed"
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "none"
    assert await _fail(service, identities, 2) is None
    assert hermes["homelab"].continue_calls == []


async def test_worker_completion_does_not_close_the_parent(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-parent", turn="active")
    await _fail(service, identities, 2, task="task-parent")
    _, resp = await service.recovery.handle_event(
        "homelab-agent", _event("task_completed", task_id="task-worker"))
    assert resp["action"] == "none"
    assert _incidents(service)[0]["status"] == "guided"
    fake.state(task_id="task-parent").update(turn="exhausted")
    _, resp = await service.recovery.handle_event(
        "homelab-agent", _stopped(task_id="task-parent"))
    assert resp["action"] == "continued"


async def test_reopened_task_starts_a_new_lifecycle(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 1)
    await service.recovery.handle_event("homelab-agent", _event("task_completed"))
    assert await _fail(service, identities, 2) is None  # generation 0 stays closed
    note = await _fail(service, identities, 2, task_generation=1)
    assert _note(note)["action"] == "change_approach"
    # A late terminal event for generation 0 does not close generation 1.
    _, resp = await service.recovery.handle_event(
        "homelab-agent", _event("task_cancelled", task_generation=0))
    assert resp["reason"] == "older task generation"


async def test_cancelled_task_reported_by_status_is_suppressed(env, hermes, rescue):
    service, identities, _ = env()
    hermes["homelab"].session("sess-1", "task-1", task="cancelled")
    assert await _fail(service, identities, 2) is None
    assert _incidents(service)[0]["outcome"] == "suppressed:cancelled"
    assert rescue.calls == [] and hermes["homelab"].continue_calls == []


# -- 9. Rescue failure ---------------------------------------------------------------


async def test_rescue_failure_ends_within_budget_as_blocked(env, hermes, rescue):
    service, identities, _ = env(rescue_timeout=1)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    rescue.mode = "slow"
    await _fail(service, identities, 1)
    started = time.monotonic()
    note = await _fail(service, identities, 1)
    assert time.monotonic() - started < 2.5
    assert _note(note)["action"] == "blocked"
    [incident] = _incidents(service)
    assert incident["outcome"] == "blocked:rescue_failed"


async def test_unlisted_rescue_model_disables_rescue(env, hermes, rescue):
    service, identities, _ = env(rescue_enabled=False)
    service.tier1 = service.tier1.__class__(**{
        **{f: getattr(service.tier1, f) for f in service.tier1.__dataclass_fields__},
        "recovery": parse_config({
            "enabled": True,
            "installations": {"homelab": {"identities": ["homelab-agent"]}},
            "rescue": {"enabled": True, "base_url": rescue.url, "model": "made-up-model",
                       "credential": "rescue-key"},
        }),
    })
    await _fail(service, identities, 1)
    assert _note(await _fail(service, identities, 1))["action"] == "change_approach"
    assert rescue.calls == []


# -- 10. Installations stay apart ------------------------------------------------------


async def test_installations_cannot_resume_each_other(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")
    hermes["personal"].session("sess-1", "task-1")
    await _fail(service, identities, 2)
    _, resp = await service.recovery.handle_event("personal-agent", _stopped())
    assert resp["action"] == "none"
    assert service.recovery.incidents_for("personal-agent") == []
    assert hermes["homelab"].continue_calls == hermes["personal"].continue_calls == []
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "continued"
    assert hermes["homelab"].continue_calls[0]["installation"] == "homelab"
    assert hermes["personal"].continue_calls == []


# -- v1 coverage limit ------------------------------------------------------------------


async def test_exhaustion_without_a_prior_incident_is_not_recovered_in_v1(env, hermes):
    service, _, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1")
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "none" and "not recovered in v1" in resp["reason"]
    assert hermes["homelab"].status_calls == [] and hermes["homelab"].continue_calls == []


# -- Bounds, redaction -------------------------------------------------------------------


async def test_recoveries_per_task_are_bounded_across_incidents(env, hermes):
    service, identities, _ = env(rescue_enabled=False,
                                 recovery_extra={"max_recoveries_per_task": 1})
    fake = hermes["homelab"]
    state = fake.session("sess-1", "task-1", turn="active", last_progress_at=time.time() + 1e6)

    async def fail(target):
        return (await _call(service, identities, "homelab-agent", "demo.fail",
                            {"target": target}))[1]

    assert await fail("nas") is None and await fail("nas") is None
    state["last_progress_at"] = 0
    assert await fail("nas") is None
    assert _note(await fail("nas"))["action"] == "change_approach"
    assert await fail("abc") is None
    assert _note(await fail("abd"))["action"] == "blocked"
    assert await fail("abe") is None
    assert _note(await fail("abf"))["action"] == "blocked"
    assert [i["outcome"] for i in _incidents(service)] == [
        "progressed", "blocked:recovery_budget_exhausted", "blocked:recovery_budget_exhausted"]


async def test_secrets_never_reach_the_state_file(env, hermes, tmp_path):
    service, identities, _ = env(rescue_enabled=False)
    await _fail(service, identities, 1)
    text = (tmp_path / "recovery.yaml").read_text(encoding="utf-8")
    assert "supersecret123" not in text and "api_token=***" in text


def test_scrub_masks_foreign_secret_shapes():
    out = scrub("Authorization: Bearer abcdefghijkl password=hunter22 sk-abcdefghijklmnop")
    assert "abcdefghijkl" not in out and "hunter22" not in out and "sk-abcdefgh" not in out


# -- Optional decision provider (mock contract only; no Jev provider exists) -------------


class MockDecider:
    version = "mock-1"

    def __init__(self, answer=None, delay=0.0, error=None):
        self.answer = answer
        self.delay = delay
        self.error = error
        self.requests: list[dict] = []

    async def decide(self, request, *, max_tokens):
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return self.answer


@pytest.fixture
def decider(monkeypatch):
    holder = {}
    monkeypatch.setitem(recovery.DECISION_PROVIDERS, "mock", lambda cfg, secret: holder["d"])

    def use(decider_obj, mode="active", **extra):
        holder["d"] = decider_obj
        return {"decision": {"enabled": True, "provider": "mock", "model": "mock-model",
                             "mode": mode, "timeout_seconds": 0.5, **extra}}
    return use


async def test_decision_is_off_by_default_and_never_consulted(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    assert _note(await _fail(service, identities, 2))["action"] == "change_approach"
    assert "decision" not in _incidents(service)[0]


async def test_decision_allowed_action_is_applied_and_logged_without_the_prompt(env, hermes, decider):
    d = MockDecider({"action": "CHECK_OPERATION_STATUS", "rationale": "state unclear",
                     "evidence": ["two identical failures"]})
    service, identities, _ = env(rescue_enabled=False, recovery_extra=decider(d))
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    body = _note(await _fail(service, identities, 2))
    assert body["action"] == "check_status_first"
    request = d.requests[0]
    assert "CONSULT_RESCUE" not in request["allowed_actions"]  # rescue is off here
    assert "supersecret123" not in json.dumps(request)
    record = _incidents(service)[0]["decision"]
    assert (record["proposed"], record["accepted"]) == ("CHECK_OPERATION_STATUS",
                                                       "CHECK_OPERATION_STATUS")
    audit = open(os.path.join(service.tier1.audit_dir, "audit.jsonl"), encoding="utf-8").read()
    line = next(json.loads(x) for x in audit.splitlines() if '"recovery.decision"' in x)
    assert line["provider"] == "mock" and line["provider_version"] == "mock-1"
    assert "failed_attempts" not in json.dumps(line)


async def test_decision_conflicting_with_fixed_rules_is_rejected(env, hermes, decider):
    d = MockDecider({"action": "CONSULT_RESCUE", "rationale": "deeper look", "evidence": []})
    service, identities, _ = env(rescue_enabled=False, recovery_extra=decider(d))
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    assert _note(await _fail(service, identities, 2))["action"] == "change_approach"
    record = _incidents(service)[0]["decision"]
    assert record["accepted"] == "CHANGE_APPROACH" and record["fallback"].startswith("rejected")


@pytest.mark.parametrize("bad", [
    MockDecider({"action": "RUN_COMMAND", "rationale": "x", "evidence": []}),
    MockDecider({"action": "WAIT"}),
    MockDecider("not json"),
    MockDecider(error=RuntimeError("down")),
    MockDecider({"action": "REPORT_BLOCKED", "rationale": "x", "evidence": []}, delay=2),
])
async def test_invalid_slow_or_failing_decisions_fall_back_deterministically(env, hermes, decider, bad):
    service, identities, _ = env(rescue_enabled=False, recovery_extra=decider(bad))
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    started = time.monotonic()
    assert _note(await _fail(service, identities, 2))["action"] == "change_approach"
    assert time.monotonic() - started < 2.0
    assert _incidents(service)[0]["decision"]["accepted"] == "CHANGE_APPROACH"


async def test_shadow_mode_logs_but_applies_the_deterministic_choice(env, hermes, decider):
    d = MockDecider({"action": "REPORT_BLOCKED", "rationale": "x", "evidence": []})
    service, identities, _ = env(rescue_enabled=False, recovery_extra=decider(d, mode="shadow"))
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    assert _note(await _fail(service, identities, 2))["action"] == "change_approach"
    record = _incidents(service)[0]["decision"]
    assert (record["proposed"], record["accepted"]) == ("REPORT_BLOCKED", "CHANGE_APPROACH")


async def test_decision_never_sees_permission_cooldown_or_unknown_outcomes(env, hermes, decider):
    d = MockDecider({"action": "CHANGE_APPROACH", "rationale": "x", "evidence": []})
    service, identities, _ = env(rescue_enabled=False, recovery_extra=decider(d))
    await _call(service, identities, "personal-agent", "demo.fail", {"target": "nas"},
                session="sess-p", task="task-p")
    await _call(service, identities, "homelab-agent", "demo.limited", task="task-2")
    await _call(service, identities, "homelab-agent", "demo.limited", task="task-2")
    await _call(service, identities, "homelab-agent", "demo.slowwrite", {"stack": "media"},
                task="task-3")
    assert d.requests == []


async def test_decision_calls_are_capped(env, hermes, decider):
    d = MockDecider({"action": "CHANGE_APPROACH", "rationale": "x", "evidence": []})
    service, identities, _ = env(rescue_enabled=False, recovery_extra=decider(d, max_per_hour=1))
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    hermes["homelab"].session("sess-1", "task-2", turn="active")
    await _fail(service, identities, 2)
    await _fail(service, identities, 2, task="task-2")
    assert len(d.requests) == 1
    assert _incidents(service)[1]["decision"]["fallback"] == "hourly limit"


# -- End to end over MCP + HTTP --------------------------------------------------------


async def test_end_to_end_over_mcp_and_the_events_route(env, hermes):
    service, identities, tokens = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    app = build_app(service=service, identities=identities, audit=service.audit)
    base = "http://gatekeeper.test"
    headers = {"Authorization": f"Bearer {tokens['homelab-agent']}"}
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),
                                      base_url=base, headers=headers, timeout=30) as http:
            transport = streamable_http_client(f"{base}/mcp", http_client=http)
            async with Client(transport) as client:
                await client.call_tool("demo.fail", {"target": "nas"}, meta=_meta("homelab-agent"))
                second = await client.call_tool("demo.fail", {"target": "nas"},
                                                meta=_meta("homelab-agent"))
            text = second.content[0].text
            assert second.is_error and '"action": "change_approach"' in text

            fake.state().update(turn="exhausted")
            response = await http.post("/recovery/events", json=_stopped())
            assert response.status_code == 200 and response.json()["action"] == "continued"
            listed = (await http.get("/recovery/incidents?task_id=task-1")).json()["incidents"]
            assert listed[0]["continuation_id"] == "cont-1"

            for _ in range(40):
                await asyncio.sleep(0.05)
                if _incidents(service)[0]["continuation"].get("started_at"):
                    break
            assert _incidents(service)[0]["continuation"]["started_at"]

        anonymous = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=base)
        async with anonymous:
            assert (await anonymous.post("/recovery/events", json=_stopped())).status_code == 401


# -- Contract v1.1: reserved-argument correlation, durable "started" ------------------


def test_catalog_refuses_the_reserved_parameter_name(tmp_path, tier1):
    spec = {"id": "demo.x", "toolkit": "demo", "binary": PYTHON, "version": 1, "title": "x",
            "description": "x", "category": "read", "idempotent": True, "enabled": True,
            "argv": ["-c", "print(1)"], "required_scopes": [], "timeout_seconds": 5,
            "max_output_bytes": 100,
            "parameters": {recovery.RESERVED_ARGUMENT: {"type": "string", "description": "x"}}}
    catalog = make_catalog(tmp_path, tier1, [spec], strict=False)
    assert "demo.x" not in catalog.tools


async def _mcp_call(app, token, tool, args):
    base = "http://gatekeeper.test"
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=base,
                                  headers={"Authorization": f"Bearer {token}"}, timeout=30) as http:
        async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as client:
            return await client.call_tool(tool, args)


async def test_reserved_argument_carries_the_correlation_and_is_never_a_parameter(env, hermes):
    service, identities, tokens = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    app = build_app(service=service, identities=identities, audit=service.audit)
    async with app.router.lifespan_context(app):
        for _ in range(2):
            args = {"target": "nas", recovery.RESERVED_ARGUMENT: _meta("homelab-agent")["hermes"]}
            result = await _mcp_call(app, tokens["homelab-agent"], "demo.fail", args)
    assert '"action": "change_approach"' in result.content[0].text
    audit = open(os.path.join(service.tier1.audit_dir, "audit.jsonl"), encoding="utf-8").read()
    calls = [json.loads(x) for x in audit.splitlines() if '"kind": "call"' in x]
    assert calls and all(recovery.RESERVED_ARGUMENT not in c["parameters"] for c in calls)
    assert all(c["outcome"] == "failed" for c in calls)  # executed, not PARAM_UNKNOWN


async def test_reserved_argument_is_stripped_while_recovery_is_off(env):
    service, identities, tokens = env(recovery_extra={"enabled": False})
    app = build_app(service=service, identities=identities, audit=service.audit)
    async with app.router.lifespan_context(app):
        result = await _mcp_call(app, tokens["homelab-agent"], "demo.read",
                                 {recovery.RESERVED_ARGUMENT: {"session_id": "x"}})
    assert not result.is_error and "stack ok" in result.content[0].text


async def test_started_is_proven_by_the_durable_record_after_the_turn_ended(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock)
    await _continued(service, identities, hermes)
    # The resumed turn ran and ended before Gatekeeper's next poll.
    hermes["homelab"].state().update(
        turn="stopped", stop_reason="final_reply", continuation_id=None,
        last_continuation={"continuation_id": "cont-1", "state": "finished",
                           "started_at": clock.now, "started_turn_seq": 2,
                           "ended_at": clock.now + 1, "exit_reason": "final_reply"})
    clock.now += 2
    await service.recovery.tick()
    assert _incidents(service)[0]["continuation"]["started_at"]


async def test_continuation_query_reporting_started_counts_as_started(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock,
                                 recovery_extra={"adapter_timeout_seconds": 0.5})
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="exhausted")
    fake.continue_delay = 1.5
    await service.recovery.handle_event("homelab-agent", _stopped())
    fake.continue_delay = 0
    key = next(iter(fake.deliveries))
    fake.deliveries[key].update(state="started", started_at=clock.now)
    clock.now += 1
    await service.recovery.tick()
    cont = _incidents(service)[0]["continuation"]
    assert _incidents(service)[0]["status"] == "accepted" and cont["started_at"]


# -- Integrity and recovery ownership (contract v1.1) ----------------------------------


async def _mcp_call_meta(app, token, tool, args, meta=None):
    base = "http://gatekeeper.test"
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=base,
                                  headers={"Authorization": f"Bearer {token}"}, timeout=30) as http:
        async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as client:
            return await client.call_tool(tool, args, meta=meta)


async def test_conflicting_carriers_give_no_recovery_but_the_call_still_runs(env, hermes):
    service, identities, tokens = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    app = build_app(service=service, identities=identities, audit=service.audit)
    async with app.router.lifespan_context(app):
        for _ in range(2):
            meta = _meta("homelab-agent")
            other = dict(meta["hermes"], session_id="sess-other")
            result = await _mcp_call_meta(app, tokens["homelab-agent"], "demo.fail",
                                          {"target": "nas", recovery.RESERVED_ARGUMENT: other}, meta)
    assert "[gatekeeper recovery]" not in result.content[0].text
    assert "connection refused" in result.content[0].text  # executed normally
    assert _incidents(service) == []


async def test_identical_carriers_are_accepted(env, hermes):
    service, identities, tokens = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    app = build_app(service=service, identities=identities, audit=service.audit)
    async with app.router.lifespan_context(app):
        for _ in range(2):
            meta = _meta("homelab-agent")
            result = await _mcp_call_meta(app, tokens["homelab-agent"], "demo.fail",
                                          {"target": "nas", recovery.RESERVED_ARGUMENT: meta["hermes"]},
                                          meta)
    assert '"action": "change_approach"' in result.content[0].text


def test_null_reserved_value_is_no_correlation(env):
    service, _, _ = env()
    assert service.recovery.correlate_call("homelab-agent", None, None) is None
    meta = _meta("homelab-agent")
    assert service.recovery.correlate_call("homelab-agent", None, meta["hermes"]) is not None


async def test_open_incident_is_pinned_to_its_session(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 1)
    assert await _fail(service, identities, 3, session="sess-intruder") is None
    [incident] = _incidents(service)
    assert len(incident["attempts"]) == 1 and incident["session_id"] == "sess-1"


async def test_mapping_failure_at_threshold_blocks_recovery(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    # No adapter session: /status answers 404 for this reference.
    note = await _fail(service, identities, 2)
    assert _note(note)["action"] == "blocked"
    assert _incidents(service)[0]["outcome"] == "blocked:session_mapping_failed"


async def test_status_echo_mismatch_is_a_mapping_failure(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    hermes["homelab"].session("sess-1", "task-1", turn="active")
    hermes["homelab"].echo_override = {"task_id": "task-other"}
    await _fail(service, identities, 2)
    assert _incidents(service)[0]["outcome"] == "blocked:session_mapping_failed"


async def test_hermes_internal_recovery_defers_the_continuation(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="exhausted", recovery_owner="hermes",
                        recovery_until=clock.now + 45)
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "internal_recovery"
    assert fake.continue_calls == []
    ledger = service.recovery.store.read(lambda d: list(d["tasks"].values()))[0]
    assert ledger["recoveries"] == 1  # the guidance only
    clock.now += 20
    await service.recovery.tick()
    assert fake.continue_calls == []  # still inside Hermes's backoff
    fake.state().update(recovery_owner=None, recovery_until=None)
    clock.now += 30
    await service.recovery.tick()
    assert len(fake.continue_calls) == 1


async def test_continue_rejected_for_internal_recovery_waits_it_out(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="exhausted")
    fake.internal_recovery_until = clock.now + 90
    _, resp = await service.recovery.handle_event("homelab-agent", _stopped())
    assert resp["action"] == "internal_recovery"
    assert _incidents(service)[0]["status"] == "cooling"
    fake.internal_recovery_until = None
    clock.now += 91
    await service.recovery.tick()
    assert _incidents(service)[0]["status"] == "accepted"


async def test_hermes_owned_session_without_deadline_is_left_to_hermes(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="exhausted", recovery_owner="hermes")
    await service.recovery.handle_event("homelab-agent", _stopped())
    assert _incidents(service)[0]["outcome"] == "suppressed:hermes_recovery_owner"
    assert fake.continue_calls == []


# -- Unmapped exits, reserved name scope ---------------------------------------------


async def test_unmapped_exit_is_accepted_but_never_continued(env, hermes):
    service, identities, _ = env(rescue_enabled=False)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1", turn="active")
    await _fail(service, identities, 2)
    fake.state().update(turn="stopped", stop_reason="unmapped")
    code, resp = await service.recovery.handle_event("homelab-agent", _stopped(reason="unmapped"))
    assert code == 200 and resp["action"] == "none"
    assert fake.continue_calls == [] and fake.status_calls[-1:] != []  # status was only the threshold check
    assert _incidents(service)[0]["status"] == "guided"


async def test_unmapped_exit_withdraws_a_cooldown_continuation(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.limited")
    await _call(service, identities, "homelab-agent", "demo.limited")
    assert _incidents(service)[0]["status"] == "cooling"
    await service.recovery.handle_event("homelab-agent", _stopped(reason="unmapped"))
    clock.now += 120
    await service.recovery.tick()
    assert fake.continue_calls == []


async def test_status_reporting_unmapped_blocks_reconcile_and_cooldown_paths(env, hermes):
    clock = Clock()
    service, identities, _ = env(rescue_enabled=False, clock=clock)
    fake = hermes["homelab"]
    fake.session("sess-1", "task-1")
    await _call(service, identities, "homelab-agent", "demo.limited")
    await _call(service, identities, "homelab-agent", "demo.limited")
    fake.state().update(turn="stopped", stop_reason="unmapped")  # stop event never arrived
    clock.now += 61
    await service.recovery.tick()
    assert fake.continue_calls == []


def test_only_the_exact_reserved_name_is_refused(tmp_path, tier1):
    base = {"toolkit": "demo", "binary": PYTHON, "version": 1, "title": "x", "description": "x",
            "category": "read", "idempotent": True, "enabled": True, "argv": ["-c", "print(1)"],
            "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 100}
    ok = {**base, "id": "demo.underscored",
          "parameters": {"_internal_flag": {"type": "string", "pattern": "^[a-z]+$", "description": "legit"},
                         "_hermes_recovery_x": {"type": "string", "pattern": "^[a-z]+$", "description": "legit"}}}
    catalog = make_catalog(tmp_path, tier1, [ok])
    assert "demo.underscored" in catalog.tools
