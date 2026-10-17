"""The `kuma` executor: Uptime Kuma monitors over Socket.IO.

Against a real Socket.IO-over-WebSocket server on loopback, speaking the
Engine.IO v4 framing Kuma's own server does -- not a mocked send(). What
matters here is what goes on the wire (no delete, no foreign monitor, no
secret coming back) and that is exactly what a mock would assume away.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import websockets
import yaml
from conftest import make_catalog

from gatekeeper import execute_kuma
from gatekeeper.audit import AuditLog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.errors import ConfigError, Denied
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

PASSWORD = "kuma-secret-pw-123"
FOREIGN_SECRET = "hand-made-basic-auth-secret"


class FakeKuma:
    """Kuma's socket API as far as this executor uses it."""

    def __init__(self) -> None:
        self.version = "1.23.16"
        self.two_factor = False
        self.stall: str | None = None
        self.received: list[tuple[str, list]] = []
        self.monitors: dict[int, dict] = {
            1: {
                "id": 1, "name": "Router", "type": "http", "active": 1, "interval": 60,
                "url": f"https://admin:{FOREIGN_SECRET}@router.lan/status?token={FOREIGN_SECRET}",
                "basic_auth_pass": FOREIGN_SECRET, "headers": '{"X-Key": "' + FOREIGN_SECRET + '"}',
                "description": "set up by hand",
            },
            2: {
                "id": 2, "name": "Blog", "type": "http", "active": 1, "interval": 300,
                "url": "https://blog.example.org/", "description": "Managed by gatekeeper (toolkit kuma)",
            },
        }

    async def handler(self, ws):
        await ws.send('0{"sid":"e1","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}')
        logged_in = False
        async for frame in ws:
            if frame == "40":
                await ws.send('40{"sid":"s1"}')
                await ws.send('42["info",{"primaryBaseURL":null}]')
                # A server ping mid-session must be answered, not mistaken for data.
                await ws.send("2")
                continue
            if frame == "3" or not frame.startswith("42"):
                continue
            body = frame[2:]
            digits = len(body) - len(body.lstrip("0123456789"))
            ack, args = body[:digits], json.loads(body[digits:])
            event, rest = args[0], args[1:]
            self.received.append((event, rest))
            if self.stall == event:
                await asyncio.sleep(10)
            if event == "login":
                creds = rest[0]
                if creds["username"] != "gk" or creds["password"] != PASSWORD:
                    answer = {"ok": False, "msg": "Incorrect username or password."}
                elif self.two_factor and not creds.get("token"):
                    answer = {"tokenRequired": True}
                else:
                    logged_in = True
                    answer = {"ok": True, "token": "jwt"}
                await ws.send(f"43{ack}" + json.dumps([answer]))
                if logged_in:
                    await ws.send('42' + json.dumps(["monitorList", {str(k): v for k, v in self.monitors.items()}]))
                    await ws.send('42' + json.dumps(["info", {"version": self.version}]))
                continue
            if not logged_in:
                await ws.send(f"43{ack}" + json.dumps([{"ok": False, "msg": "You are not logged in."}]))
                continue
            if event == "add":
                new_id = max(self.monitors) + 1
                self.monitors[new_id] = {**rest[0], "id": new_id, "active": 1}
                answer = {"ok": True, "msg": "Added Successfully.", "monitorID": new_id}
            elif event == "getMonitor":
                monitor = self.monitors.get(rest[0])
                answer = {"ok": True, "monitor": monitor} if monitor else {
                    "ok": False, "msg": "Cannot read properties of null"}
            elif event in ("pauseMonitor", "resumeMonitor"):
                self.monitors[rest[0]]["active"] = 0 if event == "pauseMonitor" else 1
                answer = {"ok": True, "msg": "Done."}
            else:
                answer = {"ok": False, "msg": "unexpected"}
            await ws.send(f"43{ack}" + json.dumps([answer]))

    @property
    def events(self) -> list[str]:
        return [name for name, _ in self.received]


@pytest.fixture
async def kuma():
    fake = FakeKuma()
    server = await websockets.serve(fake.handler, "127.0.0.1", 0)
    fake.port = server.sockets[0].getsockname()[1]
    yield fake
    server.close()
    await server.wait_closed()


ALL_OPS = ["monitor_list", "monitor_add_http", "monitor_pause", "monitor_resume"]


def _tier1(tmp_path, port, **overrides):
    spec = {
        "executor": "kuma", "base_url": f"http://127.0.0.1:{port}",
        "allowed_cidrs": ["127.0.0.1/32"], "credential": "kuma",
        "allowed_kuma_operations": ALL_OPS, "max_timeout_seconds": 30, **overrides,
    }
    path = tmp_path / "toolkits.yaml"
    path.write_text(yaml.safe_dump({"toolkits": {"kuma": spec}, "audit": {"dir": str(tmp_path / "logs")}}),
                    encoding="utf-8")
    return load_tier1(str(path))


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=AuditLog(str(tmp_path / "clogs")))
    store.create("kuma", kind="basic", value=f"gk:{PASSWORD}", actor="test", rev="")
    return store


async def _run(toolkit, credentials, operation, values=None, *, timeout=5, idempotent=None):
    return await execute_kuma.run(
        operation=operation, values=values or {}, toolkit=toolkit, credentials=credentials,
        timeout_seconds=timeout, max_output_bytes=65536,
        idempotent=(operation == "monitor_list") if idempotent is None else idempotent,
    )


# -- Operations -----------------------------------------------------------------------


async def test_list_projects_monitors_and_leaks_no_secret(tmp_path, kuma, credentials):
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_list")
    assert result.outcome == OUTCOME_OK, result.stderr
    assert result.external_untrusted
    payload = json.loads(result.stdout)
    assert payload["count"] == 2
    router = next(m for m in payload["monitors"] if m["id"] == 1)
    assert router == {"id": 1, "name": "Router", "type": "http", "url": "https://router.lan/status",
                      "active": True, "interval": 60, "managed": False}
    assert next(m for m in payload["monitors"] if m["id"] == 2)["managed"] is True
    assert FOREIGN_SECRET not in result.stdout and PASSWORD not in result.stdout
    assert kuma.events == ["login"]


async def test_add_http_sends_a_fixed_http_monitor(tmp_path, kuma, credentials):
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_add_http", {
        "name": "Docs", "url": "https://docs.example.org/health", "interval": "120",
        "expected_status": "200-299"})
    assert result.outcome == OUTCOME_OK, result.stderr
    assert json.loads(result.stdout)["monitor_id"] == 3
    (sent,) = [args[0] for name, args in kuma.received if name == "add"]
    assert sent["type"] == "http" and sent["method"] == "GET"
    assert sent["url"] == "https://docs.example.org/health" and sent["interval"] == 120
    assert sent["accepted_statuscodes"] == ["200-299"]
    assert sent["notificationIDList"] == {}
    assert sent["description"].startswith(execute_kuma.MANAGED_MARKER)
    # A 1.x server has no column for these; sending them would fail the insert.
    assert "conditions" not in sent and "rabbitmqNodes" not in sent
    assert not {"headers", "body", "basic_auth_user", "basic_auth_pass"} & set(sent)


async def test_add_http_on_kuma_2_sends_its_extra_fields(tmp_path, kuma, credentials):
    kuma.version = "2.0.2"
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_add_http", {"name": "X", "url": "http://x.lan/"})
    assert result.outcome == OUTCOME_OK, result.stderr
    (sent,) = [args[0] for name, args in kuma.received if name == "add"]
    assert sent["conditions"] == [] and sent["rabbitmqNodes"] == []
    assert sent["interval"] == 60 and sent["accepted_statuscodes"] == ["200-299"]


async def test_pause_and_resume_a_managed_monitor(tmp_path, kuma, credentials):
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    paused = await _run(toolkit, credentials, "monitor_pause", {"monitor_id": "2"})
    assert paused.outcome == OUTCOME_OK, paused.stderr
    assert kuma.monitors[2]["active"] == 0
    resumed = await _run(toolkit, credentials, "monitor_resume", {"monitor_id": "2"})
    assert resumed.outcome == OUTCOME_OK and kuma.monitors[2]["active"] == 1


@pytest.mark.parametrize("operation", ["monitor_pause", "monitor_resume"])
async def test_a_foreign_monitor_is_refused_before_anything_is_sent(tmp_path, kuma, credentials, operation):
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, operation, {"monitor_id": "1"})
    assert result.outcome == OUTCOME_FAILED
    assert result.denial_reason == "tier1_violation"
    assert "not created through gatekeeper" in result.stderr
    assert kuma.events == ["login", "getMonitor"]
    assert kuma.monitors[1]["active"] == 1
    assert FOREIGN_SECRET not in result.stderr


async def test_missing_monitor_is_a_plain_failure(tmp_path, kuma, credentials):
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_pause", {"monitor_id": "99"})
    assert result.outcome == OUTCOME_FAILED and "does not exist" in result.stderr
    assert "pauseMonitor" not in kuma.events


# -- Login ----------------------------------------------------------------------------


async def test_wrong_password_fails_without_echoing_it(tmp_path, kuma, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    store = CredentialStore(path=str(tmp_path / "c.yaml"), audit=AuditLog(str(tmp_path / "cl")))
    store.create("kuma", kind="basic", value="gk:wrong-password-xyz", actor="t", rev="")
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, store, "monitor_list")
    assert result.outcome == OUTCOME_FAILED
    assert result.denial_reason == "credential_unavailable"
    assert "Incorrect username or password" in result.stderr
    assert "wrong-password-xyz" not in result.stderr + (result.denial_detail or "")


async def test_two_factor_account_is_refused_with_a_reason(tmp_path, kuma, credentials):
    kuma.two_factor = True
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_list")
    assert result.outcome == OUTCOME_FAILED and "2FA" in result.stderr


async def test_non_basic_credential_is_refused_before_connecting(tmp_path, kuma, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    store = CredentialStore(path=str(tmp_path / "c.yaml"), audit=AuditLog(str(tmp_path / "cl")))
    store.create("kuma", kind="bearer", value="token-abc", actor="t", rev="")
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, store, "monitor_list")
    assert result.outcome == OUTCOME_FAILED and "kind 'basic'" in result.stderr
    assert "login" not in kuma.events


# -- Floors that hold regardless of the tool definition ---------------------------------


async def test_operation_outside_the_toolkit_list_never_connects(tmp_path, kuma, credentials):
    toolkit = _tier1(tmp_path, kuma.port, allowed_kuma_operations=["monitor_list"]).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_add_http", {"name": "x", "url": "https://x.org/"})
    assert result.outcome == OUTCOME_FAILED and result.denial_reason == "tier1_violation"
    assert kuma.received == []


async def test_address_outside_allowed_cidrs_never_connects(tmp_path, kuma, credentials):
    toolkit = _tier1(tmp_path, kuma.port, allowed_cidrs=["10.0.0.0/8"]).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_list")
    assert result.outcome == OUTCOME_FAILED and result.denial_reason == "cidr_not_allowed"
    assert kuma.received == []


@pytest.mark.parametrize("values, fragment", [
    ({"name": "x", "url": "ftp://x.org/"}, "http(s) URL"),
    ({"name": "x", "url": "https://user:pw@x.org/"}, "user or password"),
    ({"name": "x", "url": "https://x.org/", "interval": "10"}, "interval"),
    ({"name": "x", "url": "https://x.org/", "interval": "86400"}, "interval"),
    ({"name": "x", "url": "https://x.org/", "expected_status": "500"}, "expected_status"),
    ({"name": " ", "url": "https://x.org/"}, "name"),
])
async def test_add_values_are_checked_by_the_executor_itself(tmp_path, kuma, credentials, values, fragment):
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_add_http", values)
    assert result.outcome == OUTCOME_FAILED and fragment in result.stderr
    assert result.denial_reason == "param_invalid"
    assert kuma.received == []


async def test_timeout_after_add_was_sent_is_unknown(tmp_path, kuma, credentials):
    kuma.stall = "add"
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_add_http",
                        {"name": "x", "url": "https://x.org/"}, timeout=1)
    assert result.outcome == OUTCOME_UNKNOWN and "UNKNOWN" in result.stderr


async def test_timeout_before_any_write_is_a_plain_failure(tmp_path, kuma, credentials):
    kuma.stall = "getMonitor"
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    result = await _run(toolkit, credentials, "monitor_pause", {"monitor_id": "2"}, timeout=1)
    assert result.outcome == OUTCOME_FAILED


async def test_probe_is_tcp_only(tmp_path, kuma):
    toolkit = _tier1(tmp_path, kuma.port).toolkit("kuma")
    assert await execute_kuma.probe(toolkit) is True
    assert kuma.received == []


# -- Tier 1 -----------------------------------------------------------------------------


@pytest.mark.parametrize("overrides, fragment", [
    ({"credential": None}, "needs 'credential'"),
    ({"allowed_kuma_operations": ["monitor_delete"]}, "unknown: ['monitor_delete']"),
    ({"allowed_kuma_operations": []}, "non-empty subset"),
    ({"allowed_cidrs": None}, "allowed_cidrs"),
    ({"base_url": "ws://127.0.0.1:3001"}, "base_url"),
])
def test_tier1_refuses_an_incomplete_kuma_toolkit(tmp_path, overrides, fragment):
    with pytest.raises(ConfigError, match=None) as exc:
        _tier1(tmp_path, 3001, **overrides)
    assert fragment in str(exc.value)


def test_kuma_toolkit_takes_allowed_hosts(tmp_path):
    toolkit = _tier1(tmp_path, 3001, base_url="https://kuma.example.org",
                     allowed_cidrs=None, allowed_hosts=["kuma.example.org"]).toolkit("kuma")
    assert toolkit.allowed_hosts == ("kuma.example.org",)


# -- Catalog ----------------------------------------------------------------------------

ADD_PARAMS = {
    "name": {"type": "string", "required": True, "pattern": "^[A-Za-z0-9 ._-]{1,80}$", "description": "name"},
    "url": {"type": "string", "required": True, "pattern": "^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$",
            "description": "url"},
    "interval": {"type": "integer", "minimum": 30, "maximum": 3600, "description": "seconds"},
    "expected_status": {"type": "enum", "values": ["200-299", "401"], "description": "status"},
}
ID_PARAM = {"monitor_id": {"type": "integer", "required": True, "minimum": 1, "description": "id"}}


def _tools():
    common = {"toolkit": "kuma", "version": 1, "enabled": True, "required_scopes": [],
              "timeout_seconds": 20, "max_output_bytes": 65536, "description": "kuma"}
    return [
        {**common, "id": "kuma.monitor_list", "title": "List", "category": "read", "idempotent": True,
         "kuma_operation": "monitor_list", "parameters": {}},
        {**common, "id": "kuma.monitor_add_http", "title": "Add", "category": "write", "idempotent": False,
         "kuma_operation": "monitor_add_http", "parameters": ADD_PARAMS},
        {**common, "id": "kuma.monitor_pause", "title": "Pause", "category": "write", "idempotent": True,
         "kuma_operation": "monitor_pause", "parameters": ID_PARAM},
    ]


def test_example_tools_load(tmp_path):
    catalog = make_catalog(tmp_path, _tier1(tmp_path, 3001), _tools())
    assert catalog.tools["kuma.monitor_add_http"].kuma_operation == "monitor_add_http"


@pytest.mark.parametrize("change, fragment", [
    ({"category": "read"}, "must be 'write'"),
    ({"parameters": {**ADD_PARAMS, "interval": {**ADD_PARAMS["interval"], "maximum": 86400}}}, "interval"),
    ({"parameters": {**ADD_PARAMS, "interval": {"type": "integer", "description": "s"}}}, "interval"),
    ({"parameters": {**ADD_PARAMS, "expected_status": {"type": "enum", "values": ["500"],
                                                       "description": "s"}}}, "expected_status"),
    ({"parameters": {**ADD_PARAMS, "type": {"type": "enum", "values": ["dns"], "description": "t"}}},
     "does not read ['type']"),
    ({"parameters": {"url": ADD_PARAMS["url"]}}, "'name'"),
    ({"kuma_operation": "monitor_delete"}, "unknown"),
])
def test_catalog_refuses_a_definition_wider_than_the_executor(tmp_path, change, fragment):
    tools = _tools()
    tools[1] = {**tools[1], **change}
    with pytest.raises(ConfigError) as exc:
        make_catalog(tmp_path, _tier1(tmp_path, 3001), tools)
    assert fragment in str(exc.value)


def test_catalog_refuses_an_operation_the_toolkit_does_not_allow(tmp_path):
    tier1 = _tier1(tmp_path, 3001, allowed_kuma_operations=["monitor_list"])
    with pytest.raises(Exception, match="not in the allowlist"):
        make_catalog(tmp_path, tier1, _tools())


def test_shipped_example_toolkit_and_tools_load(tmp_path):
    """config/examples is what an operator copies from; its kuma part must load."""
    from pathlib import Path

    examples = Path(__file__).resolve().parent.parent / "config" / "examples"
    toolkits = yaml.safe_load((examples / "toolkits.yaml").read_text(encoding="utf-8"))["toolkits"]
    tools = [t for t in yaml.safe_load((examples / "tools.yaml").read_text(encoding="utf-8"))["tools"]
             if t.get("toolkit") == "kuma"]
    path = tmp_path / "toolkits.yaml"
    path.write_text(yaml.safe_dump({"toolkits": {"kuma": toolkits["kuma"]},
                                    "audit": {"dir": str(tmp_path / "logs")}}), encoding="utf-8")
    catalog = make_catalog(tmp_path, load_tier1(str(path)), tools)
    assert sorted(catalog.tools) == ["kuma.monitor_add_http", "kuma.monitor_list",
                                     "kuma.monitor_pause", "kuma.monitor_resume"]


# -- Through the service, with audit ----------------------------------------------------


async def test_service_call_is_audited_without_the_password(tmp_path, kuma, credentials):
    tier1 = _tier1(tmp_path, kuma.port)
    # A deliberately loose URL pattern: the executor's own floor, applied
    # in `validate.build_kuma_call`, is what has to refuse the userinfo.
    tools = _tools()
    loose = {**ADD_PARAMS, "url": {**ADD_PARAMS["url"], "pattern": "^\\S{1,200}$"}}
    tools[1] = {**tools[1], "parameters": loose}
    catalog = make_catalog(tmp_path, tier1, tools)
    ipath = tmp_path / "identities.yaml"
    ipath.write_text(yaml.safe_dump({"identities": [
        {"id": "hermes", "role": "agent", "token_hash": hash_token(generate_token()),
         "tools": [t["id"] for t in _tools()], "scopes": []},
    ]}), encoding="utf-8")
    identities = load_identities(str(ipath))
    service = Service(tier1=tier1, catalog=catalog, audit=AuditLog(str(tmp_path / "logs")),
                      identities=identities, credentials=credentials)
    hermes = identities.identities["hermes"]

    listed = await service.call(hermes, "kuma.monitor_list", {})
    assert listed.outcome == OUTCOME_OK, listed.stderr
    with pytest.raises(Denied) as denied:
        await service.call(hermes, "kuma.monitor_add_http", {"name": "x", "url": "https://u:p@x.org/"})
    assert "user or password" in denied.value.agent_message
    assert "add" not in kuma.events

    log = "".join(p.read_text() for p in (tmp_path / "logs").rglob("*") if p.is_file())
    records = [json.loads(line) for line in log.splitlines() if line.strip()]
    calls = [r for r in records if r.get("kind") == "call"]
    assert [r["tool"] for r in calls][-2:] == ["kuma.monitor_list", "kuma.monitor_add_http"]
    assert PASSWORD not in log and FOREIGN_SECRET not in log
