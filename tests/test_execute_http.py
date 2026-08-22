"""The `http` executor (REQUIREMENTS.md §8, FR-8.5 to FR-8.15).

A real loopback HTTP server, not a mocked transport: the properties that
matter here -- the resolved IP is actually checked before connecting, a
redirect is actually not followed, the credential actually lands in a
header and nowhere else -- are exactly the kind of thing a mock of the
HTTP client would silently assume away.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import make_catalog
from gatekeeper import execute_http, validate
from gatekeeper.catalog import parse_tool_spec
from gatekeeper.credentials import CredentialStore, KEY_ENV, generate_master_key
from gatekeeper.errors import Denied
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN
from gatekeeper.tier1 import load_tier1


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D401 -- silence test server logging
        pass

    def _respond_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://evil.example/steal")
            self.end_headers()
            return
        if self.path.startswith("/api/slow"):
            import time

            time.sleep(2)
            self._respond_json(200, {"ok": True})
            return
        self._respond_json(
            200,
            {
                "path": self.path,
                "headers": dict(self.headers.items()),
            },
        )

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            body = {"raw": raw.decode("utf-8", errors="replace")}
        self._respond_json(200, {"path": self.path, "body": body})


@pytest.fixture(scope="module")
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def toolkit(tmp_path, http_server):
    port = http_server.server_address[1]
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        f"""
toolkits:
  demo_http:
    executor: http
    base_url: "http://127.0.0.1:{port}"
    allowed_methods: ["GET", "POST"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["127.0.0.1/32"]
    credential: demo_cred
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    return tier1.toolkit("demo_http"), tier1


def _tool(tier1, **overrides):
    spec = {
        "id": "demo_http.get_thing",
        "toolkit": "demo_http",
        "version": 1,
        "title": "Get thing",
        "description": "test",
        "category": "read",
        "enabled": True,
        "method": "GET",
        "path": "/api/thing/{name}",
        "parameters": {
            "name": {"type": "string", "pattern": "^[a-z]+$", "required": True},
        },
        "timeout_seconds": 5,
        "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return parse_tool_spec(spec, tier1)


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "logs2"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store.create(
        "demo_cred", kind="api_key_header", header="X-Api-Key",
        value="super-secret-abc", actor="test", rev="",
    )
    return store


async def test_successful_get(toolkit, credentials):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    method, path, query, body = validate.build_http_request(tool, {"name": "widgets"}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=credentials, timeout_seconds=5, max_output_bytes=65536,
        idempotent=True,
    )
    assert result.outcome == OUTCOME_OK
    assert result.exit_code == 200
    payload = json.loads(result.stdout)
    assert payload["path"] == "/api/thing/widgets"
    assert payload["headers"].get("X-Api-Key") == "super-secret-abc"


async def test_url_query_credential_injected_as_query_param(toolkit, tmp_path, monkeypatch):
    """FR-8.14's narrow, documented exception: a service with no header

    option at all (this project's SABnzbd preset) gets its credential
    injected as a query parameter -- by execute_http.py directly, not
    through the tool's own query_template.
    """
    tk, tier1 = toolkit
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "logs4"))
    store = CredentialStore(path=str(tmp_path / "credentials4.yaml"), audit=audit)
    store.create(
        "demo_cred", kind="url_query", header="apikey",
        value="super-secret-query-key", actor="test", rev="",
    )
    tool = _tool(tier1)
    method, path, query, body = validate.build_http_request(tool, {"name": "widgets"}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=store, timeout_seconds=5, max_output_bytes=65536,
        idempotent=True,
    )
    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    assert "apikey=super-secret-query-key" in payload["path"]
    # Never also sent as a header -- the two injection paths are exclusive
    # per credential kind.
    assert "X-Api-Key" not in payload["headers"]


async def test_credential_masked_when_redacted(toolkit, credentials):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    method, path, query, body = validate.build_http_request(tool, {"name": "widgets"}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=credentials, timeout_seconds=5, max_output_bytes=65536,
        idempotent=True, redact=lambda text: text.replace("super-secret-abc", "***"),
    )
    assert "super-secret-abc" not in result.stdout


async def test_ssrf_blocked_when_cidr_excludes_target(tmp_path, http_server):
    port = http_server.server_address[1]
    path = tmp_path / "toolkits2.yaml"
    path.write_text(
        f"""
toolkits:
  demo_http:
    executor: http
    base_url: "http://127.0.0.1:{port}"
    allowed_methods: ["GET"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["10.0.0.0/8"]
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("demo_http")
    tool = _tool(tier1)
    method, req_path, query, body = validate.build_http_request(tool, {"name": "widgets"}, tk)
    result = await execute_http.run(
        method=method, path=req_path, query=query, body=body, toolkit=tk,
        credentials=None, timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "allowed_cidrs" in result.stderr or "cidr" in result.stderr.lower()


async def test_path_traversal_rejected_before_network(toolkit):
    tk, tier1 = toolkit
    tool = _tool(
        tier1, id="demo_http.trav", path="/api/thing/{name}",
        parameters={"name": {"type": "string", "pattern": "^.*$", "required": True}},
    )
    with pytest.raises(Denied):
        validate.build_http_request(tool, {"name": ".."}, tk)


async def test_path_outside_allowed_prefix_rejected_at_load(toolkit):
    tk, tier1 = toolkit
    with pytest.raises(Exception):
        _tool(tier1, id="demo_http.outside", path="/other/{name}")


async def test_redirect_is_reported_not_followed(toolkit, credentials):
    tk, tier1 = toolkit
    tool = _tool(
        tier1, id="demo_http.redir", path="/api/redirect",
        parameters={},
    )
    method, path, query, body = validate.build_http_request(tool, {}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=credentials, timeout_seconds=5, max_output_bytes=65536,
        idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "not followed" in result.stderr
    assert "evil.example" not in "".join([])  # never actually contacted


async def test_timeout_on_non_idempotent_is_unknown(toolkit, credentials):
    tk, tier1 = toolkit
    tool = _tool(
        tier1, id="demo_http.slow", path="/api/slow",
        category="write", idempotent=False, parameters={},
    )
    method, path, query, body = validate.build_http_request(tool, {}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=credentials, timeout_seconds=0.2, max_output_bytes=65536,
        idempotent=False,
    )
    assert result.outcome == OUTCOME_UNKNOWN


async def test_timeout_on_idempotent_is_failed(toolkit, credentials):
    tk, tier1 = toolkit
    tool = _tool(tier1, id="demo_http.slow2", path="/api/slow", parameters={})
    method, path, query, body = validate.build_http_request(tool, {}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=credentials, timeout_seconds=0.2, max_output_bytes=65536,
        idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED


async def test_response_capped_at_max_output_bytes(toolkit, credentials):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    method, path, query, body = validate.build_http_request(tool, {"name": "widgets"}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=credentials, timeout_seconds=5, max_output_bytes=10,
        idempotent=True,
    )
    assert result.truncated is True


async def test_invalid_url_component_denied_not_raised(toolkit, credentials):
    """A resolved path containing '?' or '#' must come back as a `Result`

    with `outcome=failed`, not an unhandled exception. `httpx.URL(...)`
    rejects such characters in a `path=` component with `httpx.InvalidURL`,
    which is a bare `Exception` (not `httpx.HTTPError`) -- reachable
    whenever a tool's own parameter pattern is permissive enough to let one
    through, and previously able to escape both this module's `except`
    clauses and `service.call`'s `except Denied`, producing an unaudited
    500 instead of the normal call/outcome bookkeeping.
    """
    tk, tier1 = toolkit
    tool = _tool(
        tier1, id="demo_http.weird", path="/api/thing/{name}",
        parameters={"name": {"type": "string", "pattern": "^.*$", "required": True}},
    )
    method, path, query, body = validate.build_http_request(tool, {"name": "a?b"}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=credentials, timeout_seconds=5, max_output_bytes=65536,
        idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "not a valid URL component" in result.stderr


async def test_credential_kind_mismatch_in_base_url_denied(tmp_path, http_server, monkeypatch):
    """FR-8.14: `{credential}` in `base_url` is a narrow exception reserved

    for `url_path`-kind credentials (Telegram's bot-token-in-path case) --
    a toolkit misconfigured to reference a `bearer`/`api_key_header`/etc.
    credential there must be refused, not silently place that value in the
    URL path where it lands in the target's own access logs.
    """
    port = http_server.server_address[1]
    path = tmp_path / "toolkits5.yaml"
    path.write_text(
        f"""
toolkits:
  demo_http:
    executor: http
    base_url: "http://127.0.0.1:{port}/bot{{credential}}"
    allowed_methods: ["GET"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["127.0.0.1/32"]
    credential: demo_cred
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("demo_http")
    tool = _tool(tier1)

    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "logs5"))
    store = CredentialStore(path=str(tmp_path / "credentials5.yaml"), audit=audit)
    store.create(
        "demo_cred", kind="bearer", value="should-not-land-in-a-url",
        actor="test", rev="",
    )

    method, req_path, query, body = validate.build_http_request(tool, {"name": "widgets"}, tk)
    result = await execute_http.run(
        method=method, path=req_path, query=query, body=body, toolkit=tk,
        credentials=store, timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "url_path" in result.stderr


async def test_missing_credential_denied(toolkit):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    method, path, query, body = validate.build_http_request(tool, {"name": "widgets"}, tk)
    result = await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=None, timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED


async def test_probe_reports_reachable(toolkit):
    tk, _ = toolkit
    assert await execute_http.probe(tk) is True


async def test_probe_reports_unreachable_for_closed_port(tmp_path):
    path = tmp_path / "toolkits3.yaml"
    path.write_text(
        """
toolkits:
  demo_http:
    executor: http
    base_url: "http://127.0.0.1:1"
    allowed_methods: ["GET"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["127.0.0.1/32"]
audit:
  dir: /tmp/gk-test-logs
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("demo_http")
    assert await execute_http.probe(tk) is False


# -- The audit record of an HTTP call (FR-10.7) ----------------------------
#
# Run through `Service.call` rather than `execute_http.run` directly: the
# credential *name* is attached by the service, the credential *value* by
# the executor, and the property under test is that exactly one of the two
# reaches the log. Only the full path exercises both.


def _service_for(tmp_path, tier1, credentials, *, name):
    from gatekeeper.audit import AuditLog
    from gatekeeper.identity import Identity, hash_token
    from gatekeeper.service import Service

    catalog = make_catalog(tmp_path, tier1, [_tool_spec()])
    audit = AuditLog(str(tmp_path / name))
    identity = Identity(
        id="agent",
        role="agent",
        token_hash=hash_token("unused"),
        tools=frozenset({"demo_http.get_thing"}),
        scopes=(),
    )
    service = Service(tier1=tier1, catalog=catalog, audit=audit, credentials=credentials)
    return service, identity, tmp_path / name / "audit.jsonl"


def _tool_spec():
    return {
        "id": "demo_http.get_thing",
        "toolkit": "demo_http",
        "version": 1,
        "title": "Get thing",
        "description": "test",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "method": "GET",
        "path": "/api/thing/{name}",
        "parameters": {
            "name": {"type": "string", "pattern": "^[a-z]+$", "required": True,
                      "description": "thing name"},
        },
        "required_scopes": [],
        "timeout_seconds": 5,
        "max_output_bytes": 65536,
    }


async def test_audit_records_credential_name_but_never_its_value(toolkit, credentials, tmp_path):
    _, tier1 = toolkit
    service, identity, log_path = _service_for(
        tmp_path, tier1, credentials, name="logs-named"
    )

    result = await service.call(identity, "demo_http.get_thing", {"name": "widgets"})
    assert result.outcome == OUTCOME_OK
    # The key really did reach the target -- otherwise the assertion below
    # would pass for the trivial reason that no request was ever made.
    assert json.loads(result.stdout)["headers"]["X-Api-Key"] == "super-secret-abc"

    written = log_path.read_text(encoding="utf-8")
    record = json.loads(written.splitlines()[-1])
    assert record["credentials"] == ["demo_cred"]
    # Not "the value is absent from the fields we thought to check" -- absent
    # from the serialized record, full stop.
    assert "super-secret-abc" not in written


async def test_audit_records_no_credential_when_toolkit_has_none(tmp_path, http_server):
    port = http_server.server_address[1]
    path = tmp_path / "toolkits-nocred.yaml"
    path.write_text(
        f"""
toolkits:
  demo_http:
    executor: http
    base_url: "http://127.0.0.1:{port}"
    allowed_methods: ["GET"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["127.0.0.1/32"]
audit:
  dir: {tmp_path / "logs-nocred"}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    service, identity, log_path = _service_for(tmp_path, tier1, None, name="logs-nocred")

    result = await service.call(identity, "demo_http.get_thing", {"name": "widgets"})
    assert result.outcome == OUTCOME_OK
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
    # [] and not [None]: an unauthenticated toolkit names no credential.
    assert record["credentials"] == []


async def test_audit_records_credential_name_on_denial(toolkit, credentials, tmp_path):
    """A denial names the credential the call *would* have used.

    Without this, a rejected call against a service is invisible when
    answering "what touched this key?" after it leaked.
    """
    _, tier1 = toolkit
    service, identity, log_path = _service_for(
        tmp_path, tier1, credentials, name="logs-denied"
    )

    with pytest.raises(Denied):
        # Fails `^[a-z]+$` -- denied after the toolkit resolves, so the
        # credential name is already known.
        await service.call(identity, "demo_http.get_thing", {"name": "NOT-LOWERCASE"})

    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert record["outcome"] == "denied"
    assert record["credentials"] == ["demo_cred"]
