"""Per-tool raw JSON body mode for the `http` executor.

`body: {raw_param: <name>}` hands one parameter's own JSON document to the
target as the request body, byte for byte, instead of wrapping it as
`{"<name>": "<document>"}`. n8n's `POST /api/v1/workflows` is the case that
forced it: the agent already holds a complete workflow document, and the
wrapper sends a JSON *string* where the API expects a JSON *object*.

A real loopback HTTP server, like `test_execute_http.py`: what matters here
is the bytes and the `Content-Type` that actually leave the process --
exactly what a mocked transport would assume away. The handler keeps the
body it received unparsed, so "verbatim" is checked as bytes rather than as
"parses to the same object".
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import make_catalog

from gatekeeper import execute_http, validate
from gatekeeper.catalog import parse_tool_spec
from gatekeeper.errors import ConfigError
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK
from gatekeeper.tier1 import load_tier1

#: The n8n workflow document the tests send. Deliberately *not* what
#: `json.dumps` would produce for the same object -- the key order and the
#: spacing after `:` are what prove the body was passed through rather than
#: re-serialized.
WORKFLOW_JSON = (
    '{"name":"nightly-backup", "nodes":[{"name":"Cron","type":'
    '"n8n-nodes-base.cron","parameters":{"triggerTimes":{"item":'
    '[{"hour":3}]}}}], "connections":{}, "settings":{"saveDataErrorExecution":'
    '"all"}, "active":false}'
)


class _Handler(BaseHTTPRequestHandler):
    #: Every request this server saw, oldest first: (path, headers, raw body).
    seen: list[tuple[str, dict[str, str], bytes]] = []

    def log_message(self, *args):  # noqa: D401 -- silence test server logging
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        type(self).seen.append((self.path, dict(self.headers.items()), raw))
        payload = json.dumps(
            {
                "path": self.path,
                # The body as text, never re-parsed: the assertions compare
                # it to the document the parameter carried.
                "raw": raw.decode("utf-8", errors="replace"),
                "content_type": self.headers.get("Content-Type", ""),
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def http_server():
    _Handler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


@pytest.fixture
def toolkit(tmp_path, http_server):
    port = http_server.server_address[1]
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        f"""
toolkits:
  n8n_admin:
    executor: http
    base_url: "http://127.0.0.1:{port}"
    allowed_methods: ["GET", "POST"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["127.0.0.1/32"]
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    return tier1.toolkit("n8n_admin"), tier1


def _workflow_create_spec(**overrides):
    """The n8n_admin `workflow_create` shape: one JSON document parameter."""
    spec = {
        "id": "n8n_admin.workflow_create",
        "toolkit": "n8n_admin",
        "version": 1,
        "title": "Create workflow",
        "description": "Creates a workflow from a complete n8n workflow JSON.",
        "category": "write",
        "idempotent": False,
        "enabled": True,
        "method": "POST",
        "path": "/api/v1/workflows",
        "body": {"raw_param": "workflow_json"},
        "parameters": {
            "workflow_json": {
                "type": "string",
                "pattern": "^.{1,30000}$",
                "required": True,
                "description": "Complete n8n workflow document as JSON.",
            },
        },
        "required_scopes": [],
        "timeout_seconds": 5,
        "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return spec


def _tool(tier1, **overrides):
    return parse_tool_spec(_workflow_create_spec(**overrides), tier1)


# -- Tier 1 / catalog: how `body: {raw_param: ...}` loads -------------------


def test_raw_param_loads_and_desugars_to_the_wrapper_it_replaces(toolkit):
    _, tier1 = toolkit
    tool = _tool(tier1)
    assert tool.body_raw_param == "workflow_json"
    # The wrapper template is kept: it is what the placeholder check runs
    # against, and what a fallback sends.
    assert tool.body_template == {"workflow_json": "{workflow_json}"}


def test_raw_param_must_be_a_string(toolkit):
    _, tier1 = toolkit
    with pytest.raises(ConfigError, match="raw_param"):
        _tool(tier1, body={"raw_param": ["workflow_json"]})


def test_raw_param_rejects_a_second_key(toolkit):
    """`raw_param` switches the whole body, so a sibling key is meaningless.

    Rejected at load time rather than silently dropped on the first call.
    """
    _, tier1 = toolkit
    with pytest.raises(ConfigError, match="exactly one key"):
        _tool(tier1, body={"raw_param": "workflow_json", "name": "{name}"})


def test_raw_param_naming_an_unknown_parameter_is_rejected(toolkit):
    """The typo guard covers the raw name like any other template.

    A `raw_param` pointing at a parameter nobody declared would otherwise
    surface as an unresolvable placeholder at call time.
    """
    _, tier1 = toolkit
    with pytest.raises(ConfigError, match="unknown parameter"):
        _tool(tier1, body={"raw_param": "workflow_jsonn"})


def test_ordinary_body_template_still_loads_without_raw_mode(toolkit):
    _, tier1 = toolkit
    tool = _tool(tier1, body={"data": {"name": "{workflow_json}"}})
    assert tool.body_raw_param is None
    assert tool.body_template == {"data": {"name": "{workflow_json}"}}


# -- The executor: what actually leaves the process ------------------------


async def test_raw_param_sends_the_string_verbatim_as_json(toolkit):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    method, path, query, body = validate.build_http_request(
        tool, {"workflow_json": WORKFLOW_JSON}, tk
    )
    result = await execute_http.run(
        method=method, path=path, query=query, body=body,
        raw_param=tool.body_raw_param, toolkit=tk, credentials=None,
        timeout_seconds=5, max_output_bytes=65536, idempotent=False,
    )

    assert result.outcome == OUTCOME_OK, result.stderr
    echo = json.loads(result.stdout)
    # Byte for byte, spacing and key order included -- not a re-serialization.
    assert echo["raw"] == WORKFLOW_JSON
    assert echo["content_type"] == "application/json"
    _, headers, raw = _Handler.seen[-1]
    assert raw == WORKFLOW_JSON.encode("utf-8")
    assert headers["Content-Type"] == "application/json"


async def test_raw_param_is_excluded_from_the_wrapper_object(toolkit):
    """The parameter never also appears as a field of a wrapper.

    The wrapper `build_http_request` resolves (`{"workflow_json": "..."}`)
    is replaced by the document, so the target receives the workflow's own
    top-level keys and no `workflow_json` key at all. Checked here with an
    extra resolved key next to the raw one as well -- a shape the catalog
    rejects at load time, so this pins the executor's own behaviour: the
    raw value is the entire body either way.
    """
    tk, tier1 = toolkit
    tool = _tool(tier1)
    method, path, query, body = validate.build_http_request(
        tool, {"workflow_json": WORKFLOW_JSON}, tk
    )
    assert body == {"workflow_json": WORKFLOW_JSON}  # the wrapper, pre-executor

    result = await execute_http.run(
        method=method, path=path, query=query,
        body={**body, "extra": "ignored"},
        raw_param="workflow_json", toolkit=tk, credentials=None,
        timeout_seconds=5, max_output_bytes=65536, idempotent=False,
    )

    assert result.outcome == OUTCOME_OK, result.stderr
    sent = json.loads(json.loads(result.stdout)["raw"])
    assert "workflow_json" not in sent
    assert "extra" not in sent
    assert sent["name"] == "nightly-backup"


async def test_invalid_json_errors_cleanly_without_sending_anything(toolkit):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    method, path, query, body = validate.build_http_request(
        tool, {"workflow_json": '{"name":"broken",'}, tk
    )
    result = await execute_http.run(
        method=method, path=path, query=query, body=body,
        raw_param=tool.body_raw_param, toolkit=tk, credentials=None,
        timeout_seconds=5, max_output_bytes=65536, idempotent=False,
    )

    assert result.outcome == OUTCOME_FAILED
    assert "valid JSON" in result.stderr
    assert result.exit_code is None
    # Not "sent and rejected by the target" -- never sent.
    assert _Handler.seen == []


async def test_missing_raw_param_falls_back_to_wrapping(toolkit):
    """An absent referenced parameter keeps the pre-raw-mode behaviour.

    The body is sent as the ordinary JSON object it resolved to, rather
    than becoming no body at all.
    """
    tk, tier1 = toolkit
    tool = _tool(tier1)
    result = await execute_http.run(
        method="POST", path="/api/v1/workflows", query={},
        body={"name": "nightly-backup"}, raw_param=tool.body_raw_param,
        toolkit=tk, credentials=None, timeout_seconds=5,
        max_output_bytes=65536, idempotent=False,
    )

    assert result.outcome == OUTCOME_OK, result.stderr
    echo = json.loads(result.stdout)
    assert json.loads(echo["raw"]) == {"name": "nightly-backup"}
    assert "json" in echo["content_type"]


async def test_non_string_raw_value_is_serialized(toolkit):
    """A non-string value is serialized rather than refused.

    Raw mode is about the parameter alone deciding the body, not about that
    body having to arrive as text.
    """
    tk, _ = toolkit
    result = await execute_http.run(
        method="POST", path="/api/v1/workflows", query={},
        body={"workflow_json": {"name": "nightly-backup", "active": False}},
        raw_param="workflow_json", toolkit=tk, credentials=None,
        timeout_seconds=5, max_output_bytes=65536, idempotent=False,
    )

    assert result.outcome == OUTCOME_OK, result.stderr
    echo = json.loads(result.stdout)
    assert json.loads(echo["raw"]) == {"name": "nightly-backup", "active": False}
    assert echo["content_type"] == "application/json"


# -- The whole path, through Service.call ---------------------------------


async def test_n8n_admin_workflow_create_through_service(toolkit, tmp_path):
    """The shape this option exists for, end to end.

    Through `Service.call`, not `execute_http.run`: `tool.body_raw_param`
    reaching the executor is part of what is under test -- a tool that
    declares raw mode and a service that drops it on the way would pass
    every assertion above.
    """
    _, tier1 = toolkit
    from gatekeeper.audit import AuditLog
    from gatekeeper.identity import Identity, hash_token
    from gatekeeper.service import Service

    spec = _workflow_create_spec()
    catalog = make_catalog(tmp_path, tier1, [spec])
    audit = AuditLog(str(tmp_path / "logs-raw"))
    identity = Identity(
        id="agent",
        role="agent",
        token_hash=hash_token("unused"),
        tools=frozenset({"n8n_admin.workflow_create"}),
        scopes=(),
    )
    service = Service(tier1=tier1, catalog=catalog, audit=audit)

    result = await service.call(
        identity, "n8n_admin.workflow_create", {"workflow_json": WORKFLOW_JSON}
    )

    assert result.outcome == OUTCOME_OK, result.stderr
    echo = json.loads(result.stdout)
    assert echo["path"] == "/api/v1/workflows"
    assert echo["raw"] == WORKFLOW_JSON
    assert echo["content_type"] == "application/json"
