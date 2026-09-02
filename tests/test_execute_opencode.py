"""The `opencode` executor.

A real loopback HTTP server standing in for the opencode API, not a
mocked transport: the properties that matter here -- the resolved IP is
actually checked before every request of a multi-request workflow, the
project directory actually leaves as `x-opencode-directory` and nothing
else, a session id actually cannot address a different endpoint, a
redirect actually is not followed -- are exactly the kind of thing a mock
of the HTTP client would silently assume away.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from gatekeeper import execute_opencode, validate
from gatekeeper.catalog import OPENCODE_OPERATION_PARAMS, parse_tool_spec
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.errors import ConfigError, Denied, Tier1Violation
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN
from gatekeeper.tier1 import load_tier1

#: How many `GET /session/{id}` polls the fake server answers "running"
#: before it reports the session finished. Two, so `run`'s poll loop is
#: genuinely exercised rather than satisfied by the first answer.
_BUSY_POLLS = 2


class _State:
    """What the fake opencode server remembers between requests."""

    def __init__(self) -> None:
        self.sessions: dict[str, dict] = {}
        self.counter = 0
        self.requests: list[tuple[str, str, dict, dict | None]] = []
        self.polls: dict[str, int] = {}
        #: Set to make every session poll answer "still running", so a
        #: `run` call has to hit its own timeout.
        self.never_finish = False


STATE = _State()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D401 -- silence test server logging
        pass

    # -- plumbing ---------------------------------------------------------

    def _json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self, method: str, body: dict | None = None) -> None:
        STATE.requests.append(
            (method, self.path, dict(self.headers.items()), body)
        )

    def _read_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            return None

    # -- routes -----------------------------------------------------------

    def do_GET(self):
        self._record("GET")
        if self.path == "/global/health":
            self._json(200, {"status": "ok", "version": "1.1.48"})
            return
        if self.path == "/config/providers":
            self._json(
                200,
                {
                    "providers": [
                        {
                            "id": "anthropic",
                            "name": "Anthropic",
                            "models": {"claude-opus-5": {}, "claude-sonnet-5": {}},
                        }
                    ],
                    "default": {"anthropic": "claude-opus-5"},
                },
            )
            return
        if self.path == "/api/redirect":
            self.send_response(302)
            self.send_header("Location", "http://evil.example/steal")
            self.end_headers()
            return

        parts = self.path.strip("/").split("/")
        if parts[0] == "session" and len(parts) >= 2:
            session_id = parts[1]
            if session_id not in STATE.sessions:
                self._json(404, {"error": "no such session"})
                return
            if len(parts) == 2:
                STATE.polls[session_id] = STATE.polls.get(session_id, 0) + 1
                busy = STATE.never_finish or STATE.polls[session_id] <= _BUSY_POLLS
                self._json(
                    200,
                    {
                        "id": session_id,
                        "status": "running" if busy else "idle",
                        "parts": [{"type": "text", "text": "task finished"}],
                    },
                )
                return
            if parts[2] == "todo":
                self._json(
                    200,
                    {
                        "todos": [
                            {"content": "read the file", "status": "completed"},
                            {"content": "write the patch", "status": "in_progress"},
                        ]
                    },
                )
                return
            if parts[2] == "diff":
                self._json(
                    200,
                    {
                        "files": [
                            {"path": "src/a.py", "additions": 12, "deletions": 3},
                            {"path": "src/b.py", "patch": "+one\n+two\n-three\n"},
                        ]
                    },
                )
                return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        body = self._read_body()
        self._record("POST", body)
        if self.path == "/session":
            STATE.counter += 1
            session_id = f"ses_{STATE.counter:04d}"
            STATE.sessions[session_id] = {"id": session_id}
            self._json(200, {"id": session_id, "title": (body or {}).get("title")})
            return

        parts = self.path.strip("/").split("/")
        if parts[0] == "session" and len(parts) == 3:
            session_id = parts[1]
            if session_id not in STATE.sessions:
                self._json(404, {"error": "no such session"})
                return
            if parts[2] == "message":
                self._json(
                    200,
                    {
                        "parts": [
                            {"type": "text", "text": "The answer is 4."},
                        ]
                    },
                )
                return
            if parts[2] == "prompt_async":
                STATE.polls[session_id] = 0
                self._json(200, {"accepted": True})
                return
            if parts[2] == "abort":
                self._json(200, {"aborted": True})
                return
        self._json(404, {"error": "not found"})


@pytest.fixture(scope="module")
def opencode_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture(autouse=True)
def _reset_state():
    STATE.sessions.clear()
    STATE.requests.clear()
    STATE.polls.clear()
    STATE.counter = 0
    STATE.never_finish = False
    yield


@pytest.fixture
def projects(tmp_path):
    root = tmp_path / "projects"
    (root / "demo").mkdir(parents=True)
    return root


def _toolkits_yaml(
    tmp_path,
    projects,
    port,
    *,
    cidrs='["127.0.0.1/32"]',
    operations=(
        "ask, run, fire, check, review_changes, abort, providers, health"
    ),
    credential: str | None = None,
    path_roots: str | None = None,
):
    roots = path_roots if path_roots is not None else f'["{projects}"]'
    cred = f"\n    credential: {credential}" if credential else ""
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        f"""
toolkits:
  opencode:
    executor: opencode
    base_url: "http://127.0.0.1:{port}"
    allowed_cidrs: {cidrs}
    allowed_opencode_operations: [{operations}]
    path_roots: {roots}{cred}
    max_timeout_seconds: 60
    max_output_bytes: 131072
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    return load_tier1(str(path))


@pytest.fixture
def tier1(tmp_path, projects, opencode_server):
    return _toolkits_yaml(tmp_path, projects, opencode_server.server_address[1])


@pytest.fixture
def toolkit(tier1):
    return tier1.toolkit("opencode")


_PARAMS = {
    "prompt": {
        "type": "string",
        "required": True,
        "pattern": r"^[\s\S]{1,20000}$",
        "description": "What opencode should do.",
    },
    "directory": {
        "type": "string",
        "required": False,
        "pattern": "^/[A-Za-z0-9._/-]{0,255}$",
        "description": "Project root.",
    },
    "session_id": {
        "type": "string",
        "required": False,
        "pattern": "^[A-Za-z0-9_-]{1,128}$",
        "description": "Session id.",
    },
}


#: The read-only half of the operation set -- everything else changes
#: something on the other side.
_READ_ONLY = ("check", "review_changes", "providers", "health")


def _tool_spec(operation, **overrides):
    """A tool definition for one operation, with exactly the parameters
    that operation reads (`OPENCODE_OPERATION_PARAMS`, enforced at load).
    """
    required, optional = OPENCODE_OPERATION_PARAMS[operation]
    parameters = {
        name: {**_PARAMS[name], "required": name in required}
        for name in (*required, *optional)
        if name in _PARAMS
    }
    spec = {
        "id": f"opencode.{operation}",
        "toolkit": "opencode",
        "version": 1,
        "title": operation,
        "description": f"opencode {operation}",
        "category": "read" if operation in _READ_ONLY else "write",
        "idempotent": operation in _READ_ONLY,
        "enabled": True,
        "opencode_operation": operation,
        "parameters": parameters,
        "required_scopes": [],
        "timeout_seconds": 30,
        "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return spec


def _tool(tier1, operation, **overrides):
    return parse_tool_spec(_tool_spec(operation, **overrides), tier1)


async def _run(toolkit, operation, values, *, timeout=30, idempotent=True, credentials=None):
    return await execute_opencode.run(
        operation=operation,
        values=values,
        toolkit=toolkit,
        credentials=credentials,
        timeout_seconds=timeout,
        max_output_bytes=65536,
        idempotent=idempotent,
    )


def _header_of(path_fragment: str, header: str) -> str | None:
    for _method, path, headers, _body in STATE.requests:
        if path_fragment in path:
            return headers.get(header)
    return None


# -- The eight operations --------------------------------------------------


async def test_health_reports_healthy_and_version(toolkit):
    result = await _run(toolkit, "health", {})
    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    assert payload == {"operation": "health", "healthy": True, "version": "1.1.48"}
    assert result.external_untrusted is True


async def test_ask_creates_a_session_and_returns_the_answer(toolkit):
    result = await _run(toolkit, "ask", {"prompt": "what is 2+2?"})
    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    assert payload["operation"] == "ask"
    assert payload["answer"] == "The answer is 4."
    assert payload["session_id"] in STATE.sessions
    # One call, two requests: create then message (FR: the composite is
    # the point -- an agent never sees the intermediate session object).
    assert [m for m, *_ in STATE.requests] == ["POST", "POST"]


async def test_fire_returns_the_session_id_without_waiting(toolkit):
    result = await _run(toolkit, "fire", {"prompt": "refactor it"})
    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    assert payload["status"] == "dispatched"
    assert payload["session_id"] in STATE.sessions
    # Nothing polled: fire returns as soon as opencode accepted the prompt.
    assert not any(m == "GET" for m, *_ in STATE.requests)


async def test_run_polls_until_the_session_finishes(toolkit):
    result = await _run(toolkit, "run", {"prompt": "do the thing"}, idempotent=False)
    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    assert payload["operation"] == "run"
    assert payload["done"] is True
    assert payload["status"] == "idle"
    assert payload["files_changed"] == ["src/a.py", "src/b.py"]
    session_id = payload["session_id"]
    # The poll loop ran: _BUSY_POLLS "running" answers, then "idle".
    assert STATE.polls[session_id] == _BUSY_POLLS + 1


async def test_check_reports_status_todos_and_files(toolkit):
    fired = json.loads((await _run(toolkit, "fire", {"prompt": "go"})).stdout)
    result = await _run(toolkit, "check", {"session_id": fired["session_id"]})
    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    assert payload["operation"] == "check"
    assert payload["status"] == "running"
    assert payload["done"] is False
    assert [t["status"] for t in payload["todos"]] == ["completed", "in_progress"]
    assert payload["files_changed"] == ["src/a.py", "src/b.py"]


async def test_review_changes_counts_added_and_removed(toolkit):
    fired = json.loads((await _run(toolkit, "fire", {"prompt": "go"})).stdout)
    result = await _run(
        toolkit, "review_changes", {"session_id": fired["session_id"]}
    )
    payload = json.loads(result.stdout)
    assert payload["files"][0] == {"path": "src/a.py", "added": 12, "removed": 3}
    # The second file arrives as a raw patch -- counted from the diff itself.
    assert payload["files"][1] == {"path": "src/b.py", "added": 2, "removed": 1}
    assert payload["totals"] == {"files": 2, "added": 14, "removed": 4}


async def test_abort_stops_a_session(toolkit):
    fired = json.loads((await _run(toolkit, "fire", {"prompt": "go"})).stdout)
    result = await _run(toolkit, "abort", {"session_id": fired["session_id"]})
    payload = json.loads(result.stdout)
    assert payload["operation"] == "abort"
    assert payload["aborted"] is True


async def test_providers_lists_models_and_defaults(toolkit):
    result = await _run(toolkit, "providers", {})
    payload = json.loads(result.stdout)
    assert payload["providers"] == [
        {
            "id": "anthropic",
            "name": "Anthropic",
            "default_model": "claude-opus-5",
            "models": ["claude-opus-5", "claude-sonnet-5"],
        }
    ]


# -- The directory header --------------------------------------------------


async def test_directory_travels_as_the_opencode_header(toolkit, projects):
    directory = str(projects / "demo")
    result = await _run(toolkit, "ask", {"prompt": "hi", "directory": directory})
    assert result.outcome == OUTCOME_OK
    # Every request of the workflow carries it, not just the first.
    for _method, _path, headers, _body in STATE.requests:
        assert headers.get("x-opencode-directory") == directory


async def test_directory_outside_path_roots_is_denied(toolkit, tier1):
    tool = _tool(tier1, "ask")
    with pytest.raises(Denied) as exc:
        validate.build_opencode_call(tool, {"prompt": "hi", "directory": "/etc"}, toolkit)
    assert "path_roots" in str(exc.value)


async def test_relative_directory_is_denied(toolkit, tier1):
    tool = _tool(tier1, "ask")
    with pytest.raises(Denied) as exc:
        validate.build_opencode_call(
            tool, {"prompt": "hi", "directory": "projects/demo"}, toolkit
        )
    assert "absolute" in str(exc.value)


async def test_directory_traversal_is_denied(toolkit, tier1, projects):
    tool = _tool(tier1, "ask")
    with pytest.raises(Denied) as exc:
        validate.build_opencode_call(
            tool, {"prompt": "hi", "directory": f"{projects}/../../etc"}, toolkit
        )
    assert ".." in str(exc.value)


async def test_nonexistent_directory_under_a_visible_root_is_denied(toolkit, projects):
    """The root is mounted here, so a typo is answerable -- and answered."""
    result = await _run(
        toolkit, "ask", {"prompt": "hi", "directory": f"{projects}/typo"}
    )
    assert result.outcome == OUTCOME_FAILED
    assert "does not exist" in result.stderr


async def test_directory_under_an_unmounted_root_is_passed_through(
    tmp_path, projects, opencode_server
):
    """A root gatekeeper cannot see is opencode's to resolve, not ours.

    The check that *is* structural -- inside `path_roots` -- still runs;
    only the existence check, which this container cannot answer, is
    skipped rather than turned into a false rejection.
    """
    tier1 = _toolkits_yaml(
        tmp_path,
        projects,
        opencode_server.server_address[1],
        path_roots='["/srv/not-mounted-here"]',
    )
    toolkit = tier1.toolkit("opencode")
    result = await _run(
        toolkit, "ask", {"prompt": "hi", "directory": "/srv/not-mounted-here/repo"}
    )
    assert result.outcome == OUTCOME_OK
    assert _header_of("/session", "x-opencode-directory") == "/srv/not-mounted-here/repo"


async def test_directory_needs_path_roots_at_load_time(tmp_path, projects, opencode_server):
    tier1 = _toolkits_yaml(
        tmp_path, projects, opencode_server.server_address[1], path_roots="[]"
    )
    with pytest.raises(Tier1Violation) as exc:
        _tool(tier1, "ask")
    assert "path_roots" in str(exc.value)


# -- The session id never becomes a path -----------------------------------


@pytest.mark.parametrize(
    "session_id",
    ["ses_1/../../global/health", "ses 1", "ses_1?x=1", "../session", "", "a" * 129],
)
async def test_session_id_cannot_address_another_endpoint(toolkit, tier1, session_id):
    tool = _tool(tier1, "check")
    with pytest.raises(Denied):
        validate.build_opencode_call(tool, {"session_id": session_id}, toolkit)


async def test_session_id_is_rechecked_in_the_executor(toolkit):
    """The doubled check `build_argv`/`check_binary` also do: a value that
    reached the executor without passing validation is still refused.
    """
    result = await _run(toolkit, "check", {"session_id": "../../global/health"})
    assert result.outcome == OUTCOME_FAILED
    assert "session_id" in result.stderr


# -- Tier 1 boundaries -----------------------------------------------------


async def test_operation_outside_the_allowlist_is_a_load_time_violation(
    tmp_path, projects, opencode_server
):
    tier1 = _toolkits_yaml(
        tmp_path, projects, opencode_server.server_address[1], operations="health"
    )
    with pytest.raises(Tier1Violation) as exc:
        _tool(tier1, "run")
    assert "allowlist" in str(exc.value)


async def test_operation_outside_the_allowlist_is_refused_by_the_executor(
    tmp_path, projects, opencode_server
):
    tier1 = _toolkits_yaml(
        tmp_path, projects, opencode_server.server_address[1], operations="health"
    )
    result = await _run(tier1.toolkit("opencode"), "run", {"prompt": "go"})
    assert result.outcome == OUTCOME_FAILED
    assert "not allowed" in result.stderr


async def test_unknown_operation_in_toolkit_is_a_config_error(
    tmp_path, projects, opencode_server
):
    with pytest.raises(ConfigError) as exc:
        _toolkits_yaml(
            tmp_path,
            projects,
            opencode_server.server_address[1],
            operations="health, sudo",
        )
    assert "are not opencode operations" in str(exc.value)


async def test_resolved_ip_outside_allowed_cidrs_is_blocked(
    tmp_path, projects, opencode_server
):
    """FR-8.9: the SSRF check is on the resolved IP, per request."""
    tier1 = _toolkits_yaml(
        tmp_path,
        projects,
        opencode_server.server_address[1],
        cidrs='["10.9.9.0/24"]',
    )
    result = await _run(tier1.toolkit("opencode"), "health", {})
    assert result.outcome == OUTCOME_FAILED
    assert "allowed_cidrs" in result.stderr
    assert not STATE.requests  # nothing left this process


async def test_toolkit_requires_base_url_and_cidrs(tmp_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        "toolkits:\n"
        "  opencode:\n"
        "    executor: opencode\n"
        "    allowed_opencode_operations: [health]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_tier1(str(path))
    assert "base_url" in str(exc.value)


# -- Timeouts --------------------------------------------------------------


async def test_run_timeout_is_unknown_not_failed(toolkit):
    """A non-idempotent operation that timed out may still be running --
    reported as UNKNOWN with the session id, so the follow-up is `check`,
    not a retry that would start the work twice.
    """
    STATE.never_finish = True
    result = await _run(toolkit, "run", {"prompt": "endless"}, timeout=1, idempotent=False)
    assert result.outcome == OUTCOME_UNKNOWN
    assert "UNKNOWN" in result.stderr
    assert "check operation" in result.stderr
    # The session the workflow created itself is named -- without it the
    # agent could never check on work that is still running.
    assert STATE.sessions
    assert next(iter(STATE.sessions)) in result.stderr


async def test_idempotent_timeout_is_failed(toolkit):
    STATE.never_finish = True
    result = await _run(toolkit, "run", {"prompt": "endless"}, timeout=1, idempotent=True)
    assert result.outcome == OUTCOME_FAILED
    assert "UNKNOWN" not in result.stderr


# -- Credential ------------------------------------------------------------


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "cred-logs"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store.create(
        "opencode", kind="basic", value="opencode:s3cret", actor="test", rev=""
    )
    return store


async def test_credential_is_sent_as_a_basic_auth_header(
    tmp_path, projects, opencode_server, credentials
):
    tier1 = _toolkits_yaml(
        tmp_path,
        projects,
        opencode_server.server_address[1],
        credential="opencode",
    )
    result = await _run(
        tier1.toolkit("opencode"), "health", {}, credentials=credentials
    )
    assert result.outcome == OUTCOME_OK
    import base64

    expected = base64.b64encode(b"opencode:s3cret").decode("ascii")
    assert _header_of("/global/health", "Authorization") == f"Basic {expected}"


async def test_missing_credential_is_reported_not_ignored(
    tmp_path, projects, opencode_server
):
    tier1 = _toolkits_yaml(
        tmp_path,
        projects,
        opencode_server.server_address[1],
        credential="opencode",
    )
    result = await _run(tier1.toolkit("opencode"), "health", {}, credentials=None)
    assert result.outcome == OUTCOME_FAILED
    assert "credential store" in result.stderr


# -- Tool definition contract ----------------------------------------------


def test_missing_required_parameter_is_a_config_error(tier1):
    with pytest.raises(ConfigError) as exc:
        _tool(tier1, "ask", parameters={"directory": _PARAMS["directory"]})
    assert "needs a 'prompt' parameter" in str(exc.value)


def test_optional_required_parameter_is_a_config_error(tier1):
    with pytest.raises(ConfigError) as exc:
        _tool(
            tier1,
            "ask",
            parameters={"prompt": {**_PARAMS["prompt"], "required": False}},
        )
    assert "must be required" in str(exc.value)


def test_parameter_the_operation_does_not_read_is_a_config_error(tier1):
    """A `dir` typo would be accepted, ignored, and only visible as
    opencode working in the wrong repository -- so it fails at load.
    """
    with pytest.raises(ConfigError) as exc:
        _tool(
            tier1,
            "ask",
            parameters={
                "prompt": _PARAMS["prompt"],
                "dir": {**_PARAMS["directory"], "required": False},
            },
        )
    assert "does not read ['dir']" in str(exc.value)


def test_unknown_operation_in_a_tool_is_a_config_error(tier1):
    with pytest.raises(ConfigError) as exc:
        _tool(tier1, "ask", opencode_operation="deploy")
    assert "is unknown" in str(exc.value)


def test_health_tool_takes_no_parameters(tier1):
    tool = _tool(tier1, "health")
    assert tool.parameters == {}
    assert tool.input_schema()["properties"] == {}


# -- Reading opencode's responses tolerantly -------------------------------


def test_session_done_is_read_from_any_of_the_known_signals():
    done = execute_opencode._session_is_done
    assert done({"status": "idle"})
    assert done({"state": "completed"})
    assert done({"idle": True})
    assert done({"busy": False})
    assert done({"time": {"completed": 1735689600}})
    assert done({"error": {"message": "boom"}})
    # Nothing recognisable means "keep polling", never "finished".
    assert not done({"status": "running"})
    assert not done({"unrelated": "shape"})
    assert not done({})


def test_summary_falls_back_to_the_raw_payload_when_nothing_was_recognised():
    """An upstream rename costs a less tidy answer, not an empty one."""
    summary = execute_opencode._summarise(
        {"operation": "providers", "providers": []},
        {"totally": {"different": "shape"}},
        "providers",
    )
    assert summary["raw"] == {"totally": {"different": "shape"}}


def test_summary_keeps_quiet_when_a_field_was_recognised():
    summary = execute_opencode._summarise(
        {"operation": "ask", "answer": "hi"}, {"parts": []}, "answer"
    )
    assert "raw" not in summary


def test_message_text_reads_all_three_answer_shapes():
    text = execute_opencode._message_text
    assert text("plain") == "plain"
    assert text({"text": "wrapped"}) == "wrapped"
    assert text({"parts": [{"text": "a"}, {"text": "b"}]}) == "a\nb"


# -- Redirects -------------------------------------------------------------


async def test_redirect_is_reported_not_followed(toolkit, monkeypatch):
    """FR-8.8 holds inside a workflow too, not just for a single request."""
    monkeypatch.setitem(execute_opencode._EP, "health", ("GET", "/api/redirect"))
    result = await _run(toolkit, "health", {})
    assert result.outcome == OUTCOME_FAILED
    assert "not followed" in result.stderr
    assert "evil.example" in result.stderr


# -- The request body ------------------------------------------------------


def test_prompt_body_is_opencodes_own_shape():
    body = execute_opencode._prompt_body(
        {"prompt": "fix it", "model": "anthropic/claude-opus-5", "agent": "build"}
    )
    assert body == {
        "parts": [{"type": "text", "text": "fix it"}],
        "providerID": "anthropic",
        "modelID": "claude-opus-5",
        "agent": "build",
    }


def test_prompt_body_omits_what_the_call_did_not_name():
    """An explicit null would override opencode's own default; absence
    defers to it.
    """
    assert execute_opencode._prompt_body({"prompt": "hi"}) == {
        "parts": [{"type": "text", "text": "hi"}]
    }


async def test_model_without_a_provider_is_denied(toolkit):
    result = await _run(
        toolkit, "ask", {"prompt": "hi", "model": "claude-opus-5"}
    )
    assert result.outcome == OUTCOME_FAILED
    assert "provider/model" in result.stderr


# -- Output ceiling --------------------------------------------------------


async def test_response_over_the_output_ceiling_is_reported_not_truncated(toolkit):
    """Half a JSON document is not a smaller JSON document -- the call
    says the ceiling was hit rather than handing back an unparseable body.
    """
    result = await execute_opencode.run(
        operation="health",
        values={},
        toolkit=toolkit,
        credentials=None,
        timeout_seconds=10,
        max_output_bytes=8,
        idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "max_output_bytes" in result.stderr


# -- base_url is not a place for a secret ----------------------------------


def test_credential_placeholder_in_base_url_is_refused(tmp_path):
    """`http`'s Telegram exception (FR-8.10) has no counterpart here: the
    opencode executor never substitutes it, so it would be sent literally.
    """
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        "toolkits:\n"
        "  opencode:\n"
        "    executor: opencode\n"
        '    base_url: "http://host:4096/{credential}"\n'
        '    allowed_cidrs: ["127.0.0.1/32"]\n'
        "    allowed_opencode_operations: [health]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_tier1(str(path))
    assert "credential" in str(exc.value)


# -- Probe -----------------------------------------------------------------


async def test_probe_is_true_for_a_reachable_server(toolkit):
    assert await execute_opencode.probe(toolkit) is True


async def test_probe_is_false_when_the_ip_is_outside_allowed_cidrs(
    tmp_path, projects, opencode_server
):
    tier1 = _toolkits_yaml(
        tmp_path, projects, opencode_server.server_address[1], cidrs='["10.9.9.0/24"]'
    )
    assert await execute_opencode.probe(tier1.toolkit("opencode")) is False


# -- End to end, through the whole call pipeline ---------------------------


@pytest.fixture
def opencode_service(tmp_path, tier1):
    """A real `Service` over the opencode toolkit and its eight tools.

    Direct `execute_opencode.run` calls above prove the executor; this
    proves the wiring around it -- authorize, validate,
    `build_opencode_call`, dispatch, audit -- which is the half a
    per-executor test usually leaves to a later surprise.
    """
    from conftest import make_catalog

    from gatekeeper.audit import AuditLog
    from gatekeeper.identity import Identity
    from gatekeeper.service import Service

    catalog = make_catalog(
        tmp_path,
        tier1,
        [_tool_spec(op) for op in sorted(OPENCODE_OPERATION_PARAMS)],
    )
    audit = AuditLog(str(tmp_path / "e2e-logs"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    identity = Identity(
        id="dev",
        role="agent",
        token_hash="x",
        tools=frozenset(f"opencode.{op}" for op in OPENCODE_OPERATION_PARAMS),
        scopes=(),
    )
    return service, identity


async def test_end_to_end_ask_through_the_service(opencode_service, projects):
    service, identity = opencode_service
    result = await service.call(
        identity,
        "opencode.ask",
        {"prompt": "what is 2+2?", "directory": str(projects / "demo")},
    )
    assert result.outcome == OUTCOME_OK
    assert json.loads(result.stdout)["answer"] == "The answer is 4."
    assert _header_of("/session", "x-opencode-directory") == str(projects / "demo")


async def test_end_to_end_bad_directory_is_an_audited_denial(
    opencode_service, tmp_path
):
    """A `directory` outside path_roots is refused before anything leaves
    the process, and lands in the audit log as `denied` -- not as a failed
    call, and not as an exception escaping `Service.call`.
    """
    service, identity = opencode_service
    with pytest.raises(Denied):
        await service.call(
            identity, "opencode.ask", {"prompt": "hi", "directory": "/etc"}
        )
    assert not STATE.requests

    records = [
        json.loads(line)
        for line in (tmp_path / "e2e-logs" / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    denied = [r for r in records if r.get("outcome") == "denied"]
    assert denied and denied[-1]["tool"] == "opencode.ask"
    assert denied[-1]["denial_reason"] == "path_escape"
