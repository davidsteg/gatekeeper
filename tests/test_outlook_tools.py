"""The Outlook tools: the Graph calls they make and the executor that runs them.

Two halves, both against something real rather than a mock of the thing
under test:

1. `microsoft_api.py` against a loopback HTTP server the test starts
   itself -- the same choice `test_execute_http.py` makes. What matters
   here is the exact request that leaves the process: the Graph path, the
   `$top`/`$select`/`$orderby` query, the Bearer header, the JSON body of
   a `sendMail`, and that a 202 with no body is the *success* of a send
   rather than an empty answer to be reported as a failure.
2. `execute_microsoft.py` against a real stub script, not a mocked
   subprocess -- the properties that matter (no shell, the token file
   actually lands at `$HOME/.hermes/microsoft_token.json`, the JSON
   output is actually capped) are exactly what a mocked subprocess would
   silently assume away.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import textwrap
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from gatekeeper import execute_microsoft, validate
from gatekeeper.catalog import parse_tool_spec
from gatekeeper.errors import ConfigError
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN
from gatekeeper.tier1 import load_tier1

MICROSOFT_API_PATH = (
    Path(__file__).resolve().parents[1]
    / "src" / "gatekeeper" / "_microsoft_api" / "microsoft_api.py"
)

ACCESS_TOKEN = "EwB.access-token-value"
REFRESH_TOKEN = "M.R3_BAY.refresh-token-value"
STORED_SCOPES = [
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/Mail.Send",
    "offline_access",
]


# -- A loopback stand-in for login.microsoftonline.com + graph.microsoft.com


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def _handle(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        parsed = urllib.parse.urlparse(self.path)
        self.server.requests.append(
            {
                "method": method,
                "path": parsed.path,
                "query": dict(urllib.parse.parse_qsl(parsed.query)),
                "headers": dict(self.headers),
                "body": raw.decode("utf-8") if raw else "",
            }
        )
        status, payload = self.server.responder(method, parsed.path)
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


@pytest.fixture
def graph():
    """A real listener on 127.0.0.1, recording every request it serves.

    `script` maps (method, path) to (status, payload); `/token` always
    answers with an access token unless the test overrides it, because
    every Graph call mints one first.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    server.script = {}
    server.token_response = (
        200,
        {
            "token_type": "Bearer",
            "access_token": ACCESS_TOKEN,
            "expires_in": 3599,
            "scope": " ".join(STORED_SCOPES[:2]),
        },
    )

    def responder(method: str, path: str):
        if path == "/token":
            return server.token_response
        return server.script.get((method, path), (404, {"error": {"code": "NotFound"}}))

    server.responder = responder
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture
def api(graph, tmp_path, monkeypatch):
    """microsoft_api.py, loaded fresh and pointed at the loopback server."""
    home = tmp_path / "hermes-home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location(
        "microsoft_api_graph_test", MICROSOFT_API_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    base = f"http://127.0.0.1:{graph.server_address[1]}"
    module.TOKEN_ENDPOINT = f"{base}/token"
    module.GRAPH_BASE = f"{base}/v1.0"
    module.TOKEN_PATH.write_text(
        json.dumps(
            {
                "client_id": "azure-app-client-id",
                "client_secret": "azure-app-secret",
                "refresh_token": REFRESH_TOKEN,
                "scopes": STORED_SCOPES,
            }
        ),
        encoding="utf-8",
    )
    return module


class _Args:
    """argparse.Namespace stand-in -- the action functions read attributes."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _graph_requests(graph) -> list[dict]:
    return [r for r in graph.requests if r["path"] != "/token"]


# -- The refresh that precedes every call -----------------------------------


def test_the_refresh_is_form_encoded_and_asks_for_the_stored_scopes(api, graph):
    graph.script[("GET", "/v1.0/me/mailFolders")] = (200, {"value": []})
    api.mail_folders(_Args(max=10))

    token_request = next(r for r in graph.requests if r["path"] == "/token")
    assert token_request["method"] == "POST"
    assert token_request["headers"]["Content-Type"] == (
        "application/x-www-form-urlencoded"
    )
    form = dict(urllib.parse.parse_qsl(token_request["body"]))
    assert form["grant_type"] == "refresh_token"
    assert form["refresh_token"] == REFRESH_TOKEN
    assert form["client_id"] == "azure-app-client-id"
    # Exactly the stored grant: not a superset, not the module fallback.
    # Anything wider is answered with `invalid_scope`, and that refusal
    # kills the refresh itself rather than the one call.
    assert form["scope"].split(" ") == STORED_SCOPES


def test_a_rotated_refresh_token_is_written_back(api, graph):
    """Microsoft retires the old refresh token when it issues a new one,
    so a second call in the same materialization needs the new one."""
    graph.token_response = (
        200,
        {"access_token": ACCESS_TOKEN, "refresh_token": "M.R3_BAY.rotated"},
    )
    graph.script[("GET", "/v1.0/me/mailFolders")] = (200, {"value": []})
    api.mail_folders(_Args(max=10))

    stored = json.loads(api.TOKEN_PATH.read_text())
    assert stored["refresh_token"] == "M.R3_BAY.rotated"
    assert stored["scopes"] == STORED_SCOPES
    assert api.TOKEN_PATH.stat().st_mode & 0o077 == 0


def test_a_refused_refresh_is_a_401_not_a_crash(api, graph):
    graph.token_response = (400, {"error": "invalid_grant"})

    with pytest.raises(api.GraphError) as excinfo:
        api.mail_folders(_Args(max=10))
    assert excinfo.value.code == 401
    # The error name travels; the description (which may quote the
    # request back) does not.
    assert "invalid_grant" in excinfo.value.message
    assert "azure-app-secret" not in excinfo.value.message


# -- outlook.list_messages --------------------------------------------------


def test_list_messages_calls_the_folder_endpoint_with_a_bearer_token(api, graph):
    graph.script[("GET", "/v1.0/me/mailFolders/inbox/messages")] = (
        200,
        {
            "value": [
                {
                    "id": "AAMk-1",
                    "subject": "Deploy finished",
                    "from": {"emailAddress": {"name": "CI", "address": "ci@example.com"}},
                    "toRecipients": [
                        {"emailAddress": {"address": "me@outlook.com"}}
                    ],
                    "receivedDateTime": "2026-09-23T10:00:00Z",
                    "isRead": False,
                    "hasAttachments": False,
                    "bodyPreview": "All green.",
                }
            ]
        },
    )

    result = api.mail_list(_Args(folder="inbox", max=25, search="", unread=False))

    request = _graph_requests(graph)[0]
    assert request["method"] == "GET"
    assert request["path"] == "/v1.0/me/mailFolders/inbox/messages"
    assert request["query"]["$top"] == "25"
    assert request["query"]["$orderby"] == "receivedDateTime desc"
    assert "bodyPreview" in request["query"]["$select"]
    # A listing asks for the preview, never the body: a hundred mail
    # bodies is a wall of external, injection-bearing text where a
    # subject line would have done.
    assert "body," not in request["query"]["$select"]
    assert request["headers"]["Authorization"] == f"Bearer {ACCESS_TOKEN}"

    # Graph's three-deep address nesting is flattened for the agent.
    assert result == [
        {
            "id": "AAMk-1",
            "subject": "Deploy finished",
            "from": "ci@example.com",
            "to": ["me@outlook.com"],
            "received": "2026-09-23T10:00:00Z",
            "unread": True,
            "has_attachments": False,
            "preview": "All green.",
        }
    ]


def test_list_messages_caps_the_page_size(api, graph):
    graph.script[("GET", "/v1.0/me/mailFolders/inbox/messages")] = (200, {"value": []})
    api.mail_list(_Args(folder="inbox", max=100000, search="", unread=False))

    assert _graph_requests(graph)[0]["query"]["$top"] == str(api.MAX_PAGE_SIZE)


def test_a_folder_id_is_percent_encoded_into_the_path(api, graph):
    """Folder IDs are base64url-ish and the only caller-supplied part of
    a Graph URL -- they are encoded, never concatenated raw."""
    folder = "AAMkAGI2/segment"
    graph.script[
        ("GET", f"/v1.0/me/mailFolders/{urllib.parse.quote(folder, safe='')}/messages")
    ] = (200, {"value": []})

    api.mail_list(_Args(folder=folder, max=5, search="", unread=False))

    path = _graph_requests(graph)[0]["path"]
    assert path == "/v1.0/me/mailFolders/AAMkAGI2%2Fsegment/messages"


def test_a_search_drops_the_orderby(api, graph):
    """Graph answers `$search` together with `$orderby` with a 400."""
    graph.script[("GET", "/v1.0/me/mailFolders/inbox/messages")] = (200, {"value": []})
    api.mail_list(_Args(folder="inbox", max=5, search="invoice", unread=False))

    query = _graph_requests(graph)[0]["query"]
    assert query["$search"] == '"invoice"'
    assert "$orderby" not in query


def test_unread_becomes_a_filter(api, graph):
    graph.script[("GET", "/v1.0/me/mailFolders/inbox/messages")] = (200, {"value": []})
    api.mail_list(_Args(folder="inbox", max=5, search="", unread=True))

    assert _graph_requests(graph)[0]["query"]["$filter"] == "isRead eq false"


# -- outlook.get_message ----------------------------------------------------


def test_get_message_returns_the_body(api, graph):
    graph.script[("GET", "/v1.0/me/messages/AAMk-1")] = (
        200,
        {
            "id": "AAMk-1",
            "subject": "Deploy finished",
            "from": {"emailAddress": {"address": "ci@example.com"}},
            "toRecipients": [{"emailAddress": {"address": "me@outlook.com"}}],
            "ccRecipients": [{"emailAddress": {"address": "ops@example.com"}}],
            "receivedDateTime": "2026-09-23T10:00:00Z",
            "sentDateTime": "2026-09-23T09:59:00Z",
            "isRead": True,
            "hasAttachments": False,
            "bodyPreview": "All green.",
            "body": {"contentType": "text", "content": "All green. Nothing to do."},
            "conversationId": "conv-1",
            "webLink": "https://outlook.office.com/mail/id/AAMk-1",
        },
    )

    result = api.mail_get(_Args(message_id="AAMk-1"))

    request = _graph_requests(graph)[0]
    assert request["path"] == "/v1.0/me/messages/AAMk-1"
    # Asking for one message by id *is* asking for its content.
    assert "body" in request["query"]["$select"].split(",")
    assert result["body"] == "All green. Nothing to do."
    assert result["body_type"] == "text"
    assert result["cc"] == ["ops@example.com"]
    assert result["unread"] is False
    assert result["web_link"].endswith("AAMk-1")


# -- outlook.list_folders ---------------------------------------------------


def test_list_folders_returns_names_and_counts(api, graph):
    graph.script[("GET", "/v1.0/me/mailFolders")] = (
        200,
        {
            "value": [
                {
                    "id": "AAMk-inbox",
                    "displayName": "Inbox",
                    "unreadItemCount": 3,
                    "totalItemCount": 412,
                }
            ]
        },
    )

    result = api.mail_folders(_Args(max=50))

    assert _graph_requests(graph)[0]["path"] == "/v1.0/me/mailFolders"
    assert result == [
        {"id": "AAMk-inbox", "name": "Inbox", "unread": 3, "total": 412}
    ]


# -- outlook.send_mail ------------------------------------------------------


def test_send_mail_posts_the_graph_message_shape(api, graph):
    graph.script[("POST", "/v1.0/me/sendMail")] = (202, None)

    result = api.mail_send(
        _Args(
            to="a@example.com, b@example.com",
            cc="c@example.com",
            subject="Status",
            body="All green.",
            html=False,
        )
    )

    request = _graph_requests(graph)[0]
    assert request["method"] == "POST"
    assert request["path"] == "/v1.0/me/sendMail"
    assert request["headers"]["Content-Type"] == "application/json"
    sent = json.loads(request["body"])
    assert sent["saveToSentItems"] is True
    assert sent["message"]["subject"] == "Status"
    assert sent["message"]["body"] == {
        "contentType": "Text", "content": "All green.",
    }
    assert sent["message"]["toRecipients"] == [
        {"emailAddress": {"address": "a@example.com"}},
        {"emailAddress": {"address": "b@example.com"}},
    ]
    assert sent["message"]["ccRecipients"] == [
        {"emailAddress": {"address": "c@example.com"}}
    ]
    assert result == {
        "status": "sent",
        "http_status": 202,
        "to": ["a@example.com", "b@example.com"],
        "cc": ["c@example.com"],
        "subject": "Status",
    }


def test_a_202_with_no_body_is_the_success(api, graph):
    """`POST /me/sendMail` answers 202 Accepted and nothing else -- Graph
    has queued the message, it has not handed back a resource. Treating
    "no body" as a failure would report every sent mail as an error."""
    graph.script[("POST", "/v1.0/me/sendMail")] = (202, None)

    result = api.mail_send(
        _Args(to="a@example.com", cc="", subject="s", body="b", html=False)
    )

    assert result["status"] == "sent"
    assert result["http_status"] == 202


def test_html_selects_the_html_content_type(api, graph):
    graph.script[("POST", "/v1.0/me/sendMail")] = (202, None)
    api.mail_send(
        _Args(to="a@example.com", cc="", subject="s", body="<b>hi</b>", html=True)
    )

    sent = json.loads(_graph_requests(graph)[0]["body"])
    assert sent["message"]["body"]["contentType"] == "HTML"


def test_send_without_a_recipient_never_reaches_graph(api, graph):
    with pytest.raises(api.GraphError) as excinfo:
        api.mail_send(_Args(to="  ,  ", cc="", subject="s", body="b", html=False))

    assert excinfo.value.code == 400
    assert _graph_requests(graph) == []


# -- Graph's failures -------------------------------------------------------


def test_a_403_carries_graphs_own_code(api, graph):
    graph.script[("GET", "/v1.0/me/mailFolders")] = (
        403,
        {"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}},
    )

    with pytest.raises(api.GraphError) as excinfo:
        api.mail_folders(_Args(max=10))
    assert excinfo.value.code == 403
    assert "Access is denied." in excinfo.value.message


def test_a_401_carries_graphs_own_code(api, graph):
    graph.script[("GET", "/v1.0/me/mailFolders")] = (
        401,
        {"error": {"code": "InvalidAuthenticationToken", "message": "expired"}},
    )

    with pytest.raises(api.GraphError) as excinfo:
        api.mail_folders(_Args(max=10))
    assert excinfo.value.code == 401


# -- The executor -----------------------------------------------------------
#
# A real stub script standing in for microsoft_api.py, selected by the
# action string the executor passes -- the same arrangement
# test_execute_google.py uses, for the same reason.


STUB = '''\
import json, os, sys, time

token_path = os.path.join(
    os.environ.get("HOME", ""), ".hermes", "microsoft_token.json"
)
if not os.path.isfile(token_path):
    print(json.dumps({"code": 401, "message": "token file not found"}), file=sys.stderr)
    sys.exit(1)

action = " ".join(sys.argv[1:])

if "expire" in action:
    print(json.dumps({"code": 401, "message": "invalid_grant"}), file=sys.stderr)
    sys.exit(1)
if "scope" in action:
    print(json.dumps({"code": 403, "message": "insufficient privileges"}), file=sys.stderr)
    sys.exit(1)
if "boom" in action:
    print("not json at all", file=sys.stderr)
    sys.exit(2)
if "slow" in action:
    time.sleep(2)
if "big" in action:
    print(json.dumps([{"id": str(i)} for i in range(1000)]))
    sys.exit(0)

if action.startswith("mail list"):
    print(json.dumps([{"id": "AAMk-1", "subject": "hello"}]))
elif action.startswith("mail send"):
    print(json.dumps({"status": "sent", "http_status": 202, "argv": sys.argv[1:]}))
elif action.startswith("mail folders"):
    print(json.dumps([{"id": "AAMk-inbox", "name": "Inbox"}]))
else:
    print(json.dumps({"ok": True, "action": action}))
sys.exit(0)
'''


@pytest.fixture(scope="module")
def microsoft_script(tmp_path_factory):
    d = tmp_path_factory.mktemp("microsoft-api")
    path = os.path.join(str(d), "microsoft_api.py")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(textwrap.dedent(STUB))
    os.chmod(path, 0o755)
    return path


@pytest.fixture
def toolkit(tmp_path, microsoft_script):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "outlook": {
                        "executor": "microsoft",
                        "microsoft_script": microsoft_script,
                        "allowed_microsoft_actions": [
                            "mail list", "mail get", "mail folders", "mail send",
                            "mail list expire", "mail list scope",
                            "mail list slow", "mail list big", "mail list boom",
                        ],
                        "credential": "msgraph",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 131072,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    return tier1.toolkit("outlook"), tier1


@pytest.fixture
def token_env(tmp_path):
    """A HOME with a token file, for direct execute_microsoft.run calls
    that bypass service.call's materialization."""
    home = tmp_path / "fake-home"
    hermes = home / ".hermes"
    hermes.mkdir(parents=True)
    (hermes / "microsoft_token.json").write_text(
        json.dumps(
            {
                "client_id": "azure-app-client-id",
                "client_secret": "azure-app-secret",
                "refresh_token": REFRESH_TOKEN,
                "scopes": STORED_SCOPES,
            }
        ),
        encoding="utf-8",
    )
    return {"HOME": str(home)}


def _tool(tier1, **overrides):
    spec = {
        "id": "outlook.list_messages",
        "toolkit": "outlook",
        "version": 1,
        "title": "List mail",
        "description": "Lists Outlook messages.",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "microsoft_action": "mail list",
        "microsoft_args": {
            "folder": {"flag": "--folder"},
            "max_results": {"flag": "--max"},
        },
        "parameters": {
            "folder": {"type": "string", "required": False,
                       "pattern": "^[A-Za-z0-9=_-]{1,200}$",
                       "description": "Folder."},
            "max_results": {"type": "integer", "required": False, "minimum": 1,
                            "maximum": 100, "description": "Max."},
        },
        "required_scopes": ["Mail.Read"],
        "timeout_seconds": 10,
        "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return parse_tool_spec(spec, tier1)


async def test_the_executor_runs_the_script_and_parses_its_json(
    toolkit, token_env
):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    args = validate.build_microsoft_call(
        tool, {"folder": "inbox", "max_results": "10"}, tk
    )

    result = await execute_microsoft.run(
        microsoft_action="mail list",
        args=args,
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=token_env,
    )

    assert result.outcome == OUTCOME_OK
    assert json.loads(result.stdout) == [{"id": "AAMk-1", "subject": "hello"}]
    # Graph answers are external, potentially injection-bearing data.
    assert result.external_untrusted is True


def test_the_argv_tail_is_one_element_per_parameter(toolkit):
    """FR-5.4: a parameter value cannot structurally produce a second
    argument, whatever it contains."""
    tk, tier1 = toolkit
    tool = _tool(tier1)

    assert validate.build_microsoft_call(
        tool, {"folder": "inbox --max 999", "max_results": "10"}, tk
    ) == ["--folder", "inbox --max 999", "--max", "10"]


def test_a_positional_arg_is_the_bare_value(toolkit):
    tk, tier1 = toolkit
    tool = _tool(
        tier1,
        id="outlook.get_message",
        microsoft_action="mail get",
        microsoft_args={"message_id": {"positional": True}},
        parameters={
            "message_id": {"type": "string", "required": True,
                           "pattern": "^[A-Za-z0-9=_-]{1,512}$",
                           "description": "ID."},
        },
    )

    assert validate.build_microsoft_call(tool, {"message_id": "AAMk-1"}, tk) == [
        "AAMk-1"
    ]


def test_the_service_token_is_prefixed_onto_a_bare_action(toolkit):
    """`microsoft_api.py list` is a usage error; the CLI wants a service."""
    tk, _tier1 = toolkit

    assert execute_microsoft._action_argv(tk, "list") == ["mail", "list"]
    # An action that already names its service is left alone -- prefixing
    # it again would run `mail mail list`.
    assert execute_microsoft._action_argv(tk, "mail list") == ["mail", "list"]


def test_the_argv_never_carries_the_credential(toolkit, microsoft_script):
    """FR-10.2: a secret never sits in a process argument list."""
    tk, _tier1 = toolkit
    argv = execute_microsoft._build_argv(tk, "mail list", ["--folder", "inbox"])

    assert argv[0] == sys.executable
    assert argv[1] == microsoft_script
    assert argv[2:] == ["mail", "list", "--folder", "inbox"]
    assert not any(REFRESH_TOKEN in part for part in argv)


async def test_an_action_outside_the_whitelist_is_refused(toolkit, token_env):
    """Defensive re-check: the action is fixed per tool, so this can only
    fail on a programming error -- and then it fails closed."""
    tk, _tier1 = toolkit

    result = await execute_microsoft.run(
        microsoft_action="mail delete",
        args=[],
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=token_env,
    )

    assert result.outcome == OUTCOME_FAILED
    assert "not allowed" in result.stderr


def test_a_tool_naming_an_unlisted_action_does_not_load(toolkit):
    """Tier 1 refuses at load time, not at call time: a tool naming an
    action its toolkit does not allow never enters the catalog."""
    _tk, tier1 = toolkit

    with pytest.raises(ConfigError):
        _tool(tier1, id="outlook.delete", microsoft_action="mail delete",
              microsoft_args={})


async def test_a_dead_grant_says_what_to_do_about_it(toolkit, token_env):
    tk, _tier1 = toolkit
    result = await execute_microsoft.run(
        microsoft_action="mail list expire", args=[], toolkit=tk,
        timeout_seconds=10, max_output_bytes=65536, idempotent=True, env=token_env,
    )

    assert result.outcome == OUTCOME_FAILED
    assert "authentication failed" in result.stderr
    assert "Re-run the OAuth consent flow" in result.stderr


async def test_a_missing_scope_says_what_to_do_about_it(toolkit, token_env):
    tk, _tier1 = toolkit
    result = await execute_microsoft.run(
        microsoft_action="mail list scope", args=[], toolkit=tk,
        timeout_seconds=10, max_output_bytes=65536, idempotent=True, env=token_env,
    )

    assert result.outcome == OUTCOME_FAILED
    assert "scope not covered" in result.stderr


async def test_a_non_json_failure_is_reported_plainly(toolkit, token_env):
    tk, _tier1 = toolkit
    result = await execute_microsoft.run(
        microsoft_action="mail list boom", args=[], toolkit=tk,
        timeout_seconds=10, max_output_bytes=65536, idempotent=True, env=token_env,
    )

    assert result.outcome == OUTCOME_FAILED
    assert "not json at all" in result.stderr


async def test_a_long_list_is_capped(toolkit, token_env):
    """A mailbox listing is the same list-length risk an HTTP REST
    response is (FR-8.12)."""
    tk, _tier1 = toolkit
    result = await execute_microsoft.run(
        microsoft_action="mail list big", args=[], toolkit=tk,
        timeout_seconds=10, max_output_bytes=1_000_000, idempotent=True, env=token_env,
    )

    assert result.outcome == OUTCOME_OK
    assert len(json.loads(result.stdout)) < 1000


async def test_a_timeout_on_a_non_idempotent_call_is_unknown(toolkit, token_env):
    """A send that timed out may have reached Microsoft."""
    tk, _tier1 = toolkit
    result = await execute_microsoft.run(
        microsoft_action="mail list slow", args=[], toolkit=tk,
        timeout_seconds=1, max_output_bytes=65536, idempotent=False, env=token_env,
    )

    assert result.outcome == OUTCOME_UNKNOWN
    assert "may have reached Microsoft" in result.stderr


async def test_a_missing_script_is_a_clear_denial(tmp_path, token_env):
    path = tmp_path / "toolkits-missing.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "outlook": {
                        "executor": "microsoft",
                        "microsoft_script": "/nonexistent/microsoft_api.py",
                        "allowed_microsoft_actions": ["mail list"],
                        "credential": "msgraph",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 8192,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs-missing")},
            }
        ),
        encoding="utf-8",
    )
    tk = load_tier1(str(path)).toolkit("outlook")

    result = await execute_microsoft.run(
        microsoft_action="mail list", args=[], toolkit=tk,
        timeout_seconds=5, max_output_bytes=8192, idempotent=True, env=token_env,
    )

    assert result.outcome == OUTCOME_FAILED
    assert not await execute_microsoft.probe(tk)


async def test_probe_reports_a_present_script(toolkit):
    tk, _tier1 = toolkit
    assert await execute_microsoft.probe(tk)


async def test_a_toolkit_naming_a_path_this_image_lacks_falls_back(
    tmp_path, token_env, microsoft_script, monkeypatch, caplog
):
    """A toolkit written against a host path that is not in this
    container would otherwise die on a FileNotFound naming only the path
    that is wrong. The image's own copy stands in, and the warning is
    what keeps the substitution from being silent.
    """
    path = tmp_path / "toolkits-fallback.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "outlook": {
                        "executor": "microsoft",
                        "microsoft_script": "/srv/host-mount/microsoft_api.py",
                        "allowed_microsoft_actions": ["mail list"],
                        "credential": "msgraph",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 8192,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs-fallback")},
            }
        ),
        encoding="utf-8",
    )
    tk = load_tier1(str(path)).toolkit("outlook")
    monkeypatch.setattr(
        execute_microsoft, "MICROSOFT_FALLBACK_SCRIPT", microsoft_script
    )

    assert execute_microsoft._build_argv(tk, "mail list", [])[1] == microsoft_script

    result = await execute_microsoft.run(
        microsoft_action="mail list", args=[], toolkit=tk,
        timeout_seconds=10, max_output_bytes=8192, idempotent=True, env=token_env,
    )
    assert result.outcome == OUTCOME_OK

    # A readiness poll must not write a log line per probe.
    caplog.clear()
    assert await execute_microsoft.probe(tk)
    assert caplog.records == []


# -- Three name spaces, one operation ---------------------------------------
#
# `outlook.list_messages` is a *tool ID*; `mail list` is the *action ID*
# Tier 1 whitelists and `microsoft_action` names; `mail list --folder
# inbox` is the *CLI argv* microsoft_api.py's argparse grammar accepts.
# A deployment that spells its action IDs after its tool IDs
# (`list_messages`) is internally consistent, loads clean -- and then
# every call dies on `invalid choice: 'list_messages'`. These tests pin
# the bridge: `execute_microsoft.MICROSOFT_ACTION_ALIASES`.


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        # The tool-shaped spelling, bare and with its service named.
        ("list_messages", ["mail", "list"]),
        ("mail list_messages", ["mail", "list"]),
        ("get_message", ["mail", "get"]),
        ("mail get_message", ["mail", "get"]),
        ("list_folders", ["mail", "folders"]),
        ("mail list_folders", ["mail", "folders"]),
        ("send_mail", ["mail", "send"]),
        ("mail send_mail", ["mail", "send"]),
        # The CLI's own spelling, bare and qualified -- unchanged.
        ("list", ["mail", "list"]),
        ("mail list", ["mail", "list"]),
        ("get", ["mail", "get"]),
        ("mail get", ["mail", "get"]),
        ("folders", ["mail", "folders"]),
        ("mail folders", ["mail", "folders"]),
        ("send", ["mail", "send"]),
        ("mail send", ["mail", "send"]),
    ],
)
def test_every_spelling_of_the_four_actions_reaches_the_cli_word(
    toolkit, action, expected
):
    tk, _tier1 = toolkit
    assert execute_microsoft._action_argv(tk, action) == expected


def test_an_unknown_action_is_not_rewritten(toolkit):
    """The table is four entries, not a rule: a name it has never heard
    of reaches the CLI as written and fails there, loudly."""
    tk, _tier1 = toolkit

    assert execute_microsoft._action_argv(tk, "archive_message") == [
        "mail", "archive_message",
    ]
    assert execute_microsoft._action_argv(tk, "mail move") == ["mail", "move"]
    assert execute_microsoft._action_argv(tk, "") == []


@pytest.fixture
def tool_shaped_toolkit(tmp_path, microsoft_script):
    """A toolkit whose whitelist is spelled in tool IDs, not CLI words.

    The configuration the bug report came from: `allowed_microsoft_actions`
    and every tool's `microsoft_action` read `list_messages`/`get_message`/
    `list_folders`/`send_mail`.
    """
    path = tmp_path / "toolkits-tool-shaped.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "outlook": {
                        "executor": "microsoft",
                        "microsoft_script": microsoft_script,
                        "allowed_microsoft_actions": [
                            "list_messages", "get_message",
                            "list_folders", "send_mail",
                        ],
                        "credential": "msgraph",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 131072,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs-tool-shaped")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    return tier1.toolkit("outlook"), tier1


@pytest.mark.parametrize(
    ("action", "args", "expected_tail"),
    [
        ("list_messages", ["--folder", "inbox", "--max", "10"],
         ["mail", "list", "--folder", "inbox", "--max", "10"]),
        ("get_message", ["AAMk-1"], ["mail", "get", "AAMk-1"]),
        ("list_folders", ["--max", "50"], ["mail", "folders", "--max", "50"]),
        ("send_mail", ["--to", "a@example.com", "--subject", "s", "--body", "b"],
         ["mail", "send", "--to", "a@example.com", "--subject", "s",
          "--body", "b"]),
    ],
)
def test_the_full_argv_for_each_action_of_a_tool_shaped_toolkit(
    tool_shaped_toolkit, microsoft_script, action, args, expected_tail
):
    """All four actions, argv end to end -- nothing is executed here."""
    tk, _tier1 = tool_shaped_toolkit

    argv = execute_microsoft._build_argv(tk, action, args)

    assert argv[0] == sys.executable
    assert argv[1] == microsoft_script
    assert argv[2:] == expected_tail


async def test_a_tool_shaped_read_action_actually_runs(
    tool_shaped_toolkit, token_env
):
    """The end the bug report started from: `list_messages` used to reach
    the CLI as `mail list_messages` and die in argparse."""
    tk, _tier1 = tool_shaped_toolkit

    result = await execute_microsoft.run(
        microsoft_action="list_messages",
        args=["--folder", "inbox"],
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=token_env,
    )

    assert result.outcome == OUTCOME_OK
    assert json.loads(result.stdout) == [{"id": "AAMk-1", "subject": "hello"}]


async def test_the_whitelist_still_gates_sending_under_either_spelling(
    tmp_path, microsoft_script, token_env
):
    """The alias table translates argv; it does not widen Tier 1. A
    mailbox toolkit that lists only the three read actions refuses to
    send, whichever of the two names the send is asked for by."""
    path = tmp_path / "toolkits-read-only.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "outlook": {
                        "executor": "microsoft",
                        "microsoft_script": microsoft_script,
                        "allowed_microsoft_actions": [
                            "list_messages", "get_message", "list_folders",
                        ],
                        "credential": "msgraph",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 8192,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs-read-only")},
            }
        ),
        encoding="utf-8",
    )
    tk = load_tier1(str(path)).toolkit("outlook")

    for spelling in ("send_mail", "mail send", "send"):
        result = await execute_microsoft.run(
            microsoft_action=spelling,
            args=["--to", "a@example.com"],
            toolkit=tk,
            timeout_seconds=5,
            max_output_bytes=8192,
            idempotent=False,
            env=token_env,
        )
        assert result.outcome == OUTCOME_FAILED
        assert "not allowed" in result.stderr
        assert result.exit_code is None  # nothing was ever started


# -- The argv against the real CLI grammar ----------------------------------
#
# The tests above assert the argv this executor builds; these assert that
# microsoft_api.py's own argparse grammar accepts it. Read actions run
# for real against the loopback Graph server (no credential of any kind
# is involved -- the token file is the fixture's own fake). `send` is
# parsed and dispatched with the network function replaced, so the send
# path is proven to parse without any message being addressed to
# anything.


def _cli_tail(toolkit, action, args):
    """The argv microsoft_api.py itself would see, without the
    interpreter and the script path."""
    tk, _tier1 = toolkit
    return execute_microsoft._build_argv(tk, action, args)[2:]


@pytest.mark.parametrize(
    ("action", "args", "path", "check"),
    [
        (
            "list_messages",
            ["--folder", "inbox", "--max", "5"],
            "/v1.0/me/mailFolders/inbox/messages",
            lambda request: request["query"]["$top"] == "5",
        ),
        (
            "get_message",
            ["AAMk-1"],
            "/v1.0/me/messages/AAMk-1",
            lambda request: "body" in request["query"]["$select"].split(","),
        ),
        (
            "list_folders",
            ["--max", "7"],
            "/v1.0/me/mailFolders",
            lambda request: request["query"]["$top"] == "7",
        ),
    ],
)
def test_a_read_actions_argv_parses_and_reaches_the_right_graph_path(
    tool_shaped_toolkit, api, graph, monkeypatch, capsys, action, args, path, check
):
    graph.script[("GET", path)] = (200, {"value": [], "id": "AAMk-1"})
    tail = _cli_tail(tool_shaped_toolkit, action, args)
    monkeypatch.setattr(sys, "argv", ["microsoft_api.py", *tail])

    api.main()

    # The CLI accepted the argv and emitted JSON, not a usage error.
    json.loads(capsys.readouterr().out)
    request = _graph_requests(graph)[0]
    assert request["path"] == path
    assert check(request)


def test_the_send_argv_parses_into_the_send_action_without_sending(
    tool_shaped_toolkit, api, graph, monkeypatch
):
    """`send_mail`'s argv is checked against the real grammar with
    `mail_send` replaced: the parse is proven, no message is composed,
    addressed or handed to Graph -- not even the loopback one."""
    seen = {}

    def _recorder(args):
        seen.update(vars(args))
        return {"status": "not sent -- test recorder"}

    monkeypatch.setattr(api, "mail_send", _recorder)
    # set_defaults captured the original function when the parser was
    # built, so the parser is rebuilt against the patched module.
    tail = _cli_tail(
        tool_shaped_toolkit,
        "send_mail",
        ["--to", "nobody@example.invalid", "--subject", "s", "--body", "b"],
    )
    monkeypatch.setattr(sys, "argv", ["microsoft_api.py", *tail])

    api.main()

    assert seen["func"] is _recorder
    assert seen["service"] == "mail"
    assert seen["action"] == "send"
    assert seen["to"] == "nobody@example.invalid"
    assert seen["html"] is False
    # Nothing left the process: no token was minted, no Graph call made.
    assert graph.requests == []
