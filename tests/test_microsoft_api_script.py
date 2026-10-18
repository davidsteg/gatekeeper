"""microsoft_api.py, the vendored Outlook CLI the `microsoft` executor runs.

Against something real rather than a mock of the thing under test:
`microsoft_api.py` against a loopback HTTP server the test starts itself.
What matters here is the exact request that leaves the process: the Graph
path, the `$top`/`$select`/`$orderby` query, the Bearer header, the JSON
body of a `sendMail`, and that a 202 with no body is the *success* of a
send rather than an empty answer to be reported as a failure -- plus the
token file's scopes reaching the refresh, and the argv the executor
builds parsing in the script's own grammar.

The executor half (rust/src/execute/microsoft.rs) has its own tests in the
crate; the argvs below are the ones it builds, pinned there too.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

MICROSOFT_API_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "microsoft" / "microsoft_api.py"
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


# -- The token file reaches the refresh -------------------------------------
#
# What the console asks a human to consent to (rust/src/oauth.rs,
# DEFAULT_MICROSOFT_SCOPES), spelled the way Microsoft spells it: Graph
# resources as URLs, `offline_access` bare. The crate checks the script's
# fallback against its own list; this checks the script uses it.

MICROSOFT_SCOPE_PREFIX = "https://graph.microsoft.com/"
CONSENTED = [
    MICROSOFT_SCOPE_PREFIX + "Mail.Read",
    MICROSOFT_SCOPE_PREFIX + "Mail.Send",
    MICROSOFT_SCOPE_PREFIX + "User.Read",
    "offline_access",
]
CLIENT_ID = "1234.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-test-client-secret-value"
NEW_REFRESH = "1//brand-new-refresh-token-value"


def _token_bundle(**extra) -> dict:
    return {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": NEW_REFRESH,
        **extra,
    }



def _load_microsoft_api(monkeypatch, hermes_home: Path):
    """Imports the vendored microsoft_api.py against a throwaway HERMES_HOME.

    The script is not part of the importable package (it runs as a
    subprocess, from `/opt/gatekeeper/microsoft/` in the image), and it
    resolves its token path once at import time -- so it is loaded from
    its file, fresh, with `HERMES_HOME` already pointing at a temp dir.
    """
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location(
        "microsoft_api_under_test", MICROSOFT_API_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def microsoft_api(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    home.mkdir()
    return _load_microsoft_api(monkeypatch, home)


def _write_token(microsoft_api, payload: dict) -> None:
    microsoft_api.TOKEN_PATH.write_text(json.dumps(payload), encoding="utf-8")


def test_stored_scopes_win_over_the_fallback(microsoft_api):
    stored = [MICROSOFT_SCOPE_PREFIX + "Mail.Read", "offline_access"]
    _write_token(microsoft_api, _token_bundle(scopes=stored))

    assert microsoft_api._stored_token_scopes() == stored


def test_the_fallback_is_what_the_console_asks_for(microsoft_api):
    """A token file with no scopes has nothing better to fall back to, so
    the fallback is at least a list the console does request -- anything
    wider is a refresh Microsoft refuses outright."""
    _write_token(microsoft_api, _token_bundle())

    assert microsoft_api._stored_token_scopes() == CONSENTED
    assert microsoft_api.SCOPES == CONSENTED


def test_the_fallback_survives_an_unreadable_token(microsoft_api):
    microsoft_api.TOKEN_PATH.write_text("{not json", encoding="utf-8")

    assert microsoft_api._stored_token_scopes() == CONSENTED


def test_the_endpoints_are_microsofts_own(microsoft_api):
    assert microsoft_api.TOKEN_ENDPOINT == (
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    )
    assert microsoft_api.GRAPH_BASE == "https://graph.microsoft.com/v1.0"


# -- The argv against the real CLI grammar ----------------------------------
#
# The argv tails below are what the executor builds for a toolkit whose
# whitelist is spelled in tool IDs (`list_messages`, ..., bridged by
# `MICROSOFT_ACTION_ALIASES`; the crate's own tests pin that build), and
# these tests assert that microsoft_api.py's own argparse grammar accepts
# them. Read actions run
# for real against the loopback Graph server (no credential of any kind
# is involved -- the token file is the fixture's own fake). `send` is
# parsed and dispatched with the network function replaced, so the send
# path is proven to parse without any message being addressed to
# anything.


@pytest.mark.parametrize(
    ("tail", "path", "check"),
    [
        (
            ["mail", "list", "--folder", "inbox", "--max", "5"],
            "/v1.0/me/mailFolders/inbox/messages",
            lambda request: request["query"]["$top"] == "5",
        ),
        (
            ["mail", "get", "AAMk-1"],
            "/v1.0/me/messages/AAMk-1",
            lambda request: "body" in request["query"]["$select"].split(","),
        ),
        (
            ["mail", "folders", "--max", "7"],
            "/v1.0/me/mailFolders",
            lambda request: request["query"]["$top"] == "7",
        ),
    ],
)
def test_a_read_actions_argv_parses_and_reaches_the_right_graph_path(
    api, graph, monkeypatch, capsys, tail, path, check
):
    graph.script[("GET", path)] = (200, {"value": [], "id": "AAMk-1"})
    monkeypatch.setattr(sys, "argv", ["microsoft_api.py", *tail])

    api.main()

    # The CLI accepted the argv and emitted JSON, not a usage error.
    json.loads(capsys.readouterr().out)
    request = _graph_requests(graph)[0]
    assert request["path"] == path
    assert check(request)


def test_the_send_argv_parses_into_the_send_action_without_sending(
    api, graph, monkeypatch
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
    tail = [
        "mail", "send",
        "--to", "nobody@example.invalid", "--subject", "s", "--body", "b",
    ]
    monkeypatch.setattr(sys, "argv", ["microsoft_api.py", *tail])

    api.main()

    assert seen["func"] is _recorder
    assert seen["service"] == "mail"
    assert seen["action"] == "send"
    assert seen["to"] == "nobody@example.invalid"
    assert seen["html"] is False
    # Nothing left the process: no token was minted, no Graph call made.
    assert graph.requests == []
