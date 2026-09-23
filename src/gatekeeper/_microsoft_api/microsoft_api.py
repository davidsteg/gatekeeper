#!/usr/bin/env python3
"""Microsoft Graph mail CLI -- the `microsoft` executor's counterpart to
`_google_api/google_api.py`.

Usage:
  python microsoft_api.py mail list [--folder inbox] [--max 10] [--search "..."]
  python microsoft_api.py mail get MESSAGE_ID
  python microsoft_api.py mail folders [--max 50]
  python microsoft_api.py mail send --to user@example.com --subject "Hi" --body "Hello"

Same contract as google_api.py, because `execute_microsoft.py` reads it
the same way: JSON on stdout and exit 0 on success, a JSON error object
on stderr and a non-zero exit on failure. The error object carries
`code`/`message` so the executor can turn a 401 into "re-run the consent
flow" and a 403 into "that scope is not in the grant" rather than
handing an agent a raw Graph body.

Authentication is an OAuth2 refresh token read from
``$HOME/.hermes/microsoft_token.json`` -- written there per call by
`service._microsoft_token_env`, never passed through argv (FR-10.2).
The file holds {client_id, client_secret, refresh_token, scopes}: the
same four fields google_token.json holds, spelled the same way, because
they mean the same thing. `scopes` is what the operator consented to,
and a refresh must ask for exactly that -- Microsoft refuses a request
for anything outside the grant with `invalid_scope`, failing the refresh
itself rather than the one call that wanted the extra scope.

Only the standard library is imported. This script is not part of the
importable package: it is copied into the image (Dockerfile) and run as
a subprocess, possibly by an interpreter that has none of gatekeeper's
dependencies on its path. `urllib.request` is therefore the HTTP client,
and HERMES_HOME is resolved inline rather than through a sibling module.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def get_hermes_home() -> Path:
    """The Hermes home directory (default: ``~/.hermes``).

    Inlined rather than imported from a sibling `_hermes_home` module the
    way google_api.py does it: that import needs a `sys.path` insert
    before it, which is a lint exception `_google_api` carries because it
    is excluded from ruff and this directory is not. Three lines of
    stdlib are cheaper than an exclusion.
    """
    value = os.environ.get("HERMES_HOME", "").strip()
    return Path(value) if value else Path.home() / ".hermes"


HERMES_HOME = get_hermes_home()
TOKEN_PATH = HERMES_HOME / "microsoft_token.json"

#: Microsoft's identity platform, v2.0 endpoints. `common` rather than a
#: tenant id, because this is mail for outlook.com/hotmail.com accounts
#: as much as for work accounts, and `common` is the authority that
#: accepts both. Constants, not configuration: they are Microsoft's, and
#: a configurable token endpoint is a credential-exfiltration knob (the
#: same reasoning GOOGLE_TOKEN_ENDPOINT carries in ui.py).
AUTHORITY = "https://login.microsoftonline.com/common"
TOKEN_ENDPOINT = f"{AUTHORITY}/oauth2/v2.0/token"

#: Microsoft Graph, v1.0. `beta` is deliberately not reachable from here.
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

#: Only used when the token file carries no `scopes` of its own (see
#: `_stored_token_scopes`) -- a file written by hand, or before the
#: console recorded the grant. It is therefore not "what this script can
#: do" but "what was most likely consented to", and it must stay a
#: subset of the real grant.
#:
#: Pinned to what gatekeeper's console actually asks for,
#: `ui.DEFAULT_MICROSOFT_SCOPES` -- tests/test_microsoft_oauth.py asserts
#: the two are the same set. Minimal on purpose: read mail, send mail,
#: know who "me" is, and keep the refresh token alive.
SCOPES = [
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/Mail.Send",
    "https://graph.microsoft.com/User.Read",
    "offline_access",
]

#: Ceiling on `--max`. Graph's own `$top` maximum for messages is 1000;
#: this is lower because the executor caps the JSON it hands back anyway
#: (execute_http.MAX_JSON_ITEMS), and a page nobody can read is just a
#: slower call.
MAX_PAGE_SIZE = 100

#: The message fields a list returns. Explicit rather than "whatever
#: Graph feels like sending": a list of a hundred messages with full
#: bodies is a wall of external, prompt-injection-bearing text where a
#: subject line would have done. `mail get` is the way to a body.
LIST_SELECT = (
    "id,subject,from,toRecipients,receivedDateTime,isRead,hasAttachments,bodyPreview"
)

#: The fields one message returns. `body` is here -- asking for a single
#: message by id *is* asking for its content.
GET_SELECT = (
    "id,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,"
    "isRead,hasAttachments,bodyPreview,body,conversationId,webLink"
)

HTTP_TIMEOUT = 30


class GraphError(Exception):
    """A Graph or token-endpoint answer that is not a usable result.

    `code` is the HTTP status (or an OAuth error name) so
    `execute_microsoft._interpret_exit` can tell a dead token from a
    missing scope from a typo in a message id.
    """

    def __init__(self, message: str, *, code: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def _fail(error: GraphError) -> None:
    """The one exit path for a failure: a JSON object on stderr, exit 1.

    The shape (`code` + `message`) is what google_api.py emits and what
    the executor parses -- one contract, two providers.
    """
    print(
        json.dumps({"code": error.code, "message": error.message}),
        file=sys.stderr,
    )
    sys.exit(1)


def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, Any]]:
    """One HTTP round trip, returning (status, parsed body).

    A 202 or 204 carries no body -- `sendMail` answers exactly that on
    success -- so an empty response is an empty dict, not a parse error.
    """
    request = urllib.request.Request(url, data=body, method=method)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            status = response.status
            raw = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read()
    except urllib.error.URLError as exc:
        raise GraphError(
            f"Microsoft was not reachable ({exc.reason}).", code="unreachable"
        ) from None

    if not raw:
        return status, {}
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        if status >= 400:
            raise GraphError(
                f"Microsoft answered HTTP {status} with a non-JSON body.", code=status
            ) from None
        raise GraphError(
            "Microsoft's response was not JSON.", code=status
        ) from None
    if not isinstance(payload, dict):
        raise GraphError("Microsoft's response was not an object.", code=status)
    return status, payload


def _stored_token() -> dict[str, Any]:
    """The token file, or a failure naming the flow that writes it."""
    try:
        raw = TOKEN_PATH.read_text(encoding="utf-8")
    except OSError:
        raise GraphError(
            "Not authenticated: no Microsoft token file. Connect the "
            "credential from the gatekeeper console (Credentials -> Connect "
            "Microsoft) to obtain a refresh token.",
            code=401,
        ) from None
    try:
        payload = json.loads(raw)
    except ValueError:
        raise GraphError(
            "The Microsoft token file is not valid JSON.", code=401
        ) from None
    if not isinstance(payload, dict):
        raise GraphError("The Microsoft token file is not an object.", code=401)
    return payload


def _stored_token_scopes(token: dict[str, Any] | None = None) -> list[str]:
    """The scopes a refresh may ask for: the token file's own, if it has any.

    Whoever wrote the token knew what was consented to; this script does
    not. `SCOPES` is the fallback for a file written before the scopes
    were recorded, and nothing more. Same rule, same reason, same
    spelling as google_api.py's function of this name.
    """
    if token is None:
        try:
            token = _stored_token()
        except GraphError:
            return list(SCOPES)
    scopes = token.get("scopes")
    if isinstance(scopes, list) and scopes:
        return [str(scope) for scope in scopes]
    return list(SCOPES)


def get_access_token() -> str:
    """Trades the stored refresh token for an access token.

    Microsoft's token endpoint takes a form-encoded *request* and answers
    with `application/json` -- so the body going out is urlencoded and
    the body coming back is parsed as JSON, which is not the symmetry
    the form encoding suggests.

    `scope` is the stored grant, not this script's `SCOPES`: asking for
    anything the operator did not consent to is answered with
    `invalid_scope`, and that refusal kills the refresh itself.

    Microsoft rotates refresh tokens -- a successful refresh usually
    returns a *new* one and retires the old. It is written back to the
    token file so a second call in the same materialization still has a
    live token. The file is per-call and thrown away afterwards
    (`service._microsoft_token_env`), so this is not a substitute for
    re-consenting; it is what keeps a multi-call session working.
    """
    token = _stored_token()
    client_id = token.get("client_id")
    client_secret = token.get("client_secret")
    refresh_token = token.get("refresh_token")
    if not (client_id and client_secret and refresh_token):
        raise GraphError(
            "The Microsoft token file is missing client_id, client_secret or "
            "refresh_token.",
            code=401,
        )
    scopes = _stored_token_scopes(token)
    form = urllib.parse.urlencode(
        {
            "client_id": str(client_id),
            "client_secret": str(client_secret),
            "refresh_token": str(refresh_token),
            "grant_type": "refresh_token",
            "scope": " ".join(scopes),
        }
    ).encode("utf-8")
    status, payload = _request(
        "POST",
        TOKEN_ENDPOINT,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=form,
    )
    if status >= 400:
        # `error` is the OAuth error name (`invalid_grant`,
        # `invalid_scope`); the description may quote the request back,
        # so only the name and the status travel.
        name = str(payload.get("error") or status)
        raise GraphError(
            f"Microsoft refused the token refresh ({name}).", code=401
        )
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise GraphError(
            "Microsoft's token response carried no access token.", code=401
        )

    rotated = payload.get("refresh_token")
    if isinstance(rotated, str) and rotated and rotated != refresh_token:
        token["refresh_token"] = rotated
        token["scopes"] = scopes
        _write_token_file(token)
    return access_token


def _write_token_file(token: dict[str, Any]) -> None:
    """Rewrites the token file, owner-only from the moment it exists.

    The same 0600-from-creation rule `service._write_private_file`
    applies to the original: a rotated refresh token is exactly as much
    of a secret as the one it replaces. The mode argument only takes
    effect when `open` creates the file, and here it normally does not --
    it is rewriting one -- so the permissions are set explicitly on the
    descriptor. A file that arrived readable stays readable otherwise,
    and a rotated token would be the one secret on disk nobody tightened.

    A failure here is not fatal: the access token in hand still works for
    this call, and the call is what the operator asked for.
    """
    try:
        handle = os.open(str(TOKEN_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(token))
    except OSError:
        return


def _graph(
    method: str,
    path: str,
    *,
    params: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """One authenticated Graph call.

    `path` is built here, never taken from a parameter: the only
    caller-supplied part of a URL is a message or folder id, and that is
    percent-encoded by the action functions before it gets here.
    """
    url = f"{GRAPH_BASE}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    headers = {
        "Authorization": f"Bearer {get_access_token()}",
        "Accept": "application/json",
    }
    encoded: bytes | None = None
    if body is not None:
        encoded = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    status, payload = _request(method, url, headers=headers, body=encoded)
    if status >= 400:
        error = payload.get("error")
        if isinstance(error, dict):
            message = str(error.get("message") or error.get("code") or "")
            code = error.get("code") or status
        else:
            message = ""
            code = status
        raise GraphError(
            message or f"Microsoft Graph answered HTTP {status}.", code=status or code
        )
    return status, payload


def _page_size(value: int | None) -> int:
    if not value or value < 1:
        return 10
    return min(int(value), MAX_PAGE_SIZE)


def _address(entry: Any) -> str:
    """The bare address out of Graph's {emailAddress: {name, address}}."""
    if isinstance(entry, dict):
        inner = entry.get("emailAddress")
        if isinstance(inner, dict):
            return str(inner.get("address") or "")
    return ""


def _recipients(entries: Any) -> list[str]:
    if not isinstance(entries, list):
        return []
    return [address for address in (_address(entry) for entry in entries) if address]


def _message_summary(message: dict[str, Any]) -> dict[str, Any]:
    """One message, flattened.

    Graph nests an address three levels deep and returns a dozen fields
    nobody asked for. The agent-facing shape is the one google_api.py's
    gmail actions emit: flat, named, and small.
    """
    return {
        "id": message.get("id"),
        "subject": message.get("subject"),
        "from": _address(message.get("from")),
        "to": _recipients(message.get("toRecipients")),
        "received": message.get("receivedDateTime"),
        "unread": not message.get("isRead", True),
        "has_attachments": bool(message.get("hasAttachments")),
        "preview": message.get("bodyPreview"),
    }


def mail_list(args: argparse.Namespace) -> Any:
    """Messages in one folder, newest first."""
    params = {
        "$top": str(_page_size(args.max)),
        "$select": LIST_SELECT,
        "$orderby": "receivedDateTime desc",
    }
    if args.search:
        # Graph refuses $orderby together with $search -- the relevance
        # order is the search's own, and asking for both is a 400.
        params.pop("$orderby")
        params["$search"] = f'"{args.search}"'
    if args.unread:
        params["$filter"] = "isRead eq false"
    folder = urllib.parse.quote(args.folder, safe="")
    _status, payload = _graph("GET", f"/me/mailFolders/{folder}/messages", params=params)
    messages = payload.get("value")
    if not isinstance(messages, list):
        return []
    return [_message_summary(message) for message in messages if isinstance(message, dict)]


def mail_get(args: argparse.Namespace) -> Any:
    """One message, with its body."""
    message_id = urllib.parse.quote(args.message_id, safe="")
    _status, message = _graph(
        "GET", f"/me/messages/{message_id}", params={"$select": GET_SELECT}
    )
    body = message.get("body")
    summary = _message_summary(message)
    summary.update(
        {
            "cc": _recipients(message.get("ccRecipients")),
            "sent": message.get("sentDateTime"),
            "conversation_id": message.get("conversationId"),
            "web_link": message.get("webLink"),
            "body_type": body.get("contentType") if isinstance(body, dict) else None,
            "body": body.get("content") if isinstance(body, dict) else None,
        }
    )
    return summary


def mail_folders(args: argparse.Namespace) -> Any:
    """The mailbox's folders, with their unread counts."""
    params = {
        "$top": str(_page_size(args.max)),
        "$select": "id,displayName,unreadItemCount,totalItemCount",
    }
    _status, payload = _graph("GET", "/me/mailFolders", params=params)
    folders = payload.get("value")
    if not isinstance(folders, list):
        return []
    return [
        {
            "id": folder.get("id"),
            "name": folder.get("displayName"),
            "unread": folder.get("unreadItemCount"),
            "total": folder.get("totalItemCount"),
        }
        for folder in folders
        if isinstance(folder, dict)
    ]


def _recipient_list(raw: str) -> list[dict[str, Any]]:
    addresses = [part.strip() for part in raw.split(",") if part.strip()]
    return [{"emailAddress": {"address": address}} for address in addresses]


def mail_send(args: argparse.Namespace) -> Any:
    """Sends a message.

    ``POST /me/sendMail`` answers **202 Accepted with no body** on
    success -- Graph has queued the message, it has not handed back a
    resource. So the confirmation is built here rather than echoed: an
    empty 202 is the success, and treating "no body" as a failure would
    report every sent mail as an error.
    """
    to = _recipient_list(args.to)
    if not to:
        raise GraphError("No recipient address in --to.", code=400)
    message: dict[str, Any] = {
        "subject": args.subject,
        "body": {
            "contentType": "HTML" if args.html else "Text",
            "content": args.body,
        },
        "toRecipients": to,
    }
    if args.cc:
        message["ccRecipients"] = _recipient_list(args.cc)
    status, _payload = _graph(
        "POST",
        "/me/sendMail",
        body={"message": message, "saveToSentItems": True},
    )
    return {
        "status": "sent",
        "http_status": status,
        "to": [entry["emailAddress"]["address"] for entry in to],
        "cc": [entry["emailAddress"]["address"] for entry in message.get("ccRecipients", [])],
        "subject": args.subject,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Microsoft Graph mail for gatekeeper")
    services = parser.add_subparsers(dest="service", required=True)

    mail = services.add_parser("mail")
    actions = mail.add_subparsers(dest="action", required=True)

    listing = actions.add_parser("list")
    listing.add_argument("--folder", default="inbox")
    listing.add_argument("--max", type=int, default=10)
    listing.add_argument("--search", default="")
    listing.add_argument("--unread", action="store_true")
    listing.set_defaults(func=mail_list)

    getting = actions.add_parser("get")
    getting.add_argument("message_id")
    getting.set_defaults(func=mail_get)

    folders = actions.add_parser("folders")
    folders.add_argument("--max", type=int, default=50)
    folders.set_defaults(func=mail_folders)

    sending = actions.add_parser("send")
    sending.add_argument("--to", required=True)
    sending.add_argument("--subject", default="")
    sending.add_argument("--body", default="")
    sending.add_argument("--cc", default="")
    sending.add_argument("--html", action="store_true")
    sending.set_defaults(func=mail_send)

    args = parser.parse_args()
    try:
        result = args.func(args)
    except GraphError as error:
        _fail(error)
        return
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
