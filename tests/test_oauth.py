"""Google OAuth sign-in for `oauth2` credentials (FR-1), 1.0.0 shape.

An `oauth2` credential needs three fields and only two of them can be
typed in: the refresh token exists only after a human clicked through a
consent screen. Gatekeeper does that exchange itself, so the token goes
from Google straight into the encrypted store instead of through a setup
script, a clipboard and a shell history.

Since the 1.0.0 cutover a flow is started by `POST
/api/v1/oauth/<provider>/authorize` (API session, `admin`, CSRF), which
answers the consent URL as JSON. The provider sends the browser back to
the unchanged callback path `/ui/oauth/<provider>/callback`, and that
route always answers 303 to `/app/credentials?oauth=<code>&...` -- never
a page.

What the tests here are about is the same property the rest of the
credential surface has: no token material is ever rendered, logged, or
echoed back -- not in the authorize JSON, not in the callback's Location
header, not in the audit log, on any path including every failure one.
Plus the gates around it: starting a flow needs an admin API session, the
consent URL carries a single-use state, and a callback that does not
match a flow this console started changes nothing.

Dropped with the HTML console: the 0.x test that a state redeemed under a
*different operator's* `/ui` session is refused (`identity_mismatch`).
The API session cookie is scoped to `/api/v1` and never reaches the
callback, so there is no second session to compare against; the state
alone names the operator. What replaces it is
`test_a_state_writes_as_the_operator_it_was_issued_to`: whoever's browser
redeems it, the write is attributed to the issuing operator, and only
while that operator is still an admin.
"""

from __future__ import annotations

import dataclasses
import json
import os
import urllib.parse

import httpx
import httpx2
import pytest
import yaml
from conftest import PYTHON

from gatekeeper.api import API_PREFIX
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.oauth import (
    DEFAULT_GOOGLE_SCOPES,
    GOOGLE_SCOPE_PREFIX,
    OAUTH_CALLBACK_PATH,
    OAuthExchangeError,
)
from gatekeeper.pending import PendingStore
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_proposals import ToolkitProposalStore

BASE = "http://gatekeeper.test"
API = API_PREFIX
PASSWORDS = {"root": "admin-console-password", "eye": "viewer-console-password"}

CLIENT_ID = "1234.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-test-client-secret-value"
OLD_REFRESH = "1//old-refresh-token-value"
NEW_REFRESH = "1//brand-new-refresh-token-value"
AUTH_CODE = "4/authorization-code-value"
ACCESS_TOKEN = "ya29.access-token-value"

#: Everything that must never cross a response or log boundary.
SECRETS = (NEW_REFRESH, OLD_REFRESH, CLIENT_SECRET, AUTH_CODE, ACCESS_TOKEN)

APP_RESULT = "/app/credentials"


def _google_tier1(tmp_path, *, required_scopes=None) -> object:
    """Tier 1 with a `google` toolkit bound to the `gws` credential."""
    toolkit = {
        "executor": "google",
        "binaries": [],
        "google_script": "/opt/gatekeeper/google/google_api.py",
        "allowed_google_actions": ["gmail search", "calendar list"],
        "credential": "gws",
        "max_timeout_seconds": 30,
        "max_output_bytes": 65536,
    }
    if required_scopes is not None:
        toolkit["required_scopes"] = required_scopes
    path = tmp_path / "toolkits-google.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": toolkit,
                    "demo": {
                        "executor": "local",
                        "binaries": [PYTHON],
                        "path_roots": [],
                        "max_timeout_seconds": 30,
                        "max_output_bytes": 8192,
                    },
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    return load_tier1(str(path))


def _build_env(tmp_path, tier1):
    tools_path = tmp_path / "tools-oauth.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")

    identities_path = tmp_path / "identities-oauth.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root", "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "password_hash": hash_token(PASSWORDS["root"]),
                        "tools": [], "scopes": [],
                    },
                    {
                        "id": "eye", "role": "viewer",
                        "token_hash": hash_token(generate_token()),
                        "password_hash": hash_token(PASSWORDS["eye"]),
                        "tools": [], "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(identities_path))
    audit = AuditLog(tier1.audit_dir)
    service = Service(
        tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit
    )
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    credentials = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit-proposals.yaml"),
        audit=audit,
        service=service,
        toolkits_path=str(tmp_path / "toolkits-google.yaml"),
        tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    app = build_app(
        service=service, identities=identities, audit=audit, ui=True, store=store,
        credentials=credentials, pending=pending, toolkit_proposals=toolkit_proposals,
    )
    return {
        "app": app, "credentials": credentials, "tier1": tier1, "audit": audit,
        "identities": identities,
    }


@pytest.fixture
def oauth_env(tmp_path, monkeypatch):
    """A console with a google toolkit and a half-filled oauth2 credential.

    Half-filled is the real starting point: client_id and client_secret
    come from the Google Cloud console and can be typed into the
    credential form, the refresh token cannot.
    """
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    env = _build_env(tmp_path, _google_tier1(tmp_path))
    env["credentials"].create(
        "gws",
        kind="oauth2",
        value=json.dumps(
            {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "refresh_token": OLD_REFRESH,
            }
        ),
        actor="root",
        rev="",
    )
    return env


def _client(app) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, timeout=30.0
    )


async def _login(client, identity: str = "root") -> str:
    """Signs in through the API and returns the session's CSRF token."""
    response = await client.post(
        f"{API}/session", json={"identity": identity, "password": PASSWORDS[identity]}
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


async def _authorize(
    client, csrf: str | None, *, provider: str = "google", credential: str = "gws"
):
    headers = {"X-CSRF-Token": csrf} if csrf is not None else {}
    return await client.post(
        f"{API}/oauth/{provider}/authorize", json={"credential": credential},
        headers=headers,
    )


def _consent_params(start: dict) -> dict[str, str]:
    query = urllib.parse.urlparse(start["consent_url"]).query
    return dict(urllib.parse.parse_qsl(query))


async def _start(
    client, *, provider: str = "google", credential: str = "gws", identity: str = "root"
) -> dict:
    """Signs in and starts a flow; returns the authorize JSON."""
    csrf = await _login(client, identity)
    response = await _authorize(client, csrf, provider=provider, credential=credential)
    assert response.status_code == 200, response.text
    return response.json()


async def _start_flow(client, **kwargs) -> dict[str, str]:
    """Signs in, starts a flow, returns the consent URL's query params."""
    return _consent_params(await _start(client, **kwargs))


async def _callback(client, query: str, *, path: str = OAUTH_CALLBACK_PATH) -> str:
    """Hits the callback, asserts it redirected, returns the Location."""
    response = await client.get(f"{path}?{query}", follow_redirects=False)
    assert response.status_code == 303, response.text[:2000]
    location = response.headers["location"]
    assert urllib.parse.urlparse(location).path == APP_RESULT
    # The callback is a redirect, nothing else: no body to leak through.
    for secret in SECRETS:
        assert secret not in response.text, secret
    return location


def _result(location: str) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(
        urllib.parse.urlparse(location).query, keep_blank_values=True
    ))


def _assert_clean(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text, secret


def _audit_text(tier1) -> str:
    return open(os.path.join(tier1.audit_dir, "audit.jsonl"), encoding="utf-8").read()


def _audit_records(tier1) -> list[dict]:
    return [json.loads(line) for line in _audit_text(tier1).splitlines() if line.strip()]


def _stored_bundle(credentials) -> dict:
    """The credential as the executors would resolve it.

    Reaching into `_resolve` is what `test_credentials.py` already does:
    it is the only decrypt point, and the assertion here is about what
    was *written*, never about a value crossing a response boundary.
    """
    return json.loads(credentials._resolve("gws").value)


async def _never(**_kwargs):  # pragma: no cover - must never run
    raise AssertionError("no code exchange may happen on this path")


# -- The gate ---------------------------------------------------------------


async def test_starting_a_flow_requires_an_api_session(oauth_env):
    """No session, no state: the callback writes a credential, and the
    only way to get a state is an authenticated authorize."""
    async with _client(oauth_env["app"]) as client:
        response = await _authorize(client, None)
        assert response.status_code == 401
        _assert_clean(response.text)
        # And the callback on its own, with nothing at all, redeems nothing.
        location = await _callback(client, "")
    assert _result(location) == {
        "oauth": "state_mismatch", "provider": "google", "credential": "",
    }
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH


@pytest.mark.parametrize(
    "query",
    [f"code={AUTH_CODE}&state=invented", f"code={AUTH_CODE}", f"code={AUTH_CODE}&state="],
)
async def test_callback_without_a_state_cannot_be_driven_by_query_alone(
    oauth_env, monkeypatch, query
):
    """A code and a made-up (or missing) state are not access either."""
    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", _never)
    async with _client(oauth_env["app"]) as client:
        location = await _callback(client, query)
    assert _result(location) == {
        "oauth": "state_mismatch", "provider": "google", "credential": "",
    }
    _assert_clean(location)
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "state_mismatch"' in _audit_text(oauth_env["tier1"])


async def test_a_viewer_cannot_start_the_flow(oauth_env):
    """Writing a credential is `role: admin`, here as everywhere else."""
    async with _client(oauth_env["app"]) as client:
        csrf = await _login(client, "eye")
        response = await _authorize(client, csrf)
    assert response.status_code == 403
    _assert_clean(response.text)
    assert "consent_url" not in response.text


async def test_authorize_requires_the_csrf_token(oauth_env):
    async with _client(oauth_env["app"]) as client:
        await _login(client)
        response = await _authorize(client, None)
        wrong = await _authorize(client, "not-the-csrf-token")
    assert response.status_code == 403
    assert wrong.status_code == 403
    assert "consent_url" not in response.text + wrong.text


async def test_an_unknown_provider_is_404(oauth_env):
    async with _client(oauth_env["app"]) as client:
        csrf = await _login(client)
        response = await _authorize(client, csrf, provider="yahoo")
    assert response.status_code == 404


# -- The consent URL --------------------------------------------------------


async def test_authorize_builds_the_consent_url_with_state(oauth_env):
    async with _client(oauth_env["app"]) as client:
        csrf = await _login(client)
        response = await _authorize(client, csrf)

    assert response.status_code == 200
    params = _consent_params(response.json())
    assert params["client_id"] == CLIENT_ID
    assert params["redirect_uri"] == f"{BASE}{OAUTH_CALLBACK_PATH}"
    assert params["response_type"] == "code"
    assert params["access_type"] == "offline"
    assert params["prompt"] == "consent"
    assert len(params["state"]) >= 32
    # The client secret and the stored token have no business on a
    # consent URL or anywhere in the answer.
    _assert_clean(response.text)


async def test_authorize_answers_the_callback_uri(oauth_env):
    """The one string the operator must paste into Google Cloud.

    A `redirect_uri` that differs by a character is a
    `redirect_uri_mismatch` and nothing else, so the answer carries the
    exact value, equal to what the consent URL names, plus where to
    register it and what the mismatch looks like.
    """
    async with _client(oauth_env["app"]) as client:
        start = await _start(client)

    callback_uri = f"{BASE}{OAUTH_CALLBACK_PATH}"
    assert start["callback_uri"] == callback_uri
    assert _consent_params(start)["redirect_uri"] == callback_uri
    assert start["provider"] == "google"
    assert start["credential"] == "gws"
    assert start["mismatch_error"] == "redirect_uri_mismatch"
    assert "Google Cloud" in start["registration_console"]


async def test_scopes_default_when_no_toolkit_declares_any(oauth_env):
    async with _client(oauth_env["app"]) as client:
        start = await _start(client)

    expected = [GOOGLE_SCOPE_PREFIX + name for name in DEFAULT_GOOGLE_SCOPES]
    assert _consent_params(start)["scope"].split(" ") == expected
    assert start["scopes"] == expected


async def test_scopes_are_the_union_of_the_google_toolkits(tmp_path, monkeypatch):
    """Tier 1 decides, and it is read per request, not at startup."""
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    tier1 = _google_tier1(
        tmp_path,
        required_scopes=[
            "gmail.readonly",
            # Written out in full -- both spellings are the same request.
            GOOGLE_SCOPE_PREFIX + "calendar.events",
            # And a duplicate, to show the union is one.
            "gmail.readonly",
        ],
    )
    env = _build_env(tmp_path, tier1)
    env["credentials"].create(
        "gws", kind="oauth2",
        value=json.dumps({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}),
        actor="root", rev="",
    )
    async with _client(env["app"]) as client:
        start = await _start(client)

    expected = [
        GOOGLE_SCOPE_PREFIX + "gmail.readonly",
        GOOGLE_SCOPE_PREFIX + "calendar.events",
    ]
    assert _consent_params(start)["scope"].split(" ") == expected
    assert start["scopes"] == expected


# -- The callback -----------------------------------------------------------


async def test_callback_persists_the_refresh_token(oauth_env, monkeypatch):
    """The whole point: the token lands in the store, and nowhere else."""
    seen: dict = {}

    async def fake_exchange(*, code, client_id, client_secret, redirect_uri):
        seen.update(
            code=code, client_id=client_id, client_secret=client_secret,
            redirect_uri=redirect_uri,
        )
        return {
            "access_token": ACCESS_TOKEN,
            "refresh_token": NEW_REFRESH,
            "expires_in": 3599,
            "scope": " ".join(
                GOOGLE_SCOPE_PREFIX + name for name in DEFAULT_GOOGLE_SCOPES
            ),
        }

    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        start = await _start(client)
        state = _consent_params(start)["state"]
        location = await _callback(client, f"code={AUTH_CODE}&state={state}")

    # The exchange got the credential's own client pair and the same
    # redirect URI the consent URL named.
    assert seen == {
        "code": AUTH_CODE,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": f"{BASE}{OAUTH_CALLBACK_PATH}",
    }
    bundle = _stored_bundle(oauth_env["credentials"])
    assert bundle == {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": NEW_REFRESH,
        # The grant travels with the token it belongs to -- see
        # tests/test_google_token_scopes.py for why a refresh needs it.
        "scopes": [GOOGLE_SCOPE_PREFIX + name for name in DEFAULT_GOOGLE_SCOPES],
    }
    # Rotated, not re-created: the credential existed.
    meta = next(m for m in oauth_env["credentials"].names() if m.name == "gws")
    assert meta.rotated_at

    # "ok" and nothing else: no token, no code, no secret in the redirect
    # or in the answer that started the flow.
    assert location == f"{APP_RESULT}?oauth=ok&provider=google&credential=gws"
    _assert_clean(location, json.dumps(start))


async def test_the_audit_log_carries_no_token_material(oauth_env, monkeypatch):
    async def fake_exchange(**_kwargs):
        return {"refresh_token": NEW_REFRESH, "access_token": ACCESS_TOKEN}

    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        location = await _callback(client, f"code={AUTH_CODE}&state={state}")

    assert _result(location)["oauth"] == "ok"
    log = _audit_text(oauth_env["tier1"])
    # The flow is recorded, both halves ...
    assert '"action": "google_authorize"' in log
    assert '"action": "google_callback"' in log
    assert '"result": "ok"' in log
    assert '"credential": "gws"' in log
    # ... with the scopes ...
    ok = [r for r in _audit_records(oauth_env["tier1"])
          if r.get("action") == "google_callback" and r.get("result") == "ok"]
    assert ok and ok[-1]["scopes"]
    # ... by name only: no token, no code, no secret, no client id, and
    # not the state either (it was a redeemable handle until a moment ago).
    for secret in (*SECRETS, CLIENT_ID, state):
        assert secret not in log, secret


async def test_a_denied_consent_changes_nothing(oauth_env, monkeypatch):
    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", _never)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        location = await _callback(
            client,
            f"error=access_denied%3Cscript%3Ealert(1)%3C%2Fscript%3E"
            f"&error_description=evil+text&state={state}",
        )

    # The console's own result code; the provider's text is not reflected.
    assert location == f"{APP_RESULT}?oauth=denied&provider=google&credential=gws"
    assert "access_denied" not in location
    assert "script" not in location
    assert "evil" not in location
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    # It goes to the audit log, truncated, and nowhere else.
    denied = [r for r in _audit_records(oauth_env["tier1"]) if r.get("result") == "denied"]
    assert denied and denied[-1]["detail"].startswith("access_denied")
    assert len(denied[-1]["detail"]) <= 64


async def test_a_mismatched_state_changes_nothing(oauth_env, monkeypatch):
    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", _never)

    async with _client(oauth_env["app"]) as client:
        await _start_flow(client)
        location = await _callback(client, f"code={AUTH_CODE}&state=not-the-issued-one")

    assert _result(location) == {
        "oauth": "state_mismatch", "provider": "google", "credential": "",
    }
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "state_mismatch"' in _audit_text(oauth_env["tier1"])


async def test_a_state_is_single_use(oauth_env, monkeypatch):
    """A replayed callback is a state that no longer exists."""
    calls = []

    async def fake_exchange(**_kwargs):
        calls.append(1)
        return {"refresh_token": NEW_REFRESH}

    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        first = await _callback(client, f"code={AUTH_CODE}&state={state}")
        second = await _callback(client, f"code={AUTH_CODE}&state={state}")

    assert _result(first)["oauth"] == "ok"
    assert _result(second) == {
        "oauth": "state_mismatch", "provider": "google", "credential": "",
    }
    assert calls == [1]


async def test_a_failed_flow_spends_its_state_too(oauth_env, monkeypatch):
    """Single use holds on failure paths: a denied consent cannot be
    followed by a second try with a code on the same state."""
    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", _never)
    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        denied = await _callback(client, f"error=access_denied&state={state}")
        retry = await _callback(client, f"code={AUTH_CODE}&state={state}")
    assert _result(denied)["oauth"] == "denied"
    assert _result(retry)["oauth"] == "state_mismatch"
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH


async def test_a_state_writes_as_the_operator_it_was_issued_to(oauth_env, monkeypatch):
    """Issued to `root`, redeemed in a browser signed in as `eye`.

    The callback never sees the API session (its cookie is scoped to
    `/api/v1`), so who redeems it is not who it writes as: the state
    names the operator, and the write is attributed to that operator.
    """

    async def fake_exchange(**_kwargs):
        return {"refresh_token": NEW_REFRESH}

    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as starter:
        state = (await _start_flow(starter))["state"]

    async with _client(oauth_env["app"]) as other:
        await _login(other, "eye")
        location = await _callback(other, f"code={AUTH_CODE}&state={state}")

    assert _result(location)["oauth"] == "ok"
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == NEW_REFRESH
    records = _audit_records(oauth_env["tier1"])
    ok = [r for r in records if r.get("action") == "google_callback"]
    assert [r["actor"] for r in ok] == ["root"]
    assert all(r.get("actor") != "eye" for r in records if r.get("kind") == "ui_oauth")


@pytest.mark.parametrize("change", ["demote", "delete"])
async def test_a_revoked_admin_cannot_finish_a_flow_it_started(
    oauth_env, monkeypatch, change
):
    """The role is re-checked when the credential is written, not only

    when the flow started. A demotion (or deletion) between the two would
    otherwise still spend the authority the operator had a minute ago --
    whichever browser, signed in as whoever, redeems the state.
    """
    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", _never)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        store = oauth_env["identities"]
        if change == "demote":
            # Demote in place, the way `store.save_identity` does.
            store.identities["root"] = dataclasses.replace(
                store.identities["root"], role="viewer"
            )
        else:
            store.identities.pop("root")
        location = await _callback(client, f"code={AUTH_CODE}&state={state}")

    assert location == f"{APP_RESULT}?oauth=role_required&provider=google&credential=gws"
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "role_required"' in _audit_text(oauth_env["tier1"])


async def test_a_response_without_a_refresh_token_is_an_error(oauth_env, monkeypatch):
    """An access token alone is useless: the executor cannot renew it."""

    async def fake_exchange(**_kwargs):
        return {"access_token": ACCESS_TOKEN, "expires_in": 3599}

    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        location = await _callback(client, f"code={AUTH_CODE}&state={state}")

    assert _result(location)["oauth"] == "no_refresh_token"
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    _assert_clean(location, _audit_text(oauth_env["tier1"]))


@pytest.mark.parametrize(
    "error",
    [
        OAuthExchangeError(f"Google refused the code exchange (HTTP 400): {CLIENT_SECRET}"),
        httpx.ConnectError(f"boom {CLIENT_SECRET}"),
    ],
    ids=["refused", "transport"],
)
async def test_a_failed_exchange_says_so_without_quoting_google(
    oauth_env, monkeypatch, error
):
    """Google's error body may quote the client secret back at us; even
    the exception's own text never reaches the redirect or the log."""

    async def fake_exchange(**_kwargs):
        raise error

    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        location = await _callback(client, f"code={AUTH_CODE}&state={state}")

    assert location == f"{APP_RESULT}?oauth=exchange_failed&provider=google&credential=gws"
    assert "HTTP" not in location
    _assert_clean(location, _audit_text(oauth_env["tier1"]))
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "exchange_failed"' in _audit_text(oauth_env["tier1"])


async def test_authorize_refuses_a_credential_that_has_no_client_pair(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    env = _build_env(tmp_path, _google_tier1(tmp_path))
    env["credentials"].create(
        "gws", kind="oauth2", value=json.dumps({"client_id": CLIENT_ID}),
        actor="root", rev="",
    )
    async with _client(env["app"]) as client:
        csrf = await _login(client)
        response = await _authorize(client, csrf)

    assert response.status_code == 400
    assert "client_id/client_secret" in response.json()["error"]
    assert "consent_url" not in response.text
    # Nothing was issued, so nothing was audited as started.
    assert '"action": "google_authorize"' not in _audit_text(env["tier1"])


async def test_authorize_refuses_a_missing_or_non_oauth2_credential(oauth_env):
    oauth_env["credentials"].create(
        "sonarr", kind="bearer", value="not-an-oauth-credential", actor="root", rev="",
    )
    async with _client(oauth_env["app"]) as client:
        csrf = await _login(client)
        bearer = await _authorize(client, csrf, credential="sonarr")
        missing = await _authorize(client, csrf, credential="nope")

    assert bearer.status_code == 400
    assert "not oauth2" in bearer.json()["error"]
    assert "not-an-oauth-credential" not in bearer.text
    assert missing.status_code == 400
    assert "does not exist" in missing.json()["error"]


async def test_the_providers_listing_offers_the_flow_for_toolkit_credentials(oauth_env):
    """What the credentials page offers follows Tier 1: the google toolkit
    names `gws`, and a bearer credential nothing names is not offered."""
    oauth_env["credentials"].create(
        "sonarr", kind="bearer", value="not-an-oauth-credential", actor="root", rev="",
    )
    async with _client(oauth_env["app"]) as client:
        await _login(client, "eye")
        response = await client.get(f"{API}/oauth/providers")

    assert response.status_code == 200
    assert response.json() == [{
        "key": "google", "label": "Google", "credentials": ["gws"],
        "callback_path": OAUTH_CALLBACK_PATH,
    }]
    _assert_clean(response.text)
