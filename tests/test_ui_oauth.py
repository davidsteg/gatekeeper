"""Google OAuth sign-in in the console (FR-1).

An `oauth2` credential needs three fields and only two of them can be
typed in: the refresh token exists only after a human clicked through a
consent screen. These two routes do that inside the console, so the
token goes from Google straight into the encrypted store instead of
through a setup script, a clipboard and a shell history.

What the tests here are about is the same property the rest of the
credential surface has: no token material is ever rendered, logged, or
echoed back -- on any path, including every failure one. Plus the gates
around it: a session is required, the consent URL carries a state, and a
callback that does not match a flow this console started changes nothing.
"""

from __future__ import annotations

import dataclasses
import html
import json
import os
import re
import urllib.parse

import httpx2
import pytest
import yaml
from conftest import PYTHON

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.pending import PendingStore
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_proposals import ToolkitProposalStore
from gatekeeper.ui import (
    DEFAULT_GOOGLE_SCOPES,
    GOOGLE_SCOPE_PREFIX,
    OAUTH_AUTHORIZE_PATH,
    OAUTH_CALLBACK_PATH,
    UI_PREFIX,
)

BASE = "http://gatekeeper.test"
PASSWORDS = {"root": "admin-console-password", "eye": "viewer-console-password"}

CLIENT_ID = "1234.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-test-client-secret-value"
OLD_REFRESH = "1//old-refresh-token-value"
NEW_REFRESH = "1//brand-new-refresh-token-value"
AUTH_CODE = "4/authorization-code-value"


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


async def _login(client, identity: str = "root"):
    return await client.post(
        f"{UI_PREFIX}/login",
        data={"identity": identity, "password": PASSWORDS[identity]},
    )


def _consent_url(page_text: str) -> str:
    match = re.search(r'href="(https://accounts\.google\.com[^"]+)"', page_text)
    assert match, f"no consent link on the page: {page_text[:2000]}"
    return html.unescape(match.group(1))


def _consent_params(page_text: str) -> dict[str, str]:
    query = urllib.parse.urlparse(_consent_url(page_text)).query
    return dict(urllib.parse.parse_qsl(query))


async def _start_flow(client) -> dict[str, str]:
    await _login(client)
    page = await client.get(f"{OAUTH_AUTHORIZE_PATH}?credential=gws")
    assert page.status_code == 200
    return _consent_params(page.text)


def _audit_text(tier1) -> str:
    return open(os.path.join(tier1.audit_dir, "audit.jsonl"), encoding="utf-8").read()


def _stored_bundle(credentials) -> dict:
    """The credential as the executors would resolve it.

    Reaching into `_resolve` is what `test_credentials.py` already does:
    it is the only decrypt point, and the assertion here is about what
    was *written*, never about a value crossing a response boundary.
    """
    return json.loads(credentials._resolve("gws").value)


# -- The gate ---------------------------------------------------------------


async def test_both_routes_require_a_session(oauth_env):
    """Neither route is public: the callback writes a credential."""
    async with _client(oauth_env["app"]) as client:
        for path in (OAUTH_AUTHORIZE_PATH, OAUTH_CALLBACK_PATH):
            response = await client.get(path, follow_redirects=False)
            assert response.status_code == 303, path
            assert response.headers["location"].endswith("/login"), path


async def test_callback_without_a_session_cannot_be_driven_by_query_alone(oauth_env):
    """A code and a made-up state are not access either."""
    async with _client(oauth_env["app"]) as client:
        response = await client.get(
            f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state=invented",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith("/login")
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH


async def test_a_viewer_cannot_start_the_flow(oauth_env):
    """Writing a credential is `role: admin`, here as everywhere else."""
    async with _client(oauth_env["app"]) as client:
        await _login(client, "eye")
        response = await client.get(OAUTH_AUTHORIZE_PATH, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].endswith("/credentials")


# -- The consent URL --------------------------------------------------------


async def test_authorize_builds_the_consent_url_with_state(oauth_env):
    async with _client(oauth_env["app"]) as client:
        await _login(client)
        page = await client.get(OAUTH_AUTHORIZE_PATH)

    assert page.status_code == 200
    params = _consent_params(page.text)
    assert params["client_id"] == CLIENT_ID
    assert params["redirect_uri"] == f"{BASE}{OAUTH_CALLBACK_PATH}"
    assert params["response_type"] == "code"
    assert params["access_type"] == "offline"
    assert params["prompt"] == "consent"
    assert len(params["state"]) >= 32
    # The client secret has no business on a consent URL or a page.
    assert CLIENT_SECRET not in page.text
    assert OLD_REFRESH not in page.text


async def test_authorize_page_documents_the_callback_uri(oauth_env):
    """The one string the operator must paste into Google Cloud.

    A `redirect_uri` that differs by a character is a
    `redirect_uri_mismatch` and nothing else, so the page prints the
    exact value in a copyable field.
    """
    async with _client(oauth_env["app"]) as client:
        await _login(client)
        page = await client.get(OAUTH_AUTHORIZE_PATH)

    callback_uri = f"{BASE}{OAUTH_CALLBACK_PATH}"
    assert f'class="mono copyline" readonly spellcheck="false" value="{callback_uri}"' in page.text


async def test_scopes_default_when_no_toolkit_declares_any(oauth_env):
    async with _client(oauth_env["app"]) as client:
        await _login(client)
        page = await client.get(OAUTH_AUTHORIZE_PATH)

    scopes = _consent_params(page.text)["scope"].split(" ")
    assert scopes == [GOOGLE_SCOPE_PREFIX + name for name in DEFAULT_GOOGLE_SCOPES]


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
        await _login(client)
        page = await client.get(OAUTH_AUTHORIZE_PATH)

    assert _consent_params(page.text)["scope"].split(" ") == [
        GOOGLE_SCOPE_PREFIX + "gmail.readonly",
        GOOGLE_SCOPE_PREFIX + "calendar.events",
    ]


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
            "access_token": "ya29.access-token-value",
            "refresh_token": NEW_REFRESH,
            "expires_in": 3599,
        }

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        page = await client.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")

    assert page.status_code == 200
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
    }
    # Rotated, not re-created: the credential existed.
    meta = next(m for m in oauth_env["credentials"].names() if m.name == "gws")
    assert meta.rotated_at

    # "ok" and nothing else: no token, no code, no secret on the page.
    assert "Connected" in page.text
    for secret in (NEW_REFRESH, OLD_REFRESH, CLIENT_SECRET, AUTH_CODE,
                   "ya29.access-token-value"):
        assert secret not in page.text


async def test_the_audit_log_carries_no_token_material(oauth_env, monkeypatch):
    async def fake_exchange(**_kwargs):
        return {"refresh_token": NEW_REFRESH, "access_token": "ya29.access-token-value"}

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        await client.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")

    log = _audit_text(oauth_env["tier1"])
    # The flow is recorded ...
    assert '"action": "google_authorize"' in log
    assert '"result": "ok"' in log
    assert '"credential": "gws"' in log
    # ... by name only.
    for secret in (NEW_REFRESH, OLD_REFRESH, CLIENT_SECRET, CLIENT_ID, AUTH_CODE,
                   "ya29.access-token-value"):
        assert secret not in log, secret


async def test_a_denied_consent_changes_nothing(oauth_env, monkeypatch):
    async def fail(**_kwargs):  # pragma: no cover - must never run
        raise AssertionError("no exchange on a denied consent")

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fail)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        page = await client.get(
            f"{OAUTH_CALLBACK_PATH}?error=access_denied&state={state}"
        )

    assert page.status_code == 400
    assert "Not connected" in page.text
    assert "access_denied" in page.text
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "denied"' in _audit_text(oauth_env["tier1"])


async def test_a_mismatched_state_changes_nothing(oauth_env, monkeypatch):
    async def fail(**_kwargs):  # pragma: no cover - must never run
        raise AssertionError("no exchange on a state that was never issued")

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fail)

    async with _client(oauth_env["app"]) as client:
        await _start_flow(client)
        page = await client.get(
            f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state=not-the-issued-one"
        )

    assert page.status_code == 400
    assert "Not connected" in page.text
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "state_mismatch"' in _audit_text(oauth_env["tier1"])


async def test_a_state_is_single_use(oauth_env, monkeypatch):
    """A replayed callback is a state that no longer exists."""
    calls = []

    async def fake_exchange(**_kwargs):
        calls.append(1)
        return {"refresh_token": NEW_REFRESH}

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        first = await client.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")
        second = await client.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")

    assert first.status_code == 200
    assert second.status_code == 400
    assert calls == [1]


async def test_a_state_issued_to_another_operator_is_refused(tmp_path, monkeypatch):
    """Two admins, one state: the one who did not start it cannot finish it."""
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    tier1 = _google_tier1(tmp_path)
    env = _build_env(tmp_path, tier1)
    env["credentials"].create(
        "gws", kind="oauth2",
        value=json.dumps(
            {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
             "refresh_token": OLD_REFRESH}
        ),
        actor="root", rev="",
    )

    async def fail(**_kwargs):  # pragma: no cover - must never run
        raise AssertionError("no exchange for a foreign state")

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fail)

    async with _client(env["app"]) as starter:
        state = (await _start_flow(starter))["state"]

    async with _client(env["app"]) as other:
        await _login(other, "eye")
        page = await other.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")

    assert page.status_code == 400
    assert json.loads(env["credentials"]._resolve("gws").value)["refresh_token"] == (
        OLD_REFRESH
    )
    assert '"result": "identity_mismatch"' in _audit_text(tier1)


async def test_a_revoked_admin_cannot_finish_a_flow_it_started(
    oauth_env, monkeypatch, tmp_path
):
    """The role is re-checked when the credential is written, not only

    when the flow started. A demotion between the two would otherwise
    still spend the authority the operator had a minute ago.
    """

    async def fail(**_kwargs):  # pragma: no cover - must never run
        raise AssertionError("no exchange for a demoted operator")

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fail)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        # Demote in place, the way `store.save_identity` does.
        store = oauth_env["identities"]
        store.identities["root"] = dataclasses.replace(
            store.identities["root"], role="viewer"
        )
        page = await client.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")

    assert page.status_code == 400
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "role_required"' in _audit_text(oauth_env["tier1"])


async def test_a_response_without_a_refresh_token_is_an_error(oauth_env, monkeypatch):
    """An access token alone is useless: the executor cannot renew it."""

    async def fake_exchange(**_kwargs):
        return {"access_token": "ya29.access-token-value", "expires_in": 3599}

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        page = await client.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")

    assert page.status_code == 400
    assert "no refresh token" in page.text
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert "ya29.access-token-value" not in page.text
    assert "ya29.access-token-value" not in _audit_text(oauth_env["tier1"])


async def test_a_failed_exchange_says_so_without_quoting_google(oauth_env, monkeypatch):
    """Google's error body may quote the client secret back at us."""
    from gatekeeper.ui import OAuthExchangeError

    async def fake_exchange(**_kwargs):
        raise OAuthExchangeError("Google refused the code exchange (HTTP 400).")

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fake_exchange)

    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        page = await client.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")

    assert page.status_code == 400
    assert "HTTP 400" in page.text
    assert CLIENT_SECRET not in page.text
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
        await _login(client)
        page = await client.get(OAUTH_AUTHORIZE_PATH)

    assert page.status_code == 400
    assert "client_id/client_secret" in page.text


async def test_the_credentials_page_offers_the_flow_for_oauth2_only(oauth_env):
    oauth_env["credentials"].create(
        "sonarr", kind="bearer", value="not-an-oauth-credential", actor="root", rev="",
    )
    async with _client(oauth_env["app"]) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/credentials")

    assert f'{OAUTH_AUTHORIZE_PATH}?credential=gws' in page.text
    assert f'{OAUTH_AUTHORIZE_PATH}?credential=sonarr' not in page.text
