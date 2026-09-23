"""Microsoft OAuth sign-in, and the scopes a Microsoft grant covers.

The google pair (tests/test_ui_oauth.py, tests/test_google_token_scopes.py)
established what these two routes have to be true about: no token
material is ever rendered, logged or echoed back on any path, a callback
that does not match a flow this console started changes nothing, and the
scopes the operator consented to travel with the refresh token that
needs them. This file asks the same questions of the Microsoft flow, and
three more that are Microsoft's own:

- `offline_access` is what makes Microsoft return a refresh token, and
  Microsoft leaves it out of the token response's `scope` field. Stored
  verbatim, the next refresh would stop asking for it and the credential
  would go quietly read-only.
- The flow carries PKCE, so an intercepted authorization code is not
  redeemable without a verifier that never left this process.
- One state store serves both providers, so a state minted by the Google
  flow must not be redeemable at the Microsoft callback.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import urllib.parse
from pathlib import Path

import pytest
import yaml
from conftest import PYTHON, make_catalog
from test_ui_oauth import (
    AUTH_CODE,
    BASE,
    CLIENT_ID,
    CLIENT_SECRET,
    NEW_REFRESH,
    OLD_REFRESH,
    _audit_text,
    _build_env,
    _client,
    _google_tier1,
    _login,
    _stored_bundle,
)

from gatekeeper.audit import AuditLog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.errors import Denied
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1
from gatekeeper.ui import (
    DEFAULT_MICROSOFT_SCOPES,
    MICROSOFT_OAUTH_AUTHORIZE_PATH,
    MICROSOFT_OAUTH_CALLBACK_PATH,
    MICROSOFT_SCOPE_PREFIX,
    OAUTH_AUTHORIZE_PATH,
    UI_PREFIX,
    _granted_microsoft_scopes,
    _microsoft_scope_urls,
    _pkce_pair,
)

#: What the console asks a human to consent to, spelled the way
#: Microsoft spells it: Graph resources as URLs, `offline_access` bare.
CONSENTED = _microsoft_scope_urls(DEFAULT_MICROSOFT_SCOPES)

MICROSOFT_API_PATH = (
    Path(__file__).resolve().parents[1]
    / "src" / "gatekeeper" / "_microsoft_api" / "microsoft_api.py"
)


def _microsoft_tier1(tmp_path, *, required_scopes=None) -> object:
    """Tier 1 with a `microsoft` toolkit bound to the `msgraph` credential."""
    toolkit = {
        "executor": "microsoft",
        "microsoft_script": "/opt/gatekeeper/microsoft/microsoft_api.py",
        "allowed_microsoft_actions": ["mail list", "mail send"],
        "credential": "msgraph",
        "max_timeout_seconds": 30,
        "max_output_bytes": 65536,
    }
    if required_scopes is not None:
        toolkit["required_scopes"] = required_scopes
    path = tmp_path / "toolkits-microsoft.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "outlook": toolkit,
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


def _client_pair_only(env, name: str = "msgraph") -> None:
    """The real starting point: a credential a human typed the Azure app
    registration's client_id/client_secret into, and nothing more."""
    env["credentials"].create(
        name, kind="oauth2",
        value=json.dumps({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}),
        actor="root", rev="",
    )


@pytest.fixture
def oauth_env(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    env = _build_env(tmp_path, _microsoft_tier1(tmp_path))
    _client_pair_only(env)
    return env


def _consent_params(page_text: str) -> dict[str, str]:
    import html
    import re

    match = re.search(r'href="(https://login\.microsoftonline\.com[^"]+)"', page_text)
    assert match, f"no consent link on the page: {page_text[:2000]}"
    query = urllib.parse.urlparse(html.unescape(match.group(1))).query
    return dict(urllib.parse.parse_qsl(query))


async def _start_flow(client) -> dict[str, str]:
    await _login(client)
    page = await client.get(f"{MICROSOFT_OAUTH_AUTHORIZE_PATH}?credential=msgraph")
    assert page.status_code == 200, page.text[:2000]
    return _consent_params(page.text)


async def _run_callback(env, monkeypatch, payload: dict) -> str:
    async def fake_exchange(**_kwargs):
        return payload

    monkeypatch.setattr("gatekeeper.ui._exchange_microsoft_code", fake_exchange)
    async with _client(env["app"]) as client:
        state = (await _start_flow(client))["state"]
        page = await client.get(
            f"{MICROSOFT_OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}"
        )
    assert page.status_code == 200, page.text[:2000]
    return page.text


def _stored(credentials, name: str = "msgraph") -> dict:
    return json.loads(credentials._resolve(name).value)


# -- The gate ---------------------------------------------------------------


async def test_both_routes_require_a_session(oauth_env):
    async with _client(oauth_env["app"]) as client:
        for path in (MICROSOFT_OAUTH_AUTHORIZE_PATH, MICROSOFT_OAUTH_CALLBACK_PATH):
            response = await client.get(path, follow_redirects=False)
            assert response.status_code == 303, path
            assert response.headers["location"].endswith("/login"), path


async def test_a_viewer_cannot_start_the_flow(oauth_env):
    async with _client(oauth_env["app"]) as client:
        await _login(client, "eye")
        response = await client.get(
            MICROSOFT_OAUTH_AUTHORIZE_PATH, follow_redirects=False
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith("/credentials")


# -- The consent URL --------------------------------------------------------


async def test_authorize_builds_the_consent_url_with_state_and_pkce(oauth_env):
    async with _client(oauth_env["app"]) as client:
        await _login(client)
        page = await client.get(MICROSOFT_OAUTH_AUTHORIZE_PATH)

    assert page.status_code == 200
    params = _consent_params(page.text)
    assert params["client_id"] == CLIENT_ID
    assert params["redirect_uri"] == f"{BASE}{MICROSOFT_OAUTH_CALLBACK_PATH}"
    assert params["response_type"] == "code"
    assert params["response_mode"] == "query"
    assert params["prompt"] == "consent"
    assert len(params["state"]) >= 32
    # PKCE: an S256 challenge, base64url and unpadded.
    assert params["code_challenge_method"] == "S256"
    assert "=" not in params["code_challenge"]
    assert len(params["code_challenge"]) == 43
    # The verifier is not on the page, and neither is the secret.
    assert CLIENT_SECRET not in page.text


async def test_the_exchange_gets_the_verifier_that_matches_the_challenge(
    oauth_env, monkeypatch
):
    """The point of PKCE: the code only redeems with a secret that never
    left this process, so an intercepted code is not enough."""
    seen: dict = {}

    async def fake_exchange(**kwargs):
        seen.update(kwargs)
        return {"refresh_token": NEW_REFRESH}

    monkeypatch.setattr("gatekeeper.ui._exchange_microsoft_code", fake_exchange)
    async with _client(oauth_env["app"]) as client:
        params = await _start_flow(client)
        await client.get(
            f"{MICROSOFT_OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={params['state']}"
        )

    verifier = seen["code_verifier"]
    assert verifier
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    assert base64.urlsafe_b64encode(digest).decode().rstrip("=") == (
        params["code_challenge"]
    )
    assert seen["redirect_uri"] == f"{BASE}{MICROSOFT_OAUTH_CALLBACK_PATH}"
    assert seen["client_id"] == CLIENT_ID


def test_the_pkce_pair_is_a_valid_rfc7636_pair():
    verifier, challenge = _pkce_pair()
    assert 43 <= len(verifier) <= 128
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode().rstrip("=")
    assert challenge == expected
    assert _pkce_pair()[0] != verifier


async def test_scopes_default_when_no_toolkit_declares_any(oauth_env):
    async with _client(oauth_env["app"]) as client:
        await _login(client)
        page = await client.get(MICROSOFT_OAUTH_AUTHORIZE_PATH)

    assert _consent_params(page.text)["scope"].split(" ") == CONSENTED


async def test_scopes_are_the_union_of_the_microsoft_toolkits(tmp_path, monkeypatch):
    """Tier 1 decides, and it is read per request, not at startup."""
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    tier1 = _microsoft_tier1(
        tmp_path,
        required_scopes=[
            "Mail.Read",
            # Written out in full -- both spellings are the same request.
            MICROSOFT_SCOPE_PREFIX + "Mail.Send",
            "offline_access",
            # And a duplicate, to show the union is one.
            "Mail.Read",
        ],
    )
    env = _build_env(tmp_path, tier1)
    _client_pair_only(env)
    async with _client(env["app"]) as client:
        await _login(client)
        page = await client.get(MICROSOFT_OAUTH_AUTHORIZE_PATH)

    assert _consent_params(page.text)["scope"].split(" ") == [
        MICROSOFT_SCOPE_PREFIX + "Mail.Read",
        MICROSOFT_SCOPE_PREFIX + "Mail.Send",
        "offline_access",
    ]


@pytest.mark.parametrize("reserved", ["offline_access", "openid", "profile", "email"])
def test_the_reserved_scopes_are_never_prefixed(reserved):
    """`https://graph.microsoft.com/offline_access` is not a scope, and
    Microsoft rejects the whole authorization request for it."""
    assert _microsoft_scope_urls([reserved]) == [reserved]


def test_bare_graph_names_are_expanded_and_urls_left_alone():
    assert _microsoft_scope_urls(
        ["Mail.Read", MICROSOFT_SCOPE_PREFIX + "Mail.Read", " ", "User.Read"]
    ) == [
        MICROSOFT_SCOPE_PREFIX + "Mail.Read",
        MICROSOFT_SCOPE_PREFIX + "User.Read",
    ]


# -- The callback -----------------------------------------------------------


async def test_callback_persists_the_token_scopes_and_provider(oauth_env, monkeypatch):
    page = await _run_callback(
        oauth_env, monkeypatch,
        {
            "access_token": "EwB.access-token-value",
            "refresh_token": NEW_REFRESH,
            "expires_in": 3599,
            "scope": " ".join(CONSENTED),
        },
    )

    assert _stored(oauth_env["credentials"]) == {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": NEW_REFRESH,
        "scopes": CONSENTED,
        # Both providers' bundles are kind oauth2 and look alike; this is
        # what tells a microsoft toolkit it has the right one.
        "provider": "microsoft",
    }
    assert "Connected" in page
    for secret in (NEW_REFRESH, CLIENT_SECRET, AUTH_CODE, "EwB.access-token-value"):
        assert secret not in page, secret


async def test_offline_access_survives_a_response_that_omits_it(
    oauth_env, monkeypatch
):
    """Microsoft answers with the Graph resources it granted and leaves
    `offline_access` out -- it is not a resource. Stored verbatim, the
    next refresh would stop asking for it and Microsoft would stop
    returning a rotated refresh token: the credential would go quietly
    read-only on an expiry nobody scheduled.
    """
    graph_only = [scope for scope in CONSENTED if scope != "offline_access"]
    assert "offline_access" not in graph_only

    await _run_callback(
        oauth_env, monkeypatch,
        {"refresh_token": NEW_REFRESH, "scope": " ".join(graph_only)},
    )

    stored = _stored(oauth_env["credentials"])["scopes"]
    assert stored == [*graph_only, "offline_access"]


async def test_a_narrowed_grant_is_stored_as_granted_not_as_asked(
    oauth_env, monkeypatch
):
    """The operator cleared a checkbox: Microsoft's answer wins."""
    narrowed = [MICROSOFT_SCOPE_PREFIX + "Mail.Read"]
    await _run_callback(
        oauth_env, monkeypatch,
        {"refresh_token": NEW_REFRESH, "scope": " ".join(narrowed)},
    )

    assert _stored(oauth_env["credentials"])["scopes"] == [
        *narrowed, "offline_access",
    ]


async def test_scopes_fall_back_to_the_consent_screens_when_microsoft_says_nothing(
    oauth_env, monkeypatch
):
    await _run_callback(oauth_env, monkeypatch, {"refresh_token": NEW_REFRESH})

    assert _stored(oauth_env["credentials"])["scopes"] == CONSENTED


@pytest.mark.parametrize("raw", [None, "", 123, ["not", "a", "string"]])
def test_an_unusable_scope_field_falls_back(raw):
    assert _granted_microsoft_scopes({"scope": raw}, CONSENTED) == CONSENTED


def test_the_scope_field_is_bounded_and_deduplicated():
    from gatekeeper.ui import MAX_GOOGLE_SCOPE_CHARS, MAX_GOOGLE_SCOPES

    absurd = " ".join(
        ["a" * (MAX_GOOGLE_SCOPE_CHARS + 1)] + [f"s{i}" for i in range(200)]
    )
    granted = _granted_microsoft_scopes({"scope": absurd}, [])
    assert len(granted) == MAX_GOOGLE_SCOPES
    assert all(len(scope) <= MAX_GOOGLE_SCOPE_CHARS for scope in granted)

    assert _granted_microsoft_scopes({"scope": "one one two"}, []) == ["one", "two"]


async def test_the_audit_log_carries_no_token_material(oauth_env, monkeypatch):
    await _run_callback(
        oauth_env, monkeypatch,
        {"refresh_token": NEW_REFRESH, "access_token": "EwB.access-token-value",
         "scope": " ".join(CONSENTED)},
    )

    log = _audit_text(oauth_env["tier1"])
    assert '"action": "microsoft_authorize"' in log
    assert '"action": "microsoft_callback"' in log
    assert '"result": "ok"' in log
    assert MICROSOFT_SCOPE_PREFIX + "Mail.Send" in log
    for secret in (NEW_REFRESH, CLIENT_SECRET, CLIENT_ID, AUTH_CODE,
                   "EwB.access-token-value"):
        assert secret not in log, secret


async def test_a_denied_consent_changes_nothing(oauth_env, monkeypatch):
    oauth_env["credentials"].rotate(
        "msgraph",
        value=json.dumps({
            "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
            "refresh_token": OLD_REFRESH, "provider": "microsoft",
        }),
        actor="root", rev=oauth_env["credentials"].revision(),
    )

    async def fail(**_kwargs):  # pragma: no cover - must never run
        raise AssertionError("no exchange on a denied consent")

    monkeypatch.setattr("gatekeeper.ui._exchange_microsoft_code", fail)
    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        page = await client.get(
            f"{MICROSOFT_OAUTH_CALLBACK_PATH}?error=access_denied&state={state}"
        )

    assert page.status_code == 400
    assert "Not connected" in page.text
    assert "access_denied" in page.text
    assert _stored(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "denied"' in _audit_text(oauth_env["tier1"])


async def test_a_response_without_a_refresh_token_is_an_error(oauth_env, monkeypatch):
    async def fake_exchange(**_kwargs):
        return {"access_token": "EwB.access-token-value", "expires_in": 3599}

    monkeypatch.setattr("gatekeeper.ui._exchange_microsoft_code", fake_exchange)
    async with _client(oauth_env["app"]) as client:
        state = (await _start_flow(client))["state"]
        page = await client.get(
            f"{MICROSOFT_OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}"
        )

    assert page.status_code == 400
    assert "no refresh token" in page.text
    assert "EwB.access-token-value" not in page.text
    assert "refresh_token" not in _stored(oauth_env["credentials"])


# -- One state store, two providers -----------------------------------------


async def test_a_google_state_is_not_redeemable_at_the_microsoft_callback(
    tmp_path, monkeypatch
):
    """Both flows issue into the same store. A state minted for Google
    redeemed here would write the credential with a bundle from the wrong
    identity platform.
    """
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    env = _build_env(tmp_path, _google_tier1(tmp_path))
    env["credentials"].create(
        "gws", kind="oauth2",
        value=json.dumps({
            "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
            "refresh_token": OLD_REFRESH,
        }),
        actor="root", rev="",
    )

    async def fail(**_kwargs):  # pragma: no cover - must never run
        raise AssertionError("no exchange for a foreign provider's state")

    monkeypatch.setattr("gatekeeper.ui._exchange_microsoft_code", fail)
    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fail)

    async with _client(env["app"]) as client:
        await _login(client)
        page = await client.get(f"{OAUTH_AUTHORIZE_PATH}?credential=gws")
        import html
        import re

        state = dict(
            urllib.parse.parse_qsl(
                urllib.parse.urlparse(
                    html.unescape(
                        re.search(r'href="(https://accounts\.google\.com[^"]+)"',
                                  page.text).group(1)
                    )
                ).query
            )
        )["state"]
        crossed = await client.get(
            f"{MICROSOFT_OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}"
        )

    assert crossed.status_code == 400
    assert _stored_bundle(env["credentials"])["refresh_token"] == OLD_REFRESH
    assert '"result": "state_mismatch"' in _audit_text(env["tier1"])


async def test_the_credentials_page_offers_the_flow_its_toolkit_names(oauth_env):
    """The button follows Tier 1: this credential is a microsoft
    toolkit's, so the Google flow is not offered for it."""
    async with _client(oauth_env["app"]) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/credentials")

    assert f"{MICROSOFT_OAUTH_AUTHORIZE_PATH}?credential=msgraph" in page.text
    assert f"{OAUTH_AUTHORIZE_PATH}?credential=msgraph" not in page.text


# -- The credential reaches the token file ----------------------------------


def _microsoft_service(tmp_path, bundle: dict) -> Service:
    tier1 = _microsoft_tier1(tmp_path)
    audit = AuditLog(str(tmp_path / "logs-token"))
    tools_path = tmp_path / "tools-token.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")
    credentials = CredentialStore(
        path=str(tmp_path / "credentials-token.yaml"), audit=audit
    )
    credentials.create(
        "msgraph", kind="oauth2", value=json.dumps(bundle), actor="root", rev="",
    )
    return Service(
        tier1=tier1,
        catalog=make_catalog(tmp_path, tier1, []),
        audit=audit,
        credentials=credentials,
    )


def _token_bundle(**extra) -> dict:
    return {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": NEW_REFRESH,
        **extra,
    }


def _materialized_token(service: Service) -> dict:
    env = service._microsoft_token_env("msgraph")
    return json.loads(
        (Path(env["HOME"]) / ".hermes" / "microsoft_token.json").read_text(
            encoding="utf-8"
        )
    )


def test_materialized_token_carries_the_stored_scopes(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _microsoft_service(
        tmp_path, _token_bundle(scopes=CONSENTED, provider="microsoft")
    )

    assert _materialized_token(service) == {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": NEW_REFRESH,
        "scopes": CONSENTED,
    }


def test_the_token_file_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _microsoft_service(tmp_path, _token_bundle(scopes=CONSENTED))
    env = service._microsoft_token_env("msgraph")
    path = Path(env["HOME"]) / ".hermes" / "microsoft_token.json"

    assert path.stat().st_mode & 0o077 == 0


def test_a_credential_without_scopes_still_materializes(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _microsoft_service(tmp_path, _token_bundle())

    assert "scopes" not in _materialized_token(service)


@pytest.mark.parametrize("stored", ["", [], {}, "a-string"])
def test_a_non_list_scopes_field_is_not_written(tmp_path, monkeypatch, stored):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _microsoft_service(tmp_path, _token_bundle(scopes=stored))

    assert "scopes" not in _materialized_token(service)


def test_a_google_credential_is_refused_by_a_microsoft_toolkit(tmp_path, monkeypatch):
    """The two bundles are both kind oauth2 and look alike. Without this
    the toolkit would call Graph with a Google refresh token and report
    an unexplained 401."""
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _microsoft_service(tmp_path, _token_bundle(provider="google"))

    with pytest.raises(Denied) as excinfo:
        service._microsoft_token_env("msgraph")
    assert "google" in str(excinfo.value.agent_message)


def test_invalidating_the_cache_re_materializes(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _microsoft_service(tmp_path, _token_bundle(scopes=CONSENTED))
    first = service._microsoft_token_env("msgraph")["HOME"]

    service.invalidate_microsoft_token_cache()
    second = service._microsoft_token_env("msgraph")["HOME"]

    assert first != second
    assert not Path(first).exists()


# -- The token file reaches the refresh -------------------------------------


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
