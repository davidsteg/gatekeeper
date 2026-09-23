"""The scopes a Google grant covers, from consent screen to refresh.

A refresh is not a free renewal: Google checks the scopes the request
asks for against the ones the operator actually consented to, and
answers anything wider with `invalid_scope` -- refusing the refresh
itself, so *every* call on that credential dies, not just one that
wanted the extra scope.

Nothing recorded the grant. The console asked for ten scopes, stored the
refresh token alone, `service.py` materialized a `google_token.json`
with three fields and no `scopes`, and google_api.py fell back to a
hardcoded list that named `calendar`, `documents` and
`contacts.readonly` -- three scopes no consent screen had ever shown.
Every refresh asked for them and every refresh was refused.

So these tests follow one value the whole way: the consent screen's
scopes into the credential, the credential into the token file, the
token file into the refresh request -- plus the fallback for a token
written before any of this, which now at least names scopes the console
does ask for.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml
from conftest import make_catalog
from test_ui_oauth import (
    AUTH_CODE,
    CLIENT_ID,
    CLIENT_SECRET,
    NEW_REFRESH,
    _build_env,
    _client,
    _google_tier1,
    _start_flow,
    _stored_bundle,
)

from gatekeeper.audit import AuditLog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.service import Service
from gatekeeper.ui import (
    DEFAULT_GOOGLE_SCOPES,
    GOOGLE_SCOPE_PREFIX,
    OAUTH_CALLBACK_PATH,
    _granted_google_scopes,
)

#: What the console asks a human to consent to, spelled the way Google
#: spells it. Every list in this file is compared against this one.
CONSENTED = [GOOGLE_SCOPE_PREFIX + name for name in DEFAULT_GOOGLE_SCOPES]

GOOGLE_API_PATH = (
    Path(__file__).resolve().parents[1]
    / "src" / "gatekeeper" / "_google_api" / "google_api.py"
)


def _load_google_api(monkeypatch, hermes_home: Path):
    """Imports the vendored google_api.py against a throwaway HERMES_HOME.

    The script is not part of the importable package (it runs as a
    subprocess, from `/opt/gatekeeper/google/` in the image), and it
    resolves its token path once at import time -- so it is loaded from
    its file, fresh, with `HERMES_HOME` already pointing at a temp dir.
    """
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    # The script puts its own directory on sys.path to reach
    # `_hermes_home`; the copy is restored at teardown.
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location("google_api_under_test", GOOGLE_API_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def google_api(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    home.mkdir()
    return _load_google_api(monkeypatch, home)


def _write_token(google_api, payload: dict) -> None:
    google_api.TOKEN_PATH.write_text(json.dumps(payload), encoding="utf-8")


def _token_bundle(**extra) -> dict:
    return {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": NEW_REFRESH,
        **extra,
    }


# -- The consent screen's scopes reach the credential -----------------------


@pytest.fixture
def oauth_env(tmp_path, monkeypatch):
    """The console's own oauth fixture, with the client pair only.

    Re-declared rather than imported: a fixture in another test module is
    not visible here, and the two files want the same starting point --
    a credential a human has typed client_id/client_secret into.
    """
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    env = _build_env(tmp_path, _google_tier1(tmp_path))
    env["credentials"].create(
        "gws", kind="oauth2",
        value=json.dumps({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}),
        actor="root", rev="",
    )
    return env


async def _run_callback(env, monkeypatch, payload: dict) -> str:
    async def fake_exchange(**_kwargs):
        return payload

    monkeypatch.setattr("gatekeeper.ui._exchange_google_code", fake_exchange)
    async with _client(env["app"]) as client:
        state = (await _start_flow(client))["state"]
        page = await client.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={state}")
    assert page.status_code == 200, page.text[:2000]
    return page.text


async def test_callback_persists_the_granted_scopes(oauth_env, monkeypatch):
    """The fix: the grant is recorded next to the token that uses it."""
    await _run_callback(
        oauth_env, monkeypatch,
        {"refresh_token": NEW_REFRESH, "scope": " ".join(CONSENTED)},
    )

    bundle = _stored_bundle(oauth_env["credentials"])
    assert bundle == {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": NEW_REFRESH,
        "scopes": CONSENTED,
    }


async def test_a_narrowed_grant_is_stored_as_granted_not_as_asked(
    oauth_env, monkeypatch
):
    """The operator cleared a checkbox: Google's answer wins.

    Storing the consent screen's list here would put the credential back
    in exactly the state this bug is about -- a refresh asking for a
    scope the grant does not cover.
    """
    narrowed = [GOOGLE_SCOPE_PREFIX + "gmail.readonly", GOOGLE_SCOPE_PREFIX + "drive.file"]
    await _run_callback(
        oauth_env, monkeypatch,
        {"refresh_token": NEW_REFRESH, "scope": " ".join(narrowed)},
    )

    assert _stored_bundle(oauth_env["credentials"])["scopes"] == narrowed


async def test_scopes_fall_back_to_the_consent_screens_when_google_says_nothing(
    oauth_env, monkeypatch
):
    """No `scope` field: what we asked for is the best answer available,
    and it is ours rather than an absent third party's."""
    await _run_callback(oauth_env, monkeypatch, {"refresh_token": NEW_REFRESH})

    assert _stored_bundle(oauth_env["credentials"])["scopes"] == CONSENTED


async def test_the_scopes_are_audited_but_no_token_material_is(
    oauth_env, monkeypatch, tmp_path
):
    page = await _run_callback(
        oauth_env, monkeypatch,
        {"refresh_token": NEW_REFRESH, "scope": " ".join(CONSENTED),
         "access_token": "ya29.access-token-value"},
    )
    log = open(
        str(Path(oauth_env["tier1"].audit_dir) / "audit.jsonl"), encoding="utf-8"
    ).read()

    assert '"result": "ok"' in log
    assert GOOGLE_SCOPE_PREFIX + "gmail.send" in log
    for secret in (NEW_REFRESH, CLIENT_SECRET, AUTH_CODE, "ya29.access-token-value"):
        assert secret not in log, secret
        assert secret not in page, secret


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        123,
        ["not", "a", "string"],
    ],
)
def test_an_unusable_scope_field_falls_back(raw):
    """Anything that is not a space-separated string is not a scope list."""
    assert _granted_google_scopes({"scope": raw}, CONSENTED) == CONSENTED


def test_the_scope_field_is_bounded_and_deduplicated():
    """It arrives in a token response, so it is treated like input."""
    from gatekeeper.ui import MAX_GOOGLE_SCOPE_CHARS, MAX_GOOGLE_SCOPES

    absurd = " ".join(["a" * (MAX_GOOGLE_SCOPE_CHARS + 1)] + [f"s{i}" for i in range(200)])
    granted = _granted_google_scopes({"scope": absurd}, CONSENTED)
    assert len(granted) == MAX_GOOGLE_SCOPES
    assert all(len(scope) <= MAX_GOOGLE_SCOPE_CHARS for scope in granted)

    assert _granted_google_scopes({"scope": "one one two"}, CONSENTED) == ["one", "two"]


# -- The credential reaches the token file ----------------------------------


def _google_service(tmp_path, bundle: dict) -> Service:
    tier1 = _google_tier1(tmp_path)
    audit = AuditLog(str(tmp_path / "logs-token"))
    tools_path = tmp_path / "tools-token.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")
    credentials = CredentialStore(
        path=str(tmp_path / "credentials-token.yaml"), audit=audit
    )
    credentials.create(
        "gws", kind="oauth2", value=json.dumps(bundle), actor="root", rev="",
    )
    return Service(
        tier1=tier1,
        catalog=make_catalog(tmp_path, tier1, []),
        audit=audit,
        credentials=credentials,
    )


def _materialized_token(service: Service) -> dict:
    env = service._google_token_env("gws")
    return json.loads(
        (Path(env["HOME"]) / ".hermes" / "google_token.json").read_text(encoding="utf-8")
    )


def test_materialized_token_carries_the_stored_scopes(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _google_service(tmp_path, _token_bundle(scopes=CONSENTED))

    assert _materialized_token(service) == {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": NEW_REFRESH,
        "scopes": CONSENTED,
    }


def test_a_credential_without_scopes_still_materializes(tmp_path, monkeypatch):
    """Credentials written before the grant was recorded keep working:
    the key is left out rather than guessed at, and google_api.py's own
    fallback applies."""
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _google_service(tmp_path, _token_bundle())

    assert "scopes" not in _materialized_token(service)


@pytest.mark.parametrize("stored", ["", [], {}, "a-string"])
def test_a_non_list_scopes_field_is_not_written(tmp_path, monkeypatch, stored):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    service = _google_service(tmp_path, _token_bundle(scopes=stored))

    assert "scopes" not in _materialized_token(service)


# -- The token file reaches the refresh -------------------------------------


def test_stored_scopes_win_over_the_fallback(google_api):
    stored = [GOOGLE_SCOPE_PREFIX + "gmail.readonly"]
    _write_token(google_api, _token_bundle(scopes=stored))

    assert google_api._stored_token_scopes() == stored


def test_the_fallback_is_what_the_console_asks_for(google_api):
    """A token file with no scopes has nothing better to fall back to, so
    the fallback is at least a list the console does request -- not the
    old one, which named `calendar`, `documents` and `contacts.readonly`
    and was therefore never a subset of any grant."""
    _write_token(google_api, _token_bundle())

    assert google_api._stored_token_scopes() == CONSENTED
    assert google_api.SCOPES == CONSENTED


def test_the_fallback_survives_an_unreadable_token(google_api):
    google_api.TOKEN_PATH.write_text("{not json", encoding="utf-8")

    assert google_api._stored_token_scopes() == CONSENTED


def test_the_refresh_asks_for_exactly_the_stored_scopes(google_api, monkeypatch):
    """The end of the chain: the list Google is asked to renew.

    `google.oauth2.credentials` is patched rather than reached over the
    network -- what is under test is which scopes are handed to it, which
    is the whole of the bug.
    """
    import google.auth.transport.requests
    import google.oauth2.credentials

    stored = [
        GOOGLE_SCOPE_PREFIX + "gmail.readonly",
        GOOGLE_SCOPE_PREFIX + "calendar.events",
    ]
    _write_token(google_api, _token_bundle(scopes=stored))
    seen: dict = {}

    class FakeCredentials:
        expired = True
        refresh_token = NEW_REFRESH
        valid = True

        @classmethod
        def from_authorized_user_file(cls, filename, scopes):
            seen["filename"] = filename
            seen["scopes"] = scopes
            return cls()

        def refresh(self, request):
            seen["refreshed_with"] = request

        def to_json(self):
            return json.dumps(_token_bundle(scopes=stored, token="ya29.fresh"))

    monkeypatch.setattr(google.oauth2.credentials, "Credentials", FakeCredentials)
    monkeypatch.setattr(
        google.auth.transport.requests, "Request", lambda: "transport-request"
    )

    creds = google_api.get_credentials()

    assert isinstance(creds, FakeCredentials)
    assert seen["filename"] == str(google_api.TOKEN_PATH)
    # Exactly the stored list: not a superset, not the module fallback.
    assert seen["scopes"] == stored
    assert seen["refreshed_with"] == "transport-request"
    # And the refreshed token is written back with its scopes intact --
    # `Credentials.to_json()` spells them the same way, so the file keeps
    # one shape whether gatekeeper or google-auth wrote it last.
    assert json.loads(google_api.TOKEN_PATH.read_text())["scopes"] == stored


def test_a_token_without_scopes_refreshes_against_the_fallback(google_api, monkeypatch):
    """The hardening: an old credential still refreshes, because the
    fallback is now a subset of what was consented to."""
    import google.auth.transport.requests
    import google.oauth2.credentials

    _write_token(google_api, _token_bundle())
    seen: dict = {}

    class FakeCredentials:
        expired = False
        refresh_token = NEW_REFRESH
        valid = True

        @classmethod
        def from_authorized_user_file(cls, filename, scopes):
            seen["scopes"] = scopes
            return cls()

    monkeypatch.setattr(google.oauth2.credentials, "Credentials", FakeCredentials)
    monkeypatch.setattr(google.auth.transport.requests, "Request", lambda: None)

    google_api.get_credentials()

    assert seen["scopes"] == CONSENTED
