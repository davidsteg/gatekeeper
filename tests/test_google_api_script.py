"""google_api.py, the vendored Google Workspace CLI the `google` executor runs:
the scopes a token file names reach the refresh.

A refresh is not a free renewal: Google checks the scopes the request
asks for against the ones the operator actually consented to, and
answers anything wider with `invalid_scope` -- refusing the refresh
itself, so *every* call on that credential dies, not just one that
wanted the extra scope. The console stores the granted scopes and the
executor writes them into `google_token.json` (both pinned in the
crate's tests); these tests follow them from the token file into the
refresh request -- plus the fallback for a token written before any of
this, which names exactly the scopes the console asks for.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

#: What the console asks a human to consent to (rust/src/oauth.rs,
#: DEFAULT_GOOGLE_SCOPES), spelled the way Google spells it. The crate
#: checks the script's fallback against its own list; this checks the
#: script uses it.
GOOGLE_SCOPE_PREFIX = "https://www.googleapis.com/auth/"
CONSENTED = [
    GOOGLE_SCOPE_PREFIX + name
    for name in (
        "gmail.readonly", "gmail.send", "gmail.modify", "calendar.events",
        "calendar.events.readonly", "drive", "drive.file",
        "drive.metadata.readonly", "spreadsheets", "contacts",
    )
]
CLIENT_ID = "1234.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-test-client-secret-value"
NEW_REFRESH = "1//brand-new-refresh-token-value"

GOOGLE_API_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "google" / "google_api.py"
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
