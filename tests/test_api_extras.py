"""`/api/v1` stats, bundled documents and OAuth sign-in (0.57.0).

The OAuth half reuses `test_oauth.py`'s console (a google toolkit
bound to the half-filled `gws` credential). What matters here: the API
start shares the callback's single-use state, the callback sends an
`/app`-started flow back to `/app` with a result code only, and no
response or redirect ever carries token material.
"""

from __future__ import annotations

import json
import urllib.parse

import pytest
from api_env import API, login, make_env
from test_oauth import (
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
    _stored_bundle,
)

from gatekeeper.credentials import KEY_ENV, generate_master_key
from gatekeeper.oauth import GOOGLE_SCOPE_PREFIX, OAUTH_CALLBACK_PATH

SECRETS = (CLIENT_SECRET, OLD_REFRESH, NEW_REFRESH, AUTH_CODE)


@pytest.fixture
def env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs)


@pytest.fixture
def oauth_env(tmp_path, monkeypatch):
    """`test_oauth`'s console: a google toolkit, a half-filled `gws`."""
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    env = _build_env(tmp_path, _google_tier1(tmp_path))
    env["credentials"].create(
        "gws", kind="oauth2", actor="root", rev="",
        value=json.dumps({
            "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "refresh_token": OLD_REFRESH,
        }),
    )
    return env


# -- Stats, documents ---------------------------------------------------------


async def test_stats_for_each_window(env):
    async with _client(env["app"]) as c:
        await login(c, "eye")
        for window, buckets in (("24h", 24), ("7d", 7), ("30d", 30)):
            body = (await c.get(f"{API}/stats", params={"window": window})).json()
            assert body["window"] == window
            assert len(body["series"]) == buckets
            assert [w["key"] for w in body["windows"]] == ["24h", "7d", "30d"]
        assert (await c.get(f"{API}/stats", params={"window": "1y"})).status_code in (400, 422)


async def test_stats_count_tool_calls(env):
    env["audit"].write({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok", "duration_ms": 5})
    env["audit"].write({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "denied"})
    async with _client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/stats")).json()
    assert body["totals"]["total"] == 2 and body["totals"]["ok"] == 1
    assert body["identities"][0]["name"] == "bot"


async def test_stats_top_tools_carry_their_toolkit(env):
    # Most calls first; a tool the catalog does not know is tagged
    # `_unknown`, so the console's per-toolkit filter can still show it.
    for outcome in ("ok", "ok", "failed"):
        env["audit"].write({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": outcome})
    env["audit"].write({"kind": "call", "identity": "bot", "tool": "gone.tool", "outcome": "denied"})
    env["audit"].write({"kind": "admin_change", "actor": "root", "action": "tool_create", "target": "demo.show"})
    async with _client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/stats")).json()
    assert body["tools"] == [
        {"name": "demo.show", "toolkit": "demo", "total": 3, "ok": 2, "denied": 0, "failed": 1},
        {"name": "gone.tool", "toolkit": "_unknown", "total": 1, "ok": 0, "denied": 1, "failed": 0},
    ]


async def test_stats_read_their_whole_window_and_nothing_older(env):
    # 250 calls inside the last hour (more than the 200 records the 24 h
    # window used to stop at), then one from two days ago appended before
    # them: the 24 h window counts every one of the 250 and not the old
    # one, and the 7 d window counts all 251.
    from datetime import datetime, timedelta

    now = datetime.now().astimezone()
    old = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S%z")
    recent = now.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(env["audit_path"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": old, "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok"}) + "\n")
        for _ in range(250):
            handle.write(json.dumps({"ts": recent, "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok"}) + "\n")
    async with _client(env["app"]) as c:
        await login(c, "eye")
        day = (await c.get(f"{API}/stats")).json()
        week = (await c.get(f"{API}/stats", params={"window": "7d"})).json()
    assert day["totals"]["total"] == 250
    assert day["truncated"] is False
    assert sum(b["ok"] for b in day["series"]) == 250
    assert week["totals"]["total"] == 251


async def test_documents_are_a_fixed_list(env, tmp_path, monkeypatch):
    # Found next to the package, not through the working directory.
    monkeypatch.chdir(tmp_path)
    async with _client(env["app"]) as c:
        await login(c, "eye")
        index = (await c.get(f"{API}/documents")).json()
        assert {d["slug"] for d in index} == {"readme", "requirements", "agents", "release"}
        readme = (await c.get(f"{API}/documents/readme")).json()
        assert "gatekeeper" in readme["text"]
        # No path from the request reaches the filesystem.
        for slug in ("../pyproject.toml", "README.md", "%2e%2e%2fpyproject.toml"):
            assert (await c.get(f"{API}/documents/{slug}")).status_code == 404


# -- OAuth ----------------------------------------------------------------------


async def _api_start(c, credential: str = "gws") -> dict:
    info = await login(c, "root")
    response = await c.post(
        f"{API}/oauth/google/authorize", json={"credential": credential},
        headers={"X-CSRF-Token": info["csrf"]},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _state(start: dict) -> str:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(start["consent_url"]).query))["state"]


async def test_providers_list_the_named_credentials(oauth_env):
    async with _client(oauth_env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/oauth/providers")).json()
    assert body == [{
        "key": "google", "label": "Google", "credentials": ["gws"],
        "callback_path": OAUTH_CALLBACK_PATH,
    }]


async def test_authorize_needs_an_admin_and_csrf(oauth_env):
    async with _client(oauth_env["app"]) as c:
        assert (await c.post(f"{API}/oauth/google/authorize", json={})).status_code == 401
        info = await login(c, "eye")
        response = await c.post(
            f"{API}/oauth/google/authorize", json={}, headers={"X-CSRF-Token": info["csrf"]}
        )
        assert response.status_code == 403
        await login(c, "root")
        assert (await c.post(f"{API}/oauth/google/authorize", json={})).status_code == 403


async def test_authorize_answers_the_consent_url_and_nothing_secret(oauth_env):
    async with _client(oauth_env["app"]) as c:
        start = await _api_start(c, credential="")  # the only named one is picked
    assert start["credential"] == "gws"
    assert start["callback_uri"] == f"{BASE}{OAUTH_CALLBACK_PATH}"
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(start["consent_url"]).query))
    assert query["client_id"] == CLIENT_ID and query["redirect_uri"] == start["callback_uri"]
    assert query["state"]
    assert all(s.startswith(GOOGLE_SCOPE_PREFIX) for s in start["scopes"])
    text = json.dumps(start)
    for secret in SECRETS:
        assert secret not in text
    record = json.loads(_audit_text(oauth_env["tier1"]).splitlines()[-1])
    assert record["action"] == "google_authorize" and record["surface"] == "api"
    assert CLIENT_SECRET not in _audit_text(oauth_env["tier1"])


async def test_authorize_refusals(oauth_env):
    async with _client(oauth_env["app"]) as c:
        info = await login(c, "root")
        headers = {"X-CSRF-Token": info["csrf"]}
        missing = await c.post(
            f"{API}/oauth/google/authorize", json={"credential": "nope"}, headers=headers
        )
        assert missing.status_code == 400 and "does not exist" in missing.json()["error"]
        unknown = await c.post(f"{API}/oauth/yahoo/authorize", json={}, headers=headers)
        assert unknown.status_code == 404
        extra = await c.post(
            f"{API}/oauth/google/authorize", json={"credential": "gws", "x": 1}, headers=headers
        )
        assert extra.status_code in (400, 422)


async def test_an_app_flow_returns_to_app_with_a_result_code(oauth_env, monkeypatch):
    async def fake_exchange(*, code, client_id, client_secret, redirect_uri):
        assert (code, client_id, client_secret) == (AUTH_CODE, CLIENT_ID, CLIENT_SECRET)
        return {
            "access_token": "ya29.access-token-value", "refresh_token": NEW_REFRESH,
            "scope": "https://www.googleapis.com/auth/gmail.readonly",
        }

    monkeypatch.setattr("gatekeeper.oauth._exchange_google_code", fake_exchange)
    async with _client(oauth_env["app"]) as c:
        start = await _api_start(c)
        response = await c.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={_state(start)}")
        assert response.status_code == 303
        location = response.headers["location"]
        assert location == "/app/credentials?oauth=ok&provider=google&credential=gws"
        # Single use: the same state again changes nothing.
        again = await c.get(f"{OAUTH_CALLBACK_PATH}?code={AUTH_CODE}&state={_state(start)}")
        assert again.status_code == 303
        assert again.headers["location"] == (
            "/app/credentials?oauth=state_mismatch&provider=google&credential="
        )
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == NEW_REFRESH
    for secret in SECRETS:
        assert secret not in location


async def test_a_denied_app_flow_changes_nothing(oauth_env):
    async with _client(oauth_env["app"]) as c:
        start = await _api_start(c)
        response = await c.get(
            f"{OAUTH_CALLBACK_PATH}?error=access_denied%3Cscript%3E&state={_state(start)}"
        )
    assert response.status_code == 303
    # The provider's text is not reflected; only the console's own code is.
    assert response.headers["location"] == "/app/credentials?oauth=denied&provider=google&credential=gws"
    assert _stored_bundle(oauth_env["credentials"])["refresh_token"] == OLD_REFRESH
