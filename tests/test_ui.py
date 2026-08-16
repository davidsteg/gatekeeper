"""The operations UI (read-only).

The focus is not on appearance, but on three properties
that the UI must not violate:

* The session opens exclusively `/ui`. If it also applied to `/mcp`,
  any arbitrary website could execute tools on the host via the
  automatically attached cookie.
* Console password and API token are separate proofs. Neither may
  work where the other applies -- otherwise the separation would be
  a claim and a lost secret would open both paths.
* Displayed audit data comes partly from agents and is unvalidated
  for rejected calls. It must arrive masked.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import httpx2
import pytest
import yaml

from gatekeeper.audit import AuditLog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.ui import (
    UI_PREFIX,
    LoginThrottle,
    SessionStore,
    _bucket_calls,
    has_admin,
    read_audit,
)

BASE = "http://gatekeeper.test"

#: Console password of the test admin. Long enough for MIN_PASSWORD_LENGTH.
ROOT_PASSWORD = "correct-horse-battery"


@pytest.fixture
def ui_identities(tmp_path):
    """An admin for the UI and an agent that has no business there."""
    tokens = {"root": generate_token(), "bot": generate_token()}
    path = tmp_path / "identities-ui.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token(tokens["root"]),
                        # Two separate proofs: the token speaks to /mcp,
                        # the password signs in at the console.
                        "password_hash": hash_token(ROOT_PASSWORD),
                        # An admin needs no tool rights: the UI calls nothing.
                        "tools": [],
                        "scopes": [],
                    },
                    {
                        "id": "bot",
                        "role": "agent",
                        "token_hash": hash_token(tokens["bot"]),
                        "tools": ["demo.show", "demo.echo"],
                        "scopes": ["stack:*"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    return load_identities(str(path)), tokens


@pytest.fixture
def ui_app(tier1, catalog, ui_identities, tmp_path):
    store, _ = ui_identities
    audit = AuditLog(tier1.audit_dir)
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    return build_app(service=service, identities=store, audit=audit, ui=True)


def _client(app, **kwargs) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, timeout=30.0, **kwargs
    )


async def _login(
    client: httpx2.AsyncClient, identity: str = "root", password: str = ROOT_PASSWORD
):
    return await client.post(
        f"{UI_PREFIX}/login", data={"identity": identity, "password": password}
    )


# -- The separation of MCP and UI -------------------------------------------


async def test_ui_session_does_not_authenticate_mcp(ui_app, ui_identities):
    """The most important test in this file.

    A cookie is automatically sent by the browser with every request to the
    origin. If the auth middleware accepted it as proof, a foreign website
    with a form targeting /mcp would suffice to execute tools on the host
    in the name of the signed-in admin.
    """
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        assert client.cookies.get("gatekeeper_ui")  # session exists

        # Same client, same origin, valid session - but without
        # Authorization header /mcp must not let anything through.
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}


async def test_ui_session_does_not_open_metrics(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        assert (await client.get("/metrics")).status_code == 401


async def test_bearer_token_does_not_open_ui(ui_app, ui_identities):
    """And the reverse direction: an agent token is not UI access."""
    _, tokens = ui_identities
    async with _client(
        ui_app, headers={"Authorization": f"Bearer {tokens['bot']}"}
    ) as client:
        response = await client.get(f"{UI_PREFIX}/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].endswith("/login")


async def test_session_cookie_is_scoped_and_httponly(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        response = await _login(client)
        raw = response.headers["set-cookie"].lower()
        assert "httponly" in raw
        assert "samesite=strict" in raw
        assert f"path={UI_PREFIX}" in raw


# -- Access requirement ---------------------------------------------------------


def _guarded_routes(app) -> list[tuple[str, str]]:
    """(path, method) for everything under /ui except login and logout."""
    seen = []
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith(UI_PREFIX) or path.endswith(("/login", "/logout")):
            continue
        for method in sorted(getattr(route, "methods", set()) or {"GET"}):
            if method in ("GET", "POST"):
                seen.append((path, method))
    return seen


async def test_every_ui_route_requires_a_session(ui_app):
    """Counts the registered routes instead of maintaining a list.

    A page or action added in the future where the session check was
    forgotten will be caught here and not only in operation. The
    writing routes are explicitly included -- a hole there would be
    especially costly.
    """
    routes = _guarded_routes(ui_app)
    assert len(routes) >= 12, f"too few UI routes found: {routes}"
    async with _client(ui_app) as client:
        for path, method in routes:
            response = await client.request(method, path, follow_redirects=False)
            assert response.status_code == 303, f"{method} {path}"
            assert response.headers["location"].endswith("/login"), f"{method} {path}"


async def test_agent_role_cannot_log_in(ui_app, ui_identities):
    """`role` was a field without effect until now. Now it decides.

    An agent has no console password -- neither its token nor any
    other value gets it in.
    """
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        response = await _login(client, "bot", tokens["bot"])
        assert response.status_code == 200
        assert "Sign-in failed" in response.text
        assert not client.cookies.get("gatekeeper_ui")


async def test_api_token_is_not_a_console_password(ui_app, ui_identities):
    """The core of the separation: the admin's token does not open the console.

    Previously it was exactly the sign-in secret. Whoever types it into the
    form today does not get in -- and no longer needs to, because it belongs
    in an agent's configuration, not in a browser (FR-11.5).
    """
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        response = await _login(client, "root", tokens["root"])
        assert "Sign-in failed" in response.text
        assert not client.cookies.get("gatekeeper_ui")

        # And the counter-test: with the password it works.
        assert (await _login(client)).status_code == 303


async def test_console_password_is_not_an_api_token(ui_app):
    """The reverse direction: the console password does not speak to /mcp."""
    async with _client(
        ui_app, headers={"Authorization": f"Bearer {ROOT_PASSWORD}"}
    ) as client:
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401


async def test_wrong_password_is_rejected_and_audited(ui_app, tier1):
    async with _client(ui_app) as client:
        response = await _login(client, "root", "wrong-password-here")
    assert not response.cookies.get("gatekeeper_ui")

    path = os.path.join(tier1.audit_dir, "audit.jsonl")
    with open(path, encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    assert any(r["kind"] == "auth_failure" for r in records)


async def test_unknown_identity_gets_the_same_answer(ui_app):
    """The login form must not be a directory of console accounts.

    Unknown identifier, wrong password, agent role -- the sender
    gets the same sentence three times. What actually happened is in the audit log.
    """
    def error_of(response) -> str:
        start = response.text.index('<p class="err">')
        return response.text[start : response.text.index("</p>", start)]

    async with _client(ui_app) as client:
        unknown = await _login(client, "nosuchuser", ROOT_PASSWORD)
        wrong = await _login(client, "root", "also-not-right")
    assert "Sign-in failed" in error_of(unknown)
    assert error_of(unknown) == error_of(wrong)


async def test_login_and_logout_roundtrip(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        response = await _login(client)
        assert response.status_code == 303

        page = await client.get(f"{UI_PREFIX}/")
        assert page.status_code == 200
        assert "Tier 1" in page.text

        await client.post(f"{UI_PREFIX}/logout")
        after = await client.get(f"{UI_PREFIX}/", follow_redirects=False)
        assert after.status_code == 303


async def test_ui_is_off_by_default(tier1, catalog, ui_identities, tmp_path):
    """Without --ui, /ui is not a public surface but token-required."""
    store, _ = ui_identities
    audit = AuditLog(str(tmp_path / "logs-noui"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    app = build_app(service=service, identities=store, audit=audit)
    async with _client(app) as client:
        assert (await client.get(f"{UI_PREFIX}/login")).status_code == 401


async def test_similar_prefix_is_not_public(ui_app):
    """'/uixyz' must not pass as a UI path."""
    async with _client(ui_app) as client:
        assert (await client.get("/uixyz")).status_code == 401


def _auth_failures(tier1) -> list[dict]:
    path = os.path.join(tier1.audit_dir, "audit.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [
            r
            for r in (json.loads(line) for line in handle if line.strip())
            if r["kind"] == "auth_failure"
        ]


async def test_browser_noise_does_not_reach_the_audit_log(ui_app, tier1):
    """A browser visit must not log failed attempts.

    Whoever types in the address triggers `GET /` and `GET /favicon.ico`
    without intending any of it. If those land as `auth_failure` in the log,
    the one real guessing attempt disappears in the noise -- and rotation
    pushes older, real entries out faster.
    """
    before = len(_auth_failures(tier1))
    async with _client(ui_app) as client:
        root = await client.get("/", follow_redirects=False)
        assert root.status_code == 303
        assert root.headers["location"] == f"{UI_PREFIX}/"

        icon = await client.get("/favicon.ico")
        assert icon.status_code == 200
        assert icon.headers["content-type"].startswith("image/svg+xml")

    assert len(_auth_failures(tier1)) == before


async def test_root_stays_protected_without_ui(tier1, catalog, ui_identities, tmp_path):
    """Without UI, '/' remains token-required -- the exception only applies with UI."""
    store, _ = ui_identities
    audit = AuditLog(str(tmp_path / "logs-root"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    app = build_app(service=service, identities=store, audit=audit)
    async with _client(app) as client:
        assert (await client.get("/", follow_redirects=False)).status_code == 401
        assert (await client.get("/favicon.ico")).status_code == 401


# -- Display of foreign data ---------------------------------------------


async def test_audit_values_from_agents_are_escaped(ui_app, ui_identities, tier1):
    """Rejected calls log the *unvalidated* arguments.

    An agent can therefore store largely arbitrary text there. Exactly
    this text lands in the UI -- it must arrive masked.
    """
    audit = AuditLog(tier1.audit_dir)
    payload = '<script>alert("xss")</script>'
    audit.call(
        identity="bot",
        tool_id="demo.echo",
        tool_version=1,
        parameters={"text": payload},
        scopes=[],
        outcome="denied",
        denial_reason="param_invalid",
        detail=payload,
    )

    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/audit")

    assert page.status_code == 200
    assert "<script>alert" not in page.text
    assert "&lt;script&gt;" in page.text


async def test_pages_forbid_scripts(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/tools")
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src" not in csp  # falls back to default-src 'none'
    assert page.headers["cache-control"] == "no-store"


async def test_token_hashes_are_never_rendered(ui_app, ui_identities):
    store, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/identities")
    for identity in store.identities.values():
        assert identity.token_hash not in page.text
    assert "scrypt$" not in page.text


async def test_tools_page_shows_who_may_call(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/tools")
    assert "demo.show" in page.text
    # 'bot' may call demo.show, 'root' cannot - the cross-reference is the
    # actual purpose of the page.
    assert "bot" in page.text


# -- Building blocks --------------------------------------------------------------


def test_read_audit_filters_and_orders(tmp_path):
    path = tmp_path / "audit.jsonl"
    with open(path, "w", encoding="utf-8") as handle:
        for index in range(5):
            handle.write(
                json.dumps(
                    {
                        "ts": f"t{index}",
                        "kind": "call",
                        "identity": "a" if index % 2 else "b",
                        "tool": "demo.show",
                        "outcome": "ok",
                    }
                )
                + "\n"
            )
    records, truncated = read_audit(str(path), identity="a")
    assert not truncated
    assert [r["ts"] for r in records] == ["t3", "t1"]  # most recent first


def test_read_audit_survives_broken_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"kind": "call"}\nnot json\n\n', encoding="utf-8")
    records, _ = read_audit(str(path))
    assert len(records) == 1


def test_read_audit_missing_file():
    assert read_audit("/does/not/exist/audit.jsonl") == ([], False)


def test_calls_in_the_current_hour_reach_the_chart():
    """Regression: the chart stayed empty even though calls were present.

    The present is rounded down to the full hour. If the timestamp
    of the entry was not treated the same way, a call from the current
    hour lay *after* this present -- negative age, no bucket, empty chart.
    Exactly the case one rarely reproduces by hand.
    """
    now = datetime(2026, 8, 12, 19, 0, tzinfo=timezone.utc)
    records = [
        {"kind": "call", "ts": "2026-08-12T19:57:00+0000", "outcome": "ok"},
        {"kind": "call", "ts": "2026-08-12T19:58:00+0000", "outcome": "denied"},
        # Different timezone, same hour in UTC.
        {"kind": "call", "ts": "2026-08-12T21:59:00+0200", "outcome": "ok"},
        # Non-calls do not count.
        {"kind": "ui_login", "ts": "2026-08-12T19:30:00+0000"},
    ]
    buckets = _bucket_calls(records, 12, now=now)
    assert buckets[-1] == (2, 1)
    assert sum(o + d for o, d in buckets[:-1]) == 0


def test_bucket_calls_spreads_over_hours():
    now = datetime(2026, 8, 12, 19, 0, tzinfo=timezone.utc)
    records = [
        {"kind": "call", "ts": "2026-08-12T17:10:00+0000", "outcome": "ok"},
        {"kind": "call", "ts": "2026-08-12T18:10:00+0000", "outcome": "ok"},
        # Too old for the window.
        {"kind": "call", "ts": "2026-08-11T19:10:00+0000", "outcome": "ok"},
        # An unreadable timestamp must not cause a crash.
        {"kind": "call", "ts": "broken", "outcome": "ok"},
    ]
    buckets = _bucket_calls(records, 12, now=now)
    assert buckets[-3] == (1, 0)
    assert buckets[-2] == (1, 0)
    assert sum(o + d for o, d in buckets) == 2


def test_sessions_expire():
    store = SessionStore(ttl=0)
    sid = store.create("root", "admin")
    assert store.resolve(sid) is None


def test_session_ids_are_unguessable():
    store = SessionStore()
    ids = {store.create("root", "admin") for _ in range(50)}
    assert len(ids) == 50
    assert all(len(i) >= 40 for i in ids)


def test_each_session_gets_its_own_csrf_token():
    store = SessionStore()
    first = store.resolve(store.create("root", "admin"))
    second = store.resolve(store.create("root", "admin"))
    assert first.csrf != second.csrf
    assert len(first.csrf) >= 24


def test_only_admin_may_write():
    store = SessionStore()
    assert store.resolve(store.create("root", "admin")).can_write
    assert not store.resolve(store.create("eye", "viewer")).can_write


def test_dropping_an_identity_kills_its_sessions():
    store = SessionStore()
    doomed = store.create("gone", "admin")
    other = store.create("stays", "admin")
    store.drop_identity("gone")
    assert store.resolve(doomed) is None
    assert store.resolve(other) is not None


def test_throttle_blocks_after_repeated_failures():
    throttle = LoginThrottle(max_failures=3, window_seconds=300)
    for _ in range(3):
        assert not throttle.blocked("10.0.0.1")
        throttle.record_failure("10.0.0.1")
    assert throttle.blocked("10.0.0.1")
    # Other origin remains unaffected.
    assert not throttle.blocked("10.0.0.2")
    throttle.reset("10.0.0.1")
    assert not throttle.blocked("10.0.0.1")


def test_has_admin(ui_identities, identities):
    store, _ = ui_identities
    assert has_admin(store)
    agents_only, _ = identities
    assert not has_admin(agents_only)