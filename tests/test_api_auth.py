"""`/api/v1`: who gets in, and with what.

The console API carries the same powers as `/ui`, so it inherits the
console's four rules and these tests pin each of them on the new surface:
session only (an MCP bearer token is refused), viewer reads / admin
writes, read-only mode refuses every write, and every mutating request
carries a CSRF token. `If-Match` is the fifth: a write against a stale
revision is a 412, never a silent overwrite.
"""

from __future__ import annotations

import pytest
from api_env import API, PASSWORDS, audit_records, client, login, make_env
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from gatekeeper.api.app import build_api_app, openapi_schema
from gatekeeper.api.deps import (
    ApiContext,
    if_match,
    require_admin,
    require_session_write,
)
from gatekeeper.api.session import SESSION_COOKIE, LoginThrottle, SessionStore


@pytest.fixture
def env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs)


@pytest.fixture
def ro_env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs, read_only=True)


def _get_paths() -> list[str]:
    """Every GET route in the schema, with path parameters filled in."""
    schema = openapi_schema(build_api_app(None))
    paths = []
    for path, ops in schema["paths"].items():
        if "get" in ops:
            paths.append(
                path.replace("{tool_id}", "demo.show").replace("{key}", "sonarr")
                .replace("{slug}", "readme")
            )
    return sorted(paths)


def test_the_schema_lists_the_phase_one_reads():
    # A new route shows up here first -- and then in every test below that
    # iterates `_get_paths()`, so it cannot ship without the auth checks.
    assert set(_get_paths()) >= {
        "/session", "/account", "/overview", "/tools", "/tools/demo.show",
        "/integrations", "/identities", "/credentials", "/toolkits",
        "/toolkits/reference", "/requests/pending", "/requests/toolkits",
        "/audit", "/release-notes", "/stats", "/documents", "/documents/readme",
        "/oauth/providers",
    }


async def test_every_read_needs_a_session(env):
    async with client(env["app"]) as c:
        for path in _get_paths() + ["/openapi.json"]:
            response = await c.get(f"{API}{path}")
            assert response.status_code == 401, path
            assert response.json() == {"error": "Not signed in."}, path


async def test_an_agent_token_opens_nothing(env):
    """FR-11.5: the API token is not a console credential, not even with a
    valid session cookie next to it."""
    token = env["tokens"]["bot"]
    async with client(env["app"]) as c:
        for path in _get_paths():
            response = await c.get(
                f"{API}{path}", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 401, path
        # An admin's own token is refused just the same.
        await login(c, "root")
        response = await c.get(
            f"{API}/overview", headers={"Authorization": f"Bearer {env['tokens']['root']}"}
        )
        assert response.status_code == 401
        assert (await c.get(f"{API}/overview")).status_code == 200
    assert any(r.get("reason") == "api_bearer_rejected" for r in audit_records(env))


async def test_login_with_a_token_instead_of_the_password_fails(env):
    async with client(env["app"]) as c:
        response = await c.post(
            f"{API}/session", json={"identity": "root", "password": env["tokens"]["root"]}
        )
        assert response.status_code == 401
        assert response.json() == {"error": "Sign-in failed."}


async def test_an_agent_cannot_sign_in(env):
    async with client(env["app"]) as c:
        response = await c.post(f"{API}/session", json={"identity": "bot", "password": "x" * 20})
        assert response.status_code == 401
        assert SESSION_COOKIE not in response.cookies


async def test_login_is_json_only(env):
    """A cross-site HTML form cannot send application/json, so the login
    cannot be driven from a foreign page (login CSRF)."""
    async with client(env["app"]) as c:
        response = await c.post(
            f"{API}/session",
            content=f'{{"identity": "root", "password": "{PASSWORDS["root"]}"}}',
            headers={"Content-Type": "text/plain"},
        )
        assert response.status_code in (415, 422)
        assert SESSION_COOKIE not in response.cookies


async def test_session_cookie_attributes(env):
    async with client(env["app"]) as c:
        response = await c.post(
            f"{API}/session", json={"identity": "root", "password": PASSWORDS["root"]}
        )
        cookie = response.headers["set-cookie"].lower()
        assert "httponly" in cookie
        assert "samesite=strict" in cookie
        assert f"path={API}".lower() in cookie
    records = [r for r in audit_records(env) if r.get("kind") == "ui_login"]
    assert records and records[-1]["surface"] == "api"


async def test_login_is_throttled(env):
    async with client(env["app"]) as c:
        for _ in range(10):
            await c.post(f"{API}/session", json={"identity": "root", "password": "wrong"})
        response = await c.post(
            f"{API}/session", json={"identity": "root", "password": PASSWORDS["root"]}
        )
        assert response.status_code == 429


async def test_roles_in_the_session(env, ro_env):
    async with client(env["app"]) as c:
        admin = await login(c, "root")
    async with client(env["app"]) as c:
        viewer = await login(c, "eye")
    async with client(ro_env["app"]) as c:
        ro_admin = await login(c, "root")
    assert (admin["can_write"], admin["read_only"]) == (True, False)
    assert (viewer["can_write"], viewer["read_only"]) == (False, False)
    assert (ro_admin["can_write"], ro_admin["read_only"]) == (False, True)
    assert admin["csrf"] and admin["csrf"] != viewer["csrf"]


async def test_logout_needs_the_csrf_token(env):
    async with client(env["app"]) as c:
        info = await login(c, "eye")
        assert (await c.delete(f"{API}/session")).status_code == 403
        bad = await c.delete(f"{API}/session", headers={"X-CSRF-Token": "x" + info["csrf"]})
        assert bad.status_code == 403
        assert (await c.get(f"{API}/session")).status_code == 200
        ok = await c.delete(f"{API}/session", headers={"X-CSRF-Token": info["csrf"]})
        assert ok.status_code == 204
        assert (await c.get(f"{API}/session")).status_code == 401
    denied = [r for r in audit_records(env) if r.get("kind") == "admin_denied"]
    assert [r["reason"] for r in denied] == ["csrf_mismatch", "csrf_mismatch"]


async def test_the_schema_is_admin_only(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        assert (await c.get(f"{API}/openapi.json")).status_code == 403
    async with client(env["app"]) as c:
        await login(c, "root")
        response = await c.get(f"{API}/openapi.json")
        assert response.status_code == 200
        assert response.json()["servers"] == [{"url": API}]


async def test_no_interactive_docs(env):
    """Swagger/ReDoc pages need inline and CDN scripts -- not served."""
    async with client(env["app"]) as c:
        await login(c, "root")
        for path in ("/docs", "/redoc", "/docs/oauth2-redirect"):
            assert (await c.get(f"{API}{path}")).status_code == 404


async def test_toolkit_writes_do_not_exist(env):
    """FR-4.11: no route writes a toolkit, whatever the method."""
    async with client(env["app"]) as c:
        info = await login(c, "root")
        headers = {"X-CSRF-Token": info["csrf"], "If-Match": '"x"'}
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            for path in ("/toolkits", "/toolkits/demo", "/toolkits/reference"):
                response = await c.request(method, f"{API}{path}", headers=headers, json={})
                assert response.status_code in (404, 405), (method, path)


async def test_api_responses_carry_security_headers(env):
    async with client(env["app"]) as c:
        for response in (
            await c.get(f"{API}/session"),
            await c.post(f"{API}/session", json={"identity": "root", "password": PASSWORDS["root"]}),
            await c.get(f"{API}/overview"),
            await c.get(f"{API}/nonexistent"),
        ):
            assert response.headers["content-security-policy"].startswith("default-src 'none'")
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["cache-control"] == "no-store"


async def test_unknown_api_path_is_a_json_404(env):
    async with client(env["app"]) as c:
        await login(c, "root")
        response = await c.get(f"{API}/nonexistent")
        assert response.status_code == 404
        assert "error" in response.json()


async def test_api_is_absent_without_the_console(env, tier1):
    """Without `--ui` there is no console, and no API: the path falls back
    to the bearer requirement like every other non-public path."""
    from gatekeeper.server import build_app

    app = build_app(
        service=env["service"], identities=env["identities"], audit=env["audit"], ui=False,
    )
    async with client(app) as c:
        assert (await c.get(f"{API}/session")).status_code == 401
        response = await c.get(
            f"{API}/session", headers={"Authorization": f"Bearer {env['tokens']['bot']}"}
        )
        assert response.status_code == 404


# -- The write dependencies, on a test-only route ---------------------------------
#
# The dependencies every write uses, pinned in isolation. The real write
# routes get the same checks end to end in `test_api_write.py`.


def _write_app(env: dict, *, read_only: bool = False) -> tuple[FastAPI, SessionStore]:
    sessions = SessionStore()
    context = ApiContext(
        service=env["service"], identities=env["identities"], audit=env["audit"],
        sessions=sessions, throttle=LoginThrottle(),
        store=None if read_only else env["store"],
    )
    app = build_api_app(context)

    @app.post("/_probe")
    def probe(request: Request, _s=Depends(require_admin)) -> dict:
        return {"rev": if_match(request, env["store"].tools_revision())}

    @app.post("/_self")
    def self_service(_s=Depends(require_session_write)) -> dict:
        return {"ok": True}

    return app, sessions


def _signed(sessions: SessionStore, identity: str, role: str) -> tuple[dict, dict]:
    sid = sessions.create(identity, role)
    session = sessions.resolve(sid)
    return {SESSION_COOKIE: sid}, {"X-CSRF-Token": session.csrf}


def test_write_requires_admin_csrf_and_if_match(env):
    app, sessions = _write_app(env)
    rev = env["store"].tools_revision()
    with TestClient(app) as c:
        viewer_cookie, viewer_csrf = _signed(sessions, "eye", "viewer")
        c.cookies.update(viewer_cookie)
        assert c.post("/_probe", headers=viewer_csrf).status_code == 403
        c.cookies.clear()

        cookie, csrf = _signed(sessions, "root", "admin")
        c.cookies.update(cookie)
        assert c.post("/_probe", headers={"If-Match": f'"{rev}"'}).status_code == 403
        assert c.post("/_probe", headers=csrf).status_code == 428
        stale = c.post("/_probe", headers={**csrf, "If-Match": '"0123"'})
        assert stale.status_code == 412
        assert "changed" in stale.json()["error"]
        for tag in (f'"{rev}"', f'W/"{rev}"', rev):
            ok = c.post("/_probe", headers={**csrf, "If-Match": tag})
            assert ok.status_code == 200, tag
            assert ok.json() == {"rev": rev}
    reasons = [r["reason"] for r in audit_records(env) if r.get("kind") == "admin_denied"]
    assert reasons == ["role_required", "csrf_mismatch"]


def test_read_only_mode_refuses_every_write(env):
    app, sessions = _write_app(env, read_only=True)
    with TestClient(app) as c:
        cookie, csrf = _signed(sessions, "root", "admin")
        c.cookies.update(cookie)
        rev = env["store"].tools_revision()
        assert c.post("/_probe", headers={**csrf, "If-Match": rev}).status_code == 403
        assert c.post("/_self", headers=csrf).status_code == 403
    reasons = [r["reason"] for r in audit_records(env) if r.get("kind") == "admin_denied"]
    assert reasons == ["read_only", "read_only"]


def test_self_service_writes_need_csrf_but_not_admin(env):
    app, sessions = _write_app(env)
    with TestClient(app) as c:
        cookie, csrf = _signed(sessions, "eye", "viewer")
        c.cookies.update(cookie)
        assert c.post("/_self").status_code == 403
        assert c.post("/_self", headers=csrf).status_code == 200
