"""`/app`: the React console's static build, and the contract it is built on.

The page itself carries no data -- everything comes from `/api/v1` -- so
what matters here is how the bytes are served: the CSP that replaces
`/ui`'s script-free invariant (REQUIREMENTS.md, FR-11.9), caching by
content, the SPA fallback, and that nothing outside the build directory
can be read through it.
"""

from __future__ import annotations

import os

import pytest
from api_env import client, make_env

from gatekeeper.api import web
from gatekeeper.api.app import schema_text
from gatekeeper.api.web import APP_CSP

REPO = os.path.join(os.path.dirname(__file__), "..")


@pytest.fixture
def built(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(
        '<!doctype html><script type="module" src="/app/assets/index-abc.js"></script>',
        encoding="utf-8",
    )
    (dist / "assets" / "index-abc.js").write_text("console.log('x');" * 100, encoding="utf-8")
    (dist / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside the build", encoding="utf-8")
    monkeypatch.setenv(web.WEB_DIR_ENV, str(dist))
    return dist


@pytest.fixture
def env(tmp_path, tier1, tool_specs, built):
    return make_env(tmp_path, tier1, tool_specs)


async def test_index_carries_the_console_csp(env):
    async with client(env["app"]) as c:
        response = await c.get("/app/")
    assert response.status_code == 200
    assert response.headers["content-security-policy"] == APP_CSP
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "/app/assets/index-abc.js" in response.text


def test_the_csp_allows_only_this_origin():
    directives = dict(
        (part.strip().split(" ", 1) + [""])[:2] for part in APP_CSP.split(";") if part.strip()
    )
    assert directives["default-src"] == "'none'"
    assert directives["script-src"] == "'self'"
    assert directives["require-trusted-types-for"] == "'script'"
    assert directives["frame-ancestors"] == "'none'"
    for value in directives.values():
        assert "unsafe" not in value
        assert "http" not in value and "*" not in value


async def test_hashed_assets_are_immutable(env):
    async with client(env["app"]) as c:
        response = await c.get("/app/assets/index-abc.js", headers={"Accept-Encoding": "gzip"})
        assert response.status_code == 200
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
        assert response.headers["content-type"].startswith(("text/javascript", "application/javascript"))
        assert response.headers.get("content-encoding") == "gzip"
        assert response.headers["content-security-policy"] == APP_CSP
        icon = await c.get("/app/favicon.svg")
        assert icon.status_code == 200
        assert "immutable" not in icon.headers["cache-control"]


async def test_client_routes_fall_back_to_index(env):
    async with client(env["app"]) as c:
        for path in ("/app/tools", "/app/tools/docker.compose_ps", "/app/audit?outcome=ok"):
            response = await c.get(path)
            assert response.status_code == 200, path
            assert response.headers["cache-control"] == "no-store"
            assert "index-abc.js" in response.text, path


async def test_missing_assets_are_404_not_html(env):
    async with client(env["app"]) as c:
        response = await c.get("/app/assets/index-old.js")
    assert response.status_code == 404
    assert "<script" not in response.text


async def test_no_path_escapes_the_build(env):
    async with client(env["app"]) as c:
        for path in (
            "/app/../secret.txt", "/app/%2e%2e/secret.txt", "/app/assets/..%2f..%2fsecret.txt",
            "/app/..%2fsecret.txt",
        ):
            response = await c.get(path)
            assert "outside the build" not in response.text, path


async def test_app_needs_no_token_and_redirects_to_the_slash(env):
    async with client(env["app"]) as c:
        response = await c.get("/app", follow_redirects=False)
    assert response.status_code == 308
    assert response.headers["location"] == "/app/"


async def test_not_built_is_a_clear_503(env, monkeypatch):
    monkeypatch.setattr(web, "web_dir", lambda: None)
    async with client(env["app"]) as c:
        response = await c.get("/app/")
    assert response.status_code == 503
    assert "npm run build" in response.text


async def test_no_console_without_ui(env):
    from gatekeeper.server import build_app

    app = build_app(
        service=env["service"], identities=env["identities"], audit=env["audit"], ui=False,
    )
    async with client(app) as c:
        assert (await c.get("/app/")).status_code == 401


def test_the_committed_schema_is_current():
    """The frontend's TypeScript types are generated from
    frontend/openapi.json; a stale copy means the client and server
    disagree. Regenerate with `python -m gatekeeper.api > frontend/openapi.json`
    and `npm run gen:api`."""
    with open(os.path.join(REPO, "frontend", "openapi.json"), encoding="utf-8") as handle:
        assert handle.read() == schema_text()
