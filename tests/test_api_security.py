"""The console's security properties, pinned on `/api/v1` (1.0.0).

Until 1.0.0 these assertions lived in `test_ui.py` and `test_ui_admin.py`
against the HTML console. When that console was deleted, each property
was moved here, so it is still asserted on the surface that now carries
the same powers. The properties that were already covered by
`test_api_auth.py`, `test_api_read.py` and `test_api_write.py` are not
repeated.

Sections: the console session is not an MCP credential; sign-in answers
the same way whatever was wrong; reverse-proxy headers; CSRF tokens bound
to their session; identity changes end that identity's sessions; FR-4.11
across the whole app; Tier 1 still decides over HTTP; request decisions
that must not go wrong; what is left of `/ui`; and the session-store and
throttle units.
"""

from __future__ import annotations

import json
import threading

import httpx2
import pytest
import yaml
from api_env import API, BASE, PASSWORDS, audit_records, client, login, make_env

from gatekeeper.api.session import SESSION_COOKIE, LoginThrottle, SessionStore
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.server import build_app
from gatekeeper.service import Service

MCP_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}


@pytest.fixture
def env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs)


def _h(info: dict, etag: str | None = None) -> dict:
    headers = {"X-CSRF-Token": info["csrf"]}
    if etag is not None:
        headers["If-Match"] = etag
    return headers


def _auth_failures(env) -> list[dict]:
    return [r for r in audit_records(env) if r.get("kind") == "auth_failure"]


# -- The console session is not an MCP credential --------------------------------


async def test_a_console_session_does_not_authenticate_mcp(env):
    """The most important property of the console.

    A browser attaches a cookie to every request to its origin. If the
    auth middleware took it as proof, any website with a form aimed at
    `/mcp` could run tools on the host as the signed-in admin. The
    cookie's `Path=/api/v1` already keeps the browser from sending it
    there; this sends it anyway, by hand, and it must still open nothing.
    """
    async with client(env["app"]) as c:
        await login(c, "root")
        sid = c.cookies.get(SESSION_COOKIE)
        assert sid
    async with client(env["app"]) as c:
        cookie = {"Cookie": f"{SESSION_COOKIE}={sid}"}
        for path in ("/mcp", "/admin/mcp"):
            response = await c.post(path, json=MCP_LIST, headers={**MCP_ACCEPT, **cookie})
            assert response.status_code == 401, path
            assert response.json() == {"error": "unauthorized"}, path
        assert (await c.get("/metrics", headers=cookie)).status_code == 401


async def test_the_console_password_is_not_an_api_token(env):
    async with client(env["app"]) as c:
        response = await c.post(
            "/mcp", json=MCP_LIST,
            headers={**MCP_ACCEPT, "Authorization": f"Bearer {PASSWORDS['root']}"},
        )
    assert response.status_code == 401


async def test_similar_prefixes_are_not_console_paths(env):
    """Exact prefix matching: `/api/v1xyz` is not the API, `/appxyz` not the SPA."""
    async with client(env["app"]) as c:
        for path in ("/api/v1xyz", "/apixyz", "/appxyz", "/uixyz"):
            response = await c.get(path)
            assert response.status_code == 401, path
            assert response.json() == {"error": "unauthorized"}, path


# -- Sign-in -------------------------------------------------------------------------


async def test_a_wrong_password_is_refused_and_audited(env):
    async with client(env["app"]) as c:
        response = await c.post(
            f"{API}/session", json={"identity": "root", "password": "wrong-password-here"}
        )
    assert response.status_code == 401
    assert SESSION_COOKIE not in response.headers.get("set-cookie", "")
    assert _auth_failures(env)[-1]["reason"] == "ui_login_failed"


async def test_sign_in_is_not_a_directory_of_accounts(env):
    """Unknown identity, wrong password, an agent: the same answer three
    times. What actually happened is in the audit log."""
    async with client(env["app"]) as c:
        answers = [
            await c.post(f"{API}/session", json={"identity": who, "password": pw})
            for who, pw in (
                ("nosuchuser", PASSWORDS["root"]),
                ("root", "also-not-right"),
                ("bot", "anything-at-all"),
            )
        ]
    assert {r.status_code for r in answers} == {401}
    assert {r.text for r in answers} == {json.dumps({"error": "Sign-in failed."}, separators=(",", ":"))}


async def test_password_hashing_runs_off_the_event_loop(env, monkeypatch):
    """scrypt is slow on purpose; MCP calls share this event loop."""
    loop_thread = threading.get_ident()
    seen: list[int] = []

    def authenticate_console(self, identity_id, password):
        seen.append(threading.get_ident())
        return None

    monkeypatch.setattr(
        "gatekeeper.identity.IdentityStore.authenticate_console", authenticate_console
    )
    async with client(env["app"]) as c:
        await c.post(f"{API}/session", json={"identity": "root", "password": "x" * 12})
    assert seen and seen[0] != loop_thread


# -- Behind a reverse proxy --------------------------------------------------------


def _proxied(app, *, peer: str, trusted: list[str]) -> httpx2.AsyncClient:
    """Wraps `app` the way `gatekeeper serve --trusted-proxies` does at
    runtime: uvicorn's `ProxyHeadersMiddleware` outside the ASGI app,
    rewriting scope["client"]/scope["scheme"] before anything of ours
    sees the request. Nothing in gatekeeper reads X-Forwarded-* itself."""
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(
            app=ProxyHeadersMiddleware(app, trusted_hosts=trusted), client=(peer, 12345)
        ),
        base_url=BASE, timeout=30.0,
    )


async def test_a_trusted_proxy_reveals_the_real_client(env):
    async with _proxied(env["app"], peer="172.18.0.5", trusted=["172.18.0.5"]) as c:
        response = await c.post(
            f"{API}/session", json={"identity": "root", "password": "wrong-one"},
            headers={"X-Forwarded-For": "203.0.113.7"},
        )
    assert response.status_code == 401
    detail = _auth_failures(env)[-1]["detail"]
    assert "203.0.113.7" in detail and "172.18.0.5" not in detail


async def test_an_untrusted_peer_cannot_forge_its_address(env):
    async with _proxied(env["app"], peer="203.0.113.99", trusted=["172.18.0.5"]) as c:
        await c.post(
            f"{API}/session", json={"identity": "root", "password": "wrong-one"},
            headers={"X-Forwarded-For": "10.0.0.1"},
        )
    detail = _auth_failures(env)[-1]["detail"]
    assert "203.0.113.99" in detail and "10.0.0.1" not in detail


async def test_the_session_cookie_is_secure_behind_tls(env):
    async with _proxied(env["app"], peer="172.18.0.5", trusted=["172.18.0.5"]) as c:
        tls = await c.post(
            f"{API}/session", json={"identity": "root", "password": PASSWORDS["root"]},
            headers={"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https"},
        )
    assert tls.status_code == 200
    assert "secure" in tls.headers["set-cookie"].lower()
    async with client(env["app"]) as c:
        plain = await c.post(
            f"{API}/session", json={"identity": "root", "password": PASSWORDS["root"]}
        )
    assert "secure" not in plain.headers["set-cookie"].lower()


# -- CSRF -------------------------------------------------------------------------


async def test_another_sessions_csrf_token_is_refused(env):
    async with client(env["app"]) as a, client(env["app"]) as b:
        info_a = await login(a, "root")
        await login(b, "root")
        tag = (await b.get(f"{API}/tools")).headers["etag"]
        response = await b.put(
            f"{API}/tools/demo.echo/enabled", json={"enabled": False},
            headers={"X-CSRF-Token": info_a["csrf"], "If-Match": tag},
        )
    assert response.status_code == 403
    assert env["service"].catalog.tools["demo.echo"].enabled is True
    denied = [r for r in audit_records(env) if r.get("kind") == "admin_denied"]
    assert denied[-1]["reason"] == "csrf_mismatch"


async def test_agent_data_reaches_the_client_inert(env):
    """Rejected calls log the unvalidated arguments, so an agent can put
    nearly any text in the audit log. It must leave the API as a JSON
    string under a CSP that runs nothing and with sniffing off."""
    payload = '<script>alert("xss")</script>'
    env["audit"].write({
        "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "denied",
        "parameters": {"name": payload}, "detail": payload,
    })
    async with client(env["app"]) as c:
        await login(c, "eye")
        response = await c.get(f"{API}/audit")
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    record = next(r for r in response.json()["entries"] if r.get("detail") == payload)
    assert record["parameters"] == {"name": payload}


# -- Identity changes end that identity's sessions ------------------------------------


async def _edit_eye(env, change: dict) -> None:
    async with client(env["app"]) as admin:
        info = await login(admin, "root")
        tag = (await admin.get(f"{API}/identities")).headers["etag"]
        body = {"id": "eye", "role": "viewer", "tools": [], "scopes": [], "password": "", **change}
        response = await admin.put(f"{API}/identities/eye", json=body, headers=_h(info, tag))
        assert response.status_code == 200, response.text
        assert (await admin.get(f"{API}/session")).status_code == 200


@pytest.mark.parametrize("change", [{"role": "agent"}, {"id": "eye2"}], ids=["demoted", "renamed"])
async def test_a_role_change_or_rename_ends_that_identitys_sessions(env, change):
    async with client(env["app"]) as eye:
        await login(eye, "eye")
        await _edit_eye(env, change)
        assert (await eye.get(f"{API}/session")).status_code == 401


@pytest.mark.parametrize("action", ["rotate", "delete"])
async def test_rotating_or_deleting_ends_that_identitys_sessions(env, action):
    async with client(env["app"]) as eye, client(env["app"]) as admin:
        await login(eye, "eye")
        info = await login(admin, "root")
        tag = (await admin.get(f"{API}/identities")).headers["etag"]
        if action == "rotate":
            response = await admin.post(f"{API}/identities/eye/token", headers=_h(info, tag))
        else:
            response = await admin.delete(f"{API}/identities/eye", headers=_h(info, tag))
        assert response.status_code == 200, response.text
        assert (await eye.get(f"{API}/session")).status_code == 401
        assert (await admin.get(f"{API}/session")).status_code == 200


async def test_the_last_admin_cannot_be_removed_or_demoted(env):
    async with client(env["app"]) as c:
        info = await login(c, "root")
        for method, body in (("DELETE", None), ("PUT", {"id": "root", "role": "viewer"})):
            tag = (await c.get(f"{API}/identities")).headers["etag"]
            response = await c.request(
                method, f"{API}/identities/root", json=body, headers=_h(info, tag)
            )
            assert response.status_code == 400, (method, response.text)
        assert (await c.get(f"{API}/session")).status_code == 200
    assert env["identities"].identities["root"].role == "admin"


# -- FR-4.11 across the whole app ----------------------------------------------------


def _walk(routes, prefix=""):
    for route in routes:
        path = prefix + getattr(route, "path", "")
        inner = getattr(route, "routes", None) or getattr(getattr(route, "app", None), "routes", None)
        if inner:
            yield from _walk(inner, path)
        else:
            yield path, set(getattr(route, "methods", None) or ())


def test_no_route_anywhere_writes_a_toolkit(env):
    """Toolkits are deploy-time only. Every route in the full app -- MCP,
    the API mounted at /api/v1, what is left of /ui -- is walked; the only
    writes near a toolkit are the deploy/reject of a human-reviewed
    proposal, which the store checks against Tier 1."""
    allowed = {
        f"{API}/requests/toolkits/{{proposal_id}}/deploy",
        f"{API}/requests/toolkits/{{proposal_id}}/reject",
    }
    seen = list(_walk(env["app"].routes))
    assert any(path.startswith(API) for path, _ in seen)
    for path, methods in seen:
        if "toolkit" in path and path not in allowed:
            assert methods <= {"GET", "HEAD"}, (path, methods)
    assert not hasattr(env["store"], "save_toolkit")


# -- Tier 1 still decides, over HTTP ---------------------------------------------------


def _tool_yaml(tier1, **override) -> str:
    python = tier1.toolkits["demo"].binaries[0]
    spec = {
        "id": "demo.extra", "toolkit": "demo", "binary": python, "title": "Extra",
        "description": "x", "category": "read", "idempotent": True,
        "argv": ["-c", "print(1)"], "parameters": {}, "required_scopes": [],
        "timeout_seconds": 10, "max_output_bytes": 1024,
    }
    spec.update(override)
    return yaml.safe_dump(spec)


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"timeout_seconds": 99999}, "exceeds"),
        ({"binary": "/bin/sh"}, "allowlist"),
        ({"argv": ["-c", "print(1)", "{text}"],
          "parameters": {"text": {"type": "string", "required": True}}}, "pattern"),
    ],
    ids=["ceiling", "foreign-binary", "free-text"],
)
async def test_tier1_refuses_a_tool_the_console_would_create(env, tier1, override, reason):
    async with client(env["app"]) as c:
        info = await login(c, "root")
        tag = (await c.get(f"{API}/tools")).headers["etag"]
        response = await c.post(
            f"{API}/tools", json={"yaml": _tool_yaml(tier1, **override)}, headers=_h(info, tag)
        )
    assert response.status_code == 400, response.text
    assert reason in response.json()["error"].lower()
    assert "demo.extra" not in env["service"].catalog.tools


# -- Request decisions that must not go wrong ---------------------------------------


async def test_deleting_a_toolkit_a_tool_still_uses_is_refused(env):
    queue = env["toolkit_proposals"]
    item = queue.propose(name="demo", spec={}, actor="hermes", kind="delete")
    async with client(env["app"]) as c:
        info = await login(c, "root")
        response = await c.post(
            f"{API}/requests/toolkits/{item.id}/deploy", json={"confirm": True}, headers=_h(info)
        )
    assert response.status_code == 400
    assert "still referenced" in response.json()["error"]
    assert "demo" in env["service"].tier1.toolkits
    assert queue.get(item.id).status == "pending"


async def test_a_rebind_shows_the_binding_it_replaces(env):
    """FR-10.4: a redirect must not read as an addition."""
    queue = env["toolkit_proposals"]
    first = queue.propose(name="demo", spec={"credential": "old-key"}, actor="hermes", kind="bind")
    queue.deploy(first.id, decided_by="root")
    second = queue.propose(name="demo", spec={"credential": "new-key"}, actor="hermes", kind="bind")
    async with client(env["app"]) as c:
        await login(c, "eye")
        listing = (await c.get(f"{API}/requests/toolkits")).json()
    item = next(p for p in listing if p["id"] == second.id)
    assert item["current"]["credential"] == "old-key"
    assert item["spec"]["credential"] == "new-key"


async def test_an_unchanged_grant_still_flags_a_missing_tool(env):
    env["pending"].propose(
        action="grant_set", actor="hermes",
        payload={
            "identity_id": "bot", "tools": ["demo.show", "demo.ghost"],
            "prev_tools": ["demo.show", "demo.ghost"],
        },
        base_rev=env["store"].identity_revision("bot"),
    )
    async with client(env["app"]) as c:
        await login(c, "eye")
        (item,) = (await c.get(f"{API}/requests/pending")).json()
    ghost = [t for t in item["review"]["tools"] if t["id"] == "demo.ghost"]
    assert ghost and ghost[0]["state"] == "missing"


async def test_approving_a_delete_whose_tool_is_gone_closes_it_as_stale(env, tmp_path, tier1):
    pending, store = env["pending"], env["store"]
    item = pending.propose(
        action="tool_delete", actor="hermes", payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    tools_path = tmp_path / "tools-rw.yaml"
    specs = yaml.safe_load(tools_path.read_text(encoding="utf-8"))["tools"]
    tools_path.write_text(
        yaml.safe_dump({"tools": [s for s in specs if s.get("id") != "demo.show"]}),
        encoding="utf-8",
    )
    env["service"].catalog = load_catalog(str(tools_path), tier1)
    async with client(env["app"]) as c:
        info = await login(c, "root")
        response = await c.post(f"{API}/requests/pending/{item.id}/approve", headers=_h(info))
    assert response.status_code == 400
    assert "stale" in response.json()["error"].lower()
    assert "No tool with ID" not in response.text
    assert pending.get(item.id).status == "stale"


# -- What is left of /ui ------------------------------------------------------------


async def test_ui_paths_redirect_to_the_same_page_under_app(env):
    async with client(env["app"]) as c:
        for path, target in (
            ("/ui", "/app/"), ("/ui/", "/app/"), ("/ui/requests", "/app/requests"),
            ("/ui/tools/new", "/app/tools/new"),
            ("/ui//evil.example/x", "/app/evil.example/x"),
            # The query rides along: pages read it.
            ("/ui/requests?tab=change", "/app/requests?tab=change"),
            ("/ui//evil.example?next=//x", "/app/evil.example?next=//x"),
        ):
            response = await c.get(path)
            assert response.status_code == 308, path
            assert response.headers["location"] == target, path


async def test_an_old_form_post_is_gone_not_replayed(env):
    async with client(env["app"]) as c:
        for path in ("/ui/login", "/ui/tools/save", "/ui/pending/approve"):
            response = await c.post(path, data={"identity": "root"})
            assert response.status_code == 410, path
            assert "/app" in response.text
    assert not [r for r in audit_records(env) if r.get("kind") == "ui_login"]


async def test_browser_noise_goes_to_app_and_stays_out_of_the_audit_log(env):
    before = len(_auth_failures(env))
    async with client(env["app"]) as c:
        root = await c.get("/")
        assert (root.status_code, root.headers["location"]) == (303, "/app/")
        icon = await c.get("/favicon.ico")
        assert (icon.status_code, icon.headers["location"]) == (308, "/app/favicon.svg")
    assert len(_auth_failures(env)) == before


async def test_without_the_console_root_still_needs_a_token(tier1, tool_specs, tmp_path):
    reference = make_env(tmp_path, tier1, tool_specs)
    audit = AuditLog(str(tmp_path / "logs-noui"))
    service = Service(tier1=tier1, catalog=reference["service"].catalog, audit=audit)
    app = build_app(service=service, identities=reference["identities"], audit=audit)
    async with client(app) as c:
        for path in ("/", "/favicon.ico", "/ui/", "/app/", f"{API}/session"):
            assert (await c.get(path)).status_code == 401, path


async def test_an_oauth_callback_without_a_flow_changes_nothing(env):
    async with client(env["app"]) as c:
        response = await c.get("/ui/oauth/google/callback?code=x&state=forged")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/app/credentials?oauth=state_mismatch")


# -- Session store and throttle (units) ----------------------------------------------


def test_sessions_expire():
    store = SessionStore(ttl=0)
    assert store.resolve(store.create("root", "admin")) is None


def test_session_ids_are_unguessable():
    store = SessionStore()
    ids = {store.create("root", "admin") for _ in range(50)}
    assert len(ids) == 50 and all(len(i) >= 40 for i in ids)


def test_each_session_gets_its_own_csrf_token():
    store = SessionStore()
    first = store.resolve(store.create("root", "admin"))
    second = store.resolve(store.create("root", "admin"))
    assert first.csrf != second.csrf and len(first.csrf) >= 24


def test_only_admin_may_write():
    store = SessionStore()
    assert store.resolve(store.create("root", "admin")).can_write
    assert not store.resolve(store.create("eye", "viewer")).can_write


def test_dropping_an_identity_ends_only_its_sessions():
    store = SessionStore()
    doomed, other = store.create("gone", "admin"), store.create("stays", "admin")
    store.drop_identity("gone")
    assert store.resolve(doomed) is None and store.resolve(other) is not None


def test_the_throttle_is_per_address_and_resets():
    throttle = LoginThrottle(max_failures=3, window_seconds=300)
    for _ in range(3):
        assert not throttle.blocked("10.0.0.1")
        throttle.record_failure("10.0.0.1")
    assert throttle.blocked("10.0.0.1")
    assert not throttle.blocked("10.0.0.2")
    throttle.reset("10.0.0.1")
    assert not throttle.blocked("10.0.0.1")

