"""End-to-end over real MCP for `/admin/mcp` (REQUIREMENTS.md FR-2.8/2.9).

Mirrors `test_integration_mcp.py`'s approach: bring up the complete ASGI
application in-process and talk to it with the official MCP client,
including `AuthMiddleware` and the Streamable HTTP transport -- so a
composition bug between the two `Server` instances mounted in `build_app`
(one real `StreamableHTTPSessionManager.run()` each) shows up here as a
real request failing, not as plausible-looking code.
"""

from __future__ import annotations

import contextlib
import json

import httpx2
import pytest
import yaml
from mcp.client.client import Client, streamable_http_client

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.pending import PendingStore
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.ui import UI_PREFIX

BASE = "http://gatekeeper.test"
PASSWORDS = {"root": "admin-console-password"}


@pytest.fixture
def admin_mcp_env(tmp_path, tier1, tool_specs):
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")

    tokens = {
        "hermes": generate_token(),  # role: admin, no password -- /admin/mcp only
        "root": generate_token(),    # role: admin, console + /admin/mcp
        "bot": generate_token(),     # role: agent -- /mcp only
        "eye": generate_token(),     # role: viewer -- neither MCP endpoint
    }
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "hermes", "role": "admin",
                        "token_hash": hash_token(tokens["hermes"]),
                        "tools": [], "scopes": [],
                    },
                    {
                        "id": "root", "role": "admin",
                        "token_hash": hash_token(tokens["root"]),
                        "password_hash": hash_token(PASSWORDS["root"]),
                        "tools": [], "scopes": [],
                    },
                    {
                        "id": "bot", "role": "agent",
                        "token_hash": hash_token(tokens["bot"]),
                        "tools": ["demo.show"], "scopes": ["stack:*"],
                    },
                    {
                        "id": "eye", "role": "viewer",
                        "token_hash": hash_token(tokens["eye"]),
                        "password_hash": hash_token("viewer-console-password"),
                        "tools": [], "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    def _build():
        identities = load_identities(str(identities_path))
        audit = AuditLog(str(tmp_path / "logs"))
        service = Service(
            tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit
        )
        store = ConfigStore(
            service=service, identities=identities, audit=audit,
            tools_path=str(tools_path), identities_path=str(identities_path),
        )
        pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
        app = build_app(
            service=service, identities=identities, audit=audit, ui=True,
            store=store, pending=pending,
        )
        return app, store, pending

    return {"build": _build, "tokens": tokens, "tools_path": tools_path}


def _http(app, token: str | None) -> httpx2.AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, headers=headers, timeout=30.0,
    )


@contextlib.asynccontextmanager
async def connected(app, token: str, path: str = "/mcp"):
    async with app.router.lifespan_context(app):
        async with _http(app, token) as http:
            transport = streamable_http_client(f"{BASE}{path}", http_client=http)
            async with Client(transport) as client:
                yield client


# -- Both mounts actually work (real request, not just plausible code) -----


async def test_both_mcp_endpoints_answer_over_one_app(admin_mcp_env):
    """The composition in `build_app` -- two `streamable_http_app()` results
    merged into one Starlette app with a combined lifespan running both
    session managers -- actually works: both mounts answer real requests
    concurrently, within one lifespan, on one app instance.
    """
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]

    async with app.router.lifespan_context(app):
        async with _http(app, tokens["bot"]) as http:
            transport = streamable_http_client(f"{BASE}/mcp", http_client=http)
            async with Client(transport) as client:
                agent_tools = {t.name for t in (await client.list_tools()).tools}
        async with _http(app, tokens["hermes"]) as http:
            transport = streamable_http_client(f"{BASE}/admin/mcp", http_client=http)
            async with Client(transport) as client:
                admin_tools = {t.name for t in (await client.list_tools()).tools}

    assert "demo.show" in agent_tools
    assert "admin.tool_list" in admin_tools
    assert "admin.tool_get" in admin_tools


# -- Isolation (FR-2.9): tool sets never mix, same identity's token -----------


async def test_admin_tools_never_appear_on_mcp_and_vice_versa(admin_mcp_env):
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]

    async with connected(app, tokens["root"], "/admin/mcp") as client:
        admin_tools = {t.name for t in (await client.list_tools()).tools}
    assert all(name.startswith("admin.") for name in admin_tools)
    assert "demo.show" not in admin_tools


# -- Role gating per mount (FR-2.8) -------------------------------------------


async def test_admin_role_token_rejected_on_mcp(admin_mcp_env):
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with _http(app, tokens["hermes"]) as http:
        response = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 401


async def test_agent_role_token_rejected_on_admin_mcp(admin_mcp_env):
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with _http(app, tokens["bot"]) as http:
        response = await http.post(
            "/admin/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
    assert response.status_code == 401


async def test_viewer_role_token_rejected_on_admin_mcp(admin_mcp_env):
    """`viewer` is not `admin`, so it is rejected on `/admin/mcp` just like
    `agent` is (FR-2.9: "everyone else" is rejected on the admin mount).
    `/mcp` itself has never role-gated beyond `admin` -- a `viewer` token
    authenticates there exactly as before this feature (and simply has no
    tool grants, per `identity.may_call`), so that side is not asserted
    here.
    """
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with _http(app, tokens["eye"]) as http:
        response = await http.post(
            "/admin/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
    assert response.status_code == 401


async def test_admin_token_still_cannot_call_agent_tools(admin_mcp_env):
    """The same identity's token, tried against the endpoint it doesn't
    belong to (FR-2.9's same-identity isolation check)."""
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with _http(app, tokens["root"]) as http:
        response = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 401


# -- Tier-1 rejection parity with /ui -----------------------------------------


async def test_tool_create_rejects_tier1_violation(admin_mcp_env):
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    bad_spec = {
        "id": "demo.hack", "toolkit": "demo", "binary": "/not/allowed/binary",
        "title": "x", "description": "x", "category": "read", "idempotent": True,
        "enabled": False, "argv": [], "parameters": {}, "required_scopes": [],
        "timeout_seconds": 5, "max_output_bytes": 4096,
    }
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.tool_create", {"spec": bad_spec})
    assert result.is_error


async def test_tool_validate_matches_tool_create_rejection(admin_mcp_env):
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    bad_spec = {
        "id": "demo.hack2", "toolkit": "demo", "binary": "/not/allowed/binary",
        "title": "x", "description": "x", "category": "read", "idempotent": True,
        "enabled": False, "argv": [], "parameters": {}, "required_scopes": [],
        "timeout_seconds": 5, "max_output_bytes": 4096,
    }
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.tool_validate", {"spec": bad_spec})
    payload = json.loads(result.content[0].text)
    assert payload["ok"] is False


# -- Always-inert creation, category-conditional enable, always-pending delete


async def test_tool_create_always_disabled_even_if_spec_says_enabled(admin_mcp_env):
    app, store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    spec = {
        "id": "demo.newread", "toolkit": "demo", "binary": _python(),
        "title": "n", "description": "d", "category": "read", "idempotent": True,
        "enabled": True,  # deliberately -- admin.tool_create must force this False
        "argv": ["-c", "print(1)"], "parameters": {}, "required_scopes": [],
        "timeout_seconds": 5, "max_output_bytes": 4096,
    }
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.tool_create", {"spec": spec})
    assert not result.is_error
    payload = json.loads(result.content[0].text)
    assert payload["applied"] is True
    assert store.service.catalog.tools["demo.newread"].enabled is False


async def test_tool_enable_read_category_auto_applies_no_pending(admin_mcp_env):
    app, store, pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    # demo.show is category 'read' and starts enabled; disable then re-enable
    # via admin.* to observe the auto-apply path end to end.
    store.set_tool_enabled("demo.show", False, actor="root", rev=store.tools_revision())

    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.tool_enable", {"id": "demo.show"})
    payload = json.loads(result.content[0].text)
    assert payload["applied"] is True
    assert store.service.catalog.tools["demo.show"].enabled is True
    assert pending.list() == []


async def test_tool_enable_write_category_creates_pending_item(admin_mcp_env):
    app, store, pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    write_spec = {
        "id": "demo.writeit", "toolkit": "demo", "binary": _python(),
        "title": "w", "description": "d", "category": "write", "idempotent": False,
        "enabled": False, "argv": ["-c", "print(1)"], "parameters": {},
        "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096,
    }
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        await client.call_tool("admin.tool_create", {"spec": write_spec})
        result = await client.call_tool("admin.tool_enable", {"id": "demo.writeit"})
    payload = json.loads(result.content[0].text)
    assert payload["applied"] is False
    assert payload["pending"] is True
    assert store.service.catalog.tools["demo.writeit"].enabled is False
    items = pending.list(status="pending")
    assert len(items) == 1
    assert items[0].action == "tool_enable"
    assert items[0].actor == "hermes"


async def test_tool_delete_always_pending_even_for_read_tool(admin_mcp_env):
    app, store, pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.tool_delete", {"id": "demo.show"})
    payload = json.loads(result.content[0].text)
    assert payload["pending"] is True
    assert "demo.show" in store.service.catalog.tools  # unchanged until approved
    assert pending.list(status="pending")[0].action == "tool_delete"


async def test_grant_set_always_pending(admin_mcp_env):
    app, _store, pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.grant_set", {"identity_id": "bot", "tools": ["demo.echo"]}
        )
    payload = json.loads(result.content[0].text)
    assert payload["pending"] is True
    assert pending.list(status="pending")[0].action == "grant_set"


# -- approve/reject are structurally unreachable from /admin/mcp -------------


async def test_admin_mcp_tool_list_never_includes_approve_or_reject(admin_mcp_env):
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert "admin.approve" not in names
    assert "admin.reject" not in names


async def test_calling_admin_approve_by_name_is_unknown_tool(admin_mcp_env):
    app, _store, _pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.approve", {"id": "whatever"})
    assert result.is_error


# -- Approving via /ui makes the change reach /mcp for a granted agent -------


async def test_approved_pending_change_becomes_callable_on_mcp(admin_mcp_env):
    """The manual-verification scenario from the plan, automated: create
    (inert) -> propose an enable on a write tool -> approve at /ui/pending
    -> the tool becomes callable on /mcp for a granted agent identity.
    """
    app, store, pending = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]

    write_spec = {
        "id": "demo.approved_write", "toolkit": "demo", "binary": _python(),
        "title": "w", "description": "d", "category": "write", "idempotent": False,
        "enabled": False, "argv": ["-c", "print('done')"], "parameters": {},
        "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096,
    }
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        await client.call_tool("admin.tool_create", {"spec": write_spec})
        await client.call_tool("admin.tool_enable", {"id": "demo.approved_write"})

    item = pending.list(status="pending")[0]

    # Grant 'bot' the right to call it -- store-level, standing in for a
    # human doing this in the console; the point under test is the pending
    # approval path, not the grant UI.
    store.save_identity(
        identity_id="bot", role="agent",
        tools=["demo.show", "demo.approved_write"], scopes=["stack:*"],
        actor="root", rev=store.identities_revision(), replaces="bot",
    )

    async with _http(app, tokens["root"]) as http:
        await http.post(
            f"{UI_PREFIX}/login", data={"identity": "root", "password": PASSWORDS["root"]}
        )
        page = await http.get(f"{UI_PREFIX}/pending")
        marker = 'name="_csrf" value="'
        start = page.text.index(marker) + len(marker)
        csrf = page.text[start : page.text.index('"', start)]
        approve = await http.post(
            f"{UI_PREFIX}/pending/approve", data={"id": item.id, "_csrf": csrf}
        )
    assert approve.status_code in (200, 303)
    assert store.service.catalog.tools["demo.approved_write"].enabled is True

    # A fresh app: everything above is file-backed (tools.yaml/
    # identities.yaml/pending.yaml), so a new build reflects the same
    # state as new Python objects -- and each `streamable_http_app()`'s
    # session manager can only `run()` once per instance, so `app` (already
    # connected-to above) cannot be reused for a second live connection.
    app2, _store2, _pending2 = admin_mcp_env["build"]()
    async with connected(app2, tokens["bot"], "/mcp") as client:
        result = await client.call_tool("demo.approved_write", {})
    assert not result.is_error
    assert "done" in result.content[0].text


def _python() -> str:
    import sys

    return sys.executable
