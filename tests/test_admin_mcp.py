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

import gatekeeper
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.pending import PendingStore
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.toolkit_proposals import ToolkitProposalStore
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

    def _build(*, credentials=None):
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
        toolkit_proposals = ToolkitProposalStore(
            path=str(tmp_path / "toolkit-proposals.yaml"),
            audit=audit,
            service=service,
            toolkits_path=str(tmp_path / "toolkits.yaml"),
            tools_path=str(tools_path),
            identities_path=str(identities_path),
        )
        app = build_app(
            service=service, identities=identities, audit=audit, ui=True,
            store=store, pending=pending, toolkit_proposals=toolkit_proposals,
            credentials=credentials,
        )
        return app, store, pending, toolkit_proposals

    return {"build": _build, "tokens": tokens, "tools_path": tools_path}


@pytest.fixture
def credential_store(tmp_path, monkeypatch):
    """A fresh, empty `CredentialStore` -- for `admin.cred_propose`, which

    needs one on `AdminService` to check name collisions/revision against.
    """
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    audit = AuditLog(str(tmp_path / "cred-logs"))
    return CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)


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
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
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
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]

    async with connected(app, tokens["root"], "/admin/mcp") as client:
        admin_tools = {t.name for t in (await client.list_tools()).tools}
    assert all(name.startswith("admin.") for name in admin_tools)
    assert "demo.show" not in admin_tools


# -- Role gating per mount (FR-2.8) -------------------------------------------


async def test_admin_role_token_rejected_on_mcp(admin_mcp_env):
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with _http(app, tokens["hermes"]) as http:
        response = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 401


async def test_agent_role_token_rejected_on_admin_mcp(admin_mcp_env):
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
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
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with _http(app, tokens["eye"]) as http:
        response = await http.post(
            "/admin/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
    assert response.status_code == 401


async def test_admin_token_still_cannot_call_agent_tools(admin_mcp_env):
    """The same identity's token, tried against the endpoint it doesn't
    belong to (FR-2.9's same-identity isolation check)."""
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with _http(app, tokens["root"]) as http:
        response = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 401


# -- Tier-1 rejection parity with /ui -----------------------------------------


async def test_tool_create_rejects_tier1_violation(admin_mcp_env):
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
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
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
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
    app, store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
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
    app, store, pending, _toolkit_proposals = admin_mcp_env["build"]()
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
    app, store, pending, _toolkit_proposals = admin_mcp_env["build"]()
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
    app, store, pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.tool_delete", {"id": "demo.show"})
    payload = json.loads(result.content[0].text)
    assert payload["pending"] is True
    assert "demo.show" in store.service.catalog.tools  # unchanged until approved
    assert pending.list(status="pending")[0].action == "tool_delete"


async def test_grant_set_always_pending(admin_mcp_env):
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.grant_set", {"identity_id": "bot", "tools": ["demo.echo"]}
        )
    payload = json.loads(result.content[0].text)
    assert payload["pending"] is True
    assert pending.list(status="pending")[0].action == "grant_set"


async def test_role_set_always_pending(admin_mcp_env):
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    # "eye" already has a console password (role: viewer) -- promoting it to
    # admin needs no new password, unlike a passwordless agent identity.
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.role_set", {"identity_id": "eye", "role": "admin"}
        )
    payload = json.loads(result.content[0].text)
    assert payload["pending"] is True
    assert pending.list(status="pending")[0].action == "role_set"


async def test_role_set_unknown_identity_rejected(admin_mcp_env):
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.role_set", {"identity_id": "ghost", "role": "viewer"}
        )
    assert result.is_error
    assert pending.list(status="pending") == []


async def test_role_set_to_ui_role_without_password_rejected(admin_mcp_env):
    """`bot` (role: agent) has no console password -- `admin.role_set` has
    no password field of its own, so promoting it to `viewer` here would
    leave an unsignable-in identity if it were allowed through.
    """
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.role_set", {"identity_id": "bot", "role": "viewer"}
        )
    assert result.is_error
    assert pending.list(status="pending") == []


# -- approve/reject are structurally unreachable from /admin/mcp -------------


async def test_admin_mcp_tool_list_never_includes_approve_or_reject(admin_mcp_env):
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert "admin.approve" not in names
    assert "admin.reject" not in names


async def test_calling_admin_approve_by_name_is_unknown_tool(admin_mcp_env):
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.approve", {"id": "whatever"})
    assert result.is_error


# -- Approving via /ui makes the change reach /mcp for a granted agent -------


async def test_approved_pending_change_becomes_callable_on_mcp(admin_mcp_env):
    """The manual-verification scenario from the plan, automated: create
    (inert) -> propose an enable on a write tool -> approve at /ui/requests
    -> the tool becomes callable on /mcp for a granted agent identity.
    """
    app, store, pending, _toolkit_proposals = admin_mcp_env["build"]()
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
        page = await http.get(f"{UI_PREFIX}/requests?tab=change")
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
    app2, _store2, _pending2, _toolkit_proposals = admin_mcp_env["build"]()
    async with connected(app2, tokens["bot"], "/mcp") as client:
        result = await client.call_tool("demo.approved_write", {})
    assert not result.is_error
    assert "done" in result.content[0].text


# -- Toolkit proposals (plan "Follow-up 2") -----------------------------------


async def test_toolkit_list_is_read_only_and_reflects_live_tier1(admin_mcp_env):
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.toolkit_list", {})
    payload = json.loads(result.content[0].text)
    names = {t["name"] for t in payload["toolkits"]}
    assert names == {"demo"}
    # `demo` is a `local` toolkit with no base_url/docker_host/ws_url and no
    # credential -- both new fields must report that plainly (empty
    # string, None) rather than being absent or raising.
    demo = next(t for t in payload["toolkits"] if t["name"] == "demo")
    assert demo["target"] == ""
    assert demo["credential"] is None


async def test_toolkit_list_reports_run_as(admin_mcp_env):
    """The bug this guards against: `run_as` existed on `Toolkit` (0.28.0)

    and was writable via a toolkit_update proposal (0.29.0), but
    `toolkit_list`'s reporting dict was never taught the field -- so an
    approved proposal correctly wrote toolkits.yaml and correctly reloaded
    the running process (both already covered elsewhere), and `toolkit_list`
    *still* reported nothing, because it simply never looked. No restart
    fixes that; the dict was missing the key regardless. Exactly the same
    shape of bug `target`/`credential` needed fixing once already, per the
    docstring on `toolkit_list` itself.
    """
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.toolkit_list", {})
    payload = json.loads(result.content[0].text)
    demo = next(t for t in payload["toolkits"] if t["name"] == "demo")
    # Present and explicitly null, not merely absent -- the same
    # "reported plainly, never omitted" rule target/credential follow.
    assert "run_as" in demo
    assert demo["run_as"] is None


async def test_toolkit_list_reports_a_set_run_as(tmp_path):
    """A `file` toolkit that already declares `run_as` at load time (the

    ordinary deploy-time path, no proposal involved) must report the
    value, not just the null default covered by the test above.
    """
    from gatekeeper.audit import AuditLog
    from gatekeeper.catalog import load_catalog
    from gatekeeper.identity import generate_token, hash_token, load_identities
    from gatekeeper.pending import PendingStore
    from gatekeeper.service import Service
    from gatekeeper.store import ConfigStore
    from gatekeeper.tier1 import load_tier1
    from gatekeeper.toolkit_proposals import ToolkitProposalStore

    toolkits_path = tmp_path / "toolkits.yaml"
    toolkits_path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "agentcfg": {
                        "executor": "file",
                        "binaries": [],
                        "path_roots": [str(tmp_path)],
                        "protected_resources": [],
                        "max_timeout_seconds": 10,
                        "max_output_bytes": 4096,
                        "run_as": "3001:3001",
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(toolkits_path))
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "hermes", "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [], "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit)
    identities = load_identities(str(identities_path))
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit-proposals.yaml"), audit=audit, service=service,
        toolkits_path=str(toolkits_path), tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    from gatekeeper.admin_service import AdminService

    admin = AdminService(store=store, pending=pending, toolkit_proposals=toolkit_proposals)
    payload = admin.toolkit_list("hermes", {})
    agentcfg = next(t for t in payload["toolkits"] if t["name"] == "agentcfg")
    assert agentcfg["run_as"] == "3001:3001"


async def test_toolkit_list_reports_run_as_immediately_after_deploy_no_restart(tmp_path):
    """The exact reported scenario end to end: propose a `run_as` update,

    deploy it, and read it back from `toolkit_list` on the *same*
    `AdminService`/`Service` instance -- no restart, no new process. This
    is what "reload_config already reassigns self.tier1 in-process"
    actually buys, and what the missing dict key was silently throwing
    away: the value was live the whole time, `toolkit_list` just never
    said so.
    """
    from gatekeeper.admin_service import AdminService
    from gatekeeper.audit import AuditLog
    from gatekeeper.catalog import load_catalog
    from gatekeeper.identity import generate_token, hash_token, load_identities
    from gatekeeper.pending import PendingStore
    from gatekeeper.service import Service
    from gatekeeper.store import ConfigStore
    from gatekeeper.tier1 import load_tier1
    from gatekeeper.toolkit_proposals import ToolkitProposalStore

    toolkits_path = tmp_path / "toolkits.yaml"
    toolkits_path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "agentcfg": {
                        "executor": "file",
                        "binaries": [],
                        "path_roots": [str(tmp_path)],
                        "protected_resources": [],
                        "max_timeout_seconds": 10,
                        "max_output_bytes": 4096,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(toolkits_path))
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "hermes", "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [], "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit)
    identities = load_identities(str(identities_path))
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit-proposals.yaml"), audit=audit, service=service,
        toolkits_path=str(toolkits_path), tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    admin = AdminService(store=store, pending=pending, toolkit_proposals=toolkit_proposals)

    before = admin.toolkit_list("hermes", {})
    agentcfg = next(t for t in before["toolkits"] if t["name"] == "agentcfg")
    assert agentcfg["run_as"] is None

    item = toolkit_proposals.propose(
        name="agentcfg", spec={"run_as": "root"}, actor="hermes", kind="update"
    )
    toolkit_proposals.deploy(item.id, decided_by="root")

    after = admin.toolkit_list("hermes", {})
    agentcfg = next(t for t in after["toolkits"] if t["name"] == "agentcfg")
    assert agentcfg["run_as"] == "root"


async def test_toolkit_list_reports_target_and_credential_name(tmp_path):
    """The gap that caused a real misdiagnosis: this action used to omit

    a toolkit's own connection target and credential reference entirely,
    which read as "not configured" when it was actually just unreported.
    `target` must match `_target()` -- the same resolution the console's
    Tools page and access map already use -- and `credential` must be the
    *name* only, never a value (the credential store stays write-only,
    FR-10.2, regardless of what this read-only action exposes).
    """
    from gatekeeper.audit import AuditLog
    from gatekeeper.pending import PendingStore
    from gatekeeper.service import Service
    from gatekeeper.store import ConfigStore
    from gatekeeper.tier1 import load_tier1
    from gatekeeper.toolkit_proposals import ToolkitProposalStore

    toolkits_path = tmp_path / "toolkits.yaml"
    toolkits_path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "bazarr": {
                        "executor": "http",
                        "base_url": "http://10.10.200.90:30046",
                        "allowed_methods": ["GET"],
                        "allowed_path_prefixes": ["/api/"],
                        "allowed_cidrs": ["10.10.200.0/24"],
                        "credential": "bazarr-api-key",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 65536,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(toolkits_path))
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "hermes", "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [], "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    audit = AuditLog(str(tmp_path / "logs"))
    from gatekeeper.catalog import load_catalog
    from gatekeeper.identity import load_identities

    service = Service(tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit)
    identities = load_identities(str(identities_path))
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit-proposals.yaml"), audit=audit, service=service,
        toolkits_path=str(toolkits_path), tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    from gatekeeper.admin_service import AdminService

    admin = AdminService(store=store, pending=pending, toolkit_proposals=toolkit_proposals)
    payload = admin.toolkit_list("hermes", {})
    bazarr = next(t for t in payload["toolkits"] if t["name"] == "bazarr")
    assert bazarr["target"] == "http://10.10.200.90:30046"
    # The name a call would look the credential up by -- never a value,
    # since nothing on this path ever touches the credential store itself.
    assert bazarr["credential"] == "bazarr-api-key"


async def test_toolkit_propose_always_lands_in_proposal_store(admin_mcp_env):
    """Unlike every other action `AdminService` exposes, there is no
    low-risk variant of this at all -- not even for a toolkit that looks
    entirely read-only. It must always land in `ToolkitProposalStore`,
    never `PendingStore`.
    """
    app, _store, pending, toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.toolkit_propose",
            {"name": "zfs", "spec": {"executor": "local", "binaries": [_python()]}},
        )
    payload = json.loads(result.content[0].text)
    assert payload["pending"] is True
    assert payload["applied"] is False

    proposed = toolkit_proposals.list(status="pending")
    assert len(proposed) == 1
    assert proposed[0].name == "zfs"
    assert proposed[0].actor == "hermes"
    # Never routed through the ordinary pending queue -- a toolkit proposal
    # is a categorically different severity of change (Tier 1, not Tier 2).
    assert pending.list() == []


async def test_toolkit_update_accepts_run_as(admin_mcp_env):
    """`run_as` has to reach the queue through the real MCP surface, not

    only through the store: 0.28.0 refused it at both layers, so opening
    only `UPDATE_WRITABLE_FIELDS` would leave the tool schema silently
    rejecting it one level up.
    """
    app, _store, pending, toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.toolkit_update", {"name": "demo", "updates": {"run_as": "3001:3001"}}
        )
    payload = json.loads(result.content[0].text)
    assert payload["pending"] is True
    assert payload["applied"] is False

    proposed = toolkit_proposals.list(status="pending")
    assert len(proposed) == 1
    assert proposed[0].kind == "update"
    assert proposed[0].spec == {"run_as": "3001:3001"}
    assert pending.list() == []


async def test_toolkit_update_schema_exposes_run_as_and_nothing_else_new(admin_mcp_env):
    """The schema is the contract an agent reads. It must list `run_as`

    and must NOT have grown path_roots/protected_resources/limits along
    with it -- those stay redeploy-only, which is the line this change
    deliberately does not cross.
    """
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    updates = tools["admin.toolkit_update"].input_schema["properties"]["updates"]
    assert set(updates["properties"]) == {
        "executor", "binaries", "denied_args", "run_as",
    }
    assert updates["additionalProperties"] is False
    # null is allowed, so a run_as can be handed back to the container user
    # without a redeploy -- the inverse of setting it.
    assert "null" in updates["properties"]["run_as"]["type"]


async def test_toolkit_update_rejects_a_malformed_run_as(admin_mcp_env):
    """A typo comes back as an error on the call, not as a queued proposal

    that only fails when a human tries to deploy it.
    """
    app, _store, _pending, toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.toolkit_update", {"name": "demo", "updates": {"run_as": "3001"}}
        )
    assert result.is_error
    assert toolkit_proposals.list() == []


async def test_toolkit_delete_always_pending(admin_mcp_env):
    """Like `admin.toolkit_propose`/`admin.toolkit_update`, this always
    lands in `ToolkitProposalStore` -- never `PendingStore` -- and never
    applies on its own, even though "demo" is not itself referenced by any
    live tool in this fixture's env.
    """
    app, _store, pending, toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.toolkit_delete", {"name": "demo"})
    payload = json.loads(result.content[0].text)
    assert payload["pending"] is True
    assert payload["applied"] is False

    proposed = toolkit_proposals.list(status="pending")
    assert len(proposed) == 1
    assert proposed[0].name == "demo"
    assert proposed[0].kind == "delete"
    assert proposed[0].actor == "hermes"
    assert pending.list() == []


async def test_toolkit_deploy_and_reject_absent_from_admin_mcp_tool_list(admin_mcp_env):
    """Same structural self-approval prevention as `pending.py`'s
    approve/reject, extended to this surface: `ToolkitProposalStore.deploy`/
    `.reject` are only reachable from `/ui/toolkits`, never `/admin/mcp`.
    """
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert "admin.toolkit_deploy" not in names
    assert "admin.toolkit_reject" not in names


async def test_calling_admin_toolkit_deploy_by_name_is_unknown_tool(admin_mcp_env):
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.toolkit_deploy", {"id": "whatever"})
    assert result.is_error


# -- admin.cred_propose (metadata-only credential proposals) ---------------


async def test_cred_propose_always_pending(admin_mcp_env, credential_store):
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"](
        credentials=credential_store
    )
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.cred_propose",
            {"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"},
        )
    assert not result.is_error
    payload = json.loads(result.content[0].text)
    assert payload["applied"] is False
    assert payload["pending"] is True
    items = pending.list(status="pending")
    assert len(items) == 1
    assert items[0].action == "cred_propose"
    assert items[0].payload == {
        "name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key",
    }
    # Never written to disk: no credential exists until a human fills a value.
    assert credential_store.names() == []


async def test_cred_propose_rejects_unknown_kind(admin_mcp_env, credential_store):
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"](
        credentials=credential_store
    )
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.cred_propose", {"name": "sonarr", "kind": "made_up_kind"}
        )
    assert result.is_error
    assert pending.list() == []


async def test_cred_propose_rejects_missing_header_for_api_key_header(
    admin_mcp_env, credential_store
):
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"](
        credentials=credential_store
    )
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.cred_propose", {"name": "sonarr", "kind": "api_key_header"}
        )
    assert result.is_error
    assert pending.list() == []


async def test_cred_propose_rejects_duplicate_name(admin_mcp_env, credential_store):
    credential_store.create(
        "sonarr", kind="api_key_header", header="X-Api-Key",
        value="already-here", actor="admin", rev="",
    )
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"](
        credentials=credential_store
    )
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.cred_propose",
            {"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"},
        )
    assert result.is_error
    assert pending.list() == []


async def test_cred_propose_without_a_credential_store_is_a_clean_error(admin_mcp_env):
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"]()  # no credentials=
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.cred_propose", {"name": "sonarr", "kind": "api_key_header", "header": "X"}
        )
    assert result.is_error
    assert pending.list() == []


async def test_cred_propose_schema_has_no_value_property(admin_mcp_env, credential_store):
    """The schema documents the intent (no `value` property); the actual

    enforcement -- since the MCP SDK does not itself reject an unlisted
    argument, `additionalProperties: False` is advisory to a well-behaved
    client, not a transport gate -- is `cred_propose`'s own explicit check,
    covered by the test right below.
    """
    app, _store, _pending, _toolkit_proposals = admin_mcp_env["build"](
        credentials=credential_store
    )
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    schema = tools["admin.cred_propose"].input_schema
    assert "value" not in schema["properties"]
    assert schema["additionalProperties"] is False


async def test_cred_propose_rejects_an_unexpected_value_argument(
    admin_mcp_env, credential_store
):
    """The real enforcement point (see the test above): `cred_propose`

    explicitly refuses a `value` argument rather than silently dropping
    it -- a caller who sent one should learn immediately that it went
    nowhere, not assume gatekeeper stored it.
    """
    app, _store, pending, _toolkit_proposals = admin_mcp_env["build"](
        credentials=credential_store
    )
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool(
            "admin.cred_propose",
            {
                "name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key",
                "value": "sneaked-in-secret",
            },
        )
    assert result.is_error
    assert "sneaked-in-secret" not in result.content[0].text
    assert pending.list() == []


# -- admin.release_notes ---------------------------------------------------


async def test_release_notes_are_reachable_over_admin_mcp(admin_mcp_env):
    """The agent that manages this deployment must be able to read what a

    version changed. Until this tool existed the notes were browser-only.
    """
    app, _store, _pending, _proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.release_notes", {})
    payload = json.loads(result.content[0].text)
    assert payload["current_version"] == gatekeeper.__version__
    assert payload["releases"][0]["version"] == gatekeeper.__version__
    # The default is a slice, not the whole 150 KB file -- and it says so.
    assert payload["count"] == 10
    assert payload["truncated"] is True


async def test_release_notes_full_returns_the_procedure_too(admin_mcp_env):
    """`full` exists for the agent asked to *make* a release: the rule and

    the procedure are preamble, part of no version's notes.
    """
    app, _store, _pending, _proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        result = await client.call_tool("admin.release_notes", {"full": True})
    payload = json.loads(result.content[0].text)
    assert "## Procedure" in payload["markdown"]
    assert "The rule: every change is a release" in payload["markdown"]


async def test_release_notes_search_and_version_select(admin_mcp_env):
    app, _store, _pending, _proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        found = await client.call_tool(
            "admin.release_notes", {"search": "credential", "limit": 3}
        )
        one = await client.call_tool(
            "admin.release_notes", {"version": gatekeeper.__version__}
        )
        missing = await client.call_tool("admin.release_notes", {"version": "99.99.99"})
    hits = json.loads(found.content[0].text)
    assert hits["count"] == 3 and hits["total"] > 3
    assert [r["version"] for r in json.loads(one.content[0].text)["releases"]] == [
        gatekeeper.__version__
    ]
    assert missing.is_error
    assert "99.99.99" in missing.content[0].text


async def test_release_notes_is_read_only_and_touches_no_store(admin_mcp_env, tmp_path):
    """No pending item, no file write -- the one admin action with no store

    behind it at all.
    """
    app, _store, pending, _proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    before = admin_mcp_env["tools_path"].read_text(encoding="utf-8")
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        await client.call_tool("admin.release_notes", {"limit": 1})
    assert pending.list() == []
    assert admin_mcp_env["tools_path"].read_text(encoding="utf-8") == before


async def test_admin_server_reports_the_real_version(admin_mcp_env):
    """It answered a hardcoded "0.1.0" for every release since this mount

    existed -- a wrong answer that looks authoritative, which is worse than
    none. `/mcp` has always reported `__version__`; same process, same
    build.
    """
    app, _store, _pending, _proposals = admin_mcp_env["build"]()
    tokens = admin_mcp_env["tokens"]
    async with connected(app, tokens["hermes"], "/admin/mcp") as client:
        info = client.server_info
    assert info.version == gatekeeper.__version__
    assert info.name == "gatekeeper-admin"


def _python() -> str:
    import os
    import sys

    # Must match `tests/conftest.py`'s `PYTHON` constant exactly -- on Linux
    # `sys.executable` is often a symlink (e.g. .../bin/python -> .../bin/
    # python3.12) that resolves to a different literal path than the one
    # the `tier1` fixture's binary allowlist contains, so the realpath has
    # to be taken here too or the allowlist check rejects it.
    return os.path.realpath(sys.executable)
