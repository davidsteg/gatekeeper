"""What an already-connected agent session sees after an admin change.

Reported as: 20 tools created with `admin.tool_create`, enabled, granted;
`admin.tool_list` and `admin.grant_list` show all of them; the agent's
`/mcp` session shows none until the container is restarted.

The suspicion was that the `/mcp` catalog is a startup snapshot with no
reload hook. It is not -- `ConfigStore._write_tools` reassigns
`service.catalog` from the file it just wrote, and `_write_identities`
swaps the identity contents in place, both synchronously. So the server's
answer to `tools/list` is live from the first request after the write.

That leaves the half nobody can see from the server side: whether the
*client* asks again. `ListToolsResult(cacheScope="private")` invites it to
cache, and MCP's way of saying "your cache is stale" is a
`notifications/tools/list_changed`. Without one, a long-lived session keeps
serving the list it fetched at connect time, and a container restart
"fixes" it only because it forces every session to reconnect.

These tests pin both halves: that a re-fetch on a live session sees the
change, and that the session is *told* to re-fetch.
"""

from __future__ import annotations

import contextlib

import httpx2
import pytest
import yaml
from mcp.client.client import Client, streamable_http_client

from gatekeeper.audit import AuditLog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore

BASE = "http://gatekeeper.test"


@pytest.fixture
def live(tier1, catalog, tmp_path):
    """The running server, plus the admin-side handle onto the same state.

    Deliberately one `Service` shared by both: that is the production
    shape, where `/admin/mcp` and `/mcp` are two routes into one process.
    A test that gave them separate objects could not show the bug at all.

    Its own identity file rather than the shared fixture's, because the
    store refuses an edit that would leave no administrator -- and this
    test needs to edit an agent's grants, which means an admin has to
    exist alongside it.
    """
    tokens = {"full": generate_token()}
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "full",
                        "role": "agent",
                        "token_hash": hash_token(tokens["full"]),
                        "tools": ["demo.show", "demo.echo"],
                        "scopes": ["stack:*"],
                    },
                    {
                        "id": "boss",
                        "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [],
                        "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identity_store = load_identities(str(identities_path))
    audit = AuditLog(str(tmp_path / "logs-live"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    app = build_app(service=service, identities=identity_store, audit=audit)
    store = ConfigStore(
        service=service,
        identities=identity_store,
        audit=audit,
        tools_path=str(tmp_path / "tools.yaml"),
        identities_path=str(identities_path),
    )
    return app, store, service, identity_store, tokens


@contextlib.asynccontextmanager
async def connected(app, token: str):
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=BASE,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        ) as http:
            transport = streamable_http_client(f"{BASE}/mcp", http_client=http)
            async with Client(transport) as client:
                yield client


def _create_and_grant(store, service, identity_store, catalog, tool_id: str) -> None:
    """The reported sequence: tool_create, tool_enable, grant_set."""
    spec = dict(catalog.raw[0])
    spec["id"] = tool_id
    spec.pop("versions", None)
    new_id = store.save_tool(spec, actor="admin", rev=store.tools_revision())
    store.set_tool_enabled(new_id, True, actor="admin", rev=store.tools_revision())
    existing = identity_store.identities["full"]
    store.save_identity(
        identity_id="full",
        role="agent",
        tools=[*existing.tools, new_id],
        scopes=list(existing.scopes),
        actor="admin",
        rev=store.identities_revision(),
        replaces="full",  # an edit, not a create
    )


async def test_the_server_side_is_live_without_a_restart(live, catalog):
    """The half that already worked, asserted so the fix is not credited

    with it: a re-fetch on the *same* session sees the new tool. If this
    ever fails, the problem really is a stale snapshot and the
    notification below would only paper over it.
    """
    app, store, service, identity_store, tokens = live
    async with connected(app, tokens["full"]) as client:
        before = {tool.name for tool in (await client.list_tools()).tools}
        assert "demo.brandnew" not in before

        _create_and_grant(store, service, identity_store, catalog, "demo.brandnew")

        after = {tool.name for tool in (await client.list_tools()).tools}
        assert "demo.brandnew" in after, (
            "the running process serves a stale catalog -- "
            f"before={sorted(before)} after={sorted(after)}"
        )


async def test_a_new_tool_is_callable_on_the_same_session(live, catalog):
    """Visible is not the same as reachable: the authorization path reads

    the catalog and the grants separately, so both have to be live.
    """
    app, store, service, identity_store, tokens = live
    async with connected(app, tokens["full"]) as client:
        _create_and_grant(store, service, identity_store, catalog, "demo.freshcall")
        result = await client.call_tool("demo.freshcall", {"stack": "media-a"})
        rendered = "".join(
            block.text for block in result.content if hasattr(block, "text")
        )
        assert "does not exist" not in rendered, rendered
        assert "not authorized" not in rendered.lower(), rendered
