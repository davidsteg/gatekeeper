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


# -- The second half: the session is told to re-fetch -----------------------
#
# Everything below needs a *real* socket. `httpx2.ASGITransport` collects the
# whole response body before it hands one back, so a long-lived stream --
# which is what both delivery routes are -- never yields its first frame
# through it. `served` therefore runs the same app under uvicorn on an
# ephemeral loopback port, exactly as `test_execute_http.py` starts a real
# loopback HTTP server rather than mocking a transport.


@contextlib.asynccontextmanager
async def served(app):
    """The app on a real loopback port; yields its base URL."""
    import asyncio
    import socket

    import uvicorn

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        while not server.started:
            await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(task, timeout=10)
        sock.close()


def _client(base: str, token: str) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=30.0
    )


async def test_initialize_advertises_tools_list_changed(live):
    """The reported root cause, at the wire level.

    A handshake-era client learns whether re-fetching is ever worth it from
    exactly one field of the `initialize` reply. `false` told every such
    client that the list it just cached can be kept for the session's
    lifetime -- which is why new tools stayed invisible until a reconnect.
    """
    app, _store, _service, _identities, tokens = live
    async with served(app) as base, _client(base, tokens["full"]) as http:
        response = await http.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pinning-test", "version": "1"},
                },
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200
        payload = _first_sse_message(response.text)
        capabilities = payload["result"]["capabilities"]
        assert capabilities["tools"]["listChanged"] is True, capabilities


async def test_discover_advertises_tools_list_changed(live):
    """The same promise on the 2026-07-28 wire, where it is not a flag but a

    fact: the SDK reports `listChanged` there if and only if the server
    serves `subscriptions/listen`, so this asserts the delivery route
    exists rather than that a boolean was set.
    """
    app, _store, _service, _identities, tokens = live
    async with served(app) as base, _client(base, tokens["full"]) as http:
        async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as client:
            assert client.protocol_version == "2026-07-28"
            assert client.server_capabilities is not None
            assert client.server_capabilities.tools is not None
            assert client.server_capabilities.tools.list_changed is True


async def test_a_tool_change_notifies_a_listening_session(live, catalog):
    """The bug, end to end: an admin write reaches a session nobody touched."""
    import anyio
    from mcp.shared.subscriptions import ToolsListChanged

    app, store, service, identity_store, tokens = live
    async with served(app) as base, _client(base, tokens["full"]) as http:
        async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as client:
            async with client.listen(tools_list_changed=True) as subscription:
                assert subscription.honored.tools_list_changed is True

                _create_and_grant(store, service, identity_store, catalog, "demo.announced")

                with anyio.fail_after(10):
                    async for event in subscription:
                        assert isinstance(event, ToolsListChanged)
                        break

            # The point of the notification: the re-fetch it prompts is not
            # empty. A client that acted on it sees the new tool.
            assert "demo.announced" in {tool.name for tool in (await client.list_tools()).tools}


async def test_every_listening_session_is_notified_not_just_one(live, catalog):
    """FR-1.4 filters the tool *list* per identity; the invalidation is not

    filtered at all. Two sessions are connected, one admin write happens,
    and both have to hear about it -- a fan-out that reaches only the
    session that happened to ask last would leave the others exactly as
    stale as before.
    """
    import anyio
    from mcp.shared.subscriptions import ToolsListChanged

    app, store, service, identity_store, tokens = live
    async with served(app) as base:
        async with _client(base, tokens["full"]) as one, _client(base, tokens["full"]) as two:
            async with Client(streamable_http_client(f"{base}/mcp", http_client=one)) as first:
                async with Client(streamable_http_client(f"{base}/mcp", http_client=two)) as second:
                    async with first.listen(tools_list_changed=True) as first_sub:
                        async with second.listen(tools_list_changed=True) as second_sub:
                            _create_and_grant(
                                store, service, identity_store, catalog, "demo.fanout"
                            )
                            for subscription in (first_sub, second_sub):
                                with anyio.fail_after(10):
                                    async for event in subscription:
                                        assert isinstance(event, ToolsListChanged)
                                        break


async def test_a_handshake_era_session_is_notified_on_its_standalone_stream(live, catalog):
    """The other era, whose delivery is why `/mcp` retains sessions.

    A 2025-era client has no `subscriptions/listen`: it opens a standalone
    SSE stream with `GET /mcp` and the server pushes onto that. This drives
    the handshake by hand rather than with the SDK client, because the
    installed client only speaks the newer wire -- and it is precisely the
    older one that has to keep working.
    """
    import anyio

    app, store, service, identity_store, tokens = live
    async with served(app) as base, _client(base, tokens["full"]) as http:
        session_id = await _handshake(http)
        async with http.stream(
            "GET",
            "/mcp",
            headers={"Accept": "text/event-stream", "Mcp-Session-Id": session_id},
        ) as stream:
            assert stream.status_code == 200
            lines = stream.aiter_lines()

            _create_and_grant(store, service, identity_store, catalog, "demo.standalone")

            with anyio.fail_after(10):
                async for line in lines:
                    if line.startswith("data: "):
                        assert "notifications/tools/list_changed" in line, line
                        break


def _first_sse_message(body: str) -> dict:
    """The single JSON-RPC message out of a one-shot `text/event-stream` body."""
    import json

    for line in body.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    raise AssertionError(f"no SSE data frame in {body!r}")


async def _handshake(http: httpx2.AsyncClient) -> str:
    """A 2025-era `initialize` + `notifications/initialized`; returns the session id."""
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    response = await http.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "handshake-era-test", "version": "1"},
            },
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    session_id = response.headers["mcp-session-id"]
    acknowledged = await http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={**headers, "Mcp-Session-Id": session_id},
    )
    assert acknowledged.status_code == 202, acknowledged.text
    return session_id
