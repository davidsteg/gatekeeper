"""Drive an MCP echo server with the real Python SDK client.

    python client_test.py http://127.0.0.1:PORT

Run against `mcp_echo` (rust/examples/mcp_echo.rs) by `rust/tests/mcp_interop.rs`,
and usable against `ref_server.py` to check the script itself. Both eras: a
handshake-era session (`mode="legacy"`, notified on its standalone GET stream)
and a 2026-07-28 client (`mode="auto"`, notified on a `subscriptions/listen`
stream). Prints one `ok ...` line per check; any failure raises.
"""

from __future__ import annotations

import asyncio
import sys
import warnings

import anyio
import httpx2
import mcp.types as types
from mcp.client.client import Client, streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.shared.subscriptions import ToolsListChanged

BASE = sys.argv[1].rstrip("/")


def text_of(result: types.CallToolResult) -> str:
    return "".join(block.text for block in result.content if isinstance(block, types.TextContent))


async def change(http: httpx2.AsyncClient) -> None:
    response = await http.post(f"{BASE}/_change")
    assert response.status_code == 200, response.status_code


async def common_checks(client: Client, label: str) -> None:
    names = [tool.name for tool in (await client.list_tools()).tools]
    assert names[:3] == ["demo.echo", "demo.fail", "demo.slow"], names
    echo = (await client.list_tools()).tools[0]
    assert echo.title == "Echo" and echo.annotations is not None and echo.annotations.read_only_hint is True
    result = await client.call_tool("demo.echo", {"text": "hi"})
    assert text_of(result) == "hi" and not result.is_error, result
    unknown = await client.call_tool("nope", {})
    assert unknown.is_error and text_of(unknown) == "No tool 'nope'.", unknown
    try:
        await client.call_tool("demo.fail", {})
    except MCPError as exc:
        print(f"ok {label}: failing tool -> MCPError code={exc.error.code} {exc.error.message!r}")
    else:
        raise AssertionError("demo.fail did not raise")
    print(f"ok {label}: list_tools + call_tool")


async def legacy(http: httpx2.AsyncClient) -> None:
    changed = asyncio.Event()

    async def on_message(message: object) -> None:
        if isinstance(message, types.ToolListChangedNotification):
            changed.set()

    async with Client(
        streamable_http_client(f"{BASE}/mcp", http_client=http), mode="legacy", message_handler=on_message
    ) as client:
        assert client.protocol_version == "2025-11-25", client.protocol_version
        assert client.server_capabilities is not None and client.server_capabilities.tools is not None
        assert client.server_capabilities.tools.list_changed is True
        assert client.server_info is not None and client.server_info.name == "echo"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # ping is deprecated at 2026-07-28, fine at this era
            await client.send_ping()
        await common_checks(client, "legacy")
        # The standalone GET stream opens in the background after
        # `notifications/initialized`; keep changing until it delivers.
        with anyio.fail_after(10):
            while not changed.is_set():
                await change(http)
                with anyio.move_on_after(0.5):
                    await changed.wait()
        print("ok legacy: tools/list_changed on the standalone stream")
        tracked = (await http.get(f"{BASE}/_tracked")).json()["tracked"]
        assert tracked >= 1, tracked
        print("ok legacy: session tracked")


async def modern(http: httpx2.AsyncClient) -> None:
    async with Client(streamable_http_client(f"{BASE}/mcp", http_client=http)) as client:
        assert client.protocol_version == "2026-07-28", client.protocol_version
        assert client.server_capabilities is not None and client.server_capabilities.tools is not None
        assert client.server_capabilities.tools.list_changed is True
        assert client.server_info is not None and client.server_info.name == "echo"
        await common_checks(client, "2026-07-28")
        before = {tool.name for tool in (await client.list_tools(cache_mode="bypass")).tools}
        async with client.listen(tools_list_changed=True) as subscription:
            assert subscription.honored.tools_list_changed is True
            await change(http)
            with anyio.fail_after(10):
                async for event in subscription:
                    assert isinstance(event, ToolsListChanged), event
                    break
        after = {tool.name for tool in (await client.list_tools(cache_mode="bypass")).tools}
        assert before ^ after == {"demo.extra"}, (before, after)
        print("ok 2026-07-28: tools/list_changed on the listen stream, refetch sees the change")


async def admin(http: httpx2.AsyncClient) -> None:
    for mode in ("legacy", "auto"):
        async with Client(streamable_http_client(f"{BASE}/admin/mcp", http_client=http), mode=mode) as client:
            assert client.server_info is not None and client.server_info.name == "echo-admin"
            assert client.server_info.version == "9.9.9"
            assert client.server_capabilities is not None and client.server_capabilities.tools is not None
            assert client.server_capabilities.tools.list_changed is False
            names = [tool.name for tool in (await client.list_tools()).tools]
            assert names == ["demo.echo"], names
            result = await client.call_tool("demo.echo", {"text": "adm"})
            assert text_of(result) == "adm"
            print(f"ok admin ({mode}, {client.protocol_version}): stateless mount")


async def main() -> None:
    async with httpx2.AsyncClient(timeout=30.0) as http:
        await legacy(http)
        await modern(http)
        await admin(http)
    print("ALL OK")


if __name__ == "__main__":
    asyncio.run(main())
