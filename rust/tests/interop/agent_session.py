"""One agent session against a real `gatekeeper serve`, with the Python SDK.

    python agent_session.py http://127.0.0.1:PORT TOKEN

Run by `rust/tests/cli.rs` against the binary started from a temp config
dir with one `local` echo tool (`demo.echo`) granted to the token's
identity. Both eras: a handshake-era session and a 2026-07-28 client.
Prints one `ok ...` line per check; any failure raises.
"""

from __future__ import annotations

import asyncio
import sys

import httpx2
import mcp.types as types
from mcp.client.client import Client, streamable_http_client

BASE = sys.argv[1].rstrip("/")
TOKEN = sys.argv[2]


def text_of(result: types.CallToolResult) -> str:
    return "".join(block.text for block in result.content if isinstance(block, types.TextContent))


async def session(http: httpx2.AsyncClient, mode: str) -> None:
    async with Client(streamable_http_client(f"{BASE}/mcp", http_client=http), mode=mode) as client:
        assert client.server_info is not None and client.server_info.name == "gatekeeper", client.server_info
        tools = (await client.list_tools()).tools
        assert [tool.name for tool in tools] == ["demo.echo"], tools
        assert tools[0].annotations is not None and tools[0].annotations.read_only_hint is True
        result = await client.call_tool("demo.echo", {"text": "hello from python"})
        assert not result.is_error, result
        # `_render`: the exit code heads the output.
        assert text_of(result) == "exit=0\nhello from python", text_of(result)
        print(f"ok {mode} ({client.protocol_version}): tools/list + tools/call demo.echo")


async def main() -> None:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with httpx2.AsyncClient(timeout=30.0, headers=headers) as http:
        await session(http, "legacy")
        await session(http, "auto")
    print("ALL OK")


if __name__ == "__main__":
    asyncio.run(main())
