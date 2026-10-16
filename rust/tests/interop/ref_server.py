"""Reference server: the Python SDK configured exactly the way gatekeeper
configures it, around a tiny echo catalog.

`mcp_echo` (rust/examples/mcp_echo.rs) serves the same catalog from the
Rust `gatekeeper::mcp` module. `probe.py` sends both the same raw HTTP
requests; `mcp_interop.rs` diffs the two transcripts. Run:

    python ref_server.py            # prints "PORT <n>" once listening

Routes:
  /mcp        stateful (sessions retained, idle timeout), like server.py
  /admin/mcp  stateless, like the admin mount
  POST /_change  -> notifier.tool_catalog_changed()
  GET  /_tracked -> {"tracked": notifier.tracked_sessions}
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import sys
from typing import Any

import mcp.types as types
import uvicorn
from mcp.server.lowlevel import Server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from gatekeeper.notifications import CatalogNotifier
from gatekeeper.server import SESSION_IDLE_TIMEOUT_SECONDS, SessionReaper, _AnnouncingServer

ECHO_SCHEMA = {
    "type": "object",
    "properties": {"text": {"type": "string"}},
    "required": ["text"],
    "additionalProperties": False,
}

state = {"extra_tool": False}


def tools() -> list[types.Tool]:
    out = [
        types.Tool(
            name="demo.echo",
            title="Echo",
            description="Echo the text back.",
            inputSchema=ECHO_SCHEMA,
            annotations=types.ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False),
        ),
        types.Tool(
            name="demo.fail",
            description="Raises inside the handler.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="demo.slow",
            description="Sleeps.",
            inputSchema={"type": "object", "properties": {"seconds": {"type": "number"}}},
        ),
    ]
    if state["extra_tool"]:
        out.append(types.Tool(name="demo.extra", inputSchema={"type": "object"}))
    return out


async def call(name: str, args: dict[str, Any]) -> types.CallToolResult:
    if name == "demo.echo":
        return types.CallToolResult(content=[types.TextContent(type="text", text=str(args.get("text")))], isError=False)
    if name == "demo.fail":
        raise RuntimeError("boom from handler")
    if name == "demo.slow":
        await asyncio.sleep(float(args.get("seconds", 1)))
        return types.CallToolResult(content=[types.TextContent(type="text", text="slept")], isError=False)
    if name == "demo.extra":
        return types.CallToolResult(content=[types.TextContent(type="text", text="extra")], isError=False)
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"No tool {name!r}.")], isError=True)


def build_agent(notifier: CatalogNotifier) -> Server[None]:
    async def on_list_tools(ctx: Any, _params: Any) -> types.ListToolsResult:
        notifier.track(ctx)
        return types.ListToolsResult(tools=tools(), cacheScope="private")

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        return await call(params.name, params.arguments or {})

    async def on_initialized(ctx: Any, _params: Any) -> None:
        notifier.track(ctx)

    server = _AnnouncingServer(
        "echo",
        version="9.9.9",
        instructions="Echo server for interop tests.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
        on_subscriptions_listen=notifier.listen_handler,
        notification_options=notifier.notification_options,
    )
    server.add_notification_handler("notifications/initialized", types.NotificationParams, on_initialized)
    return server


def build_admin() -> Server[None]:
    async def on_list_tools(ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tools()[:1], cacheScope="private")

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        return await call(params.name, params.arguments or {})

    return Server(
        "echo-admin",
        version="9.9.9",
        instructions="Admin echo.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def build_app() -> Starlette:
    notifier = CatalogNotifier()
    agent = build_agent(notifier)

    async def change(_request: Request) -> JSONResponse:
        state["extra_tool"] = not state["extra_tool"]
        notifier.tool_catalog_changed()
        return JSONResponse({"ok": True})

    async def tracked(_request: Request) -> JSONResponse:
        return JSONResponse({"tracked": notifier.tracked_sessions})

    routes = [Route("/_change", change, methods=["POST"]), Route("/_tracked", tracked, methods=["GET"])]
    primary = agent.streamable_http_app(
        streamable_http_path="/mcp", host="0.0.0.0", stateless_http=False, custom_starlette_routes=routes
    )
    agent.session_manager.session_idle_timeout = SESSION_IDLE_TIMEOUT_SECONDS
    admin = build_admin().streamable_http_app(streamable_http_path="/admin/mcp", host="0.0.0.0", stateless_http=True)
    sub_apps = [primary, admin]

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> Any:
        notifier.bind_loop()
        async with contextlib.AsyncExitStack() as stack:
            for sub in sub_apps:
                await stack.enter_async_context(sub.router.lifespan_context(sub))
            yield

    app = Starlette(routes=list(primary.routes) + list(admin.routes), lifespan=lifespan)
    app.add_middleware(SessionReaper, notifier=notifier)
    return app


async def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(build_app(), log_level="warning"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        await asyncio.sleep(0.01)
    print(f"PORT {port}", flush=True)
    await task


if __name__ == "__main__":
    asyncio.run(main())
