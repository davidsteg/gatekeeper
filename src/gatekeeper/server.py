"""MCP protocol and HTTP layer (REQUIREMENTS.md §3).

Authentication sits in front as pure ASGI middleware -- not as
Starlette `BaseHTTPMiddleware`, because that gets in the way of the
streaming responses of the Streamable HTTP transport.
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from ._authctx import SCOPE_IDENTITY
from ._authctx import identity_from as _identity_from
from .admin_server import build_admin_mcp_server
from .admin_service import AdminService
from .audit import AuditLog
from .errors import DenialReason, Denied
from .execute import OUTCOME_OK, OUTCOME_UNKNOWN
from .identity import ADMIN_ROLE, IdentityStore
from .service import Service
from .ui import UI_COMPANION_PATHS, UI_PREFIX, build_ui_routes

logger = logging.getLogger("gatekeeper")

#: Only these paths are reachable without a token (NFR-3). They disclose
#: nothing about catalog or identities.
PUBLIC_PATHS = frozenset({"/health/live", "/health/ready", "/health/startup"})

#: The agent-facing and admin MCP mount points. Isolation between them
#: (FR-2.8/2.9) is structural: two separate `Server` instances sharing no
#: tool registry, mounted at these two fixed paths, with `AuthMiddleware`
#: role-gating each one so a token for one endpoint is simply rejected on
#: the other -- not filtered, rejected outright.
MCP_PATH = "/mcp"
ADMIN_MCP_PATH = "/admin/mcp"


class AuthMiddleware:
    """Check bearer token, otherwise 401 (FR-2.3).

    This middleware reads exclusively the `Authorization` header and
    never a cookie. That is the reason why `/mcp` is immune to CSRF:
    a browser does not attach such a header on its own, so a foreign
    site cannot produce it. The session of the operations UI (`ui.py`)
    is deliberately a separate mechanism -- if it applied here,
    any arbitrary website could execute tools on the host in the background.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        identities: IdentityStore,
        audit: AuditLog,
        ui_enabled: bool = False,
    ) -> None:
        self.app = app
        self.identities = identities
        self.audit = audit
        self.ui_enabled = ui_enabled

    def _is_ui_path(self, path: str) -> bool:
        # Exact prefix comparison: '/uixyz' must not be included.
        if path == UI_PREFIX or path.startswith(UI_PREFIX + "/"):
            return True
        # '/' and '/favicon.ico' are requested by the browser on its own.
        # Letting them through keeps the audit log free of noise that
        # would otherwise cover up every real failed attempt.
        return path in UI_COMPANION_PATHS

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        # The UI routes bring their own check (session instead of token).
        # If the UI is disabled, the token requirement still applies here.
        if self.ui_enabled and self._is_ui_path(path):
            await self.app(scope, receive, send)
            return

        token = _bearer_token(scope)
        identity = self.identities.authenticate(token) if token else None
        if identity is None:
            self.audit.auth_failure(
                reason=DenialReason.UNKNOWN_TOKEN.value,
                detail=f"{scope.get('method', '?')} {path}",
            )
            response = JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        # FR-2.8/2.9: isolation between the agent-facing and admin MCP
        # mounts is enforced here, per request, not only by which tools
        # each `Server` instance happens to expose. An `admin` token on
        # `/mcp` and any non-admin token on `/admin/mcp` are both rejected
        # outright -- the same response an unknown token gets, so neither
        # endpoint's existence nor the caller's role is disclosed by the
        # shape of the denial.
        role_mismatch = (path == ADMIN_MCP_PATH and identity.role != ADMIN_ROLE) or (
            path == MCP_PATH and identity.role == ADMIN_ROLE
        )
        if role_mismatch:
            self.audit.auth_failure(
                reason=DenialReason.UNKNOWN_TOKEN.value,
                detail=f"role {identity.role!r} on {path} ({identity.id!r})",
            )
            response = JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        scope[SCOPE_IDENTITY] = identity
        await self.app(scope, receive, send)


def _bearer_token(scope: Scope) -> str | None:
    for name, value in scope.get("headers", ()):
        if name == b"authorization":
            raw = value.decode("latin-1")
            prefix, _, token = raw.partition(" ")
            if prefix.lower() == "bearer" and token:
                return token.strip()
    return None


def build_mcp_server(service: Service) -> Server[None]:
    async def on_list_tools(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        identity = _identity_from(ctx)
        tools = [
            types.Tool(
                name=view.name,
                title=view.title,
                description=view.description,
                inputSchema=view.input_schema,
                annotations=types.ToolAnnotations(
                    readOnlyHint=view.read_only,
                    idempotentHint=view.idempotent,
                    destructiveHint=not view.read_only and not view.idempotent,
                ),
            )
            for view in service.visible_tools(identity)
        ]
        # cacheScope private: the list differs per identity and must
        # not be shared between agents.
        return types.ListToolsResult(tools=tools, cacheScope="private")

    async def on_call_tool(
        ctx: Any, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        identity = _identity_from(ctx)
        try:
            result = await service.call(identity, params.name, params.arguments or {})
        except Denied as denial:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=denial.agent_message)],
                isError=True,
            )

        return types.CallToolResult(
            content=[types.TextContent(type="text", text=_render(result))],
            isError=result.outcome != OUTCOME_OK,
        )

    return Server(
        "gatekeeper",
        version="0.1.0",
        instructions=(
            "Controlled access to host operations. Every tool performs one "
            "fixed action; there are no free-form commands. A timeout on a "
            "non-idempotent tool means 'outcome unknown' -- check the state "
            "instead of retrying."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def _render(result: Any) -> str:
    parts = []
    if result.outcome == OUTCOME_UNKNOWN:
        parts.append("OUTCOME UNKNOWN")
    if result.exit_code is not None:
        parts.append(f"exit={result.exit_code}")
    if result.truncated:
        parts.append("[output truncated]")
    header = " ".join(parts)
    body = "\n".join(filter(None, [result.stdout.rstrip(), result.stderr.rstrip()]))
    return f"{header}\n{body}".strip() if header else body or "(no output)"


def build_app(
    *,
    service: Service,
    identities: IdentityStore,
    audit: AuditLog,
    host: str = "0.0.0.0",
    ui: bool = False,
    store: Any = None,
    credentials: Any = None,
    pending: Any = None,
    toolkit_proposals: Any = None,
) -> Starlette:
    """Builds the complete ASGI application.

    `ui=False` is intentional: the UI is the only browser-facing
    surface of the server and does not silently grow on an existing
    deployment. It is enabled via `--ui` or `GATEKEEPER_UI=1`.

    `store=None` means: read only. Only a `ConfigStore` enables the
    write functions -- and even then only for `role: admin`.

    `/admin/mcp` (FR-2.8) is mounted under exactly the same condition as
    `/ui`'s write functions: a writable `ConfigStore`. `pending` (a
    `PendingStore`) and `toolkit_proposals` (a `ToolkitProposalStore`) must
    both be supplied whenever `store` is -- `__main__.py` constructs all
    three together; a caller passing `store` without either is a
    programming error, not a runtime configuration to degrade gracefully
    from.
    """
    mcp_server = build_mcp_server(service)

    async def health_live(_request: Request) -> Response:
        return JSONResponse({"status": "live"})

    async def health_ready(_request: Request) -> Response:
        ready = await service.probe_executors()
        # Without toolkits there is nothing to check. This is the state after
        # `init` and not a deficiency -- reporting it as 'degraded' would
        # flag a fresh installation as a malfunction.
        ok = all(ready.values()) if ready else not service.tier1.toolkits
        return JSONResponse(
            {"status": "ready" if ok else "degraded", "executors": ready},
            status_code=200 if ok else 503,
        )

    async def health_startup(_request: Request) -> Response:
        return JSONResponse(
            {
                "status": "started",
                "tools": len(service.catalog.tools),
                "disabled_by_tier1": len(service.catalog.disabled_by_tier1),
            }
        )

    async def metrics(_request: Request) -> Response:
        return PlainTextResponse(
            service.render_metrics(), media_type="text/plain; version=0.0.4"
        )

    routes = [
        Route("/health/live", health_live, methods=["GET"]),
        Route("/health/ready", health_ready, methods=["GET"]),
        Route("/health/startup", health_startup, methods=["GET"]),
        Route("/metrics", metrics, methods=["GET"]),
    ]
    if ui:
        routes.extend(
            build_ui_routes(
                service=service, identities=identities, audit=audit, store=store,
                credentials=credentials, pending=pending,
                toolkit_proposals=toolkit_proposals,
            )
        )

    primary_app = mcp_server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        host=host,
        stateless_http=True,
        custom_starlette_routes=routes,
    )

    all_routes = list(primary_app.routes)
    # Every `streamable_http_app()` result carries its own session manager,
    # started by its own `lifespan`. Starlette does not propagate the
    # "lifespan" ASGI scope into a mounted sub-application on its own (only
    # "http"/"websocket" scopes are dispatched by path) -- so composing two
    # of these into one outer app means running both lifespans explicitly,
    # not just merging routes.
    sub_apps = [primary_app]

    if store is not None:
        if pending is None:
            raise ValueError(
                "build_app(store=...) requires pending=... as well -- "
                "__main__.py constructs a PendingStore alongside the "
                "ConfigStore for exactly this."
            )
        if toolkit_proposals is None:
            raise ValueError(
                "build_app(store=...) requires toolkit_proposals=... as "
                "well -- __main__.py constructs a ToolkitProposalStore "
                "alongside the ConfigStore/PendingStore for exactly this."
            )
        admin_service = AdminService(
            store=store, pending=pending, toolkit_proposals=toolkit_proposals,
            credentials=credentials,
        )
        admin_mcp_server = build_admin_mcp_server(admin_service)
        admin_app = admin_mcp_server.streamable_http_app(
            streamable_http_path=ADMIN_MCP_PATH,
            host=host,
            stateless_http=True,
        )
        all_routes.extend(admin_app.routes)
        sub_apps.append(admin_app)

    @contextlib.asynccontextmanager
    async def combined_lifespan(_app: Starlette) -> Any:
        async with contextlib.AsyncExitStack() as stack:
            for sub_app in sub_apps:
                await stack.enter_async_context(sub_app.router.lifespan_context(sub_app))
            yield

    app = Starlette(routes=all_routes, lifespan=combined_lifespan)
    app.add_middleware(
        AuthMiddleware, identities=identities, audit=audit, ui_enabled=ui
    )
    return app


def log_startup(service: Service, identities: IdentityStore) -> dict[str, Any]:
    """NFR-7: record at startup what actually applies."""
    from .identity import summarize

    payload = {
        "toolkits": {
            name: {
                "executor": tk.executor,
                "binaries": list(tk.binaries),
                "denied_args": list(tk.denied_args),
                "path_roots": list(tk.path_roots),
                "protected_resources": list(tk.protected_resources),
            }
            for name, tk in service.tier1.toolkits.items()
        },
        "tools_active": sorted(service.catalog.tools),
        "tools_disabled_by_tier1": service.catalog.disabled_by_tier1,
        "identities": summarize(identities),
    }
    service.audit.startup(payload)
    logger.info("gatekeeper ready: %s", json.dumps(payload, ensure_ascii=False))
    for violation in service.catalog.disabled_by_tier1:
        logger.warning("Definition disabled by Tier 1 violation: %s", violation)
    return payload