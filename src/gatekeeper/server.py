"""MCP-Protokoll und HTTP-Schicht (REQUIREMENTS.md §3).

Die Authentifizierung sitzt als reine ASGI-Middleware davor -- nicht als
Starlette-`BaseHTTPMiddleware`, weil die den Streaming-Antworten des
Streamable-HTTP-Transports im Weg steht.
"""

from __future__ import annotations

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

from .audit import AuditLog
from .errors import Denied, DenialReason
from .execute import OUTCOME_OK, OUTCOME_UNKNOWN
from .identity import Identity, IdentityStore
from .service import Service
from .ui import UI_COMPANION_PATHS, UI_PREFIX, build_ui_routes

logger = logging.getLogger("gatekeeper")

#: Nur diese Pfade sind ohne Token erreichbar (NFR-3). Sie geben nichts ueber
#: Katalog oder Identitaeten preis.
PUBLIC_PATHS = frozenset({"/health/live", "/health/ready", "/health/startup"})

#: Schluessel, unter dem die Identitaet im ASGI-Scope liegt. Der Scope ist das
#: einzige Objekt, das zuverlaessig von der Middleware bis zum MCP-Handler
#: durchgereicht wird -- Contextvars ueberleben den Taskwechsel des Transports
#: nicht verlaesslich.
SCOPE_IDENTITY = "gatekeeper.identity"


class AuthMiddleware:
    """Bearer-Token pruefen, sonst 401 (FR-2.3).

    Diese Middleware liest ausschliesslich den `Authorization`-Header und
    niemals ein Cookie. Das ist der Grund, warum `/mcp` gegen CSRF immun ist:
    ein Browser haengt einen solchen Header nicht von sich aus an, eine fremde
    Seite kann ihn also nicht erzeugen. Die Sitzung des Betriebs-UIs (`ui.py`)
    ist bewusst ein davon getrennter Mechanismus -- wuerde sie hier gelten,
    koennte jede beliebige Webseite im Hintergrund Tools auf dem Host
    ausfuehren lassen.
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
        # Exakter Praefixvergleich: '/uixyz' darf nicht mitgemeint sein.
        if path == UI_PREFIX or path.startswith(UI_PREFIX + "/"):
            return True
        # '/' und '/favicon.ico' fragt der Browser von sich aus ab. Sie hier
        # durchzulassen haelt das Audit-Log frei von Rauschen, das sonst jeden
        # echten Fehlversuch zudecken wuerde.
        return path in UI_COMPANION_PATHS

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        # Die UI-Routen bringen ihre eigene Pruefung mit (Sitzung statt Token).
        # Ist das UI abgeschaltet, greift hier weiterhin die Token-Pflicht.
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


def _identity_from(ctx: Any) -> Identity:
    request = getattr(ctx, "request", None)
    scope = getattr(request, "scope", None)
    identity = (scope or {}).get(SCOPE_IDENTITY)
    if identity is None:
        # Kann nur eintreten, wenn die Middleware umgangen wurde. Dann ist der
        # sichere Ausgang, gar nichts zu zeigen.
        raise Denied(DenialReason.UNKNOWN_TOKEN, "No identity in the request scope")
    return identity


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
        # cacheScope private: die Liste ist pro Identitaet verschieden und darf
        # zwischen Agenten nicht geteilt werden.
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
) -> Starlette:
    """Baut die vollstaendige ASGI-Anwendung.

    `ui=False` ist Absicht: die Oberflaeche ist die einzige browserseitige
    Flaeche des Servers und waechst einem bestehenden Deployment nicht
    stillschweigend zu. Sie wird ueber `--ui` bzw. `GATEKEEPER_UI=1`
    eingeschaltet.

    `store=None` heisst: nur lesen. Erst ein `ConfigStore` schaltet die
    Schreibfunktionen frei -- und auch dann nur fuer `role: admin`.
    """
    mcp_server = build_mcp_server(service)

    async def health_live(_request: Request) -> Response:
        return JSONResponse({"status": "live"})

    async def health_ready(_request: Request) -> Response:
        ready = await service.probe_executors()
        # Ohne Toolkits gibt es nichts zu pruefen. Das ist der Zustand nach
        # `init` und kein Mangel -- ihn als 'degraded' zu melden wuerde eine
        # frische Installation als Stoerung ausweisen.
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
                service=service, identities=identities, audit=audit, store=store
            )
        )

    app = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        host=host,
        stateless_http=True,
        custom_starlette_routes=routes,
    )
    app.add_middleware(
        AuthMiddleware, identities=identities, audit=audit, ui_enabled=ui
    )
    return app


def log_startup(service: Service, identities: IdentityStore) -> dict[str, Any]:
    """NFR-7: beim Start festhalten, was tatsaechlich gilt."""
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
