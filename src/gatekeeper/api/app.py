"""The `/api/v1` application: a FastAPI sub-app mounted into gatekeeper's
Starlette app by `server.build_app`, next to `/mcp`, `/admin/mcp` and `/ui`.

Session handling and every *read* the legacy console offers live here;
the writes for tools, identities, credentials and one's own password are
in `writes.py` (phases 3a and 3b, docs/ROADMAP.md), request decisions
included.

Invariants this module keeps, and the tests in `tests/test_api_*.py` pin:

* No route writes a toolkit. Toolkits are `GET` only, plus the reference
  YAML as text for a human to paste (FR-4.11).
* No response carries a credential value, token hash or password hash --
  the response models in `models.py` have no field for one.
* An MCP bearer token opens nothing here (`deps.current_session`).
* The OpenAPI schema is admin-only (`GET /openapi.json`); there are no
  interactive docs pages, which would need inline scripts.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

from .. import __version__, release_notes
from ..identity import ADMIN_ROLE
from . import API_PREFIX, models
from . import service as rm
from .deps import (
    ApiContext,
    ApiError,
    ctx,
    require_csrf,
    require_viewer,
    set_etag,
)
from .extras import register_extra_routes
from .session import SESSION_COOKIE, Session
from .writes import register_request_routes, register_write_routes

#: API responses are data, never a document: nothing in them may run,
#: frame or load anything, even if a browser is pointed straight at one.
_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}

_ERRORS = {
    401: {"model": models.Problem, "description": "Not signed in, or a bearer token was sent."},
    403: {"model": models.Problem, "description": "Role, CSRF or read-only refusal."},
}


def _session_info(context: ApiContext, session: Session) -> models.SessionInfo:
    return models.SessionInfo(
        identity=session.identity,
        role=session.role,
        can_write=context.can_write(session),
        read_only=context.read_only,
        csrf=session.csrf,
        version=__version__,
    )


def build_api_app(context: ApiContext | None) -> FastAPI:
    """The API app. `context=None` builds it for schema generation only."""
    app = FastAPI(
        title="gatekeeper console API",
        version=__version__,
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
        responses=_ERRORS,
    )
    app.state.ctx = context

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(ApiError)
    async def api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse({"error": str(exc.detail)}, exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def invalid(_request: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
        message = first.get("msg", "Invalid request.")
        return JSONResponse({"error": f"{where}: {message}" if where else message}, 422)

    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # 404/405 for paths and methods that do not exist -- in the same
        # `{"error"}` shape as everything else.
        return JSONResponse({"error": str(exc.detail)}, exc.status_code, headers=exc.headers)

    # -- Session -----------------------------------------------------------

    @app.get("/session", response_model=models.SessionInfo, tags=["session"])
    def session_get(
        session: Session = Depends(require_viewer), context: ApiContext = Depends(ctx)
    ) -> models.SessionInfo:
        return _session_info(context, session)

    @app.post(
        "/session", response_model=models.SessionInfo, tags=["session"],
        responses={429: {"model": models.Problem}, 415: {"model": models.Problem}},
    )
    async def session_create(
        body: models.LoginRequest, request: Request, response: Response,
        context: ApiContext = Depends(ctx),
    ) -> models.SessionInfo:
        """Sign in with the console password (FR-11.5), never the API token.

        JSON only: a cross-site form post cannot send `application/json`
        without a CORS preflight this app never answers, which is the
        login form's CSRF protection here. The failure message never says
        which half was wrong; the audit log has it in full.
        """
        if request.headers.get("authorization") is not None:
            context.audit.auth_failure(
                reason="api_bearer_rejected", detail=f"POST {request.url.path}"
            )
            raise ApiError(401, "Bearer tokens are not accepted here; sign in to the console.")
        if not request.headers.get("content-type", "").startswith("application/json"):
            raise ApiError(415, "Send the credentials as application/json.")
        client = request.client.host if request.client else "unknown"
        if context.throttle.blocked(client):
            context.audit.auth_failure(reason="ui_login_throttled", detail=client)
            raise ApiError(429, "Too many failed attempts. Try again later.")
        supplied = body.identity.strip()[:64]
        identity = (
            await asyncio.to_thread(
                context.identities.authenticate_console, supplied, body.password
            )
            if supplied and body.password
            else None
        )
        if identity is None:
            context.throttle.record_failure(client)
            context.audit.auth_failure(
                reason="ui_login_failed", detail=f"identity={supplied!r} from {client}"
            )
            raise ApiError(401, "Sign-in failed.")
        context.throttle.reset(client)
        sid = context.sessions.create(identity.id, identity.role)
        context.audit.write(
            {
                "kind": "ui_login",
                "identity": identity.id,
                "role": identity.role,
                "client": client,
                "surface": "api",
            }
        )
        response.set_cookie(
            SESSION_COOKIE,
            sid,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path=API_PREFIX,
            max_age=context.sessions.ttl,
        )
        session = context.sessions.resolve(sid)
        assert session is not None
        return _session_info(context, session)

    @app.delete("/session", status_code=204, tags=["session"])
    def session_delete(
        request: Request, _session: Session = Depends(require_csrf),
        context: ApiContext = Depends(ctx),
    ) -> Response:
        context.sessions.destroy(request.cookies.get(SESSION_COOKIE))
        response = Response(status_code=204)
        response.delete_cookie(SESSION_COOKIE, path=API_PREFIX)
        return response

    @app.get("/account", response_model=models.Account, tags=["account"])
    def account(
        response: Response, session: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> models.Account:
        if context.store is not None:
            # The `If-Match` for `PUT /account/password`.
            set_etag(response, context.store.identities_revision())
        return models.Account(
            identity=session.identity, role=session.role,
            can_change_password=not context.read_only,
        )

    # -- Overview ------------------------------------------------------------

    @app.get("/overview", response_model=models.Overview, tags=["overview"])
    def overview(
        _s: Session = Depends(require_viewer), context: ApiContext = Depends(ctx)
    ) -> Any:
        return rm.overview_view(
            context.service, context.identities, context.store,
            context.pending, context.toolkit_proposals,
        )

    # -- Tools -----------------------------------------------------------------

    @app.get("/tools", response_model=models.ToolList, tags=["tools"])
    def tools(
        response: Response, _s: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> Any:
        if context.store is not None:
            set_etag(response, context.store.tools_revision())
        return rm.tools_view(context.service, context.identities)

    @app.get(
        "/tools/{tool_id}", response_model=models.ToolDetail, tags=["tools"],
        responses={404: {"model": models.Problem}},
    )
    def tool(
        tool_id: str, response: Response, _s: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> Any:
        detail = rm.tool_detail(context.service, context.identities, tool_id)
        if detail is None:
            raise ApiError(404, f"No tool definition with ID {tool_id!r}.")
        if context.store is not None:
            set_etag(response, context.store.tools_revision())
        return detail

    @app.get("/integrations", response_model=list[models.Integration], tags=["tools"])
    def integrations(
        _s: Session = Depends(require_viewer), context: ApiContext = Depends(ctx)
    ) -> Any:
        return rm.integrations_view(context.service)

    @app.get(
        "/integrations/{key}/logo.svg", tags=["tools"],
        response_class=Response, responses={200: {"content": {"image/svg+xml": {}}}},
    )
    def integration_logo(key: str, _s: Session = Depends(require_viewer)) -> Response:
        """The brand mark as an image, for `<img src>`. An SVG loaded as an
        image never runs script, so the SPA needs no `innerHTML` for it."""
        from ..integrations import INTEGRATIONS

        integration = INTEGRATIONS.get(key)
        if integration is None:
            raise ApiError(404, f"No integration {key!r}.")
        return Response(
            integration.logo_svg, media_type="image/svg+xml",
            headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                "Cache-Control": "private, max-age=3600",
            },
        )

    # -- Identities --------------------------------------------------------------

    @app.get("/identities", response_model=list[models.IdentityOut], tags=["identities"])
    def identities(
        response: Response, _s: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> Any:
        if context.store is not None:
            set_etag(response, context.store.identities_revision())
        return rm.identities_view(context.service, context.identities)

    # -- Credentials (metadata only, FR-10.2) ---------------------------------------

    @app.get("/credentials", response_model=models.CredentialList, tags=["credentials"])
    def credentials(
        response: Response, _s: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> Any:
        refs = context.service.tier1.credential_references()
        if context.credentials is None:
            return {"configured": False, "credentials": [], "dangling": sorted(refs)}
        set_etag(response, context.credentials.revision())
        metas = rm.credential_summaries(context.credentials, context.service.tier1)
        held = {m["name"] for m in metas}
        return {
            "configured": True,
            "credentials": metas,
            "dangling": sorted(n for n in refs if n not in held),
        }

    # -- Toolkits (read-only, FR-4.11) ------------------------------------------------

    @app.get("/toolkits", response_model=models.ToolkitList, tags=["toolkits"])
    def toolkits(
        _s: Session = Depends(require_viewer), context: ApiContext = Depends(ctx)
    ) -> Any:
        tier1 = context.service.tier1
        return {
            "toolkits": rm.toolkit_summaries(tier1),
            "destinations": sorted(tier1.destinations),
        }

    @app.get(
        "/toolkits/reference", response_model=list[models.ToolkitReference], tags=["toolkits"]
    )
    def toolkit_reference(_s: Session = Depends(require_viewer)) -> Any:
        return rm.toolkit_reference_view()

    # -- Requests ------------------------------------------------------------------------

    @app.get("/requests/pending", response_model=list[models.PendingItem], tags=["requests"])
    def requests_pending(
        response: Response,
        status: str | None = Query(None, max_length=32),
        _s: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> Any:
        items = rm.pending_view(context.store, context.pending, status)
        if context.pending is not None:
            set_etag(response, context.pending.revision())
        return items

    @app.get(
        "/requests/toolkits", response_model=list[models.ToolkitProposalOut], tags=["requests"]
    )
    def requests_toolkits(
        response: Response,
        status: str | None = Query(None, max_length=32),
        _s: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> Any:
        if context.toolkit_proposals is not None:
            set_etag(response, context.toolkit_proposals.revision())
        return rm.toolkit_proposals_view(context.service, context.toolkit_proposals, status)

    # -- Audit ------------------------------------------------------------------------------

    @app.get(
        "/audit", response_model=models.AuditPage, tags=["audit"],
        responses={400: {"model": models.Problem}},
    )
    def audit(
        identity: str = Query("", max_length=256),
        tool: str = Query("", max_length=256),
        outcome: str = Query("", pattern="^(|ok|denied|failed|unknown)$"),
        limit: int = Query(100, ge=1, le=500),
        cursor: str | None = Query(None, max_length=128),
        _s: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> Any:
        try:
            return rm.audit_page(
                context.service, limit=limit, cursor=cursor,
                identity=identity, tool=tool, outcome=outcome,
            )
        except (ValueError, KeyError, TypeError):
            raise ApiError(400, "Invalid cursor.") from None

    # -- Release notes ------------------------------------------------------------------------

    @app.get("/release-notes", response_model=models.ReleaseNotes, tags=["release-notes"])
    def notes(
        version: str | None = Query(None, max_length=64),
        search: str | None = Query(None, max_length=256),
        limit: int | None = Query(None, ge=1, le=1000),
        _s: Session = Depends(require_viewer),
    ) -> Any:
        releases, total = release_notes.query(version=version, search=search, limit=limit)
        return {"version": __version__, "releases": releases, "total": total}

    register_write_routes(app)
    register_request_routes(app)
    register_extra_routes(app)

    # -- Schema --------------------------------------------------------------------------------

    @app.get("/openapi.json", include_in_schema=False)
    def openapi(_s: Session = Depends(require_admin_read)) -> JSONResponse:
        return JSONResponse(openapi_schema(app))

    return app


def require_admin_read(
    request: Request, session: Session = Depends(require_viewer),
    context: ApiContext = Depends(ctx),
) -> Session:
    """Admin role for a read: the schema maps every capability the console
    has, which is more than a viewer needs to see. Read-only mode does not
    matter for a read, so this is not `require_admin`."""
    if session.role != ADMIN_ROLE:
        context.audit.write(
            {
                "kind": "admin_denied", "actor": session.identity, "role": session.role,
                "path": request.url.path, "reason": "role_required",
            }
        )
        raise ApiError(403, "The API schema is available to role admin only.")
    return session


def openapi_schema(app: FastAPI) -> dict[str, Any]:
    if app.openapi_schema is None:
        app.openapi_schema = get_openapi(
            title=app.title, version="v1", routes=app.routes,
            servers=[{"url": API_PREFIX}],
        )
    return app.openapi_schema


def schema_text() -> str:
    """The schema as committed in `frontend/openapi.json`: stable key order,
    no deployment-specific data, so CI can diff it against a fresh build."""
    import json

    return json.dumps(openapi_schema(build_api_app(None)), indent=2, sort_keys=True) + "\n"
