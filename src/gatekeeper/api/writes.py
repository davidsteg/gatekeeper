"""Write routes of `/api/v1`: tools, identities, credentials, own password.

Phase 3a of the console migration (docs/ROADMAP.md). Every route here does
exactly what the matching `/ui` form handler does -- the same store call,
the same audit record, the same sessions ended -- and adds nothing a form
could not do. In particular there is still no route that writes a toolkit
(FR-4.11).

What every write needs, in this order (`deps.py`):

1. a console session (an `Authorization` header is refused),
2. `role: admin` and a writable configuration (`require_admin`) -- or, for
   one's own password, only a writable configuration,
3. `X-CSRF-Token`,
4. `If-Match` with the ETag of the collection read (`GET /tools`,
   `GET /identities`, `GET /credentials`). Missing is a 428, stale a 412.

The early `If-Match` check makes the common conflict a clean 412 before any
work; the store's own check under its lock is the real guarantee, and its
"changed since" refusal is mapped to 412 as well. Every other refusal of
the store (validation, Tier 1, unknown IDs) is a 400 with the store's own
sentence, which is what the form showed.

Store calls run on a thread: password hashing is scrypt, and on the event
loop every MCP call would wait behind it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import Depends, FastAPI, Request, Response

from ..credentials import WriteRefused as CredentialWriteRefused
from ..errors import ConfigError
from ..store import WriteRefused, load_tool_yaml
from . import models
from . import service as rm
from .deps import (
    EMPTY_REVISION,
    ApiContext,
    ApiError,
    ctx,
    if_match,
    require_admin,
    require_session_write,
    require_viewer,
    set_etag,
)
from .session import SESSION_COOKIE, Session

_WRITE_ERRORS: dict[int | str, dict[str, Any]] = {
    400: {"model": models.Problem, "description": "The store refused the write."},
    404: {"model": models.Problem},
    409: {"model": models.Problem},
    412: {"model": models.Problem, "description": "If-Match is stale."},
    428: {"model": models.Problem, "description": "If-Match is missing."},
}


def _refused(exc: Exception) -> ApiError:
    message = str(exc)
    if "changed since" in message:
        return ApiError(412, "The resource changed since you loaded it. Reload and apply your edit again.")
    return ApiError(400, message)


async def _call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    except (WriteRefused, CredentialWriteRefused, ConfigError) as exc:
        raise _refused(exc) from None


def _written(response: Response, revision: str) -> dict[str, str]:
    set_etag(response, revision)
    return {"revision": revision or EMPTY_REVISION}


def register_write_routes(app: FastAPI) -> None:
    # -- Tools ----------------------------------------------------------------

    def _tools_rev(request: Request, context: ApiContext) -> str:
        return if_match(request, context.store.tools_revision())

    @app.get(
        "/tool-scaffold", response_model=models.ToolScaffold, tags=["tools"],
        responses={409: {"model": models.Problem}},
    )
    def tool_scaffold(
        _s: Session = Depends(require_viewer), context: ApiContext = Depends(ctx)
    ) -> Any:
        """A starting point for a new definition, built from the first
        configured toolkit. 409 without a toolkit: nothing to build on.
        A read: it holds nothing `GET /toolkits` does not show already."""
        if not context.service.tier1.toolkits:
            raise ApiError(409, "No toolkit is configured, so there is nothing a tool could build on.")
        return {"yaml": rm._tool_scaffold(context.service)}

    @app.post("/tools", response_model=models.ToolSaved, status_code=201, tags=["tools"],
              responses=_WRITE_ERRORS)
    async def tool_create(
        body: models.ToolWrite, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        rev = _tools_rev(request, context)
        try:
            spec = load_tool_yaml(body.yaml)
        except (WriteRefused, ConfigError) as exc:
            raise _refused(exc) from None
        tool_id = await _call(context.store.save_tool, spec, actor=session.identity, rev=rev)
        return {"id": tool_id, **_written(response, context.store.tools_revision())}

    @app.put("/tools/{tool_id}", response_model=models.ToolSaved, tags=["tools"],
             responses=_WRITE_ERRORS)
    async def tool_update(
        tool_id: str, body: models.ToolWrite, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        """Replaces the definition `tool_id`. The YAML may carry a new ID --
        a rename, as in the form."""
        rev = _tools_rev(request, context)
        try:
            spec = load_tool_yaml(body.yaml)
        except (WriteRefused, ConfigError) as exc:
            raise _refused(exc) from None
        new_id = await _call(
            context.store.save_tool, spec, actor=session.identity, rev=rev, replaces=tool_id
        )
        return {"id": new_id, **_written(response, context.store.tools_revision())}

    @app.put("/tools/{tool_id}/enabled", response_model=models.Written, tags=["tools"],
             responses=_WRITE_ERRORS)
    async def tool_enable(
        tool_id: str, body: models.ToolEnabled, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        rev = _tools_rev(request, context)
        await _call(
            context.store.set_tool_enabled, tool_id, body.enabled,
            actor=session.identity, rev=rev,
        )
        return _written(response, context.store.tools_revision())

    @app.delete("/tools/{tool_id}", response_model=models.Written, tags=["tools"],
                responses=_WRITE_ERRORS)
    async def tool_delete(
        tool_id: str, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        """The full definition goes to the audit log, so it can be restored
        from there. Grants on it stay and dangle, as with the form."""
        rev = _tools_rev(request, context)
        await _call(context.store.delete_tool, tool_id, actor=session.identity, rev=rev)
        return _written(response, context.store.tools_revision())

    # -- Identities ---------------------------------------------------------------

    def _identities_rev(request: Request, context: ApiContext) -> str:
        return if_match(request, context.store.identities_revision())

    def _clean(body: models.IdentityWrite) -> dict[str, Any]:
        return {
            "identity_id": body.id.strip(),
            "role": body.role,
            "tools": list(body.tools),
            "scopes": [s.strip() for s in body.scopes if s.strip()],
        }

    @app.post("/identities", response_model=models.TokenIssued, status_code=201,
              tags=["identities"], responses=_WRITE_ERRORS)
    async def identity_create(
        body: models.IdentityWrite, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        """Creates an identity and returns its API token -- once. The token
        is in the response body only, never in a URL or the audit log."""
        rev = _identities_rev(request, context)
        values = _clean(body)
        token = await _call(
            context.store.create_identity, **values, actor=session.identity, rev=rev,
            password=body.password,
        )
        return {
            "identity": values["identity_id"], "token": token,
            **_written(response, context.store.identities_revision()),
        }

    @app.put("/identities/{identity_id}", response_model=models.Written,
             tags=["identities"], responses=_WRITE_ERRORS)
    async def identity_update(
        identity_id: str, body: models.IdentityWrite, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        """Role, grants, scopes, and optionally a new console password or ID.

        Sessions end by the same rule as in `/ui`
        (`service.drop_sessions_after_identity_update`)."""
        rev = _identities_rev(request, context)
        values = _clean(body)
        await _call(
            context.store.save_identity, **values, actor=session.identity, rev=rev,
            replaces=identity_id, password=body.password,
        )
        rm.drop_sessions_after_identity_update(
            context.sessions, replaces=identity_id, new_id=values["identity_id"],
            role=values["role"], password_set=bool(body.password), actor=session.identity,
            current_sid=request.cookies.get(SESSION_COOKIE),
        )
        return _written(response, context.store.identities_revision())

    @app.post("/identities/{identity_id}/token", response_model=models.TokenIssued,
              tags=["identities"], responses=_WRITE_ERRORS)
    async def identity_rotate(
        identity_id: str, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        """A new API token; the old one stops working at once. The
        identity's console sessions end too (a rotation answers a
        suspicion), except the caller's own."""
        rev = _identities_rev(request, context)
        token = await _call(
            context.store.rotate_token, identity_id, actor=session.identity, rev=rev
        )
        if identity_id != session.identity:
            context.sessions.drop_identity(identity_id)
        return {
            "identity": identity_id, "token": token,
            **_written(response, context.store.identities_revision()),
        }

    @app.delete("/identities/{identity_id}", response_model=models.Written,
                tags=["identities"], responses=_WRITE_ERRORS)
    async def identity_delete(
        identity_id: str, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        """The token stops working immediately and every console session of
        the identity ends -- the caller's own included, if it is them."""
        rev = _identities_rev(request, context)
        await _call(context.store.delete_identity, identity_id, actor=session.identity, rev=rev)
        context.sessions.drop_identity(identity_id)
        return _written(response, context.store.identities_revision())

    # -- Credentials (write-only, FR-10.2) -------------------------------------------

    def _credentials(context: ApiContext) -> Any:
        if context.credentials is None:
            raise ApiError(
                409, "No credential store is configured (GATEKEEPER_CREDENTIAL_KEY is not set)."
            )
        return context.credentials

    @app.post("/credentials", response_model=models.Written, status_code=201,
              tags=["credentials"], responses=_WRITE_ERRORS)
    async def credential_create(
        body: models.CredentialCreate, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        """The value goes in and never comes out: no route returns it."""
        store = _credentials(context)
        rev = if_match(request, store.revision())
        name = body.name.strip()
        probe_url = (body.probe_url or "").strip() or None
        await _call(
            store.create, name, kind=body.kind, header=(body.header or "").strip() or None,
            value=body.value, probe_url=probe_url, actor=session.identity, rev=rev,
        )
        if probe_url:
            rm._schedule_credential_probe(store, name)
        return _written(response, store.revision())

    @app.post("/credentials/{name}/rotate", response_model=models.Written,
              tags=["credentials"], responses=_WRITE_ERRORS)
    async def credential_rotate(
        name: str, body: models.CredentialRotate, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        """A new value. With `overlap_seconds`, the previous one keeps
        working for that long, so callers can switch over."""
        store = _credentials(context)
        rev = if_match(request, store.revision())
        await _call(
            store.rotate, name, value=body.value, overlap_seconds=body.overlap_seconds,
            actor=session.identity, rev=rev,
        )
        if any(meta.name == name and meta.probe_url for meta in store.names()):
            rm._schedule_credential_probe(store, name)
        return _written(response, store.revision())

    @app.delete("/credentials/{name}", response_model=models.Written,
                tags=["credentials"], responses=_WRITE_ERRORS)
    async def credential_delete(
        name: str, request: Request, response: Response,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        store = _credentials(context)
        rev = if_match(request, store.revision())
        await _call(store.delete, name, actor=session.identity, rev=rev)
        return _written(response, store.revision())

    # -- Account ------------------------------------------------------------------------

    @app.put("/account/password", response_model=models.Written, tags=["account"],
             responses=_WRITE_ERRORS)
    async def account_password(
        body: models.PasswordChange, request: Request, response: Response,
        session: Session = Depends(require_session_write), context: ApiContext = Depends(ctx),
    ) -> Any:
        """One's own console password; any role. Needs the current one. On
        success every *other* session of this identity ends."""
        rev = if_match(request, context.store.identities_revision())
        try:
            await asyncio.to_thread(
                context.store.set_password, session.identity, body.password,
                actor=session.identity, rev=rev, current_password=body.current,
                require_current=True,
            )
        except (WriteRefused, ConfigError) as exc:
            # A wrong current password is a failed attempt and belongs in
            # the log, as in `/ui`.
            context.audit.auth_failure(
                reason="ui_password_change_failed",
                detail=f"identity={session.identity!r}: {exc}",
            )
            raise _refused(exc) from None
        context.sessions.drop_identity(
            session.identity, keep=request.cookies.get(SESSION_COOKIE)
        )
        return _written(response, context.store.identities_revision())
