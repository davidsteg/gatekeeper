"""Authentication, roles, CSRF and optimistic concurrency for `/api/v1`.

The rules are the legacy console's, carried over one for one:

* **Session, not token.** A request is authenticated by the console session
  cookie only. An `Authorization` header is refused outright -- an MCP
  bearer token must never reach console capabilities, the same separation
  `AuthMiddleware` keeps in the other direction (FR-11.5).
* **Two roles.** `viewer` reads, `admin` writes; read-only mode
  (`--ui-read-only`, `GATEKEEPER_UI_READ_ONLY`, i.e. no `ConfigStore`)
  turns every write into a 403 for everyone.
* **CSRF.** Every mutating request carries `X-CSRF-Token` equal to the
  session's token, compared in constant time like `ui._csrf_ok`. The
  cookie is `SameSite=Strict` as well; the header closes the same-site gap.
* **If-Match.** Reads return `ETag: "<store revision>"`; writes must send it
  back. A stale revision is a 412 -- the guarantee the legacy forms' hidden
  `rev` fields give.

Denials are audited with the same `admin_denied` record the legacy
console writes, so the log reads the same whichever surface was used.
"""

from __future__ import annotations

import dataclasses
import hmac
from typing import Any

from fastapi import Depends, HTTPException, Request, Response

from ..audit import AuditLog
from ..credentials import CredentialStore
from ..identity import IdentityStore
from ..pending import PendingStore
from ..service import Service
from ..toolkit_proposals import ToolkitProposalStore
from .session import SESSION_COOKIE, LoginThrottle, Session, SessionStore

CSRF_HEADER = "X-CSRF-Token"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclasses.dataclass(slots=True)
class ApiContext:
    """The stores the API shares with the legacy console and the MCP mounts."""

    service: Service
    identities: IdentityStore
    audit: AuditLog
    sessions: SessionStore
    throttle: LoginThrottle
    store: Any = None  # ConfigStore | None -- None means read-only mode
    credentials: CredentialStore | None = None
    pending: PendingStore | None = None
    toolkit_proposals: ToolkitProposalStore | None = None

    @property
    def read_only(self) -> bool:
        return self.store is None

    def can_write(self, session: Session) -> bool:
        return session.can_write and not self.read_only


def ctx(request: Request) -> ApiContext:
    return request.app.state.ctx


class ApiError(HTTPException):
    """An error answered as `{"error": "<sentence>"}` (see `app.py`)."""


def current_session(request: Request, context: ApiContext = Depends(ctx)) -> Session:
    if request.headers.get("authorization") is not None:
        # Not a fallback, not a second way in: an agent's bearer token is
        # refused on every API route, with or without a cookie next to it.
        context.audit.auth_failure(
            reason="api_bearer_rejected",
            detail=f"{request.method} {request.url.path}",
        )
        raise ApiError(401, "Bearer tokens are not accepted here; sign in to the console.")
    session = context.sessions.resolve(request.cookies.get(SESSION_COOKIE))
    if session is None:
        raise ApiError(401, "Not signed in.")
    return session


def _deny(context: ApiContext, request: Request, session: Session, reason: str) -> None:
    context.audit.write(
        {
            "kind": "admin_denied",
            "actor": session.identity,
            "role": session.role,
            "path": request.url.path,
            "reason": reason,
        }
    )


def require_viewer(session: Session = Depends(current_session)) -> Session:
    """Any console session. Viewers and admins read the same data."""
    return session


def require_csrf(
    request: Request,
    session: Session = Depends(current_session),
    context: ApiContext = Depends(ctx),
) -> Session:
    if request.method in MUTATING_METHODS:
        supplied = request.headers.get(CSRF_HEADER) or ""
        if not hmac.compare_digest(supplied, session.csrf):
            _deny(context, request, session, "csrf_mismatch")
            raise ApiError(403, "Missing or stale CSRF token.")
    return session


def require_session_write(
    request: Request,
    session: Session = Depends(require_csrf),
    context: ApiContext = Depends(ctx),
) -> Session:
    """A write that needs a session and CSRF, but not `admin` -- one's own
    console password, mirroring `ui.session_post`."""
    if context.read_only:
        _deny(context, request, session, "read_only")
        raise ApiError(403, "The console is read-only.")
    return session


def require_admin(
    request: Request,
    session: Session = Depends(current_session),
    context: ApiContext = Depends(ctx),
) -> Session:
    """Role first, then CSRF -- the legacy `writer` order, so a viewer is
    told "not permitted" rather than "stale token"."""
    if context.read_only or not session.can_write:
        _deny(context, request, session, "read_only" if context.read_only else "role_required")
        raise ApiError(403, "Writing requires role admin and a writable configuration.")
    return require_csrf(request, session, context)


#: The ETag of a store whose file does not exist yet (no credential has
#: been created, say). Sent back, it matches only while the file is still
#: missing -- once someone creates it, the revision is real and this is stale.
EMPTY_REVISION = "0"


def set_etag(response: Response, revision: str) -> None:
    response.headers["ETag"] = f'"{revision or EMPTY_REVISION}"'


def if_match(request: Request, current: str) -> str:
    """The revision a write is based on, checked against `current`.

    Returns the supplied revision so the caller can hand it to the store,
    whose own check at write time is the real guarantee -- this early
    check only turns the common case into a clean 412 before any work.
    """
    raw = request.headers.get("if-match")
    if raw is None:
        raise ApiError(428, "If-Match is required; send the ETag of the resource you edited.")
    supplied = raw.strip()
    if supplied.startswith("W/"):
        supplied = supplied[2:]
    supplied = supplied.strip('"')
    if supplied != (current or EMPTY_REVISION):
        raise ApiError(412, "The resource changed since you loaded it. Reload and apply your edit again.")
    return supplied
