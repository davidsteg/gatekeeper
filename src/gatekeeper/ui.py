"""What is left of `/ui` after the 1.0.0 cutover to the React console.

The HTML console that lived here was replaced by `/app` (`frontend/`,
backed by `/api/v1`). Three things remain, all without a page:

- Redirects. A bookmark or an installed shortcut to `/ui/...` lands on
  the same page under `/app/...`; `/` and `/favicon.ico` -- fetched by
  the browser on its own -- go there too. Anything but `GET`/`HEAD`
  (an old form posted from a tab left open) gets 410: it is not
  replayed against the new API, which has its own CSRF and `If-Match`.
- The OAuth callbacks (`oauth.build_callback_routes`), whose paths are
  the redirect URIs registered with Google and Microsoft.
- `has_ui_identity`, the startup check for "can anyone sign in at all".
"""

from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from .identity import IdentityStore
from .oauth import OAuthStateStore, build_callback_routes

UI_PREFIX = "/ui"
APP_PREFIX = "/app"

#: Paths a browser requests on its own when someone types the address.
#: Without letting them past the token check, every visit would write two
#: `auth_failure` records -- and a failed attempt is the most important
#: finding in the audit log, worthless if it sits among favicon noise.
#: Applies only when the console is enabled.
UI_COMPANION_PATHS = frozenset({"/", "/favicon.ico"})

GONE_MESSAGE = (
    "The /ui console was replaced by /app in gatekeeper 1.0.0. "
    "Nothing was changed; reload the page under /app.\n"
)


def app_path_for(path: str) -> str:
    """`/ui/<rest>` -> `/app/<rest>`. The target always starts with `/app/`,
    so no request can turn it into a redirect to another origin."""
    rest = path[len(UI_PREFIX):].lstrip("/")
    return f"{APP_PREFIX}/{rest}"


def build_ui_routes(
    *, identities: IdentityStore, audit: Any, store: Any = None,
    credentials: Any = None, oauth_states: OAuthStateStore,
) -> list[Route]:
    async def to_app(request: Request) -> Response:
        if request.method not in ("GET", "HEAD"):
            return PlainTextResponse(GONE_MESSAGE, status_code=410)
        return RedirectResponse(app_path_for(request.url.path), status_code=308)

    async def root(_request: Request) -> Response:
        return RedirectResponse(f"{APP_PREFIX}/", status_code=303)

    async def favicon(_request: Request) -> Response:
        return RedirectResponse(f"{APP_PREFIX}/favicon.svg", status_code=308)

    every = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
    return [
        # First: the callbacks are more specific than the catch-all below.
        *build_callback_routes(
            identities=identities, audit=audit, store=store,
            credentials=credentials, states=oauth_states,
        ),
        Route("/", root, methods=["GET", "HEAD"]),
        Route("/favicon.ico", favicon, methods=["GET", "HEAD"]),
        Route(UI_PREFIX, to_app, methods=every),
        Route(f"{UI_PREFIX}/{{path:path}}", to_app, methods=every),
    ]


def has_ui_identity(identities: IdentityStore) -> bool:
    """Is there anyone at all who could sign in?

    Role *and* password: since console sign-in, a console role without a
    password is not access. A server that delivers a login form nobody
    can get past is worse than one without a console -- it looks usable.
    """
    return any(i.can_sign_in for i in identities.identities.values())
