"""Serves the React console's static build at `/app`.

The build (`frontend/dist`, produced by `npm run build`) ships inside the
package as `gatekeeper/_web/` -- the Dockerfile's node stage builds it and
copies it there, so the runtime image needs no Node. In a dev checkout the
route falls back to `frontend/dist`, and `GATEKEEPER_WEB_DIR` overrides
both.

What the routes guarantee:

* **CSP on every `/app` response** (`APP_CSP`): scripts and styles only
  from this origin, no inline script, no eval, Trusted Types enforced for
  script sinks, nothing framed, no third-party anything. This is the
  console's invariant, replacing the removed HTML console's "no script at
  all" (see
  REQUIREMENTS.md, FR-11.9).
* **Caching by content.** Hashed files under `/app/assets/` are
  `immutable`; `index.html` is `no-store`, so a deploy is picked up on the
  next navigation.
* **SPA fallback.** Any other `/app/...` path without a file behind it
  answers `index.html`, so a deep link or reload works. A missing file
  under `/app/assets/` stays a 404 -- a stale hashed URL must not come
  back as HTML.
* **No data.** These are public bytes; `AuthMiddleware` lets `/app`
  through like `/ui`, and everything the page shows comes from `/api/v1`
  behind a session.
"""

from __future__ import annotations

import mimetypes
import os

from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

APP_PREFIX = "/app"

APP_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; font-src 'self'; manifest-src 'self'; worker-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "require-trusted-types-for 'script'"
)

_HEADERS = {
    "Content-Security-Policy": APP_CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

#: Not in every platform's mime table; a manifest served as
#: application/octet-stream is ignored by the browser.
mimetypes.add_type("application/manifest+json", ".webmanifest")

WEB_DIR_ENV = "GATEKEEPER_WEB_DIR"

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def web_dir() -> str | None:
    """The first directory holding a built `index.html`, or None."""
    candidates = [
        os.environ.get(WEB_DIR_ENV) or "",
        os.path.join(_HERE, "_web"),
        os.path.join(os.path.dirname(os.path.dirname(_HERE)), "frontend", "dist"),
    ]
    for base in candidates:
        if base and os.path.isfile(os.path.join(base, "index.html")):
            return base
    return None


def _headers(cache: str) -> dict[str, str]:
    return {**_HEADERS, "Cache-Control": cache}


def _resolve(base: str, rel: str) -> str | None:
    """`rel` inside `base`, or None for anything that escapes it."""
    root = os.path.realpath(base)
    target = os.path.realpath(os.path.join(root, rel))
    if target != root and not target.startswith(root + os.sep):
        return None
    return target if os.path.isfile(target) else None


def build_web_routes() -> list[Route]:
    async def serve(request: Request) -> Response:
        base = web_dir()
        if base is None:
            return PlainTextResponse(
                "The console is not built into this installation. In a checkout, "
                "run `npm ci --ignore-scripts && npm run build` in frontend/.",
                503, headers=_headers("no-store"),
            )
        rel = request.path_params.get("path", "")
        index = os.path.join(base, "index.html")
        if rel in ("", "index.html"):
            return FileResponse(index, media_type="text/html", headers=_headers("no-store"))
        found = _resolve(base, rel)
        if found is not None:
            immutable = rel.startswith("assets/")
            media = mimetypes.guess_type(found)[0] or "application/octet-stream"
            return FileResponse(
                found, media_type=media,
                headers=_headers(
                    "public, max-age=31536000, immutable" if immutable else "public, max-age=3600"
                ),
            )
        # Only under assets/: a client route may contain a dot (a tool ID
        # like `docker.compose_ps` is one), so an extension alone proves
        # nothing.
        if rel.startswith("assets/"):
            return PlainTextResponse("not found", 404, headers=_headers("no-store"))
        return FileResponse(index, media_type="text/html", headers=_headers("no-store"))

    async def redirect(_request: Request) -> Response:
        return RedirectResponse(f"{APP_PREFIX}/", status_code=308)

    routes = [
        Route(APP_PREFIX, redirect, methods=["GET"]),
        Route(f"{APP_PREFIX}/", serve, methods=["GET", "HEAD"]),
        Route(f"{APP_PREFIX}/{{path:path}}", serve, methods=["GET", "HEAD"]),
    ]
    for route in routes:
        route.app = GZipMiddleware(route.app, minimum_size=500)
    return routes
