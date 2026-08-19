"""Shared helper for reading the authenticated identity out of an MCP
request context.

Factored out of `server.py` so `admin_server.py` can use the exact same
lookup without importing `server.py` -- `server.py` builds and mounts the
admin server, so the reverse import would be circular.
"""

from __future__ import annotations

from typing import Any

from .errors import Denied, DenialReason
from .identity import Identity

#: Key under which `AuthMiddleware` (`server.py`) stores the authenticated
#: identity in the ASGI scope -- the only object reliably passed through
#: from the middleware to either MCP handler.
SCOPE_IDENTITY = "gatekeeper.identity"


def identity_from(ctx: Any) -> Identity:
    request = getattr(ctx, "request", None)
    scope = getattr(request, "scope", None)
    identity = (scope or {}).get(SCOPE_IDENTITY)
    if identity is None:
        # Can only occur if the middleware was bypassed. Then the
        # safe outcome is to show nothing at all.
        raise Denied(DenialReason.UNKNOWN_TOKEN, "No identity in the request scope")
    return identity


__all__ = ["SCOPE_IDENTITY", "identity_from"]
