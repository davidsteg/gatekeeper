"""`X-Real-IP` from a trusted proxy.

uvicorn's own `ProxyHeadersMiddleware` (`--trusted-proxies`) reads
`X-Forwarded-For` only. nginx's common `proxy_set_header X-Real-IP
$remote_addr;` setups, and some ingress controllers, send `X-Real-IP`
instead, and the client address then stays the proxy's own. This fills that
gap with the same trust list: the header counts only when the immediate peer
is a trusted proxy, and only when no `X-Forwarded-For` came along, so the
two never disagree about who called.
"""

from __future__ import annotations

import ipaddress

from starlette.types import ASGIApp, Receive, Scope, Send

# uvicorn's own default when `forwarded_allow_ips` is unset.
DEFAULT_TRUSTED = ("127.0.0.1",)


def _parse(entries: list[str] | None) -> tuple[bool, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    networks = []
    for entry in entries if entries is not None else DEFAULT_TRUSTED:
        if entry == "*":
            return True, []
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # uvicorn also accepts a literal host such as a unix socket
            # path; neither can be the peer of a TCP request with a header.
            continue
    return False, networks


class RealIpMiddleware:
    def __init__(self, app: ASGIApp, trusted: list[str] | None) -> None:
        self.app = app
        self.trust_all, self.networks = _parse(trusted)

    def _trusted(self, host: str) -> bool:
        if self.trust_all:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address in network for network in self.networks)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            peer = scope.get("client")
            headers = dict(scope.get("headers", ()))
            real = headers.get(b"x-real-ip", b"").decode("latin-1").strip()
            # uvicorn has already handled X-Forwarded-For when it was sent,
            # and `client` may by now be the forwarded address: leave it be.
            if (
                real
                and b"x-forwarded-for" not in headers
                and peer
                and self._trusted(peer[0])
                and _is_address(real)
            ):
                scope = dict(scope, client=(real, 0))
        await self.app(scope, receive, send)


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
