"""`X-Real-IP` from a trusted proxy, and the DELETE that ends an MCP session."""

from __future__ import annotations

import pytest

from gatekeeper.realip import RealIpMiddleware
from gatekeeper.server import SessionReaper


async def _client_seen(trusted, peer, headers):
    seen = {}

    async def app(scope, receive, send):
        seen["client"] = scope["client"]

    await RealIpMiddleware(app, trusted)(
        {"type": "http", "client": (peer, 5000), "headers": headers}, None, None
    )
    return seen["client"][0]


@pytest.mark.parametrize(
    ("trusted", "peer", "headers", "expected"),
    [
        # A trusted proxy's X-Real-IP names the caller.
        (["172.16.0.0/12"], "172.16.29.1", [(b"x-real-ip", b"10.10.110.102")], "10.10.110.102"),
        (["*"], "172.16.29.1", [(b"x-real-ip", b"10.10.110.102")], "10.10.110.102"),
        # Anyone else's is ignored, so a caller cannot pick its own address.
        (["172.16.0.0/12"], "10.10.110.7", [(b"x-real-ip", b"1.2.3.4")], "10.10.110.7"),
        # Unset means uvicorn's default: only 127.0.0.1.
        (None, "172.16.29.1", [(b"x-real-ip", b"1.2.3.4")], "172.16.29.1"),
        (None, "127.0.0.1", [(b"x-real-ip", b"1.2.3.4")], "1.2.3.4"),
        # X-Forwarded-For, already applied by uvicorn, wins.
        (
            ["*"],
            "10.10.110.102",
            [(b"x-forwarded-for", b"10.10.110.102"), (b"x-real-ip", b"1.2.3.4")],
            "10.10.110.102",
        ),
        # Not an address: ignored.
        (["*"], "172.16.29.1", [(b"x-real-ip", b"<script>")], "172.16.29.1"),
    ],
)
async def test_x_real_ip_counts_only_from_a_trusted_proxy(trusted, peer, headers, expected):
    assert await _client_seen(trusted, peer, headers) == expected


class _Notifier:
    def __init__(self) -> None:
        self.forgotten: list[str] = []

    def forget(self, session_id: str) -> None:
        self.forgotten.append(session_id)


async def test_a_delete_on_mcp_forgets_the_session():
    notifier = _Notifier()

    async def app(scope, receive, send):
        pass

    await SessionReaper(app, notifier=notifier)(
        {
            "type": "http",
            "method": "DELETE",
            "path": "/mcp",
            "headers": [(b"mcp-session-id", b"abc123")],
        },
        None,
        None,
    )
    assert notifier.forgotten == ["abc123"]
