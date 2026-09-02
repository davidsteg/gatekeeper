"""Telling already-connected agents that the tool catalog changed.

The server side of a catalog change has always been live: `ConfigStore`
reloads `tools.yaml` synchronously after every write, so the very next
`tools/list` on an existing connection already contains the new tool. What
was missing is the other half of the handshake -- **nothing told the client
to ask again.** Most MCP clients fetch `tools/list` once when the session is
established and keep that list for the session's lifetime, which is why a
new tool only showed up after a reconnect.

MCP's mechanism for invalidating that cache is
`notifications/tools/list_changed`, and how it reaches a client depends on
which protocol era the client speaks. This module owns both routes, so the
rest of gatekeeper has exactly one thing to call
(`CatalogNotifier.tool_catalog_changed()`) and never has to know which:

* **2026-07-28 and later.** There is no standing server stream at this era.
  A client opts in by sending `subscriptions/listen`, whose *response* is
  the stream, and the server fans changes out on a `SubscriptionBus`. This
  works on `/mcp` exactly as it is -- a listen stream is a long-lived POST,
  so it needs no session id and no retained transport. Serving the method
  is also what makes `tools.listChanged` true in `server/discover`: at this
  era the SDK derives the flag from whether `subscriptions/listen` is
  registered, not from a hand-set option.

* **2025-11-25 and earlier.** The notification rides the standalone SSE
  stream the client opens with `GET /mcp`, which only exists if the server
  retains the session between requests -- hence `stateless_http=False` on
  `/mcp` (see `server.build_app`). Here the `listChanged` flag in the
  `initialize` response comes from `NotificationOptions(tools_changed=True)`.
  Sessions are tracked by the `Mcp-Session-Id` the transport assigned, so a
  change reaches *every* live session, not just the one whose admin call
  caused it.

Delivery is best-effort in both directions and deliberately so: a client
that has gone away, or one that never opened a stream, must not turn an
admin write into an error. The notification carries no payload -- it says
"your list is stale", not what changed -- so broadcasting it to every
session discloses nothing about another identity's catalog.
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from typing import Any

from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler, ToolsListChanged

logger = logging.getLogger("gatekeeper")

#: Upper bound on tracked handshake-era sessions. A session is forgotten
#: when the client terminates it (`DELETE /mcp`), but a client that simply
#: vanishes leaves its entry behind -- there is no close hook for that.
#: The map is therefore an LRU: every message on a session moves it to the
#: front, so the entries evicted first are the ones that have been silent
#: longest, and an evicted-but-live session re-registers on its next
#: message. Sized far above any realistic agent count, small enough that a
#: reconnect loop cannot grow it without bound.
MAX_TRACKED_SESSIONS = 512

#: The transport header carrying the session id in the handshake-era
#: Streamable HTTP transport. Present on every request after `initialize`.
SESSION_ID_HEADER = "mcp-session-id"


class CatalogNotifier:
    """Fans `notifications/tools/list_changed` out to every live connection.

    One instance belongs to one MCP mount. `server.build_mcp_server` builds
    it, hands its `listen_handler` to the SDK `Server` and its
    `notification_options` to the `initialize` reply, and `build_app` binds
    it to the event loop in the app's lifespan.
    """

    def __init__(self) -> None:
        self._bus = InMemorySubscriptionBus()
        self._listen_handler = ListenHandler(self._bus)
        #: session id -> the `ServerSession` whose standalone channel serves
        #: it. Ordered: the front is the most recently active session.
        self._sessions: OrderedDict[str, Any] = OrderedDict()
        self._loop: asyncio.AbstractEventLoop | None = None
        #: Strong references to the in-flight send tasks. The event loop
        #: keeps only weak ones, so a task nobody holds can be collected
        #: mid-send -- and the notification it was carrying disappears with
        #: it. Entries remove themselves when the send finishes.
        self._sending: set[asyncio.Task[None]] = set()

    # -- Wiring ------------------------------------------------------------

    @property
    def listen_handler(self) -> ListenHandler:
        """The `subscriptions/listen` handler to pass as `on_subscriptions_listen`.

        Registering it is what advertises `tools.listChanged` at 2026-07-28+;
        the flag and the delivery mechanism are the same fact there.
        """
        return self._listen_handler

    @property
    def notification_options(self) -> NotificationOptions:
        """The handshake-era capability advertisement.

        Only `tools_changed`: gatekeeper serves no prompts or resources, so
        claiming their list can change would be advertising an empty
        promise.
        """
        return NotificationOptions(tools_changed=True)

    def bind_loop(self) -> None:
        """Capture the running event loop; call once from the app lifespan.

        Catalog writes arrive on whichever thread Starlette ran the console
        handler on, while the notification has to be sent on the loop that
        owns the MCP transports. Without a bound loop
        `tool_catalog_changed()` degrades to a debug log rather than
        raising -- a write must never fail because nobody is listening.
        """
        self._loop = asyncio.get_running_loop()

    # -- Session tracking (handshake era) ----------------------------------

    def track(self, ctx: Any) -> None:
        """Remember the connection this request arrived on, if it has one.

        Called from the `tools/list` handler and from the
        `notifications/initialized` handler: between them every client that
        could be caching a tool list has registered by the time it has one.
        Sessions without an id (stateless mounts, stdio, and the 2026-07-28
        single-exchange wire) are skipped -- they have no standalone
        channel, and at that era the listen stream carries the change.
        """
        session_id = _session_id_of(ctx)
        if session_id is None:
            return
        session = getattr(ctx, "session", None)
        if session is None:  # pragma: no cover - defensive
            return
        self._sessions[session_id] = session
        self._sessions.move_to_end(session_id, last=False)
        while len(self._sessions) > MAX_TRACKED_SESSIONS:
            evicted, _ = self._sessions.popitem(last=True)
            logger.debug("Forgetting least recently active MCP session %s", evicted[:8])

    def forget(self, session_id: str) -> None:
        """Drop a session the client terminated (`DELETE /mcp`)."""
        self._sessions.pop(session_id, None)

    @property
    def tracked_sessions(self) -> int:
        """How many handshake-era sessions are currently tracked."""
        return len(self._sessions)

    # -- Sending -----------------------------------------------------------

    def tool_catalog_changed(self) -> None:
        """Announce a catalog change. Safe to call from any thread.

        Synchronous by design: every caller is a configuration write in
        `store.py` / `service.py`, none of which is async. The actual send
        is scheduled on the MCP event loop and never awaited -- an admin
        write completes on its own terms whether or not a client is there
        to hear about it.
        """
        loop = self._loop
        if loop is None:
            logger.debug("Tool catalog changed before the event loop was bound; no clients yet")
            return
        try:
            loop.call_soon_threadsafe(self._schedule)
        except RuntimeError:  # loop already closed (shutdown, or a torn-down test app)
            logger.debug("Tool catalog changed after the event loop closed; nothing to notify")

    def _schedule(self) -> None:
        # Runs on the MCP loop: `create_task` is legal here and nowhere else.
        task = asyncio.get_running_loop().create_task(self.broadcast())
        self._sending.add(task)
        task.add_done_callback(self._sending.discard)

    async def broadcast(self) -> None:
        """Deliver the notification on both routes. Never raises."""
        try:
            await self._bus.publish(ToolsListChanged())
        except Exception:  # boundary: one bad listen stream must not stop the rest
            logger.exception("Publishing tools/list_changed to listen streams failed")

        for session_id, session in list(self._sessions.items()):
            try:
                await session.send_tool_list_changed()
            except Exception:
                # A closed standalone stream is already swallowed by the
                # SDK; anything reaching here is a session worth dropping
                # rather than retrying on every future change.
                logger.debug("Dropping MCP session %s: %s", session_id[:8], "notify failed")
                self._sessions.pop(session_id, None)


def _session_id_of(ctx: Any) -> str | None:
    """The transport's session id for this message, read off the HTTP request.

    `ServerRequestContext` exposes the message's Starlette request but not
    the connection object behind it, and the session id is on the request as
    the `Mcp-Session-Id` header the client echoes after `initialize` -- so
    this is the public route to the one key that identifies a connection
    across requests.
    """
    request = getattr(ctx, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    session_id = headers.get(SESSION_ID_HEADER)
    return session_id or None


__all__ = ["MAX_TRACKED_SESSIONS", "SESSION_ID_HEADER", "CatalogNotifier"]
