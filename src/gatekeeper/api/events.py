"""Live updates for the console: `GET /api/v1/events`, a Server-Sent Events
stream that tells an open `/app` page *that* something changed, so it can
refetch at once instead of waiting for its next poll (1.3.0).

Every change gatekeeper makes is written to the audit log first -- a tool
call, a proposal from `/admin/mcp`, a decision, a sign-in, a credential
rotation -- so `AuditLog.write` is the one place to hear about all of them.
`EventHub` listens there and turns each record into *topics* (`requests`,
`audit`, `tools`, ...), never the record itself: the stream carries no
agent-supplied text, no IDs and no values. The browser maps a topic to the
queries it already has and refetches them through the normal, typed,
authenticated reads. A stream that drops loses nothing, because the page
refetches everything when it reconnects.

What the stream may not do:

* outlive its session -- it re-resolves the session cookie on every
  heartbeat and ends when the session has gone (sign-out, expiry, a
  password change, the identity deleted);
* run forever -- it closes after `STREAM_SECONDS` and the browser
  reconnects, which also re-checks the session from scratch;
* hold a server shutdown hostage -- `gatekeeper serve` gives open
  requests `timeout_graceful_shutdown` seconds, after which uvicorn cancels
  them (a stream never finishes on its own);
* grow without bound -- at most `MAX_SUBSCRIBERS` streams at once, and a
  subscriber that does not keep up is sent "everything changed" once
  instead of an ever longer queue.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from collections.abc import AsyncIterator
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import StreamingResponse

from .deps import ApiContext, ApiError, ctx, require_viewer
from .session import SESSION_COOKIE, Session

logger = logging.getLogger(__name__)

#: Seconds between heartbeats: a comment line that keeps reverse proxies
#: from timing the stream out, and the moment the session is re-checked.
HEARTBEAT_SECONDS = 15.0

#: A stream closes after this long and the browser reconnects.
STREAM_SECONDS = 10 * 60

#: Changes arriving within this window go out as one event: a burst of
#: tool calls must not become a burst of refetches in every open tab.
COALESCE_SECONDS = 0.5

MAX_SUBSCRIBERS = 64

#: The browser's reconnect delay after a dropped stream, in milliseconds.
RETRY_MS = 3000

#: Every topic the console knows; "everything changed" is all of them.
ALL_TOPICS = frozenset(
    {"audit", "overview", "stats", "requests", "tools", "identities", "credentials", "toolkits"}
)

_QUEUE_LIMIT = 64


def topics_for(record: dict[str, Any]) -> frozenset[str]:
    """Which console queries an audit record makes stale. Anything new in
    the log changes the audit page and the overview's feed; the kind and
    action narrow the rest. An approval or a deploy can change anything,
    and an action this table does not know refreshes everything rather
    than guessing which page it belongs to."""
    base = {"audit", "overview"}
    kind = record.get("kind")
    action = str(record.get("action") or "")
    if kind == "call":
        return frozenset(base | {"stats"})
    if kind == "ui_oauth":
        return frozenset(base | {"credentials"})
    if kind != "admin_change":
        return frozenset(base)
    base.add("stats")
    if action == "pending_approve" or action.endswith("_deploy"):
        return ALL_TOPICS
    if action.startswith("pending_") or action.endswith("_propose") or action == "toolkit_reject":
        return frozenset(base | {"requests"})
    if action.startswith("tool_") or action == "dangling_grant":
        return frozenset(base | {"tools", "identities"})
    if action.startswith(("identity_", "token_", "password_")):
        return frozenset(base | {"identities", "tools"})
    if action.startswith("credential_"):
        return frozenset(base | {"credentials", "toolkits"})
    return ALL_TOPICS


class _Subscriber:
    __slots__ = ("loop", "queue", "overflowed")

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.queue: asyncio.Queue[frozenset[str]] = asyncio.Queue(_QUEUE_LIMIT)
        self.overflowed = False

    def offer(self, topics: frozenset[str]) -> None:
        # Runs on the subscriber's loop (via call_soon_threadsafe).
        try:
            self.queue.put_nowait(topics)
        except asyncio.QueueFull:
            # Behind by a whole queue: drop it and say "everything".
            while not self.queue.empty():
                self.queue.get_nowait()
            self.queue.put_nowait(ALL_TOPICS)


class EventHub:
    """Fans audit records out to open streams, from whatever thread wrote
    them (the console's sync handlers run in a thread pool)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: set[_Subscriber] = set()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def publish(self, record: dict[str, Any]) -> None:
        """`AuditLog` listener. Never raises: a failure to notify a browser
        must not fail the write that was being audited."""
        try:
            topics = topics_for(record)
            with self._lock:
                targets = list(self._subscribers)
            for sub in targets:
                try:
                    sub.loop.call_soon_threadsafe(sub.offer, topics)
                except RuntimeError:  # Its loop has closed.
                    pass
        except Exception:  # pragma: no cover - defensive
            logger.exception("live-update publish failed")

    def subscribe(self) -> _Subscriber | None:
        with self._lock:
            if len(self._subscribers) >= MAX_SUBSCRIBERS:
                return None
            sub = _Subscriber(asyncio.get_running_loop())
            self._subscribers.add(sub)
            return sub

    def unsubscribe(self, sub: _Subscriber) -> None:
        with self._lock:
            self._subscribers.discard(sub)


def _event(name: str, data: dict[str, Any]) -> str:
    return f"event: {name}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


async def stream(
    sub: _Subscriber,
    *,
    still_signed_in: Any,
    disconnected: Any,
    heartbeat: float | None = None,
    lifetime: float | None = None,
    coalesce: float | None = None,
) -> AsyncIterator[str]:
    """The body of one stream. `still_signed_in()` re-checks the session,
    `disconnected()` asks whether the browser went away."""
    heartbeat = HEARTBEAT_SECONDS if heartbeat is None else heartbeat
    lifetime = STREAM_SECONDS if lifetime is None else lifetime
    coalesce = COALESCE_SECONDS if coalesce is None else coalesce
    loop = asyncio.get_running_loop()
    deadline = loop.time() + lifetime
    yield f"retry: {RETRY_MS}\n\n"
    yield _event("ready", {})
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return
        try:
            topics = set(await asyncio.wait_for(sub.queue.get(), min(heartbeat, remaining)))
        except TimeoutError:
            if await disconnected() or not still_signed_in():
                return
            yield ": ping\n\n"
            continue
        # Gather whatever else lands in the next moment into one event.
        await asyncio.sleep(coalesce)
        while not sub.queue.empty():
            topics |= sub.queue.get_nowait()
        if not still_signed_in():
            return
        yield _event("change", {"topics": sorted(topics)})


def register_event_routes(app: FastAPI, context: ApiContext | None) -> None:
    """`GET /events` on the API app. `context=None` (schema generation)
    registers the route without a hub behind it."""
    hub = EventHub()
    if context is not None:
        context.audit.add_listener(hub.publish)
    app.state.events = hub

    @app.get(
        "/events",
        tags=["session"],
        response_class=StreamingResponse,
        responses={
            200: {
                "content": {"text/event-stream": {}},
                "description": "`change` events naming stale topics, never data.",
            },
            503: {"description": "Too many open streams."},
        },
    )
    async def events(
        request: Request,
        session: Session = Depends(require_viewer),
        context: ApiContext = Depends(ctx),
    ) -> StreamingResponse:
        """Server-Sent Events: `event: change` with `{"topics": [...]}` when
        something an open console page shows has changed. Topics only --
        the page refetches through the ordinary reads."""
        sub = hub.subscribe()
        if sub is None:
            raise ApiError(503, "Too many live-update streams are open; the console falls back to polling.")
        sid = request.cookies.get(SESSION_COOKIE)

        def still_signed_in() -> bool:
            return context.sessions.resolve(sid) == session

        async def body() -> AsyncIterator[str]:
            try:
                async for chunk in stream(
                    sub, still_signed_in=still_signed_in, disconnected=request.is_disconnected
                ):
                    yield chunk
            finally:
                hub.unsubscribe(sub)

        return StreamingResponse(
            body(),
            media_type="text/event-stream",
            # nginx and friends buffer a response unless told not to, and a
            # buffered event stream delivers nothing until it ends.
            headers={"X-Accel-Buffering": "no"},
        )
