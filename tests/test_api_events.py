"""`GET /api/v1/events`: the console's live-update stream (1.3.0).

What matters: a change anywhere reaches an open console as a topic name
and nothing else; the stream needs a console session and ends with it;
and a burst of changes becomes one event, not one per record.

The end-to-end cases need a real socket (`httpx2.ASGITransport` collects a
whole body before returning it, and a stream never ends), so they run the
app under uvicorn on a loopback port, as `test_mcp_live_catalog.py` does.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading

import httpx2
import pytest
from api_env import API, PASSWORDS, client, make_env
from test_mcp_live_catalog import served

from gatekeeper.api import events
from gatekeeper.api.events import ALL_TOPICS, EventHub, stream, topics_for


@pytest.fixture
def env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs)


# -- Topics ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"kind": "call", "tool": "demo.show"}, {"audit", "overview", "stats"}),
        ({"kind": "ui_login"}, {"audit", "overview"}),
        ({"kind": "admin_change", "action": "pending_propose"}, {"audit", "overview", "stats", "requests"}),
        ({"kind": "admin_change", "action": "toolkit_propose"}, {"audit", "overview", "stats", "requests"}),
        ({"kind": "admin_change", "action": "pending_reject"}, {"audit", "overview", "stats", "requests"}),
        ({"kind": "admin_change", "action": "tool_update"}, {"audit", "overview", "stats", "tools", "identities"}),
        ({"kind": "admin_change", "action": "credential_rotate"}, {"audit", "overview", "stats", "credentials", "toolkits"}),
        ({"kind": "admin_change", "action": "pending_approve"}, set(ALL_TOPICS)),
        ({"kind": "admin_change", "action": "toolkit_deploy"}, set(ALL_TOPICS)),
        # An action the table does not know refreshes everything.
        ({"kind": "admin_change", "action": "something_new"}, set(ALL_TOPICS)),
    ],
)
def test_topics_for(record, expected):
    assert set(topics_for(record)) == expected


# -- The stream, without HTTP -------------------------------------------------------


async def _collect(gen, n: int) -> list[str]:
    out = []
    async for chunk in gen:
        out.append(chunk)
        if len(out) == n:
            break
    return out


async def test_a_burst_from_another_thread_becomes_one_event():
    hub = EventHub()
    sub = hub.subscribe()
    assert sub is not None

    async def never() -> bool:
        return False

    gen = stream(sub, still_signed_in=lambda: True, disconnected=never, coalesce=0.05)
    retry, ready = await _collect(gen, 2)
    assert retry.startswith("retry:") and ready.startswith("event: ready")

    def burst() -> None:
        hub.publish({"kind": "call", "tool": "demo.show", "identity": "bot", "argv": ["secret-ish"]})
        for _ in range(20):
            hub.publish({"kind": "admin_change", "action": "pending_propose", "target": "abc"})

    threading.Thread(target=burst).start()
    (change,) = await _collect(gen, 1)
    assert change.startswith("event: change\n")
    data = json.loads(change.split("data: ", 1)[1])
    assert data == {"topics": ["audit", "overview", "requests", "stats"]}
    # Topic names only: nothing from the record itself.
    assert "demo.show" not in change and "bot" not in change and "abc" not in change
    await gen.aclose()


async def test_the_stream_ends_when_the_session_does():
    hub = EventHub()
    sub = hub.subscribe()
    signed_in = {"yes": True}

    async def never() -> bool:
        return False

    gen = stream(sub, still_signed_in=lambda: signed_in["yes"], disconnected=never, heartbeat=0.05)
    await _collect(gen, 2)
    (ping,) = await _collect(gen, 1)
    assert ping == ": ping\n\n"
    signed_in["yes"] = False
    assert await _collect(gen, 1) == []


async def test_the_stream_has_a_lifetime():
    hub = EventHub()
    sub = hub.subscribe()

    async def never() -> bool:
        return False

    gen = stream(sub, still_signed_in=lambda: True, disconnected=never, heartbeat=0.05, lifetime=0.2)
    chunks = [c async for c in gen]
    assert chunks[0].startswith("retry:") and all(c == ": ping\n\n" for c in chunks[2:])


async def test_a_slow_subscriber_gets_everything_once_instead_of_a_backlog(monkeypatch):
    monkeypatch.setattr(events, "_QUEUE_LIMIT", 3)
    hub = EventHub()
    sub = hub.subscribe()
    for _ in range(10):
        sub.offer(frozenset({"audit"}))
    queued = []
    while not sub.queue.empty():
        queued.append(sub.queue.get_nowait())
    assert len(queued) <= 3 and ALL_TOPICS in queued


async def test_subscribers_are_capped(monkeypatch):
    monkeypatch.setattr(events, "MAX_SUBSCRIBERS", 2)
    hub = EventHub()
    first, second = hub.subscribe(), hub.subscribe()
    assert first is not None and second is not None
    assert hub.subscribe() is None
    hub.unsubscribe(first)
    assert hub.subscribe() is not None


def test_a_failing_listener_never_breaks_the_audit_write(env):
    def broken(_record):
        raise RuntimeError("boom")

    env["audit"].add_listener(broken)
    env["audit"].write({"kind": "call", "tool": "demo.show", "outcome": "ok"})
    with open(env["audit_path"], encoding="utf-8") as handle:
        assert any('"demo.show"' in line for line in handle)


# -- Over HTTP ------------------------------------------------------------------------


async def test_needs_a_console_session(env):
    async with client(env["app"]) as c:
        assert (await c.get(f"{API}/events")).status_code == 401
        response = await c.get(
            f"{API}/events", headers={"Authorization": f"Bearer {env['tokens']['bot']}"}
        )
        assert response.status_code == 401


@contextlib.asynccontextmanager
async def _signed_in(base: str, identity: str = "eye"):
    async with httpx2.AsyncClient(base_url=base, timeout=30.0) as http:
        response = await http.post(
            f"{API}/session", json={"identity": identity, "password": PASSWORDS[identity]}
        )
        assert response.status_code == 200, response.text
        yield http


async def _next_event(lines, name: str) -> dict:
    current = None
    async for line in lines:
        if line.startswith("event: "):
            current = line[len("event: "):]
        elif line.startswith("data: ") and current == name:
            return json.loads(line[len("data: "):])
    raise AssertionError(f"stream ended before a {name!r} event")


async def test_a_proposal_reaches_an_open_console(env):
    async with served(env["app"]) as base, _signed_in(base) as http:
        async with http.stream("GET", f"{API}/events") as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            assert response.headers["x-accel-buffering"] == "no"
            lines = response.aiter_lines()
            await asyncio.wait_for(_next_event(lines, "ready"), 5)
            # What `admin.tool_enable` does for a write-category tool, from
            # a worker thread as the MCP handler would.
            await asyncio.to_thread(
                env["pending"].propose,
                action="tool_enable", actor="root", payload={"id": "demo.echo"},
                base_rev=env["store"].tool_revision("demo.echo"),
            )
            data = await asyncio.wait_for(_next_event(lines, "change"), 5)
    assert "requests" in data["topics"]


async def test_signing_out_ends_the_stream(env, monkeypatch):
    monkeypatch.setattr(events, "HEARTBEAT_SECONDS", 0.1)
    async with served(env["app"]) as base, _signed_in(base) as http:
        info = (await http.get(f"{API}/session")).json()
        async with http.stream("GET", f"{API}/events") as response:
            lines = response.aiter_lines()
            await asyncio.wait_for(_next_event(lines, "ready"), 5)
            # Sign out on a second connection with the same cookie.
            async with httpx2.AsyncClient(base_url=base, cookies=http.cookies, timeout=30.0) as other:
                gone = await other.delete(f"{API}/session", headers={"X-CSRF-Token": info["csrf"]})
                assert gone.status_code == 204

            async def drain() -> None:
                async for _ in lines:
                    pass

            await asyncio.wait_for(drain(), 5)


async def test_an_open_stream_does_not_hold_up_shutdown(env):
    # `gatekeeper serve` passes this grace to uvicorn; without one, uvicorn
    # waits for every open request to finish, and a stream never does.
    import socket
    import time

    import uvicorn

    from gatekeeper.__main__ import SHUTDOWN_GRACE_SECONDS

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(
        env["app"], log_level="warning", timeout_graceful_shutdown=SHUTDOWN_GRACE_SECONDS,
    ))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        while not server.started:
            await asyncio.sleep(0.01)
        async with _signed_in(base) as http, http.stream("GET", f"{API}/events") as response:
            await asyncio.wait_for(_next_event(response.aiter_lines(), "ready"), 5)
            started = time.monotonic()
            server.should_exit = True
            await asyncio.wait_for(task, SHUTDOWN_GRACE_SECONDS + 5)
            assert time.monotonic() - started < SHUTDOWN_GRACE_SECONDS + 2
    finally:
        server.should_exit = True
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, 10)
        sock.close()
