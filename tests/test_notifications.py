"""The catalog notifier in isolation.

`test_mcp_live_catalog.py` proves the notification reaches a real client
over a real socket. These tests cover the parts that are awkward to reach
that way: which writes announce a change at all, and what keeps the map of
tracked sessions from growing without bound.
"""

from __future__ import annotations

import asyncio

import yaml

from gatekeeper.audit import AuditLog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.notifications import MAX_TRACKED_SESSIONS, CatalogNotifier
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore


class _FakeSession:
    """Stands in for the SDK's per-request `ServerSession`."""

    def __init__(self) -> None:
        self.sent = 0

    async def send_tool_list_changed(self) -> None:
        self.sent += 1


class _FakeRequest:
    def __init__(self, session_id: str | None) -> None:
        self.headers = {} if session_id is None else {"mcp-session-id": session_id}


async def _settle() -> None:
    """Let the notifier's scheduled send run to completion.

    `tool_catalog_changed()` deliberately does not await anything -- it
    hands the send to the event loop and returns, so an admin write never
    waits on a client. That means a test has to yield a few times before
    the delivery it triggered has happened.
    """
    for _ in range(20):
        await asyncio.sleep(0)


class _FakeCtx:
    def __init__(self, session_id: str | None, session: object | None = None) -> None:
        self.request = _FakeRequest(session_id)
        self.session = session if session is not None else _FakeSession()


# -- Tracking ---------------------------------------------------------------


def test_a_session_without_an_id_is_not_tracked():
    """2026-07-28 requests are self-contained and carry no session id, and

    neither does stdio. Both have no standalone channel to push onto -- at
    that era the `subscriptions/listen` stream carries the change instead,
    so tracking them would only build a map of things that cannot be sent
    to.
    """
    notifier = CatalogNotifier()
    notifier.track(_FakeCtx(None))
    assert notifier.tracked_sessions == 0


def test_tracking_the_same_session_twice_keeps_one_entry():
    notifier = CatalogNotifier()
    session = _FakeSession()
    notifier.track(_FakeCtx("abc", session))
    notifier.track(_FakeCtx("abc", session))
    assert notifier.tracked_sessions == 1


def test_a_terminated_session_is_forgotten():
    """`DELETE /mcp` is the one moment a client says it is done."""
    notifier = CatalogNotifier()
    notifier.track(_FakeCtx("abc"))
    notifier.forget("abc")
    assert notifier.tracked_sessions == 0


def test_the_map_is_bounded_and_evicts_the_least_recently_active():
    """A client that vanishes without a DELETE leaves an entry behind; there

    is no close hook for that. The bound is what keeps a reconnect loop from
    growing the map forever, and evicting by activity is what keeps it from
    dropping a session that is still in use.
    """
    notifier = CatalogNotifier()
    live = _FakeSession()
    notifier.track(_FakeCtx("first", live))
    for index in range(MAX_TRACKED_SESSIONS + 10):
        notifier.track(_FakeCtx(f"session-{index}"))
        # The oldest session keeps working, so it keeps its place.
        notifier.track(_FakeCtx("first", live))

    assert notifier.tracked_sessions == MAX_TRACKED_SESSIONS
    asyncio.run(notifier.broadcast())
    assert live.sent == 1, "the continuously active session was evicted"


async def test_broadcast_reaches_every_tracked_session():
    notifier = CatalogNotifier()
    sessions = [_FakeSession() for _ in range(3)]
    for index, session in enumerate(sessions):
        notifier.track(_FakeCtx(f"s{index}", session))

    await notifier.broadcast()

    assert [session.sent for session in sessions] == [1, 1, 1]


async def test_a_failing_session_is_dropped_and_does_not_stop_the_others():
    class _Broken(_FakeSession):
        async def send_tool_list_changed(self) -> None:
            raise RuntimeError("stream is gone")

    notifier = CatalogNotifier()
    broken, healthy = _Broken(), _FakeSession()
    notifier.track(_FakeCtx("broken", broken))
    notifier.track(_FakeCtx("healthy", healthy))

    await notifier.broadcast()

    assert healthy.sent == 1
    assert notifier.tracked_sessions == 1


def test_a_change_before_the_loop_is_bound_is_not_an_error():
    """Config writes happen at startup too (and in every test that never

    builds an app). A catalog change with nobody listening must not raise
    -- an admin write does not depend on an agent being connected.
    """
    CatalogNotifier().tool_catalog_changed()


async def test_a_change_is_delivered_when_the_loop_is_bound():
    notifier = CatalogNotifier()
    notifier.bind_loop()
    session = _FakeSession()
    notifier.track(_FakeCtx("abc", session))

    notifier.tool_catalog_changed()
    await _settle()

    assert session.sent == 1


# -- Which writes announce ---------------------------------------------------


def _store(tier1, catalog, tmp_path):
    token = generate_token()
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "agent",
                        "role": "agent",
                        "token_hash": hash_token(token),
                        "tools": ["demo.show"],
                        "scopes": ["stack:*"],
                    },
                    {
                        "id": "boss",
                        "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [],
                        "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identity_store = load_identities(str(identities_path))
    audit = AuditLog(str(tmp_path / "logs-notify"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    store = ConfigStore(
        service=service,
        identities=identity_store,
        audit=audit,
        tools_path=str(tmp_path / "tools.yaml"),
        identities_path=str(identities_path),
    )
    return service, store, identity_store


async def test_every_catalog_write_announces_a_change(tier1, catalog, tmp_path):
    """One assertion per mutation an agent's tool list can turn on.

    Enumerated rather than spot-checked: a write that silently skips the
    announcement is exactly the bug this exists to prevent, and it is
    invisible from the write's own result.
    """
    service, store, identity_store = _store(tier1, catalog, tmp_path)
    service.catalog_notifier.bind_loop()
    session = _FakeSession()
    service.catalog_notifier.track(_FakeCtx("abc", session))

    async def announcements_after(action) -> int:
        before = session.sent
        action()
        await _settle()
        return session.sent - before

    spec = dict(catalog.raw[0])
    spec["id"] = "demo.created"
    spec.pop("versions", None)

    assert await announcements_after(
        lambda: store.save_tool(spec, actor="admin", rev=store.tools_revision())
    ), "tool_create"
    assert await announcements_after(
        lambda: store.set_tool_enabled(
            "demo.created", True, actor="admin", rev=store.tools_revision()
        )
    ), "tool_enable"
    assert await announcements_after(
        lambda: store.set_tool_enabled(
            "demo.created", False, actor="admin", rev=store.tools_revision()
        )
    ), "tool_disable"
    assert await announcements_after(
        lambda: store.delete_tool("demo.created", actor="admin", rev=store.tools_revision())
    ), "tool_delete"

    existing = identity_store.identities["agent"]
    assert await announcements_after(
        lambda: store.save_identity(
            identity_id="agent",
            role="agent",
            tools=list(existing.tools),
            scopes=list(existing.scopes),
            actor="admin",
            rev=store.identities_revision(),
            replaces="agent",
        )
    ), "grant_set"


async def test_a_tier1_reload_announces_a_change(tier1, catalog, tmp_path):
    """A deployed toolkit proposal and a SIGHUP both land in

    `reload_config`, and both can change which tools load at all.
    """
    service, store, _identities = _store(tier1, catalog, tmp_path)
    service.catalog_notifier.bind_loop()
    session = _FakeSession()
    service.catalog_notifier.track(_FakeCtx("abc", session))

    # `_store` has not written tools.yaml yet; reload_config needs one.
    spec = dict(catalog.raw[0])
    spec["id"] = "demo.reloaded"
    spec.pop("versions", None)
    store.save_tool(spec, actor="admin", rev=store.tools_revision())
    await _settle()
    before = session.sent

    error = service.reload_config(
        toolkits_path=str(tmp_path / "toolkits.yaml"),
        tools_path=str(tmp_path / "tools.yaml"),
        identities_path=str(tmp_path / "identities.yaml"),
    )
    assert error is None, error
    await _settle()

    assert session.sent == before + 1


# -- Mount configuration -----------------------------------------------------


def test_the_agent_mount_retains_sessions_and_reaps_idle_ones(tier1, catalog, tmp_path):
    """Two settings that only make sense together.

    `/mcp` keeps sessions so a 2025-era client's standalone SSE stream has
    somewhere to live -- and a retained session that is never terminated is
    a transport and a parked task leaked for the life of a container that
    runs for months. The reaper is not optional decoration; asserting it
    here is what keeps a future edit from dropping one half.
    """
    from gatekeeper.server import SESSION_IDLE_TIMEOUT_SECONDS, build_app

    service, _config_store, identity_store = _store(tier1, catalog, tmp_path)
    app = build_app(
        service=service,
        identities=identity_store,
        audit=AuditLog(str(tmp_path / "logs-mount")),
    )
    manager = None
    for route in app.routes:
        endpoint = getattr(route, "endpoint", None)
        manager = getattr(endpoint, "session_manager", None)
        if manager is not None and getattr(route, "path", "") == "/mcp":
            break
    assert manager is not None, "no session manager behind /mcp"
    assert manager.stateless is False
    assert manager.session_idle_timeout == SESSION_IDLE_TIMEOUT_SECONDS
