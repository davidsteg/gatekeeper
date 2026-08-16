"""End-to-end over real MCP.

Brings up the complete ASGI application in-process and talks to it with the
official MCP client -- including auth middleware, Streamable HTTP transport
and protocol handshake. The unit tests check the rules; this test checks
that an agent can reach them at all.
"""

from __future__ import annotations

import contextlib

import httpx2
import pytest
from mcp.client.client import Client, streamable_http_client

from gatekeeper.audit import AuditLog
from gatekeeper.server import build_app
from gatekeeper.service import Service

BASE = "http://gatekeeper.test"


@pytest.fixture
def make_app(tier1, catalog, identities, tmp_path):
    """Creates a fresh application each time.

    The Streamable HTTP session manager can only be started once per
    instance. For operation this is irrelevant -- uvicorn starts exactly one
    instance -- but a test with two connections needs two applications.
    """

    def _build():
        store, _tokens = identities
        audit = AuditLog(str(tmp_path / "logs-int"))
        service = Service(tier1=tier1, catalog=catalog, audit=audit)
        return build_app(service=service, identities=store, audit=audit)

    return _build


@pytest.fixture
def app(make_app):
    return make_app()


def _http(app, token: str | None) -> httpx2.AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url=BASE,
        headers=headers,
        timeout=30.0,
    )


@contextlib.asynccontextmanager
async def connected(app, token: str):
    """A connected MCP client with bearer token.

    The lifespan is entered here and not in a fixture: `ASGITransport`
    does not trigger start and stop events itself, and an async fixture
    would run setup and teardown in different tasks -- which the
    anyio cancel scopes of the session manager do not allow.
    """
    async with app.router.lifespan_context(app):
        async with _http(app, token) as http:
            transport = streamable_http_client(f"{BASE}/mcp", http_client=http)
            async with Client(transport) as client:
                yield client


# -- Health and authentication ------------------------------------------


async def test_health_needs_no_token(app):
    """NFR-3: health probes are public but reveal nothing."""
    async with _http(app, None) as http:
        live = await http.get("/health/live")
        startup = await http.get("/health/startup")
    assert live.status_code == 200
    assert live.json() == {"status": "live"}
    assert startup.status_code == 200
    # No tool names, no identities - only numbers.
    assert set(startup.json()) == {"status", "tools", "disabled_by_tier1"}


async def test_mcp_without_token_is_401(app):
    """FR-2.3"""
    async with _http(app, None) as http:
        response = await http.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"


async def test_mcp_with_wrong_token_is_401(app):
    async with _http(app, "gk_completely_wrong") as http:
        response = await http.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
    assert response.status_code == 401


async def test_metrics_requires_token(app, identities):
    """NFR-3a: /metrics is not publicly reachable."""
    _store, tokens = identities
    async with _http(app, None) as http:
        assert (await http.get("/metrics")).status_code == 401
    async with _http(app, tokens["full"]) as http:
        response = await http.get("/metrics")
    assert response.status_code == 200
    assert "gatekeeper_tool_calls_total" in response.text


# -- Protocol --------------------------------------------------------------


async def test_tools_list_is_filtered_per_identity(make_app, identities):
    """FR-1.4 over the real protocol, not just via the service layer."""
    _store, tokens = identities

    async with connected(make_app(), tokens["full"]) as client:
        full = {t.name for t in (await client.list_tools()).tools}

    async with connected(make_app(), tokens["narrow"]) as client:
        narrow_result = await client.list_tools()
        narrow = {t.name for t in narrow_result.tools}

    assert full == {"demo.show", "demo.echo"}
    assert narrow == {"demo.show"}
    # The list differs per identity and must not be shared.
    assert narrow_result.cache_scope == "private"


async def test_call_tool_succeeds(app, identities):
    _store, tokens = identities
    async with connected(app, tokens["full"]) as client:
        result = await client.call_tool("demo.show", {"stack": "media-jellyfin"})
    assert result.is_error is False
    assert "media-jellyfin" in result.content[0].text


async def test_call_tool_denial_is_opaque_over_protocol(app, identities):
    """FR-7.7 in combination: the agent cannot probe the catalog."""
    _store, tokens = identities
    async with connected(app, tokens["narrow"]) as client:
        forbidden = await client.call_tool("demo.echo", {"text": "x"})
        nonexistent = await client.call_tool("demo.does_not_exist", {})

    assert forbidden.is_error and nonexistent.is_error
    assert forbidden.content[0].text == nonexistent.content[0].text


async def test_invalid_parameter_is_reported_concretely(app, identities):
    """Validation errors may be specific.

    They reveal nothing about the catalog, only about the values
    sent by the agent itself -- unlike the denials from FR-7.7.
    """
    _store, tokens = identities
    async with connected(app, tokens["full"]) as client:
        result = await client.call_tool("demo.show", {"stack": "INVALID; rm -rf /"})
    assert result.is_error
    assert "stack" in result.content[0].text


async def test_annotations_reach_the_agent(app, identities):
    """The agent should know what is read-only and what is idempotent."""
    _store, tokens = identities
    async with connected(app, tokens["full"]) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}

    show = tools["demo.show"]
    assert show.annotations.read_only_hint is True
    assert show.annotations.idempotent_hint is True
    # Derived parameters do not appear in the agent's schema.
    assert set(show.input_schema["properties"]) == {"stack"}