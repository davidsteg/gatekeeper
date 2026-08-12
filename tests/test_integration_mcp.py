"""Ende-zu-Ende ueber echtes MCP.

Faehrt die vollstaendige ASGI-Anwendung in-process hoch und spricht sie mit dem
offiziellen MCP-Client an -- inklusive Auth-Middleware, Streamable-HTTP-Transport
und Protokoll-Handshake. Die Unit-Tests pruefen die Regeln; dieser Test prueft,
dass ein Agent sie ueberhaupt erreicht.
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
    """Erzeugt jeweils eine frische Anwendung.

    Der Streamable-HTTP-Session-Manager laesst sich pro Instanz nur einmal
    starten. Fuer den Betrieb ist das folgenlos -- uvicorn startet genau eine
    Instanz --, ein Test mit zwei Verbindungen braucht aber zwei Anwendungen.
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
    """Ein verbundener MCP-Client mit Bearer-Token.

    Der Lifespan wird hier und nicht in einer Fixture betreten: `ASGITransport`
    loest Start- und Stop-Ereignisse nicht selbst aus, und eine async-Fixture
    wuerde Auf- und Abbau in verschiedenen Tasks ausfuehren -- was die
    anyio-Cancel-Scopes des Session-Managers nicht zulassen.
    """
    async with app.router.lifespan_context(app):
        async with _http(app, token) as http:
            transport = streamable_http_client(f"{BASE}/mcp", http_client=http)
            async with Client(transport) as client:
                yield client


# -- Health und Authentifizierung ------------------------------------------


async def test_health_needs_no_token(app):
    """NFR-3: Health-Probes sind oeffentlich, verraten aber nichts."""
    async with _http(app, None) as http:
        live = await http.get("/health/live")
        startup = await http.get("/health/startup")
    assert live.status_code == 200
    assert live.json() == {"status": "live"}
    assert startup.status_code == 200
    # Keine Tool-Namen, keine Identitaeten - nur Zahlen.
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
    async with _http(app, "gk_voellig_falsch") as http:
        response = await http.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
    assert response.status_code == 401


async def test_metrics_requires_token(app, identities):
    """NFR-3a: /metrics ist nicht oeffentlich erreichbar."""
    _store, tokens = identities
    async with _http(app, None) as http:
        assert (await http.get("/metrics")).status_code == 401
    async with _http(app, tokens["full"]) as http:
        response = await http.get("/metrics")
    assert response.status_code == 200
    assert "gatekeeper_tool_calls_total" in response.text


# -- Protokoll --------------------------------------------------------------


async def test_tools_list_is_filtered_per_identity(make_app, identities):
    """FR-1.4 ueber das echte Protokoll, nicht nur ueber die Service-Schicht."""
    _store, tokens = identities

    async with connected(make_app(), tokens["full"]) as client:
        full = {t.name for t in (await client.list_tools()).tools}

    async with connected(make_app(), tokens["narrow"]) as client:
        narrow_result = await client.list_tools()
        narrow = {t.name for t in narrow_result.tools}

    assert full == {"demo.show", "demo.echo"}
    assert narrow == {"demo.show"}
    # Die Liste unterscheidet sich pro Identitaet und darf nicht geteilt werden.
    assert narrow_result.cache_scope == "private"


async def test_call_tool_succeeds(app, identities):
    _store, tokens = identities
    async with connected(app, tokens["full"]) as client:
        result = await client.call_tool("demo.show", {"stack": "media-jellyfin"})
    assert result.is_error is False
    assert "media-jellyfin" in result.content[0].text


async def test_call_tool_denial_is_opaque_over_protocol(app, identities):
    """FR-7.7 im Zusammenspiel: der Agent kann den Katalog nicht abtasten."""
    _store, tokens = identities
    async with connected(app, tokens["narrow"]) as client:
        forbidden = await client.call_tool("demo.echo", {"text": "x"})
        nonexistent = await client.call_tool("demo.gibt_es_nicht", {})

    assert forbidden.is_error and nonexistent.is_error
    assert forbidden.content[0].text == nonexistent.content[0].text


async def test_invalid_parameter_is_reported_concretely(app, identities):
    """Validierungsfehler duerfen konkret sein.

    Sie verraten nichts ueber den Katalog, sondern nur ueber die vom Agenten
    selbst gesendeten Werte -- anders als die Ablehnungen aus FR-7.7.
    """
    _store, tokens = identities
    async with connected(app, tokens["full"]) as client:
        result = await client.call_tool("demo.show", {"stack": "UNGUELTIG; rm -rf /"})
    assert result.is_error
    assert "stack" in result.content[0].text


async def test_annotations_reach_the_agent(app, identities):
    """Der Agent soll wissen, was lesend und was idempotent ist."""
    _store, tokens = identities
    async with connected(app, tokens["full"]) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}

    show = tools["demo.show"]
    assert show.annotations.read_only_hint is True
    assert show.annotations.idempotent_hint is True
    # Abgeleitete Parameter tauchen im Schema des Agenten nicht auf.
    assert set(show.input_schema["properties"]) == {"stack"}
