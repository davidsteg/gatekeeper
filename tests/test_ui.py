"""Das Betriebs-UI (nur lesend).

Der Schwerpunkt liegt nicht auf dem Aussehen, sondern auf drei Eigenschaften,
die das UI nicht verletzen darf:

* Die Sitzung oeffnet ausschliesslich `/ui`. Wuerde sie auch fuer `/mcp`
  gelten, koennte eine beliebige Webseite ueber das automatisch mitgeschickte
  Cookie Tools auf dem Host ausfuehren lassen.
* Konsolenpasswort und API-Token sind getrennte Nachweise. Keiner von beiden
  darf dort wirken, wo der andere gilt -- sonst waere die Trennung eine
  Behauptung und ein verlorenes Geheimnis oeffnete beide Wege.
* Angezeigte Audit-Daten stammen teilweise von Agenten und sind bei
  abgelehnten Aufrufen unvalidiert. Sie muessen maskiert ankommen.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import httpx2
import pytest
import yaml

from gatekeeper.audit import AuditLog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.ui import (
    UI_PREFIX,
    LoginThrottle,
    SessionStore,
    _bucket_calls,
    has_admin,
    read_audit,
)

BASE = "http://gatekeeper.test"


#: Konsolenpasswort des Test-Admins. Lang genug fuer MIN_PASSWORD_LENGTH.
ROOT_PASSWORD = "korrektes-pferd-batterie"


@pytest.fixture
def ui_identities(tmp_path):
    """Ein Admin fuer das UI und ein Agent, der dort nichts verloren hat."""
    tokens = {"root": generate_token(), "bot": generate_token()}
    path = tmp_path / "identities-ui.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token(tokens["root"]),
                        # Zwei getrennte Nachweise: der Token spricht /mcp an,
                        # das Passwort meldet an der Konsole an.
                        "password_hash": hash_token(ROOT_PASSWORD),
                        # Ein Admin braucht keine Tool-Rechte: das UI ruft nichts auf.
                        "tools": [],
                        "scopes": [],
                    },
                    {
                        "id": "bot",
                        "role": "agent",
                        "token_hash": hash_token(tokens["bot"]),
                        "tools": ["demo.show", "demo.echo"],
                        "scopes": ["stack:*"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    return load_identities(str(path)), tokens


@pytest.fixture
def ui_app(tier1, catalog, ui_identities, tmp_path):
    store, _ = ui_identities
    audit = AuditLog(tier1.audit_dir)
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    return build_app(service=service, identities=store, audit=audit, ui=True)


def _client(app, **kwargs) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, timeout=30.0, **kwargs
    )


async def _login(
    client: httpx2.AsyncClient, identity: str = "root", password: str = ROOT_PASSWORD
):
    return await client.post(
        f"{UI_PREFIX}/login", data={"identity": identity, "password": password}
    )


# -- Die Trennung von MCP und UI -------------------------------------------


async def test_ui_session_does_not_authenticate_mcp(ui_app, ui_identities):
    """Der wichtigste Test dieser Datei.

    Ein Cookie wird vom Browser bei jedem Request an die Herkunft automatisch
    mitgeschickt. Wuerde die Auth-Middleware es als Nachweis gelten lassen,
    genuegte eine fremde Webseite mit einem Formular auf /mcp, um im Namen des
    angemeldeten Admins Tools auf dem Host auszufuehren.
    """
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        assert client.cookies.get("gatekeeper_ui")  # Sitzung besteht

        # Derselbe Client, dieselbe Herkunft, gueltige Sitzung - aber ohne
        # Authorization-Header darf /mcp nichts durchlassen.
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}


async def test_ui_session_does_not_open_metrics(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        assert (await client.get("/metrics")).status_code == 401


async def test_bearer_token_does_not_open_ui(ui_app, ui_identities):
    """Und die Gegenrichtung: ein Agenten-Token ist kein UI-Zugang."""
    _, tokens = ui_identities
    async with _client(
        ui_app, headers={"Authorization": f"Bearer {tokens['bot']}"}
    ) as client:
        response = await client.get(f"{UI_PREFIX}/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].endswith("/login")


async def test_session_cookie_is_scoped_and_httponly(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        response = await _login(client)
        raw = response.headers["set-cookie"].lower()
        assert "httponly" in raw
        assert "samesite=strict" in raw
        assert f"path={UI_PREFIX}" in raw


# -- Zugangspflicht ---------------------------------------------------------


def _guarded_routes(app) -> list[tuple[str, str]]:
    """(Pfad, Methode) fuer alles unter /ui ausser An- und Abmeldung."""
    seen = []
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith(UI_PREFIX) or path.endswith(("/login", "/logout")):
            continue
        for method in sorted(getattr(route, "methods", set()) or {"GET"}):
            if method in ("GET", "POST"):
                seen.append((path, method))
    return seen


async def test_every_ui_route_requires_a_session(ui_app):
    """Zaehlt die registrierten Routen ab, statt eine Liste zu pflegen.

    Eine kuenftig hinzugefuegte Seite oder Aktion, bei der die
    Sitzungspruefung vergessen wurde, faellt damit hier auf und nicht erst im
    Betrieb. Die schreibenden Routen sind ausdruecklich mitgemeint -- gerade
    dort waere ein Loch teuer.
    """
    routes = _guarded_routes(ui_app)
    assert len(routes) >= 12, f"zu wenige UI-Routen gefunden: {routes}"
    async with _client(ui_app) as client:
        for path, method in routes:
            response = await client.request(method, path, follow_redirects=False)
            assert response.status_code == 303, f"{method} {path}"
            assert response.headers["location"].endswith("/login"), f"{method} {path}"


async def test_agent_role_cannot_log_in(ui_app, ui_identities):
    """`role` war bis hierher ein Feld ohne Wirkung. Jetzt entscheidet es.

    Ein Agent hat kein Konsolenpasswort -- weder sein Token noch irgendein
    anderer Wert bringt ihn hinein.
    """
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        response = await _login(client, "bot", tokens["bot"])
        assert response.status_code == 200
        assert "Sign-in failed" in response.text
        assert not client.cookies.get("gatekeeper_ui")


async def test_api_token_is_not_a_console_password(ui_app, ui_identities):
    """Der Kern der Trennung: der Token des Admins oeffnet die Konsole nicht.

    Frueher war er genau das Anmeldegeheimnis. Wer ihn heute ins Formular
    tippt, kommt nicht hinein -- und muss es auch nicht mehr, denn er gehoert
    in die Konfiguration eines Agenten, nicht in einen Browser (FR-11.5).
    """
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        response = await _login(client, "root", tokens["root"])
        assert "Sign-in failed" in response.text
        assert not client.cookies.get("gatekeeper_ui")

        # Und die Gegenprobe: mit dem Passwort geht es.
        assert (await _login(client)).status_code == 303


async def test_console_password_is_not_an_api_token(ui_app):
    """Die Gegenrichtung: das Konsolenpasswort spricht /mcp nicht an."""
    async with _client(
        ui_app, headers={"Authorization": f"Bearer {ROOT_PASSWORD}"}
    ) as client:
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401


async def test_wrong_password_is_rejected_and_audited(ui_app, tier1):
    async with _client(ui_app) as client:
        response = await _login(client, "root", "falsches-passwort-hier")
    assert not response.cookies.get("gatekeeper_ui")

    path = os.path.join(tier1.audit_dir, "audit.jsonl")
    with open(path, encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    assert any(r["kind"] == "auth_failure" for r in records)


async def test_unknown_identity_gets_the_same_answer(ui_app):
    """Die Maske darf kein Verzeichnis der Konsolenkonten sein.

    Unbekannte Kennung, falsches Passwort, Agentenrolle -- der Absender
    bekommt dreimal denselben Satz. Was wirklich war, steht im Audit-Log.
    """
    def error_of(response) -> str:
        start = response.text.index('<p class="err">')
        return response.text[start : response.text.index("</p>", start)]

    async with _client(ui_app) as client:
        unknown = await _login(client, "gibtsnicht", ROOT_PASSWORD)
        wrong = await _login(client, "root", "auch-nicht-richtig")
    assert "Sign-in failed" in error_of(unknown)
    assert error_of(unknown) == error_of(wrong)


async def test_login_and_logout_roundtrip(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        response = await _login(client)
        assert response.status_code == 303

        page = await client.get(f"{UI_PREFIX}/")
        assert page.status_code == 200
        assert "Tier 1" in page.text

        await client.post(f"{UI_PREFIX}/logout")
        after = await client.get(f"{UI_PREFIX}/", follow_redirects=False)
        assert after.status_code == 303


async def test_ui_is_off_by_default(tier1, catalog, ui_identities, tmp_path):
    """Ohne --ui ist /ui keine oeffentliche Flaeche, sondern token-pflichtig."""
    store, _ = ui_identities
    audit = AuditLog(str(tmp_path / "logs-noui"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    app = build_app(service=service, identities=store, audit=audit)
    async with _client(app) as client:
        assert (await client.get(f"{UI_PREFIX}/login")).status_code == 401


async def test_similar_prefix_is_not_public(ui_app):
    """'/uixyz' darf nicht als UI-Pfad durchgehen."""
    async with _client(ui_app) as client:
        assert (await client.get("/uixyz")).status_code == 401


def _auth_failures(tier1) -> list[dict]:
    path = os.path.join(tier1.audit_dir, "audit.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [
            r
            for r in (json.loads(line) for line in handle if line.strip())
            if r["kind"] == "auth_failure"
        ]


async def test_browser_noise_does_not_reach_the_audit_log(ui_app, tier1):
    """Ein Browserbesuch darf keine Fehlversuche protokollieren.

    Wer die Adresse eintippt, loest `GET /` und `GET /favicon.ico` aus, ohne
    etwas davon zu wollen. Landen die als `auth_failure` im Log, verschwindet
    der eine echte Rateversuch zwischen dem Rauschen -- und die Rotation
    schiebt aeltere, echte Eintraege schneller hinaus.
    """
    before = len(_auth_failures(tier1))
    async with _client(ui_app) as client:
        root = await client.get("/", follow_redirects=False)
        assert root.status_code == 303
        assert root.headers["location"] == f"{UI_PREFIX}/"

        icon = await client.get("/favicon.ico")
        assert icon.status_code == 200
        assert icon.headers["content-type"].startswith("image/svg+xml")

    assert len(_auth_failures(tier1)) == before


async def test_root_stays_protected_without_ui(tier1, catalog, ui_identities, tmp_path):
    """Ohne UI bleibt '/' token-pflichtig -- die Ausnahme gilt nur mit UI."""
    store, _ = ui_identities
    audit = AuditLog(str(tmp_path / "logs-root"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    app = build_app(service=service, identities=store, audit=audit)
    async with _client(app) as client:
        assert (await client.get("/", follow_redirects=False)).status_code == 401
        assert (await client.get("/favicon.ico")).status_code == 401


# -- Darstellung fremder Daten ---------------------------------------------


async def test_audit_values_from_agents_are_escaped(ui_app, ui_identities, tier1):
    """Abgelehnte Aufrufe protokollieren die *unvalidierten* Argumente.

    Ein Agent kann dort also weitgehend beliebigen Text hinterlegen. Genau
    dieser Text landet im UI -- er muss maskiert ankommen.
    """
    audit = AuditLog(tier1.audit_dir)
    payload = '<script>alert("xss")</script>'
    audit.call(
        identity="bot",
        tool_id="demo.echo",
        tool_version=1,
        parameters={"text": payload},
        scopes=[],
        outcome="denied",
        denial_reason="param_invalid",
        detail=payload,
    )

    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/audit")

    assert page.status_code == 200
    assert "<script>alert" not in page.text
    assert "&lt;script&gt;" in page.text


async def test_pages_forbid_scripts(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/tools")
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src" not in csp  # faellt auf default-src 'none' zurueck
    assert page.headers["cache-control"] == "no-store"


async def test_token_hashes_are_never_rendered(ui_app, ui_identities):
    store, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/identities")
    for identity in store.identities.values():
        assert identity.token_hash not in page.text
    assert "scrypt$" not in page.text


async def test_tools_page_shows_who_may_call(ui_app, ui_identities):
    _, tokens = ui_identities
    async with _client(ui_app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/tools")
    assert "demo.show" in page.text
    # 'bot' darf demo.show aufrufen, 'root' nicht - die Querverbindung ist der
    # eigentliche Nutzen der Seite.
    assert "bot" in page.text


# -- Bausteine --------------------------------------------------------------


def test_read_audit_filters_and_orders(tmp_path):
    path = tmp_path / "audit.jsonl"
    with open(path, "w", encoding="utf-8") as handle:
        for index in range(5):
            handle.write(
                json.dumps(
                    {
                        "ts": f"t{index}",
                        "kind": "call",
                        "identity": "a" if index % 2 else "b",
                        "tool": "demo.show",
                        "outcome": "ok",
                    }
                )
                + "\n"
            )
    records, truncated = read_audit(str(path), identity="a")
    assert not truncated
    assert [r["ts"] for r in records] == ["t3", "t1"]  # juengste zuerst


def test_read_audit_survives_broken_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"kind": "call"}\nkein json\n\n', encoding="utf-8")
    records, _ = read_audit(str(path))
    assert len(records) == 1


def test_read_audit_missing_file():
    assert read_audit("/gibt/es/nicht/audit.jsonl") == ([], False)


def test_calls_in_the_current_hour_reach_the_chart():
    """Regression: das Diagramm blieb leer, obwohl Aufrufe vorlagen.

    Die Gegenwart wird auf die volle Stunde abgerundet. Wurde der Zeitstempel
    des Eintrags nicht ebenso behandelt, lag ein Aufruf aus der laufenden
    Stunde *nach* dieser Gegenwart -- negatives Alter, kein Fach, leeres Bild.
    Genau der Fall, den man am seltensten von Hand nachstellt.
    """
    now = datetime(2026, 8, 12, 19, 0, tzinfo=timezone.utc)
    records = [
        {"kind": "call", "ts": "2026-08-12T19:57:00+0000", "outcome": "ok"},
        {"kind": "call", "ts": "2026-08-12T19:58:00+0000", "outcome": "denied"},
        # Andere Zeitzone, gleiche Stunde in UTC.
        {"kind": "call", "ts": "2026-08-12T21:59:00+0200", "outcome": "ok"},
        # Nicht-Aufrufe zaehlen nicht mit.
        {"kind": "ui_login", "ts": "2026-08-12T19:30:00+0000"},
    ]
    buckets = _bucket_calls(records, 12, now=now)
    assert buckets[-1] == (2, 1)
    assert sum(o + d for o, d in buckets[:-1]) == 0


def test_bucket_calls_spreads_over_hours():
    now = datetime(2026, 8, 12, 19, 0, tzinfo=timezone.utc)
    records = [
        {"kind": "call", "ts": "2026-08-12T17:10:00+0000", "outcome": "ok"},
        {"kind": "call", "ts": "2026-08-12T18:10:00+0000", "outcome": "ok"},
        # Zu alt fuer das Fenster.
        {"kind": "call", "ts": "2026-08-11T19:10:00+0000", "outcome": "ok"},
        # Unlesbarer Zeitstempel darf nicht abstuerzen lassen.
        {"kind": "call", "ts": "kaputt", "outcome": "ok"},
    ]
    buckets = _bucket_calls(records, 12, now=now)
    assert buckets[-3] == (1, 0)
    assert buckets[-2] == (1, 0)
    assert sum(o + d for o, d in buckets) == 2


def test_sessions_expire():
    store = SessionStore(ttl=0)
    sid = store.create("root", "admin")
    assert store.resolve(sid) is None


def test_session_ids_are_unguessable():
    store = SessionStore()
    ids = {store.create("root", "admin") for _ in range(50)}
    assert len(ids) == 50
    assert all(len(i) >= 40 for i in ids)


def test_each_session_gets_its_own_csrf_token():
    store = SessionStore()
    first = store.resolve(store.create("root", "admin"))
    second = store.resolve(store.create("root", "admin"))
    assert first.csrf != second.csrf
    assert len(first.csrf) >= 24


def test_only_admin_may_write():
    store = SessionStore()
    assert store.resolve(store.create("root", "admin")).can_write
    assert not store.resolve(store.create("eye", "viewer")).can_write


def test_dropping_an_identity_kills_its_sessions():
    store = SessionStore()
    doomed = store.create("gone", "admin")
    other = store.create("stays", "admin")
    store.drop_identity("gone")
    assert store.resolve(doomed) is None
    assert store.resolve(other) is not None


def test_throttle_blocks_after_repeated_failures():
    throttle = LoginThrottle(max_failures=3, window_seconds=300)
    for _ in range(3):
        assert not throttle.blocked("10.0.0.1")
        throttle.record_failure("10.0.0.1")
    assert throttle.blocked("10.0.0.1")
    # Andere Herkunft bleibt unbehelligt.
    assert not throttle.blocked("10.0.0.2")
    throttle.reset("10.0.0.1")
    assert not throttle.blocked("10.0.0.1")


def test_has_admin(ui_identities, identities):
    store, _ = ui_identities
    assert has_admin(store)
    agents_only, _ = identities
    assert not has_admin(agents_only)
