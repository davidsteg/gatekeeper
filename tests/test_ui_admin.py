"""Schreibzugriff der Oberflaeche.

Mit Stufe 3 kann eine Weboberflaeche die Konfiguration eines Dienstes aendern,
der root-aequivalenten Zugriff auf den Host hat. Die Tests hier sind der
Gegenbeweis zu den drei Befuerchtungen, die das ausloest:

* Kann sich ein Admin ueber Ebene 1 hinwegsetzen? (nein -- derselbe Pruefpfad)
* Kann eine fremde Seite im Namen eines angemeldeten Admins schreiben?
  (nein -- CSRF-Token, und die Sitzung gilt weiterhin nicht fuer /mcp)
* Kann man sich selbst aussperren oder die Datei zerschiessen?
  (nein -- letzter Admin geschuetzt, atomar geschrieben, Revision geprueft)
"""

from __future__ import annotations

import json
import os

import httpx2
import pytest
import yaml

from conftest import PYTHON
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore, WriteRefused, load_tool_yaml
from gatekeeper.ui import UI_PREFIX

BASE = "http://gatekeeper.test"


@pytest.fixture
def admin_env(tmp_path, tier1, tool_specs):
    """Beschreibbare Ebene-2-Dateien plus laufende Anwendung mit Schreibrecht."""
    tools_path = tmp_path / "tools-rw.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")

    tokens = {"root": generate_token(), "eye": generate_token(), "bot": generate_token()}
    identities_path = tmp_path / "identities-rw.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token(tokens["root"]),
                        "tools": [],
                        "scopes": [],
                    },
                    {
                        "id": "eye",
                        "role": "viewer",
                        "token_hash": hash_token(tokens["eye"]),
                        "tools": [],
                        "scopes": [],
                    },
                    {
                        "id": "bot",
                        "role": "agent",
                        "token_hash": hash_token(tokens["bot"]),
                        "tools": ["demo.show"],
                        "scopes": ["stack:*"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    identities = load_identities(str(identities_path))
    audit = AuditLog(tier1.audit_dir)
    service = Service(
        tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit
    )
    store = ConfigStore(
        service=service,
        identities=identities,
        audit=audit,
        tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    app = build_app(
        service=service, identities=identities, audit=audit, ui=True, store=store
    )
    return {
        "app": app,
        "store": store,
        "service": service,
        "identities": identities,
        "tokens": tokens,
        "tools_path": tools_path,
        "identities_path": identities_path,
        "tier1": tier1,
    }


def _client(app) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, timeout=30.0
    )


async def _signed_in(client, token: str) -> str:
    """Meldet an und liefert das CSRF-Token aus der gerenderten Seite."""
    await client.post(f"{UI_PREFIX}/login", data={"token": token})
    page = await client.get(f"{UI_PREFIX}/tools")
    marker = 'name="_csrf" value="'
    start = page.text.index(marker) + len(marker)
    return page.text[start : page.text.index('"', start)]


def _rev(store) -> str:
    return store.tools_revision()


# -- Ebene 1 bleibt unantastbar --------------------------------------------


def test_admin_cannot_exceed_tier1_ceilings(admin_env):
    """Der wichtigste Test dieser Datei.

    Ein Admin darf Tools anlegen -- aber nicht solche, die die Grenzen des
    Deployments sprengen. Ginge das, waere Ebene 1 nur noch Dekoration und die
    Oberflaeche der kuerzeste Weg zu einer Root-Shell.
    """
    store = admin_env["store"]
    spec = {
        "id": "demo.toolong",
        "toolkit": "demo",
        "binary": PYTHON,
        "title": "x",
        "description": "x",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "argv": [],
        "parameters": {},
        "required_scopes": [],
        "timeout_seconds": 99999,  # Toolkit-Maximum ist 30
        "max_output_bytes": 1024,
    }
    with pytest.raises(Exception) as exc:
        store.save_tool(spec, actor="root", rev=_rev(store))
    assert "exceeds" in str(exc.value)
    assert "demo.toolong" not in store.service.catalog.tools


def test_admin_cannot_introduce_a_foreign_binary(admin_env):
    store = admin_env["store"]
    spec = {
        "id": "demo.evil",
        "toolkit": "demo",
        "binary": "/bin/sh",
        "title": "x",
        "description": "x",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "argv": ["-c", "id"],
        "parameters": {},
        "required_scopes": [],
        "timeout_seconds": 5,
        "max_output_bytes": 1024,
    }
    with pytest.raises(Exception) as exc:
        store.save_tool(spec, actor="root", rev=_rev(store))
    assert "allowlist" in str(exc.value)


def test_admin_cannot_use_a_denied_argument(admin_env):
    store = admin_env["store"]
    spec = {
        "id": "demo.rm",
        "toolkit": "demo",
        "binary": PYTHON,
        "title": "x",
        "description": "x",
        "category": "write",
        "idempotent": False,
        "enabled": True,
        "argv": ["rm", "-rf"],  # 'rm' steht auf der Sperrliste des Toolkits
        "parameters": {},
        "required_scopes": [],
        "timeout_seconds": 5,
        "max_output_bytes": 1024,
    }
    with pytest.raises(Exception) as exc:
        store.save_tool(spec, actor="root", rev=_rev(store))
    assert "denied argument" in str(exc.value)


def test_no_route_writes_tier1(admin_env):
    """Es gibt keinen Pfad, ueber den toolkits.yaml erreichbar waere."""
    paths = [getattr(r, "path", "") for r in admin_env["app"].routes]
    assert not [p for p in paths if "toolkit" in p.lower()]
    assert not hasattr(admin_env["store"], "save_toolkit")
    assert "toolkits" not in "".join(dir(admin_env["store"]))


def test_free_text_parameter_still_refused(admin_env):
    """FR-5.7 gilt auch fuer das, was aus dem Formular kommt."""
    store = admin_env["store"]
    spec = {
        "id": "demo.freetext",
        "toolkit": "demo",
        "binary": PYTHON,
        "title": "x",
        "description": "x",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "argv": ["-c", "print(1)", "{anything}"],
        "parameters": {"anything": {"type": "string", "required": True, "description": "x"}},
        "required_scopes": [],
        "timeout_seconds": 5,
        "max_output_bytes": 1024,
    }
    with pytest.raises(Exception) as exc:
        store.save_tool(spec, actor="root", rev=_rev(store))
    assert "pattern" in str(exc.value)


# -- Der glueckliche Pfad ---------------------------------------------------


def test_create_edit_disable_delete_roundtrip(admin_env):
    store, service = admin_env["store"], admin_env["service"]
    spec = {
        "id": "demo.ping",
        "toolkit": "demo",
        "binary": PYTHON,
        "version": 1,
        "title": "Ping",
        "description": "Prints pong.",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "argv": ["-c", "print('pong')"],
        "parameters": {},
        "required_scopes": [],
        "timeout_seconds": 5,
        "max_output_bytes": 1024,
    }
    store.save_tool(spec, actor="root", rev=_rev(store))
    assert "demo.ping" in service.catalog.tools

    # Die Datei traegt die Aenderung, nicht nur der Speicher.
    on_disk = yaml.safe_load(admin_env["tools_path"].read_text(encoding="utf-8"))
    assert any(s["id"] == "demo.ping" for s in on_disk["tools"])

    edited = dict(spec, title="Ping v2")
    store.save_tool(edited, actor="root", rev=_rev(store), replaces="demo.ping")
    assert service.catalog.tools["demo.ping"].title == "Ping v2"

    store.set_tool_enabled("demo.ping", False, actor="root", rev=_rev(store))
    assert not service.catalog.tools["demo.ping"].enabled

    store.delete_tool("demo.ping", actor="root", rev=_rev(store))
    assert "demo.ping" not in service.catalog.tools


def test_written_file_reloads_cleanly(admin_env):
    """Was geschrieben wurde, muss ein Neustart genauso lesen koennen."""
    store = admin_env["store"]
    store.set_tool_enabled("demo.echo", False, actor="root", rev=_rev(store))
    fresh = load_catalog(str(admin_env["tools_path"]), admin_env["tier1"], strict=True)
    assert not fresh.tools["demo.echo"].enabled
    assert set(fresh.tools) == set(store.service.catalog.tools)


def test_identity_lifecycle(admin_env):
    store, identities = admin_env["store"], admin_env["identities"]
    token = store.create_identity(
        identity_id="fresh", role="agent", tools=["demo.show"],
        scopes=["stack:media-*"], actor="root", rev=store.identities_revision(),
    )
    assert token.startswith("gk_")
    assert identities.authenticate(token).id == "fresh"

    store.save_identity(
        identity_id="fresh", role="agent", tools=["demo.show", "demo.echo"],
        scopes=["stack:*"], actor="root", rev=store.identities_revision(),
        replaces="fresh",
    )
    assert identities.identities["fresh"].tools == frozenset({"demo.show", "demo.echo"})
    # Der Token ueberlebt eine Rechteaenderung.
    assert identities.authenticate(token) is not None

    rotated = store.rotate_token("fresh", actor="root", rev=store.identities_revision())
    assert identities.authenticate(rotated) is not None
    assert identities.authenticate(token) is None, "alter Token muss tot sein"

    store.delete_identity("fresh", actor="root", rev=store.identities_revision())
    assert identities.authenticate(rotated) is None


def test_new_identity_token_is_never_logged(admin_env, tier1):
    store = admin_env["store"]
    token = store.create_identity(
        identity_id="quiet", role="agent", tools=[], scopes=[],
        actor="root", rev=store.identities_revision(),
    )
    log = open(os.path.join(tier1.audit_dir, "audit.jsonl"), encoding="utf-8").read()
    assert token not in log
    assert "identity_create" in log


# -- Schutz vor dem eigenen Fehlgriff --------------------------------------


def test_cannot_delete_the_last_admin(admin_env):
    store = admin_env["store"]
    with pytest.raises(WriteRefused) as exc:
        store.delete_identity("root", actor="root", rev=store.identities_revision())
    assert "no identity with role 'admin'" in str(exc.value)
    assert "root" in admin_env["identities"].identities


def test_cannot_demote_the_last_admin(admin_env):
    store = admin_env["store"]
    with pytest.raises(WriteRefused):
        store.save_identity(
            identity_id="root", role="viewer", tools=[], scopes=[],
            actor="root", rev=store.identities_revision(), replaces="root",
        )
    assert admin_env["identities"].identities["root"].role == "admin"


def test_stale_revision_is_refused(admin_env):
    """Zwei Admins gleichzeitig duerfen sich nicht gegenseitig ueberschreiben."""
    store = admin_env["store"]
    stale = _rev(store)
    store.set_tool_enabled("demo.echo", False, actor="a", rev=stale)
    with pytest.raises(WriteRefused) as exc:
        store.set_tool_enabled("demo.show", False, actor="b", rev=stale)
    assert "changed since" in str(exc.value)


def test_unknown_tool_right_is_refused(admin_env):
    store = admin_env["store"]
    with pytest.raises(WriteRefused) as exc:
        store.create_identity(
            identity_id="typo", role="agent", tools=["demo.tpyo"], scopes=[],
            actor="root", rev=store.identities_revision(),
        )
    assert "Unknown tool IDs" in str(exc.value)


def test_duplicate_ids_are_refused(admin_env):
    store = admin_env["store"]
    with pytest.raises(WriteRefused):
        store.create_identity(
            identity_id="root", role="admin", tools=[], scopes=[],
            actor="root", rev=store.identities_revision(),
        )


def test_deleting_a_tool_records_the_definition(admin_env, tier1):
    """Eine Loeschung muss aus dem Log heraus umkehrbar bleiben."""
    store = admin_env["store"]
    store.delete_tool("demo.echo", actor="root", rev=_rev(store))
    entries = [
        json.loads(line)
        for line in open(os.path.join(tier1.audit_dir, "audit.jsonl"), encoding="utf-8")
        if line.strip()
    ]
    deletion = [e for e in entries if e.get("action") == "tool_delete"][-1]
    assert deletion["spec"]["id"] == "demo.echo"
    assert deletion["spec"]["argv"]


def test_dangling_grant_is_recorded(admin_env, tier1):
    store = admin_env["store"]
    store.delete_tool("demo.show", actor="root", rev=_rev(store))
    entries = [
        json.loads(line)
        for line in open(os.path.join(tier1.audit_dir, "audit.jsonl"), encoding="utf-8")
        if line.strip()
    ]
    notes = [e for e in entries if e.get("action") == "dangling_grant"]
    assert notes and "bot" in notes[-1]["identities"]


def test_write_refused_on_read_only_file(admin_env, monkeypatch):
    store = admin_env["store"]
    monkeypatch.setattr("gatekeeper.store.writable", lambda path: False)
    with pytest.raises(WriteRefused) as exc:
        store.set_tool_enabled("demo.echo", False, actor="root", rev=_rev(store))
    assert "not writable" in str(exc.value)


def test_bad_yaml_is_reported_not_raised_raw(admin_env):
    with pytest.raises(WriteRefused) as exc:
        load_tool_yaml("id: [unclosed")
    assert "Not valid YAML" in str(exc.value)

    with pytest.raises(WriteRefused) as exc:
        load_tool_yaml("tools:\n  - id: a.b\n")
    assert "one tool definition" in str(exc.value)


# -- Ueber HTTP: Rollen und CSRF -------------------------------------------


async def test_viewer_cannot_write(admin_env):
    """Lesen und Schreiben sind getrennte Rollen -- ueber HTTP nachgewiesen."""
    app, tokens = admin_env["app"], admin_env["tokens"]
    async with _client(app) as client:
        await client.post(f"{UI_PREFIX}/login", data={"token": tokens["eye"]})
        page = await client.get(f"{UI_PREFIX}/tools")
        assert page.status_code == 200
        # Ein viewer sieht die Schaltflaechen gar nicht erst.
        assert f"{UI_PREFIX}/tools/new" not in page.text

        blocked = await client.post(
            f"{UI_PREFIX}/tools/toggle",
            data={"id": "demo.echo", "enabled": "0", "rev": "", "_csrf": "x"},
        )
        assert blocked.status_code == 403
        assert "role: admin" in blocked.text
    assert admin_env["service"].catalog.tools["demo.echo"].enabled


async def test_write_without_csrf_token_is_refused(admin_env):
    """Ohne gueltiges Formular-Token passiert nichts.

    Das ist die Absicherung gegen eine fremde Seite, die ein Formular auf
    /ui/... abschickt: das Cookie waere dabei, das Token nicht.
    """
    app, tokens = admin_env["app"], admin_env["tokens"]
    async with _client(app) as client:
        await client.post(f"{UI_PREFIX}/login", data={"token": tokens["root"]})
        response = await client.post(
            f"{UI_PREFIX}/tools/toggle",
            data={"id": "demo.echo", "enabled": "0", "rev": ""},
        )
        assert response.status_code == 403
        assert "form token" in response.text
    assert admin_env["service"].catalog.tools["demo.echo"].enabled


async def test_csrf_token_of_another_session_does_not_work(admin_env):
    app, tokens = admin_env["app"], admin_env["tokens"]
    async with _client(app) as first, _client(app) as second:
        stolen = await _signed_in(first, tokens["root"])
        await second.post(f"{UI_PREFIX}/login", data={"token": tokens["root"]})
        response = await second.post(
            f"{UI_PREFIX}/tools/toggle",
            data={"id": "demo.echo", "enabled": "0", "rev": "", "_csrf": stolen},
        )
        assert response.status_code == 403
    assert admin_env["service"].catalog.tools["demo.echo"].enabled


async def test_admin_session_still_does_not_open_mcp(admin_env):
    """Schreibrecht im UI aendert nichts an der Trennung zu /mcp."""
    app, tokens = admin_env["app"], admin_env["tokens"]
    async with _client(app) as client:
        await _signed_in(client, tokens["root"])
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401


async def test_admin_can_toggle_over_http(admin_env):
    app, tokens = admin_env["app"], admin_env["tokens"]
    store = admin_env["store"]
    async with _client(app) as client:
        csrf = await _signed_in(client, tokens["root"])
        response = await client.post(
            f"{UI_PREFIX}/tools/toggle",
            data={"id": "demo.echo", "enabled": "0", "rev": _rev(store), "_csrf": csrf},
            follow_redirects=False,
        )
        assert response.status_code == 303
    assert not admin_env["service"].catalog.tools["demo.echo"].enabled


async def test_invalid_definition_returns_to_the_editor(admin_env):
    """Ein Fehler darf die Eingabe nicht verwerfen."""
    app, tokens = admin_env["app"], admin_env["tokens"]
    store = admin_env["store"]
    async with _client(app) as client:
        csrf = await _signed_in(client, tokens["root"])
        broken = "id: demo.bad\ntoolkit: demo\nbinary: /bin/sh\ncategory: read\n"
        response = await client.post(
            f"{UI_PREFIX}/tools/new",
            data={"yaml": broken, "rev": _rev(store), "_csrf": csrf},
        )
        assert response.status_code == 400
        assert "allowlist" in response.text
        assert "demo.bad" in response.text, "die Eingabe muss erhalten bleiben"


async def test_agent_token_cannot_reach_the_console(admin_env):
    app, tokens = admin_env["app"], admin_env["tokens"]
    async with _client(app) as client:
        response = await client.post(
            f"{UI_PREFIX}/login", data={"token": tokens["bot"]}
        )
        assert "Sign-in failed" in response.text
