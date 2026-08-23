"""Write access of the UI.

With stage 3, a web UI can change the configuration of a service
that has root-equivalent access to the host. The tests here are the
counter-evidence to the three concerns that this raises:

* Can an admin override Tier 1? (no -- same check path)
* Can a foreign site write in the name of a signed-in admin?
  (no -- CSRF token, and the session still does not apply to /mcp)
* Can you lock yourself out or corrupt the file?
  (no -- last admin protected, written atomically, revision checked)
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
from gatekeeper.pending import PendingStore
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore, WriteRefused, load_tool_yaml
from gatekeeper.toolkit_proposals import ToolkitProposalStore
from gatekeeper.ui import UI_PREFIX

BASE = "http://gatekeeper.test"

#: Console passwords of the two humans in the test. The agent has none --
#: it does not sign in anywhere.
PASSWORDS = {"root": "admin-console-password", "eye": "viewer-console-password"}


@pytest.fixture
def admin_env(tmp_path, tier1, tool_specs):
    """Writable Tier 2 files plus a running application with write permission."""
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
                        "password_hash": hash_token(PASSWORDS["root"]),
                        "tools": [],
                        "scopes": [],
                    },
                    {
                        "id": "eye",
                        "role": "viewer",
                        "token_hash": hash_token(tokens["eye"]),
                        "password_hash": hash_token(PASSWORDS["eye"]),
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
    pending = PendingStore(path=str(tmp_path / "pending-rw.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit-proposals-rw.yaml"),
        audit=audit,
        service=service,
        toolkits_path=str(tmp_path / "toolkits.yaml"),
        tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    app = build_app(
        service=service, identities=identities, audit=audit, ui=True, store=store,
        pending=pending, toolkit_proposals=toolkit_proposals,
    )
    return {
        "app": app,
        "store": store,
        "pending": pending,
        "toolkit_proposals": toolkit_proposals,
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


async def _login(client, identity: str = "root"):
    return await client.post(
        f"{UI_PREFIX}/login",
        data={"identity": identity, "password": PASSWORDS[identity]},
    )


async def _signed_in(client, identity: str = "root") -> str:
    """Signs in and returns the CSRF token from the rendered page."""
    await _login(client, identity)
    page = await client.get(f"{UI_PREFIX}/tools")
    marker = 'name="_csrf" value="'
    start = page.text.index(marker) + len(marker)
    return page.text[start : page.text.index('"', start)]


def _rev(store) -> str:
    return store.tools_revision()


# -- Tier 1 remains untouchable --------------------------------------------


def test_admin_cannot_exceed_tier1_ceilings(admin_env):
    """The most important test in this file.

    An admin may create tools -- but not ones that break the limits of the
    deployment. If that were possible, Tier 1 would be mere decoration and
    the UI the shortest path to a root shell.
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
        "timeout_seconds": 99999,  # toolkit maximum is 30
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
        "argv": ["rm", "-rf"],  # 'rm' is on the toolkit's block list
        "parameters": {},
        "required_scopes": [],
        "timeout_seconds": 5,
        "max_output_bytes": 1024,
    }
    with pytest.raises(Exception) as exc:
        store.save_tool(spec, actor="root", rev=_rev(store))
    assert "denied argument" in str(exc.value)


def test_no_route_writes_tier1(admin_env):
    """`ConfigStore` has a narrowly-scoped `save_toolkit` (since v0.23.0)
    that can change ``executor``/``binaries``/``denied_args`` — but never
    the security-critical fields (``path_roots``, ``protected_resources``,
    ``limits``). Among the UI's routes, only ``/ui/toolkits/deploy`` may
    write Tier 1 directly, and only for a human through `writer` (session
    + ``role: admin`` + CSRF), never automatically and never from
    ``/admin/mcp``.
    """
    tier1_writing_routes = {f"{UI_PREFIX}/toolkits/deploy"}
    proposal_only_routes = {f"{UI_PREFIX}/toolkits/reject"}
    toolkit_routes = [
        r for r in admin_env["app"].routes if "toolkit" in getattr(r, "path", "").lower()
    ]
    assert toolkit_routes, "expected at least the /ui/toolkits routes to be registered"
    for route in toolkit_routes:
        methods = getattr(route, "methods", None) or set()
        if route.path in tier1_writing_routes or route.path in proposal_only_routes:
            continue
        assert methods <= {"GET", "HEAD"}, (
            f"{route.path} accepts {methods} -- only GET/HEAD may touch a "
            f"'toolkit' path (the only exceptions are {sorted(tier1_writing_routes)} "
            f"and {sorted(proposal_only_routes)})"
        )
    # save_toolkit exists now, but must reject security-critical fields
    assert hasattr(admin_env["store"], "save_toolkit")
    from gatekeeper.store import WriteRefused
    store = admin_env["store"]
    # Must reject path_roots changes
    with pytest.raises(WriteRefused):
        store.save_toolkit(
            "demo", {"path_roots": ["/etc"]}, actor="root",
            rev=store.tools_revision(),
        )
    # Must reject protected_resources changes
    with pytest.raises(WriteRefused):
        store.save_toolkit(
            "demo", {"protected_resources": []}, actor="root",
            rev=store.tools_revision(),
        )
    # Must reject limits changes
    with pytest.raises(WriteRefused):
        store.save_toolkit(
            "demo", {"limits": {}}, actor="root",
            rev=store.tools_revision(),
        )


def test_free_text_parameter_still_refused(admin_env):
    """FR-5.7 also applies to what comes from the form."""
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


# -- The happy path ---------------------------------------------------


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

    # The file carries the change, not just memory.
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
    """What was written must be readable by a restart just the same."""
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
    # The token survives a permission change.
    assert identities.authenticate(token) is not None

    rotated = store.rotate_token("fresh", actor="root", rev=store.identities_revision())
    assert identities.authenticate(rotated) is not None
    assert identities.authenticate(token) is None, "old token must be dead"

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


# -- Protection from one's own mistakes --------------------------------------


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
    """Two admins simultaneously must not overwrite each other."""
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
    """A deletion must remain reversible from the log."""
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


# -- Over HTTP: roles and CSRF -------------------------------------------


async def test_viewer_cannot_write(admin_env):
    """Reading and writing are separate roles -- proven over HTTP."""
    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client, "eye")
        page = await client.get(f"{UI_PREFIX}/tools")
        assert page.status_code == 200
        # A viewer does not even see the buttons.
        assert f"{UI_PREFIX}/tools/new" not in page.text

        blocked = await client.post(
            f"{UI_PREFIX}/tools/toggle",
            data={"id": "demo.echo", "enabled": "0", "rev": "", "_csrf": "x"},
        )
        assert blocked.status_code == 403
        assert "role: admin" in blocked.text
    assert admin_env["service"].catalog.tools["demo.echo"].enabled


async def test_write_without_csrf_token_is_refused(admin_env):
    """Without a valid form token, nothing happens.

    This is the protection against a foreign site that submits a form to
    /ui/...: the cookie would be present, the token would not.
    """
    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client)
        response = await client.post(
            f"{UI_PREFIX}/tools/toggle",
            data={"id": "demo.echo", "enabled": "0", "rev": ""},
        )
        assert response.status_code == 403
        assert "form token" in response.text
    assert admin_env["service"].catalog.tools["demo.echo"].enabled


async def test_csrf_token_of_another_session_does_not_work(admin_env):
    app = admin_env["app"]
    async with _client(app) as first, _client(app) as second:
        stolen = await _signed_in(first)
        await _login(second)
        response = await second.post(
            f"{UI_PREFIX}/tools/toggle",
            data={"id": "demo.echo", "enabled": "0", "rev": "", "_csrf": stolen},
        )
        assert response.status_code == 403
    assert admin_env["service"].catalog.tools["demo.echo"].enabled


async def test_admin_session_still_does_not_open_mcp(admin_env):
    """Write permission in the UI changes nothing about the separation from /mcp."""
    app = admin_env["app"]
    async with _client(app) as client:
        await _signed_in(client)
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401


async def test_admin_can_toggle_over_http(admin_env):
    app = admin_env["app"]
    store = admin_env["store"]
    async with _client(app) as client:
        csrf = await _signed_in(client)
        response = await client.post(
            f"{UI_PREFIX}/tools/toggle",
            data={"id": "demo.echo", "enabled": "0", "rev": _rev(store), "_csrf": csrf},
            follow_redirects=False,
        )
        assert response.status_code == 303
    assert not admin_env["service"].catalog.tools["demo.echo"].enabled


async def test_invalid_definition_returns_to_the_editor(admin_env):
    """An error must not discard the input."""
    app = admin_env["app"]
    store = admin_env["store"]
    async with _client(app) as client:
        csrf = await _signed_in(client)
        broken = "id: demo.bad\ntoolkit: demo\nbinary: /bin/sh\ncategory: read\n"
        response = await client.post(
            f"{UI_PREFIX}/tools/new",
            data={"yaml": broken, "rev": _rev(store), "_csrf": csrf},
        )
        assert response.status_code == 400
        assert "allowlist" in response.text
        assert "demo.bad" in response.text, "the input must be preserved"


async def test_tier1_ceilings_render_as_symbols_not_entities(admin_env):
    """The Tier 1 sidebar next to the tool editor shows a literal '<=' sign.

    The ceiling text used to be built with the HTML entity '&le;' and then
    passed through the same escaping helper as every other value in
    _pills() -- which turned the entity's own ampersand into '&amp;le;'
    and printed the entity name on the page instead of the symbol.
    """
    app = admin_env["app"]
    async with _client(app) as client:
        await _signed_in(client)
        page = await client.get(f"{UI_PREFIX}/tools/new")

    assert page.status_code == 200
    assert "&le;" not in page.text
    assert "≤" in page.text  # '<=' -- rendered next to the editor


async def test_agent_token_cannot_reach_the_console(admin_env):
    """Neither as a password nor otherwise: an agent has no console account."""
    app, tokens = admin_env["app"], admin_env["tokens"]
    async with _client(app) as client:
        response = await client.post(
            f"{UI_PREFIX}/login",
            data={"identity": "bot", "password": tokens["bot"]},
        )
        assert "Sign-in failed" in response.text

        # And the admin's token just as little -- it belongs to /mcp.
        response = await client.post(
            f"{UI_PREFIX}/login",
            data={"identity": "root", "password": tokens["root"]},
        )
        assert "Sign-in failed" in response.text
        assert not client.cookies.get("gatekeeper_ui")


# -- Console passwords ----------------------------------------------------


def test_console_password_is_stored_only_as_a_hash(admin_env):
    """The plain text must end up neither in the file nor in the log."""
    store = admin_env["store"]
    secret = "a-fresh-console-password"
    store.set_password("eye", secret, actor="root", rev=store.identities_revision())

    on_disk = admin_env["identities_path"].read_text(encoding="utf-8")
    assert secret not in on_disk
    assert "password_hash: scrypt$" in on_disk

    log = open(
        os.path.join(admin_env["tier1"].audit_dir, "audit.jsonl"), encoding="utf-8"
    ).read()
    assert secret not in log
    assert "password_set" in log

    assert admin_env["identities"].authenticate_console("eye", secret).role == "viewer"


def test_a_short_password_is_refused(admin_env):
    store = admin_env["store"]
    with pytest.raises(WriteRefused) as exc:
        store.set_password("eye", "short", actor="root", rev=store.identities_revision())
    assert "at least" in str(exc.value)


def test_an_agent_gets_no_console_password(admin_env):
    """A password on a role that signs in nowhere is a door
    without a room -- and usually a wrongly set role."""
    store = admin_env["store"]
    with pytest.raises(WriteRefused) as exc:
        store.set_password(
            "bot", "a-password-anyway", actor="root",
            rev=store.identities_revision(),
        )
    assert "does not sign in" in str(exc.value)

    with pytest.raises(WriteRefused):
        store.create_identity(
            identity_id="bot2", role="agent", tools=[], scopes=[],
            actor="root", rev=store.identities_revision(),
            password="a-password-anyway",
        )


def test_a_console_role_needs_a_password_from_the_start(admin_env):
    """Otherwise an account would be created that nobody can sign in to."""
    store = admin_env["store"]
    with pytest.raises(WriteRefused) as exc:
        store.create_identity(
            identity_id="ghost", role="viewer", tools=[], scopes=[],
            actor="root", rev=store.identities_revision(),
        )
    assert "needs a password" in str(exc.value)
    assert "ghost" not in admin_env["identities"].identities


def test_promoting_an_agent_requires_a_password(admin_env):
    """The path through the role must also not produce a passwordless account."""
    store = admin_env["store"]
    with pytest.raises(WriteRefused) as exc:
        store.save_identity(
            identity_id="bot", role="viewer", tools=["demo.show"], scopes=["stack:*"],
            actor="root", rev=store.identities_revision(), replaces="bot",
        )
    assert "needs a console password" in str(exc.value)
    assert admin_env["identities"].identities["bot"].role == "agent"


def test_demoting_drops_the_password(admin_env):
    """Whoever is no longer a console account keeps no hash either.

    A left-behind password would be an access that silently
    revives on the next role change.
    """
    store = admin_env["store"]
    store.save_identity(
        identity_id="eye", role="agent", tools=[], scopes=[],
        actor="root", rev=store.identities_revision(), replaces="eye",
    )
    assert admin_env["identities"].identities["eye"].password_hash == ""
    on_disk = yaml.safe_load(admin_env["identities_path"].read_text(encoding="utf-8"))
    entry = next(e for e in on_disk["identities"] if e["id"] == "eye")
    assert "password_hash" not in entry


def test_the_last_signed_in_admin_cannot_lose_the_console(admin_env):
    """The lock-out protection counts accesses, not roles, since login.

    An `admin` without a password cannot sign in. If only such a one
    remained, the UI would be locked -- the costly error that
    `_guard_last_admin` is meant to prevent.
    """
    store = admin_env["store"]
    # A second admin, but without console access: by hand in the file, because
    # via the store that would not be possible in the first place.
    payload = yaml.safe_load(admin_env["identities_path"].read_text(encoding="utf-8"))
    payload["identities"].append(
        {
            "id": "halfadmin",
            "role": "admin",
            "token_hash": hash_token(generate_token()),
            "tools": [],
            "scopes": [],
        }
    )
    admin_env["identities_path"].write_text(yaml.safe_dump(payload), encoding="utf-8")
    admin_env["identities"].identities = load_identities(
        str(admin_env["identities_path"])
    ).identities

    with pytest.raises(WriteRefused) as exc:
        store.delete_identity("root", actor="root", rev=store.identities_revision())
    assert "console password" in str(exc.value)
    assert "root" in admin_env["identities"].identities


async def test_self_service_password_change(admin_env):
    """Even a viewer must be able to change their own password.

    They may write nothing else. An access whose password only
    someone else can change will never be changed.
    """
    app = admin_env["app"]
    fresh = "a-new-viewer-password"
    async with _client(app) as client:
        await _login(client, "eye")
        page = await client.get(f"{UI_PREFIX}/account")
        assert page.status_code == 200
        marker = 'name="_csrf" value="'
        start = page.text.index(marker) + len(marker)
        csrf = page.text[start : page.text.index('"', start)]

        response = await client.post(
            f"{UI_PREFIX}/account/password",
            data={
                "_csrf": csrf,
                "rev": admin_env["store"].identities_revision(),
                "current": PASSWORDS["eye"],
                "password": fresh,
                "confirm": fresh,
            },
        )
        assert response.status_code == 200
        assert "Password changed" in response.text
        # The own session survives the change.
        assert (await client.get(f"{UI_PREFIX}/")).status_code == 200

    identities = admin_env["identities"]
    assert identities.authenticate_console("eye", fresh) is not None
    assert identities.authenticate_console("eye", PASSWORDS["eye"]) is None


async def test_self_service_needs_the_current_password(admin_env):
    """An unsupervised session must not be able to take over the access."""
    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client, "eye")
        page = await client.get(f"{UI_PREFIX}/account")
        marker = 'name="_csrf" value="'
        start = page.text.index(marker) + len(marker)
        csrf = page.text[start : page.text.index('"', start)]

        response = await client.post(
            f"{UI_PREFIX}/account/password",
            data={
                "_csrf": csrf,
                "rev": admin_env["store"].identities_revision(),
                "current": "that-is-not-it",
                "password": "taken-over-password",
                "confirm": "taken-over-password",
            },
        )
        assert response.status_code == 400
        assert "current password is not correct" in response.text

    assert admin_env["identities"].authenticate_console("eye", PASSWORDS["eye"])


async def test_password_change_without_csrf_is_refused(admin_env):
    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client, "eye")
        response = await client.post(
            f"{UI_PREFIX}/account/password",
            data={
                "rev": "",
                "current": PASSWORDS["eye"],
                "password": "not-going-through",
                "confirm": "not-going-through",
            },
        )
        assert response.status_code == 403
        assert "form token" in response.text
    assert admin_env["identities"].authenticate_console("eye", PASSWORDS["eye"])


async def test_admin_password_reset_ends_the_other_sessions(admin_env):
    """If an admin sets someone else's password, the open session is over.

    Otherwise exactly the session that he is trying to close would remain open --
    the password change is the usual response to a suspicion.
    """
    app, store = admin_env["app"], admin_env["store"]
    async with _client(app) as viewer, _client(app) as admin:
        await _login(viewer, "eye")
        assert (await viewer.get(f"{UI_PREFIX}/")).status_code == 200

        csrf = await _signed_in(admin)
        response = await admin.post(
            f"{UI_PREFIX}/identities/edit",
            data={
                "_csrf": csrf,
                "rev": store.identities_revision(),
                "replaces": "eye",
                "id": "eye",
                "role": "viewer",
                "scopes": "",
                "password": "reset-by-admin",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303

        after = await viewer.get(f"{UI_PREFIX}/", follow_redirects=False)
        assert after.status_code == 303, "the old session must be terminated"
        # The admin themselves remains signed in.
        assert (await admin.get(f"{UI_PREFIX}/")).status_code == 200

    assert admin_env["identities"].authenticate_console("eye", "reset-by-admin")


async def test_identities_page_shows_who_can_sign_in(admin_env):
    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/identities")
    assert "console access" in page.text
    assert "api only" in page.text


def test_a_password_on_an_agent_role_never_reaches_the_file(admin_env):
    """Must fail before writing.

    The loader rejects a password on an agent role, and after every
    write operation the file is reloaded. A check only afterwards
    would have already made the file unreadable -- the service would
    no longer start.
    """
    store = admin_env["store"]
    before = admin_env["identities_path"].read_text(encoding="utf-8")
    with pytest.raises(WriteRefused) as exc:
        store.save_identity(
            identity_id="eye", role="agent", tools=[], scopes=[],
            actor="root", rev=store.identities_revision(), replaces="eye",
            password="a-password-for-nobody",
        )
    assert "door without a room" in str(exc.value)
    assert admin_env["identities_path"].read_text(encoding="utf-8") == before
    # The file still loads -- that is the actual finding.
    assert load_identities(str(admin_env["identities_path"])).identities["eye"].role == "viewer"


async def test_pending_page_distinguishes_real_from_missing_tools_in_a_grant(admin_env):
    """A `grant_set` proposal naming a tool that doesn't exist must not look
    the same on /ui/requests as one naming a real, enabled tool -- otherwise
    a human can approve a grant to nothing without ever noticing (the gap
    found and fixed after the first real-world use of /admin/mcp).
    """
    pending = admin_env["pending"]
    pending.propose(
        action="grant_set",
        actor="hermes",
        payload={
            "identity_id": "bot",
            "role": "agent",
            "tools": ["demo.show", "demo.ghost"],
            "scopes": ["stack:*"],
        },
        base_rev=admin_env["store"].identities_revision(),
    )

    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/requests?tab=change")

    assert "demo.show" in page.text
    assert "demo.ghost" in page.text
    # The real, enabled tool is marked as such -- not lumped in with the
    # missing one under a single "2 tool grant(s)" count.
    assert "enabled" in page.text
    # The nonexistent tool is unmistakably flagged, not silently accepted.
    assert "missing" in page.text
    assert "no such tool in the catalog" in page.text


# -- Toolkits (plan "Follow-up 2") -------------------------------------------


async def test_toolkits_deploy_requires_csrf_token(admin_env):
    """Same guarantee as every other write route -- proven directly for
    the one route in this file that may ever write toolkits.yaml.
    """
    toolkit_proposals = admin_env["toolkit_proposals"]
    item = toolkit_proposals.propose(
        name="zfs", spec={"executor": "local", "binaries": [PYTHON]}, actor="hermes",
    )
    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client)
        response = await client.post(
            f"{UI_PREFIX}/toolkits/deploy", data={"id": item.id},
        )
        assert response.status_code == 403
        assert "form token" in response.text
    assert toolkit_proposals.get(item.id).status == "pending"


async def test_toolkits_deploy_requires_admin_role(admin_env):
    toolkit_proposals = admin_env["toolkit_proposals"]
    item = toolkit_proposals.propose(
        name="zfs", spec={"executor": "local", "binaries": [PYTHON]}, actor="hermes",
    )
    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client, "eye")
        page = await client.get(f"{UI_PREFIX}/requests?tab=toolkit")
        assert page.status_code == 200
        # A viewer does not even see the deploy/reject buttons.
        assert f"{UI_PREFIX}/toolkits/deploy" not in page.text

        blocked = await client.post(
            f"{UI_PREFIX}/toolkits/deploy", data={"id": item.id, "_csrf": "x"},
        )
        assert blocked.status_code == 403
        assert "role: admin" in blocked.text
    assert toolkit_proposals.get(item.id).status == "pending"


async def test_toolkits_deploy_over_http_writes_toolkits_yaml_live(admin_env):
    """The full path: propose (as Hermes would, store-level here) -> a
    human approves at /ui/requests (Toolkit tab) -> toolkits.yaml is written and the
    running service reflects the new toolkit -- no restart.
    """
    toolkit_proposals = admin_env["toolkit_proposals"]
    service = admin_env["service"]
    assert "zfs" not in service.tier1.toolkits

    item = toolkit_proposals.propose(
        name="zfs", spec={"executor": "local", "binaries": [PYTHON]}, actor="hermes",
    )
    app = admin_env["app"]
    async with _client(app) as client:
        csrf = await _signed_in(client)
        response = await client.post(
            f"{UI_PREFIX}/toolkits/deploy",
            data={"id": item.id, "_csrf": csrf},
            follow_redirects=False,
        )
        assert response.status_code == 303
    assert "zfs" in service.tier1.toolkits
    assert toolkit_proposals.get(item.id).status == "deployed"


async def test_toolkits_reject_leaves_toolkits_yaml_unchanged(admin_env):
    toolkit_proposals = admin_env["toolkit_proposals"]
    item = toolkit_proposals.propose(
        name="zfs", spec={"executor": "local", "binaries": [PYTHON]}, actor="hermes",
    )
    app = admin_env["app"]
    async with _client(app) as client:
        csrf = await _signed_in(client)
        response = await client.post(
            f"{UI_PREFIX}/toolkits/reject",
            data={"id": item.id, "_csrf": csrf, "reason": "not now"},
            follow_redirects=False,
        )
        assert response.status_code == 303
    assert toolkit_proposals.get(item.id).status == "rejected"
    assert "zfs" not in admin_env["service"].tier1.toolkits

# -- Approve-all (batch) ------------------------------------------------------


async def test_approve_all_applies_every_pending_proposal(admin_env):
    """Two independent proposals → one POST applies both."""
    pending = admin_env["pending"]
    store = admin_env["store"]
    # Two independent proposals targeting different records.
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.echo"},
        base_rev=store.tool_revision("demo.echo"),
    )
    live = [i for i in pending.list() if i.status == "pending"]
    assert len(live) == 2

    app = admin_env["app"]
    async with _client(app) as client:
        csrf = await _signed_in(client)
        # GET confirm page.
        page = await client.get(f"{UI_PREFIX}/pending/approve-all")
        assert page.status_code == 200
        assert "Approve all 2" in page.text
        # POST.
        r = await client.post(
            f"{UI_PREFIX}/pending/approve-all",
            data={"_csrf": csrf, "id": [live[0].id, live[1].id]},
            follow_redirects=False,
        )
        assert r.status_code == 303
    # Both are now approved.
    assert pending.get(live[0].id).status == "approved"
    assert pending.get(live[1].id).status == "approved"


async def test_approve_all_partial_failure_still_applies_rest(admin_env):
    """Two proposals against the same record → first applies, second goes stale."""
    pending = admin_env["pending"]
    store = admin_env["store"]
    # Disable the tool first so that tool_enable actually changes its state.
    store.set_tool_enabled("demo.show", False, actor="root", rev=store.tools_revision())
    # Two proposals targeting the same tool — the second will go stale
    # because the first changes the tool's fingerprint.
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    live = [i for i in pending.list() if i.status == "pending"]
    assert len(live) == 2

    app = admin_env["app"]
    async with _client(app) as client:
        csrf = await _signed_in(client)
        r = await client.post(
            f"{UI_PREFIX}/pending/approve-all",
            data={"_csrf": csrf, "id": [live[0].id, live[1].id]},
            follow_redirects=False,
        )
        # Partial failure → 400 with summary.
        assert r.status_code == 400
        assert "Applied 1" in r.text
        assert "Refused 1" in r.text
    # First is approved, second is stale.
    assert pending.get(live[0].id).status == "approved"
    assert pending.get(live[1].id).status in ("stale", "pending")


async def test_approve_all_only_applies_submitted_ids(admin_env):
    """A third proposal not in the POST body stays pending."""
    pending = admin_env["pending"]
    store = admin_env["store"]
    for tool_id in ("demo.show", "demo.echo", "demo.ping"):
        pending.propose(
            action="tool_enable",
            actor="hermes",
            payload={"id": tool_id},
            base_rev=store.tool_revision(tool_id),
        )
    live = [i for i in pending.list() if i.status == "pending"]
    assert len(live) == 3

    app = admin_env["app"]
    async with _client(app) as client:
        csrf = await _signed_in(client)
        # POST with only the first two ids.
        r = await client.post(
            f"{UI_PREFIX}/pending/approve-all",
            data={"_csrf": csrf, "id": [live[0].id, live[1].id]},
            follow_redirects=False,
        )
        assert r.status_code == 303
    # First two approved, third still pending.
    assert pending.get(live[0].id).status == "approved"
    assert pending.get(live[1].id).status == "approved"
    assert pending.get(live[2].id).status == "pending"


async def test_approve_all_without_csrf_is_refused(admin_env):
    """CSRF absent → 403 and nothing applied."""
    pending = admin_env["pending"]
    store = admin_env["store"]
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.echo"},
        base_rev=store.tool_revision("demo.echo"),
    )
    live = [i for i in pending.list() if i.status == "pending"]

    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client)
        r = await client.post(
            f"{UI_PREFIX}/pending/approve-all",
            data={"id": [live[0].id, live[1].id]},  # no _csrf
            follow_redirects=False,
        )
        assert r.status_code == 403
    # Nothing applied.
    assert all(pending.get(i.id).status == "pending" for i in live)


async def test_approve_all_viewer_role_refused_and_link_absent(admin_env):
    """Viewer role → 403 on POST, and the Approve-all link is absent from the page."""
    pending = admin_env["pending"]
    store = admin_env["store"]
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.echo"},
        base_rev=store.tool_revision("demo.echo"),
    )
    live = [i for i in pending.list() if i.status == "pending"]

    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client, "eye")
        # The Approve-all link should not appear for a viewer.
        page = await client.get(f"{UI_PREFIX}/requests?tab=change")
        assert "pending/approve-all" not in page.text
        # POST should be refused.
        r = await client.post(
            f"{UI_PREFIX}/pending/approve-all",
            data={"id": [live[0].id, live[1].id]},
            follow_redirects=False,
        )
        assert r.status_code == 403
    assert all(pending.get(i.id).status == "pending" for i in live)


async def test_approve_all_link_appears_with_two_pending(admin_env):
    """The Approve-all link appears when can_decide and >=2 pending items."""
    pending = admin_env["pending"]
    store = admin_env["store"]
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    pending.propose(
        action="tool_enable",
        actor="hermes",
        payload={"id": "demo.echo"},
        base_rev=store.tool_revision("demo.echo"),
    )

    app = admin_env["app"]
    async with _client(app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/requests?tab=change")
        assert "Approve all (2)" in page.text
        assert f"{UI_PREFIX}/pending/approve-all" in page.text
