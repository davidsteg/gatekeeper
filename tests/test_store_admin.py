"""Tier 2 writes through `ConfigStore` (moved from `test_ui_admin.py`).

An admin can change the configuration of a service that has
root-equivalent access to the host. These are the store-level halves of
the console's write-path guarantees -- whatever surface drives the store
(`/api/v1`, `/admin/mcp` approvals), these hold:

* Can an admin override Tier 1? (no -- same check path)
* Can you lock yourself out or corrupt the file?
  (no -- last admin protected, written atomically, revision checked)
* Do secrets stay out of files and the log? (passwords only as hashes,
  tokens never logged)

The HTTP halves (roles, CSRF, sessions) live in `test_api_*.py`.
"""

from __future__ import annotations

import json
import os

import pytest
import yaml
from conftest import PYTHON

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore, WriteRefused, load_tool_yaml

#: Console passwords of the two humans in the test. The agent has none --
#: it does not sign in anywhere.
PASSWORDS = {"root": "admin-console-password", "eye": "viewer-console-password"}


@pytest.fixture
def admin_env(tmp_path, tier1, tool_specs):
    """Writable Tier 2 files and the `ConfigStore` over them -- no app."""
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
    return {
        "store": store,
        "service": service,
        "identities": identities,
        "tokens": tokens,
        "tools_path": tools_path,
        "identities_path": identities_path,
        "tier1": tier1,
    }


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


def test_no_store_function_writes_tier1(admin_env):
    """`ConfigStore` (Tier 2 writes) has no function that writes

    `toolkits.yaml` at all -- the one exception lives entirely outside it,
    in `ToolkitProposalStore.deploy`, reachable only from a human approving
    a toolkit proposal in the console -- never automatically and never from
    `/admin/mcp`. (v0.23.0 briefly gave `ConfigStore` its own
    `save_toolkit` that applied instantly from `/admin/mcp` with no human
    review; that broke this invariant and was reverted in v0.23.1.) The
    HTTP route walk for the same rule is in `test_api_*.py` (FR-4.11).
    """
    assert not hasattr(admin_env["store"], "save_toolkit")


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

