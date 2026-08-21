"""The pending-actions queue and `admin_service.apply_pending`.

Unit-level: no HTTP, no MCP protocol -- those are covered end-to-end in
`test_admin_mcp.py`. Here the concern is `pending.py`'s own guarantees
(propose/approve/reject, stale-on-race) and that `apply_pending` calls the
exact same `ConfigStore` mutator a human `/ui` write would.
"""

from __future__ import annotations

import yaml

from conftest import PYTHON
from gatekeeper.admin_service import apply_pending
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import IdentityStore, generate_token, hash_token, load_identities
from gatekeeper.pending import PendingStore, PendingWriteRefused
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore, WriteRefused


def _env(tmp_path, tier1, tool_specs):
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")

    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "password_hash": hash_token("x" * 20),
                        "tools": [],
                        "scopes": [],
                    },
                    {
                        "id": "hermes",
                        "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [],
                        "scopes": [],
                    },
                    {
                        "id": "bot",
                        "role": "agent",
                        "token_hash": hash_token(generate_token()),
                        "tools": [],
                        "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(identities_path))
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit)
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
    return store, pending, tools_path, identities_path


# -- Propose / list / reject -------------------------------------------------


def test_propose_then_list_then_reject(tmp_path, tier1, tool_specs):
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)

    item = pending.propose(
        action="tool_delete", actor="hermes",
        payload={"id": "demo.show"}, base_rev=store.tool_revision("demo.show"),
    )
    assert item.status == "pending"
    listed = pending.list()
    assert len(listed) == 1 and listed[0].id == item.id

    rejected = pending.reject(item.id, decided_by="root", reason="not needed")
    assert rejected.status == "rejected"
    assert rejected.reason == "not needed"
    # State is unchanged and still visible.
    assert pending.get(item.id).status == "rejected"
    assert "demo.show" in load_catalog(str(_tp), tier1).tools


def test_reject_unknown_action_refused(tmp_path, tier1, tool_specs):
    _store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    try:
        pending.reject("does-not-exist", decided_by="root")
        assert False, "expected PendingWriteRefused"
    except PendingWriteRefused:
        pass


def test_reject_already_decided_refused(tmp_path, tier1, tool_specs):
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    item = pending.propose(
        action="tool_delete", actor="hermes",
        payload={"id": "demo.show"}, base_rev=store.tool_revision("demo.show"),
    )
    pending.reject(item.id, decided_by="root")
    try:
        pending.reject(item.id, decided_by="root")
        assert False, "expected PendingWriteRefused"
    except PendingWriteRefused:
        pass


# -- Approve applies the exact ConfigStore mutator ---------------------------


def test_approve_tool_delete_applies_and_matches_direct_ui_write(tmp_path, tier1, tool_specs):
    store, pending, tools_path, _ip = _env(tmp_path, tier1, tool_specs)
    item = pending.propose(
        action="tool_delete", actor="hermes",
        payload={"id": "demo.show"}, base_rev=store.tool_revision("demo.show"),
    )
    apply_pending(store, pending, item.id, decided_by="root")

    assert "demo.show" not in store.service.catalog.tools
    # Soft-deleted: the raw entry survives with its history (FR-3.1).
    raw = store.service.catalog.raw_of("demo.show")
    assert raw is not None and raw.get("deleted") is True

    approved = pending.get(item.id)
    assert approved.status == "approved"
    assert approved.decided_by == "root"


def test_approve_grant_set_updates_identity_tools(tmp_path, tier1, tool_specs):
    """`grant_set` targets an *agent*-role identity -- the only role that
    can ever call a tool on `/mcp`. An `admin`-role identity (Hermes'
    own) is rejected outright on `/mcp` by `AuthMiddleware`'s per-mount
    role gate, so granting it tools would be meaningless.
    """
    store, pending, _tp, identities_path = _env(tmp_path, tier1, tool_specs)
    item = pending.propose(
        action="grant_set", actor="hermes",
        payload={
            "identity_id": "bot", "role": "agent",
            "tools": ["demo.show"], "scopes": [],
        },
        base_rev=store.identity_revision("bot"),
    )
    apply_pending(store, pending, item.id, decided_by="root")
    assert store.identities.identities["bot"].tools == frozenset({"demo.show"})


def test_approve_role_set_updates_identity_role(tmp_path, tier1, tool_specs):
    """`hermes` starts as an admin with no console password (`/admin/mcp`
    only). Give it one directly first, as a human would via the identity
    editor -- otherwise demoting it to viewer would also hit
    `save_identity`'s "role needs a console password" guard, which is not
    what this test is about. `root` staying an admin with a password keeps
    the last-admin guard from firing too.
    """
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    store.save_identity(
        identity_id="hermes", role="admin", tools=[], scopes=[],
        actor="root", rev=store.identities_revision(), replaces="hermes",
        password="x" * 20,
    )
    item = pending.propose(
        action="role_set", actor="root",
        payload={
            "identity_id": "hermes", "role": "viewer",
            "tools": [], "scopes": [],
        },
        base_rev=store.identity_revision("hermes"),
    )
    apply_pending(store, pending, item.id, decided_by="root")
    assert store.identities.identities["hermes"].role == "viewer"


def test_approve_nonexistent_action_refused(tmp_path, tier1, tool_specs):
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    try:
        apply_pending(store, pending, "nope", decided_by="root")
        assert False, "expected WriteRefused"
    except WriteRefused:
        pass


# -- Stale on a revision race -------------------------------------------------


def test_approve_not_stale_when_unrelated_tool_changes(tmp_path, tier1, tool_specs):
    """Changing a DIFFERENT tool's record must not stale this proposal --
    staleness is checked per-record, not by hashing the whole file. Two
    proposals against unrelated tools/identities in the same YAML file
    must not invalidate each other (the false positive this fixes).
    """
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    item = pending.propose(
        action="tool_delete", actor="hermes",
        payload={"id": "demo.show"}, base_rev=store.tool_revision("demo.show"),
    )
    # Something else changes tools.yaml -- but not demo.show's own record.
    store.set_tool_enabled("demo.echo", False, actor="root", rev=store.tools_revision())

    apply_pending(store, pending, item.id, decided_by="root")  # must not raise

    assert "demo.show" not in store.service.catalog.tools
    assert pending.get(item.id).status == "approved"


def test_approve_marks_stale_when_same_tool_changes(tmp_path, tier1, tool_specs):
    store, pending, tools_path, _ip = _env(tmp_path, tier1, tool_specs)
    item = pending.propose(
        action="tool_delete", actor="hermes",
        payload={"id": "demo.show"}, base_rev=store.tool_revision("demo.show"),
    )
    # Something else changes demo.show's OWN record before the human reviews it.
    store.set_tool_enabled("demo.show", False, actor="root", rev=store.tools_revision())

    try:
        apply_pending(store, pending, item.id, decided_by="root")
        assert False, "expected PendingWriteRefused (stale)"
    except PendingWriteRefused as exc:
        assert "stale" in str(exc).lower()

    marked = pending.get(item.id)
    assert marked.status == "stale"
    # No silent re-basing: the tool is still enabled, untouched by the proposal.
    assert store.service.catalog.tools["demo.show"].enabled is False


def test_stale_item_cannot_be_approved_again(tmp_path, tier1, tool_specs):
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    item = pending.propose(
        action="tool_delete", actor="hermes",
        payload={"id": "demo.show"}, base_rev=store.tool_revision("demo.show"),
    )
    store.set_tool_enabled("demo.show", False, actor="root", rev=store.tools_revision())
    try:
        apply_pending(store, pending, item.id, decided_by="root")
    except PendingWriteRefused:
        pass
    # Still refused -- status is 'stale', not 'pending'.
    try:
        apply_pending(store, pending, item.id, decided_by="root")
        assert False, "expected PendingWriteRefused"
    except PendingWriteRefused as exc:
        assert "already" in str(exc).lower() or "stale" in str(exc).lower()


def test_approve_role_set_marks_stale_when_identities_moved_since_proposal(
    tmp_path, tier1, tool_specs
):
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    item = pending.propose(
        action="role_set", actor="hermes",
        payload={
            "identity_id": "bot", "role": "viewer",
            "tools": [], "scopes": [],
        },
        base_rev=store.identity_revision("bot"),
    )
    # Something else changes identities.yaml before the human reviews it.
    store.save_identity(
        identity_id="bot", role="agent", tools=["demo.show"], scopes=[],
        actor="root", rev=store.identities_revision(), replaces="bot",
    )

    try:
        apply_pending(store, pending, item.id, decided_by="root")
        assert False, "expected PendingWriteRefused (stale)"
    except PendingWriteRefused as exc:
        assert "stale" in str(exc).lower()

    marked = pending.get(item.id)
    assert marked.status == "stale"
    # No silent re-basing: the role is still what the concurrent write set.
    assert store.identities.identities["bot"].role == "agent"


# -- Per-record fingerprinting fixes the cross-record false positive --------


def test_two_pending_grant_sets_for_different_identities_do_not_invalidate_each_other(
    tmp_path, tier1, tool_specs
):
    """The reported bug: Hermes batch-proposing grant/role changes for
    several identities in one session, then a human approving them one at
    a time, used to stale every proposal after the first approval -- even
    ones targeting a completely different identity.
    """
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    # hermes needs a console password before it can become 'viewer' --
    # give it one first, so this proposal's own base_rev already reflects it.
    store.save_identity(
        identity_id="hermes", role="admin", tools=[], scopes=[],
        actor="root", rev=store.identities_revision(), replaces="hermes",
        password="x" * 20,
    )
    item_bot = pending.propose(
        action="grant_set", actor="hermes",
        payload={"identity_id": "bot", "role": "agent", "tools": ["demo.show"], "scopes": []},
        base_rev=store.identity_revision("bot"),
    )
    item_hermes = pending.propose(
        action="role_set", actor="root",
        payload={"identity_id": "hermes", "role": "viewer", "tools": [], "scopes": []},
        base_rev=store.identity_revision("hermes"),
    )

    apply_pending(store, pending, item_bot.id, decided_by="root")  # must not raise
    assert store.identities.identities["bot"].tools == frozenset({"demo.show"})
    assert pending.get(item_bot.id).status == "approved"

    # hermes' own proposal must still be approvable -- bot's approval just
    # rewrote the whole identities.yaml file, but never touched hermes' own
    # record.
    apply_pending(store, pending, item_hermes.id, decided_by="root")  # must not raise stale
    assert store.identities.identities["hermes"].role == "viewer"
    assert pending.get(item_hermes.id).status == "approved"


def test_two_pending_tool_deletes_for_different_tools_do_not_invalidate_each_other(
    tmp_path, tier1, tool_specs
):
    store, pending, _tp, _ip = _env(tmp_path, tier1, tool_specs)
    item_show = pending.propose(
        action="tool_delete", actor="hermes",
        payload={"id": "demo.show"}, base_rev=store.tool_revision("demo.show"),
    )
    item_echo = pending.propose(
        action="tool_delete", actor="hermes",
        payload={"id": "demo.echo"}, base_rev=store.tool_revision("demo.echo"),
    )

    apply_pending(store, pending, item_show.id, decided_by="root")  # must not raise
    assert "demo.show" not in store.service.catalog.tools
    assert pending.get(item_show.id).status == "approved"

    apply_pending(store, pending, item_echo.id, decided_by="root")  # must not raise stale
    assert "demo.echo" not in store.service.catalog.tools
    assert pending.get(item_echo.id).status == "approved"


# -- Last-admin guard still fires through an approved pending identity change --


def test_approving_last_admin_deletion_still_refused(tmp_path, tier1, tool_specs):
    """No parallel guard was built for the pending path -- `apply_pending`
    calls `store.delete_identity`, and that function's own
    `_guard_last_admin` fires exactly as it would for a direct /ui delete.
    """
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "password_hash": hash_token("x" * 20),
                        "tools": [],
                        "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(identities_path))
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit)
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)

    # `identity_delete` is not an admin.* action exposed via AdminService,
    # but `apply_pending`'s dispatch is independent of that -- exercise the
    # guard the way a hand-built "identity_delete" pending item would.
    from gatekeeper import admin_service as admin_service_mod

    def _apply_identity_delete(store, item):
        return store.delete_identity(item.payload["id"], actor=item.actor, rev=store.identities_revision())

    admin_service_mod._APPLIERS["identity_delete"] = (
        _apply_identity_delete, "identities", lambda payload: payload["id"],
    )
    try:
        item = pending.propose(
            action="identity_delete", actor="root",
            payload={"id": "root"}, base_rev=store.identity_revision("root"),
        )
        try:
            apply_pending(store, pending, item.id, decided_by="root")
            assert False, "expected WriteRefused from _guard_last_admin"
        except WriteRefused as exc:
            assert "last" in str(exc).lower() or "admin" in str(exc).lower()
    finally:
        del admin_service_mod._APPLIERS["identity_delete"]
