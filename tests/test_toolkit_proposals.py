"""`ToolkitProposalStore` -- propose/list/reject/deploy (plan "Follow-up 2":
let Hermes draft toolkits, with a one-click human deploy, not agent-live).

Unit-level: no HTTP, no MCP protocol -- those are covered end-to-end in
`test_admin_mcp.py`. Here the concern is this store's own guarantees: a
deploy validates the *entire* merged toolkits.yaml with the exact
`load_tier1()` startup uses before writing anything real, rejects a name
collision, and on success writes atomically and calls
`Service.reload_config` synchronously -- no restart, no background task,
and the new toolkit is live in the same process afterwards.
"""

from __future__ import annotations

import os

import yaml

from conftest import PYTHON
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_proposals import ToolkitProposalStore, ToolkitProposalWriteRefused


def _toolkit_spec(sandbox, *, binaries=None):
    return {
        "executor": "local",
        "binaries": binaries or [PYTHON],
        "denied_args": [],
        "path_roots": [str(sandbox)],
        "protected_resources": [],
        "max_timeout_seconds": 10,
        "max_output_bytes": 4096,
    }


def _env(tmp_path, sandbox):
    toolkits_path = tmp_path / "toolkits.yaml"
    toolkits_path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {"demo": _toolkit_spec(sandbox)},
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")
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
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    tier1 = load_tier1(str(toolkits_path))
    catalog = load_catalog(str(tools_path), tier1)
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)

    store = ToolkitProposalStore(
        path=str(tmp_path / "toolkit_proposals.yaml"),
        audit=audit,
        service=service,
        toolkits_path=str(toolkits_path),
        tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    return store, service, str(toolkits_path)


# -- Propose / list -----------------------------------------------------------


def test_propose_then_list(tmp_path, sandbox):
    store, _service, _tp = _env(tmp_path, sandbox)
    item = store.propose(name="zfs", spec=_toolkit_spec(sandbox), actor="hermes")
    assert item.status == "pending"
    assert item.name == "zfs"

    listed = store.list()
    assert len(listed) == 1 and listed[0].id == item.id

    fetched = store.get(item.id)
    assert fetched is not None and fetched.name == "zfs"


def test_list_filters_by_status(tmp_path, sandbox):
    store, _service, _tp = _env(tmp_path, sandbox)
    item = store.propose(name="zfs", spec=_toolkit_spec(sandbox), actor="hermes")
    store.reject(item.id, decided_by="root", reason="not now")
    assert store.list(status="rejected")[0].id == item.id
    assert store.list(status="pending") == []


# -- Reject --------------------------------------------------------------------


def test_reject_leaves_toolkits_yaml_unchanged(tmp_path, sandbox):
    store, _service, toolkits_path = _env(tmp_path, sandbox)
    before = open(toolkits_path, encoding="utf-8").read()
    item = store.propose(name="zfs", spec=_toolkit_spec(sandbox), actor="hermes")

    rejected = store.reject(item.id, decided_by="root", reason="not needed")
    assert rejected.status == "rejected"
    assert rejected.reason == "not needed"
    assert open(toolkits_path, encoding="utf-8").read() == before


def test_reject_already_decided_refused(tmp_path, sandbox):
    store, _service, _tp = _env(tmp_path, sandbox)
    item = store.propose(name="zfs", spec=_toolkit_spec(sandbox), actor="hermes")
    store.reject(item.id, decided_by="root")
    try:
        store.reject(item.id, decided_by="root")
        assert False, "expected ToolkitProposalWriteRefused"
    except ToolkitProposalWriteRefused:
        pass


# -- Deploy: collision ----------------------------------------------------------


def test_deploy_rejects_name_collision_and_leaves_toolkits_yaml_untouched(tmp_path, sandbox):
    store, service, toolkits_path = _env(tmp_path, sandbox)
    before = open(toolkits_path, encoding="utf-8").read()
    old_tier1 = service.tier1

    # 'demo' already exists in toolkits.yaml.
    item = store.propose(name="demo", spec=_toolkit_spec(sandbox), actor="hermes")

    try:
        store.deploy(item.id, decided_by="root")
        assert False, "expected ToolkitProposalWriteRefused (name collision)"
    except ToolkitProposalWriteRefused as exc:
        assert "already exists" in str(exc)

    assert open(toolkits_path, encoding="utf-8").read() == before
    assert service.tier1 is old_tier1
    assert store.get(item.id).status == "pending"


# -- Deploy: Tier-1 validation failure --------------------------------------


def test_deploy_rejects_tier1_invalid_proposal_and_leaves_state_untouched(tmp_path, sandbox):
    store, service, toolkits_path = _env(tmp_path, sandbox)
    before = open(toolkits_path, encoding="utf-8").read()
    old_tier1 = service.tier1
    old_catalog = service.catalog

    # A binary not on any absolute-path allowlist rule / missing required
    # field -- 'executor' is required and absent here, so `load_tier1`
    # must reject the merged config before anything real is touched.
    bad_spec = {"binaries": [PYTHON]}
    item = store.propose(name="broken", spec=bad_spec, actor="hermes")

    try:
        store.deploy(item.id, decided_by="root")
        assert False, "expected ToolkitProposalWriteRefused (Tier-1 invalid)"
    except ToolkitProposalWriteRefused as exc:
        assert "invalid" in str(exc).lower()

    # Nothing real touched: neither the file, nor the running Service's
    # in-memory tier1/catalog -- reload_config never got a chance to run,
    # let alone corrupt anything, because validation happens first.
    assert open(toolkits_path, encoding="utf-8").read() == before
    assert service.tier1 is old_tier1
    assert service.catalog is old_catalog
    assert store.get(item.id).status == "pending"


# -- Deploy: success --------------------------------------------------------


def test_deploy_writes_atomically_reloads_and_becomes_live_without_restart(tmp_path, sandbox):
    store, service, toolkits_path = _env(tmp_path, sandbox)
    assert "zfs" not in service.tier1.toolkits

    item = store.propose(name="zfs", spec=_toolkit_spec(sandbox), actor="hermes")
    deployed = store.deploy(item.id, decided_by="root")

    assert deployed.status == "deployed"
    assert deployed.decided_by == "root"

    # Live in the same process -- no restart, no SIGHUP needed.
    assert "zfs" in service.tier1.toolkits
    assert set(service.tier1.toolkits) == {"demo", "zfs"}

    # And on disk, so a real restart would also come back with it.
    on_disk = yaml.safe_load(open(toolkits_path, encoding="utf-8").read())
    assert "zfs" in on_disk["toolkits"]
    assert "demo" in on_disk["toolkits"]

    assert store.get(item.id).status == "deployed"


def test_deploy_already_decided_refused(tmp_path, sandbox):
    store, _service, _tp = _env(tmp_path, sandbox)
    item = store.propose(name="zfs", spec=_toolkit_spec(sandbox), actor="hermes")
    store.deploy(item.id, decided_by="root")
    try:
        store.deploy(item.id, decided_by="root")
        assert False, "expected ToolkitProposalWriteRefused"
    except ToolkitProposalWriteRefused as exc:
        assert "already" in str(exc).lower()


def test_deploy_unknown_proposal_refused(tmp_path, sandbox):
    store, _service, _tp = _env(tmp_path, sandbox)
    try:
        store.deploy("does-not-exist", decided_by="root")
        assert False, "expected ToolkitProposalWriteRefused"
    except ToolkitProposalWriteRefused:
        pass


# -- Delete -------------------------------------------------------------------


def _write_tools(tools_path, entries):
    open(tools_path, "w", encoding="utf-8").write(
        yaml.safe_dump({"tools": entries})
    )


def test_delete_propose_rejects_nonempty_spec(tmp_path, sandbox):
    store, _service, _tp = _env(tmp_path, sandbox)
    try:
        store.propose(name="demo", spec={"executor": "local"}, actor="hermes", kind="delete")
        assert False, "expected ToolkitProposalWriteRefused"
    except ToolkitProposalWriteRefused as exc:
        assert "no 'spec'" in str(exc)


def test_deploy_delete_removes_toolkit_and_reloads(tmp_path, sandbox):
    store, service, toolkits_path = _env(tmp_path, sandbox)
    assert "demo" in service.tier1.toolkits

    item = store.propose(name="demo", spec={}, actor="hermes", kind="delete")
    deployed = store.deploy(item.id, decided_by="root")

    assert deployed.status == "deployed"
    assert "demo" not in service.tier1.toolkits

    on_disk = yaml.safe_load(open(toolkits_path, encoding="utf-8").read())
    assert "demo" not in on_disk["toolkits"]
    assert store.get(item.id).status == "deployed"


def test_deploy_delete_rejects_missing_toolkit_and_leaves_state_untouched(tmp_path, sandbox):
    store, service, toolkits_path = _env(tmp_path, sandbox)
    before = open(toolkits_path, encoding="utf-8").read()
    old_tier1 = service.tier1

    item = store.propose(name="ghost", spec={}, actor="hermes", kind="delete")
    try:
        store.deploy(item.id, decided_by="root")
        assert False, "expected ToolkitProposalWriteRefused (no such toolkit)"
    except ToolkitProposalWriteRefused as exc:
        assert "No toolkit named" in str(exc)

    assert open(toolkits_path, encoding="utf-8").read() == before
    assert service.tier1 is old_tier1
    assert store.get(item.id).status == "pending"


def test_deploy_delete_rejects_when_tool_still_references_toolkit(tmp_path, sandbox):
    store, service, toolkits_path = _env(tmp_path, sandbox)
    before = open(toolkits_path, encoding="utf-8").read()
    _write_tools(store.tools_path, [{"id": "demo.run", "toolkit": "demo"}])

    item = store.propose(name="demo", spec={}, actor="hermes", kind="delete")
    try:
        store.deploy(item.id, decided_by="root")
        assert False, "expected ToolkitProposalWriteRefused (still referenced)"
    except ToolkitProposalWriteRefused as exc:
        assert "demo.run" in str(exc)

    assert open(toolkits_path, encoding="utf-8").read() == before
    assert "demo" in service.tier1.toolkits
    assert store.get(item.id).status == "pending"


def test_deploy_delete_ignores_soft_deleted_referencing_tool(tmp_path, sandbox):
    store, service, _toolkits_path = _env(tmp_path, sandbox)
    # Versioned shape, matching what `catalog.soft_delete_entry` actually
    # produces -- a flat `deleted: true` entry with no `versions:` list
    # would not be recognized as deleted by `load_catalog` itself (only
    # `_tools_referencing_toolkit`'s raw check would see it), which would
    # make this test pass for the wrong reason.
    _write_tools(
        store.tools_path,
        [
            {
                "id": "demo.run",
                "toolkit": "demo",
                "enabled": True,
                "deleted": True,
                "current_version": 1,
                "versions": [{"version": 1, "spec": {"toolkit": "demo"}}],
            }
        ],
    )

    item = store.propose(name="demo", spec={}, actor="hermes", kind="delete")
    deployed = store.deploy(item.id, decided_by="root")

    assert deployed.status == "deployed"
    assert "demo" not in service.tier1.toolkits


def test_reject_delete_leaves_toolkits_yaml_unchanged(tmp_path, sandbox):
    store, _service, toolkits_path = _env(tmp_path, sandbox)
    before = open(toolkits_path, encoding="utf-8").read()
    item = store.propose(name="demo", spec={}, actor="hermes", kind="delete")

    rejected = store.reject(item.id, decided_by="root", reason="not yet")
    assert rejected.status == "rejected"
    assert open(toolkits_path, encoding="utf-8").read() == before
