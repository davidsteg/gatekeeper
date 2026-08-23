"""Tests for the ``admin.toolkit_update`` -> toolkit-proposal-queue path.

Since v0.23.1, `admin.toolkit_update` no longer writes `toolkits.yaml`
directly and immediately from `/admin/mcp` -- that broke the two-tier
model's key invariant (Tier 1 is never runtime-writable without a human in
the loop, REQUIREMENTS.md §6) and, in practice, meant an admin-role agent
token could flip a toolkit's executor live with no review step at all. It
now works exactly like `admin.toolkit_propose`: the call only *proposes* a
change (kind="update" on the same `ToolkitProposalStore`/
`toolkit_proposals.yaml` queue `admin.toolkit_propose` uses), and only a
human clicking "Approve & Deploy" at `/ui/requests` (Toolkit tab) can make
it take effect (`ToolkitProposalStore.deploy`).

Only `executor`/`binaries`/`denied_args` may ever appear in an update
proposal -- `path_roots`, `protected_resources`, and `limits` remain
deploy-time only, checked both at propose time (immediate feedback) and
again at deploy time (the authoritative gate, defense in depth).
"""

from __future__ import annotations

import yaml

from conftest import PYTHON
from gatekeeper.admin_service import AdminService
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.pending import PendingStore
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_proposals import ToolkitProposalStore, ToolkitProposalWriteRefused


def _env(tmp_path, sandbox):
    toolkits_path = tmp_path / "toolkits.yaml"
    toolkits_path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "demo": {
                        "executor": "local",
                        "binaries": [PYTHON],
                        "denied_args": [],
                        "path_roots": [str(sandbox)],
                        "protected_resources": ["gatekeeper"],
                        "max_timeout_seconds": 30,
                        "max_output_bytes": 8192,
                    }
                },
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
                        "id": "hermes",
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
    identities = load_identities(str(identities_path))

    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit_proposals.yaml"), audit=audit, service=service,
        toolkits_path=str(toolkits_path), tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    admin = AdminService(store=store, pending=pending, toolkit_proposals=toolkit_proposals)
    return admin, toolkit_proposals, service, str(toolkits_path)


# -- admin.toolkit_update never applies on its own ---------------------------


def test_toolkit_update_only_proposes_never_applies(tmp_path, sandbox):
    admin, toolkit_proposals, service, _tp = _env(tmp_path, sandbox)

    result = admin.toolkit_update(
        "hermes",
        {"name": "demo", "updates": {"executor": "file", "binaries": [], "denied_args": []}},
    )

    assert result == {"applied": False, "pending": True, "proposal_id": result["proposal_id"]}
    # Nothing changed live -- the running toolkit is untouched.
    assert service.tier1.toolkit("demo").executor == "local"
    # And it landed on the same queue admin.toolkit_propose uses.
    items = toolkit_proposals.list()
    assert len(items) == 1
    assert items[0].kind == "update"
    assert items[0].name == "demo"
    assert items[0].status == "pending"


def test_toolkit_update_rejects_security_critical_fields_at_propose_time(tmp_path, sandbox):
    admin, _toolkit_proposals, _service, _tp = _env(tmp_path, sandbox)
    try:
        admin.toolkit_update("hermes", {"name": "demo", "updates": {"path_roots": ["/etc"]}})
        assert False, "expected ToolkitProposalWriteRefused"
    except ToolkitProposalWriteRefused as exc:
        assert "path_roots" in str(exc)


def test_toolkit_update_no_updates_returns_error_without_proposing(tmp_path, sandbox):
    admin, toolkit_proposals, _service, _tp = _env(tmp_path, sandbox)
    result = admin.toolkit_update("hermes", {"name": "demo", "updates": {}})
    assert result == {"applied": False, "error": "No updates provided."}
    assert toolkit_proposals.list() == []


# -- Deploying an update proposal (human, /ui/requests only) ----------------


def test_deploy_update_merges_only_the_proposed_fields(tmp_path, sandbox):
    admin, toolkit_proposals, service, toolkits_path = _env(tmp_path, sandbox)

    item = toolkit_proposals.propose(
        name="demo",
        spec={"executor": "file", "binaries": [], "denied_args": []},
        actor="hermes",
        kind="update",
    )
    deployed = toolkit_proposals.deploy(item.id, decided_by="root")

    assert deployed.status == "deployed"
    # Live in the same process, no restart.
    assert service.tier1.toolkit("demo").executor == "file"
    assert service.tier1.toolkit("demo").binaries == ()
    # Untouched fields survive the merge.
    assert service.tier1.toolkit("demo").path_roots == (str(sandbox),)
    assert service.tier1.toolkit("demo").protected_resources == ("gatekeeper",)

    on_disk = yaml.safe_load(open(toolkits_path, encoding="utf-8").read())
    assert on_disk["toolkits"]["demo"]["executor"] == "file"
    assert on_disk["toolkits"]["demo"]["path_roots"] == [str(sandbox)]


def test_deploy_update_rejects_unknown_toolkit(tmp_path, sandbox):
    _admin, toolkit_proposals, _service, toolkits_path = _env(tmp_path, sandbox)
    before = open(toolkits_path, encoding="utf-8").read()

    item = toolkit_proposals.propose(
        name="does-not-exist", spec={"executor": "file"}, actor="hermes", kind="update",
    )
    try:
        toolkit_proposals.deploy(item.id, decided_by="root")
        assert False, "expected ToolkitProposalWriteRefused"
    except ToolkitProposalWriteRefused as exc:
        assert "No toolkit named" in str(exc)
    assert open(toolkits_path, encoding="utf-8").read() == before


def test_propose_rejects_illegal_field_before_anything_is_written(tmp_path, sandbox):
    _admin, toolkit_proposals, _service, toolkits_path = _env(tmp_path, sandbox)
    before = open(toolkits_path, encoding="utf-8").read()
    try:
        toolkit_proposals.propose(
            name="demo", spec={"limits": {"timeout_seconds": 999}}, actor="hermes",
            kind="update",
        )
        assert False, "expected ToolkitProposalWriteRefused"
    except ToolkitProposalWriteRefused as exc:
        assert "limits" in str(exc)
    assert toolkit_proposals.list() == []
    assert open(toolkits_path, encoding="utf-8").read() == before
