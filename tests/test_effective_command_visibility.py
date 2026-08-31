"""What actually ran, and which definition actually runs.

Both halves here come from one real misdiagnosis. A `docker.compose_ps`
call was failing with `unknown shorthand flag: 'p' in -p` -- the docker
CLI's way of saying it never saw the `compose` subcommand -- and the
command builder was blamed for three rounds before the definition was.

Nothing in the system could settle it, and that was the actual defect:

* The audit log recorded `parameters`, not the command. `{"stack":
  "jellyfin"}` is identical whether the template is right or wrong, so
  the log could not distinguish a bad definition from a bad argument.
* `admin.tool_get` returned every version of an entry. A correct `argv`
  in a superseded version reads exactly like a correct definition unless
  the reader cross-references `current_version` by hand.

So the tests below pin the two things that make a failing call legible:
the resolved argv reaches the audit record, and `tool_get` names the one
version that runs.
"""

from __future__ import annotations

import json

import pytest
import yaml

from conftest import PYTHON, make_catalog
from gatekeeper.admin_service import AdminActionError, AdminService
from gatekeeper.audit import AuditLog
from gatekeeper.errors import Denied
from gatekeeper.pending import PendingStore
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.toolkit_proposals import ToolkitProposalStore


def _calls(tmp_path, tool: str | None = None) -> list[dict]:
    path = tmp_path / "logs" / "audit.jsonl"
    entries = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    return [
        e
        for e in entries
        if e.get("kind") == "call" and (tool is None or e.get("tool") == tool)
    ]


# -- The resolved argv reaches the audit log -------------------------------


async def test_a_successful_call_records_the_command_it_ran(
    service, identities, tmp_path
):
    store, _ = identities
    await service.call(store.identities["full"], "demo.show", {"stack": "media-jellyfin"})

    argv = _calls(tmp_path, "demo.show")[-1]["argv"]
    assert argv[0] == PYTHON, "the binary is the first element, as executed"
    assert "media-jellyfin" in argv[-1]
    # Not a rendered string: one element per argv element is the whole
    # point of FR-5.4, and a joined string would lose exactly the boundary
    # that guarantees it.
    assert isinstance(argv, list)
    assert all(isinstance(part, str) for part in argv)


async def test_the_argv_separates_a_bad_template_from_a_bad_argument(
    tmp_path, tier1, identities, tool_specs
):
    """The reason this field exists.

    Two definitions, the same parameters, the same identity -- and only
    the command tells them apart. Without it, the audit records are
    indistinguishable, which is precisely the position the compose
    misdiagnosis argued from.
    """
    broken = [dict(spec) for spec in tool_specs]
    for spec in broken:
        if spec["id"] == "demo.show":
            # Drops the leading '-c', the way the live catalog had dropped
            # 'compose' -- same shape of defect, same invisible symptom.
            spec["argv"] = spec["argv"][1:]
    catalog = make_catalog(tmp_path, tier1, broken)
    service = Service(tier1=tier1, catalog=catalog, audit=AuditLog(str(tmp_path / "logs")))

    store, _ = identities
    await service.call(store.identities["full"], "demo.show", {"stack": "media-jellyfin"})

    entry = _calls(tmp_path, "demo.show")[-1]
    assert entry["parameters"] == {
        "stack": "media-jellyfin",
        "compose_path": entry["parameters"]["compose_path"],
    }, "the parameters look entirely healthy -- that is the trap"
    assert "-c" not in entry["argv"], "and the argv is where the defect is visible"


async def test_a_denial_before_the_argv_exists_records_none(
    service, identities, tmp_path
):
    """`_authorize` denies before a command is built.

    A regression test with a scar: wiring the argv through initially read
    it in the denial handler while it was still assigned further down, so
    every not-granted call raised `UnboundLocalError` instead of auditing
    a denial.
    """
    store, _ = identities
    with pytest.raises(Denied):
        await service.call(store.identities["narrow"], "demo.echo", {"text": "hi"})

    entry = _calls(tmp_path, "demo.echo")[-1]
    assert entry["outcome"] == "denied"
    assert entry["denial_reason"] == "not_granted"
    assert entry["argv"] is None


async def test_known_secrets_are_masked_in_the_argv(
    service, identities, tmp_path
):
    """FR-10.6 covers the new field too, because `write` scrubs the whole
    record -- worth pinning, since a command line is exactly the place an
    operator would fear a credential surfacing."""
    service.audit.set_secrets(("hunter2",))
    store, _ = identities
    await service.call(store.identities["full"], "demo.echo", {"text": "hunter2"})

    entry = _calls(tmp_path, "demo.echo")[-1]
    assert "hunter2" not in json.dumps(entry["argv"])


# -- `tool_get` names the version that runs --------------------------------


def _admin(tmp_path, tier1, entries) -> AdminService:
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": entries}), encoding="utf-8")
    from gatekeeper.catalog import load_catalog
    from gatekeeper.identity import generate_token, hash_token, load_identities

    # An empty identities.yaml is rejected on load -- nobody could ever
    # authenticate against it -- so the file carries the one admin whose
    # id these tests pass as the actor.
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root", "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [], "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(
        tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit
    )
    store = ConfigStore(
        service=service, identities=load_identities(str(identities_path)), audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    return AdminService(
        store=store,
        pending=PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit),
        toolkit_proposals=ToolkitProposalStore(
            path=str(tmp_path / "proposals.yaml"), audit=audit, service=service,
            toolkits_path=str(tmp_path / "toolkits.yaml"), tools_path=str(tools_path),
            identities_path=str(identities_path),
        ),
    )


def _versioned(tool_specs, *, current: int) -> list[dict]:
    """One entry, two versions: v1 correct, v2 with the argv truncated."""
    base = next(spec for spec in tool_specs if spec["id"] == "demo.show")
    good = {k: v for k, v in base.items() if k not in ("id", "enabled")}
    bad = dict(good, argv=good["argv"][1:])
    return [
        {
            "id": "demo.show",
            "enabled": True,
            "deleted": False,
            "current_version": current,
            "versions": [
                {"version": 1, "spec": good, "superseded": current != 1},
                {"version": 2, "spec": bad, "superseded": current != 2},
            ],
        }
    ]


def test_effective_is_the_version_current_version_names(tmp_path, tier1, tool_specs):
    """The misdiagnosis, reproduced and then made visible.

    `versions` still carries the healthy v1 -- a reader who stops there
    concludes the definition is fine. `effective` says which one runs.
    """
    admin = _admin(tmp_path, tier1, _versioned(tool_specs, current=2))
    entry = admin.tool_get("root", {"id": "demo.show"})

    assert entry["current_version"] == 2
    assert [v["version"] for v in entry["versions"]] == [1, 2]
    assert entry["versions"][0]["spec"]["argv"][0] == "-c", "v1 still looks correct"
    assert entry["effective"]["argv"][0] != "-c", "and v2 is what actually runs"
    assert entry["effective"]["version"] == 2


def test_effective_follows_current_version_when_it_points_elsewhere(
    tmp_path, tier1, tool_specs
):
    admin = _admin(tmp_path, tier1, _versioned(tool_specs, current=1))
    entry = admin.tool_get("root", {"id": "demo.show"})

    assert entry["effective"]["version"] == 1
    assert entry["effective"]["argv"][0] == "-c"


def test_effective_matches_what_the_executor_loaded(tmp_path, tier1, tool_specs):
    """Not merely self-consistent: the same argv the catalog handed the
    executor. If these two ever diverge, `effective` would be a second
    opinion rather than the answer."""
    admin = _admin(tmp_path, tier1, _versioned(tool_specs, current=2))
    entry = admin.tool_get("root", {"id": "demo.show"})
    loaded = admin.store.service.catalog.tools["demo.show"]

    assert list(entry["effective"]["argv"]) == list(loaded.argv)


def test_unknown_tool_still_raises(tmp_path, tier1, tool_specs):
    admin = _admin(tmp_path, tier1, _versioned(tool_specs, current=1))
    with pytest.raises(AdminActionError):
        admin.tool_get("root", {"id": "demo.nope"})
