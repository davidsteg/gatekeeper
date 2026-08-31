"""`admin.tool_exec` -- running a catalog tool from `/admin/mcp`.

An admin identity can define a tool but never call one: `/mcp` rejects the
`admin` role (`server.py`'s `AuthMiddleware`), and `grant_set` refuses to
grant tools to anything whose role is not `agent`. So an admin could set an
`argv` and then had to ask an agent whether it actually worked.

`admin.tool_exec` closes that, and the security question it raises is the
point of most of these tests. It does not consult grants or scopes -- an
admin can hold neither, so checking them would deny every call rather than
decide anything -- which is a real widening: `tool_create` plus
`tool_enable` plus this is a path from an admin token to a running command
with no human in it. The compensation is that it is Tier 1: `admin_exec`
is declared at deploy time, defaults off, and cannot be switched on through
the admin API (FR-4.11).

So the tests below pin what the exception relaxes (grants, scopes) and,
more importantly, everything it must not: the off-by-default gate, the
enabled flag, FR-4.12's protected resources, Tier 1's re-check against the
resolved argv, and the audit record.
"""

from __future__ import annotations

import copy
import json

import pytest
import yaml

from conftest import PYTHON
from gatekeeper.admin_service import (
    EXPOSED_ACTIONS,
    EXPOSED_ASYNC_ACTIONS,
    AdminActionError,
    AdminService,
)
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.pending import PendingStore
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_proposals import ToolkitProposalStore

ADMIN = "hermes"
AGENT = "narrow"


def _build(tmp_path, sandbox, tool_specs, *, admin_exec: bool) -> AdminService:
    """An `AdminService` whose Tier 1 has admin execution on or off.

    Built from written YAML rather than constructed objects, the same way
    `conftest` does it: the loaders then run inside the test, so a Tier 1
    that would not parse on a host fails here instead.
    """
    toolkits_path = tmp_path / "toolkits.yaml"
    section: dict = {
        "toolkits": {
            "demo": {
                "executor": "local",
                "binaries": [PYTHON],
                "denied_args": ["--dangerous", "rm"],
                "path_roots": [str(sandbox)],
                "protected_resources": ["gatekeeper", "dockhand"],
                "max_timeout_seconds": 30,
                "max_output_bytes": 8192,
            }
        },
        "audit": {"dir": str(tmp_path / "logs")},
    }
    if admin_exec:
        section["admin_exec"] = True
    toolkits_path.write_text(yaml.safe_dump(section), encoding="utf-8")
    tier1 = load_tier1(str(toolkits_path))

    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")

    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    # No tools and no scopes -- the only shape an admin
                    # identity can have, since `grant_set` rejects any
                    # non-agent role.
                    {
                        "id": ADMIN, "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [], "scopes": [],
                    },
                    {
                        "id": AGENT, "role": "agent",
                        "token_hash": hash_token(generate_token()),
                        "tools": ["demo.show"], "scopes": ["stack:media-*"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(identities_path))
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(
        tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit
    )
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    return AdminService(
        store=store,
        pending=PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit),
        toolkit_proposals=ToolkitProposalStore(
            path=str(tmp_path / "proposals.yaml"), audit=audit, service=service,
            toolkits_path=str(toolkits_path), tools_path=str(tools_path),
            identities_path=str(identities_path),
        ),
    )


@pytest.fixture
def admin_on(tmp_path, sandbox, tool_specs):
    return _build(tmp_path, sandbox, tool_specs, admin_exec=True)


@pytest.fixture
def admin_off(tmp_path, sandbox, tool_specs):
    return _build(tmp_path, sandbox, tool_specs, admin_exec=False)


# -- The Tier 1 gate -------------------------------------------------------


async def test_off_unless_tier1_turns_it_on(admin_off):
    """The default is refusal, and the message says where the switch is."""
    with pytest.raises(AdminActionError) as exc:
        await admin_off.tool_exec(ADMIN, {"id": "demo.show", "arguments": {"stack": "x"}})
    assert "admin_exec" in str(exc.value)
    assert "toolkits.yaml" in str(exc.value)


def test_admin_exec_defaults_to_false_in_tier1(admin_off, admin_on):
    """The flag, not merely the error message -- a default that flipped
    silently would turn every existing deployment into an executing one."""
    assert admin_off.store.service.tier1.admin_exec is False
    assert admin_on.store.service.tier1.admin_exec is True


# -- What it does ----------------------------------------------------------


async def test_runs_the_tool_and_reports_the_real_exit_code(admin_on, sandbox):
    result = await admin_on.tool_exec(
        ADMIN, {"id": "demo.show", "arguments": {"stack": "media-jellyfin"}}
    )
    assert result["ok"] is True
    assert result["outcome"] == "ok"
    assert result["exit_code"] == 0
    assert str(sandbox) in result["stdout"]
    assert isinstance(result["duration_ms"], int)


async def test_admin_needs_no_grant_but_an_agent_still_does(admin_on):
    """The exception is scoped to the admin role, not opened for everyone.

    The admin holds `tools: []` and `scopes: []` and succeeds; the agent
    holds a grant for this tool but a scope profile that does not cover
    this stack, and is still refused. If the bypass ever widened past the
    role check, this second half would start passing.
    """
    ok = await admin_on.tool_exec(
        ADMIN, {"id": "demo.show", "arguments": {"stack": "production"}}
    )
    assert ok["outcome"] != "denied"

    # Same tool, same stack, same running process -- only the identity
    # differs. 'stack:production' is outside the agent's 'stack:media-*'.
    denied = await admin_on.tool_exec(
        AGENT, {"id": "demo.show", "arguments": {"stack": "production"}}
    )
    assert denied["ok"] is False
    assert denied["denial_reason"] == "scope_mismatch"


# -- What it must not relax ------------------------------------------------


async def test_a_disabled_tool_stays_disabled(tmp_path, sandbox, tool_specs):
    specs = copy.deepcopy(tool_specs)
    for spec in specs:
        if spec["id"] == "demo.echo":
            spec["enabled"] = False
    admin = _build(tmp_path, sandbox, specs, admin_exec=True)

    result = await admin.tool_exec(ADMIN, {"id": "demo.echo", "arguments": {"text": "hi"}})
    assert result["ok"] is False
    assert result["denial_reason"] in ("tool_disabled", "unknown_tool")


async def test_protected_resources_stay_blocked(admin_on):
    """FR-4.12 is a Tier 1 block list, not a permission -- and an admin is
    exactly who it exists to stop from shutting down gatekeeper itself."""
    result = await admin_on.tool_exec(
        ADMIN, {"id": "demo.show", "arguments": {"stack": "gatekeeper"}}
    )
    assert result["ok"] is False
    assert result["denial_reason"] == "protected_resource"


async def test_tier1_is_rechecked_against_the_resolved_argv(admin_on):
    """FR-4.2 on the resolved argv, not just the template: a parameter
    value that becomes a denied argument is caught for an admin too."""
    result = await admin_on.tool_exec(ADMIN, {"id": "demo.echo", "arguments": {"text": "rm"}})
    assert result["ok"] is False
    assert result["denial_reason"] == "tier1_violation"


async def test_the_call_is_audited_under_the_admin_identity(admin_on, tmp_path):
    await admin_on.tool_exec(
        ADMIN, {"id": "demo.show", "arguments": {"stack": "media-jellyfin"}}
    )
    lines = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    calls = [
        entry
        for entry in (json.loads(line) for line in lines)
        if entry.get("kind") == "call" and entry.get("tool") == "demo.show"
    ]
    assert calls, "the execution must leave an audit record"
    entry = calls[-1]
    assert entry["identity"] == ADMIN
    assert entry["outcome"] == "ok"
    assert entry["exit_code"] == 0
    assert "duration_ms" in entry


# -- Argument handling and dispatch ---------------------------------------


async def test_rejects_arguments_that_are_not_an_object(admin_on):
    with pytest.raises(AdminActionError):
        await admin_on.tool_exec(ADMIN, {"id": "demo.echo", "arguments": ["text", "hi"]})


async def test_unknown_tool_is_reported_as_a_denial(admin_on):
    result = await admin_on.tool_exec(ADMIN, {"id": "demo.nope", "arguments": {}})
    assert result["ok"] is False
    assert result["denial_reason"] == "unknown_tool"


async def test_dispatch_tables_stay_disjoint_and_typed(admin_on):
    """`tool_exec` must not be reachable through the sync `call`.

    Sync dispatch would return an un-awaited coroutine, which serialises
    as a result nobody ran -- a silent success for a call that never
    happened. Each name belongs to exactly one table.
    """
    assert not (EXPOSED_ACTIONS & EXPOSED_ASYNC_ACTIONS)
    assert "tool_exec" in EXPOSED_ASYNC_ACTIONS

    with pytest.raises(AdminActionError):
        admin_on.call(ADMIN, "tool_exec", {"id": "demo.echo"})
    with pytest.raises(AdminActionError):
        await admin_on.call_async(ADMIN, "tool_list", {})


async def test_call_async_runs_it_end_to_end(admin_on):
    result = await admin_on.call_async(
        ADMIN, "tool_exec", {"id": "demo.show", "arguments": {"stack": "media-jellyfin"}}
    )
    assert result["exit_code"] == 0
