"""The second MCP server: the `admin.*` namespace (REQUIREMENTS.md FR-2.8/2.9).

A hand-written, fixed tool list wired straight to `AdminService` -- this
`Server` instance shares no `Catalog`/tool registry with the agent-facing
one in `server.py`, so admin tools cannot leak into `/mcp` (or vice versa)
by construction. `server.py` mounts this at `/admin/mcp`, under the same
`AuthMiddleware` that role-gates each mount so a non-admin token is
rejected here outright.

`approve` and `reject` are not on `_TOOLS` and have no handler here --
`admin_service.apply_pending` (the only function that turns a pending item
into a live change) is called exclusively from `ui.py`. There is no code
path from this file that reaches it.
"""

from __future__ import annotations

import json
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server

from gatekeeper import __version__

from ._authctx import identity_from as _identity_from
from .admin_service import (
    EXPOSED_ACTIONS,
    EXPOSED_ASYNC_ACTIONS,
    AdminActionError,
    AdminService,
)
from .credentials import KINDS as CREDENTIAL_KINDS
from .errors import ConfigError
from .identity import ROLES
from .store import WriteRefused

_OPEN_OBJECT: dict[str, Any] = {"type": "object", "additionalProperties": True}
_ID_ONLY: dict[str, Any] = {
    "type": "object",
    "properties": {"id": {"type": "string"}},
    "required": ["id"],
    "additionalProperties": False,
}

#: The fixed `admin.*` tool list (FR-2.8/2.9, REQUIREMENTS.md §17's
#: middle-ground resolution). Every entry's bare name must appear in
#: `admin_service.EXPOSED_ACTIONS` or its awaited counterpart
#: `EXPOSED_ASYNC_ACTIONS` -- checked once at import time below -- and
#: nothing else does: `approve`/`reject` are absent from all three.
_TOOLS: list[types.Tool] = [
    types.Tool(
        name="admin.tool_list",
        title="List tool definitions",
        description=(
            "Lists every tool definition (id, enabled, deleted, current "
            "version, category, full version history). Read-only."
        ),
        inputSchema={
            "type": "object",
            "properties": {"include_deleted": {"type": "boolean"}},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.tool_get",
        title="Get one tool definition",
        description=(
            "Returns one tool's full record: 'versions' is the complete "
            "history, and 'effective' is the single version that actually "
            "runs, resolved from 'current_version'. Read 'effective' when "
            "asking what a tool does today -- a field can be correct in a "
            "superseded version and wrong in the live one. Read-only."
        ),
        inputSchema=_ID_ONLY,
    ),
    types.Tool(
        name="admin.tool_create",
        title="Create a tool definition",
        description=(
            "Creates a new tool definition. Always applies immediately, but "
            "the tool is always created disabled (enabled: false) regardless "
            "of what 'spec' says -- enabling it is a separate, auditable "
            "step via admin.tool_enable."
        ),
        inputSchema={
            "type": "object",
            "properties": {"spec": _OPEN_OBJECT},
            "required": ["spec"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.tool_update",
        title="Update a tool definition",
        description=(
            "Appends a new version to an existing tool definition (never "
            "overwrites -- old versions remain fetchable via admin.tool_get). "
            "Applies immediately if the resulting category is 'read'; "
            "otherwise it is written to the pending queue for a human to "
            "approve at /ui/requests (Change tab)."
        ),
        inputSchema={
            "type": "object",
            "properties": {"id": {"type": "string"}, "spec": _OPEN_OBJECT},
            "required": ["id", "spec"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.tool_enable",
        title="Enable a tool",
        description=(
            "Enables a tool. Applies immediately if its category is 'read'; "
            "otherwise it is written to the pending queue for a human to "
            "approve at /ui/requests (Change tab)."
        ),
        inputSchema=_ID_ONLY,
    ),
    types.Tool(
        name="admin.tool_disable",
        title="Disable a tool",
        description="Disables a tool. Always applies immediately -- disabling only narrows access.",
        inputSchema=_ID_ONLY,
    ),
    types.Tool(
        name="admin.tool_delete",
        title="Delete a tool definition",
        description=(
            "Soft-deletes a tool definition (version history is retained). "
            "Always written to the pending queue for a human to approve."
        ),
        inputSchema=_ID_ONLY,
    ),
    types.Tool(
        name="admin.tool_validate",
        title="Validate a tool definition",
        description=(
            "Checks a tool definition against Tier 1 without storing "
            "anything -- the same validation path startup and every write "
            "use. Read-only."
        ),
        inputSchema={
            "type": "object",
            "properties": {"spec": _OPEN_OBJECT},
            "required": ["spec"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.tool_exec",
        title="Run a tool",
        description=(
            "Runs a catalog tool and returns its real outcome, exit code, "
            "stdout and stderr -- the same execution path an agent's call "
            "takes on /mcp, audited the same way under the admin's own "
            "identity. Intended for verifying a definition you just "
            "changed, without having to ask an agent whether it works. "
            "Grants and scopes do not apply (an admin identity can hold "
            "neither); everything else does -- the tool must be enabled, "
            "protected resources stay blocked, and Tier 1 is re-checked "
            "against the resolved argv. Disabled unless Tier 1 declares "
            "'admin_exec: true', which takes a redeploy."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": (
                        "Catalog tool ID, e.g. 'docker.compose_ps'. Where a "
                        "toolkit declares destinations, use the expanded ID "
                        "('docker.compose_ps@nas1') -- admin.tool_get "
                        "reports them as 'grantable_ids'."
                    ),
                },
                "arguments": {
                    **_OPEN_OBJECT,
                    "description": (
                        "The tool's own parameters, e.g. {\"stack\": "
                        "\"jellyfin\"}. Derived parameters are computed by "
                        "the server and rejected here, exactly as on /mcp."
                    ),
                },
            },
            "required": ["id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.grant_list",
        title="List grants",
        description="Lists identities and the tool IDs/scopes each holds. Read-only.",
        inputSchema={
            "type": "object",
            "properties": {
                "tool_id": {"type": "string"},
                "identity_id": {"type": "string"},
            },
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.grant_set",
        title="Set an identity's tool grants",
        description=(
            "Replaces an existing identity's tool grants (and, if given, its "
            "scopes). Cannot create a new identity. Always written to the "
            "pending queue for a human to approve -- this is the only "
            "identity mutation exposed on /admin/mcp."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "identity_id": {"type": "string"},
                "tools": {"type": "array", "items": {"type": "string"}},
                "scopes": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["identity_id", "tools"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.role_set",
        title="Change an identity's role",
        description=(
            "Changes an existing identity's role (agent/viewer/admin). "
            "Cannot create a new identity. Always written to the pending "
            "queue for a human to approve -- role changes go through the "
            "same review surface as grant changes."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "identity_id": {"type": "string"},
                "role": {"type": "string", "enum": list(ROLES)},
            },
            "required": ["identity_id", "role"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.audit_query",
        title="Query the audit log",
        description="Reads recent audit log entries, optionally filtered. Read-only.",
        inputSchema={
            "type": "object",
            "properties": {
                "identity": {"type": "string"},
                "tool": {"type": "string"},
                "outcome": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            },
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.pending_list",
        title="List pending actions",
        description=(
            "Lists proposals in the pending queue, optionally filtered by "
            "status (pending/approved/rejected/stale). Read-only -- approving "
            "or rejecting a proposal is only possible through /ui/requests (Change tab), "
            "never from here."
        ),
        inputSchema={
            "type": "object",
            "properties": {"status": {"type": "string"}},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.release_notes",
        title="Read this deployment's release notes",
        description=(
            "Returns RELEASE.md -- the notes for every version of the "
            "gatekeeper you are managing, newest first. `full: true` gives "
            "the whole file verbatim including the release rule, the "
            "procedure and the versioning scheme; otherwise it is "
            "version-by-version, narrowable with `version` (exact), "
            "`search` (case-insensitive, matched against heading and body) "
            "and `limit` (default 10). Read-only. Check here what a version "
            "actually changed before blaming a deployment for it."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "version": {"type": "string"},
                "search": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                "full": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.toolkit_list",
        title="List live toolkits",
        description=(
            "Lists every toolkit and destination defined in the running "
            "Tier 1 configuration (toolkits.yaml) -- executor, binaries, "
            "path roots, protected resources, ceilings. Read-only; check "
            "reality here before drafting a proposal instead of guessing."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.cred_propose",
        title="Propose a new credential slot",
        description=(
            "Proposes a new named credential -- name, kind, and (for "
            "api_key_header/url_query) the header/param name. There is no "
            "'value' property, and one sent anyway is explicitly refused, "
            "never stored or ignored quietly: no operation on /admin/mcp "
            "ever carries a secret (FR-10.2/10.8), not even to create one. "
            "Always written to the pending queue and never auto-applies -- "
            "a human reviews the proposed name/kind/header at /ui/requests "
            "and, if they approve, types the actual secret value there "
            "themselves; the value never exists anywhere an agent could "
            "have written it."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "kind": {"type": "string", "enum": sorted(CREDENTIAL_KINDS)},
                "header": {"type": "string"},
            },
            "required": ["name", "kind"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.toolkit_propose",
        title="Propose a new toolkit",
        description=(
            "Proposes adding a brand-new toolkit to Tier 1. Always written "
            "to the toolkit-proposal queue -- never applies, not even for a "
            "read-only-looking toolkit -- since this changes what is "
            "possible at all (REQUIREMENTS.md §6), not just who can do "
            "what. A human reviews it at /ui/toolkits and, if they approve, "
            "gatekeeper validates, writes toolkits.yaml, and reloads it "
            "into the running process itself -- no redeploy needed, but "
            "also no way for this call to make it live on its own. Editing "
            "an existing toolkit is not supported here; the name must be new."
        ),
        inputSchema={
            "type": "object",
            "properties": {"name": {"type": "string"}, "spec": _OPEN_OBJECT},
            "required": ["name", "spec"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.toolkit_update",
        title="Propose updating a toolkit's executor/binaries",
        description=(
            "Proposes changing an existing toolkit's executor type, "
            "binaries, denied_args, and/or run_as (the OS user a 'file' "
            "toolkit's operations run as). Only these four fields can be "
            "proposed — path_roots, protected_resources, and limits remain "
            "deploy-time only (FR-4.11) and are rejected, so a proposal can "
            "change who an operation runs as but never widen where it may "
            "reach. Like "
            "admin.toolkit_propose, this changes Tier 1 -- what is possible "
            "at all, not just who can do what -- so it is always written to "
            "the toolkit-proposal queue and never applies on its own. A "
            "human reviews it at /ui/requests (Toolkit tab) and, if they "
            "approve, gatekeeper validates, writes toolkits.yaml, and "
            "reloads it into the running process itself -- no redeploy "
            "needed, but also no way for this call to make it live by "
            "itself. Example: propose switching executor from 'local' to "
            "'file' by passing "
            "updates={\"executor\": \"file\", \"binaries\": [], \"denied_args\": []}, "
            "or pointing an existing 'file' toolkit at another user with "
            "updates={\"run_as\": \"3001:3001\"}."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Toolkit name"},
                "updates": {
                    "type": "object",
                    "description": "Fields to propose changing (executor, binaries, denied_args, run_as only)",
                    "properties": {
                        "executor": {"type": "string"},
                        "binaries": {"type": "array", "items": {"type": "string"}},
                        "denied_args": {"type": "array", "items": {"type": "string"}},
                        "run_as": {
                            # null, not just a string: handing a toolkit back
                            # to the container user has to be proposable too,
                            # or the only way to undo a run_as would be the
                            # redeploy this whole path exists to avoid.
                            "type": ["string", "null"],
                            "description": (
                                "'file' toolkits only: the OS user its file "
                                "operations run as -- an account name in the "
                                "container image ('hermes') or a numeric "
                                "'uid:gid' pair ('3001:3001'). A bare uid is "
                                "rejected. null clears it, handing the "
                                "toolkit back to the container user. Only "
                                "takes effect where the container was started "
                                "privileged enough to change user; elsewhere "
                                "the calls fail."
                            ),
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "required": ["name", "updates"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="admin.toolkit_delete",
        title="Propose deleting a toolkit",
        description=(
            "Proposes removing an existing toolkit from Tier 1. Refused at "
            "deploy time if the toolkit no longer exists or any non-deleted "
            "tool still references it. Like admin.toolkit_propose/"
            "toolkit_update, this changes Tier 1 -- what is possible at "
            "all, not just who can do what -- so it is always written to "
            "the toolkit-proposal queue and never applies on its own. A "
            "human reviews it at /ui/requests (Toolkit tab) and, if they "
            "approve, gatekeeper removes it from toolkits.yaml and reloads "
            "it into the running process itself -- no restart needed, but "
            "also no way for this call to make it take effect by itself."
        ),
        inputSchema={
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Toolkit name"}},
            "required": ["name"],
            "additionalProperties": False,
        },
    ),
]

# Kept honest at import time, not merely by convention: if these two lists
# ever drift apart, building the admin server fails loudly instead of
# quietly exposing (or hiding) a tool.
_names = {t.name.removeprefix("admin.") for t in _TOOLS}
_reachable = set(EXPOSED_ACTIONS) | set(EXPOSED_ASYNC_ACTIONS)
if _names != _reachable:
    raise AssertionError(
        f"admin_server._TOOLS and admin_service's exposed actions have "
        f"drifted apart: {_names!r} != {_reachable!r}"
    )


def build_admin_mcp_server(admin_service: AdminService) -> Server[None]:
    async def on_list_tools(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        # Requires a valid identity like the agent-facing server does, even
        # though `AuthMiddleware` has already role-gated this mount -- an
        # unauthenticated context should still see nothing.
        _identity_from(ctx)
        return types.ListToolsResult(tools=list(_TOOLS), cacheScope="private")

    async def on_call_tool(
        ctx: Any, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        identity = _identity_from(ctx)
        name = params.name.removeprefix("admin.")
        try:
            # Two dispatch paths because the executors are async and the
            # catalog writes are not -- see `AdminService.call_async`. The
            # name decides, and each table is an explicit allowlist, so an
            # action can never take the wrong one.
            if name in EXPOSED_ASYNC_ACTIONS:
                result = await admin_service.call_async(
                    identity.id, name, params.arguments or {}
                )
            else:
                result = admin_service.call(identity.id, name, params.arguments or {})
        except (AdminActionError, WriteRefused, ConfigError) as exc:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(exc))],
                isError=True,
            )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(result, default=str))],
            isError=False,
        )

    return Server(
        "gatekeeper-admin",
        # The real version, not a hand-set constant: an admin client asking
        # `serverInfo` which build it is talking to was told "0.1.0" by
        # every release since this endpoint existed, which is worse than no
        # answer -- it is a wrong one that looks authoritative. The
        # agent-facing server in `server.py` has always reported
        # `__version__`; these two describe the same process.
        version=__version__,
        instructions=(
            "Self-service catalog and grant management for gatekeeper. "
            "Read-only queries and low-risk changes (creating a disabled "
            "tool, disabling a tool, enabling/updating a read-category "
            "tool) apply immediately. Anything that expands what an agent "
            "can do -- enabling/updating a write tool, deleting a tool, "
            "granting access -- is written to a pending queue and takes "
            "effect only once a human approves it at /ui/requests (Change tab). There is "
            "no way to approve your own proposal from this endpoint."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


__all__ = ["build_admin_mcp_server"]
