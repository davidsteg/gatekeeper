"""The `admin.*` MCP surface's application layer (REQUIREMENTS.md FR-2.8-3.7).

`AdminService` wraps `ConfigStore` + `PendingStore` and is the single
dispatch point `admin_server.py` calls into for every `admin.*` tool. Every
mutating action goes through the *same* `ConfigStore`/`PendingStore`
mutators a human `/ui` write uses -- there is no second, more lenient path
(the same principle `catalog.parse_tool_spec`'s docstring states for tool
definitions applies here to the whole admin surface).

One dispatch table (`_EXPOSED`, enforced by `call`) decides, per action,
whether a change applies immediately or is written to the pending queue:

* read-only queries (`tool_list`, `tool_get`, `tool_validate`, `grant_list`,
  `audit_query`, `pending_list`) always execute directly.
* `tool_create` always auto-applies, but forces the new definition
  `enabled: false` -- creation is always inert (FR-3.x): an admin or a
  later `tool_enable` call is a separate, auditable decision.
* `tool_disable` always auto-applies -- disabling only ever narrows what an
  agent can do.
* `tool_enable`/`tool_update` are category-conditional: a `read`-category
  tool auto-applies, `write`/`write_external` always goes to the pending
  queue.
* `tool_delete` and `grant_set` (the only identity mutation exposed here)
  always go to the pending queue -- they either remove a capability or
  change who has one.

`approve`/`reject` are deliberately **not** methods on this class and are
not in `_EXPOSED`. The only place a pending item is ever turned into a live
change is `apply_pending` below, called exclusively from `ui.py`'s
`/ui/pending` routes (human session + CSRF, exactly like every other admin
write). There is no code path from `/admin/mcp` that reaches it -- FR-2.8's
self-approval prevention is structural, not a permission check.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Any, Callable

from .catalog import normalize_tool_entry, parse_tool_spec
from .errors import ConfigError
from .pending import PendingAction, PendingStore
from .store import ConfigStore, WriteRefused
from .toolkit_proposals import ToolkitProposalStore

# Imported lazily inside `audit_query` (not at module level): `ui.py`
# imports `apply_pending` from this module for its `/ui/pending` routes,
# so a top-level `from .ui import read_audit` here would be circular.


class AdminActionError(ConfigError):
    """A malformed `admin.*` call -- unknown tool name, missing argument."""


def _require_str(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str) or not value:
        raise AdminActionError(f"'{name}' is required and must be a non-empty string.")
    return value


def _require_dict(args: dict[str, Any], name: str) -> dict[str, Any]:
    value = args.get(name)
    if not isinstance(value, dict):
        raise AdminActionError(f"'{name}' is required and must be a mapping.")
    return value


@dataclasses.dataclass(slots=True)
class AdminService:
    store: ConfigStore
    pending: PendingStore
    toolkit_proposals: ToolkitProposalStore

    #: Exact set of action names reachable via `call` -- deliberately an
    #: explicit allowlist rather than a raw `getattr`, so a private helper
    #: method added to this class later cannot become callable from
    #: `/admin/mcp` by accident, and so `approve`/`reject` (which do not
    #: exist on this class at all) stay unreachable in every case.
    def call(self, actor: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in _EXPOSED:
            raise AdminActionError(f"Unknown admin tool {name!r}.")
        method = getattr(self, name)
        return method(actor, arguments)

    # -- Read-only ---------------------------------------------------------

    def tool_list(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        include_deleted = bool(args.get("include_deleted", False))
        out = []
        for raw in self.store.service.catalog.raw:
            entry = normalize_tool_entry(raw)
            if entry["deleted"] and not include_deleted:
                continue
            out.append(entry)
        out.sort(key=lambda e: e["id"] or "")
        return {"tools": out}

    def tool_get(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        tool_id = _require_str(args, "id")
        raw = self.store.service.catalog.raw_of(tool_id)
        if raw is None:
            raise AdminActionError(f"No tool with ID {tool_id!r}.")
        return normalize_tool_entry(raw)

    def tool_validate(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        spec = _require_dict(args, "spec")
        try:
            tool = parse_tool_spec(dict(spec), self.store.service.tier1)
        except ConfigError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "id": tool.id, "category": tool.category}

    def grant_list(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        tool_id = args.get("tool_id")
        identity_id = args.get("identity_id")
        out = []
        for ident in self.store.identities.identities.values():
            if identity_id and ident.id != identity_id:
                continue
            tools = sorted(ident.tools)
            if tool_id and tool_id not in tools:
                continue
            out.append(
                {
                    "identity": ident.id,
                    "role": ident.role,
                    "tools": tools,
                    "scopes": list(ident.scopes),
                }
            )
        out.sort(key=lambda g: g["identity"])
        return {"grants": out}

    def audit_query(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        from .ui import read_audit

        limit = int(args.get("limit") or 200)
        path = os.path.join(self.store.service.tier1.audit_dir, "audit.jsonl")
        records, truncated = read_audit(
            path,
            limit=max(1, min(limit, 1000)),
            identity=str(args.get("identity") or ""),
            tool=str(args.get("tool") or ""),
            outcome=str(args.get("outcome") or ""),
        )
        return {"entries": records, "truncated": truncated}

    def pending_list(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        status = args.get("status") or None
        items = self.pending.list(status=status)
        return {"pending": [i.to_spec() for i in items]}

    def toolkit_list(self, _actor: str, _args: dict[str, Any]) -> dict[str, Any]:
        """Lists live Tier 1 toolkits + destinations, so Hermes can check
        reality (what toolkit/destination names already exist, what a
        toolkit's executor/limits are) instead of guessing before drafting
        a proposal. Read-only -- Tier 1 itself is never written from here.
        """
        tier1 = self.store.service.tier1
        toolkits = [
            {
                "name": name,
                "executor": tk.executor,
                "binaries": list(tk.binaries),
                "denied_args": list(tk.denied_args),
                "path_roots": list(tk.path_roots),
                "protected_resources": list(tk.protected_resources),
                "max_timeout_seconds": tk.max_timeout_seconds,
                "max_output_bytes": tk.max_output_bytes,
                "destinations": list(tk.destinations),
            }
            for name, tk in sorted(tier1.toolkits.items())
        ]
        return {"toolkits": toolkits, "destinations": sorted(tier1.destinations)}

    # -- Always auto-apply ---------------------------------------------------

    def tool_create(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        spec = dict(_require_dict(args, "spec"))
        # Always-inert creation: enabling is a separate, auditable step,
        # and possibly a pending one (see `tool_enable` below).
        spec["enabled"] = False
        tool_id = self.store.save_tool(spec, actor=actor, rev=self.store.tools_revision())
        return {"applied": True, "id": tool_id}

    def tool_disable(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        tool_id = _require_str(args, "id")
        self.store.set_tool_enabled(
            tool_id, False, actor=actor, rev=self.store.tools_revision()
        )
        return {"applied": True, "id": tool_id}

    # -- Category-conditional ------------------------------------------------

    def tool_enable(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        tool_id = _require_str(args, "id")
        flat = self.store.service.catalog.flat_spec_of(tool_id)
        if flat is None:
            raise AdminActionError(f"No tool with ID {tool_id!r}.")
        if flat.get("category") == "read":
            self.store.set_tool_enabled(
                tool_id, True, actor=actor, rev=self.store.tools_revision()
            )
            return {"applied": True, "id": tool_id}
        item = self.pending.propose(
            action="tool_enable",
            actor=actor,
            payload={"id": tool_id},
            base_rev=self.store.tools_revision(),
        )
        return {"applied": False, "pending": True, "pending_id": item.id}

    def tool_update(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        tool_id = _require_str(args, "id")
        spec = dict(_require_dict(args, "spec"))
        spec.setdefault("id", tool_id)
        if spec["id"] != tool_id:
            raise AdminActionError("'spec.id' must match 'id' -- renaming is not supported here.")
        # Validate up front: a definition that would fail `parse_tool_spec`
        # should not consume a pending-queue slot only to be rejected by a
        # human later for the same reason `admin.tool_validate` would have
        # already reported.
        tool = parse_tool_spec(dict(spec), self.store.service.tier1)
        if tool.category == "read":
            new_id = self.store.save_tool(
                spec, actor=actor, rev=self.store.tools_revision(), replaces=tool_id
            )
            return {"applied": True, "id": new_id}
        item = self.pending.propose(
            action="tool_update",
            actor=actor,
            payload={"spec": spec, "replaces": tool_id},
            base_rev=self.store.tools_revision(),
        )
        return {"applied": False, "pending": True, "pending_id": item.id}

    # -- Always pending ------------------------------------------------------

    def tool_delete(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        tool_id = _require_str(args, "id")
        if self.store.service.catalog.raw_of(tool_id) is None:
            raise AdminActionError(f"No tool with ID {tool_id!r}.")
        item = self.pending.propose(
            action="tool_delete",
            actor=actor,
            payload={"id": tool_id},
            base_rev=self.store.tools_revision(),
        )
        return {"applied": False, "pending": True, "pending_id": item.id}

    def grant_set(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        identity_id = _require_str(args, "identity_id")
        existing = self.store.identities.identities.get(identity_id)
        if existing is None:
            raise AdminActionError(f"No identity {identity_id!r}.")
        if existing.role != "agent":
            # Only an `agent`-role identity ever authenticates on `/mcp`
            # (`AuthMiddleware` rejects every other role there) -- granting
            # tools to a `viewer`/`admin` identity would be a right that can
            # never be exercised.
            raise AdminActionError(
                f"{identity_id!r} has role {existing.role!r}, not 'agent' -- "
                "tool grants only take effect for an agent identity."
            )
        raw_tools = args.get("tools")
        if not isinstance(raw_tools, list) or any(not isinstance(t, str) for t in raw_tools):
            raise AdminActionError("'tools' is required and must be a list of strings.")
        if "scopes" in args:
            raw_scopes = args.get("scopes")
            if not isinstance(raw_scopes, list) or any(not isinstance(s, str) for s in raw_scopes):
                raise AdminActionError("'scopes' must be a list of strings.")
            scopes = list(raw_scopes)
        else:
            scopes = list(existing.scopes)
        payload = {
            "identity_id": identity_id,
            "role": existing.role,
            "tools": sorted(set(raw_tools)),
            "scopes": scopes,
        }
        item = self.pending.propose(
            action="grant_set",
            actor=actor,
            payload=payload,
            base_rev=self.store.identities_revision(),
        )
        return {"applied": False, "pending": True, "pending_id": item.id}

    def toolkit_propose(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Always writes to `ToolkitProposalStore`, never auto-applies --
        unlike every other action in this class, a toolkit changes Tier 1
        (REQUIREMENTS.md §6), so there is no "low-risk" variant of this at
        all, not even a read-category one. Deliberately not written to
        `PendingStore`: a toolkit proposal must never be reachable through
        the same review surface as an ordinary tool/grant change (see
        `toolkit_proposals.py`).
        """
        name = _require_str(args, "name")
        spec = dict(_require_dict(args, "spec"))
        item = self.toolkit_proposals.propose(name=name, spec=spec, actor=actor)
        return {"applied": False, "pending": True, "proposal_id": item.id}


#: The complete, fixed set of `admin.*` actions reachable from `/admin/mcp`
#: (FR-2.8/2.9). `admin_server.py`'s tool list is asserted to match this
#: exactly at build time, so the two cannot silently drift apart.
_EXPOSED: tuple[str, ...] = (
    "tool_list",
    "tool_get",
    "tool_create",
    "tool_update",
    "tool_enable",
    "tool_disable",
    "tool_delete",
    "tool_validate",
    "grant_list",
    "grant_set",
    "audit_query",
    "pending_list",
    "toolkit_list",
    "toolkit_propose",
)

EXPOSED_ACTIONS: frozenset[str] = frozenset(_EXPOSED)


# -- Applying an approved pending action (called only from ui.py) -----------


def _apply_tool_update(store: ConfigStore, item: PendingAction) -> Any:
    payload = item.payload
    return store.save_tool(
        payload["spec"], actor=item.actor, rev=item.base_rev, replaces=payload.get("replaces")
    )


def _apply_tool_enable(store: ConfigStore, item: PendingAction) -> Any:
    return store.set_tool_enabled(item.payload["id"], True, actor=item.actor, rev=item.base_rev)


def _apply_tool_delete(store: ConfigStore, item: PendingAction) -> Any:
    return store.delete_tool(item.payload["id"], actor=item.actor, rev=item.base_rev)


def _apply_grant_set(store: ConfigStore, item: PendingAction) -> Any:
    payload = item.payload
    return store.save_identity(
        identity_id=payload["identity_id"],
        role=payload["role"],
        tools=payload["tools"],
        scopes=payload["scopes"],
        actor=item.actor,
        rev=item.base_rev,
        replaces=payload["identity_id"],
    )


#: proposed_action -> (applier, "tools"|"identities" -- which file's live
#: revision `PendingStore.approve` re-checks the proposal's `base_rev`
#: against before applying).
_APPLIERS: dict[str, tuple[Callable[[ConfigStore, PendingAction], Any], str]] = {
    "tool_update": (_apply_tool_update, "tools"),
    "tool_enable": (_apply_tool_enable, "tools"),
    "tool_delete": (_apply_tool_delete, "tools"),
    "grant_set": (_apply_grant_set, "identities"),
}


def apply_pending(
    store: ConfigStore, pending: PendingStore, action_id: str, *, decided_by: str
) -> Any:
    """Approves and applies one pending action -- the only function in this
    codebase that turns a proposal into a live change. Called exclusively
    from `ui.py`'s `/ui/pending/approve` route (human session, `role:
    admin`, CSRF token -- the same `writer` wrapper every other admin write
    goes through). Not part of `AdminService`, not reachable from
    `/admin/mcp` (FR-2.8/2.9).
    """
    item = pending.get(action_id)
    if item is None:
        raise WriteRefused(f"No pending action {action_id!r}.")
    entry = _APPLIERS.get(item.action)
    if entry is None:
        raise WriteRefused(f"Unknown pending action type {item.action!r}.")
    applier, kind = entry
    current_rev = store.tools_revision if kind == "tools" else store.identities_revision
    return pending.approve(
        action_id,
        decided_by=decided_by,
        current_rev=lambda _item: current_rev(),
        apply=lambda _item: applier(store, _item),
    )


__all__ = [
    "AdminActionError",
    "AdminService",
    "EXPOSED_ACTIONS",
    "apply_pending",
]
