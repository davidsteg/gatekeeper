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
* `cred_propose` always goes to the pending queue too, but is never applied
  through `apply_pending`/`_APPLIERS` below -- see its own docstring. It
  proposes a credential's name/kind/header only, never a value.

`approve`/`reject` are deliberately **not** methods on this class and are
not in `_EXPOSED`. The only place a pending item is ever turned into a live
change is `apply_pending` below, called exclusively from `ui.py`'s
`/ui/requests` (Change tab) routes (human session + CSRF, exactly like
every other admin write). There is no code path from `/admin/mcp` that
reaches it -- FR-2.8's
self-approval prevention is structural, not a permission check.
"""

from __future__ import annotations

import dataclasses
import os
import re
from collections.abc import Callable
from typing import Any

from .catalog import normalize_tool_entry, parse_tool_spec
from .credentials import KINDS as CREDENTIAL_KINDS
from .credentials import CredentialStore
from .errors import ConfigError
from .identity import ROLES, UI_ROLES
from .pending import PendingAction, PendingStore
from .store import ConfigStore, WriteRefused
from .toolkit_proposals import ToolkitProposalStore

#: Server-side mirror of `_credential_editor`'s HTML `pattern` attribute
#: (ui.py) -- that one is client-side only, so a raw MCP call bypasses it
#: entirely unless enforced here too.
_CREDENTIAL_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

# Imported lazily inside `audit_query` (not at module level): `ui.py`
# imports `apply_pending` from this module for its `/ui/requests` routes,
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
    #: `None` on a deployment with no credential store configured (no
    #: master key, or `--ui` disabled) -- `cred_propose` reports that
    #: plainly rather than the store simply not existing on `self`.
    credentials: CredentialStore | None = None

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

    def _grantable_ids(self, tool_id: str) -> list[str]:
        """The catalog id(s) `grant_set` actually accepts for `tool_id`.

        Surfaced here so `tool_get`/`tool_list` don't show a tool as
        "enabled" while every grant against its bare id is silently
        rejected as unknown. See `Catalog.grantable_ids` for why the
        expansion is necessary.
        """
        return self.store.service.catalog.grantable_ids(tool_id)

    def tool_list(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        include_deleted = bool(args.get("include_deleted", False))
        out = []
        for raw in self.store.service.catalog.raw:
            entry = normalize_tool_entry(raw)
            if entry["deleted"] and not include_deleted:
                continue
            entry["grantable_ids"] = self._grantable_ids(entry["id"])
            out.append(entry)
        out.sort(key=lambda e: e["id"] or "")
        return {"tools": out}

    def tool_get(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        tool_id = _require_str(args, "id")
        raw = self.store.service.catalog.raw_of(tool_id)
        if raw is None:
            raise AdminActionError(f"No tool with ID {tool_id!r}.")
        entry = normalize_tool_entry(raw)
        entry["grantable_ids"] = self._grantable_ids(tool_id)
        return entry

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
        # Deferred: ui.py imports admin_service.py at module load, so a
        # top-level import here would be circular -- same reason
        # `read_audit` above is imported this way instead of at the top.
        from .ui import _target

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
                # Where this toolkit connects to, and which credential it
                # references -- not previously reported here, which read
                # as "not configured" when it was actually just missing
                # from this report. `credential` is the name only (e.g.
                # "bazarr-api-key"), never its value -- the credential
                # store stays write-only (FR-10.2) regardless.
                "target": _target(tk),
                "credential": tk.credential,
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
            base_rev=self.store.tool_revision(tool_id),
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
            base_rev=self.store.tool_revision(tool_id),
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
            base_rev=self.store.tool_revision(tool_id),
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
            # Snapshotted here (not diffed against live state at render
            # time) so an archived proposal still shows the diff it was
            # approved on, instead of diffing against the post-application
            # state and reading as "nothing changed".
            "prev_tools": sorted(existing.tools),
        }
        item = self.pending.propose(
            action="grant_set",
            actor=actor,
            payload=payload,
            base_rev=self.store.identity_revision(identity_id),
        )
        return {"applied": False, "pending": True, "pending_id": item.id}

    def role_set(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        identity_id = _require_str(args, "identity_id")
        existing = self.store.identities.identities.get(identity_id)
        if existing is None:
            raise AdminActionError(f"No identity {identity_id!r}.")
        role = _require_str(args, "role")
        if role not in ROLES:
            raise AdminActionError(f"Unknown role {role!r}.")
        if role in UI_ROLES and not existing.password_hash:
            # `save_identity` refuses a UI role without a console password,
            # and this call has no password field of its own -- a token
            # never carries one, on purpose (identity.py's module docstring:
            # a stolen token must not double as a stolen password). Turning
            # a passwordless agent into a console user needs a human at the
            # identity editor, not a proposal an agent can complete alone.
            raise AdminActionError(
                f"{identity_id!r} has no console password -- role {role!r} "
                "needs one to sign in, and this proposal cannot set one. "
                "A human must set a password directly in the identity editor."
            )
        payload = {
            "identity_id": identity_id,
            "role": role,
            "tools": sorted(existing.tools),
            "scopes": list(existing.scopes),
        }
        item = self.pending.propose(
            action="role_set",
            actor=actor,
            payload=payload,
            base_rev=self.store.identity_revision(identity_id),
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

    def toolkit_update(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Proposes changing a toolkit's executor type, binaries, and/or

        denied_args. Narrowly scoped: only those three fields can be
        proposed; security-critical fields (``path_roots``,
        ``protected_resources``, ``limits``) remain deploy-time only and
        are rejected. Like `toolkit_propose`, this changes Tier 1 -- what is
        possible at all, not just who can do what -- so it is always written
        to the toolkit-proposal queue and never applies on its own; a human
        reviews it at `/ui/requests` (Toolkit tab) and, if they approve,
        gatekeeper validates, writes toolkits.yaml, and reloads it into the
        running process itself. There is no code path from `/admin/mcp` that
        can make this take effect by itself (FR-2.8's self-approval
        prevention applies here the same as it does to `toolkit_propose`).
        """
        name = _require_str(args, "name")
        updates = dict(_require_dict(args, "updates"))
        if not updates:
            return {"applied": False, "error": "No updates provided."}

        item = self.toolkit_proposals.propose(
            name=name, spec=updates, actor=actor, kind="update"
        )
        return {"applied": False, "pending": True, "proposal_id": item.id}

    def toolkit_delete(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Proposes removing an existing toolkit from Tier 1. Like
        `toolkit_propose`/`toolkit_update`, this changes Tier 1 -- what is
        possible at all, not just who can do what -- so it is always
        written to the toolkit-proposal queue and never applies on its
        own. `ToolkitProposalStore.deploy` refuses it at approval time if
        the toolkit no longer exists or any non-deleted tool still
        references it; there is no such check here since nothing has been
        written yet either way.
        """
        name = _require_str(args, "name")
        item = self.toolkit_proposals.propose(name=name, spec={}, actor=actor, kind="delete")
        return {"applied": False, "pending": True, "proposal_id": item.id}

    def cred_propose(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Proposes a *named, typed, headerless-or-not credential slot* --

        never a value (FR-10.2/10.8). `admin_server.py`'s inputSchema for
        this tool has no `value` property, but the MCP SDK does not itself
        enforce `additionalProperties: False` against an extra argument
        (that's advisory to a well-behaved client, not a transport gate) --
        so a stray `value` is rejected explicitly below, loudly rather than
        silently ignored. The value is always typed by a human, at approval
        time, in `/ui/requests` -- never written to `pending.yaml` (see
        `pending.py`'s module docstring: everything proposed through it
        sits in a plaintext Tier 2 file).

        Deliberately not wired through `PendingStore.approve()`'s generic
        `apply` callback the way `grant_set`/`tool_delete` are: that
        callback fires synchronously at approval with no way to collect
        additional input, but filling in the value *is* the approval here.
        `ui.py`'s dedicated `/ui/pending/credential-fill` route calls
        `pending.approve()` directly instead of going through
        `admin_service.apply_pending`/`_APPLIERS`.
        """
        if self.credentials is None:
            raise AdminActionError(
                "No credential store is configured on this deployment -- "
                "nothing to propose against."
            )
        if "value" in args:
            # The MCP SDK does not enforce `additionalProperties: False`
            # itself (it's advisory to a well-behaved client, not a
            # transport-level gate) -- so this is the actual enforcement
            # point. Rejected loudly rather than silently ignored: a
            # caller sending a value here should learn immediately that it
            # went nowhere, not assume it was stored.
            raise AdminActionError(
                "'value' is not a valid argument here -- this proposes a "
                "credential's name/kind/header only. The secret value is "
                "always typed by a human in /ui at approval time, never "
                "sent over /admin/mcp (FR-10.2/10.8)."
            )
        name = _require_str(args, "name")
        if not _CREDENTIAL_NAME_RE.match(name):
            raise AdminActionError(
                f"{name!r} is not a valid credential name -- must match "
                f"{_CREDENTIAL_NAME_RE.pattern!r}."
            )
        kind = _require_str(args, "kind")
        if kind not in CREDENTIAL_KINDS:
            raise AdminActionError(f"Unknown credential kind {kind!r} (allowed: {sorted(CREDENTIAL_KINDS)}).")
        header = args.get("header")
        if header is not None and not isinstance(header, str):
            raise AdminActionError("'header' must be a string if given.")
        if kind in ("api_key_header", "url_query") and not header:
            raise AdminActionError(f"kind {kind!r} requires a 'header' (header/param name).")
        existing_names = {meta.name for meta in self.credentials.names()}
        if name in existing_names:
            raise AdminActionError(f"A credential named {name!r} already exists.")
        item = self.pending.propose(
            action="cred_propose",
            actor=actor,
            payload={"name": name, "kind": kind, "header": header},
            base_rev=self.credentials.revision(),
        )
        return {"applied": False, "pending": True, "pending_id": item.id}


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
    "role_set",
    "audit_query",
    "pending_list",
    "toolkit_list",
    "toolkit_propose",
    "toolkit_update",
    "toolkit_delete",
    "cred_propose",
)

EXPOSED_ACTIONS: frozenset[str] = frozenset(_EXPOSED)


# -- Applying an approved pending action (called only from ui.py) -----------


def _apply_tool_update(store: ConfigStore, item: PendingAction) -> Any:
    payload = item.payload
    return store.save_tool(
        payload["spec"], actor=item.actor, rev=store.tools_revision(),
        replaces=payload.get("replaces"),
    )


def _apply_tool_enable(store: ConfigStore, item: PendingAction) -> Any:
    return store.set_tool_enabled(
        item.payload["id"], True, actor=item.actor, rev=store.tools_revision()
    )


def _apply_tool_delete(store: ConfigStore, item: PendingAction) -> Any:
    return store.delete_tool(item.payload["id"], actor=item.actor, rev=store.tools_revision())


def _apply_grant_set(store: ConfigStore, item: PendingAction) -> Any:
    payload = item.payload
    return store.save_identity(
        identity_id=payload["identity_id"],
        role=payload["role"],
        tools=payload["tools"],
        scopes=payload["scopes"],
        actor=item.actor,
        rev=store.identities_revision(),
        replaces=payload["identity_id"],
    )


def _apply_role_set(store: ConfigStore, item: PendingAction) -> Any:
    payload = item.payload
    return store.save_identity(
        identity_id=payload["identity_id"],
        role=payload["role"],
        tools=payload["tools"],
        scopes=payload["scopes"],
        actor=item.actor,
        rev=store.identities_revision(),
        replaces=payload["identity_id"],
    )


def _target_id_tool_update(payload: dict[str, Any]) -> str:
    return payload["replaces"]


def _target_id_tool_id_field(payload: dict[str, Any]) -> str:
    return payload["id"]


def _target_id_identity(payload: dict[str, Any]) -> str:
    return payload["identity_id"]


#: proposed_action -> (applier, "tools"|"identities" -- which store's
#: per-record fingerprint `PendingStore.approve` re-checks the proposal's
#: `base_rev` against, and a function that pulls the specific tool/identity
#: id a proposal targets out of its own payload). Staleness is checked at
#: the granularity of the ONE record a proposal targets, not the whole
#: file -- two simultaneous proposals against different identities (or
#: different tools) in the same YAML file no longer invalidate each other.
#: `store.save_tool`/`save_identity`/etc. still perform their own
#: whole-file `_check()` at the moment of writing (see store.py) as the
#: real atomic-write safety net; that is unrelated to this gate.
_APPLIERS: dict[
    str, tuple[Callable[[ConfigStore, PendingAction], Any], str, Callable[[dict[str, Any]], str]]
] = {
    "tool_update": (_apply_tool_update, "tools", _target_id_tool_update),
    "tool_enable": (_apply_tool_enable, "tools", _target_id_tool_id_field),
    "tool_delete": (_apply_tool_delete, "tools", _target_id_tool_id_field),
    "grant_set": (_apply_grant_set, "identities", _target_id_identity),
    "role_set": (_apply_role_set, "identities", _target_id_identity),
}


def apply_pending(
    store: ConfigStore, pending: PendingStore, action_id: str, *, decided_by: str
) -> Any:
    """Approves and applies one pending action -- the only function in this
    codebase that turns a proposal into a live change. Called exclusively
    from `ui.py`'s `/ui/requests` (Change tab) approve route (human
    session, `role: admin`, CSRF token -- the same `writer` wrapper every
    other admin write goes through). Not part of `AdminService`, not
    reachable from `/admin/mcp` (FR-2.8/2.9).
    """
    item = pending.get(action_id)
    if item is None:
        raise WriteRefused(f"No pending action {action_id!r}.")
    entry = _APPLIERS.get(item.action)
    if entry is None:
        raise WriteRefused(f"Unknown pending action type {item.action!r}.")
    applier, kind, target_id_of = entry

    def _current_rev(pending_item: PendingAction) -> str:
        target_id = target_id_of(pending_item.payload)
        if kind == "tools":
            return store.tool_revision(target_id)
        return store.identity_revision(target_id)

    return pending.approve(
        action_id,
        decided_by=decided_by,
        current_rev=_current_rev,
        apply=lambda _item: applier(store, _item),
    )


__all__ = [
    "AdminActionError",
    "AdminService",
    "EXPOSED_ACTIONS",
    "apply_pending",
]
