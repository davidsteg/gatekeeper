"""The `admin.*` MCP surface's application layer (REQUIREMENTS.md FR-2.8-3.7).

`AdminService` wraps `ConfigStore` + `PendingStore` and is the single
dispatch point `admin_server.py` calls into for every `admin.*` tool. Every
mutating action goes through the *same* `ConfigStore`/`PendingStore`
mutators a human console write (`/api/v1`) uses -- there is no second, more lenient path
(the same principle `catalog.parse_tool_spec`'s docstring states for tool
definitions applies here to the whole admin surface).

One dispatch table (`_EXPOSED`, enforced by `call`) decides, per action,
whether a change applies immediately or is written to the pending queue:

* read-only queries (`tool_list`, `tool_get`, `tool_validate`, `grant_list`,
  `audit_query`, `pending_list`, `proposal_list`) always execute directly.
* `proposal_withdraw` always auto-applies: it only takes a still-pending
  toolkit proposal off the queue, and only one the caller filed itself.
* `tool_create` always auto-applies, but forces the new definition
  `enabled: false` -- creation is always inert (FR-3.x): an admin or a
  later `tool_enable` call is a separate, auditable decision.
* `tool_disable` always auto-applies -- disabling only ever narrows what an
  agent can do. `cred_delete` auto-applies for the same reason: it removes
  a credential slot, never creates or reveals one, and is refused outright
  while any toolkit or destination still references it.
* `tool_enable`/`tool_update` are category-conditional: a `read`-category
  tool auto-applies, `write`/`write_external` always goes to the pending
  queue.
* `tool_delete` and `grant_set` (the only identity mutation exposed here)
  always go to the pending queue -- they either remove a capability or
  change who has one.
* `cred_propose` always goes to the pending queue too, but is never applied
  through `apply_pending`/`_APPLIERS` below -- see its own docstring. It
  proposes a credential's name/kind/header only, never a value.
* `cred_update` always goes to the pending queue and applies through
  `apply_pending` like `grant_set` does: it changes a slot's name, kind,
  header and probe URL -- whether a call authenticates at all -- but never
  its value, so a plain approval is enough and nobody re-types the secret.
* `credential_bind` goes to the *toolkit*-proposal queue, not the pending
  one: binding a toolkit to a credential name writes `toolkits.yaml`, which
  is Tier 1 (FR-10.4), so it shares `toolkit_propose`/`toolkit_update`'s
  store and review surface rather than the Tier-2-shaped one. Two names,
  never a value -- see its own docstring.

`approve`/`reject` are deliberately **not** methods on this class and are
not in `_EXPOSED`. The only place a pending item is ever turned into a live
change is `apply_pending` below, called only from the console API's
request-decision routes (`api/writes.py`: human session + `role: admin` +
CSRF, exactly like every other console write). There is no code path from `/admin/mcp` that
reaches it -- FR-2.8's
self-approval prevention is structural, not a permission check.
"""

from __future__ import annotations

import dataclasses
import os
import re
from collections.abc import Callable
from typing import Any

from . import __version__
from .api.service import credential_summaries, read_audit, toolkit_summaries
from .catalog import normalize_tool_entry, parse_tool_spec
from .credentials import (
    HEADER_KINDS,
    HEADER_NAME_RE,
    VALUE_SHAPES,
    CredentialStore,
    check_header_format,
)
from .credentials import KINDS as CREDENTIAL_KINDS
from .credentials import WriteRefused as CredentialWriteRefused
from .errors import ConfigError
from .identity import ROLES, UI_ROLES
from .pending import PendingAction, PendingStore
from .release_notes import query as _release_query
from .release_notes import read_full as _release_full
from .store import ConfigStore, WriteRefused
from .toolkit_proposals import BIND_FIELD, KINDS, STATUSES, ToolkitProposalStore

#: Same cause as the console popup's fallback, phrased for a caller with no
#: browser: a build that shipped without RELEASE.md (a bare `pip install`
#: rather than the image, which bakes it in at /usr/share/gatekeeper).
_NO_RELEASE_NOTES = (
    "Release notes are not available in this build -- RELEASE.md was not "
    "found. Set GATEKEEPER_RELEASE_NOTES to its path, or use the container "
    "image, which ships it at /usr/share/gatekeeper/RELEASE.md."
)

#: The credential-name rule for `cred_propose`. A console form check is
#: client-side only, so a raw MCP call would bypass it entirely unless
#: enforced here too.
_CREDENTIAL_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

#: Argument names `credential_bind` refuses outright instead of ignoring.
#:
#: `cred_propose` refuses a bare `value` for this reason and this one only
#: applies the same rule wider: a bind proposal is stored in
#: `toolkit_proposals.yaml`, a plaintext Tier 1 file, so anything
#: value-shaped that slipped through would sit there in the clear until a
#: human read the card. The MCP SDK does not enforce
#: `additionalProperties: False` itself (advisory to a well-behaved client,
#: not a transport gate), so this list is the actual enforcement point.
_BIND_VALUE_ARGS = frozenset(
    {
        "value",
        "secret",
        "token",
        "password",
        "passphrase",
        "api_key",
        "apikey",
        "key",
        "credential_value",
    }
)

#: Tier 1 fields that stay deploy-time only (FR-4.11) and are refused here
#: rather than quietly dropped. `destination` heads the list on purpose: a
#: destination carries its own `credential:` override (FR-8.3g) that beats
#: the toolkit's, so accepting one would turn a binding a reviewer reads as
#: "this toolkit, that credential" into a narrower, less visible one.
#: `credential_bind` is toolkit-level only.
_BIND_DEPLOY_TIME_ARGS = frozenset(
    {
        "destination",
        "destinations",
        "path_roots",
        "protected_resources",
        "max_timeout_seconds",
        "max_output_bytes",
    }
)

#: Fields that are proposable, just not from here -- pointed at the tool
#: that does take them rather than refused with a flat "unknown argument".
_BIND_UPDATE_ARGS = frozenset({"executor", "binaries", "denied_args", "run_as"})

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

    def release_notes(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """The deployment's own RELEASE.md, for the agent that manages it.

        An agent asked to propose a change here has to follow the same
        release rule a human does ("what lands on main is published":
        bump `pyproject.toml`, add a `## <version>` section), and until now
        that rule lived only in a file it could not read -- the console
        popup renders it for a browser, and `serverInfo` reports a version
        with no notes attached to it. Read-only, and the one admin action
        that touches no store at all.

        `full: true` returns the file verbatim, preamble included -- the
        procedure and versioning sections are not part of any version's
        notes and are exactly what "how do I release this" needs. Without
        it the answer is version-by-version, newest first, optionally
        narrowed by `version` (exact), `search` (case-insensitive, over
        heading and body -- "credential" across a hundred releases is the
        question this exists for) and `limit`.

        `limit` defaults to 10 rather than everything: RELEASE.md is well
        past 150 KB, and an unbounded default would spend an agent's whole
        context on the answer to a narrow question. `total` always reports
        the pre-limit match count, so a truncated answer says so.
        """
        if bool(args.get("full", False)):
            text = _release_full()
            if not text:
                raise AdminActionError(_NO_RELEASE_NOTES)
            return {"current_version": __version__, "markdown": text}
        limit = args.get("limit")
        limit = 10 if limit is None else max(1, int(limit))
        version = str(args.get("version") or "") or None
        releases, total = _release_query(
            version=version, search=str(args.get("search") or "") or None, limit=limit
        )
        if not releases and not _release_query()[1]:
            raise AdminActionError(_NO_RELEASE_NOTES)
        if version and not releases:
            raise AdminActionError(f"No release notes for version {version!r}.")
        return {
            "current_version": __version__,
            "releases": releases,
            "count": len(releases),
            "total": total,
            "truncated": total > len(releases),
        }

    def pending_list(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Reads the queue -- and, first, closes what is no longer decidable.

        The sweep is on the read path on purpose: an item whose target
        record has vanished can only be closed by `approve`'s staleness
        gate, i.e. by a human clicking Approve on a proposal that can no
        longer do anything -- which nobody has a reason to do, so it stays
        `pending` forever instead (see `sweep_vanished_pendings`). Listing
        is the one moment someone is looking, so it is where these
        self-heal. Nothing whose target still exists is touched, and a
        second list is a no-op.
        """
        sweep_vanished_pendings(self.store, self.pending, credentials=self.credentials)
        status = args.get("status") or None
        items = self.pending.list(status=status)
        return {"pending": [i.to_spec() for i in items]}

    def proposal_list(self, _actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Lists the toolkit-proposal queue -- the Tier 1 counterpart of
        `pending_list`, which never shows these (they live in their own
        store, see `toolkit_proposals.py`). Without it an agent could file
        a proposal and then never see what became of it. Optionally
        filtered by `kind` and `status`. Read-only.
        """
        kind = args.get("kind") or None
        status = args.get("status") or None
        if kind is not None and kind not in KINDS:
            raise AdminActionError(f"Unknown proposal kind {kind!r} (one of {sorted(KINDS)}).")
        if status is not None and status not in STATUSES:
            raise AdminActionError(
                f"Unknown proposal status {status!r} (one of {sorted(STATUSES)})."
            )
        items = self.toolkit_proposals.list(status=status)
        if kind is not None:
            items = [i for i in items if i.kind == kind]
        return {"proposals": [i.to_spec() for i in items]}

    def toolkit_list(self, _actor: str, _args: dict[str, Any]) -> dict[str, Any]:
        """Lists live Tier 1 toolkits + destinations, so Hermes can check
        reality (what toolkit/destination names already exist, what a
        toolkit's executor/limits are) instead of guessing before drafting
        a proposal. Read-only -- Tier 1 itself is never written from here.
        """
        tier1 = self.store.service.tier1
        return {"toolkits": toolkit_summaries(tier1), "destinations": sorted(tier1.destinations)}

    def cred_list(self, _actor: str, _args: dict[str, Any]) -> dict[str, Any]:
        if self.credentials is None:
            return {"credentials": []}
        return {
            "credentials": credential_summaries(self.credentials, self.store.service.tier1)
        }

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

    def cred_delete(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Deletes a credential *slot* by name -- the missing counterpart

        to `cred_propose`, and the reason a wrong `kind` is no longer a
        dead end. A slot's kind is fixed at creation (a `paperless` token
        created as `bearer` when the service wants `api_key_header`
        authenticates against nothing), and nothing could change or remove
        it from here: the only way out was a human in `/app/credentials`.
        Deleting the slot and proposing it again with the right kind is
        that fix, reachable over `/admin/mcp` alone.

        Auto-applies, for `tool_disable`'s reason: removing a credential
        only ever narrows what this deployment can do. The safety is in
        the refusal below, not in a queue -- and the value is not
        recoverable from here either way, since re-creating the slot still
        routes through `cred_propose`, where a human types the secret
        (FR-10.2/10.8). Nothing value-shaped is accepted or returned here:
        a name goes in, a name is audited (`CredentialStore.delete` writes
        `credential_delete` with the name only).

        Refused while the slot is still bound. `credential_references()`
        is the same walk `cred_list`'s "used_by" and the startup
        dangling-reference check use -- including the destination-level
        `credential:` override (FR-8.3g) that a hand-rolled second walk
        forgets. Deleting a bound slot would not fail loudly; it would
        turn a working toolkit into one that refuses every call with "is
        not configured yet", so the binding has to go first (an approved
        `credential_bind` pointing elsewhere, or a host-side edit).
        """
        if self.credentials is None:
            raise AdminActionError(
                "No credential store is configured on this deployment -- "
                "there is no credential slot to delete."
            )
        name = _require_str(args, "name")
        known = sorted(meta.name for meta in self.credentials.names())
        if name not in known:
            raise AdminActionError(
                f"No credential slot named {name!r} exists "
                f"(known credentials: {known}). Check admin.cred_list."
            )
        used_by = self.store.service.tier1.credential_references().get(name, ())
        if used_by:
            raise AdminActionError(
                f"Credential {name!r} is still referenced by "
                f"{sorted(used_by)} -- deleting it would leave those refusing "
                "every call with 'credential is not configured yet'. Point "
                "them at another slot first (admin.credential_bind, "
                "human-approved), then delete this one."
            )
        self.credentials.delete(name, actor=actor, rev=self.credentials.revision())
        return {"applied": True, "name": name}

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
        item = self.toolkit_proposals.propose(
            name=name, spec=spec, actor=actor,
            confirm_broad_cidrs=args.get("confirm_broad_cidrs") is True,
        )
        return {"applied": False, "pending": True, "proposal_id": item.id}

    def toolkit_update(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Proposes changing a toolkit's executor type, binaries,

        denied_args, run_as, and an http/opencode toolkit's allowed_hosts/
        allowed_cidrs. Narrowly scoped: only those fields can be proposed
        (`toolkit_proposals.UPDATE_WRITABLE_FIELDS`); security-critical fields (``path_roots``,
        ``protected_resources``, ``limits``) remain deploy-time only and
        are rejected. Like `toolkit_propose`, this changes Tier 1 -- what is
        possible at all, not just who can do what -- so it is always written
        to the toolkit-proposal queue and never applies on its own; a human
        reviews it at `/app/requests` (Toolkit tab) and, if they approve,
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
            name=name, spec=updates, actor=actor, kind="update",
            confirm_broad_cidrs=args.get("confirm_broad_cidrs") is True,
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

    def proposal_withdraw(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Takes back a still-pending toolkit proposal the caller filed
        itself. A withdrawal approves nothing and writes nothing to
        toolkits.yaml, and the store refuses anyone's proposal but the
        caller's own, so FR-2.8's separation holds: deploying and
        rejecting stay with a human at /app/requests.
        """
        proposal_id = _require_str(args, "proposal_id")
        item = self.toolkit_proposals.withdraw(proposal_id, actor=actor)
        return {"withdrawn": True, "proposal_id": item.id, "name": item.name}

    def credential_bind(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Proposes pointing an existing toolkit at an existing credential
        *slot* -- two names, nothing else (FR-10.2/10.8).

        This is the missing half of `cred_propose`. That one gets a
        credential *created*; a created credential that nothing references
        is inert, and closing that gap previously meant a human hand-editing
        toolkits.yaml and redeploying, because the binding is Tier 1
        (FR-10.4: "only changeable via redeploy", precisely so an admin
        agent cannot redirect the `docker` toolkit at a credential of its
        choosing).

        What this relaxes is the redeploy, not the human -- the same trade
        `toolkit_update` already made for an executor swap. The proposal is
        written to `ToolkitProposalStore` and never applies on its own;
        `/app/requests` (Toolkit tab) is the only place it can take effect,
        behind a session, `role: admin`, CSRF and an explicit confirmation.
        There is no code path from `/admin/mcp` to
        `ToolkitProposalStore.deploy` (FR-2.8's self-approval prevention is
        structural here as everywhere else in this class).

        Both names are checked against the *running* configuration -- the
        same two sources `toolkit_list` and `cred_list` read -- so a typo
        is refused now, by name, instead of sitting in the queue until a
        human discovers at review time that it could never have deployed.
        Reporting whether a credential slot exists is no new disclosure:
        `cred_list` already reports every slot's name to this same
        admin-role caller, and neither returns a value.
        """
        # Refused before anything else is even looked at, and before the
        # arguments could reach `toolkit_proposals.yaml`: a caller who sent
        # a secret here must learn immediately that it went nowhere, not
        # assume gatekeeper stored it. Same reasoning as `cred_propose`'s
        # `value` check -- see `_BIND_VALUE_ARGS`.
        smuggled = sorted(set(args) & _BIND_VALUE_ARGS)
        if smuggled:
            raise AdminActionError(
                f"{smuggled} {'is' if len(smuggled) == 1 else 'are'} not a "
                "valid argument here -- this binds a toolkit to a credential "
                "*name*. No operation on /admin/mcp ever carries secret "
                "material (FR-10.2/10.8); a value is typed by a human in "
                "/app/credentials and never reaches this queue."
            )
        deploy_time = sorted(set(args) & _BIND_DEPLOY_TIME_ARGS)
        if deploy_time:
            raise AdminActionError(
                f"{deploy_time} cannot be proposed -- this binds a "
                "credential at the toolkit level only. Destination-level "
                "credential overrides, path_roots, protected_resources and "
                "limits stay deploy-time only (FR-4.11) and need a redeploy."
            )
        update_args = sorted(set(args) & _BIND_UPDATE_ARGS)
        if update_args:
            raise AdminActionError(
                f"{update_args} cannot be proposed here -- this tool sets a "
                "toolkit's credential and nothing else. Use "
                "admin.toolkit_update for those fields."
            )

        toolkit = _require_str(args, "toolkit")
        credential = _require_str(args, "credential")

        # The running Tier 1 -- the same source `toolkit_list` reports from,
        # so what an agent was told exists is what is checked here.
        tier1 = self.store.service.tier1
        if toolkit not in tier1.toolkits:
            known = sorted(tier1.toolkits)
            raise AdminActionError(
                f"No toolkit named {toolkit!r} in the running configuration "
                f"(known toolkits: {known}). Check admin.toolkit_list."
            )
        if self.credentials is None:
            raise AdminActionError(
                "No credential store is configured on this deployment -- "
                "there is no credential slot to bind to."
            )
        known_credentials = sorted(meta.name for meta in self.credentials.names())
        if credential not in known_credentials:
            raise AdminActionError(
                f"No credential slot named {credential!r} exists "
                f"(known credentials: {known_credentials}). Propose it first "
                "with admin.cred_propose, or check admin.cred_list."
            )

        item = self.toolkit_proposals.propose(
            name=toolkit,
            spec={BIND_FIELD: credential},
            actor=actor,
            kind="bind",
        )
        return {"applied": False, "pending": True, "proposal_id": item.id}

    def cred_propose(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Proposes a *named, typed, headerless-or-not credential slot* --

        never a value (FR-10.2/10.8). `admin_server.py`'s inputSchema for
        this tool has no `value` property, but the MCP SDK does not itself
        enforce `additionalProperties: False` against an extra argument
        (that's advisory to a well-behaved client, not a transport gate) --
        so a stray `value` is rejected explicitly below, loudly rather than
        silently ignored. The value is always typed by a human, at approval
        time, in `/app/requests` -- never written to `pending.yaml` (see
        `pending.py`'s module docstring: everything proposed through it
        sits in a plaintext Tier 2 file).

        Deliberately not wired through `PendingStore.approve()`'s generic
        `apply` callback the way `grant_set`/`tool_delete` are: that
        callback fires synchronously at approval with no way to collect
        additional input, but filling in the value *is* the approval here.
        The console API's dedicated `POST /api/v1/requests/pending/{id}/credential`
        route (`api/writes.py`) calls `pending.approve()` directly instead of going through
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
                "always typed by a human in /app/requests at approval time, never "
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
        probe_url = args.get("probe_url")
        if probe_url is not None and not isinstance(probe_url, str):
            raise AdminActionError("'probe_url' must be a string if given.")
        if probe_url and not probe_url.startswith(("http://", "https://")):
            raise AdminActionError("'probe_url' must be an http(s) URL if given.")
        if kind in ("api_key_header", "url_query") and not header:
            raise AdminActionError(f"kind {kind!r} requires a 'header' (header/param name).")
        header_format = args.get("header_format")
        if header_format is not None and not isinstance(header_format, str):
            raise AdminActionError("'header_format' must be a string if given.")
        try:
            header_format = check_header_format(kind, header_format)
        except CredentialWriteRefused as exc:
            raise AdminActionError(str(exc)) from None
        existing_names = {meta.name for meta in self.credentials.names()}
        if name in existing_names:
            raise AdminActionError(f"A credential named {name!r} already exists.")
        item = self.pending.propose(
            action="cred_propose",
            actor=actor,
            payload={
                "name": name, "kind": kind, "header": header, "probe_url": probe_url,
                **({"header_format": header_format} if header_format else {}),
            },
            base_rev=self.credentials.revision(),
        )
        return {"applied": False, "pending": True, "pending_id": item.id}

    def cred_update(self, actor: str, args: dict[str, Any]) -> dict[str, Any]:
        """Proposes changing an existing slot's kind, header, probe URL
        and/or name -- keeping the stored value (FR-10.2/10.8).

        The repair `cred_delete` + `cred_propose` could only do by throwing
        a working secret away: a slot whose header is wrong (a token sent
        as `X-Emby-Token` to a server that wants `Authorization`) had to be
        deleted, which is refused while bound, so the way out was a
        throwaway anchor slot, two binds and a human pasting the same
        secret again. The value was never the problem; this changes only
        what is around it.

        Always pending, never auto-applied: kind and header decide whether
        a call authenticates at all, and a header is where a request could
        be pointed somewhere a human did not expect. Unlike `cred_propose`
        it goes through `apply_pending`, because approving it needs no
        input beyond the click -- the value stays where it is.

        Fields left out keep their current value. A kind change stays
        within one value shape (`credentials.VALUE_SHAPES`): a token can
        move between `api_key_header`, `bearer`, `url_query` and the like,
        but never become a `docker_tls` bundle, since nobody can read the
        value back to check it. A rename is refused while the slot is
        bound, because the binding is Tier 1 and would dangle; changing
        kind or header is not, since the binding is by name.
        """
        if self.credentials is None:
            raise AdminActionError(
                "No credential store is configured on this deployment -- "
                "there is no credential slot to update."
            )
        smuggled = sorted(set(args) & _BIND_VALUE_ARGS)
        if smuggled:
            raise AdminActionError(
                f"{smuggled} {'is' if len(smuggled) == 1 else 'are'} not a "
                "valid argument here -- this changes a credential's "
                "name/kind/header and keeps its stored value. No operation on "
                "/admin/mcp ever carries secret material (FR-10.2/10.8); a new "
                "value is a rotation, typed by a human in /app/credentials."
            )
        name = _require_str(args, "name")
        current = next((m for m in self.credentials.names() if m.name == name), None)
        if current is None:
            known = sorted(meta.name for meta in self.credentials.names())
            raise AdminActionError(
                f"No credential slot named {name!r} exists "
                f"(known credentials: {known}). Check admin.cred_list."
            )
        for field in ("new_name", "kind", "header", "header_format", "probe_url"):
            if field in args and args[field] is not None and not isinstance(args[field], str):
                raise AdminActionError(f"'{field}' must be a string if given.")

        new_name = args.get("new_name") or None
        if new_name == name:
            new_name = None
        if new_name is not None:
            if not _CREDENTIAL_NAME_RE.match(new_name):
                raise AdminActionError(
                    f"{new_name!r} is not a valid credential name -- must match "
                    f"{_CREDENTIAL_NAME_RE.pattern!r}."
                )
            if new_name in {meta.name for meta in self.credentials.names()}:
                raise AdminActionError(f"A credential named {new_name!r} already exists.")
            used_by = self.store.service.tier1.credential_references().get(name, ())
            if used_by:
                raise AdminActionError(
                    f"Credential {name!r} is still referenced by {sorted(used_by)} "
                    "-- renaming it would leave those pointing at a slot that no "
                    "longer exists, and the binding is Tier 1 (FR-10.4). Kind and "
                    "header can be changed without a rename: leave out 'new_name'."
                )

        kind = args.get("kind") or current.kind
        if kind not in CREDENTIAL_KINDS:
            raise AdminActionError(
                f"Unknown credential kind {kind!r} (allowed: {sorted(CREDENTIAL_KINDS)})."
            )
        if VALUE_SHAPES.get(kind) != VALUE_SHAPES.get(current.kind):
            raise AdminActionError(
                f"Cannot change {name!r} from {current.kind!r} to {kind!r}: the "
                f"stored value is a {VALUE_SHAPES.get(current.kind, 'value')}, and "
                f"{kind!r} needs a {VALUE_SHAPES[kind]}. The value cannot be read "
                "back to convert it -- propose a new slot with admin.cred_propose."
            )
        if "header" in args:
            header = args.get("header") or None
        else:
            # A kind that takes no header drops the old one, rather than
            # carrying a stale `X-Api-Key` along on a `bearer` slot.
            header = current.header if kind in HEADER_KINDS else None
        if kind in HEADER_KINDS and not header:
            raise AdminActionError(f"kind {kind!r} requires a 'header' (header/param name).")
        if header is not None and kind not in HEADER_KINDS:
            raise AdminActionError(
                f"kind {kind!r} takes no 'header' -- it builds its own "
                "(bearer, basic) or is not sent as a header at all."
            )
        if header is not None and not HEADER_NAME_RE.match(header):
            raise AdminActionError(f"{header!r} is not a valid header/param name.")
        if "header_format" in args:
            header_format = args.get("header_format") or None
        else:
            # Kept only while the slot stays an `api_key_header`: the
            # format wraps that header's value and means nothing elsewhere.
            header_format = current.header_format if kind == "api_key_header" else None
        try:
            header_format = check_header_format(kind, header_format)
        except CredentialWriteRefused as exc:
            raise AdminActionError(str(exc)) from None
        if "probe_url" in args:
            probe_url = (args.get("probe_url") or "").strip() or None
        else:
            probe_url = current.probe_url
        if probe_url and not probe_url.startswith(("http://", "https://")):
            raise AdminActionError("'probe_url' must be an http(s) URL if given.")

        prev = {
            "kind": current.kind, "header": current.header,
            "header_format": current.header_format, "probe_url": current.probe_url,
        }
        proposed = {
            "kind": kind, "header": header, "header_format": header_format,
            "probe_url": probe_url,
        }
        if new_name is None and prev == proposed:
            raise AdminActionError(
                f"Nothing to change: {name!r} already has kind {kind!r}"
                + (f", header {header!r}" if header else "")
                + "."
            )
        item = self.pending.propose(
            action="cred_update",
            actor=actor,
            payload={
                "name": name,
                "new_name": new_name,
                "kind": kind,
                "header": header,
                "header_format": header_format,
                "probe_url": probe_url,
                # Snapshotted for the reviewer's diff, like `grant_set`'s
                # `prev_tools`: an archived item still shows what it changed.
                "prev": prev,
            },
            base_rev=self.credentials.record_revision(name),
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
    "proposal_list",
    "release_notes",
    "toolkit_list",
    "cred_list",
    "cred_delete",
    "toolkit_propose",
    "toolkit_update",
    "toolkit_delete",
    "proposal_withdraw",
    "cred_propose",
    "cred_update",
    "credential_bind",
)

EXPOSED_ACTIONS: frozenset[str] = frozenset(_EXPOSED)


# -- Applying an approved pending action (called only from api/writes.py) ---


def _apply_tool_update(
    store: ConfigStore, item: PendingAction, _credentials: CredentialStore | None
) -> Any:
    payload = item.payload
    return store.save_tool(
        payload["spec"], actor=item.actor, rev=store.tools_revision(),
        replaces=payload.get("replaces"),
    )


def _apply_tool_enable(
    store: ConfigStore, item: PendingAction, _credentials: CredentialStore | None
) -> Any:
    return store.set_tool_enabled(
        item.payload["id"], True, actor=item.actor, rev=store.tools_revision()
    )


def _apply_tool_delete(
    store: ConfigStore, item: PendingAction, _credentials: CredentialStore | None
) -> Any:
    return store.delete_tool(item.payload["id"], actor=item.actor, rev=store.tools_revision())


def _apply_grant_set(
    store: ConfigStore, item: PendingAction, _credentials: CredentialStore | None
) -> Any:
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


def _apply_role_set(
    store: ConfigStore, item: PendingAction, _credentials: CredentialStore | None
) -> Any:
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


def _apply_cred_update(
    store: ConfigStore, item: PendingAction, credentials: CredentialStore | None
) -> Any:
    if credentials is None:
        raise WriteRefused("No credential store is configured on this deployment.")
    payload = item.payload
    name = payload["name"]
    new_name = payload.get("new_name") or None
    if new_name is not None:
        # Checked again here, not only at propose time: a toolkit may have
        # been bound to this slot (an approved `credential_bind`) while the
        # rename waited in the queue, and the bind lives in Tier 1, which
        # this slot's own revision does not cover.
        used_by = store.service.tier1.credential_references().get(name, ())
        if used_by:
            raise WriteRefused(
                f"Credential {name!r} is now referenced by {sorted(used_by)}; "
                "renaming it would leave that binding dangling. Reject this "
                "and ask for the change without a rename."
            )
    return credentials.update(
        name,
        kind=payload["kind"],
        header=payload.get("header"),
        probe_url=payload.get("probe_url"),
        header_format=payload.get("header_format"),
        new_name=new_name,
        actor=item.actor,
        rev=credentials.revision(),
    )


def _target_id_tool_update(payload: dict[str, Any]) -> str:
    return payload["replaces"]


def _target_id_tool_id_field(payload: dict[str, Any]) -> str:
    return payload["id"]


def _target_id_identity(payload: dict[str, Any]) -> str:
    return payload["identity_id"]


def _target_id_name(payload: dict[str, Any]) -> str:
    return payload["name"]


#: proposed_action -> (applier, "tools"|"identities"|"credentials" -- which store's
#: per-record fingerprint `PendingStore.approve` re-checks the proposal's
#: `base_rev` against, and a function that pulls the specific tool/identity
#: id a proposal targets out of its own payload). Staleness is checked at
#: the granularity of the ONE record a proposal targets, not the whole
#: file -- two simultaneous proposals against different identities (or
#: different tools) in the same YAML file no longer invalidate each other.
#: `store.save_tool`/`save_identity`/etc. still perform their own
#: whole-file `_check()` at the moment of writing (see store.py) as the
#: real atomic-write safety net; that is unrelated to this gate.
_Applier = Callable[[ConfigStore, PendingAction, CredentialStore | None], Any]

_APPLIERS: dict[str, tuple[_Applier, str, Callable[[dict[str, Any]], str]]] = {
    "tool_update": (_apply_tool_update, "tools", _target_id_tool_update),
    "tool_enable": (_apply_tool_enable, "tools", _target_id_tool_id_field),
    "tool_delete": (_apply_tool_delete, "tools", _target_id_tool_id_field),
    "grant_set": (_apply_grant_set, "identities", _target_id_identity),
    "role_set": (_apply_role_set, "identities", _target_id_identity),
    "cred_update": (_apply_cred_update, "credentials", _target_id_name),
}


def _target_rev(
    store: ConfigStore, item: PendingAction, credentials: CredentialStore | None = None
) -> str | None:
    """The live per-record revision of what one pending item targets, or
    `None` if it targets no record this module can resolve.

    The single walk over `_APPLIERS` that both the approval gate
    (`apply_pending`) and the read-path sweep (`sweep_vanished_pendings`)
    go through, so a kind added to the registry is covered by both at once
    and neither can forget one the other knows about.

    `None` is deliberately distinct from `""`: `""` is a real answer ("the
    record is gone"), `None` means "not a question about a record" -- an
    action with no applier (`cred_propose`, whose `base_rev` is the
    credential file's whole-file revision and whose target is a slot that
    must *not* exist yet), a payload missing the field naming its own
    target, or a `cred_update` on a deployment with no credential store.
    """
    entry = _APPLIERS.get(item.action)
    if entry is None:
        return None
    _applier, kind, target_id_of = entry
    try:
        target_id = target_id_of(item.payload)
    except (KeyError, TypeError):
        return None
    if not target_id:
        return None
    if kind == "tools":
        return store.tool_revision(target_id)
    if kind == "credentials":
        return None if credentials is None else credentials.record_revision(target_id)
    return store.identity_revision(target_id)


def sweep_vanished_pendings(
    store: ConfigStore, pending: PendingStore, *, credentials: Any = None,
    decided_by: str = "system",
) -> list[PendingAction]:
    """Closes every queued proposal whose target record no longer exists.

    Called from the read paths a human or an agent actually looks at the
    queue through (`AdminService.pending_list`, the console's
    `GET /api/v1/requests/pending` via `api/service.pending_view`), so the
    items `approve`'s guard can only close on a click -- and which nobody
    has a reason to ever click -- do not accumulate as permanent `pending`
    rows. Idempotent; see `PendingStore.close_vanished_targets`.

    With `credentials`, also closes a `cred_update` whose slot is gone, and
    a `cred_propose` (or renaming `cred_update`) whose name has been taken
    since (`PendingStore.close_taken_credentials`): that one could never be
    approved either, since the write refuses an existing name.
    """
    closed = pending.close_vanished_targets(
        lambda item: _target_rev(store, item, credentials), decided_by=decided_by
    )
    if credentials is not None:
        taken = {meta.name for meta in credentials.names()}
        closed += pending.close_taken_credentials(taken, decided_by=decided_by)
    return closed


def apply_pending(
    store: ConfigStore, pending: PendingStore, action_id: str, *, decided_by: str,
    credentials: CredentialStore | None = None,
) -> Any:
    """Approves and applies one pending action -- the only function in this
    codebase that turns a proposal into a live change. Called only
    from the console API's request-decision routes in `api/writes.py`
    (approve and approve-all; human session, `role: admin`, CSRF token --
    the same `require_admin` dependency every other console write goes
    through). Not part of `AdminService`, not
    reachable from `/admin/mcp` (FR-2.8/2.9).
    """
    item = pending.get(action_id)
    if item is None:
        raise WriteRefused(f"No pending action {action_id!r}.")
    entry = _APPLIERS.get(item.action)
    if entry is None:
        raise WriteRefused(f"Unknown pending action type {item.action!r}.")
    applier, kind, _target_id_of = entry
    if kind == "credentials" and credentials is None:
        # Refused before the staleness gate, which would otherwise read the
        # unanswerable revision as "the slot is gone" and close the item.
        raise WriteRefused("No credential store is configured on this deployment.")

    def _current_rev(pending_item: PendingAction) -> str:
        # `_target_rev` answering `None` here means the payload does not
        # name a target this registry entry can read (it always should).
        # Resolving that to "" routes it into the same vanished-target
        # staleness gate rather than raising `KeyError` out of the approve
        # route -- an unhandled 500 leaves the item `pending`, which is the
        # exact zombie shape this whole guard exists to prevent.
        return _target_rev(store, pending_item, credentials) or ""

    return pending.approve(
        action_id,
        decided_by=decided_by,
        current_rev=_current_rev,
        apply=lambda _item: applier(store, _item, credentials),
    )


__all__ = [
    "AdminActionError",
    "AdminService",
    "EXPOSED_ACTIONS",
    "apply_pending",
    "sweep_vanished_pendings",
]
