"""The toolkit-proposal queue for the `admin.*` MCP surface (plan
"Follow-up 2": let Hermes draft toolkits, with a one-click human deploy).

A toolkit proposal is a categorically different severity of change from
anything in `pending.py`: Tier 1 (`toolkits.yaml`) is what makes the admin
token *not* equivalent to root (REQUIREMENTS.md §6) -- it defines what is
possible at all, not merely who may do what. This is deliberately its own
file (`toolkit_proposals.yaml`) and its own store, never `PendingStore`, so
a toolkit proposal can never be routed through the same approval surface as
an ordinary tool/grant change, and so `EXPOSED_ACTIONS`/`admin_server.py`'s
drift-check has one fewer place to accidentally expose `deploy`/`reject`
from `/admin/mcp`.

Three proposal ``kind``s share this one queue and one review surface
(`/ui/requests`, Toolkit tab), because all three change Tier 1 and none may
ever be reachable through `pending.yaml`'s Tier-2-shaped review path:

- ``"create"`` (`admin.toolkit_propose`) -- drafts a brand-new toolkit.
  ``spec`` is the toolkit's full body; the name must not already exist.
- ``"update"`` (`admin.toolkit_update`) -- narrowly-scoped edits to an
  *existing* toolkit's ``executor``/``binaries``/``denied_args`` only
  (``_UPDATE_WRITABLE_FIELDS``); ``spec`` holds just the changed fields,
  merged into the toolkit's existing body at deploy time. Every other Tier 1
  field (``path_roots``, ``protected_resources``, limits) stays reachable
  only by a redeploy -- this exists so an executor swap (e.g. `local` ->
  `file`) doesn't require one, not to open a general editing surface.
- ``"delete"`` (`admin.toolkit_delete`) -- removes an *existing* toolkit.
  ``spec`` is always empty; the name must already exist and, at deploy
  time, must not still be referenced by any non-deleted tool (deleting a
  toolkit out from under a live tool is exactly the "way to bring the
  service down" `catalog.parse_tool_spec` guards against).

`deploy` is the only function that ever writes `toolkits.yaml`:

1. Reads the live file. For ``"create"``, merges the proposed toolkit in
   under its name, which must not collide with an existing one. For
   ``"update"``, merges the proposed fields into the *existing* toolkit's
   body, which must already exist. For ``"delete"``, removes the named
   toolkit's key entirely, refusing if any non-deleted tool still
   references it.
2. Writes the merged content to a temp file and validates it with the exact
   `load_tier1()` startup uses. Nothing real is touched if this fails.
3. Only then: atomically writes the real file (`_atomic.py`, the same
   primitives `store.py`/`pending.py` use).
4. Calls `Service.reload_config(...)` synchronously, in-process -- the same
   function the existing SIGHUP handler already calls, so the change is
   live with no restart. If it errors (defensive only: step 2 already
   validated the exact bytes just written), the proposal is left `pending`
   and the failure is surfaced -- not silently swallowed.
5. Audits before/after state, marks the proposal `deployed`.
"""

from __future__ import annotations

import dataclasses
import os
import secrets
import tempfile
import threading
from typing import Any

import yaml

from ._atomic import atomic_write as _atomic_write
from ._atomic import dump as _dump
from ._atomic import revision as _revision
from ._atomic import writable as _writable
from .audit import AuditLog
from .catalog import now_iso
from .errors import ConfigError
from .service import Service
from .tier1 import load_tier1

#: What a toolkit proposal may be in. No 'stale' state: unlike `pending.py`,
#: `deploy` re-validates the *entire* merged configuration fresh at deploy
#: time (not just a revision fingerprint) -- a moved toolkits.yaml simply
#: surfaces as a collision or a Tier-1 validation error instead.
STATUSES = frozenset({"pending", "deployed", "rejected"})

#: The three shapes a proposal can take -- see the module docstring.
KINDS = frozenset({"create", "update", "delete"})

#: Fields `"update"`-kind proposals may change. Everything else
#: (`path_roots`, `protected_resources`, limits) stays deploy-time only
#: (FR-4.11) -- checked both at `propose()` (immediate feedback to the
#: agent) and again at `deploy()` (the authoritative gate; `propose()`'s
#: check is not itself a security boundary since nothing has been written
#: yet either way).
UPDATE_WRITABLE_FIELDS = frozenset({"executor", "binaries", "denied_args"})

#: Audit `action` names, keyed by `kind` -- one for `propose()`, one for
#: `deploy()`.
_PROPOSE_ACTION_NAMES = {
    "create": "toolkit_propose",
    "update": "toolkit_update_propose",
    "delete": "toolkit_delete_propose",
}
_DEPLOY_ACTION_NAMES = {
    "create": "toolkit_deploy",
    "update": "toolkit_update_deploy",
    "delete": "toolkit_delete_deploy",
}


class ToolkitProposalWriteRefused(ConfigError):
    """A toolkit-proposal write was refused -- with a human-readable reason."""


def _tools_referencing_toolkit(tools_path: str, toolkit_name: str) -> set[str]:
    """Tool ids in `tools_path` whose `toolkit` field is `toolkit_name` and
    which are not soft-deleted (`store.py`'s `ConfigStore.delete_tool`) --
    the set `deploy()` must refuse a `"delete"` proposal over, since
    `catalog.parse_tool_spec` treats a dangling `toolkit` reference as a
    Tier 1 violation, not a syntax error.
    """
    if not os.path.exists(tools_path):
        return set()
    with open(tools_path, encoding="utf-8") as handle:
        raw = yaml.safe_load(handle.read()) or {}
    entries = raw.get("tools")
    if not isinstance(entries, list):
        return set()
    return {
        str(entry.get("id"))
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("toolkit") == toolkit_name
        and not entry.get("deleted", False)
    }


@dataclasses.dataclass(frozen=True, slots=True)
class ToolkitProposal:
    id: str
    #: The toolkit's name -- the key it would get (or already has) under
    #: `toolkits:` in toolkits.yaml.
    name: str
    #: For `kind="create"`: the toolkit's full body (executor, binaries,
    #: path_roots, ...) -- exactly what would sit under `toolkits.<name>:`.
    #: For `kind="update"`: just the changed fields, a subset of
    #: `UPDATE_WRITABLE_FIELDS`, merged into the existing toolkit's body
    #: at deploy time.
    spec: dict[str, Any]
    actor: str
    #: `"create"` (default, backward-compatible with proposals written
    #: before this field existed) or `"update"` -- see the module docstring.
    kind: str = "create"
    status: str = "pending"
    created_at: str = ""
    decided_by: str | None = None
    decided_at: str | None = None
    reason: str | None = None

    def to_spec(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "spec": self.spec,
            "actor": self.actor,
            "kind": self.kind,
            "status": self.status,
            "created_at": self.created_at,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "reason": self.reason,
        }


def _from_spec(spec: dict[str, Any]) -> ToolkitProposal:
    return ToolkitProposal(
        id=str(spec.get("id")),
        name=str(spec.get("name")),
        spec=dict(spec.get("spec") or {}),
        actor=str(spec.get("actor")),
        kind=str(spec.get("kind") or "create"),
        status=str(spec.get("status") or "pending"),
        created_at=str(spec.get("created_at") or ""),
        decided_by=spec.get("decided_by"),
        decided_at=spec.get("decided_at"),
        reason=spec.get("reason"),
    )


@dataclasses.dataclass(slots=True)
class ToolkitProposalStore:
    """Owns `toolkit_proposals.yaml` and is the only writer of the real
    `toolkits.yaml` outside of a deploy-time redeploy (see module docstring).
    """

    path: str
    audit: AuditLog
    service: Service
    toolkits_path: str
    tools_path: str
    identities_path: str
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    def revision(self) -> str:
        return _revision(self.path)

    def _load(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle.read()) or {}
        entries = raw.get("proposals")
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise ConfigError(
                "toolkit_proposals.yaml: section 'proposals' is missing or not a list"
            )
        return [e for e in entries if isinstance(e, dict)]

    def _write(self, entries: list[dict[str, Any]]) -> None:
        _atomic_write(self.path, _dump({"proposals": entries}))

    # -- Reads ---------------------------------------------------------------

    def list(self, *, status: str | None = None) -> list[ToolkitProposal]:
        items = [_from_spec(e) for e in self._load()]
        items.sort(key=lambda i: i.created_at)
        if status:
            items = [i for i in items if i.status == status]
        return items

    def get(self, proposal_id: str) -> ToolkitProposal | None:
        for entry in self._load():
            if entry.get("id") == proposal_id:
                return _from_spec(entry)
        return None

    # -- Writes ----------------------------------------------------------------

    def propose(
        self, *, name: str, spec: dict[str, Any], actor: str, kind: str = "create"
    ) -> ToolkitProposal:
        if not name or not isinstance(name, str):
            raise ToolkitProposalWriteRefused(
                "A toolkit proposal needs a non-empty 'name'."
            )
        if kind not in KINDS:
            raise ToolkitProposalWriteRefused(f"Unknown proposal kind {kind!r}.")
        if kind == "update":
            if not spec:
                raise ToolkitProposalWriteRefused(
                    "An update proposal needs at least one changed field."
                )
            illegal = set(spec) - UPDATE_WRITABLE_FIELDS
            if illegal:
                raise ToolkitProposalWriteRefused(
                    f"Cannot propose changing {sorted(illegal)} -- only "
                    f"{sorted(UPDATE_WRITABLE_FIELDS)} are writable via an "
                    "update proposal. path_roots, protected_resources, and "
                    "limits require a redeploy."
                )
        if kind == "delete" and spec:
            raise ToolkitProposalWriteRefused(
                "A delete proposal takes no 'spec' -- there is nothing to "
                "change, only a toolkit to remove."
            )
        with self._lock:
            entries = self._load()
            item = ToolkitProposal(
                id=secrets.token_urlsafe(12),
                name=name,
                spec=spec,
                actor=actor,
                kind=kind,
                status="pending",
                created_at=now_iso(),
            )
            entries.append(item.to_spec())
            self._write(entries)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": _PROPOSE_ACTION_NAMES[kind],
                    "target": name,
                    "spec": spec,
                }
            )
            return item

    def reject(
        self, proposal_id: str, *, decided_by: str, reason: str = ""
    ) -> ToolkitProposal:
        with self._lock:
            entries = self._load()
            match = next((e for e in entries if e.get("id") == proposal_id), None)
            if match is None:
                raise ToolkitProposalWriteRefused(f"No toolkit proposal {proposal_id!r}.")
            if match.get("status") != "pending":
                raise ToolkitProposalWriteRefused(
                    f"Toolkit proposal {proposal_id!r} is already {match.get('status')!r}."
                )
            match["status"] = "rejected"
            match["decided_by"] = decided_by
            match["decided_at"] = now_iso()
            match["reason"] = reason
            self._write(entries)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": decided_by,
                    "action": "toolkit_reject",
                    "target": match.get("name"),
                    "proposal_id": proposal_id,
                    "original_actor": match.get("actor"),
                    "reason": reason,
                }
            )
            return _from_spec(match)

    def deploy(self, proposal_id: str, *, decided_by: str) -> ToolkitProposal:
        """Approves and deploys one proposal -- see the module docstring for
        the five steps. Raises `ToolkitProposalWriteRefused` (nothing real
        touched) on a name collision or a Tier-1 validation failure, and
        again (this time with `toolkits.yaml` already written, but the
        proposal left `pending`) if `reload_config` itself errors.
        """
        with self._lock:
            entries = self._load()
            match = next((e for e in entries if e.get("id") == proposal_id), None)
            if match is None:
                raise ToolkitProposalWriteRefused(f"No toolkit proposal {proposal_id!r}.")
            if match.get("status") != "pending":
                raise ToolkitProposalWriteRefused(
                    f"Toolkit proposal {proposal_id!r} is already {match.get('status')!r}."
                )
            item = _from_spec(match)

            if not os.path.exists(self.toolkits_path):
                raise ToolkitProposalWriteRefused(f"{self.toolkits_path} not found.")
            if not _writable(self.toolkits_path):
                raise ToolkitProposalWriteRefused(
                    f"{os.path.basename(self.toolkits_path)} is not writable. The "
                    "file or its directory is mounted read-only."
                )
            with open(self.toolkits_path, encoding="utf-8") as handle:
                raw = yaml.safe_load(handle.read()) or {}
            toolkit_section = raw.get("toolkits")
            if toolkit_section is None:
                toolkit_section = {}
            if not isinstance(toolkit_section, dict):
                raise ToolkitProposalWriteRefused(
                    "toolkits.yaml: section 'toolkits' is not a mapping."
                )

            merged_toolkits = dict(toolkit_section)
            before_fields: dict[str, Any] | None = None
            if item.kind == "update":
                existing = toolkit_section.get(item.name)
                if not isinstance(existing, dict):
                    raise ToolkitProposalWriteRefused(
                        f"No toolkit named {item.name!r} exists in toolkits.yaml "
                        "-- it may have been renamed or removed by a redeploy "
                        "since this proposal was made. Reject this proposal."
                    )
                illegal = set(item.spec) - UPDATE_WRITABLE_FIELDS
                if illegal:
                    # Defense in depth: propose() already rejected this, but
                    # deploy() re-checks its own authoritative input rather
                    # than trusting a value it merely wrote earlier.
                    raise ToolkitProposalWriteRefused(
                        f"Cannot change {sorted(illegal)} at runtime -- only "
                        f"{sorted(UPDATE_WRITABLE_FIELDS)} are writable via an "
                        "update proposal."
                    )
                before_fields = {k: existing.get(k) for k in item.spec}
                merged_toolkits[item.name] = {**existing, **item.spec}
            elif item.kind == "delete":
                existing = toolkit_section.get(item.name)
                if not isinstance(existing, dict):
                    raise ToolkitProposalWriteRefused(
                        f"No toolkit named {item.name!r} exists in toolkits.yaml "
                        "-- it may already have been removed. Reject this "
                        "proposal."
                    )
                referencing = _tools_referencing_toolkit(self.tools_path, item.name)
                if referencing:
                    raise ToolkitProposalWriteRefused(
                        f"Toolkit {item.name!r} is still referenced by "
                        f"{len(referencing)} tool(s): {sorted(referencing)}. "
                        "Delete or reassign those tools first."
                    )
                before_fields = {item.name: existing}
                del merged_toolkits[item.name]
            else:
                if item.name in toolkit_section:
                    raise ToolkitProposalWriteRefused(
                        f"A toolkit named {item.name!r} already exists in "
                        "toolkits.yaml -- deploying this proposal would silently "
                        "overwrite it. Reject this proposal and have it "
                        "re-proposed under a different name (adding a new "
                        "toolkit is all a 'create' proposal supports; use an "
                        "update proposal to edit an existing one)."
                    )
                merged_toolkits[item.name] = item.spec

            merged = dict(raw)
            merged["toolkits"] = merged_toolkits
            merged_text = _dump(merged)

            # Validate the merged configuration exactly as startup would,
            # before anything real is touched -- Tier 1 has no lenient path
            # (REQUIREMENTS.md §6).
            directory = os.path.dirname(os.path.abspath(self.toolkits_path)) or "."
            fd, tmp_path = tempfile.mkstemp(
                prefix=".gk-toolkit-validate-", suffix=".yaml", dir=directory
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(merged_text)
                try:
                    load_tier1(tmp_path)
                except ConfigError as exc:
                    raise ToolkitProposalWriteRefused(
                        f"Proposed toolkit {item.name!r} is invalid: {exc}"
                    ) from exc
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

            before_names = sorted(toolkit_section)
            _atomic_write(self.toolkits_path, merged_text)

            error = self.service.reload_config(
                toolkits_path=self.toolkits_path,
                tools_path=self.tools_path,
                identities_path=self.identities_path,
            )
            if error:
                # Defensive only: the block above already validated the
                # exact bytes just written. Left as 'pending' (not marked
                # 'deployed') so a human sees this failed rather than
                # believing the toolkit is live when it might not be.
                raise ToolkitProposalWriteRefused(
                    f"toolkits.yaml was written, but reloading it into this "
                    f"running process failed: {error}. A SIGHUP or restart "
                    "should pick it up; investigate before re-deploying."
                )

            match["status"] = "deployed"
            match["decided_by"] = decided_by
            match["decided_at"] = now_iso()
            self._write(entries)
            record: dict[str, Any] = {
                "kind": "admin_change",
                "actor": decided_by,
                "action": _DEPLOY_ACTION_NAMES[item.kind],
                "target": item.name,
                "proposal_id": proposal_id,
                "original_actor": item.actor,
                "before_toolkits": before_names,
                "after_toolkits": sorted(merged_toolkits),
            }
            if before_fields is not None:
                record["before_fields"] = before_fields
                record["after_fields"] = item.spec
            self.audit.write(record)
            return _from_spec(match)


__all__ = [
    "KINDS",
    "STATUSES",
    "UPDATE_WRITABLE_FIELDS",
    "ToolkitProposal",
    "ToolkitProposalStore",
    "ToolkitProposalWriteRefused",
]
