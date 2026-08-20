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

`deploy` is the only function that ever writes `toolkits.yaml`:

1. Reads the live file, merges the proposed toolkit in under its name --
   which must not collide with an existing one (adding a *new* toolkit is
   all this pass supports; editing an existing one is deliberately out of
   scope, see the plan).
2. Writes the merged content to a temp file and validates it with the exact
   `load_tier1()` startup uses. Nothing real is touched if this fails.
3. Only then: atomically writes the real file (`_atomic.py`, the same
   primitives `store.py`/`pending.py` use).
4. Calls `Service.reload_config(...)` synchronously, in-process -- the same
   function the existing SIGHUP handler already calls, so the new toolkit is
   live with no restart. If it errors (defensive only: step 2 already
   validated the exact bytes just written), the proposal is left `pending`
   and the failure is surfaced -- not silently swallowed.
5. Audits before/after toolkit names, marks the proposal `deployed`.
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


class ToolkitProposalWriteRefused(ConfigError):
    """A toolkit-proposal write was refused -- with a human-readable reason."""


@dataclasses.dataclass(frozen=True, slots=True)
class ToolkitProposal:
    id: str
    #: The toolkit's name -- the key it would get under `toolkits:` in
    #: toolkits.yaml.
    name: str
    #: The toolkit's body (executor, binaries, path_roots, ...) -- exactly
    #: what would sit under `toolkits.<name>:`.
    spec: dict[str, Any]
    actor: str
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

    def propose(self, *, name: str, spec: dict[str, Any], actor: str) -> ToolkitProposal:
        if not name or not isinstance(name, str):
            raise ToolkitProposalWriteRefused(
                "A toolkit proposal needs a non-empty 'name'."
            )
        with self._lock:
            entries = self._load()
            item = ToolkitProposal(
                id=secrets.token_urlsafe(12),
                name=name,
                spec=spec,
                actor=actor,
                status="pending",
                created_at=now_iso(),
            )
            entries.append(item.to_spec())
            self._write(entries)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "toolkit_propose",
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
            if item.name in toolkit_section:
                raise ToolkitProposalWriteRefused(
                    f"A toolkit named {item.name!r} already exists in "
                    "toolkits.yaml -- deploying this proposal would silently "
                    "overwrite it. Reject this proposal and have it "
                    "re-proposed under a different name (adding a new "
                    "toolkit is all this supports; editing an existing one "
                    "is deliberately out of scope)."
                )

            merged = dict(raw)
            merged_toolkits = dict(toolkit_section)
            merged_toolkits[item.name] = item.spec
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
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": decided_by,
                    "action": "toolkit_deploy",
                    "target": item.name,
                    "proposal_id": proposal_id,
                    "original_actor": item.actor,
                    "before_toolkits": before_names,
                    "after_toolkits": sorted(merged_toolkits),
                }
            )
            return _from_spec(match)


__all__ = [
    "STATUSES",
    "ToolkitProposal",
    "ToolkitProposalStore",
    "ToolkitProposalWriteRefused",
]
