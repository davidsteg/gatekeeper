"""The pending-actions queue for the `admin.*` MCP surface.

Low-risk admin actions apply immediately (see `admin_service.py`); anything
that expands what an agent can actually do or touch is written here instead
and waits for a human to approve or reject it through `/ui/requests` (Change
tab). This is
a third Tier 2 file, `pending.yaml`, written with the exact same
atomic-write / revision-fingerprint primitives `store.py` uses for
`tools.yaml`/`identities.yaml` (`_atomic.py`) -- so the same "no silent
overwriting, no half-written file" guarantees apply here too.

`approve` is deliberately not the thing that decides *what* a proposal does
-- it re-checks the proposal's captured `base_rev` against the live
revision of the file the action targets and, if it moved, marks the item
`stale` instead of applying (no silent re-basing: a human/Hermes must
re-propose from the current state). If it is not stale, the caller-supplied
`apply` callback performs the mutation -- which for every real admin action
means calling straight into the *same* `ConfigStore` mutator a human `/ui`
write would call (wired up in `admin_service.apply_pending`), so the
resulting audit entry and validation are identical either way.
"""

from __future__ import annotations

import dataclasses
import os
import secrets
import threading
from collections.abc import Callable
from typing import Any

import yaml

from ._atomic import atomic_write as _atomic_write
from ._atomic import dump as _dump
from ._atomic import revision as _revision
from ._atomic import writable as _writable
from .audit import AuditLog
from .catalog import now_iso
from .errors import ConfigError

#: What a pending item may be in.
STATUSES = frozenset({"pending", "approved", "rejected", "stale"})

#: The two reasons an item is marked `stale`, as one vocabulary shared by
#: every path that can mark one -- `approve`'s gate and
#: `close_vanished_targets`' sweep -- so a human reading `/ui/requests`
#: sees the same sentence whichever of the two closed the item.
STALE_VANISHED_REASON = "What this targeted no longer exists. Nothing to apply."
STALE_CHANGED_REASON = (
    "Configuration changed since this was proposed. "
    "Re-propose from the current state."
)


class PendingWriteRefused(ConfigError):
    """A pending-queue write was refused -- with a human-readable reason."""


@dataclasses.dataclass(frozen=True, slots=True)
class PendingAction:
    id: str
    action: str
    actor: str
    payload: dict[str, Any]
    #: Revision of the file this action targets, captured at propose time.
    base_rev: str
    status: str = "pending"
    created_at: str = ""
    decided_by: str | None = None
    decided_at: str | None = None
    reason: str | None = None

    def to_spec(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "actor": self.actor,
            "payload": self.payload,
            "base_rev": self.base_rev,
            "status": self.status,
            "created_at": self.created_at,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "reason": self.reason,
        }


def _from_spec(spec: dict[str, Any]) -> PendingAction:
    return PendingAction(
        id=str(spec.get("id")),
        action=str(spec.get("action")),
        actor=str(spec.get("actor")),
        payload=dict(spec.get("payload") or {}),
        base_rev=str(spec.get("base_rev") or ""),
        status=str(spec.get("status") or "pending"),
        created_at=str(spec.get("created_at") or ""),
        decided_by=spec.get("decided_by"),
        decided_at=spec.get("decided_at"),
        reason=spec.get("reason"),
    )


@dataclasses.dataclass(slots=True)
class PendingStore:
    """Owns `pending.yaml`."""

    path: str
    audit: AuditLog
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    def revision(self) -> str:
        return _revision(self.path)

    def _load(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle.read()) or {}
        entries = raw.get("pending")
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise ConfigError("pending.yaml: section 'pending' is missing or not a list")
        return [e for e in entries if isinstance(e, dict)]

    def _write(self, entries: list[dict[str, Any]]) -> None:
        _atomic_write(self.path, _dump({"pending": entries}))

    # -- Reads -------------------------------------------------------------

    def list(self, *, status: str | None = None) -> list[PendingAction]:
        items = [_from_spec(e) for e in self._load()]
        items.sort(key=lambda i: i.created_at)
        if status:
            items = [i for i in items if i.status == status]
        return items

    def get(self, action_id: str) -> PendingAction | None:
        for entry in self._load():
            if entry.get("id") == action_id:
                return _from_spec(entry)
        return None

    # -- Writes --------------------------------------------------------------

    def propose(
        self, *, action: str, actor: str, payload: dict[str, Any], base_rev: str
    ) -> PendingAction:
        with self._lock:
            entries = self._load()
            item = PendingAction(
                id=secrets.token_urlsafe(12),
                action=action,
                actor=actor,
                payload=payload,
                base_rev=base_rev,
                status="pending",
                created_at=now_iso(),
            )
            entries.append(item.to_spec())
            self._write(entries)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "pending_propose",
                    "target": item.id,
                    "proposed_action": action,
                    "payload": payload,
                }
            )
            return item

    def reject(self, action_id: str, *, decided_by: str, reason: str = "") -> PendingAction:
        with self._lock:
            entries = self._load()
            match = next((e for e in entries if e.get("id") == action_id), None)
            if match is None:
                raise PendingWriteRefused(f"No pending action {action_id!r}.")
            if match.get("status") != "pending":
                raise PendingWriteRefused(
                    f"Pending action {action_id!r} is already {match.get('status')!r}."
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
                    "action": "pending_reject",
                    "target": action_id,
                    "proposed_action": match.get("action"),
                    "original_actor": match.get("actor"),
                    "reason": reason,
                }
            )
            return _from_spec(match)

    def close_vanished_targets(
        self,
        live_rev: Callable[[PendingAction], str | None],
        *,
        decided_by: str = "system",
    ) -> list[PendingAction]:
        """Marks `stale` every still-`pending` item whose target record has
        vanished, and returns the ones it closed.

        The self-healing half of the guard in `approve`: that one can only
        close an item a human actually clicks Approve on, so an item nobody
        ever clicks -- there is nothing to gain from approving a delete of a
        tool that is already gone -- sits in the queue as `pending` forever
        (14 such items observed in production on 0.46.4). Sweeping on the
        read path closes them on the next `/ui/requests` visit instead,
        with the same `STALE_VANISHED_REASON` a clicked approval would have
        written.

        `live_rev` returns the live per-record revision of what the item
        targets, or `None` for an item this sweep must not judge: a kind
        with no target record at all (`cred_propose`, whose `base_rev` is a
        whole-file revision and whose target is deliberately a credential
        that does *not* exist yet), or a payload whose target id cannot be
        read. Only `""` -- the record existed at propose time and is gone
        now -- closes an item.

        Idempotent by construction: a closed item is no longer `pending`,
        so a second sweep skips it and writes nothing at all. An item whose
        target still exists is never touched, whatever else changed about
        it -- a target that merely *moved* is `approve`'s business, where a
        human is present to be told about it.
        """
        # A read-only `pending.yaml` cannot self-heal; refusing to try is
        # the difference between a queue that still renders and a GET of
        # `/ui/requests` that 500s on an `OSError` from the atomic write.
        if not _writable(self.path):
            return []
        with self._lock:
            entries = self._load()
            closed: list[PendingAction] = []
            for entry in entries:
                if entry.get("status") != "pending":
                    continue
                item = _from_spec(entry)
                # No `base_rev` means the item was proposed against a record
                # that did not exist yet; "gone" is not a thing it can be.
                if not item.base_rev:
                    continue
                rev = live_rev(item)
                if rev is None or rev != "":
                    continue
                entry["status"] = "stale"
                entry["decided_by"] = decided_by
                entry["decided_at"] = now_iso()
                entry["reason"] = STALE_VANISHED_REASON
                closed.append(_from_spec(entry))
            if not closed:
                return []
            self._write(entries)
            for item in closed:
                self.audit.write(
                    {
                        "kind": "admin_change",
                        "actor": decided_by,
                        "action": "pending_stale",
                        "target": item.id,
                        "proposed_action": item.action,
                        "original_actor": item.actor,
                        "reason": STALE_VANISHED_REASON,
                    }
                )
            return closed

    def approve(
        self,
        action_id: str,
        *,
        decided_by: str,
        current_rev: Callable[[PendingAction], str],
        apply: Callable[[PendingAction], Any],
    ) -> Any:
        """Approves one item.

        `current_rev` reads the live revision of the record the action
        targets; if it no longer matches the proposal's `base_rev`, the
        item is marked `stale` and `apply` is never called (no silent
        re-basing -- FR "Stale proposals" design decision). A target that
        has vanished entirely (`current_rev` returns "") counts as changed
        for exactly the same reason -- see below. Otherwise `apply`
        performs the actual mutation and its result (or any
        `WriteRefused`/`ConfigError` it raises) is returned/propagated
        unchanged; on success the item is marked `approved`.
        """
        with self._lock:
            entries = self._load()
            match = next((e for e in entries if e.get("id") == action_id), None)
            if match is None:
                raise PendingWriteRefused(f"No pending action {action_id!r}.")
            if match.get("status") != "pending":
                raise PendingWriteRefused(
                    f"Pending action {action_id!r} is already {match.get('status')!r}."
                )
            item = _from_spec(match)

            live_rev = current_rev(item)
            # An empty `live_rev` means the targeted record is gone (see
            # `store._fingerprint`: `None` fingerprints as ""), and that is
            # a stale proposal too -- not a reason to proceed. This gate
            # used to tolerate it (`... and live_rev and ...`), a leftover
            # from when it hashed the whole *file*, where "" only meant
            # "not created yet". Once it became per-record, that tolerance
            # let an approval fall through to an applier that could do
            # nothing but raise (`delete_tool` -> "No tool with ID ..."),
            # so a `tool_delete` whose tool had since been removed could be
            # neither approved nor closed and stayed `pending` forever.
            if item.base_rev and item.base_rev != live_rev:
                vanished = not live_rev
                match["status"] = "stale"
                match["decided_by"] = decided_by
                match["decided_at"] = now_iso()
                match["reason"] = (
                    STALE_VANISHED_REASON if vanished else STALE_CHANGED_REASON
                )
                self._write(entries)
                self.audit.write(
                    {
                        "kind": "admin_change",
                        "actor": decided_by,
                        "action": "pending_stale",
                        "target": action_id,
                        "proposed_action": item.action,
                        "original_actor": item.actor,
                    }
                )
                raise PendingWriteRefused(
                    f"Pending action {action_id!r} is stale: "
                    + (
                        "what it targeted no longer exists."
                        if vanished
                        else "the configuration changed since it was proposed."
                    )
                    + " It has been marked 'stale' -- re-propose from the "
                    "current state."
                )

            result = apply(item)

            match["status"] = "approved"
            match["decided_by"] = decided_by
            match["decided_at"] = now_iso()
            self._write(entries)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": decided_by,
                    "action": "pending_approve",
                    "target": action_id,
                    "proposed_action": item.action,
                    "original_actor": item.actor,
                }
            )
            return result


__all__ = [
    "PendingAction",
    "PendingStore",
    "PendingWriteRefused",
    "STALE_CHANGED_REASON",
    "STALE_VANISHED_REASON",
    "STATUSES",
]
