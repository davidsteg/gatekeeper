"""The pending-actions queue for the `admin.*` MCP surface.

Low-risk admin actions apply immediately (see `admin_service.py`); anything
that expands what an agent can actually do or touch is written here instead
and waits for a human to approve or reject it through `/ui/pending`. This is
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
from typing import Any, Callable

import yaml

from ._atomic import atomic_write as _atomic_write
from ._atomic import dump as _dump
from ._atomic import revision as _revision
from .audit import AuditLog
from .catalog import now_iso
from .errors import ConfigError

#: What a pending item may be in.
STATUSES = frozenset({"pending", "approved", "rejected", "stale"})


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

    def approve(
        self,
        action_id: str,
        *,
        decided_by: str,
        current_rev: Callable[[PendingAction], str],
        apply: Callable[[PendingAction], Any],
    ) -> Any:
        """Approves one item.

        `current_rev` reads the live revision of the file the action
        targets; if it no longer matches the proposal's `base_rev`, the
        item is marked `stale` and `apply` is never called (no silent
        re-basing -- FR "Stale proposals" design decision). Otherwise
        `apply` performs the actual mutation and its result (or any
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
            if item.base_rev and live_rev and item.base_rev != live_rev:
                match["status"] = "stale"
                match["decided_by"] = decided_by
                match["decided_at"] = now_iso()
                match["reason"] = (
                    "Configuration changed since this was proposed. "
                    "Re-propose from the current state."
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
                    f"Pending action {action_id!r} is stale: the configuration "
                    "changed since it was proposed. It has been marked 'stale' "
                    "-- re-propose from the current state."
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


__all__ = ["PendingAction", "PendingStore", "PendingWriteRefused", "STATUSES"]
