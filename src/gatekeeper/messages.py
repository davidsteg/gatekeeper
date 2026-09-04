"""The agent mailbox (`messages.yaml`) behind the `agent` executor.

**Why a mailbox and not a push.** An MCP server cannot hand a running
client an unsolicited payload. The one notification the protocol offers
that a client like Hermes actually acts on is
`notifications/tools/list_changed`, and it carries *nothing* -- it says
"your tool list is stale", not what happened (see
`notifications.py`'s own note on why that emptiness is a feature for
FR-1.4). So "agent A pushes text into agent B's live session" is not
implementable over MCP without changing the client. What is implementable,
and is what this module does, is a **mailbox**: A's message is persisted,
addressed to a gatekeeper identity, and B receives it the next time B
calls `agent.read_messages`. Delivery is therefore "on B's next call",
not "immediately" -- but it is reliable, survives a restart on either
side, and needs no client change.

**The store is plaintext.** `messages.yaml` holds subject and body as
written, on the same volume as the other Tier 2 files. It is *not* the
credential store: nothing here is encrypted at rest, and an operator
reading the file reads every message. Known credential values are scrubbed
on the way in (`audit.Redactor`, FR-10.6) so a secret gatekeeper itself
holds cannot be laundered into the mailbox -- but that covers exactly the
secrets gatekeeper knows, and nothing an agent typed from elsewhere.
Messages are for coordination ("stack media-jellyfin is restarted, go
ahead"), not for handing over secrets.

Written with the same atomic-write primitives as `pending.yaml` and
`tools.yaml` (`_atomic.py`): no half-written file, no silent overwrite of
a concurrent delivery. `atomic_write` creates its temp file 0600 and
`os.replace`s it into position, so the mailbox never exists
world-readable, not even for the instant between write and chmod.
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
from .catalog import now_iso
from .errors import GatekeeperError
from .tier1 import DEFAULT_MAILBOX_LIMIT


class MailboxFull(GatekeeperError):
    """The recipient holds as many unread messages as it may.

    Deliberately an error rather than a silent drop of the oldest unread
    one: an unread message is the only copy of something another agent
    meant to say. What gets pruned is read messages (see `deliver`), never
    something nobody has seen.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class Message:
    id: str
    #: The gatekeeper identity this is addressed to. `read_messages` filters
    #: on exactly this field -- it is what makes FR-1.4's per-identity
    #: isolation hold for the mailbox, too.
    to: str
    #: The identity that sent it. Never a parameter: `service.py` passes the
    #: *authenticated* identity, so an agent cannot claim to be another one.
    sender: str
    subject: str
    body: str
    created_at: str
    read_at: str | None = None

    def to_spec(self) -> dict[str, Any]:
        # "from" is the natural YAML key and not a Python identifier --
        # hence `sender` on the dataclass and `from` on disk.
        return {
            "id": self.id,
            "to": self.to,
            "from": self.sender,
            "subject": self.subject,
            "body": self.body,
            "created_at": self.created_at,
            "read_at": self.read_at,
        }

    def to_payload(self) -> dict[str, Any]:
        """What the agent sees. Same shape minus the read bookkeeping."""
        return {
            "id": self.id,
            "from": self.sender,
            "to": self.to,
            "subject": self.subject,
            "body": self.body,
            "created_at": self.created_at,
        }


def _from_spec(spec: dict[str, Any]) -> Message:
    return Message(
        id=str(spec.get("id") or ""),
        to=str(spec.get("to") or ""),
        sender=str(spec.get("from") or ""),
        subject=str(spec.get("subject") or ""),
        body=str(spec.get("body") or ""),
        created_at=str(spec.get("created_at") or ""),
        read_at=spec.get("read_at"),
    )


@dataclasses.dataclass(slots=True)
class MessageStore:
    """Owns one `messages.yaml`.

    Reloads from disk on every operation instead of caching: the file is
    small, the write path is the same lock, and a store that re-reads is
    the one that survives a hand-edit and a restart identically. Same
    discipline as `pending.PendingStore`.
    """

    path: str
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    # -- Disk ---------------------------------------------------------------

    def _load(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle.read()) or {}
        entries = raw.get("messages")
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise GatekeeperError(
                f"{self.path}: section 'messages' must be a list"
            )
        return [e for e in entries if isinstance(e, dict)]

    def _write(self, entries: list[dict[str, Any]]) -> None:
        _atomic_write(self.path, _dump({"messages": entries}))

    # -- Reads ---------------------------------------------------------------

    def inbox(self, recipient: str, *, unread_only: bool = True) -> list[Message]:
        """Every message addressed to `recipient`, oldest first.

        The filter is the isolation: a caller never sees an entry whose
        `to` is not its own identity, no matter how many other mailboxes
        share the file.

        Ordering is `(created_at, position in the file)`. The second half
        is not decoration: `created_at` has second granularity, deliveries
        are appended, and two messages sent in the same second would
        otherwise be ordered by their random ids -- i.e. a mailbox that
        silently stops being FIFO exactly when traffic picks up.
        """
        items = [
            (entry_index, message)
            for entry_index, message in enumerate(
                _from_spec(e) for e in self._load()
            )
            if message.to == recipient
        ]
        if unread_only:
            items = [pair for pair in items if pair[1].read_at is None]
        items.sort(key=lambda pair: (pair[1].created_at, pair[0]))
        return [message for _, message in items]

    def unread_count(self, recipient: str) -> int:
        return len(self.inbox(recipient))

    # -- Writes --------------------------------------------------------------

    def deliver(
        self,
        *,
        to: str,
        sender: str,
        subject: str,
        body: str,
        max_messages: int = DEFAULT_MAILBOX_LIMIT,
    ) -> Message:
        """Appends one message to `to`'s mailbox.

        Refuses once `to` holds `max_messages` **unread** messages -- an
        unread message is the only copy of what somebody meant to say, so
        the cap is enforced by refusing the new one, not by discarding an
        old one. Already-read messages are pruned oldest-first to keep the
        recipient's total at the cap; those the recipient has already seen.
        """
        with self._lock:
            entries = self._load()
            mine = [
                (index, _from_spec(entry))
                for index, entry in enumerate(entries)
                if str(entry.get("to") or "") == to
            ]
            unread = [pair for pair in mine if pair[1].read_at is None]
            if len(unread) >= max_messages:
                raise MailboxFull(
                    f"Mailbox of {to!r} holds {len(unread)} unread messages, the "
                    f"maximum is {max_messages}. It has to read them before it "
                    "can receive more."
                )

            message = Message(
                id=f"msg_{secrets.token_urlsafe(9)}",
                to=to,
                sender=sender,
                subject=subject,
                body=body,
                created_at=now_iso(),
            )
            entries.append(message.to_spec())

            # Prune read messages oldest-first until the recipient is back
            # at the cap. `mine` was collected before the append, so the
            # new message is never a pruning candidate.
            overflow = len(mine) + 1 - max_messages
            if overflow > 0:
                read = sorted(
                    (pair for pair in mine if pair[1].read_at is not None),
                    key=lambda pair: (pair[1].created_at, pair[0]),
                )
                drop = {index for index, _ in read[:overflow]}
                entries = [e for i, e in enumerate(entries) if i not in drop]

            self._write(entries)
            return message

    def collect(
        self,
        recipient: str,
        *,
        limit: int,
        peek: bool = False,
        fits: Callable[[list[Message]], bool] | None = None,
    ) -> tuple[list[Message], int]:
        """Returns up to `limit` unread messages for `recipient` and, unless
        `peek`, marks exactly those read.

        `fits` is the output budget, injected rather than assumed: the
        store has no opinion on how the executor renders a message, so the
        caller passes a predicate over the candidate list and the batch is
        shrunk from the end until it says yes. Marking read is what the
        *returned* list drives -- a message trimmed for size stays unread
        and comes back on the next call, instead of being marked delivered
        and then dropped from the response.

        The count returned alongside is how many unread ones are still
        waiting after this call -- so an agent that hit the limit or the
        budget knows to come back rather than assuming its mailbox is
        empty.
        """
        with self._lock:
            entries = self._load()
            pending = sorted(
                (
                    (index, _from_spec(entry))
                    for index, entry in enumerate(entries)
                    if str(entry.get("to") or "") == recipient
                    and entry.get("read_at") is None
                ),
                key=lambda pair: (pair[1].created_at, pair[0]),
            )
            taken = pending[:limit]
            if fits is not None:
                # Never shrink below one message: a single message that
                # blows the budget on its own is the executor's to
                # truncate and report, not the store's to withhold
                # forever -- withholding it would wedge the mailbox.
                while len(taken) > 1 and not fits([m for _, m in taken]):
                    taken = taken[:-1]
            remaining = len(pending) - len(taken)
            if taken and not peek:
                stamp = now_iso()
                for index, _ in taken:
                    entries[index]["read_at"] = stamp
                self._write(entries)
            return [message for _, message in taken], remaining


__all__ = [
    "MailboxFull",
    "Message",
    "MessageStore",
]
