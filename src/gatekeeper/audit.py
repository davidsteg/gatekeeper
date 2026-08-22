"""Audit log (REQUIREMENTS.md §12).

Append-only, JSON Lines, with rotation. Rotation is not cosmetic: an
append-only log without a limit eventually fills the dataset, and then
not only gatekeeper stops (FR-9.5).
"""

from __future__ import annotations

import dataclasses
import json
import os
import threading
import time
from typing import Any

#: Substrings that mark a field name as secret-bearing -- regardless of
#: where it appears. Matched against a *normalized* key (lowercased, with
#: `-`, `_`, `.` and spaces stripped), so `api_key`, `X-Api-Key`, `apiKey`
#: and `apikey` all collapse onto the same token. Exact-name matching --
#: what this used to do -- caught only one spelling of each and let a
#: parameter named `x-api-key` or `access_token` through in cleartext.
#: The `Redactor` below is no backstop for that: it only knows values
#: gatekeeper stores itself, not a token an agent passed in as an argument.
#: Deliberately generous, because the two failure modes are not symmetric --
#: a wrongly masked field costs readability, a missed one costs a secret.
_NEVER_LOG = frozenset({"token", "authorization", "password", "apikey", "secret"})

#: The exceptions to the above: keys that match a `_NEVER_LOG` token but
#: describe a secret instead of carrying one. Masking these would delete
#: exactly the metadata the log exists for -- FR-10.7's point is that a
#: credential's *name* and *kind* are loggable, only its value is not.
#: Stored normalized, the same way keys are before comparison.
_LOGGABLE = frozenset({"passwordchanged"})


def _is_secret_key(key: str) -> bool:
    """True if `key` names a field whose value must never be logged."""
    normalized = key.lower()
    for char in "-_. ":
        normalized = normalized.replace(char, "")
    if normalized in _LOGGABLE:
        return False
    return any(token in normalized for token in _NEVER_LOG)


@dataclasses.dataclass(slots=True)
class Redactor:
    """Masks known secrets in outputs (FR-10.6).

    The set is fed from `CredentialStore.plaintext_values_for_masking()` at
    startup and refreshed on every create/rotate/delete. It therefore covers
    exactly the secrets gatekeeper holds itself -- which is why `_NEVER_LOG`
    above has to stand on its own for everything else: `docker compose logs`
    regularly contains a target container's environment variables, and an
    agent can pass a foreign token as a plain tool argument. Neither is a
    value this Redactor has ever seen.
    """

    secrets: tuple[str, ...] = ()
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    def __call__(self, text: str) -> str:
        with self._lock:
            secrets = self.secrets
        for secret in secrets:
            if secret and secret in text:
                text = text.replace(secret, "***")
        return text

    def set_secrets(self, secrets: tuple[str, ...]) -> None:
        """Replaces the known-secret set (FR-10.6), e.g. after a credential

        is created or rotated. Swapped under a lock so a concurrent audit
        write never observes a half-updated tuple -- `tuple` assignment
        itself is atomic in CPython, but the lock also documents the
        invariant for readers instead of relying on that implementation
        detail.
        """
        with self._lock:
            self.secrets = secrets


class AuditLog:
    """Writes structured records, rotates by size."""

    def __init__(
        self,
        directory: str,
        *,
        max_bytes: int = 32 * 1024 * 1024,
        keep_files: int = 10,
        redactor: Redactor | None = None,
    ) -> None:
        self._dir = directory
        self._path = os.path.join(directory, "audit.jsonl")
        self._max_bytes = max_bytes
        self._keep = keep_files
        self._redact = redactor or Redactor()
        self._lock = threading.Lock()
        os.makedirs(directory, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        try:
            size = os.path.getsize(self._path)
        except OSError:
            return
        if size < self._max_bytes:
            return
        for index in range(self._keep - 1, 0, -1):
            src = f"{self._path}.{index}"
            dst = f"{self._path}.{index + 1}"
            if os.path.exists(src):
                os.replace(src, dst)
        os.replace(self._path, f"{self._path}.1")

    def write(self, event: dict[str, Any]) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
        line = json.dumps(_scrub(record, self._redact), ensure_ascii=False)
        with self._lock:
            self._rotate_if_needed()
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def call(
        self,
        *,
        identity: str,
        tool_id: str,
        tool_version: int | None,
        parameters: dict[str, Any],
        scopes: list[str],
        outcome: str,
        exit_code: int | None = None,
        duration_ms: int | None = None,
        truncated: bool = False,
        denial_reason: str | None = None,
        detail: str | None = None,
        credential_names: list[str] | None = None,
    ) -> None:
        """A call -- successful, denied, or with unclear outcome.

        `denial_reason` records the *true* reason, even if the agent
        received only a non-descriptive response per FR-7.7. This
        asymmetry is what makes the log analyzable.
        """
        self.write(
            {
                "kind": "call",
                "identity": identity,
                "tool": tool_id,
                "tool_version": tool_version,
                "parameters": parameters,
                "scopes": scopes,
                "outcome": outcome,
                "exit_code": exit_code,
                "duration_ms": duration_ms,
                "output_truncated": truncated,
                "denial_reason": denial_reason,
                "detail": detail,
                # FR-10.7: names of used credentials, never their values.
                "credentials": credential_names or [],
            }
        )

    def set_secrets(self, secrets: tuple[str, ...]) -> None:
        """Refreshes the known-secret set used to mask output (FR-10.6),

        e.g. after a credential is created or rotated in the store.
        """
        self._redact.set_secrets(secrets)

    def redact(self, text: str) -> str:
        """Masks known credential values in `text` (FR-10.6).

        Used by `execute_http.py`/`execute_truenas.py` to scrub a response
        *before* it reaches the agent -- not only when it is later written
        to the audit log, which `write()` already does on its own.
        """
        return self._redact(text)

    def auth_failure(self, *, reason: str, detail: str = "") -> None:
        self.write({"kind": "auth_failure", "reason": reason, "detail": detail})

    def startup(self, payload: dict[str, Any]) -> None:
        self.write({"kind": "startup", **payload})


def _scrub(value: Any, redact: Redactor) -> Any:
    """Removes obvious secrets and masks known values."""
    if isinstance(value, dict):
        return {
            key: ("***" if _is_secret_key(key) else _scrub(item, redact))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item, redact) for item in value]
    if isinstance(value, str):
        return redact(value)
    return value