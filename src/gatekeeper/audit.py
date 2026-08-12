"""Audit-Log (REQUIREMENTS.md §12).

Append-only, JSON Lines, mit Rotation. Die Rotation ist keine Kuer: ein
append-only-Log ohne Begrenzung fuellt irgendwann das Dataset, und dann steht
nicht nur gatekeeper (FR-9.5).
"""

from __future__ import annotations

import dataclasses
import json
import os
import threading
import time
from typing import Any

#: Feldnamen, deren Werte nie ins Log gelangen -- unabhaengig davon, wo sie
#: auftauchen. Ab Stufe 2 kommen die Credential-Werte aus §11 dazu.
_NEVER_LOG = frozenset({"token", "authorization", "password", "api_key", "secret"})


@dataclasses.dataclass(slots=True)
class Redactor:
    """Maskiert bekannte Geheimnisse in Ausgaben (FR-10.6).

    In Stufe 1 ist die Liste leer -- es gibt noch keinen Credential-Store. Die
    Stelle existiert trotzdem, weil `docker compose logs` regelmaessig
    Env-Variablen des Zielcontainers enthaelt und die Maskierung sonst spaeter
    an zehn Stellen nachgeruestet werden muesste.
    """

    secrets: tuple[str, ...] = ()

    def __call__(self, text: str) -> str:
        for secret in self.secrets:
            if secret and secret in text:
                text = text.replace(secret, "***")
        return text


class AuditLog:
    """Schreibt strukturierte Eintraege, rotiert nach Groesse."""

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
        """Ein Aufruf -- erfolgreich, abgelehnt oder mit unklarem Ausgang.

        `denial_reason` haelt den *echten* Grund fest, auch wenn der Agent nach
        FR-7.7 nur eine nichtssagende Antwort bekommen hat. Genau diese
        Asymmetrie macht das Log auswertbar.
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
                # FR-10.7: Namen der verwendeten Credentials, nie deren Werte.
                "credentials": credential_names or [],
            }
        )

    def auth_failure(self, *, reason: str, detail: str = "") -> None:
        self.write({"kind": "auth_failure", "reason": reason, "detail": detail})

    def startup(self, payload: dict[str, Any]) -> None:
        self.write({"kind": "startup", **payload})


def _scrub(value: Any, redact: Redactor) -> Any:
    """Entfernt offensichtliche Geheimnisse und maskiert bekannte Werte."""
    if isinstance(value, dict):
        return {
            key: ("***" if key.lower() in _NEVER_LOG else _scrub(item, redact))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item, redact) for item in value]
    if isinstance(value, str):
        return redact(value)
    return value
