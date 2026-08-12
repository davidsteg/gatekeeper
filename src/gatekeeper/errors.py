"""Fehlertypen.

Die Trennung ist bewusst: `DenialReason` ist das, was ins Audit-Log geht
(FR-9.2), `AGENT_MESSAGE` das, was der Agent zu sehen bekommt. Nach FR-7.7
duerfen sich fehlendes Recht und nicht existierendes Tool fuer den Agenten
nicht unterscheiden lassen, sonst wird `tools/call` zum Katalog-Orakel.
"""

from __future__ import annotations

import enum


class DenialReason(str, enum.Enum):
    """Interner Ablehnungsgrund - vollstaendig, nur fuers Audit-Log."""

    UNKNOWN_TOKEN = "unknown_token"
    UNKNOWN_TOOL = "unknown_tool"
    TOOL_DISABLED = "tool_disabled"
    NOT_GRANTED = "not_granted"
    SCOPE_MISMATCH = "scope_mismatch"
    PROTECTED_RESOURCE = "protected_resource"
    PARAM_INVALID = "param_invalid"
    PARAM_UNKNOWN = "param_unknown"
    PARAM_MISSING = "param_missing"
    PARAM_DERIVED_SUPPLIED = "param_derived_supplied"
    CONTROL_CHARACTER = "control_character"
    PATH_ESCAPE = "path_escape"
    TIER1_VIOLATION = "tier1_violation"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    EXECUTOR_UNAVAILABLE = "executor_unavailable"


#: Einheitliche Antwort fuer alles, was der Agent nicht wissen soll (FR-7.7).
#: Unbekanntes Tool und fehlendes Recht ergeben exakt diesen Text.
#:
#: Alle ausgegebenen Texte sind englisch: sie erreichen Agenten (also
#: Sprachmodelle), das Audit-Log und das Betriebs-UI. Kommentare und Doku
#: bleiben deutsch.
OPAQUE_DENIAL = "Unknown tool, or not available."

#: Ablehnungsgruende, die dem Agenten gegenueber verschleiert werden.
_OPAQUE = frozenset(
    {
        DenialReason.UNKNOWN_TOOL,
        DenialReason.TOOL_DISABLED,
        DenialReason.NOT_GRANTED,
        DenialReason.SCOPE_MISMATCH,
        DenialReason.PROTECTED_RESOURCE,
    }
)


class GatekeeperError(Exception):
    """Basisklasse."""


class ConfigError(GatekeeperError):
    """Konfiguration ist ungueltig - fuehrt zum Startabbruch."""


class Tier1Violation(ConfigError):
    """Eine Tool-Definition verletzt die Deploy-Zeit-Grenzen (FR-4.6)."""


class Denied(GatekeeperError):
    """Ein Aufruf wurde abgelehnt.

    `reason` und `detail` gehen ins Audit-Log, `agent_message` an den Agenten.
    """

    def __init__(self, reason: DenialReason, detail: str = "") -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason
        self.detail = detail

    @property
    def agent_message(self) -> str:
        """Was der Agent sieht - bei Katalog-Informationen bewusst nichtssagend."""
        if self.reason in _OPAQUE:
            return OPAQUE_DENIAL
        if self.reason is DenialReason.RATE_LIMITED:
            return "Rate limit reached. Try again later."
        if self.reason is DenialReason.TIMEOUT:
            return self.detail or "Timed out."
        # Validierungsfehler duerfen konkret sein: sie verraten nichts ueber den
        # Katalog, sondern nur ueber die vom Agenten selbst gesendeten Werte.
        return self.detail or "Call denied."
