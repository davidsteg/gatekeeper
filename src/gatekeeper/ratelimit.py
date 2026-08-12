"""Rate-Limiting je Identitaet und Kategorie (FR-6.8)."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from .tier1 import RateLimit


class RateLimiter:
    """Gleitendes Fenster, im Speicher.

    Ausreichend fuer eine Handvoll Agenten in einem Container. Bei mehreren
    Instanzen muesste der Zaehler geteilt werden -- gatekeeper laeuft nach
    §14 als einzelne Instanz.
    """

    def __init__(self, limits: dict[str, RateLimit]) -> None:
        self._limits = limits
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, identity: str, category: str) -> bool:
        """Registriert einen Aufruf. False = Limit erreicht."""
        limit = self._limits.get(category)
        if limit is None:
            return True
        now = time.monotonic()
        window = self._events[(identity, category)]
        cutoff = now - limit.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= limit.count:
            return False
        window.append(now)
        return True
