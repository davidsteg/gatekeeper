"""Rate limiting per identity and category (FR-6.8)."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from .tier1 import RateLimit


class RateLimiter:
    """Sliding window, in memory.

    Sufficient for a handful of agents in a single container. With multiple
    instances the counter would need to be shared -- gatekeeper runs as a
    single instance per §14.
    """

    def __init__(self, limits: dict[str, RateLimit]) -> None:
        self._limits = limits
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, identity: str, category: str) -> bool:
        """Registers a call. False = limit reached."""
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