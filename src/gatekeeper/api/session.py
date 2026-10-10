"""Console sessions, shared by the legacy `/ui` and the JSON API (`/api/v1`).

Moved here from `ui.py` unchanged, so both surfaces resolve the same
in-memory store: a password change or an identity deletion that calls
`drop_identity` signs that identity out of both, and there is exactly one
place that decides what a session is. The session never applies to `/mcp`
or `/admin/mcp` -- `AuthMiddleware` does not read cookies.
"""

from __future__ import annotations

import dataclasses
import secrets
import time

from ..identity import ADMIN_ROLE

SESSION_COOKIE = "gatekeeper_ui"
SESSION_TTL_SECONDS = 8 * 3600


@dataclasses.dataclass(frozen=True, slots=True)
class Session:
    identity: str
    role: str
    csrf: str

    @property
    def can_write(self) -> bool:
        return self.role == ADMIN_ROLE


@dataclasses.dataclass(slots=True)
class SessionStore:
    """Sessions in memory.

    Deliberately not persisted: a restart signs out everyone. The loss is
    a re-login, the gain is that a session token does not
    survive a restart and never lands on disk.
    """

    ttl: int = SESSION_TTL_SECONDS
    _sessions: dict[str, tuple[Session, float]] = dataclasses.field(default_factory=dict)

    def create(self, identity_id: str, role: str) -> str:
        self._prune()
        sid = secrets.token_urlsafe(32)
        session = Session(
            identity=identity_id, role=role, csrf=secrets.token_urlsafe(24)
        )
        self._sessions[sid] = (session, time.monotonic() + self.ttl)
        return sid

    def resolve(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        entry = self._sessions.get(sid)
        if entry is None:
            return None
        session, expires = entry
        if time.monotonic() >= expires:
            self._sessions.pop(sid, None)
            return None
        return session

    def destroy(self, sid: str | None) -> None:
        if sid:
            self._sessions.pop(sid, None)

    def drop_identity(self, identity_id: str, *, keep: str | None = None) -> None:
        """Signs out all sessions of an identity.

        Called after deletion, role revocation, and password change: an
        existing session would otherwise continue, even though access
        has been revoked or the secret has been changed.

        `keep` spares exactly one session -- the one that initiated the change
        itself. Without this exception, self-service would sign
        the user out for a successful change.
        """
        for sid in [
            s
            for s, (sess, _) in self._sessions.items()
            if sess.identity == identity_id and s != keep
        ]:
            self._sessions.pop(sid, None)

    def _prune(self) -> None:
        now = time.monotonic()
        for sid in [s for s, (_, exp) in self._sessions.items() if now >= exp]:
            self._sessions.pop(sid, None)


@dataclasses.dataclass(slots=True)
class LoginThrottle:
    """Thwarts rate attacks against the login form.

    The scrypt comparison costs about 50 ms per attempt per stored
    identity and thus already throttles on its own. But the form is the
    first surface a human can touch in a browser -- a hard
    limit per source address is cheaper here than the debate over whether
    scrypt alone suffices.
    """

    max_failures: int = 10
    window_seconds: int = 300
    _failures: dict[str, list[float]] = dataclasses.field(default_factory=dict)

    def blocked(self, client: str) -> bool:
        return len(self._recent(client)) >= self.max_failures

    def record_failure(self, client: str) -> None:
        self._recent(client).append(time.monotonic())

    def reset(self, client: str) -> None:
        self._failures.pop(client, None)

    def _recent(self, client: str) -> list[float]:
        cutoff = time.monotonic() - self.window_seconds
        recent = [t for t in self._failures.get(client, []) if t >= cutoff]
        self._failures[client] = recent
        return recent



