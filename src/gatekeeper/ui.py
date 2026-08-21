"""Operations and administration console.

Shows what applies at runtime -- Tier 1 boundaries, catalog, permission profiles,
audit log -- and lets Tier 2 be edited: create and modify tools,
manage identities, issue tokens.

Five design decisions underpin this layer:

1. **The session never applies to /mcp.** The MCP endpoint authenticates
   exclusively via the `Authorization` header, and that is exactly what makes it
   CSRF-proof: a browser does not attach such a header on its own,
   so a foreign page cannot produce it. A cookie, on the other hand, is
   sent automatically. The session here is read only by `ui.py` --
   `AuthMiddleware` does not know about it.

2. **Sign-in uses ID and password, not the token**
   (FR-11.5). The token is the credential for the API; typing it into a login form
   would send it through the clipboard, password store, and history
   -- and the same secret would then open both. Separate
   credentials mean: a lost console password cannot call tools,
   a lost token cannot open the console, and each can be
   changed independently.

3. **Every write form carries a CSRF token.** With write access,
   the cookie becomes a weapon for the first time: a foreign page could submit
   a form to `/ui/...`. `SameSite=Strict` already prevents this, but
   not in every constellation -- a page on the same site does not count
   as foreign. The token in the form closes the gap.

4. **Script-free by default.** The CSP forbids scripts entirely on every
   page. This follows from the data situation: the audit log shows
   parameter values from agents, for denied calls, unvalidated ones.
   Without script execution, an injected `<script>` is harmless, even if
   the escaping fails. Chart, forms, and most of the console therefore
   manage without code in the browser. The one narrow exception is the
   interactive access map (Overview and `/ui/access-map`), whose
   `script-src`/`connect-src 'self'` is nonce-scoped to those two routes
   only and never widened -- its client-side JS (`_ACCESS_MAP_JS`) builds
   every DOM node from server-JSON via `textContent`/`createElement`,
   never `innerHTML`, so the same untrusted-audit-data guarantee holds
   there too.

5. **Reading and writing are separate roles.** `viewer` sees everything,
   `admin` may change. Without this separation, anyone who can view the audit
   log would also have the right to create tools.

All output text is English; comments remain German.
"""

from __future__ import annotations

import dataclasses
import hmac
import html
import json
import os
import re
import secrets
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from . import __version__
from .admin_service import apply_pending
from .audit import AuditLog
from .catalog import ToolDef
from .credentials import KINDS as CREDENTIAL_KINDS
from .credentials import CredentialStore
from .credentials import WriteRefused as CredentialWriteRefused
from .errors import ConfigError
from .identity import (
    ADMIN_ROLE,
    MIN_PASSWORD_LENGTH,
    ROLES,
    UI_ROLES,
    IdentityStore,
)
from .integrations import INTEGRATIONS, Integration
from .pending import PendingAction, PendingStore, PendingWriteRefused
from .service import Service
from .store import ConfigStore, WriteRefused, load_tool_yaml, tool_to_yaml
from .tier1 import Destination, Toolkit
from .toolkit_proposals import (
    ToolkitProposal,
    ToolkitProposalStore,
    ToolkitProposalWriteRefused,
)

#: Prefix of all UI paths. `AuthMiddleware` lets exactly this prefix through
#: without a Bearer token -- the handlers check the session instead.
UI_PREFIX = "/ui"

#: Served from under `UI_PREFIX` (session-gated like every other UI route,
#: see `build_ui_routes`) rather than as a public static asset -- the page
#: that references it already requires a session, so nothing is gained by
#: making the script fetchable without one, and it avoids adding another
#: entry to `UI_COMPANION_PATHS`/`AuthMiddleware` for a single small file.
ACCESS_MAP_JS_PATH = f"{UI_PREFIX}/access-map.js"

#: Paths that a browser hits on its own as soon as someone types the
#: address. Without special handling, every visit would run into the token requirement
#: and produce two `auth_failure` entries -- but the failed attempt is the
#: most important finding in the audit log, and it is worthless if it sits
#: among favicon noise. Applies only when the UI is enabled.
UI_COMPANION_PATHS = frozenset({"/", "/favicon.ico"})

SESSION_COOKIE = "gatekeeper_ui"
SESSION_TTL_SECONDS = 8 * 3600

#: Read at most this many bytes from the end of the log file. The log may grow to 32 MB;
#: parsing it in full would make the page unusable.
AUDIT_READ_BYTES = 2 * 1024 * 1024
AUDIT_DEFAULT_LIMIT = 200


# -- Sessions -------------------------------------------------------------


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


# -- Reading the audit log -------------------------------------------------------


def read_audit(
    path: str,
    *,
    limit: int = AUDIT_DEFAULT_LIMIT,
    identity: str = "",
    tool: str = "",
    outcome: str = "",
) -> tuple[list[dict[str, Any]], bool]:
    """Reads the most recent entries of the current log file.

    Returns `(entries, truncated)`. `truncated` indicates that older
    material exists that is not visible here -- either because the file
    is longer than `AUDIT_READ_BYTES` or because rotation has already occurred. The UI
    points this out so that nobody takes the absence of an entry as
    proof.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return [], False

    start = max(0, size - AUDIT_READ_BYTES)
    with open(path, "rb") as handle:
        handle.seek(start)
        blob = handle.read()
    if start:
        # The first line is truncated and therefore not valid JSON.
        _, _, blob = blob.partition(b"\n")

    records: list[dict[str, Any]] = []
    for line in blob.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        if identity and record.get("identity") != identity:
            continue
        if tool and record.get("tool") != tool:
            continue
        if outcome and record.get("outcome") != outcome:
            continue
        records.append(record)

    truncated = start > 0 or len(records) > limit
    return list(reversed(records[-limit:])), truncated


def _parse_ts(value: Any) -> datetime | None:
    try:
        return datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S%z")
    except (ValueError, TypeError):
        return None


def _bucket_calls(
    records: list[dict[str, Any]], hours: int = 12, *, now: datetime | None = None
) -> list[tuple[int, int]]:
    """Calls per hour slot as `(succeeded, not succeeded)`.

    Both sides are rounded down to the full hour before computing.
    Rounding down only the present would be a silent bug: an entry from the
    current hour would then lie *after* the rounded-down present, get a
    negative age, and fall out of every slot -- the chart would
    stay empty even though calls just took place.
    """
    current = (now or datetime.now(UTC)).replace(
        minute=0, second=0, microsecond=0
    )
    buckets = [(0, 0) for _ in range(hours)]
    for record in records:
        if record.get("kind") != "call":
            continue
        stamp = _parse_ts(record.get("ts"))
        if stamp is None:
            continue
        hour = stamp.astimezone(UTC).replace(
            minute=0, second=0, microsecond=0
        )
        age = int((current - hour).total_seconds() // 3600)
        if 0 <= age < hours:
            slot = hours - 1 - age
            ok, bad = buckets[slot]
            if record.get("outcome") == "ok":
                buckets[slot] = (ok + 1, bad)
            else:
                buckets[slot] = (ok, bad + 1)
    return buckets


# -- Image markers ------------------------------------------------------------

_FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<path fill="#2f81f7" d="M16 2 4 7v9c0 7 5 12 12 14 7-2 12-7 12-14V7z"/>'
    '<path fill="#fff" d="M13 15v-2a3 3 0 0 1 6 0v2h1.2v6.5h-8.4V15z"/>'
    '<path fill="#2f81f7" d="M15 13.2a1 1 0 0 1 2 0V15h-2z"/>'
    "</svg>"
)

#: Line graphics, inline. No external source -- the container has no network,
#: and the CSP forbids anything foreign anyway.
_ICONS = {
    "shield": '<path d="M12 21.5s7.5-3.7 7.5-9.5V5.4L12 2.5 4.5 5.4v6.6c0 5.8 7.5 9.5 7.5 9.5z"/>',
    "gauge": '<path d="M3.5 18a9 9 0 1 1 17 0"/><path d="M12 14.5 16 9.5"/>',
    "layers": '<path d="M12 2.8 2.8 7.4 12 12l9.2-4.6z"/><path d="M2.8 16.6 12 21.2l9.2-4.6"/><path d="M2.8 12 12 16.6 21.2 12"/>',
    "sliders": '<path d="M4 7h5M13 7h7M4 17h9M17 17h3"/><circle cx="11" cy="7" r="2"/><circle cx="15" cy="17" r="2"/>',
    "key": '<circle cx="7.5" cy="15.5" r="3.6"/><path d="M10.2 13 20 3.2M17 3.2l3 3M14.6 5.6l2.6 2.6"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 6.8V12l3.4 2"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "lock": '<rect x="4.5" y="10.5" width="15" height="9.5" rx="2"/><path d="M8 10.5V7.4a4 4 0 0 1 8 0v3.1"/>',
    "ban": '<circle cx="12" cy="12" r="9"/><path d="m5.9 5.9 12.2 12.2"/>',
    "folder": '<path d="M3.5 7.4a2 2 0 0 1 2-2h3.6l2 2h7.4a2 2 0 0 1 2 2v8.2a2 2 0 0 1-2 2H5.5a2 2 0 0 1-2-2z"/>',
    "chip": '<rect x="7.5" y="7.5" width="9" height="9" rx="1.5"/><path d="M4 10h3.5M4 14h3.5M16.5 10H20M16.5 14H20M10 4v3.5M14 4v3.5M10 16.5V20M14 16.5V20"/>',
    "users": '<circle cx="9" cy="8" r="3.2"/><path d="M3.2 19.5a5.8 5.8 0 0 1 11.6 0"/><path d="M16.2 5.3a3.2 3.2 0 0 1 0 5.4M17.5 19.5a5.8 5.8 0 0 0-1.6-4"/>',
    "alert": '<path d="M12 3.5 2.8 19.8h18.4z"/><path d="M12 9.8v4.2M12 17.2h.01"/>',
    "check": '<path d="m5 12.5 4.6 4.6L19 7.7"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="m15.8 15.8 4.2 4.2"/>',
    "logout": '<path d="M14 20H6.5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2H14"/><path d="m16.5 15.5 3.5-3.5-3.5-3.5M20 12H9.5"/>',
    "share": '<circle cx="6" cy="12" r="2.6"/><circle cx="18" cy="6.5" r="2.6"/><circle cx="18" cy="17.5" r="2.6"/><path d="m8.4 10.8 7.2-3.2M8.4 13.2l7.2 3.2"/>',
    "activity": '<path d="M3 12h3.5l2.5-7 4 14 2.5-7H21"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "edit": '<path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17z"/><path d="m14.5 6.5 3 3"/>',
    "trash": '<path d="M4 7h16M9.5 7V4.8h5V7M6 7l1 12.2A1.8 1.8 0 0 0 8.8 21h6.4a1.8 1.8 0 0 0 1.8-1.8L18 7"/>',
    "power": '<path d="M12 3.5v8"/><path d="M7.5 6.4a7.5 7.5 0 1 0 9 0"/>',
    "refresh": '<path d="M20 11.5a8 8 0 1 0-.8 4.5"/><path d="M20 4.5V12h-6"/>',
    "save": '<path d="M5 4.5h11L19.5 8v11.5H5z"/><path d="M8.5 4.5v5h7v-5M8.5 19.5v-5h7v5"/>',
    "back": '<path d="M20 12H4.5"/><path d="m10 6-6 6 6 6"/>',
    "pencil": '<path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17z"/>',
    "chevron": '<path d="m9 5 7 7-7 7"/>',
    "book": '<path d="M4 19.5v-15A1.5 1.5 0 0 1 5.5 3H11v18H5.5A1.5 1.5 0 0 1 4 19.5z"/><path d="M20 19.5v-15A1.5 1.5 0 0 0 18.5 3H13v18h5.5a1.5 1.5 0 0 0 1.5-1.5z"/>',
    "bar-chart": '<path d="M4 20V10M12 20V4M20 20v-6"/><path d="M3 20h18"/>',
    # Generic executor/tooling glyphs -- deliberately schematic rather than
    # brand marks: a toolkit's own logo would be trademarked and would also
    # need refreshing whenever the toolkit doesn't map to a real product.
    # These read as "a package", "a shell", "a container", "git", "an API"
    # without claiming to *be* any specific vendor's icon.
    "package": '<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z"/>'
    '<path d="M3.5 7.5 12 12l8.5-4.5"/><path d="M12 12v9"/>',
    "terminal": '<rect x="3" y="4.5" width="18" height="15" rx="2"/>'
    '<path d="m7.5 9.5 3.5 3-3.5 3"/><path d="M13 15.5h4"/>',
    "container": '<rect x="3" y="9" width="8" height="8" rx="1"/>'
    '<rect x="13" y="9" width="8" height="8" rx="1"/>'
    '<path d="M7 9V6.5a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1V9"/>',
    "git-branch": '<path d="M6 3v9"/><circle cx="6" cy="15" r="3"/>'
    '<circle cx="6" cy="6" r="3"/><circle cx="17" cy="6" r="3"/>'
    '<path d="M17 9a8 8 0 0 1-8 8"/>',
    "cloud": '<path d="M7 18h10.5a4 4 0 0 0 .4-8 5.5 5.5 0 0 0-10.6-1.8A4.5 4.5 0 0 0 7 18z"/>',
}

# Which glyph best represents an executor: a docker-run toolkit reads as a
# container, a local one as a shell. Free-form executor strings that don't
# match a known value (an operator's own future addition) fall back to the
# generic "package" glyph rather than guessing.
_EXECUTOR_ICONS = {
    "docker": "container",
    "local": "terminal",
    "cli": "terminal",
    "shell": "terminal",
    "github": "git-branch",
    "git": "git-branch",
    "google": "cloud",
    "cloud": "cloud",
    "api": "cloud",
}


def _executor_icon(executor: str) -> str:
    return _EXECUTOR_ICONS.get(executor.strip().lower(), "package")


def _guess_integration(toolkit_name: str) -> str | None:
    """Best-effort match of an admin-named toolkit to a known integration.

    `Toolkit` has no field linking back to `Integration` -- the name in
    `toolkits.yaml` is free text the admin chose -- so this is containment
    matching against known integration keys, not a guarantee. Used only to
    pick a service logo for the access map; falls back to the executor icon
    (`_executor_icon`) when nothing matches, same fallback spirit as
    `_view_tools`'s own icon lookup.
    """
    name = toolkit_name.strip().lower()
    for key in INTEGRATIONS:
        if key in name:
            return key
    return None


def _target(obj: Toolkit | Destination) -> str:
    """The one target field that's actually set on a Toolkit or a

    Destination -- both carry the same three mutually-exclusive
    per-executor fields (FR-8.3g: a Destination mirrors Toolkit's own
    target fields), so picking "whichever one is set" is exactly the same
    one-liner for either type.
    """
    return obj.docker_host or obj.base_url or obj.ws_url or ""


def _base_tool_id(tool: ToolDef) -> str:
    """The bare, un-expanded id (`docker.compose_up`) a destination-qualified

    ToolDef (`docker.compose_up@nas1`) was fanned out from -- what
    `catalog.raw_of`/`store.py`'s write ops key on (FR-8.3h expands the
    YAML entry in memory only; the entry on disk keeps its bare id).
    Identical to `tool.id` when the tool has no destination.
    """
    if tool.destination is None:
        return tool.id
    return tool.id[: -(len(tool.destination) + 1)]


def _icon(name: str, size: int = 16) -> str:
    return (
        f'<svg class="icon" width="{size}" height="{size}" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.7" '
        f'stroke-linecap="round" stroke-linejoin="round">{_ICONS.get(name, "")}</svg>'
    )


# -- HTML ------------------------------------------------------------------

_STYLE = """
:root {
  --bg: #eef2f3;
  --surface: #ffffff;
  --sunken: #f3f7f8;
  --line: #d9e2e4;
  --fg: #0d1417;
  --muted: #5a6d72;
  /* Cyan/teal "gate" accent -- deliberately not the generic SaaS blue every
     other admin console reaches for. Semantic ok/deny/warn are unchanged:
     this is the one color that means "gatekeeper", not "pass/fail". */
  --accent: #0e7490;
  --accent-soft: rgba(14,116,144,.10);
  /* Ink on a filled accent or deny surface. Light mode carries enough
     contrast with white; the dark palette lightens both colours until
     white on top drops to 2.5:1, so there the ink turns dark. */
  --on-solid: #ffffff;
  --ok: #0c7a4f;   --ok-soft: rgba(12,122,79,.12);
  --deny: #bb2740; --deny-soft: rgba(187,39,64,.10);
  --warn: #8a5600; --warn-soft: rgba(138,86,0,.13);
  /* One color per identity on the access map, so a busy graph reads as
     "these lines belong to dev, those to homelab" at a glance instead of
     every granted edge being the same green. Picked to sit clearly apart
     from accent/ok/deny/warn's hues (no teal, green, red, or amber/brown)
     and from each other; cycles if there are more identities than colors. */
  --cat-1: #2563eb; --cat-1-soft: rgba(37,99,235,.12);
  --cat-2: #7c3aed; --cat-2-soft: rgba(124,58,237,.12);
  --cat-3: #db2777; --cat-3-soft: rgba(219,39,119,.12);
  --cat-4: #4338ca; --cat-4-soft: rgba(67,56,202,.12);
  --cat-5: #a21caf; --cat-5-soft: rgba(162,28,175,.12);
  --cat-6: #0369a1; --cat-6-soft: rgba(3,105,161,.12);
  --shadow: 0 1px 2px rgba(16,24,40,.05), 0 10px 26px -16px rgba(16,24,40,.26);
  /* Sharper than the rounded-card SaaS default -- a control panel, not a
     consumer app. One scale, everywhere, so nothing is ever half-reskinned. */
  --radius: 6px;
  --radius-sm: 4px;
  /* The sidebar's own palette, constant in both themes -- a console bezel,
     not a page that happens to be on the left. It is always dark: the one
     fixed reference point while the content column follows the OS theme. */
  --bezel-bg: #0a0f14;
  --bezel-line: #1c2830;
  --bezel-fg: #e6eef0;
  --bezel-muted: #7f9198;
  --bezel-accent: #2dd4bf;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #080b0d;
    --surface: #101619;
    --sunken: #0c1114;
    --line: #1e2a2e;
    --fg: #e3ecee;
    --muted: #85999e;
    --accent: #2dd4bf;
    --accent-soft: rgba(45,212,191,.14);
    --on-solid: #04191a;
    --ok: #46c08a;   --ok-soft: rgba(70,192,138,.14);
    --deny: #ff8296; --deny-soft: rgba(255,130,150,.14);
    --warn: #e0b341; --warn-soft: rgba(224,179,65,.15);
    --cat-1: #60a5fa; --cat-1-soft: rgba(96,165,250,.16);
    --cat-2: #a78bfa; --cat-2-soft: rgba(167,139,250,.16);
    --cat-3: #f472b6; --cat-3-soft: rgba(244,114,182,.16);
    --cat-4: #818cf8; --cat-4-soft: rgba(129,140,248,.16);
    --cat-5: #e879f9; --cat-5-soft: rgba(232,121,249,.16);
    --cat-6: #38bdf8; --cat-6-soft: rgba(56,189,248,.16);
    --shadow: 0 1px 2px rgba(0,0,0,.5), 0 12px 32px -18px rgba(0,0,0,.9);
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; color: var(--fg); background: var(--bg);
  /* A faint schematic dot grid instead of a flat fill -- infrastructure
     tooling, not a landing page. Pure CSS, no image request, invisible at
     reading distance until you look for it. */
  background-image: radial-gradient(color-mix(in srgb, var(--fg) 6%, transparent) 1px, transparent 1px);
  background-size: 22px 22px;
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.icon { flex: none; vertical-align: -.18em; }
.mono, code, input, select, textarea { font-family: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace; }
.muted { color: var(--muted); }

/* -- Layout -- */
.app { display: grid; grid-template-columns: 236px 1fr; min-height: 100vh; }
/* The sidebar is a bezel, not a page: it uses --bezel-* rather than the
   theme tokens, so it stays the same dark panel whether the content column
   is in light or dark mode -- the one constant a user re-orients from. */
.side {
  background: var(--bezel-bg); border-right: 1px solid var(--bezel-line);
  display: flex; flex-direction: column; gap: .25rem;
  padding: .9rem .7rem; color: var(--bezel-fg);
}
.brand {
  display: flex; align-items: center; gap: .55rem; min-width: 0;
  padding: .5rem .5rem 1rem;
  font-weight: 650; letter-spacing: -.015em; font-size: 1.02rem;
  font-family: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
}
.brand .icon { color: var(--bezel-accent); flex: none; }
.brand .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.brand .ver { font-weight: 500; font-size: .68rem; color: var(--bezel-muted); }
.side nav { display: flex; flex-direction: column; gap: .12rem; }
.side nav a {
  display: flex; align-items: center; gap: .6rem;
  padding: .52rem .6rem .52rem .5rem; border-radius: var(--radius-sm); text-decoration: none;
  color: var(--bezel-muted); font-size: .9rem; border-left: 2px solid transparent;
}
.side nav a:hover { background: color-mix(in srgb, var(--bezel-fg) 6%, transparent); color: var(--bezel-fg); }
/* A bracket instead of a filled pill -- "selected" reads as a targeting
   reticle on a console, not a hover state left switched on. */
.side nav a.active {
  background: color-mix(in srgb, var(--bezel-accent) 10%, transparent);
  color: var(--bezel-accent); font-weight: 600; border-left-color: var(--bezel-accent);
}
.side nav a.active::before { content: "\\203a"; font-weight: 700; }
.nav-badge {
  margin-left: auto; background: var(--bezel-accent); color: var(--bezel-bg);
  border-radius: 999px; font-size: .7rem; font-weight: 700; line-height: 1.4;
  padding: .02rem .42rem;
}
.side-foot { margin-top: auto; border-top: 1px solid var(--bezel-line); padding-top: .7rem; }
.who { display: flex; align-items: center; gap: .5rem; margin: 0; font-size: .84rem; }
.who b { font-weight: 600; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; }
.who .icon { color: var(--bezel-muted); }
.who .pill { background: transparent; border-color: var(--bezel-line); color: var(--bezel-muted); }
.side-foot a.btn, .side-foot button.ghost {
  border-color: var(--bezel-line); color: var(--bezel-muted);
}
.side-foot a.btn:hover, .side-foot button.ghost:hover { color: var(--bezel-fg); border-color: var(--bezel-muted); }

.col { min-width: 0; display: flex; flex-direction: column; }
.topbar {
  position: sticky; top: 0; z-index: 15;
  background: var(--surface); border-bottom: 1px solid var(--line);
  padding: 1rem 1.4rem; display: flex; gap: 1rem; align-items: flex-start; flex-wrap: wrap;
}
.topbar .grow { flex: 1; min-width: 260px; }
.topbar h1 { display: flex; align-items: center; gap: .5rem; font-size: 1.3rem; letter-spacing: -.02em; margin: 0; }
.topbar h1 .icon { color: var(--accent); }
.topbar p { margin: .3rem 0 0; color: var(--muted); font-size: .87rem; max-width: 78ch; }
.actions { display: flex; gap: .4rem; align-items: center; flex-wrap: wrap; }
main { padding: 1.2rem 1.4rem 3.5rem; }

@media (max-width: 900px) {
  /* minmax(0,...) and not a bare 1fr: a grid track defaults to the
     min-content width of its item, and the sidebar's is the full width of
     the nav row. That pushed the page 17px past the viewport and made the
     whole layout, content column included, slide sideways. */
  .app { grid-template-columns: minmax(0, 1fr); }
  .side {
    position: static; height: auto; flex-direction: row; align-items: center;
    flex-wrap: wrap; gap: .5rem; border-right: none; border-bottom: 1px solid var(--bezel-line);
    /* Matches .topbar/main's 1rem below, so the bezel's left edge lines up
       with the content column's instead of sitting ~5px further in. */
    padding: .9rem 1rem;
  }
  .brand { padding: .2rem .3rem; }
  /* min-width: 0 so the nav may become narrower than its links and scroll
     them instead of widening the row. */
  .side nav { flex-direction: row; flex: 1 1 320px; min-width: 0; overflow-x: auto; scrollbar-width: none; }
  .side nav::-webkit-scrollbar { display: none; }
  .side nav a { white-space: nowrap; border-left: none; border-bottom: 2px solid transparent; }
  .side nav a.active { border-left: none; border-bottom-color: var(--bezel-accent); }
  .side-foot { margin: 0; border: none; padding: 0; min-width: 0; }
  .topbar, main { padding-left: 1rem; padding-right: 1rem; }
}

/* -- Components -- */
h2 {
  display: flex; align-items: center; gap: .45rem;
  font-family: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
  font-size: .78rem; text-transform: uppercase; letter-spacing: .07em;
  color: var(--muted); margin: 1.6rem 0 .65rem; font-weight: 650;
}
h2 .icon { color: var(--accent); }
h2::before { content: "//"; color: var(--accent); font-weight: 700; }
.subhead {
  font-size: .68rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); font-weight: 650; padding: .75rem 1rem 0;
}
.card {
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: .8rem;
}
.card > .pad { padding: .9rem 1rem; }
/* No more filled sunken bar -- a thin accent rule under the label plus a
   colored tick reads as an instrument-panel readout, not a button. */
.card-head {
  display: flex; align-items: center; gap: .5rem; flex-wrap: wrap;
  padding: .7rem 1rem; border-bottom: 1px solid var(--line);
  border-radius: var(--radius) var(--radius) 0 0;
}
.card-head .name { font-weight: 650; letter-spacing: -.01em; }
.card-head .spacer { flex: 1; }
/* A <summary> reuses .card-head so a disclosure looks identical to every
   other card until it is opened. Closed, there is nothing below the divider
   to divide from, so the bottom border and rounding come back. */
summary.card-head { cursor: pointer; list-style: none; user-select: none; }
summary.card-head::-webkit-details-marker { display: none; }
details:not([open]) > summary.card-head {
  border-bottom: none; border-radius: var(--radius);
}
summary.card-head .chev {
  margin-left: auto; color: var(--muted); transition: transform .15s;
}
details[open] > summary.card-head .chev { transform: rotate(90deg); }
.card-head h3, .tk-head h3 {
  margin: 0; font-family: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
  font-size: .78rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); font-weight: 650; display: flex; align-items: center; gap: .4rem;
}

/* margin-bottom, not just the .7rem inter-tile gap: without it, the stat
   grid sits flush against whatever card follows -- .card already carries
   its own margin-bottom, but that trails the element, not leads it. */
.grid { display: grid; gap: .7rem; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); margin-bottom: .8rem; }
.stat {
  display: flex; align-items: center; gap: .75rem;
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); padding: .8rem .9rem; box-shadow: var(--shadow);
}
/* An outlined chip, not a filled one -- a readout indicator, not an icon
   badge. The tone shows in the ring and glyph, not a soft color fill. */
.stat .chip {
  width: 34px; height: 34px; border-radius: var(--radius-sm); flex: none;
  display: grid; place-items: center; background: transparent;
  border: 1.5px solid var(--accent); color: var(--accent);
}
.stat.t-deny .chip { border-color: var(--deny); color: var(--deny); }
.stat.t-ok .chip { border-color: var(--ok); color: var(--ok); }
.stat.t-warn .chip { border-color: var(--warn); color: var(--warn); }
.stat .n {
  font-family: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
  font-size: 1.5rem; font-weight: 650; line-height: 1.1; letter-spacing: -.01em;
}
.stat .l { color: var(--muted); font-size: .74rem; text-transform: uppercase; letter-spacing: .05em; }
.stat-link { text-decoration: none; color: var(--fg); display: flex; align-items: center; gap: .75rem; width: 100%; }
.stat-link:hover { background: var(--sunken); border-radius: 11px; }
.stat-link .n { color: var(--accent); }

/* Same reasoning as .grid's margin-bottom: this is a bare grid container,
   not a .card, so it carries none of .card's own trailing margin -- without
   one of its own it sits flush against whatever section follows it. */
.split { display: grid; grid-template-columns: minmax(0,1fr) 330px; gap: .8rem; align-items: start; margin-bottom: .8rem; }
@media (max-width: 1080px) { .split { grid-template-columns: 1fr; } }

.pill {
  display: inline-flex; align-items: center; gap: .25rem;
  padding: .12rem .48rem; border-radius: 999px;
  font-size: .755rem; font-weight: 500; white-space: nowrap;
  background: var(--sunken); border: 1px solid var(--line); color: var(--muted);
}
/* Every pill from _pills() carries a value that comes out of the
   configuration: a path root, a binary, a scope pattern. Those have no
   length limit, and kept on one line a single long one widens the grid
   column, then the card, then the whole page -- the sidebar scrolls
   sideways along with it. Short label pills ("required", "read") are not
   .mono and keep their single line. */
.pill.mono { white-space: normal; overflow-wrap: anywhere; }
.pill.accent { background: var(--accent-soft); border-color: transparent; color: var(--accent); }
.pill.ok     { background: var(--ok-soft);     border-color: transparent; color: var(--ok); }
.pill.deny   { background: var(--deny-soft);   border-color: transparent; color: var(--deny); }
.pill.warn   { background: var(--warn-soft);   border-color: transparent; color: var(--warn); }
/* For pills that are pure reference trivia (a binary path, a ceiling
   value) sitting next to pills that mean "notice this" (a denied
   argument, a protected resource). Same shape, quieter ink, so the
   colored ones keep their weight instead of competing with a wall of
   equally loud neutral pills. */
.pill.quiet { opacity: .62; }
.pills { display: flex; flex-wrap: wrap; gap: .28rem; }

/* -- /ui/requests tab switcher -- */
.req-tabs { display: flex; gap: .5rem; margin-bottom: .8rem; }
.req-tab {
  display: flex; align-items: center; gap: .4rem; padding: .5rem .9rem;
  border-radius: var(--radius); border: 1px solid var(--line);
  background: var(--surface); color: var(--muted); text-decoration: none;
  font-size: .88rem; font-weight: 600;
}
.req-tab:hover { border-color: var(--accent); color: var(--fg); }
.req-tab.active { border-color: var(--accent); color: var(--accent); background: var(--accent-soft); }
code {
  background: var(--sunken); border: 1px solid var(--line);
  padding: .06rem .3rem; border-radius: var(--radius-sm); font-size: .84em;
}

.rows { display: grid; }
.row { display: grid; grid-template-columns: minmax(150px, 190px) 1fr; gap: .45rem 1rem; padding: .55rem 1rem; align-items: start; }
/* Without this a grid item refuses to become narrower than its longest
   unbreakable word, which is what lets one long value push the layout wider
   than the viewport. */
.row > * { min-width: 0; }
.row + .row { border-top: 1px solid var(--line); }
.row-l { display: flex; align-items: center; gap: .4rem; color: var(--muted); font-size: .83rem; }
@media (max-width: 620px) { .row { grid-template-columns: 1fr; gap: .25rem; } }

/* -- Tables -- */
/* overflow-x alone already makes .wrap a scroll container on both axes -- a
   visible axis computes to auto next to a clipped one. The sticky header
   below therefore sticks inside .wrap and not to the viewport, which does
   nothing at all while .wrap is free to grow to its content height: on the
   audit page the header simply scrolled away with the rest.
   Bounding the height is what makes it work. The bound leaves the page
   itself less scroll than the table's own distance from the top, so the
   header cannot slide under the sticky topbar either. */
.wrap { overflow: auto; max-height: calc(100vh - 13rem); border-radius: var(--radius); }
table { width: 100%; border-collapse: collapse; font-size: .87rem; }
thead th {
  /* Above the striped row backgrounds and the inset outcome bars. */
  position: sticky; top: 0; background: var(--sunken); z-index: 2;
  text-align: left; padding: .58rem .7rem; color: var(--muted);
  font-size: .72rem; font-weight: 650; text-transform: uppercase;
  letter-spacing: .06em; border-bottom: 1px solid var(--line); white-space: nowrap;
}
tbody td { padding: .6rem .7rem; border-bottom: 1px solid var(--line); vertical-align: middle; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:nth-child(even) { background: color-mix(in srgb, var(--sunken) 35%, transparent); }
tbody tr:hover { background: var(--sunken); }
tbody tr.t-ok   td:first-child { box-shadow: inset 3px 0 var(--ok); }
tbody tr.t-deny td:first-child { box-shadow: inset 3px 0 var(--deny); }
tbody tr.t-warn td:first-child { box-shadow: inset 3px 0 var(--warn); }
/* A tool ID is one unbroken run of characters (dots, not spaces) -- with
   no break opportunity, "docker.compose_restart" stayed on one line and
   ran past the edge of the narrower Tools-page cards instead of wrapping. */
.tool-id { font-weight: 600; letter-spacing: -.01em; overflow-wrap: anywhere; }
.tool-matrix .col-tool { min-width: 160px; }
.tool-matrix .col-status, .tool-matrix .col-cat, .tool-matrix .col-idem { width: 1%; white-space: nowrap; }
.tool-matrix .col-ident { text-align: center; width: 1%; white-space: nowrap; }
.tool-matrix .cell-grant { text-align: center; }

/* -- Tool card grid (Tools page) -- */
.tk-section { margin-bottom: 1.4rem; }
.tk-head {
  display: flex; align-items: center; gap: .6rem;
  padding: .5rem 0; margin-bottom: .6rem;
  border-bottom: 1px solid var(--line);
}
.tk-count { font-size: .78rem; color: var(--muted); }
.tk-summary { display: flex; gap: .28rem; flex-wrap: wrap; margin-left: auto; }

.t-grid {
  display: grid; gap: .6rem;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
}
.t-card {
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); overflow: hidden; box-shadow: var(--shadow);
  transition: border-color .18s, box-shadow .18s;
}
.t-card:hover { border-color: var(--accent); box-shadow: var(--shadow), 0 0 0 1px var(--accent); }
.t-card.disabled { opacity: .5; }
.t-card-h {
  display: flex; align-items: flex-start; justify-content: space-between; gap: .5rem;
  padding: .6rem .8rem; border-bottom: 1px solid var(--line);
}
.t-card-id { display: flex; flex-direction: column; gap: .15rem; min-width: 0; }
.t-card-id .tool-id { font-size: .85rem; }
.t-card-title { font-size: .78rem; }
.t-card-marks { display: flex; gap: .25rem; flex-wrap: wrap; justify-content: flex-end; }
.t-card-body { padding: .55rem .8rem; display: flex; flex-direction: column; gap: .4rem; }
.t-card-row {
  display: flex; align-items: baseline; gap: .5rem; font-size: .82rem;
}
.t-card-row > .muted { min-width: 68px; flex-shrink: 0; font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; }
.t-card-ops {
  display: flex; gap: .3rem; padding: .4rem .8rem;
  border-top: 1px solid var(--line);
}
.t-detail { margin-top: .2rem; }
.t-detail summary {
  cursor: pointer; font-size: .78rem; color: var(--muted);
  padding: .3rem 0; user-select: none;
}
.t-detail summary:hover { color: var(--accent); }
.t-detail-body {
  padding: .4rem 0 .2rem; display: flex; flex-direction: column; gap: .4rem;
  border-top: 1px solid var(--line); margin-top: .3rem;
}

.argv {
  display: block; background: var(--sunken); border: 1px solid var(--line);
  border-radius: var(--radius-sm); padding: .38rem .48rem; margin-top: .28rem;
  font-size: .77rem; line-height: 1.45; white-space: pre-wrap; word-break: break-word;
  max-width: 30ch; color: var(--muted);
}
.param + .param { margin-top: .45rem; }
.param-h { display: flex; align-items: center; gap: .3rem; flex-wrap: wrap; }
.param-d { color: var(--muted); font-size: .77rem; margin-top: .1rem; }
td.ops { white-space: nowrap; }
td.ops form { display: inline; }

/* -- Access map -- */
.graph { width: 100%; height: 100%; display: block; touch-action: none; }
.graph text { font-family: inherit; }
.g-box { fill: var(--sunken); stroke: var(--line); transition: fill .18s, stroke .18s, stroke-width .18s; }
.g-box.deny { fill: var(--deny-soft); stroke: var(--deny); }
.g-box.ok { fill: var(--ok-soft); stroke: var(--ok); }
/* One identity, one color, on both its node and every edge leaving it --
   so a busy graph reads as "which lines are dev's" instead of every
   granted path being the same undifferentiated green. */
.g-box.c1 { fill: var(--cat-1-soft); stroke: var(--cat-1); }
.g-box.c2 { fill: var(--cat-2-soft); stroke: var(--cat-2); }
.g-box.c3 { fill: var(--cat-3-soft); stroke: var(--cat-3); }
.g-box.c4 { fill: var(--cat-4-soft); stroke: var(--cat-4); }
.g-box.c5 { fill: var(--cat-5-soft); stroke: var(--cat-5); }
.g-box.c6 { fill: var(--cat-6-soft); stroke: var(--cat-6); }
.g-t { fill: var(--fg); font-size: 11.5px; font-weight: 600; pointer-events: none; }
.g-s { fill: var(--muted); font-size: 9.5px; pointer-events: none; }
.g-count { fill: var(--accent); font-size: 10px; font-weight: 700; pointer-events: none; }
.g-e { fill: none; stroke: var(--ok); stroke-width: 1.5; opacity: .55; transition: opacity .18s, stroke-width .18s; }
.g-e.c1 { stroke: var(--cat-1); }
.g-e.c2 { stroke: var(--cat-2); }
.g-e.c3 { stroke: var(--cat-3); }
.g-e.c4 { stroke: var(--cat-4); }
.g-e.c5 { stroke: var(--cat-5); }
.g-e.c6 { stroke: var(--cat-6); }
.g-e.deny { stroke: var(--deny); stroke-dasharray: 5 4; opacity: .7; }
.g-e.none { stroke: var(--line); stroke-dasharray: 2 3; opacity: .5; }
.g-e.hot { stroke-width: 2.8; opacity: .9; }
.g-n { fill: var(--muted); font-size: 9px; pointer-events: none; }
.g-bg { fill: transparent; }
.g-node { cursor: help; }
.g-node:hover .g-box { fill: var(--accent-soft); stroke: var(--accent); stroke-width: 2; }
.g-node:hover .g-box.deny { fill: var(--deny-soft); stroke: var(--deny); stroke-width: 2; }
.g-node:hover .g-box.ok { fill: var(--ok-soft); stroke: var(--ok); stroke-width: 2; }
.g-node:hover .g-box.c1 { fill: var(--cat-1-soft); stroke: var(--cat-1); stroke-width: 2; }
.g-node:hover .g-box.c2 { fill: var(--cat-2-soft); stroke: var(--cat-2); stroke-width: 2; }
.g-node:hover .g-box.c3 { fill: var(--cat-3-soft); stroke: var(--cat-3); stroke-width: 2; }
.g-node:hover .g-box.c4 { fill: var(--cat-4-soft); stroke: var(--cat-4); stroke-width: 2; }
.g-node:hover .g-box.c5 { fill: var(--cat-5-soft); stroke: var(--cat-5); stroke-width: 2; }
.g-node:hover .g-box.c6 { fill: var(--cat-6-soft); stroke: var(--cat-6); stroke-width: 2; }
.g-node:hover .g-t { fill: var(--accent); }
.g-edge-group { cursor: help; }
.g-edge-group:hover .g-e { opacity: 1; stroke-width: 3; }
/* Filter result: a match is not decorated -- the point is that everything
   *else* recedes, so the shape of the map survives even with one hit. */
.g-node.dim, .g-edge-group.dim { opacity: .2; }
.g-node.match .g-box { stroke: var(--accent); stroke-width: 2; }
.legend { display: flex; gap: .8rem; flex-wrap: wrap; font-size: .78rem; color: var(--muted); margin-top: .6rem; }

/* -- Interactive access map (access-map.js) -- */
.btn.active { color: var(--fg); border-color: var(--accent); background: var(--accent-soft); }
/* A fixed, resizable box -- the map's content no longer dictates the
   <svg>'s own size (that would defeat zooming, the whole point of this
   view); pan/zoom happens inside this fixed viewport instead. */
.map-root {
  position: relative; height: 52vh; min-height: 380px; max-height: 780px;
  overflow: hidden; border: 1px solid var(--line); border-radius: var(--radius);
  cursor: grab; background: var(--sunken);
}
.map-root:active { cursor: grabbing; }
.map-root.map-root-full { height: 78vh; min-height: 520px; }
.map-root .g-node { cursor: pointer; }
.map-root .g-node.cluster .g-box { stroke-dasharray: 3 3; }
.map-root .g-logo { pointer-events: none; }
.map-root .map-loading { position: absolute; top: .8rem; left: .9rem; margin: 0; }
.map-controls {
  position: absolute; right: .6rem; bottom: .6rem; display: flex; gap: .3rem; z-index: 2;
}
.map-control-btn {
  width: 2rem; height: 2rem; padding: 0; font-size: 1rem; line-height: 1;
  border-radius: 6px; background: var(--surface);
}
.map-panel {
  position: fixed; top: 0; right: 0; bottom: 0; width: min(26rem, 92vw);
  background: var(--surface); border-left: 1px solid var(--line);
  box-shadow: -8px 0 24px rgba(0, 0, 0, .18);
  transform: translateX(100%); transition: transform .18s ease-out;
  z-index: 40; overflow-y: auto;
}
.map-panel.open { transform: translateX(0); }
.map-panel-head {
  display: flex; align-items: center; gap: .5rem; padding: .9rem 1rem;
  border-bottom: 1px solid var(--line); position: sticky; top: 0;
  background: var(--surface);
}
.map-panel-head h4 { margin: 0; font-size: .95rem; flex: 1; }
.map-panel-close { cursor: pointer; background: none; border: none; color: var(--muted); }
.map-panel-close:hover { color: var(--fg); }
.map-panel-body { padding: 1rem; font-size: .85rem; }
.map-panel-body .row-l { color: var(--muted); }
.map-backdrop {
  position: fixed; inset: 0; background: rgba(0, 0, 0, .25); z-index: 39;
  opacity: 0; pointer-events: none; transition: opacity .18s ease-out;
}
.map-backdrop.open { opacity: 1; pointer-events: auto; }
/* CSP is `style-src 'nonce-...'`, which does not cover inline `style=""`
   attributes -- only a `<style>` block with the nonce runs. An inline
   style is silently dropped, not an error the eye catches, so one-off
   layout tweaks live here as named classes instead. */
.caption { margin: .5rem 0 0; font-size: .78rem; }
.inline-row { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
.filter-row { display: flex; gap: .35rem; align-items: center; }
.filter-row input[type="text"] { width: 12rem; }
.pad.pad-tight { padding-top: .5rem; }
.scopes-area { min-height: 6rem; }
.legend i { display: inline-block; width: 14px; height: 0; margin-right: .3rem; vertical-align: middle; }
.legend .l-deny i { border-top: 2px dashed var(--deny); }
.legend .l-hot i { border-top: 3px solid var(--accent); }

/* -- Call flow pipeline -- */
.flow-scroll { overflow-x: auto; }
/* 10px measured wider than its 130px node box for the longest caption
   ("JSON-RPC 2.0, tools/list, tools/call") -- text ran past both edges of
   the box instead of staying inside it. 8px keeps every caption in this
   pipeline within its node, longest included. */
.flow-scroll .g-s { font-size: 8px; fill: var(--muted); }
.flow-scroll .g-t { font-size: 12.5px; }
.flow-empty { text-align: center; color: var(--muted); font-size: .82rem; padding: .8rem 0; }

/* -- Activity -- */
.chart { width: 100%; height: auto; display: block; }
.c-ok { fill: var(--ok); }
.c-deny { fill: var(--deny); }
.c-base { fill: var(--line); }
.c-ax { fill: var(--muted); font-size: 9px; font-family: inherit; }
.feed { display: flex; flex-direction: column; }
.feed-item { display: flex; gap: .55rem; padding: .7rem 1rem; align-items: baseline; border-top: 1px solid var(--line); font-size: .82rem; }
.feed-item .dot { width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--muted); }
.feed-item.t-ok .dot { background: var(--ok); }
.feed-item.t-deny .dot { background: var(--deny); }
.feed-item.t-warn .dot { background: var(--warn); }
.feed-item.t-accent .dot { background: var(--accent); }
.feed-item .txt { flex: 1; min-width: 0; }
.feed-item .txt b { font-weight: 600; }
.feed-item .when { color: var(--muted); font-size: .74rem; white-space: nowrap; }

/* -- Notes -- */
.note {
  display: flex; gap: .55rem; align-items: flex-start;
  background: var(--warn-soft); color: var(--warn);
  border-left: 3px solid var(--warn); border-radius: var(--radius);
  padding: .65rem .8rem; margin-bottom: .8rem; font-size: .85rem;
}
.note.bad { background: var(--deny-soft); color: var(--deny); border-left-color: var(--deny); }
.note.good { background: var(--ok-soft); color: var(--ok); border-left-color: var(--ok); }
.note .icon { margin-top: .1rem; }
.note strong { font-weight: 650; }
.note ul { margin: .3rem 0 0; padding-left: 1.1rem; }

/* -- Forms -- */
.filter {
  display: flex; gap: .5rem; flex-wrap: wrap; align-items: flex-end;
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); padding: .75rem .9rem; margin-bottom: .8rem; box-shadow: var(--shadow);
}
.filter label, .field { display: flex; flex-direction: column; gap: .22rem; }
.field { margin-bottom: .9rem; }
.filter span, .field > span {
  font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); font-weight: 650;
}
.field .hint { text-transform: none; letter-spacing: 0; font-weight: 400; font-size: .78rem; }
input, select, button, textarea {
  font-size: .87rem; padding: .4rem .58rem; border-radius: var(--radius-sm);
  border: 1px solid var(--line); background: var(--surface); color: var(--fg);
}
textarea { width: 100%; min-height: 26rem; line-height: 1.5; resize: vertical; tab-size: 2; }
input:focus, select:focus, button:focus-visible, textarea:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
button {
  cursor: pointer; font-weight: 600; font-family: inherit;
  background: var(--accent); border-color: var(--accent); color: var(--on-solid);
  display: inline-flex; align-items: center; gap: .3rem;
}
button.ghost { background: transparent; border-color: var(--line); color: var(--muted); }
button.ghost:hover { color: var(--fg); border-color: var(--muted); }
button.danger { background: transparent; border-color: var(--deny); color: var(--deny); }
button.danger:hover { background: var(--deny-soft); }
button.solid-danger { background: var(--deny); border-color: var(--deny); color: var(--on-solid); }
a.btn {
  text-decoration: none; font-size: .87rem; padding: .4rem .58rem; border-radius: var(--radius-sm);
  border: 1px solid var(--line); color: var(--muted); font-weight: 600;
  display: inline-flex; align-items: center; gap: .3rem;
}
a.btn:hover { color: var(--fg); border-color: var(--muted); }
a.btn.primary { background: var(--accent); border-color: var(--accent); color: var(--on-solid); }
a.reset { align-self: center; color: var(--muted); text-decoration: none; font-size: .83rem; padding: .4rem .3rem; }
a.reset:hover { color: var(--accent); }
.checks { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: .3rem; }
.checks label { display: flex; align-items: center; gap: .45rem; font-size: .85rem; padding: .25rem .35rem; border-radius: var(--radius-sm); }
.checks label:hover { background: var(--sunken); }
.checks input { width: auto; padding: 0; }
.editor { max-width: 900px; }
.secret {
  background: var(--sunken); border: 1px dashed var(--accent); border-radius: var(--radius);
  padding: .7rem .8rem; font-size: .9rem; word-break: break-all; margin: .5rem 0;
}

/* -- Integrations -- */
.integration-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: .8rem; }
.integration-card { display: flex; flex-direction: column; gap: .5rem; min-height: 100%; }
.integration-card-head { display: flex; align-items: center; gap: .6rem; }
.integration-card-head .name { font-weight: 650; font-size: 1rem; }
.integration-card-foot { margin-top: auto; }
.integration-logo {
  display: inline-flex; flex: none; align-items: center; justify-content: center;
  width: 28px; height: 28px; border-radius: 999px; overflow: hidden;
  /* Real brand marks are full-color and drawn for a light background; a
     monogram fallback (Tdarr) paints its own full-bleed colored circle
     over this, so the white never shows through for that case. */
  background: #fff;
}
.integration-logo-lg { width: 36px; height: 36px; }
.integration-logo svg { display: block; width: 100%; height: 100%; }

/* -- Release notes popup --
   CSS-only modal (:target), consistent with "no JavaScript" -- the
   backdrop is a full-viewport <a href="#..."> so clicking outside the
   box closes it (navigating away from the #release-notes fragment) with
   no script, and the close link/Escape-via-navigation does the same. */
a.ver { text-decoration: none; color: inherit; cursor: pointer; }
a.ver:hover { text-decoration: underline; color: var(--accent); }
.modal-backdrop {
  display: none; position: fixed; inset: 0; background: rgba(0,0,0,.6); z-index: 80;
}
#release-notes:target { display: block; }
#release-notes:target ~ .modal-box { display: flex; }
.modal-box {
  display: none; position: fixed; inset: 0; z-index: 81; margin: auto;
  width: min(640px, calc(100vw - 2.4rem)); max-height: min(80vh, 720px);
  background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: 1.4rem 1.6rem; flex-direction: column; overflow: hidden;
}
.modal-box h2 { margin: 0 0 .8rem; font-size: 1.1rem; display: flex; align-items: center; gap: .4rem; }
.modal-close {
  position: absolute; top: .7rem; right: .9rem; font-size: 1.3rem; line-height: 1;
  color: var(--muted); text-decoration: none; padding: .2rem .5rem; border-radius: var(--radius-sm);
}
.modal-close:hover { color: var(--fg); background: var(--sunken); }
.release-list { overflow-y: auto; }
.release-entry { padding-bottom: 1rem; margin-bottom: 1rem; border-bottom: 1px solid var(--line); }
.release-entry:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
.release-entry h3 {
  display: flex; align-items: center; gap: .4rem; font-size: .95rem; margin: 0 0 .4rem;
  font-family: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
}
.release-entry p { margin: .4rem 0; font-size: .87rem; color: var(--muted); line-height: 1.5; }
.release-entry ul { margin: .4rem 0; padding-left: 1.2rem; font-size: .87rem; color: var(--muted); line-height: 1.5; }
.release-entry code { background: var(--sunken); padding: .05rem .3rem; border-radius: 3px; font-size: .85em; }

/* -- Login -- */
.login { max-width: 390px; margin: 13vh auto; padding: 0 1.15rem; }
.login .card { margin: 0; }
.login .pad { padding: 1.6rem 1.5rem; }
.login .mark { width: 46px; height: 46px; border-radius: var(--radius); display: grid; place-items: center; background: var(--accent-soft); color: var(--accent); margin-bottom: .9rem; }
.login h1 { font-size: 1.28rem; margin: 0; letter-spacing: -.02em; }
.login p { color: var(--muted); font-size: .87rem; margin: .4rem 0 1.2rem; }
.login form { display: flex; flex-direction: column; gap: .6rem; }
.login input { width: 100%; padding: .55rem .7rem; }
.login button { padding: .55rem .7rem; justify-content: center; }
.login p.foot { font-size: .8rem; margin: .9rem 0 0; }
.err { display: flex; align-items: center; gap: .4rem; color: var(--deny); font-size: .85rem; margin: .9rem 0 0; }

/* -- Docs page -- */
.docs-tabs { display: flex; gap: .3rem; margin-bottom: 1rem; flex-wrap: wrap; }
.docs-tabs a {
  padding: .45rem .9rem; border-radius: 8px; text-decoration: none;
  font-size: .87rem; font-weight: 500; color: var(--muted);
  border: 1px solid var(--line); background: var(--surface);
}
.docs-tabs a:hover { color: var(--fg); }
.docs-tabs a.active { background: var(--accent-soft); color: var(--accent); border-color: transparent; }
.prose { max-width: 86ch; font-size: .9rem; line-height: 1.62; }
.prose h1 { font-size: 1.35rem; margin: 1.4rem 0 .5rem; letter-spacing: -.02em; }
.prose h2 { font-size: 1.05rem; margin: 1.6rem 0 .5rem; text-transform: none; letter-spacing: -.01em; color: var(--fg); font-weight: 650; }
.prose h3 { font-size: .93rem; margin: 1.3rem 0 .4rem; font-weight: 600; }
.prose h4 { font-size: .87rem; margin: 1.1rem 0 .35rem; font-weight: 600; color: var(--muted); }
.prose p { margin: .5rem 0; }
.prose ul, .prose ol { margin: .5rem 0; padding-left: 1.5rem; }
.prose li { margin: .2rem 0; }
.prose pre {
  background: var(--sunken); border: 1px solid var(--line); border-radius: 8px;
  padding: .7rem .9rem; overflow-x: auto; margin: .7rem 0; font-size: .82rem;
}
.prose code { font-size: .84em; }
.prose pre code { background: none; border: none; padding: 0; }
.prose blockquote {
  border-left: 3px solid var(--accent); margin: .7rem 0; padding: .3rem .8rem;
  color: var(--muted); background: var(--accent-soft); border-radius: 0 6px 6px 0;
}
.prose table { margin: .8rem 0; font-size: .85rem; }
.prose table th, .prose table td { padding: .4rem .6rem; }
.prose hr { border: none; border-top: 1px solid var(--line); margin: 1.4rem 0; }
.prose a { color: var(--accent); }
.prose img { max-width: 100%; }
"""

#: The console is entirely in English -- comments and docs remain
#: German as in the rest of the project.
#: Overview's path is "" (it maps to UI_PREFIX + "/"), not a sentinel --
#: pages with no nav entry of their own (Account, the 403 pages) must pass
#: active="none" rather than active="", or they match Overview by accident.
_NAV = (
    ("", "Overview", "gauge"),
    ("/tools", "Tools", "sliders"),
    ("/tools/integrations", "Integrations", "package"),
    ("/identities", "Identities", "key"),
    ("/credentials", "Credentials", "lock"),
    ("/requests", "Requests", "share"),
    ("/audit", "Audit", "clock"),
    ("/stats", "Stats", "bar-chart"),
    ("/docs", "Docs", "book"),
)


def _e(value: Any) -> str:
    """Escape -- without exception.

    Everything that passes through here can come from an agent: audit entries
    record the *unvalidated* arguments for denied calls, so that the log
    shows what was actually attempted.
    """
    return html.escape("" if value is None else str(value), quote=True)


#: Cached per worker process: the file is small, read-only at runtime, and
#: reread on every popup click would be wasteful for something that never
#: changes without a redeploy anyway (RELEASE.md ships baked into the image).
_release_notes_cache: list[tuple[str, str]] | None = None


def _release_notes_path() -> str | None:
    """Where RELEASE.md lives, checked in order:

    1. `GATEKEEPER_RELEASE_NOTES` -- what the container image sets
       (`/usr/share/gatekeeper/RELEASE.md`, baked in at build time, since
       RELEASE.md is not part of the installed Python package).
    2. Walking up from this file -- a dev checkout or an editable install
       has the real `RELEASE.md` sitting next to `pyproject.toml`, the same
       trick `__init__.py`'s version lookup uses and for the same reason:
       always current, nothing to keep in sync by hand.

    Returns `None` if neither exists -- the popup then says so plainly
    instead of failing to render the page it's embedded in.
    """
    override = os.environ.get("GATEKEEPER_RELEASE_NOTES")
    if override and os.path.isfile(override):
        return override
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        candidate = os.path.join(here, "RELEASE.md")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    return None


def _inline_md(text: str) -> str:
    """Minimal, safe inline markdown: escape first, then allow exactly

    `**bold**` and `` `code` `` back in. No dependency, no HTML from the
    file ever passes through unescaped -- the regexes only ever *add*
    tags around already-escaped text, never interpret raw '<'/'>' in it.
    """
    escaped = _e(text)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    return escaped


def _render_release_body(text: str) -> str:
    """Blank lines separate blocks; within a bullet-list block, an indented

    continuation line belongs to the bullet above it rather than starting
    a new paragraph -- RELEASE.md's own entries wrap long bullets across
    several lines without a blank line between items (see e.g. the 0.4.0
    entry), so treating every line as its own list item would have
    flattened the whole list into one run-on paragraph.
    """
    blocks = re.split(r"\n\s*\n", text.strip())
    parts = []
    for block in blocks:
        raw_lines = [line for line in block.splitlines() if line.strip()]
        if not raw_lines:
            continue
        if raw_lines[0].strip().startswith(("- ", "* ")):
            items: list[str] = []
            current: list[str] = []
            for line in raw_lines:
                stripped = line.strip()
                if stripped.startswith(("- ", "* ")):
                    if current:
                        items.append(" ".join(current))
                    current = [stripped[2:].strip()]
                else:
                    current.append(stripped)
            if current:
                items.append(" ".join(current))
            rendered = "".join(f"<li>{_inline_md(item)}</li>" for item in items)
            parts.append(f"<ul>{rendered}</ul>")
        else:
            paragraph = " ".join(line.strip() for line in raw_lines)
            parts.append(f"<p>{_inline_md(paragraph)}</p>")
    return "".join(parts)


#: Only headings that look like a version (`## 0.4.0`, optionally with a
#: build/pre-release suffix) start a new entry -- RELEASE.md's own
#: explanatory prose has `## Procedure` and `## Versioning` headings above
#: the version list, and those must stay preamble, not become fake
#: "releases" with no notes.
_RELEASE_HEADING_RE = r"(?m)^## (\d+\.\d+\.\d+\S*)[ \t]*\n"


def _parse_release_notes(text: str) -> list[tuple[str, str]]:
    """Splits on `## <version>` headings -- the exact format RELEASE.md's

    own procedure section mandates, and what the release workflow's CI
    check parses too (see RELEASE.md). One format, read by both.
    """
    pieces = re.split(_RELEASE_HEADING_RE, text)
    sections = []
    # pieces[0] is the preamble before the first version heading; after
    # that, version/body pairs alternate. A duplicate version heading
    # (has happened once in this file's history) is kept as its own
    # entry rather than silently merged -- the list is never deduplicated.
    for i in range(1, len(pieces), 2):
        version = pieces[i]
        body = pieces[i + 1] if i + 1 < len(pieces) else ""
        sections.append((version, _render_release_body(body)))
    return sections


def _load_release_notes() -> list[tuple[str, str]]:
    global _release_notes_cache
    if _release_notes_cache is not None:
        return _release_notes_cache
    path = _release_notes_path()
    text = ""
    if path is not None:
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            text = ""
    sections = _parse_release_notes(text)
    _release_notes_cache = sections
    return sections


def _release_notes_modal() -> str:
    sections = _load_release_notes()
    if not sections:
        entries = _note(
            "Release notes are not available in this build -- RELEASE.md "
            "was not found. This does not affect what the server does, only "
            "this popup.",
            tone="bad",
        )
    else:
        entries = "".join(
            f'<section class="release-entry"><h3>{_icon("layers", 13)}'
            f'{_e(version)}</h3>{body}</section>'
            for version, body in sections
        )
    return (
        '<a href="#" id="release-notes" class="modal-backdrop" '
        'aria-hidden="true" tabindex="-1"></a>'
        '<div class="modal-box" role="dialog" aria-label="Release notes">'
        '<a href="#" class="modal-close" title="Close" aria-label="Close">'
        "&times;</a>"
        f"<h2>{_icon('layers', 16)}Release notes</h2>"
        f'<div class="release-list">{entries}</div>'
        "</div>"
    )


#: The interactive access map's client-side renderer. Vanilla ES2019, no
#: dependencies, no build step -- loaded only by `/ui/access-map` via a
#: script-src nonce scoped to that one route (see `_shell`/`_respond`).
#: Never touches `innerHTML` with server-derived data: every label, tool
#: ID, and identity name that could contain hostile audit-log-sourced text
#: is set through `textContent`, so nothing rendered here can execute.
_ACCESS_MAP_JS = """
(function () {
  "use strict";

  var NW = 132, NH = 52, GAP = 14;
  var TOOLKIT_GROUP_THRESHOLD = 8;
  var IDENTITY_GROUP_THRESHOLD = 20;
  //: Pan/zoom bounds and the drag-vs-click threshold, all in client pixels
  //: except MIN_K/MAX_K which are unitless scale factors.
  var MIN_K = 0.15, MAX_K = 6, CLICK_THRESHOLD_PX = 4;

  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

  function el(tag, attrs, ns) {
    var node = ns ? document.createElementNS(ns, tag) : document.createElement(tag);
    for (var k in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, k)) node.setAttribute(k, attrs[k]);
    }
    return node;
  }

  function svgEl(tag, attrs) {
    return el(tag, attrs, "http://www.w3.org/2000/svg");
  }

  function text(tag, attrs, value) {
    var node = svgEl(tag, attrs);
    node.textContent = value;
    return node;
  }

  function laneY(index, count, height) {
    var span = count * NH + Math.max(count - 1, 0) * GAP;
    return (height - span) / 2 + index * (NH + GAP);
  }

  function curve(x1, y1, x2, y2) {
    var span = (x2 - x1) / 2;
    return "M" + x1 + " " + y1 + " C" + (x1 + span) + " " + y1 + " "
      + (x2 - span) + " " + y2 + " " + x2 + " " + y2;
  }

  function callTotal(calls) {
    return calls && calls.total ? calls.total : 0;
  }

  // -- Grouping: collapse toolkits by executor and identities by role once
  // past a threshold, so hundreds of nodes render as a handful of clusters
  // by default. Expanding one cluster (click) only ever affects that lane.
  function groupNodes(nodes, kind, threshold, expanded) {
    var of_kind = nodes.filter(function (n) { return n.kind === kind; });
    if (of_kind.length <= threshold) return of_kind;
    var byGroup = {};
    var order = [];
    of_kind.forEach(function (n) {
      var g = n.group || "(none)";
      if (!byGroup[g]) { byGroup[g] = []; order.push(g); }
      byGroup[g].push(n);
    });
    var out = [];
    order.sort().forEach(function (g) {
      var members = byGroup[g];
      if (expanded[kind + ":" + g] || members.length === 1) {
        out = out.concat(members);
        return;
      }
      var calls = { ok: 0, denied: 0, failed: 0, total: 0 };
      members.forEach(function (m) {
        calls.ok += m.calls.ok; calls.denied += m.calls.denied;
        calls.failed += m.calls.failed; calls.total += m.calls.total;
      });
      var noun = kind === "identity" ? "identit" + (members.length === 1 ? "y" : "ies")
        : kind + (members.length === 1 ? "" : "s");
      out.push({
        id: "cluster:" + kind + ":" + g, kind: "cluster", label: g,
        sub: members.length + " " + noun,
        group: g, icon: members[0].icon, logo_key: null, color_class: "",
        calls: calls, granted_tools: [], cluster_kind: kind, members: members,
      });
    });
    return out;
  }

  function App(root) {
    this.root = root;
    this.endpoint = root.getAttribute("data-endpoint");
    this.query = (root.getAttribute("data-query") || "").toLowerCase();
    this.expanded = {};
    this.data = null;
    this.panel = null;
    this.backdrop = null;
    // Pan/zoom state -- world (SVG user unit) coordinates, independent of
    // the container's own CSS pixel size. `userAdjusted` is what lets a
    // re-render (search, cluster expand/collapse, window resize) preserve
    // the current view instead of snapping back to fit-to-content every
    // time the underlying data changes.
    this.tx = 0; this.ty = 0; this.k = 1;
    this.viewW = 100; this.viewH = 100;
    this.userAdjusted = false;
    this.pointers = {};
    this.dragStart = null;
    this.dragMoved = 0;
    this.pinchDist = null;
    this.resizeTimer = null;
  }

  App.prototype.load = function () {
    var self = this;
    fetch(this.endpoint, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("fetch failed"); return r.json(); })
      .then(function (data) { self.data = data; self.render(); })
      .catch(function () {
        var p = document.createElement("p");
        p.className = "muted";
        p.textContent = "Could not load the interactive map. The page below still works without scripts.";
        self.root.insertBefore(p, self.root.firstChild);
      });
  };

  App.prototype.visibleNodes = function () {
    var identities = groupNodes(this.data.nodes, "identity", IDENTITY_GROUP_THRESHOLD, this.expanded);
    var toolkits = groupNodes(this.data.nodes, "toolkit", TOOLKIT_GROUP_THRESHOLD, this.expanded);
    var destinations = this.data.nodes.filter(function (n) { return n.kind === "destination"; });
    return { identities: identities, toolkits: toolkits, destinations: destinations };
  };

  App.prototype.render = function () {
    var self = this;
    var q = this.query;
    var visible = this.visibleNodes();
    var hasDestinations = this.data.meta.has_destinations;

    var midItems = visible.toolkits.length;
    var rightItems = hasDestinations ? visible.destinations.length : midItems;
    var lanes = Math.max(visible.identities.length, midItems, rightItems, 1);
    // "World" size -- the content's own layout extent, unrelated to how
    // much of it is currently visible on screen (that's viewW/viewH below).
    var worldH = Math.max(lanes * (NH + GAP) + 30, 210);
    var lx = 8, mx = 360;
    var dx = mx + NW + 220;
    var rightmostX = hasDestinations ? dx : mx;
    var worldW = rightmostX + NW + 8;

    // The <svg>'s own viewBox is sized to the container's rendered CSS
    // box, not to content -- 1 viewBox unit == 1 CSS pixel. Zoom/pan is
    // entirely the g-viewport transform below; the outer svg never
    // resizes itself to fit content the way the old renderer's did.
    var rect = this.root.getBoundingClientRect();
    this.viewW = Math.max(rect.width, 100);
    this.viewH = Math.max(rect.height, 100);

    var svg = svgEl("svg", {
      "class": "graph", viewBox: "0 0 " + this.viewW + " " + this.viewH,
      role: "img", "aria-label": "Access map",
    });

    var viewport = svgEl("g", { "class": "g-viewport" });
    // A transparent full-extent rect so drag-to-pan works starting from
    // empty space, not just from directly grabbing a node. Kept OUTSIDE
    // g-content: its own huge extent would otherwise dominate
    // g-content's getBBox() and break fitToContent's scale calculation.
    var catcher = svgEl("rect", {
      "class": "g-pan-catcher", x: -100000, y: -100000, width: 200000, height: 200000,
      fill: "transparent",
    });
    var content = svgEl("g", { "class": "g-content" });
    var edgeLayer = svgEl("g", {});
    var nodeLayer = svgEl("g", {});
    content.appendChild(edgeLayer);
    content.appendChild(nodeLayer);
    viewport.appendChild(catcher);
    viewport.appendChild(content);
    svg.appendChild(viewport);

    var idPos = {}; // node id -> {x, y}
    var byId = {};
    this.data.nodes.forEach(function (n) { byId[n.id] = n; });

    function matches(node) {
      if (!q) return null;
      return (node.label || "").toLowerCase().indexOf(q) !== -1 ? "match" : "dim";
    }

    function drawNode(node, x, y, extraCls) {
      idPos[node.id] = { x: x, y: y };
      var mark = matches(node);
      var g = svgEl("g", { "class": "g-node" + (mark ? " " + mark : "") + (extraCls || "") });
      g.dataset.nodeId = node.id;
      var box = svgEl("rect", {
        "class": "g-box " + (node.color_class || ""), x: x, y: y, width: NW, height: NH, rx: 8,
      });
      g.appendChild(box);
      g.appendChild(text("text", { "class": "g-t", x: x + NW / 2, y: y + NH / 2 - 2, "text-anchor": "middle" }, node.label));
      g.appendChild(text("text", { "class": "g-s", x: x + NW / 2, y: y + NH / 2 + 11, "text-anchor": "middle" }, node.sub));
      var total = callTotal(node.calls);
      if (total) {
        g.appendChild(text("text", { "class": "g-count", x: x + NW / 2, y: y + NH / 2 + 22, "text-anchor": "middle" }, total + " calls"));
      }
      var title = svgEl("title", {});
      title.textContent = node.label + (node.sub ? " \\u2013 " + node.sub : "");
      g.appendChild(title);
      // A drag that happened to pass over this node must not also open it
      // -- dragMoved (tracked by the pointer handlers below) is the signal
      // that this "click" was really the tail end of a pan gesture.
      g.addEventListener("click", function () {
        if (self.dragMoved > CLICK_THRESHOLD_PX) { self.dragMoved = 0; return; }
        self.onNodeClick(node);
      });
      nodeLayer.appendChild(g);
    }

    visible.identities.forEach(function (node, i) {
      drawNode(node, lx, laneY(i, visible.identities.length, worldH), node.kind === "cluster" ? " cluster" : "");
    });
    visible.toolkits.forEach(function (node, i) {
      drawNode(node, mx, laneY(i, midItems, worldH), node.kind === "cluster" ? " cluster" : "");
    });
    if (hasDestinations) {
      visible.destinations.forEach(function (node, i) {
        drawNode(node, dx, laneY(i, rightItems, worldH));
      });
    }

    // Edges: only drawn between two currently-visible endpoints -- a
    // collapsed cluster's member edges fold into one edge from/to the
    // cluster node instead of disappearing.
    function resolve(rawId) {
      if (idPos[rawId]) return rawId;
      var node = byId[rawId];
      if (!node) return null;
      var prefix = node.kind + ":" + (node.group || "(none)");
      var clusterId = "cluster:" + prefix;
      return idPos[clusterId] ? clusterId : null;
    }

    var drawnPairs = {};
    this.data.edges.forEach(function (edge) {
      var fromId = resolve(edge.from);
      var toId = resolve(edge.to);
      if (!fromId || !toId || fromId === toId) return;
      var pairKey = fromId + ">" + toId;
      var already = drawnPairs[pairKey];
      if (already) {
        already.total += callTotal(edge.calls);
        return;
      }
      var rec = { total: callTotal(edge.calls), hot: edge.hot, kind: edge.kind, from: fromId, to: toId };
      drawnPairs[pairKey] = rec;
    });

    Object.keys(drawnPairs).forEach(function (key) {
      var e = drawnPairs[key];
      var p1 = idPos[e.from], p2 = idPos[e.to];
      if (!p1 || !p2) return;
      var y1 = p1.y + NH / 2, y2 = p2.y + NH / 2;
      var x1 = p1.x + NW, x2 = p2.x;
      var fromNode = byId[e.from] || { color_class: "" };
      var cls = "g-e " + (e.kind === "structural" ? "none" : (fromNode.color_class || ""));
      if (e.hot) cls += " hot";
      var mark = "";
      if (q) {
        var f = matches(byId[e.from] || {}), t = matches(byId[e.to] || {});
        mark = (f === "match" || t === "match") ? " match" : " dim";
      }
      var group = svgEl("g", { "class": "g-edge-group" + mark });
      var path = svgEl("path", { "class": cls, d: curve(x1, y1, x2, y2) });
      group.appendChild(path);
      var title = svgEl("title", {});
      title.textContent = (byId[e.from] ? byId[e.from].label : "") + " -> "
        + (byId[e.to] ? byId[e.to].label : "") + (e.total ? " (" + e.total + " calls)" : "");
      group.appendChild(title);
      // Edges live in edgeLayer, appended before nodeLayer above -- SVG
      // paints in document order, so they sit behind nodes without an
      // insertBefore trick.
      edgeLayer.appendChild(group);
    });

    nodeLayer.appendChild(text("text", { "class": "g-n", x: lx, y: 14 }, "IDENTITIES"));
    nodeLayer.appendChild(text("text", { "class": "g-n", x: mx, y: 14 }, "TOOLKITS"));
    if (hasDestinations) {
      nodeLayer.appendChild(text("text", { "class": "g-n", x: dx, y: 14 }, "DESTINATIONS"));
    }

    // Narrow teardown: only the previous <svg>, never the whole root --
    // the loading notice (removed once, below) and the control bar
    // (added once, before the first render) are siblings that must survive
    // every subsequent render() call triggered by search or cluster-expand.
    var loading = this.root.querySelector(".map-loading");
    if (loading) this.root.removeChild(loading);
    var old = this.root.querySelector("svg.graph");
    if (old) this.root.removeChild(old);
    this.root.appendChild(svg);

    // Preserve the user's own pan/zoom across data-driven re-renders;
    // only fit-to-content on the very first render (or after an explicit
    // Fit click resets nothing -- see ensureControls).
    if (this.userAdjusted) {
      this.applyTransform();
    } else {
      this.fitToContent();
    }
  };

  // -- Pan/zoom --------------------------------------------------------

  App.prototype.svgEl_ = function () {
    return this.root.querySelector("svg.graph");
  };

  App.prototype.applyTransform = function () {
    var svg = this.svgEl_();
    if (!svg) return;
    var g = svg.querySelector(".g-viewport");
    if (g) {
      g.setAttribute("transform", "translate(" + this.tx + " " + this.ty + ") scale(" + this.k + ")");
    }
  };

  // Converts a client-space point (e.g. straight from a mouse/pointer
  // event) into the <svg>'s own coordinate system via its screen CTM --
  // NOT a naive pixel delta, since CSS can render the svg at any size
  // independent of its viewBox.
  App.prototype.clientToSvg = function (clientX, clientY) {
    var svg = this.svgEl_();
    if (!svg) return { x: 0, y: 0 };
    var ctm = svg.getScreenCTM();
    if (!ctm) return { x: 0, y: 0 };
    var pt = svg.createSVGPoint();
    pt.x = clientX;
    pt.y = clientY;
    return pt.matrixTransform(ctm.inverse());
  };

  // Zoom by `factor`, keeping the world point under (clientX, clientY)
  // visually fixed -- the standard "zoom to cursor" (or pinch midpoint)
  // math, incremental so wheel and pinch can both call it per-step.
  App.prototype.zoomAt = function (clientX, clientY, factor) {
    var pre = this.clientToSvg(clientX, clientY);
    var newK = clamp(this.k * factor, MIN_K, MAX_K);
    var applied = newK / this.k;
    this.tx = pre.x - (pre.x - this.tx) * applied;
    this.ty = pre.y - (pre.y - this.ty) * applied;
    this.k = newK;
    this.userAdjusted = true;
    this.applyTransform();
  };

  App.prototype.zoomBy = function (factor) {
    var rect = this.root.getBoundingClientRect();
    this.zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, factor);
  };

  // Fits the full rendered content into the current viewport (a
  // `contain`-style scale + centered translate), padded so nodes at the
  // very edge aren't flush against the container's border.
  App.prototype.fitToContent = function () {
    var svg = this.svgEl_();
    if (!svg) return;
    // .g-content, not .g-viewport -- the viewport also holds the
    // full-extent pan-catcher rect, which would otherwise dominate the
    // bounding box and force the scale to its minimum every time.
    var g = svg.querySelector(".g-content");
    if (!g) return;
    var bbox;
    try {
      bbox = g.getBBox();
    } catch (err) {
      return;
    }
    if (!bbox || !bbox.width || !bbox.height) return;
    var pad = 24;
    var k = Math.min(
      this.viewW / (bbox.width + pad * 2),
      this.viewH / (bbox.height + pad * 2),
      MAX_K
    );
    this.k = Math.max(k, MIN_K);
    this.tx = this.viewW / 2 - (bbox.x + bbox.width / 2) * this.k;
    this.ty = this.viewH / 2 - (bbox.y + bbox.height / 2) * this.k;
    this.applyTransform();
  };

  App.prototype.ensureControls = function () {
    var self = this;
    var bar = document.createElement("div");
    bar.className = "map-controls";
    [
      ["+", "Zoom in", function () { self.zoomBy(1.3); }],
      ["\\u2212", "Zoom out", function () { self.zoomBy(1 / 1.3); }],
      ["Fit", "Fit to content", function () {
        self.fitToContent();
        // A one-time action, not a persistent mode: the next unrelated
        // re-render (search, cluster expand) must not silently re-fit
        // again on its own -- only another explicit Fit click does that.
        self.userAdjusted = true;
      }],
    ].forEach(function (spec) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "ghost map-control-btn";
      b.title = spec[1];
      b.textContent = spec[0];
      b.addEventListener("click", spec[2]);
      bar.appendChild(b);
    });
    this.root.appendChild(bar);
  };

  // Wheel-zoom, drag-to-pan, and touch (single-finger pan, two-finger
  // pinch-zoom) all wired once on the container -- it survives every
  // render() call, unlike the <svg> element itself, which gets replaced
  // on each one.
  App.prototype.wireZoomPan = function () {
    var self = this;
    var root = this.root;

    root.addEventListener("wheel", function (e) {
      e.preventDefault();
      var factor = Math.pow(1.0015, -e.deltaY);
      self.zoomAt(e.clientX, e.clientY, factor);
    }, { passive: false });

    // No setPointerCapture: capturing the pointer on `root` retargets the
    // browser's own click synthesis away from whatever element was
    // actually under the cursor (a node, a control button) to the
    // capturing element instead -- silently breaking every click. Plain
    // root-level pointerdown plus window-level move/up while a gesture is
    // active gets the same drag/pinch behavior without that side effect.
    function onPointerMove(e) {
      if (!(e.pointerId in self.pointers)) return;
      self.pointers[e.pointerId] = { x: e.clientX, y: e.clientY };
      var ids = Object.keys(self.pointers);
      if (ids.length >= 2) {
        var a = self.pointers[ids[0]], b = self.pointers[ids[1]];
        var dist = Math.hypot(a.x - b.x, a.y - b.y);
        var mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
        if (self.pinchDist) self.zoomAt(mid.x, mid.y, dist / self.pinchDist);
        self.pinchDist = dist;
        return;
      }
      if (!self.dragStart) return;
      var dxClient = e.clientX - self.dragStart.x;
      var dyClient = e.clientY - self.dragStart.y;
      self.dragMoved = Math.max(self.dragMoved, Math.hypot(dxClient, dyClient));
      var svg = self.svgEl_();
      var ctm = svg && svg.getScreenCTM();
      if (!ctm) return;
      // Client-pixel deltas -> viewBox-unit deltas via the CTM's own x/y
      // scale, cheaper than a full clientToSvg point conversion per move.
      self.tx = self.dragStart.tx + dxClient / ctm.a;
      self.ty = self.dragStart.ty + dyClient / ctm.d;
      self.userAdjusted = true;
      self.applyTransform();
    }

    function onPointerUp(e) {
      delete self.pointers[e.pointerId];
      self.pinchDist = null;
      var ids = Object.keys(self.pointers);
      if (ids.length === 1) {
        var remaining = self.pointers[ids[0]];
        self.dragStart = { x: remaining.x, y: remaining.y, tx: self.tx, ty: self.ty };
        self.dragMoved = 0;
      } else {
        self.dragStart = null;
      }
      if (ids.length === 0) {
        window.removeEventListener("pointermove", onPointerMove);
        window.removeEventListener("pointerup", onPointerUp);
        window.removeEventListener("pointercancel", onPointerUp);
      }
    }

    root.addEventListener("pointerdown", function (e) {
      // A control button (+/-/Fit) handles its own click; starting a pan
      // gesture from it would swallow that click for no benefit.
      if (e.target.closest && e.target.closest(".map-controls")) return;
      self.pointers[e.pointerId] = { x: e.clientX, y: e.clientY };
      if (Object.keys(self.pointers).length >= 2) {
        self.dragStart = null;
        self.pinchDist = null;
      } else {
        self.dragStart = { x: e.clientX, y: e.clientY, tx: self.tx, ty: self.ty };
        self.dragMoved = 0;
      }
      window.addEventListener("pointermove", onPointerMove);
      window.addEventListener("pointerup", onPointerUp);
      window.addEventListener("pointercancel", onPointerUp);
    });

    window.addEventListener("resize", function () {
      window.clearTimeout(self.resizeTimer);
      self.resizeTimer = window.setTimeout(function () {
        if (self.data) self.render();
      }, 120);
    });
  };

  App.prototype.onNodeClick = function (node) {
    if (node.kind === "cluster") {
      this.expanded[node.cluster_kind + ":" + node.group] = true;
      this.render();
      return;
    }
    this.openPanel(node);
  };

  App.prototype.ensurePanel = function () {
    if (this.panel) return;
    var self = this;
    var backdrop = document.createElement("div");
    backdrop.className = "map-backdrop";
    backdrop.addEventListener("click", function () { self.closePanel(); });
    document.body.appendChild(backdrop);

    var panel = document.createElement("div");
    panel.className = "map-panel";
    var head = document.createElement("div");
    head.className = "map-panel-head";
    var h4 = document.createElement("h4");
    var closeBtn = document.createElement("button");
    closeBtn.className = "map-panel-close";
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "Close");
    closeBtn.textContent = "\\u00d7";
    closeBtn.addEventListener("click", function () { self.closePanel(); });
    head.appendChild(h4);
    head.appendChild(closeBtn);
    var body = document.createElement("div");
    body.className = "map-panel-body";
    panel.appendChild(head);
    panel.appendChild(body);
    document.body.appendChild(panel);

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") self.closePanel();
    });

    this.panel = panel;
    this.backdrop = backdrop;
    this.panelTitle = h4;
    this.panelBody = body;
  };

  function row(label, value) {
    var r = document.createElement("div");
    r.className = "row";
    var l = document.createElement("div");
    l.className = "row-l";
    l.textContent = label;
    var v = document.createElement("div");
    v.textContent = value;
    r.appendChild(l);
    r.appendChild(v);
    return r;
  }

  App.prototype.openPanel = function (node) {
    this.ensurePanel();
    this.panelTitle.textContent = node.label;
    while (this.panelBody.firstChild) this.panelBody.removeChild(this.panelBody.firstChild);
    this.panelBody.appendChild(row("Kind", node.kind));
    this.panelBody.appendChild(row("Detail", node.sub));
    if (node.group) this.panelBody.appendChild(row(node.kind === "identity" ? "Role" : "Executor", node.group));
    if (node.target) this.panelBody.appendChild(row("Target", node.target));
    var calls = node.calls || { ok: 0, denied: 0, failed: 0, total: 0 };
    this.panelBody.appendChild(row("Calls", calls.total + " total (" + calls.ok + " ok, "
      + calls.denied + " denied, " + calls.failed + " failed)"));
    if (node.destinations && node.destinations.length) {
      this.panelBody.appendChild(row("Destinations", node.destinations.join(", ")));
    }
    if (node.granted_tools && node.granted_tools.length) {
      var label = document.createElement("div");
      label.className = "row-l";
      label.textContent = "Tools";
      this.panelBody.appendChild(label);
      var pills = document.createElement("div");
      pills.className = "pills";
      // Identity nodes carry {id, scopes} per tool (which scope THIS
      // grant needs); toolkit/destination nodes carry plain id strings
      // (just "what exists here") -- one loop handles both shapes.
      node.granted_tools.forEach(function (t) {
        var pill = document.createElement("span");
        pill.className = "pill mono quiet";
        var id = (t && typeof t === "object") ? t.id : t;
        var scopes = (t && typeof t === "object") ? t.scopes : null;
        pill.textContent = scopes && scopes.length ? id + " \\u00b7 " + scopes.join(", ") : id;
        pills.appendChild(pill);
      });
      this.panelBody.appendChild(pills);
    }
    this.panel.classList.add("open");
    this.backdrop.classList.add("open");
  };

  App.prototype.closePanel = function () {
    if (!this.panel) return;
    this.panel.classList.remove("open");
    this.backdrop.classList.remove("open");
  };

  App.prototype.wireSearch = function () {
    var self = this;
    var input = document.getElementById("map-search");
    var form = document.getElementById("map-filter");
    if (!input || !form) return;
    form.addEventListener("submit", function (e) {
      // Once the client-side renderer is live, filtering happens without a
      // reload -- the GET form is only the no-script fallback.
      e.preventDefault();
    });
    var timer = null;
    input.addEventListener("input", function () {
      window.clearTimeout(timer);
      timer = window.setTimeout(function () {
        self.query = input.value.toLowerCase();
        self.render();
      }, 150);
    });
  };

  function boot() {
    var root = document.getElementById("access-map-root");
    if (!root) return;
    var app = new App(root);
    app.ensureControls();
    app.wireZoomPan();
    app.wireSearch();
    app.load();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
"""


def _page(
    title: str,
    body: str,
    *,
    session: Session,
    subtitle: str = "",
    icon: str = "gauge",
    active: str,
    nonce: str,
    actions: str = "",
    account: bool = False,
    script_tag: str = "",
    nav_badge: int = 0,
) -> str:
    nav = "".join(
        f'<a href="{UI_PREFIX}{path or "/"}"'
        f'{" class=\"active\"" if path == active else ""}>'
        f"{_icon(name_icon, 16)}{_e(label)}"
        + (f'<span class="nav-badge">{nav_badge}</span>' if path == "/requests" and nav_badge else "")
        + "</a>"
        for path, label, name_icon in _NAV
    )
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=yes">'
        f"<title>{_e(title)} - gatekeeper</title>"
        f'<style nonce="{nonce}">{_STYLE}</style></head><body><div class="app">'
        '<aside class="side">'
        f'<div class="brand">{_icon("shield", 20)}'
        f'<span class="name">gatekeeper</span>'
        f'<a href="#release-notes" class="ver" title="Release notes">'
        f"v{_e(__version__)}</a></div>"
        f"<nav>{nav}</nav>"
        '<div class="side-foot">'
        f'<form class="who" method="post" action="{UI_PREFIX}/logout">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'{_icon("users", 15)}<b>{_e(session.identity)}</b>'
        f'<span class="pill">{_e(session.role)}</span>'
        + (
            f'<a class="btn" href="{UI_PREFIX}/account" title="Account">'
            f'{_icon("lock", 14)}</a>'
            if account
            else ""
        )
        + f'<button class="ghost" type="submit" title="Sign out">'
        f"{_icon('logout', 14)}</button>"
        "</form></div></aside>"
        f'<div class="col"><div class="topbar"><div class="grow">'
        f'<h1>{_icon(icon, 20)}{_e(title)}</h1>'
        + (f"<p>{subtitle}</p>" if subtitle else "")
        + "</div>"
        + (f'<div class="actions">{actions}</div>' if actions else "")
        + f"</div><main>{body}</main></div></div>"
        + _release_notes_modal()
        + script_tag
        + "</body></html>"
    )


def _pills(values: Any, *, tone: str = "", quiet: bool = False) -> str:
    items = list(values or ())
    if not items:
        return '<span class="muted">&ndash;</span>'
    css = " ".join(filter(None, ["pill", tone, "mono", "quiet" if quiet else ""]))
    return (
        '<div class="pills">'
        + "".join(f'<span class="{css}">{_e(v)}</span>' for v in items)
        + "</div>"
    )


def _note(text: str, *, icon: str = "alert", tone: str = "") -> str:
    return f'<div class="note {tone}">{_icon(icon, 16)}<div>{text}</div></div>'


def _stat(number: Any, label: str, icon: str, tone: str = "", title: str = "") -> str:
    title_attr = f' title="{_e(title)}"' if title else ""
    return (
        f'<div class="stat {tone}"{title_attr}><div class="chip">{_icon(icon, 18)}</div>'
        f'<div><div class="n">{_e(number)}</div>'
        f'<div class="l">{_e(label)}</div></div></div>'
    )


def _post_button(
    action: str,
    label: str,
    icon: str,
    session: Session,
    *,
    css: str = "ghost",
    fields: dict[str, str] | None = None,
) -> str:
    hidden = "".join(
        f'<input type="hidden" name="{_e(k)}" value="{_e(v)}">'
        for k, v in (fields or {}).items()
    )
    return (
        f'<form method="post" action="{_e(action)}">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">{hidden}'
        f'<button class="{css}" type="submit" title="{_e(label)}">'
        f"{_icon(icon, 14)}</button></form>"
    )


def _respond(
    request: Request, html_text: str, nonce: str, status: int = 200,
    *, script_nonce: str | None = None,
) -> Response:
    response = HTMLResponse(html_text, status_code=status)
    # No scripts and no external sources by default. The nonce applies only
    # to the single <style> block. Most pages are inline HTML/SVG and
    # therefore need neither an image source nor code in the browser. The
    # one exception is `script_nonce`, opted into only by the routes that
    # render the interactive access map (Overview and /ui/access-map) --
    # nonce-scoped to that single response, never widened to 'self' or a
    # blanket default-src relaxation.
    directives = [
        "default-src 'none'",
        f"style-src 'nonce-{nonce}'",
        "img-src 'self' data:",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
    ]
    if script_nonce:
        directives.append(f"script-src 'nonce-{script_nonce}'")
        # The map's own fetch() to its same-origin JSON endpoint would
        # otherwise fall back to `default-src 'none'` and be blocked like
        # any other network access -- still same-origin only, not 'self'
        # on every route.
        directives.append("connect-src 'self'")
    response.headers["Content-Security-Policy"] = "; ".join(directives)
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # A UI with permission and audit data does not belong in any cache.
    response.headers["Cache-Control"] = "no-store"
    return response


# -- Access map ---------------------------------------------------------


def _call_stats(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Counts calls per identity: {id: {ok, denied, failed, total}}."""
    stats: dict[str, dict[str, int]] = {}
    for record in records:
        if record.get("kind") != "call":
            continue
        ident = record.get("identity") or ""
        if not ident:
            continue
        bucket = stats.setdefault(ident, {"ok": 0, "denied": 0, "failed": 0, "total": 0})
        outcome = record.get("outcome") or "unknown"
        if outcome == "ok":
            bucket["ok"] += 1
        elif outcome == "denied":
            bucket["denied"] += 1
        elif outcome == "failed":
            bucket["failed"] += 1
        bucket["total"] += 1
    return stats


def _tool_call_stats(
    records: list[dict[str, Any]], tools_by_kit: dict[str, set[str]],
) -> dict[str, dict[str, int]]:
    """Counts calls per toolkit by resolving the tool ID.

    ``{toolkit: {ok, denied, failed, total}}``. A call whose tool is in
    no known toolkit is grouped under ``_unknown``.
    """
    tool_to_kit: dict[str, str] = {}
    for kit, tool_ids in tools_by_kit.items():
        for tid in tool_ids:
            tool_to_kit[tid] = kit
    stats: dict[str, dict[str, int]] = {}
    for record in records:
        if record.get("kind") != "call":
            continue
        tool_id = record.get("tool") or ""
        kit = tool_to_kit.get(tool_id, "_unknown")
        bucket = stats.setdefault(kit, {"ok": 0, "denied": 0, "failed": 0, "total": 0})
        outcome = record.get("outcome") or "unknown"
        if outcome == "ok":
            bucket["ok"] += 1
        elif outcome == "denied":
            bucket["denied"] += 1
        elif outcome == "failed":
            bucket["failed"] += 1
        bucket["total"] += 1
    return stats


def _pair_call_stats(
    records: list[dict[str, Any]], tools_by_kit: dict[str, set[str]],
) -> dict[tuple[str, str], dict[str, int]]:
    """Counts calls per (identity, toolkit) pair -- the access map's edges.

    Without a hub node in the middle, each edge is a direct claim ("this
    identity called into this toolkit this many times"), so the stat it
    needs is per-pair, not per-identity and per-toolkit separately.
    """
    tool_to_kit: dict[str, str] = {}
    for kit, tool_ids in tools_by_kit.items():
        for tid in tool_ids:
            tool_to_kit[tid] = kit
    stats: dict[tuple[str, str], dict[str, int]] = {}
    for record in records:
        if record.get("kind") != "call":
            continue
        ident = record.get("identity") or ""
        kit = tool_to_kit.get(record.get("tool") or "")
        if not ident or not kit:
            continue
        bucket = stats.setdefault((ident, kit), {"ok": 0, "denied": 0, "failed": 0, "total": 0})
        outcome = record.get("outcome") or "unknown"
        if outcome == "ok":
            bucket["ok"] += 1
        elif outcome == "denied":
            bucket["denied"] += 1
        elif outcome == "failed":
            bucket["failed"] += 1
        bucket["total"] += 1
    return stats


def _bucket_calls_by_day(
    records: list[dict[str, Any]], days: int = 7, *, now: datetime | None = None,
) -> list[tuple[int, int]]:
    """Calls per day slot as ``(succeeded, not succeeded)``.

    Same shape and rounding-down-before-diffing approach as ``_bucket_calls``,
    but day-granularity for the 7d/30d chart on the Stats page.
    """
    current = (now or datetime.now(UTC)).replace(
        hour=0, minute=0, second=0, microsecond=0,
    )
    buckets = [(0, 0) for _ in range(days)]
    for record in records:
        if record.get("kind") != "call":
            continue
        stamp = _parse_ts(record.get("ts"))
        if stamp is None:
            continue
        day = stamp.astimezone(UTC).replace(
            hour=0, minute=0, second=0, microsecond=0,
        )
        age = int((current - day).total_seconds() // 86400)
        if 0 <= age < days:
            slot = days - 1 - age
            ok, bad = buckets[slot]
            if record.get("outcome") == "ok":
                buckets[slot] = (ok + 1, bad)
            else:
                buckets[slot] = (ok, bad + 1)
    return buckets


def _admin_action_stats(records: list[dict[str, Any]]) -> dict[str, int]:
    """Counts ``admin_change`` records by action, using ``_ADMIN_VERBS`` labels."""
    stats: dict[str, int] = {}
    for record in records:
        if record.get("kind") != "admin_change":
            continue
        action = record.get("action", "")
        label = _ADMIN_VERBS.get(action, action or "admin_change")
        stats[label] = stats.get(label, 0) + 1
    return dict(sorted(stats.items(), key=lambda kv: (-kv[1], kv[0])))


def _duration_stats(
    records: list[dict[str, Any]], tools_by_kit: dict[str, set[str]] | None = None,
) -> dict[str, dict[str, float]]:
    """Average and p95 duration per toolkit, plus overall."""
    tool_to_kit: dict[str, str] = {}
    if tools_by_kit:
        for kit, tool_ids in tools_by_kit.items():
            for tid in tool_ids:
                tool_to_kit[tid] = kit
    per_kit: dict[str, list[int]] = {}
    all_durations: list[int] = []
    for record in records:
        if record.get("kind") != "call":
            continue
        dur = record.get("duration_ms")
        if dur is None:
            continue
        try:
            dur = int(dur)
        except (TypeError, ValueError):
            continue
        all_durations.append(dur)
        kit = tool_to_kit.get(record.get("tool") or "", "_unknown")
        per_kit.setdefault(kit, []).append(dur)

    def _pct(values: list[int], pct: float) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        idx = max(0, min(len(s) - 1, int(len(s) * pct) - 1))
        return float(s[idx])

    result: dict[str, dict[str, float]] = {}
    for kit, durations in per_kit.items():
        result[kit] = {
            "avg": sum(durations) / len(durations) if durations else 0.0,
            "p95": _pct(durations, 0.95),
            "count": float(len(durations)),
        }
    result["_overall"] = {
        "avg": sum(all_durations) / len(all_durations) if all_durations else 0.0,
        "p95": _pct(all_durations, 0.95),
        "count": float(len(all_durations)),
    }
    return result


def _outcome_totals(records: list[dict[str, Any]]) -> dict[str, int]:
    """Flat outcome totals and error rate across all call records."""
    ok = denied = failed = 0
    for record in records:
        if record.get("kind") != "call":
            continue
        outcome = record.get("outcome") or "unknown"
        if outcome == "ok":
            ok += 1
        elif outcome == "denied":
            denied += 1
        elif outcome == "failed":
            failed += 1
    total = ok + denied + failed
    error_rate = int((denied + failed) / total * 100) if total else 0
    return {
        "ok": ok, "denied": denied, "failed": failed,
        "total": total, "error_rate": error_rate,
    }


def _access_graph_data(
    service: Service, identities: IdentityStore,
    records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The access map's node/edge model as JSON, for the interactive view.

    Gathers identities, toolkits, destinations, and live call stats, and
    returns plain structures rather than laid-out coordinates --
    `access-map.js` does the layout, grouping, filtering, and pan/zoom
    client-side, which is what lets it scale past the point a fixed
    server-rendered canvas could. Protected resources are deliberately not
    included -- they add nothing an identity can reach or a call can hit,
    and the Overview page's own "Protected resources" stat and each
    toolkit's own card already cover them.
    """
    idents = sorted(
        (i for i in identities.identities.values() if i.role not in UI_ROLES or i.tools),
        key=lambda i: i.id,
    ) or sorted(identities.identities.values(), key=lambda i: i.id)
    toolkits = sorted(service.tier1.toolkits.items())

    tools_by_kit: dict[str, set[str]] = {name: set() for name, _ in toolkits}
    tools_by_kit_and_dest: dict[str, dict[str, set[str]]] = {name: {} for name, _ in toolkits}
    for tool in service.catalog.tools.values():
        tools_by_kit.setdefault(tool.toolkit, set()).add(tool.id)
        if tool.destination:
            tools_by_kit_and_dest.setdefault(tool.toolkit, {}).setdefault(
                tool.destination, set()
            ).add(tool.id)

    dest_names = sorted({d for _, tk in toolkits for d in tk.destinations})
    dest_granted: dict[str, set[str]] = {
        d: {
            tid
            for name, _ in toolkits
            for tid in tools_by_kit_and_dest.get(name, {}).get(d, set())
        }
        for d in dest_names
    }

    audit_records = records or []
    ident_stats = _call_stats(audit_records)
    kit_stats = _tool_call_stats(audit_records, tools_by_kit)
    pair_stats = _pair_call_stats(audit_records, tools_by_kit)
    all_totals = [s["total"] for s in pair_stats.values()]
    hot_threshold = max(
        sorted(all_totals)[int(len(all_totals) * 0.75)] if all_totals else 0, 3,
    )

    def _zero() -> dict[str, int]:
        return {"ok": 0, "denied": 0, "failed": 0, "total": 0}

    # One color per identity that actually holds a grant, cycling past 6.
    ident_color: dict[str, str] = {}
    for identity in idents:
        if identity.tools:
            ident_color[identity.id] = f"c{len(ident_color) % 6 + 1}"

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for identity in idents:
        stats = ident_stats.get(identity.id, _zero())
        nodes.append({
            "id": f"identity:{identity.id}", "kind": "identity", "label": identity.id,
            "sub": f"{len(identity.tools)} tools" if identity.tools else "no tool rights",
            "group": identity.role,
            "icon": "key", "logo_key": None, "color_class": ident_color.get(identity.id, ""),
            "calls": stats,
            # Each tool paired with the scope(s) it requires -- not just
            # the identity's own scopes as a flat list, but which scope
            # each concrete grant actually needs (a tool not in the
            # catalog, if the grant outlived a delete/rename, is skipped
            # rather than guessed at).
            "granted_tools": [
                {"id": tid, "scopes": list(service.catalog.tools[tid].required_scopes)}
                for tid in sorted(identity.tools)[:20]
                if tid in service.catalog.tools
            ],
        })

    for name, tk in toolkits:
        stats = kit_stats.get(name, _zero())
        kit_tools = tools_by_kit.get(name, set())
        nodes.append({
            "id": f"toolkit:{name}", "kind": "toolkit", "label": name,
            "sub": f"{len(kit_tools)} tools", "group": tk.executor,
            "icon": _executor_icon(tk.executor), "logo_key": _guess_integration(name),
            "color_class": "", "calls": stats, "granted_tools": sorted(kit_tools)[:20],
            "destinations": list(tk.destinations),
            # Where this toolkit itself connects to -- distinct from its
            # `destinations` fan-out, and shown even when it has none.
            "target": _target(tk),
        })
        if tk.destinations:
            for dest_name in tk.destinations:
                edges.append({
                    "from": f"toolkit:{name}", "to": f"destination:{dest_name}",
                    "kind": "structural", "calls": _zero(), "hot": False,
                })
        else:
            for identity in idents:
                if not (identity.tools & kit_tools):
                    continue
                pair = pair_stats.get((identity.id, name), _zero())
                edges.append({
                    "from": f"identity:{identity.id}", "to": f"toolkit:{name}",
                    "kind": "grant", "calls": pair,
                    "hot": bool(pair["total"] >= hot_threshold and pair["total"] > 0),
                })

    for dest_name in dest_names:
        dest = service.tier1.destination(dest_name)
        granted_tools = dest_granted.get(dest_name, set())
        nodes.append({
            "id": f"destination:{dest_name}", "kind": "destination", "label": dest_name,
            "sub": f"{len(granted_tools)} tools", "group": "",
            "icon": "cloud", "logo_key": None, "color_class": "",
            "calls": _zero(), "granted_tools": sorted(granted_tools)[:20],
            "target": _target(dest) if dest else "",
        })
        for identity in idents:
            if not (identity.tools & granted_tools):
                continue
            edges.append({
                "from": f"identity:{identity.id}", "to": f"destination:{dest_name}",
                "kind": "grant", "calls": _zero(), "hot": False,
            })

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "hot_threshold": hot_threshold,
            "has_destinations": bool(dest_names),
            "identity_count": len(idents),
            "toolkit_count": len(toolkits),
            "destination_count": len(dest_names),
        },
    }


def _toolkit_access_matrix(
    service: Service, identities: IdentityStore, *, highlight: str = "",
) -> str:
    """Identity x toolkit grant matrix -- the access map's alternate, denser

    view for real scale (many toolkits/identities). Generalizes
    `_tool_matrix`'s per-tool table one level up to per-toolkit, so it stays
    legible with hundreds of tools where a tool-per-row table would not.
    """
    q = highlight.strip().lower()
    toolkits = sorted(service.tier1.toolkits.items())
    if not toolkits:
        return '<p class="muted">No toolkits configured yet.</p>'
    idents = sorted(
        (i for i in identities.identities.values() if i.role not in UI_ROLES or i.tools),
        key=lambda i: i.id,
    ) or sorted(identities.identities.values(), key=lambda i: i.id)

    tools_by_kit: dict[str, set[str]] = {name: set() for name, _ in toolkits}
    for tool in service.catalog.tools.values():
        tools_by_kit.setdefault(tool.toolkit, set()).add(tool.id)

    rows = []
    for name, tk in toolkits:
        if q and q not in name.lower():
            continue
        kit_tools = tools_by_kit.get(name, set())
        cells = "".join(
            f'<td class="cell-grant"><span class="pill ok">{len(i.tools & kit_tools)}'
            "</span></td>"
            if (i.tools & kit_tools)
            else '<td class="cell-grant"><span class="pill">&mdash;</span></td>'
            for i in idents
        )
        rows.append(
            f'<tr><td><code class="tool-id">{_e(name)}</code></td>'
            f'<td><span class="pill accent">{_icon(_executor_icon(tk.executor), 12)}'
            f'{_e(tk.executor)}</span></td>'
            f"<td>{len(kit_tools)}</td>{cells}</tr>"
        )

    if not rows:
        return _note(
            f"No toolkit matches &ldquo;{_e(highlight)}&rdquo;.", icon="search",
        )

    id_cols = "".join(
        f'<th class="col-ident" title="{_e(i.id)}">{_e(i.id[:8])}</th>' for i in idents
    )
    return (
        '<div class="wrap"><table class="tool-matrix">'
        "<thead><tr><th>Toolkit</th><th>Executor</th><th>Tools</th>"
        f"{id_cols}</tr></thead>"
        f'<tbody>{"".join(rows)}</tbody></table></div>'
    )


# -- Activity ------------------------------------------------------------


def _activity_chart(records: list[dict[str, Any]], hours: int = 12) -> str:
    """Calls per hour, succeeded vs. rejected -- as stacked bars."""
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    buckets = _bucket_calls(records, hours, now=now)
    peak = max((o + d for o, d in buckets), default=0)

    width, height, pad = 300.0, 78.0, 14.0
    slot_w = width / hours
    bw = slot_w * 0.62
    bars = []
    for index, (ok, bad) in enumerate(buckets):
        x = index * slot_w + (slot_w - bw) / 2
        usable = height - pad - 6
        h_ok = usable * ok / peak if peak else 0
        h_bad = usable * bad / peak if peak else 0
        if h_bad > 0:
            bars.append(
                f'<rect class="c-deny" x="{x:.1f}" y="{height - pad - h_bad:.1f}" '
                f'width="{bw:.1f}" height="{h_bad:.1f}" rx="1.5"/>'
            )
        if h_ok > 0:
            bars.append(
                f'<rect class="c-ok" x="{x:.1f}" y="{height - pad - h_bad - h_ok:.1f}" '
                f'width="{bw:.1f}" height="{h_ok:.1f}" rx="1.5"/>'
            )
        if h_ok == 0 and h_bad == 0:
            bars.append(
                f'<rect class="c-base" x="{x:.1f}" y="{height - pad - 2:.1f}" '
                f'width="{bw:.1f}" height="2" rx="1"/>'
            )

    first = (now - timedelta(hours=hours - 1)).strftime("%H:%M")
    has_data = peak > 0
    if not has_data:
        return (
            f'<svg class="chart" viewBox="0 0 {width:.0f} {height:.0f}" role="img" '
            f'aria-label="Calls per hour (none in last {hours}h)">'
            f'<text class="c-ax" x="{width / 2:.0f}" y="{height / 2:.0f}" '
            f'text-anchor="middle">No tool calls in the last {hours} hours</text>'
            f'<text class="c-ax" x="0" y="{height - 3:.0f}">{_e(first)}</text>'
            f'<text class="c-ax" x="{width:.0f}" y="{height - 3:.0f}" '
            f'text-anchor="end">{_e(now.strftime("%H:%M"))} UTC</text>'
            "</svg>"
        )
    return (
        f'<svg class="chart" viewBox="0 0 {width:.0f} {height:.0f}" role="img" '
        f'aria-label="Calls per hour">{"".join(bars)}'
        f'<text class="c-ax" x="0" y="{height - 3:.0f}">{_e(first)}</text>'
        f'<text class="c-ax" x="{width:.0f}" y="{height - 3:.0f}" '
        f'text-anchor="end">{_e(now.strftime("%H:%M"))} UTC</text>'
        "</svg>"
    )


_TONE = {"ok": "t-ok", "denied": "t-deny", "failed": "t-deny", "unknown": "t-warn"}
_PILL_TONE = {"ok": "ok", "denied": "deny", "failed": "deny", "unknown": "warn"}

_ADMIN_VERBS = {
    "tool_create": "created tool",
    "tool_update": "updated tool",
    "tool_delete": "deleted tool",
    "tool_enable": "enabled tool",
    "tool_disable": "disabled tool",
    "identity_create": "created identity",
    "identity_update": "updated identity",
    "identity_delete": "deleted identity",
    "token_rotate": "rotated the API token of",
    "password_set": "set the console password of",
}


def _feed(records: list[dict[str, Any]], limit: int = 7) -> str:
    """Recent events, newest first, with consecutive repeats collapsed.

    Three identical "Sign-in failed" rows in a row say nothing the first
    one didn't -- collapsing a run into a single "x3" row frees the
    limited slots shown here for events that actually differ.
    """
    collapsed: list[list[Any]] = []  # [tone, what, clock, count]
    for record in records:
        kind = record.get("kind", "")
        outcome = record.get("outcome") or ""
        clock = str(record.get("ts") or "").partition("T")[2][:5]
        if kind == "call":
            what = (
                f'<b class="mono">{_e(record.get("identity"))}</b> '
                f'&rarr; <span class="mono">{_e(record.get("tool"))}</span>'
            )
            if record.get("denial_reason"):
                what += f' <span class="pill deny">{_e(record["denial_reason"])}</span>'
        elif kind == "admin_change":
            verb = _ADMIN_VERBS.get(record.get("action", ""), record.get("action", ""))
            what = (
                f'<b class="mono">{_e(record.get("actor"))}</b> {_e(verb)} '
                f'<span class="mono">{_e(record.get("target"))}</span>'
            )
            outcome = "accent"
        elif kind == "auth_failure":
            what = (
                "<b>Sign-in failed</b> "
                f'<span class="pill deny">{_e(record.get("reason"))}</span>'
            )
            outcome = "denied"
        elif kind == "ui_login":
            what = f'<b class="mono">{_e(record.get("identity"))}</b> signed in'
            outcome = "ok"
        else:
            what = f"<b>{_e(kind)}</b>"
        tone = "t-accent" if outcome == "accent" else _TONE.get(outcome, "")
        if collapsed and collapsed[-1][0] == tone and collapsed[-1][1] == what:
            collapsed[-1][3] += 1
        else:
            if len(collapsed) >= limit:
                break
            collapsed.append([tone, what, clock, 1])

    items = []
    for tone, what, clock, count in collapsed:
        suffix = f' <span class="muted">&times;{count}</span>' if count > 1 else ""
        items.append(
            f'<div class="feed-item {tone}"><span class="dot"></span>'
            f'<span class="txt">{what}{suffix}</span>'
            f'<span class="when mono">{_e(clock)}</span></div>'
        )
    return (
        "".join(items)
        or '<div class="feed-item"><span class="txt muted">No activity yet.</span></div>'
    )


# -- Views: read ----------------------------------------------------------

# -- Call pipeline -------------------------------------------------------


def _call_flow_pipeline() -> str:
    """The 8 layers that every call passes through -- as a horizontal SVG.

    Each layer is a node with a name and a short explanation. The arrows
    show the path from the agent to execution. The diagram answers
    the question that otherwise only the code answers: in what order
    do the protective mechanisms engage, and what does each layer do.
    """
    layers = [
        ("MCP", "JSON-RPC 2.0, tools/list, tools/call"),
        ("Auth", "Bearer token → identity"),
        ("Authorize", "May this identity call this tool?"),
        ("Registry", "Look up the active definition"),
        ("Validate", "Type, regex, path resolution"),
        ("argv-build", "Structured args, never a shell"),
        ("Executor", "docker or local, timeouts, caps"),
        ("Audit", "JSON Lines, rotation, redaction"),
    ]
    n = len(layers)
    bw, bh, gap = 130.0, 58.0, 10.0
    arrow = 14.0
    total_w = n * bw + (n - 1) * (gap + arrow)
    height = bh + 36.0
    y = 8.0

    nodes = []
    edges = []
    for i, (name, desc) in enumerate(layers):
        x = i * (bw + gap + arrow)
        rx = x + bw
        cy = y + bh / 2
        nodes.append(
            f'<g class="g-node">'
            f'<rect class="g-box" x="{x:.0f}" y="{y:.0f}" width="{bw:.0f}" '
            f'height="{bh:.0f}" rx="7"/>'
            f'<text class="g-t" x="{x + bw / 2:.0f}" y="{y + bh / 2 - 6:.0f}" '
            f'text-anchor="middle">{_e(name)}</text>'
            f'<text class="g-s" x="{x + bw / 2:.0f}" y="{y + bh / 2 + 10:.0f}" '
            f'text-anchor="middle">{_e(desc)}</text>'
            f"<title>{_e(name)}: {_e(desc)}</title>"
            f"</g>"
        )
        if i < n - 1:
            ax = rx + 2
            ax2 = ax + arrow
            edges.append(
                f'<line x1="{ax:.0f}" y1="{cy:.0f}" x2="{ax2:.0f}" y2="{cy:.0f}" '
                f'class="g-e"/>'
                f'<polygon class="g-e" points="{ax2:.0f},{cy - 4:.0f} '
                f'{ax2 + 4:.0f},{cy:.0f} {ax2:.0f},{cy + 4:.0f}"/>'
            )

    return (
        f'<svg class="graph" viewBox="0 0 {total_w:.0f} {height:.0f}" '
        f'role="img" aria-label="Call flow pipeline">'
        f'{"".join(edges)}{"".join(nodes)}'
        "</svg>"
    )


# -- Tool matrix -----------------------------------------------------------


def _tool_matrix(service: Service, identities: IdentityStore) -> str:
    """Each tool as a row: status, category, idempotency, who may call it.

    The matrix answers at a glance: which tools exist, are they
    active, are they idempotent, and which identities may call them.
    """
    tools = sorted(service.catalog.tools.values(), key=lambda t: t.id)
    if not tools:
        return '<p class="muted">No tools defined yet.</p>'

    idents = sorted(
        (i for i in identities.identities.values() if i.role not in UI_ROLES or i.tools),
        key=lambda i: i.id,
    ) or sorted(identities.identities.values(), key=lambda i: i.id)

    rows = []
    for tool in tools:
        status = (
            '<span class="pill ok">enabled</span>' if tool.enabled
            else '<span class="pill deny">disabled</span>'
        )
        cat_tone = {"read": "", "write": "warn", "write_external": "deny"}
        category = (
            f'<span class="pill {cat_tone.get(tool.category, "")}">{_e(tool.category)}</span>'
        )
        idem = (
            '<span class="pill ok">yes</span>' if tool.idempotent
            else '<span class="pill warn">no</span>'
        )
        # One cell per identity — aligned with the header columns
        grant_cells = ""
        for i in idents:
            if tool.id in i.tools:
                grant_cells += '<td class="cell-grant"><span class="pill ok">✓</span></td>'
            else:
                grant_cells += '<td class="cell-grant"><span class="pill">—</span></td>'
        # The @destination suffix rendered dimmed and separate -- at a
        # glance it reads as "docker.compose_up, at nas1", not as a typo'd
        # tool ID (FR-8.3g).
        if tool.destination:
            id_html = (
                f'<code class="tool-id">{_e(_base_tool_id(tool))}'
                f'<span class="muted">@{_e(tool.destination)}</span></code>'
            )
        else:
            id_html = f'<code class="tool-id">{_e(tool.id)}</code>'
        rows.append(
            f"<tr>"
            f"<td>{id_html}</td>"
            f"<td>{status}</td>"
            f"<td>{category}</td>"
            f"<td>{idem}</td>"
            f"{grant_cells}"
            "</tr>"
        )

    id_cols = "".join(
        f'<th class="col-ident" title="{_e(i.id)}">{_e(i.id[:8])}</th>' for i in idents
    )
    omitted = len(identities.identities) - len(idents)
    caption = (
        f'<p class="muted caption">'
        f"{omitted} identit{'y' if omitted == 1 else 'ies'} with a "
        f"{'/'.join(UI_ROLES)} role and no per-tool grants "
        f"{'is' if omitted == 1 else 'are'} omitted here &ndash; "
        "their access comes from the role, not a grant per tool.</p>"
        if omitted > 0 else ""
    )
    return (
        '<div class="wrap"><table class="tool-matrix">'
        "<thead><tr>"
        '<th class="col-tool">Tool</th><th class="col-status">Status</th>'
        '<th class="col-cat">Category</th><th class="col-idem">Idempotent</th>'
        f"{id_cols}"
        "</tr></thead>"
        f'<tbody>{"".join(rows)}</tbody></table></div>{caption}'
    )


#: Above this many combined identities/toolkits/destinations, the access
#: map defaults to the dense table view instead of the graph -- a single
#: SVG canvas stops being legible well before this, while the table stays
#: scannable (FR: access map redesign).
ACCESS_MAP_TABLE_THRESHOLD = 80


def _access_map_legend() -> str:
    return (
        '<div class="legend">'
        "<span>each color is one identity</span>"
        '<span class="l-hot"><i></i>high traffic</span>'
        "<span>scroll/pinch to zoom, drag to pan, click a node for detail</span>"
        "</div>"
    )


def _access_map_mount(query: str, *, height_class: str = "") -> str:
    """The live map's mount point: a container `access-map.js` renders

    into, plus a plain-text notice for the no-script case. Shared by the
    Overview embed and the dedicated `/ui/access-map` page so the two
    can't drift out of sync -- there is only one map renderer now, entirely
    client-side (see `_ACCESS_MAP_JS`).
    """
    return (
        f'<div id="access-map-root" class="map-root{height_class}" '
        f'data-endpoint="{UI_PREFIX}/access-map/data" data-query="{_e(query)}">'
        '<p class="muted map-loading">Loading access map&hellip;</p>'
        '<noscript><p class="muted">Enable JavaScript to view the '
        "access map.</p></noscript>"
        "</div>"
    )


def _view_access_map(
    service: Service, identities: IdentityStore, request: Request,
) -> str:
    """The interactive access map page.

    Server-renders a filter/view-toggle form and the map's mount point
    (`_access_map_mount`); `access-map.js` -- loaded only on this route and
    `/ui/` via a scoped CSP `script-src` nonce (see `_shell`) -- fetches
    `{UI_PREFIX}/access-map/data`, groups nodes by executor/role once past a
    threshold, and renders a pannable/zoomable graph: nodes expand on
    click, search narrows live instead of just dimming, and a side panel
    shows detail without leaving the page.
    """
    query = request.query_params.get("q", "").strip()
    view = request.query_params.get("view", "").strip()

    dest_names = {d for _, tk in service.tier1.toolkits.items() for d in tk.destinations}
    total_nodes = (
        len(identities.identities) + len(service.tier1.toolkits) + len(dest_names)
    )
    table_default = total_nodes > ACCESS_MAP_TABLE_THRESHOLD
    show_table = view == "table" or (view != "graph" and table_default)
    q_param = f"&q={_e(query)}" if query else ""

    filter_form = (
        f'<form method="get" action="{UI_PREFIX}/access-map" class="filter-row" '
        'id="map-filter">'
        f'<input type="text" name="q" id="map-search" value="{_e(query)}" '
        'placeholder="Filter identity, toolkit, or resource&hellip;">'
        f'<button class="ghost" type="submit" title="Filter">{_icon("search", 14)}</button>'
        + (f'<a class="reset" href="{UI_PREFIX}/access-map">reset</a>' if query else "")
        + '<span class="spacer"></span>'
        + f'<a class="btn{"" if show_table else " active"}" '
        f'href="{UI_PREFIX}/access-map?view=graph{q_param}">'
        f'{_icon("share", 13)}Graph</a>'
        + f'<a class="btn{" active" if show_table else ""}" '
        f'href="{UI_PREFIX}/access-map?view=table{q_param}">'
        f'{_icon("sliders", 13)}Table</a>'
        "</form>"
    )

    if show_table:
        body = f'<div class="pad">{_toolkit_access_matrix(service, identities, highlight=query)}</div>'
    else:
        body = _access_map_mount(query, height_class=" map-root-full") + _access_map_legend()

    return (
        '<div class="card">'
        f'<div class="card-head"><h3>{_icon("share", 14)}Access map</h3></div>'
        f"<div class=\"pad\">{filter_form}{body}</div>"
        "</div>"
    )


def _view_overview(
    service: Service, identities: IdentityStore, store: ConfigStore | None,
    request: Request | None = None, session: Session | None = None,
) -> str:
    ready = service.executor_ready
    catalog = service.catalog
    active = sum(1 for t in catalog.tools.values() if t.enabled)
    blocked = len(catalog.disabled_by_tier1)
    protected = {r for tk in service.tier1.toolkits.values() for r in tk.protected_resources}
    records, _ = read_audit(os.path.join(service.tier1.audit_dir, "audit.jsonl"), limit=400)
    # Seeds the map's search box on load (?q=) and its GET form remains a
    # working fallback if scripts are off (a plain reload, filtering
    # nothing -- the map itself only renders with scripts, see
    # `_access_map_mount`); `App.prototype.wireSearch` takes over live
    # filtering client-side once access-map.js runs.
    query = request.query_params.get("q", "").strip() if request is not None else ""

    parts = []
    if store is not None:
        stuck = [n for n, ok in store.writability().items() if not ok]
        if stuck:
            parts.append(
                _note(
                    "<strong>Configuration is not writable.</strong> "
                    f"{_e(', '.join(sorted(stuck)))}.yaml sits on a read-only mount, "
                    "so every change will be refused. Mount the Tier 2 files "
                    "writable to use the admin functions.",
                    tone="bad",
                )
            )
    if catalog.disabled_by_tier1:
        rows = "".join(f"<li>{_e(v)}</li>" for v in catalog.disabled_by_tier1)
        parts.append(
            _note(
                "<strong>Disabled by a Tier 1 violation.</strong> These "
                f"definitions were not loaded:<ul>{rows}</ul>"
            )
        )
    if not service.tier1.toolkits:
        parts.append(_no_toolkits_note())
    elif not catalog.tools:
        parts.append(
            _note(
                "<strong>The catalog is empty, which is the state after "
                "installation.</strong> gatekeeper can currently do nothing at "
                "all. The Tier 1 boundaries below say what would be possible; "
                f'a tool has to be created before any of it is &ndash; <a href="{UI_PREFIX}'
                '/tools">start here</a>.',
                icon="sliders",
                tone="good",
            )
        )

    parts.append(
        '<div class="grid">'
        + _stat(active, "Tools active", "sliders", "t-ok")
        + _stat(len(identities.identities), "Identities", "key")
        + _stat(
            len(protected), "Protected resources", "lock", "t-deny",
            title="Toolkit targets blocked for every identity, from toolkits.yaml (FR-4.12)",
        )
        + _stat(
            blocked, "Tools disabled", "ban", "t-deny" if blocked else "",
            title="Tool definitions rejected at load time for violating a Tier 1 rule",
        )
        + "</div>"
    )

    # Highlight tiles from the same audit records loaded above — no extra
    # read.  These give the most important signal (calls and success rate)
    # without a click to the Stats page.
    _ov_totals = _outcome_totals(records)
    _ov_success = int(_ov_totals["ok"] / _ov_totals["total"] * 100) if _ov_totals["total"] else 0
    parts.append(
        '<div class="grid">'
        + _stat(
            _ov_totals["total"], "Calls (last 12h)", "activity",
            "t-ok" if _ov_totals["total"] else "",
        )
        + _stat(
            f"{_ov_success}%", "Success rate (last 12h)", "check",
            "t-ok" if _ov_success >= 80 else ("t-warn" if _ov_success >= 50 else "t-deny"),
        )
        + f'<div class="stat"><a href="{UI_PREFIX}/stats" class="stat-link">'
        f'<div class="chip">{_icon("bar-chart", 18)}</div>'
        f'<div><div class="n">View &rarr;</div>'
        f'<div class="l">Full stats</div></div></a></div>'
        + "</div>"
    )

    # Call pipeline: the 8 layers that every call passes through. This is
    # documentation, not a status readout -- it looks the same on every
    # visit, so it stays collapsed by default rather than pushing the
    # things that actually change (the map, the activity) below the fold.
    parts.append(
        '<details class="card">'
        f'<summary class="card-head"><h3>{_icon("layers", 14)}Call flow &ndash; '
        f'8 layers every request passes</h3><span class="spacer"></span>'
        f'<span class="chev">{_icon("chevron", 14)}</span></summary>'
        f'<div class="pad flow-scroll">{_call_flow_pipeline()}</div>'
        "</details>"
    )

    if ready:
        exec_cells = '<div class="pills">' + "".join(
            f'<span class="pill {"ok" if ok else "deny"}">'
            f'{_icon("check" if ok else "ban", 13)}{_e(name)}: '
            f'{"reachable" if ok else "unreachable"}</span>'
            for name, ok in sorted(ready.items())
        ) + "</div>"
    elif session is not None:
        exec_cells = (
            '<div class="inline-row">'
            '<span class="muted">not probed yet</span>'
            f'<form method="post" action="{UI_PREFIX}/probe-executors">'
            f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
            f'<button class="ghost" type="submit">{_icon("refresh", 13)}Check now</button>'
            "</form></div>"
        )
    else:
        exec_cells = (
            '<span class="muted">not probed yet &ndash; '
            "call <code>/health/ready</code></span>"
        )

    has_call_activity = any(r.get("kind") == "call" for r in records)
    # With no traffic yet, every edge is thin and every "hot path" feature
    # has nothing to show -- the map can read as broken rather than as a
    # topology view that also happens to track traffic. Said once, plainly,
    # instead of hidden behind a hover on each individual edge.
    no_traffic_caption = (
        '<p class="muted caption">'
        "No call traffic yet &ndash; the map above shows current grants; "
        "edges thicken and highlight as tools actually get used.</p>"
        if not has_call_activity
        else ""
    )

    parts.append(
        '<div class="split"><div>'
        '<div class="card">'
        f'<div class="card-head"><h3>{_icon("share", 14)}Access map</h3>'
        '<span class="spacer"></span>'
        f'<a class="btn" href="{UI_PREFIX}/access-map" title="Open the '
        f'full-page access map">{_icon("share", 13)}Open full page</a>'
        # GET form: still a working no-script fallback (a plain reload of
        # this page with ?q= seeded); `App.prototype.wireSearch` intercepts
        # it and filters live once access-map.js runs.
        f'<form method="get" action="{UI_PREFIX}/" class="filter-row" id="map-filter">'
        f'<input type="text" name="q" id="map-search" value="{_e(query)}" '
        'placeholder="Filter identity or toolkit&hellip;">'
        f'<button class="ghost" type="submit" title="Filter">{_icon("search", 14)}</button>'
        + (f'<a class="reset" href="{UI_PREFIX}/">reset</a>' if query else "")
        + "</form></div>"
        f'<div class="pad">{_access_map_mount(query)}'
        f"{_access_map_legend()}{no_traffic_caption}</div></div>"
        '<div class="card">'
        f'<div class="card-head"><h3>{_icon("server", 14)}Executors</h3></div>'
        f'<div class="pad">{exec_cells}</div></div>'
        "</div><div>"
        '<div class="card">'
        f'<div class="card-head"><h3>{_icon("activity", 14)}Activity</h3></div>'
        '<div class="subhead">Calls, last 12 h</div>'
        f'<div class="pad pad-tight">{_activity_chart(records)}</div>'
        # The feed below also carries sign-ins and admin changes, not just
        # calls -- labelling the whole card "Calls" said less than it
        # showed. Two headings, one for what is actually a call and one
        # for what is not.
        '<div class="subhead">Recent events</div>'
        f'<div class="feed">{_feed(records)}</div>'
        f'<div class="subhead"><a href="{UI_PREFIX}/stats">View full stats &rarr;</a></div>'
        "</div>"
        "</div></div>"
    )

    # Tool matrix: each tool as a row with status, category, idempotency
    # and who may call it. Answers the question that the access map
    # only shows aggregated: which concrete tool is granted to whom.
    if catalog.tools:
        parts.append(
            '<div class="card">'
            f'<div class="card-head"><h3>{_icon("sliders", 14)}Tool matrix &ndash; '
            f'{len(catalog.tools)} tools</h3></div>'
            f'<div class="pad">{_tool_matrix(service, identities)}</div>'
            "</div>"
        )

    toolkit_cards = "".join(
        '<div class="card">'
        f'<div class="card-head"><span class="name mono">{_e(name)}</span>'
        f'<span class="pill accent">{_icon(_executor_icon(tk.executor), 12)}{_e(tk.executor)}</span></div>'
        '<div class="rows">'
        f'<div class="row"><div class="row-l">{_icon("chip", 14)}Binaries</div>'
        f"<div>{_pills(tk.binaries, quiet=True)}</div></div>"
        f'<div class="row"><div class="row-l">{_icon("ban", 14)}Denied arguments</div>'
        f"<div>{_pills(tk.denied_args, tone='deny')}</div></div>"
        f'<div class="row"><div class="row-l">{_icon("folder", 14)}Path roots</div>'
        f"<div>{_pills(tk.path_roots, quiet=True)}</div></div>"
        f'<div class="row"><div class="row-l">{_icon("lock", 14)}Protected resources</div>'
        f"<div>{_pills(tk.protected_resources, tone='deny')}</div></div>"
        f'<div class="row"><div class="row-l">{_icon("gauge", 14)}Ceilings</div>'
        f'<div>{_pills([f"timeout {tk.max_timeout_seconds}s", f"output {tk.max_output_bytes} B"], quiet=True)}</div></div>'
        "</div></div>"
        for name, tk in sorted(service.tier1.toolkits.items())
    )

    limits = "".join(
        f"<tr><td><code>{_e(cat)}</code></td>"
        f"<td class='mono'>{lim.count}</td><td class='mono'>{lim.window_seconds} s</td></tr>"
        for cat, lim in sorted(service.tier1.rate_limits.items())
    )

    # Deploy-time configuration: it looks the same on every visit until the
    # next redeploy, unlike everything above (grants, traffic, tool state),
    # which changes from inside this same UI. Collapsed by default for the
    # same reason the call-flow pipeline is -- reference material should not
    # outweigh what actually changes on the page.
    parts.append(
        '<details class="card">'
        f'<summary class="card-head"><h3>{_icon("lock", 14)}Tier 1 &ndash; immutable '
        f'at runtime &ndash; {len(service.tier1.toolkits)} toolkits</h3>'
        '<span class="spacer"></span>'
        f'<span class="chev">{_icon("chevron", 14)}</span></summary>'
        '<div class="pad">'
        + _note(
            "These boundaries come from <code>toolkits.yaml</code> and cannot be "
            "edited here, by anyone, at any time. Changing them requires a "
            "redeploy (FR-4.11) &ndash; that is what makes every tool below safe "
            "to create from a web form.",
            icon="lock",
        )
        + toolkit_cards
        + f'<h2>{_icon("gauge", 14)}Rate limits</h2>'
        '<div class="wrap"><table>'
        "<thead><tr><th>Category</th><th>Calls</th><th>Window</th></tr></thead>"
        f"<tbody>{limits}</tbody></table></div>"
        "</div></details>"
    )
    return "".join(parts)


def _param_cell(tool: ToolDef) -> str:
    blocks = []
    for name, p in sorted(tool.parameters.items()):
        marks = [f'<span class="pill">{_e(p.type)}</span>']
        if p.is_derived:
            marks.append('<span class="pill ok">derived</span>')
        elif p.required:
            marks.append('<span class="pill accent">required</span>')
        detail = []
        if p.pattern is not None:
            detail.append(f"pattern <code>{_e(p.pattern.pattern)}</code>")
        if p.values:
            detail.append("values " + ", ".join(f"<code>{_e(v)}</code>" for v in p.values))
        if p.minimum is not None or p.maximum is not None:
            detail.append(f"range <code>{_e(p.minimum)}..{_e(p.maximum)}</code>")
        if p.derived:
            detail.append(f"from <code>{_e(p.derived)}</code>")
        if p.must_resolve_under:
            detail.append(f"under <code>{_e(p.must_resolve_under)}</code>")
        blocks.append(
            '<div class="param"><div class="param-h">'
            f'<span class="mono tool-id">{_e(name)}</span>{"".join(marks)}</div>'
            + (f'<div class="param-d">{" &middot; ".join(detail)}</div>' if detail else "")
            + "</div>"
        )
    return "".join(blocks) or '<span class="muted">none</span>'


def _view_tools(
    service: Service, identities: IdentityStore, session: Session, store: ConfigStore | None
) -> str:
    rev = store.tools_revision() if store else ""
    can_write = session.can_write and store is not None

    # Group tools by toolkit (the prefix before the first dot).
    by_toolkit: dict[str, list] = {}
    for tool in sorted(service.catalog.tools.values(), key=lambda t: t.id):
        tk = tool.id.split(".", 1)[0] if "." in tool.id else "other"
        by_toolkit.setdefault(tk, []).append(tool)

    if not by_toolkit and not service.tier1.toolkits:
        return _no_toolkits_note()

    if not by_toolkit:
        hint = (
            f'<p><a class="btn primary" href="{UI_PREFIX}/tools/new">'
            f'{_icon("plus", 14)}Create the first tool</a></p>'
            if can_write
            else '<p class="muted">An identity with <code>role: admin</code> '
            "can create tools here.</p>"
        )
        return (
            '<div class="card"><div class="pad">'
            "<p><strong>No tools yet.</strong> gatekeeper ships an empty "
            "catalog on purpose: after installation it can do nothing at all, "
            "and every capability from here on is a deliberate decision that "
            "lands in the audit log.</p>"
            "<p class='muted'>A tool binds one fixed action to a toolkit from "
            "Tier 1. It stays invisible to every agent until an identity is "
            "granted the right to it &ndash; defining and granting are two "
            "separate steps.</p>"
            f"{hint}</div></div>"
        )

    broken = ""
    if service.catalog.rejected:
        items = "".join(
            f"<li><code>{_e(spec.get('id', '?'))}</code> &ndash; {_e(reason)}</li>"
            for spec, reason in service.catalog.rejected
        )
        broken = _note(
            "<strong>Rejected by Tier 1 and therefore not loaded.</strong> They "
            f"stay in the file so they can be fixed:<ul>{items}</ul>"
        )

    sections = []
    for tk_name in sorted(by_toolkit):
        # No-destination tools first, then clustered by destination -- so
        # e.g. compose_up@nas1/compose_down@nas1 sit together instead of
        # interleaving alphabetically with the @nas2 pair (FR-8.3g).
        tk_tools = sorted(by_toolkit[tk_name], key=lambda t: (t.destination or "", t.id))
        tk_executor_name = service.tier1.toolkits[tk_name].executor if tk_name in service.tier1.toolkits else ""
        n_read = sum(1 for t in tk_tools if t.category == "read")
        n_write = len(tk_tools) - n_read
        n_enabled = sum(1 for t in tk_tools if t.enabled)
        n_disabled = len(tk_tools) - n_enabled

        # Toolkit summary header
        summary = (
            f'<span class="pill ok">{n_read} read</span>'
            if n_read
            else ""
        )
        if n_write:
            summary += f'<span class="pill warn">{n_write} write</span>'
        if n_disabled:
            summary += f'<span class="pill deny">{n_disabled} disabled</span>'

        cards = []
        for tool in tk_tools:
            callers = sorted(
                i.id for i in identities.identities.values() if tool.id in i.tools
            )
            cat_cls = "ok" if tool.category == "read" else "warn"
            marks = [
                f'<span class="pill {cat_cls}">{_e(tool.category)}</span>',
            ]
            if tool.idempotent:
                marks.append('<span class="pill">idempotent</span>')
            else:
                marks.append('<span class="pill deny">not idempotent</span>')
            if not tool.enabled:
                marks.append('<span class="pill deny">disabled</span>')
            if tool.destination:
                marks.append(
                    f'<span class="pill accent">{_icon("server", 12)}'
                    f'{_e(tool.destination)}</span>'
                )

            ops = ""
            if can_write:
                # Edit/toggle/delete act on the underlying YAML definition,
                # which is written once under its bare id -- a destination
                # expansion (tool.id = "docker.compose_up@nas1") has no
                # matching raw spec of its own (catalog.raw_of only knows
                # the bare id), and store.py's write ops match on that same
                # bare id. All destinations of one definition are therefore
                # edited/enabled/deleted together, which is correct: they
                # share one `enabled:` flag and one YAML entry.
                fields = {"id": _base_tool_id(tool), "rev": rev}
                ops = (
                    f'<a class="btn" title="Edit" '
                    f'href="{UI_PREFIX}/tools/edit?id={_e(fields["id"])}">{_icon("pencil", 14)}</a>'
                    + _post_button(
                        f"{UI_PREFIX}/tools/toggle",
                        "Disable" if tool.enabled else "Enable",
                        "power",
                        session,
                        fields={**fields, "enabled": "0" if tool.enabled else "1"},
                    )
                    + f'<a class="btn" title="Delete" '
                    f'href="{UI_PREFIX}/tools/delete?id={_e(fields["id"])}">{_icon("trash", 14)}</a>'
                )

            granted = (
                _pills(callers) if callers
                else '<span class="pill deny">nobody</span>'
            )

            # The primary-action row and the detail row are shaped by which
            # executor the tool's toolkit uses -- an http/truenas tool has
            # no binary/argv to show, and showing an empty one would read
            # as a bug rather than as "this executor doesn't have that".
            if tk_executor_name == "http":
                action_label, action_value = "request", f"{tool.http_method} {tool.path_template}"
                detail_label, detail_value = "query/body", " ".join(
                    f"{k}={v}" for k, v in {**tool.query_template, **(tool.body_template or {})}.items()
                ) or "-"
            elif tk_executor_name == "truenas":
                action_label, action_value = "rpc method", tool.rpc_method or ""
                detail_label, detail_value = "params", " ".join(
                    f"{k}={v}" for k, v in (tool.params_template or {}).items()
                ) or "-"
            else:
                action_label, action_value = "binary", tool.binary or ""
                detail_label, detail_value = "argv", " ".join(tool.argv)

            # Compact card: header row + expandable details
            cards.append(
                f'<div class="t-card {"disabled" if not tool.enabled else ""}">'
                f'<div class="t-card-h">'
                f'<div class="t-card-id">'
                f'<code class="tool-id">{_e(tool.id)}</code>'
                f'<span class="t-card-title muted">{_e(tool.title)}</span>'
                f'</div>'
                f'<div class="t-card-marks">{" ".join(marks)}</div>'
                f'</div>'
                f'<div class="t-card-body">'
                f'<div class="t-card-row"><span class="muted">{action_label}</span>'
                f'<code class="mono">{_e(action_value)}</code></div>'
                f'<div class="t-card-row"><span class="muted">granted to</span>{granted}</div>'
                f'<details class="t-detail"><summary>params, scopes &amp; limits</summary>'
                f'<div class="t-detail-body">'
                f'<div class="t-card-row"><span class="muted">{detail_label}</span>'
                f'<code class="argv">{_e(detail_value)}</code></div>'
                f'<div class="t-card-row"><span class="muted">params</span>{_param_cell(tool)}</div>'
                f'<div class="t-card-row"><span class="muted">scopes</span>{_pills(tool.required_scopes, tone="accent")}</div>'
                f'<div class="t-card-row"><span class="muted">limits</span>'
                f'<span class="mono muted">{tool.timeout_seconds}s / {tool.max_output_bytes} B</span></div>'
                f'</div></details>'
                f'</div>'
                + (f'<div class="t-card-ops">{ops}</div>' if can_write else "")
                + "</div>"
            )

        tk_executor = service.tier1.toolkits.get(tk_name)
        tk_icon = _executor_icon(tk_executor.executor) if tk_executor else "package"
        # Destination badges (FR-8.3g): a toolkit with declared destinations
        # lists each by name; one without still shows its single implicit
        # target if it has one (docker_host/base_url/ws_url), closing the
        # "where does this toolkit actually reach" visibility gap even
        # without multi-host.
        dest_badges = ""
        if tk_executor and tk_executor.destinations:
            dest_badges = "".join(
                f'<span class="pill accent">{_icon("server", 12)}{_e(d)}</span>'
                for d in tk_executor.destinations
            )
        elif tk_executor:
            single_target = _target(tk_executor)
            if single_target:
                dest_badges = (
                    f'<span class="pill quiet">{_icon("server", 12)}'
                    f'{_e(single_target)}</span>'
                )
        sections.append(
            f'<div class="tk-section">'
            f'<div class="tk-head">'
            f'<h3>{_icon(tk_icon, 14)}{_e(tk_name)}</h3>'
            f'<span class="tk-count">{n_enabled} tool{"s" if n_enabled != 1 else ""}</span>'
            f'<div class="tk-summary">{summary}{dest_badges}</div>'
            f'</div>'
            f'<div class="t-grid">{" ".join(cards)}</div>'
            f'</div>'
        )

    return broken + "".join(sections)


def _view_identities(
    service: Service, identities: IdentityStore, session: Session, store: ConfigStore | None
) -> str:
    known = set(service.catalog.tools)
    rev = store.identities_revision() if store else ""
    parts = []
    for identity in sorted(identities.identities.values(), key=lambda i: i.id):
        unknown = sorted(identity.tools - known)
        warn = (
            _note(
                "<strong>Rights on unknown tools.</strong> These IDs appear in "
                f"no catalog: {_pills(unknown, tone='deny')}"
            )
            if unknown
            else ""
        )
        ops = ""
        if session.can_write and store is not None:
            fields = {"id": identity.id, "rev": rev}
            ops = (
                f'<a class="btn" href="{UI_PREFIX}/identities/edit?id={_e(identity.id)}">'
                f'{_icon("pencil", 14)}Edit</a>'
                + _post_button(
                    f"{UI_PREFIX}/identities/rotate",
                    "Issue a new API token",
                    "refresh",
                    session,
                    fields=fields,
                )
                + f'<a class="btn" title="Delete" '
                f'href="{UI_PREFIX}/identities/delete?id={_e(identity.id)}">'
                f'{_icon("trash", 14)}</a>'
            )
        # Two credentials, two indicators: the token opens /mcp, the password
        # the console. Someone who only sees the role might mistake an
        # `admin` without a password for access.
        if identity.role in UI_ROLES:
            console = (
                '<span class="pill ok">console access</span>'
                if identity.can_sign_in
                else '<span class="pill deny">no console password</span>'
            )
        else:
            console = '<span class="pill">api only</span>'
        parts.append(
            '<div class="card">'
            f'<div class="card-head"><span class="name mono">{_e(identity.id)}</span>'
            f'<span class="pill {"accent" if identity.role == ADMIN_ROLE else ""}">'
            f'{_icon("key", 12)}{_e(identity.role)}</span>{console}'
            + (
                f'<span class="pill">{len(identity.tools)} tools</span>'
                if identity.tools
                else '<span class="pill">no tool rights</span>'
            )
            + f'<span class="spacer"></span>{ops}</div>'
            f'<div class="rows"><div class="row">'
            f'<div class="row-l">{_icon("sliders", 14)}Granted tools</div>'
            f"<div>{_pills(sorted(identity.tools), tone='ok')}</div></div>"
            f'<div class="row"><div class="row-l">{_icon("folder", 14)}Scopes</div>'
            f"<div>{_pills(identity.scopes, tone='accent')}</div></div></div>"
            + (f'<div class="pad">{warn}</div>' if warn else "")
            + "</div>"
        )
    return "".join(parts)


def _view_credentials(
    service: Service, session: Session, store: ConfigStore | None,
    credentials: CredentialStore | None,
) -> str:
    if credentials is None:
        return _note(
            "<strong>No credential store configured.</strong> Set "
            "GATEKEEPER_CREDENTIAL_KEY (or GATEKEEPER_CREDENTIAL_KEY_FILE) and "
            "restart to enable it.",
            tone="bad",
        )
    used_by: dict[str, tuple[str, ...]] = {}

    def _add_user(credential_name: str, label: str) -> None:
        used_by.setdefault(credential_name, ())
        used_by[credential_name] = (*used_by[credential_name], label)

    for tk in service.tier1.toolkits.values():
        if tk.credential:
            _add_user(tk.credential, tk.name)
    # A destination's own `credential:` overrides the toolkit's (FR-8.3g) --
    # missing it here would let an admin delete/rotate a credential that a
    # destination still depends on with no warning (the toolkit-level loop
    # above only ever sees a toolkit-wide credential, never a per-destination one).
    for dest in service.tier1.destinations.values():
        if dest.credential:
            _add_user(dest.credential, f"{dest.name} (destination)")
    parts = []
    for meta in credentials.names(used_by=used_by):
        ops = ""
        if session.can_write and store is not None:
            ops = (
                f'<a class="btn" href="{UI_PREFIX}/credentials/rotate?name={_e(meta.name)}">'
                f'{_icon("refresh", 14)}Rotate</a>'
                + f'<a class="btn" title="Delete" '
                f'href="{UI_PREFIX}/credentials/delete?name={_e(meta.name)}">'
                f'{_icon("trash", 14)}</a>'
            )
        overlap = (
            '<span class="pill accent">rotation overlap active</span>'
            if meta.in_overlap
            else ""
        )
        parts.append(
            '<div class="card">'
            f'<div class="card-head"><span class="name mono">{_e(meta.name)}</span>'
            f'<span class="pill">{_icon("lock", 12)}{_e(meta.kind)}</span>{overlap}'
            + (
                f'<span class="pill">{len(meta.used_by)} toolkit(s)</span>'
                if meta.used_by
                else '<span class="pill deny">unused</span>'
            )
            + f'<span class="spacer"></span>{ops}</div>'
            '<div class="rows">'
            + (
                f'<div class="row"><div class="row-l">{_icon("terminal", 14)}Header</div>'
                f'<div class="mono">{_e(meta.header)}</div></div>'
                if meta.header
                else ""
            )
            + f'<div class="row"><div class="row-l">{_icon("folder", 14)}Used by</div>'
            f"<div>{_pills(sorted(meta.used_by), tone='ok')}</div></div>"
            f'<div class="row"><div class="row-l">{_icon("clock", 14)}Created</div>'
            f'<div class="mono">{_e(meta.created_at)}</div></div>'
            + (
                f'<div class="row"><div class="row-l">{_icon("refresh", 14)}Rotated</div>'
                f'<div class="mono">{_e(meta.rotated_at)}</div></div>'
                if meta.rotated_at
                else ""
            )
            + "</div></div>"
        )
    return (
        _note(
            "The value is never shown here or anywhere else once saved "
            "(FR-10.2). Create, rotate, and delete -- there is no 'view'.",
            icon="lock",
        )
        + ("".join(parts) or '<p class="muted">No credentials yet.</p>')
    )


#: Rendering tone for each pending status -- matches the note/pill
#: vocabulary already used for call outcomes elsewhere in this file.
_PENDING_TONE = {
    "pending": "warn",
    "approved": "ok",
    "rejected": "",
    "stale": "deny",
}


def _resolved_tool_badge(store: ConfigStore | None, tool_id: str) -> str:
    """One tool, resolved against the live catalog -- so a reviewer sees
    whether it exists and what it currently is, not just a bare id.

    A pending proposal (especially `grant_set`) can name a tool that was
    never created, or that exists but is disabled -- approving that
    silently grants a right to nothing. This is the fix for exactly that:
    every tool id rendered on the Change tab of `/ui/requests` is looked up here, and a
    missing tool gets a distinct, unmissable warning state instead of
    looking identical to a real one.
    """
    flat = store.service.catalog.flat_spec_of(tool_id) if store is not None else None
    if flat is None:
        return (
            f'<div class="row"><span class="pill deny">missing</span> '
            f'<code>{_e(tool_id)}</code> &mdash; no such tool in the catalog</div>'
        )
    tone = "ok" if flat.get("enabled") else "warn"
    state = "enabled" if flat.get("enabled") else "disabled"
    return (
        f'<div class="row"><span class="pill {tone}">{_e(state)}</span> '
        f'<code>{_e(tool_id)}</code> &mdash; {_e(flat.get("title") or tool_id)} '
        f'(<code>{_e(flat.get("category", ""))}</code>)</div>'
    )


def _pending_payload_summary(item: PendingAction, store: ConfigStore | None = None) -> str:
    """A short, human-scannable rendering of what was proposed -- the full
    payload is available in the audit log; here it only needs to be enough
    for a reviewer to judge whether to approve.
    """
    if item.action in ("tool_enable", "tool_disable", "tool_delete"):
        tool_id = item.payload.get("id", "")
        return _resolved_tool_badge(store, tool_id)
    if item.action in ("tool_create", "tool_update"):
        target = item.payload.get("replaces") or item.payload.get("spec", {}).get("id", "")
        spec = item.payload.get("spec") or {}
        return (
            f"tool <code>{_e(target)}</code> &rarr; "
            f"category <code>{_e(spec.get('category', ''))}</code>, "
            f"enabled=<code>{_e(spec.get('enabled', False))}</code>"
        )
    if item.action == "grant_set":
        tools = item.payload.get("tools") or []
        header = f'identity <code>{_e(item.payload.get("identity_id", ""))}</code> &rarr; {len(tools)} tool grant(s)'
        if not tools:
            return header
        return header + "".join(_resolved_tool_badge(store, t) for t in sorted(tools))
    if item.action == "role_set":
        identity_id = item.payload.get("identity_id", "")
        new_role = item.payload.get("role", "")
        current = store.identities.identities.get(identity_id) if store is not None else None
        current_role = current.role if current is not None else None
        arrow = (
            f'<code>{_e(current_role)}</code> &rarr; <code>{_e(new_role)}</code>'
            if current_role is not None and current_role != new_role
            else f'<code>{_e(new_role)}</code>'
        )
        return f'identity <code>{_e(identity_id)}</code> &rarr; role {arrow}'
    return _e(json.dumps(item.payload, default=str))


#: Statuses that need no further action -- tucked into a collapsed archive
#: on /ui/requests instead of piling up forever in the live queue.
_PENDING_ARCHIVE_STATUSES = {"approved", "rejected", "stale"}
_TOOLKIT_ARCHIVE_STATUSES = {"deployed", "rejected"}


def _decided_row(item: Any) -> str:
    """The "who decided this, when, and why" row -- identical shape for a
    `PendingAction` and a `ToolkitProposal` (both carry `decided_by`/
    `decided_at`/`reason`), so one function covers both archives.
    """
    if item.status == "pending":
        return ""
    detail = (
        f'{_e(item.decided_by or "")} &middot; {_e(item.decided_at or "")}'
        + (f" &mdash; {_e(item.reason)}" if item.reason else "")
    )
    return (
        f'<div class="row"><div class="row-l">Decision</div>'
        f'<div class="row-l">{_icon("users", 12)}{detail}</div></div>'
    )


def _stale_row(item: PendingAction) -> str:
    """Explains a `stale` item in place, instead of leaving a reviewer to
    piece it together from a bare exception (the error this is meant to
    fix: "Pending action ... is stale" used to be all a caller ever saw).
    """
    if item.status != "stale":
        return ""
    return (
        '<div class="row"><div class="row-l">Why</div>'
        "<div>The configuration this referred to changed after it was "
        "proposed &mdash; ask Hermes to re-propose from the current "
        "state.</div></div>"
    )


def _pending_card(
    session: Session, item: PendingAction, store: ConfigStore | None, *, can_decide: bool
) -> str:
    tone = _PENDING_TONE.get(item.status, "")
    ops = ""
    if item.status == "pending" and can_decide:
        ops = (
            _post_button(
                f"{UI_PREFIX}/pending/approve", "Approve", "check", session,
                css="ghost", fields={"id": item.id},
            )
            + f'<a class="btn" href="{UI_PREFIX}/pending/reject?id={_e(item.id)}">'
            f'{_icon("ban", 14)}Reject</a>'
        )
    meta = f'{_icon("users", 12)}{_e(item.actor)} &middot; {_e(item.created_at)}'
    detail_rows = (
        f'<div class="row"><div class="row-l">{_icon("sliders", 14)}Change</div>'
        f"<div>{_pending_payload_summary(item, store)}</div></div>"
        + _stale_row(item)
        + _decided_row(item)
    )
    return (
        '<details class="card"><summary class="card-head">'
        f'<span class="name mono">{_e(item.action)}</span>'
        f'<span class="pill {tone}">{_e(item.status)}</span>'
        f'<span class="row-l muted">{meta}</span>'
        f'<span class="spacer"></span>{ops}'
        f'<span class="chev">{_icon("chevron", 14)}</span>'
        "</summary>"
        f'<div class="rows">{detail_rows}</div>'
        "</details>"
    )


def _archive_details(label: str, rows_html: str, count: int) -> str:
    """One collapsed `<details>` trailing a live list -- resolved items
    (approved/rejected/stale, or deployed/rejected for toolkits) stay
    reachable but out of the way, instead of piling up in the queue
    forever alongside what still needs a decision.
    """
    return (
        '<details class="card"><summary class="card-head">'
        f'<span class="name">{_e(label)} ({count})</span>'
        f'<span class="spacer"></span><span class="chev">{_icon("chevron", 14)}</span>'
        "</summary>"
        f'<div class="pad">{rows_html}</div>'
        "</details>"
    )


def _change_tab(session: Session, store: ConfigStore | None, pending: PendingStore | None) -> str:
    if pending is None:
        return _note(
            "<strong>No pending queue configured.</strong> This deployment "
            "runs without a writable console (or /admin/mcp is disabled), "
            "so there is nothing an agent could have proposed.",
            tone="bad",
        )
    items = pending.list()
    if not items:
        return _note(
            "No proposals yet. This fills up when an admin-role agent on "
            "/admin/mcp calls a tool that expands what it can do -- "
            "enabling/updating a write tool, deleting a tool, setting a "
            "grant, or changing a role.",
            icon="share",
        )
    can_decide = session.can_write and store is not None
    live = [i for i in items if i.status not in _PENDING_ARCHIVE_STATUSES]
    archived = [i for i in items if i.status in _PENDING_ARCHIVE_STATUSES]
    parts = [
        _note(
            "Only a human can approve or reject a proposal here -- there is "
            "no path from /admin/mcp that reaches this decision (FR-2.8).",
            icon="share",
        )
    ]
    parts.append(
        "".join(_pending_card(session, i, store, can_decide=can_decide) for i in reversed(live))
        or '<p class="muted">Nothing pending.</p>'
    )
    if archived:
        parts.append(
            _archive_details(
                "Archive",
                "".join(_pending_card(session, i, store, can_decide=False) for i in reversed(archived)),
                len(archived),
            )
        )
    return "".join(parts)


def _pending_reject_confirm(session: Session, item: PendingAction) -> str:
    return (
        '<div class="editor card"><div class="pad">'
        f"<p><strong>Reject proposal {_e(item.id)}?</strong></p>"
        f"<p class='muted'>{_e(item.action)} proposed by {_e(item.actor)}. "
        "This leaves the current configuration unchanged.</p>"
        f'<form method="post" action="{UI_PREFIX}/pending/reject">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'<input type="hidden" name="id" value="{_e(item.id)}">'
        '<div class="field"><span>Reason (optional)</span>'
        '<input name="reason" maxlength="240"></div>'
        f'<button class="solid-danger" type="submit">{_icon("ban", 14)}Reject</button> '
        f'<a class="btn" href="{UI_PREFIX}/requests?tab=change">{_icon("back", 14)}Cancel</a>'
        "</form></div></div>"
    )


#: Rendering tone for each toolkit-proposal status -- mirrors _PENDING_TONE.
_TOOLKIT_PROPOSAL_TONE = {
    "pending": "warn",
    "deployed": "ok",
    "rejected": "",
}


def _toolkit_proposal_card(
    session: Session, item: ToolkitProposal, *, can_decide: bool
) -> str:
    tone = _TOOLKIT_PROPOSAL_TONE.get(item.status, "")
    ops = ""
    if item.status == "pending" and can_decide:
        ops = (
            f'<a class="btn solid-danger" href="{UI_PREFIX}/toolkits/deploy?id={_e(item.id)}">'
            f'{_icon("alert", 14)}Approve &amp; Deploy</a> '
            f'<a class="btn" href="{UI_PREFIX}/toolkits/reject?id={_e(item.id)}">'
            f'{_icon("ban", 14)}Reject</a>'
        )
    meta = f'{_icon("users", 12)}{_e(item.actor)} &middot; {_e(item.created_at)}'
    spec_yaml = yaml.safe_dump({item.name: item.spec}, sort_keys=False, allow_unicode=True)
    detail_rows = (
        f'<div class="row"><div class="row-l">{_icon("sliders", 14)}Proposed toolkit</div>'
        f'<div><pre class="mono">{_e(spec_yaml)}</pre></div></div>'
        + _decided_row(item)
    )
    return (
        '<details class="card"><summary class="card-head">'
        f'<span class="name mono">{_e(item.name)}</span>'
        f'<span class="pill {tone}">{_e(item.status)}</span>'
        f'<span class="row-l muted">{meta}</span>'
        f'<span class="spacer"></span>{ops}'
        f'<span class="chev">{_icon("chevron", 14)}</span>'
        "</summary>"
        f'<div class="rows">{detail_rows}</div>'
        "</details>"
    )


def _toolkit_tab(
    session: Session,
    service: Service,
    store: ConfigStore | None,
    toolkit_proposals: ToolkitProposalStore | None,
) -> str:
    """Proposals for a brand-new Tier 1 toolkit that Hermes has drafted via
    `admin.toolkit_propose` -- review/Approve & Deploy/Reject. Live
    toolkits themselves aren't shown here -- they're already visible,
    grouped by toolkit, on the Tools page.

    Unlike the Change tab, a proposal here changes Tier 1 -- what is
    possible at all, not just who can do what -- so the confirmation on
    Approve & Deploy (`_toolkit_deploy_confirm`) is deliberately heavier
    than the Change tab's single click.
    """
    parts = [
        _note(
            "Adding a toolkit normally needs a redeploy (Tier 1 is "
            "immutable at runtime) -- a proposal below is the one way "
            "around that, and only a human can make it take effect. Live "
            "toolkits are on the <a href=\""
            + UI_PREFIX + "/tools\">Tools page</a>.",
            icon="lock",
        )
    ]

    if toolkit_proposals is None:
        parts.append(
            _note(
                "<strong>No toolkit-proposal queue configured.</strong> This "
                "deployment runs without a writable console (or /admin/mcp "
                "is disabled), so there is nothing an agent could have "
                "proposed.",
                tone="bad",
            )
        )
        return "".join(parts)

    items = toolkit_proposals.list()
    if not items:
        parts.append(
            _note(
                "No proposals yet. This fills up when an admin-role agent "
                "on /admin/mcp calls admin.toolkit_propose -- e.g. Hermes "
                "hitting an 'Unknown toolkit' wall and drafting the fix "
                "itself instead of a human hand-editing toolkits.yaml.",
                icon="share",
            )
        )
        return "".join(parts)

    can_decide = session.can_write and store is not None
    live = [i for i in items if i.status not in _TOOLKIT_ARCHIVE_STATUSES]
    archived = [i for i in items if i.status in _TOOLKIT_ARCHIVE_STATUSES]
    parts.append(
        "".join(_toolkit_proposal_card(session, i, can_decide=can_decide) for i in reversed(live))
        or '<p class="muted">Nothing pending.</p>'
    )
    if archived:
        parts.append(
            _archive_details(
                "Archive",
                "".join(_toolkit_proposal_card(session, i, can_decide=False) for i in reversed(archived)),
                len(archived),
            )
        )
    return "".join(parts)


def _request_pending_counts(
    pending: PendingStore | None, toolkit_proposals: ToolkitProposalStore | None
) -> tuple[int, int]:
    change_n = sum(1 for i in pending.list() if i.status == "pending") if pending is not None else 0
    toolkit_n = (
        sum(1 for i in toolkit_proposals.list() if i.status == "pending")
        if toolkit_proposals is not None else 0
    )
    return change_n, toolkit_n


def _view_requests(
    request: Request,
    session: Session,
    service: Service,
    store: ConfigStore | None,
    pending: PendingStore | None,
    toolkit_proposals: ToolkitProposalStore | None,
) -> str:
    """Both proposal queues in one place, as two tabs sharing one layout --
    "Change" (tool/grant/role proposals, formerly /ui/pending) and
    "Toolkit" (Tier 1 proposals, formerly /ui/toolkits). Splitting them
    across two unrelated-looking pages was the original complaint: same
    review workflow, same card shape, no reason for two menu entries.
    """
    tab = request.query_params.get("tab", "change")
    if tab not in ("change", "toolkit"):
        tab = "change"
    change_n, toolkit_n = _request_pending_counts(pending, toolkit_proposals)
    tabs = (
        '<div class="req-tabs">'
        f'<a class="req-tab{" active" if tab == "change" else ""}" '
        f'href="{UI_PREFIX}/requests?tab=change">{_icon("share", 14)}Change'
        + (f'<span class="pill warn">{change_n}</span>' if change_n else "")
        + "</a>"
        f'<a class="req-tab{" active" if tab == "toolkit" else ""}" '
        f'href="{UI_PREFIX}/requests?tab=toolkit">{_icon("layers", 14)}Toolkit'
        + (f'<span class="pill warn">{toolkit_n}</span>' if toolkit_n else "")
        + "</a></div>"
    )
    if change_n or toolkit_n:
        banner_text = (
            f"<strong>{change_n}</strong> change{'s' if change_n != 1 else ''} and "
            f"<strong>{toolkit_n}</strong> toolkit{'s' if toolkit_n != 1 else ''} "
            "awaiting review, across both tabs."
        )
    else:
        banner_text = "Nothing awaiting review right now."
    banner = _note(banner_text, icon="share")
    body = (
        _change_tab(session, store, pending) if tab == "change"
        else _toolkit_tab(session, service, store, toolkit_proposals)
    )
    return tabs + banner + body


def _toolkit_deploy_confirm(session: Session, item: ToolkitProposal) -> str:
    """Deliberately heavier than `_pending_reject_confirm`/the Change tab's
    Approve: this is a Tier 1 change, not a Tier 2 one -- it widens what is
    *possible* at all on this deployment, not just who can do what, and it
    takes effect immediately, with no further review after this click.
    """
    spec_yaml = yaml.safe_dump({item.name: item.spec}, sort_keys=False, allow_unicode=True)
    return (
        _note(
            "<strong>This changes Tier 1.</strong> Tier 1 is the reason the "
            "admin token is not equivalent to root: nothing in it normally "
            "takes effect without a human editing toolkits.yaml and "
            "redeploying. Approving this writes the toolkit below into "
            "toolkits.yaml <em>and reloads it into this running process "
            "immediately</em> -- every binary, path root, and destination "
            "it lists becomes reachable the moment you click, with no "
            "further review afterwards.",
            tone="bad", icon="alert",
        )
        + '<div class="editor card"><div class="pad">'
        f"<p><strong>Approve &amp; deploy toolkit {_e(item.name)}?</strong></p>"
        f"<p class='muted'>Proposed by {_e(item.actor)} at {_e(item.created_at)}.</p>"
        f'<pre class="mono">{_e(spec_yaml)}</pre>'
        f'<form method="post" action="{UI_PREFIX}/toolkits/deploy">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'<input type="hidden" name="id" value="{_e(item.id)}">'
        '<div class="field"><label>'
        '<input type="checkbox" name="confirm" value="yes" required> '
        "I understand this immediately expands what this deployment can "
        "reach, with no further review.</label></div>"
        f'<button class="solid-danger" type="submit">{_icon("alert", 14)}Approve &amp; Deploy</button> '
        f'<a class="btn" href="{UI_PREFIX}/requests?tab=toolkit">{_icon("back", 14)}Cancel</a>'
        "</form></div></div>"
    )


def _toolkit_reject_confirm(session: Session, item: ToolkitProposal) -> str:
    return (
        '<div class="editor card"><div class="pad">'
        f"<p><strong>Reject toolkit proposal {_e(item.name)}?</strong></p>"
        f"<p class='muted'>Proposed by {_e(item.actor)}. This leaves "
        "toolkits.yaml unchanged.</p>"
        f'<form method="post" action="{UI_PREFIX}/toolkits/reject">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'<input type="hidden" name="id" value="{_e(item.id)}">'
        '<div class="field"><span>Reason (optional)</span>'
        '<input name="reason" maxlength="240"></div>'
        f'<button class="solid-danger" type="submit">{_icon("ban", 14)}Reject</button> '
        f'<a class="btn" href="{UI_PREFIX}/requests?tab=toolkit">{_icon("back", 14)}Cancel</a>'
        "</form></div></div>"
    )


_OUTCOMES = ("", "ok", "denied", "failed", "unknown")


def _view_audit(service: Service, request: Request) -> str:
    q = request.query_params
    f_identity = q.get("identity", "")
    f_tool = q.get("tool", "")
    f_outcome = q.get("outcome", "")

    path = os.path.join(service.tier1.audit_dir, "audit.jsonl")
    records, truncated = read_audit(path, identity=f_identity, tool=f_tool, outcome=f_outcome)

    options = "".join(
        f'<option value="{_e(o)}"{" selected" if o == f_outcome else ""}>'
        f'{_e(o or "all")}</option>'
        for o in _OUTCOMES
    )
    form = (
        f'<form class="filter" method="get" action="{UI_PREFIX}/audit">'
        f'<label><span>Identity</span><input name="identity" value="{_e(f_identity)}"></label>'
        f'<label><span>Tool</span><input name="tool" value="{_e(f_tool)}"></label>'
        f'<label><span>Outcome</span><select name="outcome">{options}</select></label>'
        f'<button type="submit">{_icon("search", 14)}Filter</button>'
        f'<a class="reset" href="{UI_PREFIX}/audit">reset</a>'
        "</form>"
    )
    note = (
        _note(
            "<strong>Only the most recent entries of the current log file.</strong> "
            "Older material sits in the rotated files and is not visible here "
            "&ndash; a missing entry is no proof that it never happened."
        )
        if truncated
        else ""
    )

    rows = []
    for record in records:
        kind = record.get("kind", "")
        outcome = record.get("outcome") or ""
        bits = []
        if kind in ("admin_change", "admin_note"):
            verb = _ADMIN_VERBS.get(record.get("action", ""), record.get("action", ""))
            bits.append(f'<span class="pill accent">{_e(verb)}</span>')
            for key in ("role", "tools", "scopes", "identities", "previous_id"):
                if record.get(key):
                    bits.append(
                        f'<span class="muted">{_e(key)}=</span>'
                        f'<code>{_e(json.dumps(record[key], ensure_ascii=False))}</code>'
                    )
            outcome = outcome or "ok"
        if record.get("denial_reason"):
            bits.append(f'<span class="pill deny">{_e(record["denial_reason"])}</span>')
        if record.get("detail"):
            bits.append(f'<span class="muted">{_e(record["detail"])}</span>')
        if record.get("parameters"):
            # Agent data. json.dumps turns it into a string, _e makes it
            # harmless -- in that order.
            bits.append(
                f"<code>{_e(json.dumps(record['parameters'], ensure_ascii=False))}</code>"
            )
        exit_code = record.get("exit_code")
        duration = record.get("duration_ms")
        ts = str(record.get("ts") or "")
        date, _, clock = ts.partition("T")
        who = record.get("identity") or record.get("actor") or record.get("reason") or "-"
        rows.append(
            f'<tr class="{_TONE.get(outcome, "")}">'
            f"<td class='mono'><div>{_e(clock[:8] or ts)}</div>"
            f"<div class='muted'>{_e(date)}</div></td>"
            f'<td><span class="pill">{_e(kind)}</span></td>'
            f"<td class='mono'>{_e(who)}</td>"
            f"<td class='mono'>{_e(record.get('tool') or record.get('target') or '-')}</td>"
            + (
                f'<td><span class="pill {_PILL_TONE.get(outcome, "")}">{_e(outcome)}</span></td>'
                if outcome
                else "<td class='muted'>&ndash;</td>"
            )
            + f"<td class='mono'>{_e(exit_code) if exit_code is not None else '&ndash;'}</td>"
            f"<td class='mono muted'>{_e(duration) if duration is not None else '&ndash;'}</td>"
            f'<td><div class="pills">{"".join(bits) or "&ndash;"}</div></td></tr>'
        )

    body = "".join(rows) or '<tr><td colspan="8" class="muted">No entries.</td></tr>'
    return (
        form
        + note
        + '<div class="card wrap"><table><thead><tr>'
        "<th>Time</th><th>Kind</th><th>Who</th><th>Target</th><th>Outcome</th>"
        "<th>Exit</th><th>ms</th><th>Details</th>"
        f"</tr></thead><tbody>{body}</tbody></table></div>"
    )


# -- Views: write ------------------------------------------------------

def _tool_scaffold(service: Service) -> str:
    """Scaffold for a new definition, built from the real Tier 1.

    This used to contain a finished Docker tool with foreign paths. That was
    doubly wrong: it looked like an integration, and on a system
    without this toolkit it could not even be saved. The scaffold now
    takes the first configured toolkit and its actual values -- it
    is thus a valid starting point on every deployment.
    """
    name, toolkit = next(iter(sorted(service.tier1.toolkits.items())))
    binary = toolkit.binaries[0]
    lines = [
        f"id: {name}.CHANGEME",
        f"toolkit: {name}",
        f"binary: {binary}",
        "version: 1",
        "title: CHANGEME",
        "description: What this does, in one sentence for the agent.",
        "category: read            # read | write | write_external",
        "idempotent: true",
        "enabled: true",
        "",
        "# Every element becomes exactly one argument. A parameter value can",
        "# never produce a second one (FR-5.4).",
        'argv: ["--help"]',
        "",
        "# Every string parameter needs a pattern -- unvalidated free text is",
        "# not permitted (FR-5.7). Paths are derived by the server, never",
        "# supplied by the agent.",
        "parameters: {}",
        "",
        "required_scopes: []",
        f"timeout_seconds: {min(30, toolkit.max_timeout_seconds)}",
        f"max_output_bytes: {min(65536, toolkit.max_output_bytes)}",
    ]
    if toolkit.path_roots:
        lines.insert(
            -3,
            "# This toolkit allows derived paths under: "
            + ", ".join(toolkit.path_roots),
        )
    return "\n".join(lines) + "\n"


def _no_toolkits_note() -> str:
    """What to do when Tier 1 is empty.

    The state after `init`. It needs explanation, because it cannot
    be fixed here -- and that is not a gap, but the core of the
    design: what should be possible is decided by the deploy, not the
    running console.
    """
    return _note(
        "<strong>No toolkits configured.</strong> A tool always binds to a "
        "toolkit from Tier 1, and Tier 1 is empty &ndash; the state right "
        "after <code>gatekeeper init</code>. Nothing can be executed yet."
        "<p>This cannot be fixed here, and deliberately so: a toolkit grants "
        "access to real binaries on the host, so it is a deploy-time decision "
        "(FR-4.11). Edit <code>toolkits.yaml</code> and redeploy. There is a "
        "worked example in <code>config/examples/toolkits.yaml</code>.</p>",
        icon="lock",
    )


def _tier1_reference(service: Service) -> str:
    """The boundaries next to the editor -- not as decoration.

    Anyone writing a tool needs to know which binaries are allowed and which
    arguments are blocked. If this is not shown alongside, the editor becomes
    guesswork with an error message.
    """
    cards = []
    for name, tk in sorted(service.tier1.toolkits.items()):
        cards.append(
            '<div class="card">'
            f'<div class="card-head"><span class="name mono">{_e(name)}</span>'
            f'<span class="pill accent">{_e(tk.executor)}</span></div>'
            '<div class="rows">'
            f'<div class="row"><div class="row-l">Binaries</div><div>{_pills(tk.binaries)}</div></div>'
            f'<div class="row"><div class="row-l">Denied arguments</div>'
            f"<div>{_pills(tk.denied_args, tone='deny')}</div></div>"
            f'<div class="row"><div class="row-l">Path roots</div><div>{_pills(tk.path_roots)}</div></div>'
            f'<div class="row"><div class="row-l">Ceilings</div>'
            # A literal character, not an entity: everything in _pills goes
            # through _e(), which would escape the ampersand and print the
            # entity itself.
            f'<div>{_pills([f"timeout ≤ {tk.max_timeout_seconds}s", f"output ≤ {tk.max_output_bytes} B"])}</div>'
            "</div></div></div>"
        )
    return "".join(cards)


def _integration_logo(integration: Integration, *, large: bool = False) -> str:
    """Renders an integration's inline-SVG brand mark.

    Deliberately its own helper, not folded into `_icon()`/`_ICONS`: those
    are generic Lucide-style UI chrome (nav, buttons) shared across every
    page, whereas an integration logo is per-service and lives in `integrations.py`,
    not this module. Conflating the two dicts would make an unrelated icon
    edit risk breaking every integration card.

    Sizing is a named class (`.integration-logo`/`.integration-logo-lg`), not an
    inline `style="width:...px"` -- the CSP's `style-src 'nonce-...'` does
    not cover inline style attributes, so one silently does nothing
    instead of erroring (see the `.caption` comment in `_STYLE`). The
    fetched brand SVGs also carry no width/height of their own (only a
    `viewBox`), unlike the old monogram fallback, so without a sized CSS
    class every logo would render at the browser's default replaced-
    element size -- large and inconsistent, exactly the bug this class
    exists to avoid.
    """
    cls = "integration-logo integration-logo-lg" if large else "integration-logo"
    return f'<span class="{cls}">{integration.logo_svg}</span>'


def _view_integrations(service: Service, session: Session, store: ConfigStore | None) -> str:
    configured = set(service.tier1.toolkits)
    cards = []
    for integration in sorted(INTEGRATIONS.values(), key=lambda p: p.display_name):
        has_toolkit = integration.key in configured
        if has_toolkit and session.can_write and store is not None:
            action = (
                f'<a class="btn primary" '
                f'href="{UI_PREFIX}/tools/integrations/pick?key={_e(integration.key)}">'
                f'{_icon("plus", 14)}Create a tool</a>'
            )
        else:
            action = (
                f'<a class="btn" href="{UI_PREFIX}/toolkits/reference#{_e(integration.key)}">'
                f'{_icon("lock", 14)}'
                + ("View starter tools" if has_toolkit else "Add this toolkit first")
                + "</a>"
            )
        cards.append(
            '<div class="card"><div class="pad integration-card">'
            f'<div class="integration-card-head">{_integration_logo(integration)}'
            f'<span class="name">{_e(integration.display_name)}</span>'
            + (
                '<span class="pill ok">toolkit configured</span>'
                if has_toolkit
                else '<span class="pill">toolkit not configured</span>'
            )
            + "</div>"
            + (f'<p class="muted">{_e(integration.notes)}</p>' if integration.notes else "")
            + f'<div class="integration-card-foot">{action}</div>'
            "</div></div>"
        )
    return (
        _note(
            "Picking an integration only pre-fills the tool editor -- it goes "
            "through the exact same Tier 1 validation as hand-written YAML "
            "(FR-4.6). The toolkit itself always stays a manual, deploy-time "
            "edit (FR-4.11); use the reference page for its YAML.",
            icon="package",
        )
        + f'<div class="integration-grid">{"".join(cards)}</div>'
    )


def _view_integration_picker(integration: Integration, service: Service, session: Session) -> str:
    rows = []
    for spec in integration.tool_specs:
        exists = service.catalog.raw_of(spec["id"]) is not None
        action = (
            '<span class="pill">already defined</span>'
            if exists
            else (
                f'<a class="btn primary" href="{UI_PREFIX}/tools/integrations/new'
                f'?key={_e(integration.key)}&tool={_e(spec["id"])}">'
                f'{_icon("plus", 14)}Use this</a>'
            )
        )
        rows.append(
            '<div class="card"><div class="card-head">'
            f'<span class="name mono">{_e(spec["id"])}</span>'
            f'<span class="pill {"accent" if spec.get("category") == "write_external" else ""}">'
            f'{_e(spec.get("category", ""))}</span>'
            f'<span class="spacer"></span>{action}</div>'
            f'<div class="pad"><p class="muted">{_e(spec.get("description", ""))}</p></div>'
            "</div>"
        )
    return (
        f'<div class="integration-card-head">{_integration_logo(integration, large=True)}'
        f'<span class="name">{_e(integration.display_name)}</span></div>'
        + (f'<p class="muted">{_e(integration.notes)}</p>' if integration.notes else "")
        + "".join(rows)
        + f'<p><a class="btn" href="{UI_PREFIX}/tools/integrations">'
        f'{_icon("back", 14)}Back to integrations</a></p>'
    )


def _view_toolkit_reference() -> str:
    sections = []
    for integration in sorted(INTEGRATIONS.values(), key=lambda p: p.display_name):
        sections.append(
            f'<div class="card" id="{_e(integration.key)}"><div class="card-head">'
            f'{_integration_logo(integration)}<span class="name">{_e(integration.display_name)}</span></div>'
            '<div class="pad">'
            + (f'<p class="muted">{_e(integration.notes)}</p>' if integration.notes else "")
            + "<p>Paste this block under <code>toolkits:</code> in "
            "<code>toolkits.yaml</code>, fill in the CHANGEME placeholders "
            "for your host and address range, then redeploy (FR-4.11) -- "
            "this page cannot write the file for you.</p>"
            f'<pre class="mono">{_e(integration.toolkit_yaml)}</pre>'
            "</div></div>"
        )
    return (
        _note(
            "Toolkit creation is a deploy-time decision and stays one "
            "(FR-4.11) &ndash; this page only saves you writing the YAML "
            "block from scratch. Once a toolkit exists here, its integrations "
            "become actionable on the Integrations page.",
            icon="lock",
        )
        + "".join(sections)
    )


def _tool_editor(
    service: Service, session: Session, *, yaml_text: str, rev: str,
    replaces: str | None, error: str = "",
) -> str:
    target = f"{UI_PREFIX}/tools/edit" if replaces else f"{UI_PREFIX}/tools/new"
    return (
        (_note(f"<strong>Rejected.</strong> {_e(error)}", tone="bad") if error else "")
        + '<div class="split"><div class="editor">'
        '<div class="card"><div class="pad">'
        f'<form method="post" action="{target}">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'<input type="hidden" name="rev" value="{_e(rev)}">'
        + (f'<input type="hidden" name="replaces" value="{_e(replaces)}">' if replaces else "")
        + '<div class="field"><span>Definition (YAML)'
        '<div class="hint">Validated against Tier 1 before anything is written. '
        "A definition that exceeds the boundaries is refused, not clamped.</div></span>"
        f'<textarea name="yaml" spellcheck="false">{_e(yaml_text)}</textarea></div>'
        f'<button type="submit">{_icon("save", 14)}Save</button> '
        f'<a class="btn" href="{UI_PREFIX}/tools">{_icon("back", 14)}Cancel</a>'
        "</form></div></div></div>"
        f'<div><h2>{_icon("lock", 14)}Tier 1 boundaries</h2>{_tier1_reference(service)}</div>'
        "</div>"
    )


def _account_page(
    session: Session, *, rev: str, error: str = "", done: bool = False
) -> str:
    """Self-service: change your own console password.

    A `viewer` also gets in here, even though they may write
    nothing else. This is not a hole in the role separation: what is changed
    is exclusively their own password, and an access whose password can
    only be changed by someone else will never be changed.
    """
    return (
        (_note(f"<strong>Rejected.</strong> {_e(error)}", tone="bad") if error else "")
        + (
            _note(
                "<strong>Password changed.</strong> Other sessions of this "
                "identity have been signed out.",
                icon="check",
                tone="good",
            )
            if done
            else ""
        )
        + '<div class="editor card">'
        f'<div class="card-head"><span class="name mono">{_e(session.identity)}</span>'
        f'<span class="pill accent">{_icon("key", 12)}{_e(session.role)}</span></div>'
        '<div class="pad">'
        f'<form method="post" action="{UI_PREFIX}/account/password">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'<input type="hidden" name="rev" value="{_e(rev)}">'
        '<div class="field"><span>Current password</span>'
        '<input type="password" name="current" autocomplete="current-password" '
        "required></div>"
        '<div class="field"><span>New password'
        f'<div class="hint">At least {MIN_PASSWORD_LENGTH} characters.</div></span>'
        '<input type="password" name="password" autocomplete="new-password" '
        "required></div>"
        '<div class="field"><span>Repeat the new password</span>'
        '<input type="password" name="confirm" autocomplete="new-password" '
        "required></div>"
        f'<button type="submit">{_icon("save", 14)}Change password</button> '
        f'<a class="btn" href="{UI_PREFIX}/">{_icon("back", 14)}Back</a>'
        "</form></div></div>"
        + _note(
            "<strong>This password is not your API token.</strong> It opens "
            "this console and nothing else; the token opens <code>/mcp</code> "
            "and not this console. Changing one leaves the other untouched "
            "&ndash; an administrator issues a new token on the identities "
            "page.",
            icon="key",
        )
    )


def _identity_editor(
    service: Service, session: Session, *, values: dict[str, Any], rev: str,
    replaces: str | None, error: str = "",
) -> str:
    target = f"{UI_PREFIX}/identities/edit" if replaces else f"{UI_PREFIX}/identities/new"
    granted = set(values.get("tools") or ())
    checks = "".join(
        f'<label><input type="checkbox" name="tools" value="{_e(tid)}"'
        f'{" checked" if tid in granted else ""}>'
        f'<span class="mono">{_e(tid)}</span></label>'
        for tid in sorted(service.catalog.tools)
    ) or '<span class="muted">No tools in the catalog yet.</span>'
    roles = "".join(
        f'<option value="{_e(r)}"{" selected" if r == values.get("role") else ""}>{_e(r)}</option>'
        for r in ROLES
    )
    return (
        (_note(f"<strong>Rejected.</strong> {_e(error)}", tone="bad") if error else "")
        + '<div class="editor card"><div class="pad">'
        f'<form method="post" action="{target}">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'<input type="hidden" name="rev" value="{_e(rev)}">'
        + (f'<input type="hidden" name="replaces" value="{_e(replaces)}">' if replaces else "")
        + '<div class="field"><span>Identity ID</span>'
        f'<input name="id" value="{_e(values.get("id", ""))}" required></div>'
        '<div class="field"><span>Role'
        '<div class="hint">agent = MCP access only. viewer = read the console. '
        "admin = read and change everything on this page.</div></span>"
        f'<select name="role">{roles}</select></div>'
        '<div class="field"><span>Console password'
        f'<div class="hint">At least {MIN_PASSWORD_LENGTH} characters, and only '
        "for <code>viewer</code> and <code>admin</code> &ndash; an agent signs "
        "in nowhere. This is not the API token: the token authenticates "
        "<code>/mcp</code>, the password opens this console."
        + (
            " Leave empty to keep the current one.</div></span>"
            if replaces
            else "</div></span>"
        )
        + '<input type="password" name="password" autocomplete="new-password"></div>'
        '<div class="field"><span>Granted tools'
        '<div class="hint">Rights attach to individual tool IDs (FR-7.5). A tool '
        "added later is never granted automatically.</div></span>"
        f'<div class="checks">{checks}</div></div>'
        '<div class="field"><span>Scopes, one per line'
        '<div class="hint">Patterns such as <code>stack:media-*</code>. Empty means '
        "the identity can call no tool that requires a scope.</div></span>"
        f'<textarea name="scopes" rows="4" class="scopes-area" spellcheck="false">'
        f'{_e(chr(10).join(values.get("scopes") or ()))}</textarea></div>'
        + (
            ""
            if replaces
            else _note(
                "A token is generated on save and shown exactly once. It cannot "
                "be recovered afterwards &ndash; only replaced.",
                icon="key",
            )
        )
        + f'<button type="submit">{_icon("save", 14)}Save</button> '
        f'<a class="btn" href="{UI_PREFIX}/identities">{_icon("back", 14)}Cancel</a>'
        "</form></div></div>"
    )


def _credential_editor(session: Session, *, rev: str, error: str = "") -> str:
    kind_options = "".join(
        f'<option value="{_e(k)}">{_e(k)}</option>' for k in sorted(CREDENTIAL_KINDS)
    )
    return (
        (_note(f"<strong>Rejected.</strong> {_e(error)}", tone="bad") if error else "")
        + '<div class="editor card"><div class="pad">'
        f'<form method="post" action="{UI_PREFIX}/credentials/new">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'<input type="hidden" name="rev" value="{_e(rev)}">'
        '<div class="field"><span>Name'
        '<div class="hint">What a toolkit\'s <code>credential:</code> field in '
        "toolkits.yaml refers to -- e.g. <code>sonarr</code>.</div></span>"
        '<input name="name" required pattern="[a-z][a-z0-9_-]*"></div>'
        '<div class="field"><span>Kind'
        '<div class="hint">api_key_header/bearer/basic inject an HTTP header; '
        "url_query injects a query parameter instead (only for a service with "
        "no header option, e.g. SABnzbd -- FR-8.14 prefers a header wherever "
        "one exists); ws_api_key is used by the truenas executor's auth call; "
        "ssh_private_key is a PEM private key for the ssh executor; docker_tls "
        "is for a TLS-secured remote Docker destination (FR-8.3g).</div></span>"
        f'<select name="kind">{kind_options}</select></div>'
        '<div class="field"><span>Header/param name'
        '<div class="hint">Required for kind=api_key_header (the header name, '
        "e.g. <code>X-Api-Key</code>) and kind=url_query (the query "
        "parameter name, e.g. <code>apikey</code>). Ignored otherwise.</div></span>"
        '<input name="header"></div>'
        '<div class="field"><span>Value'
        '<div class="hint">Encrypted at rest, never shown again after this '
        "form (FR-10.2). For kind=docker_tls, a JSON object: "
        "<code>{&quot;cert&quot;: ..., &quot;key&quot;: ..., "
        "&quot;ca&quot;: ...}</code> (PEM text, ca optional).</div></span>"
        '<input type="password" name="value" autocomplete="new-password" required></div>'
        f'<button type="submit">{_icon("save", 14)}Create</button> '
        f'<a class="btn" href="{UI_PREFIX}/credentials">{_icon("back", 14)}Cancel</a>'
        "</form></div></div>"
    )


def _credential_rotate_editor(
    session: Session, *, name: str, rev: str, error: str = ""
) -> str:
    return (
        (_note(f"<strong>Rejected.</strong> {_e(error)}", tone="bad") if error else "")
        + '<div class="editor card"><div class="pad">'
        f'<form method="post" action="{UI_PREFIX}/credentials/rotate">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">'
        f'<input type="hidden" name="rev" value="{_e(rev)}">'
        f'<input type="hidden" name="name" value="{_e(name)}">'
        f'<p>Rotating <code>{_e(name)}</code>.</p>'
        '<div class="field"><span>New value</span>'
        '<input type="password" name="value" autocomplete="new-password" required></div>'
        '<div class="field"><span>Overlap window, seconds'
        '<div class="hint">The previous value keeps resolving for this many '
        "seconds after rotation (FR-10.5), so calls already in flight with the "
        "old key do not break. 0 replaces it immediately.</div></span>"
        '<input type="number" name="overlap_seconds" value="0" min="0"></div>'
        f'<button type="submit">{_icon("refresh", 14)}Rotate</button> '
        f'<a class="btn" href="{UI_PREFIX}/credentials">{_icon("back", 14)}Cancel</a>'
        "</form></div></div>"
    )


def _confirm(
    session: Session, *, question: str, detail: str, action: str,
    fields: dict[str, str], back: str,
) -> str:
    hidden = "".join(
        f'<input type="hidden" name="{_e(k)}" value="{_e(v)}">' for k, v in fields.items()
    )
    return (
        '<div class="editor card"><div class="pad">'
        f"<p><strong>{_e(question)}</strong></p><p class='muted'>{detail}</p>"
        f'<form method="post" action="{_e(action)}">'
        f'<input type="hidden" name="_csrf" value="{_e(session.csrf)}">{hidden}'
        f'<button class="solid-danger" type="submit">{_icon("trash", 14)}Delete</button> '
        f'<a class="btn" href="{_e(back)}">{_icon("back", 14)}Cancel</a>'
        "</form></div></div>"
    )


def _token_page(identity_id: str, token: str, back: str) -> str:
    return (
        _note(
            "<strong>Copy this token now.</strong> It is stored only as an scrypt "
            "hash and is never shown again. Losing it means issuing a new one.",
            icon="key",
            tone="good",
        )
        + '<div class="editor card"><div class="pad">'
        f'<p>API token for <code>{_e(identity_id)}</code>:</p>'
        f'<div class="secret mono">{_e(token)}</div>'
        "<p class='muted'>Goes into the agent's config as "
        "<code>Authorization: Bearer &lt;token&gt;</code>. It authenticates "
        "<code>/mcp</code> and does not sign in to this console &ndash; that "
        "is what the console password is for.</p>"
        f'<a class="btn primary" href="{_e(back)}">{_icon("check", 14)}Done</a>'
        "</div></div>"
    )


# -- Routen ----------------------------------------------------------------


def _login_page(nonce: str, error: str = "", identity: str = "") -> str:
    """Sign-in: ID and password, not the API token.

    The field used to be called `token`, and that was exactly the mistake: the same
    credential opened `/mcp` and the console, and it had to pass through a
    clipboard and a browser password store (FR-11.5). Anyone
    who types a token here can no longer get in -- the note below
    the form says so before someone tries three times.
    """
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=yes">'
        "<title>Sign in - gatekeeper</title>"
        f'<style nonce="{nonce}">{_STYLE}</style></head><body>'
        '<main class="login"><div class="card"><div class="pad">'
        f'<div class="mark">{_icon("shield", 24)}</div>'
        f'<h1>gatekeeper <a href="#release-notes" class="ver" '
        f'title="Release notes">v{_e(__version__)}</a></h1>'
        "<p>Operations console. Sign in with the console password of an "
        "identity with <code>role: viewer</code> or <code>role: admin</code>.</p>"
        f'<form method="post" action="{UI_PREFIX}/login">'
        f'<input name="identity" placeholder="Identity" value="{_e(identity)}" '
        'autocomplete="username" autocapitalize="none" spellcheck="false" autofocus>'
        '<input type="password" name="password" placeholder="Console password" '
        'autocomplete="current-password">'
        '<button type="submit">Sign in</button></form>'
        + (f'<p class="err">{_icon("alert", 15)}{_e(error)}</p>' if error else "")
        + '<p class="foot">'
        "An API token does not sign in here &ndash; it belongs in the "
        "<code>Authorization</code> header of an agent, never in a browser."
        "</p>"
        "</div></div></main>"
        + _release_notes_modal()
        + "</body></html>"
    )


#: ---------------------------------------------------------------------------
#: Docs page — full project documentation, readable in the console.
#: ---------------------------------------------------------------------------

_DOCS_DIR_CANDIDATES = (
    "/opt/gatekeeper-docs",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", ".."),
    "/opt/data/gatekeeper",
    ".",
)


def _read_doc_file(name: str) -> str:
    """Read a doc file from the repo root, best-effort.

    The source tree lives next to the package; in the container the docs
    are bundled at /opt/gatekeeper-docs by the Dockerfile.  Returns empty
    string if not found.
    """
    for base in _DOCS_DIR_CANDIDATES:
        candidate = os.path.join(base, name)
        try:
            with open(candidate, encoding="utf-8") as fh:
                return fh.read()
        except (OSError, FileNotFoundError):
            continue
    return ""


def _md_to_html(text: str) -> str:
    """Minimal Markdown → HTML converter.

    Handles the subset used by the gatekeeper docs: headings (h1-h4),
    paragraphs, unordered/ordered lists, fenced code blocks, inline code,
    bold, italic, blockquotes, tables, hr, and links.

    Everything is escaped first; only safe constructs produce live HTML.
    No raw HTML passthrough — no external dependency, CSP-clean.
    """
    import re

    esc = html.escape

    def inline(text: str) -> str:
        parts: list[str] = []
        counter = [0]

        def _code(m: re.Match) -> str:
            tag = f"\x00CODE{counter[0]}\x00"
            parts.append(f"<code>{esc(m.group(1))}</code>")
            counter[0] += 1
            return tag

        text = re.sub(r"`([^`]+)`", _code, text)
        text = esc(text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"(?<!\*)\*(?!\*)(.+?)\*(?!\*)", r"<em>\1</em>", text)

        def _link(m: re.Match) -> str:
            url = m.group(2)
            if url.startswith(("http://", "https://", "#", "/")):
                return f'<a href="{esc(url)}" rel="noopener">{esc(m.group(1))}</a>'
            return esc(m.group(0))

        text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link, text)
        for i, part in enumerate(parts):
            text = text.replace(f"\x00CODE{i}\x00", part)
        return text

    lines = text.split("\n")
    out: list[str] = []
    i = 0
    in_list: str | None = None
    in_blockquote = False
    in_code = False
    code_buf: list[str] = []
    table_buf: list[str] = []

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append(f"</{in_list}>")
            in_list = None

    def close_blockquote() -> None:
        nonlocal in_blockquote
        if in_blockquote:
            out.append("</blockquote>")
            in_blockquote = False

    def close_table() -> None:
        nonlocal table_buf
        if table_buf:
            rows = table_buf
            if len(rows) >= 2 and re.match(r"^\s*\|?[\s\-:|]+\|?\s*$", rows[1]):
                header = [c.strip() for c in rows[0].strip().strip("|").split("|")]
                body = rows[2:]
            else:
                header = None
                body = rows
            parts = ['<div class="wrap"><table>']
            if header:
                parts.append("<thead><tr>" + "".join(f"<th>{inline(h)}</th>" for h in header) + "</tr></thead>")
            parts.append("<tbody>")
            for row in body:
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                parts.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            parts.append("</tbody></table></div>")
            out.append("".join(parts))
            table_buf = []

    while i < len(lines):
        line = lines[i]

        if line.strip().startswith("```"):
            if in_code:
                out.append(f'<pre><code>{esc(chr(10).join(code_buf))}</code></pre>')
                code_buf = []
                in_code = False
            else:
                close_list()
                close_blockquote()
                close_table()
                in_code = True
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        if line.strip().startswith("|") and line.strip().endswith("|"):
            close_list()
            close_blockquote()
            table_buf.append(line)
            i += 1
            continue
        elif table_buf:
            close_table()

        if not line.strip():
            close_list()
            close_blockquote()
            i += 1
            continue

        m = re.match(r"^(#{1,4})\s+(.+)$", line)
        if m:
            close_list()
            close_blockquote()
            level = len(m.group(1))
            out.append(f"<h{level}>{inline(m.group(2))}</h{level}>")
            i += 1
            continue

        if re.match(r"^(-{3,}|\*{3,}|_{3,})\s*$", line):
            close_list()
            close_blockquote()
            out.append("<hr>")
            i += 1
            continue

        if line.strip().startswith(">"):
            close_list()
            content = re.sub(r"^\s*>\s?", "", line)
            if not in_blockquote:
                out.append("<blockquote>")
                in_blockquote = True
            out.append(f"<p>{inline(content)}</p>")
            i += 1
            continue
        elif in_blockquote:
            close_blockquote()

        m = re.match(r"^(\s*)[-*+]\s+(.+)$", line)
        if m:
            if in_list != "ul":
                close_list()
                out.append("<ul>")
                in_list = "ul"
            out.append(f"<li>{inline(m.group(2))}</li>")
            i += 1
            continue

        m = re.match(r"^(\s*)\d+\.\s+(.+)$", line)
        if m:
            if in_list != "ol":
                close_list()
                out.append("<ol>")
                in_list = "ol"
            out.append(f"<li>{inline(m.group(2))}</li>")
            i += 1
            continue

        close_list()
        para_lines = [line]
        while i + 1 < len(lines) and lines[i + 1].strip() and not re.match(
            r"^(#{1,4}\s|[-*+]\s|\d+\.\s|>|\|)",
            lines[i + 1].strip(),
        ) and not lines[i + 1].strip().startswith("```"):
            i += 1
            para_lines.append(lines[i])
        out.append(f"<p>{inline(' '.join(line.strip() for line in para_lines))}</p>")
        i += 1

    if in_code:
        out.append(f'<pre><code>{esc(chr(10).join(code_buf))}</code></pre>')
    close_list()
    close_blockquote()
    close_table()
    return "".join(out)


_DOC_FILES = (
    ("readme", "README", "README.md"),
    ("requirements", "Requirements", "REQUIREMENTS.md"),
    ("agents", "AGENTS", "AGENTS.md"),
    ("release", "Release Notes", "RELEASE.md"),
)


_STATS_WINDOWS = (("24h", "Last 24 hours", 24, 200), ("7d", "Last 7 days", 7, 1000), ("30d", "Last 30 days", 30, 2000))


def _activity_chart_by_day(
    records: list[dict[str, Any]], days: int = 7, *, now: datetime | None = None,
) -> str:
    """Day-bucketed stacked bar chart, same SVG style as ``_activity_chart``."""
    current = (now or datetime.now(UTC)).replace(
        hour=0, minute=0, second=0, microsecond=0,
    )
    buckets = _bucket_calls_by_day(records, days, now=current)
    peak = max((o + d for o, d in buckets), default=0)

    width, height, pad = 300.0, 78.0, 14.0
    slot_w = width / days
    bw = slot_w * 0.62
    bars = []
    for index, (ok, bad) in enumerate(buckets):
        x = index * slot_w + (slot_w - bw) / 2
        usable = height - pad - 6
        h_ok = usable * ok / peak if peak else 0
        h_bad = usable * bad / peak if peak else 0
        if h_bad > 0:
            bars.append(
                f'<rect class="c-deny" x="{x:.1f}" y="{height - pad - h_bad:.1f}" '
                f'width="{bw:.1f}" height="{h_bad:.1f}" rx="1.5"/>'
            )
        if h_ok > 0:
            bars.append(
                f'<rect class="c-ok" x="{x:.1f}" y="{height - pad - h_bad - h_ok:.1f}" '
                f'width="{bw:.1f}" height="{h_ok:.1f}" rx="1.5"/>'
            )
        if h_ok == 0 and h_bad == 0:
            bars.append(
                f'<rect class="c-base" x="{x:.1f}" y="{height - pad - 2:.1f}" '
                f'width="{bw:.1f}" height="2" rx="1"/>'
            )

    first = (current - timedelta(days=days - 1)).strftime("%b %d")
    if not peak:
        return (
            f'<svg class="chart" viewBox="0 0 {width:.0f} {height:.0f}" role="img" '
            f'aria-label="Calls per day (none in last {days}d)">'
            f'<text class="c-ax" x="{width / 2:.0f}" y="{height / 2:.0f}" '
            f'text-anchor="middle">No tool calls in the last {days} days</text>'
            f'<text class="c-ax" x="0" y="{height - 3:.0f}">{_e(first)}</text>'
            f'<text class="c-ax" x="{width:.0f}" y="{height - 3:.0f}" '
            f'text-anchor="end">{_e(current.strftime("%b %d"))}</text>'
            "</svg>"
        )
    return (
        f'<svg class="chart" viewBox="0 0 {width:.0f} {height:.0f}" role="img" '
        f'aria-label="Calls per day">{"".join(bars)}'
        f'<text class="c-ax" x="0" y="{height - 3:.0f}">{_e(first)}</text>'
        f'<text class="c-ax" x="{width:.0f}" y="{height - 3:.0f}" '
        f'text-anchor="end">{_e(current.strftime("%b %d"))}</text>'
        "</svg>"
    )


def _view_stats(service: Service, identities: IdentityStore, request: Request | None = None) -> str:
    """Aggregate statistics over the audit log."""
    window = request.query_params.get("window", "24h") if request else "24h"
    win_spec = next((w for w in _STATS_WINDOWS if w[0] == window), _STATS_WINDOWS[0])
    win_label, win_value, limit = win_spec[1], win_spec[2], win_spec[3]

    path = os.path.join(service.tier1.audit_dir, "audit.jsonl")
    records, truncated = read_audit(path, limit=limit)

    tools_by_kit: dict[str, set[str]] = {}
    for name in service.tier1.toolkits:
        tools_by_kit.setdefault(name, set())
    for tool in service.catalog.tools.values():
        tools_by_kit.setdefault(tool.toolkit, set()).add(tool.id)

    totals = _outcome_totals(records)
    call_stats = _call_stats(records)
    kit_stats = _tool_call_stats(records, tools_by_kit)
    admin_stats = _admin_action_stats(records)
    durations = _duration_stats(records, tools_by_kit)

    success_rate = int(totals["ok"] / totals["total"] * 100) if totals["total"] else 0
    active_idents = len(call_stats)
    active_kits = sum(1 for k, v in kit_stats.items() if v["total"] > 0 and k != "_unknown")
    admin_total = sum(admin_stats.values())

    tabs = "".join(
        f'<a href="{UI_PREFIX}/stats?window={_e(w[0])}"'
        f'{" class=\"active\"" if w[0] == window else ""}>'
        f"{_e(w[1])}</a>"
        for w in _STATS_WINDOWS
    )

    note = (
        _note(
            "<strong>Only the most recent entries of the current log file.</strong> "
            "Older material sits in the rotated files and is not visible here "
            "&ndash; the window is best-effort, not a complete view."
        )
        if truncated
        else ""
    )

    tiles = (
        '<div class="grid">'
        + _stat(totals["total"], "Total calls", "activity")
        + _stat(f"{success_rate}%", "Success rate", "check", "t-ok" if success_rate >= 80 else ("t-warn" if success_rate >= 50 else "t-deny"))
        + _stat(active_idents, "Active identities", "users")
        + _stat(active_kits, "Active toolkits", "layers")
        + _stat(admin_total, "Admin actions", "share")
        + "</div>"
    )

    if window == "24h":
        chart = _activity_chart(records, hours=24)
    else:
        chart = _activity_chart_by_day(records, days=win_value)

    kit_rows = "".join(
        f'<tr><td class="mono">{_e(kit)}</td>'
        f'<td class="mono">{v["total"]}</td>'
        f'<td class="mono">{v["ok"]}</td>'
        f'<td class="mono">{v["denied"]}</td>'
        f'<td class="mono">{v["failed"]}</td></tr>'
        for kit, v in sorted(kit_stats.items(), key=lambda kv: (-kv[1]["total"], kv[0]))
        if v["total"] > 0
    ) or '<tr><td colspan="5" class="muted">No calls.</td></tr>'

    ident_rows = "".join(
        f'<tr><td class="mono">{_e(ident)}</td>'
        f'<td class="mono">{v["total"]}</td>'
        f'<td class="mono">{v["ok"]}</td>'
        f'<td class="mono">{v["denied"]}</td>'
        f'<td class="mono">{v["failed"]}</td></tr>'
        for ident, v in sorted(call_stats.items(), key=lambda kv: (-kv[1]["total"], kv[0]))
    ) or '<tr><td colspan="5" class="muted">No calls.</td></tr>'

    admin_rows = "".join(
        f'<tr><td>{_e(label)}</td><td class="mono">{count}</td></tr>'
        for label, count in admin_stats.items()
    ) or '<tr><td colspan="2" class="muted">No admin changes.</td></tr>'

    dur_rows = "".join(
        f'<tr><td class="mono">{_e(kit)}</td>'
        f'<td class="mono">{int(v["avg"])} ms</td>'
        f'<td class="mono">{int(v["p95"])} ms</td>'
        f'<td class="mono">{int(v["count"])}</td></tr>'
        for kit, v in sorted(durations.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
        if v["count"] > 0
    ) or '<tr><td colspan="4" class="muted">No duration data.</td></tr>'

    error_rate = totals["error_rate"]
    err_tone = "deny" if error_rate >= 20 else ("warn" if error_rate >= 5 else "ok")

    return (
        f'<div class="docs-tabs">{tabs}</div>'
        + note
        + tiles
        + (
            '<div class="card">'
            f'<div class="card-head"><h3>{_icon("activity", 14)}Activity &ndash; {win_label}</h3></div>'
            f'<div class="pad pad-tight">{chart}</div>'
            "</div>"
        )
        + (
            '<div class="split"><div>'
            '<div class="card">'
            f'<div class="card-head"><h3>{_icon("layers", 14)}Toolkit usage</h3></div>'
            '<div class="wrap"><table><thead><tr>'
            '<th>Toolkit</th><th>Calls</th><th>OK</th><th>Denied</th><th>Failed</th>'
            f'</tr></thead><tbody>{kit_rows}</tbody></table></div></div>'
            '<div class="card">'
            f'<div class="card-head"><h3>{_icon("gauge", 14)}Latency</h3></div>'
            '<div class="wrap"><table><thead><tr>'
            '<th>Toolkit</th><th>Avg</th><th>P95</th><th>Calls</th>'
            f'</tr></thead><tbody>{dur_rows}</tbody></table></div></div>'
            "</div><div>"
            '<div class="card">'
            f'<div class="card-head"><h3>{_icon("users", 14)}Identity activity</h3></div>'
            '<div class="wrap"><table><thead><tr>'
            '<th>Identity</th><th>Calls</th><th>OK</th><th>Denied</th><th>Failed</th>'
            f'</tr></thead><tbody>{ident_rows}</tbody></table></div></div>'
            '<div class="card">'
            f'<div class="card-head"><h3>{_icon("share", 14)}Admin actions</h3></div>'
            '<div class="wrap"><table><thead><tr>'
            f'<th>Action</th><th>Count</th>'
            f'</tr></thead><tbody>{admin_rows}</tbody></table></div></div>'
            "</div></div>"
        )
        + (
            '<div class="card">'
            f'<div class="card-head"><h3>{_icon("ban", 14)}Error rate</h3></div>'
            f'<div class="pad"><span class="pill {err_tone}">{error_rate}%</span> '
            f'<span class="muted">({totals["denied"]} denied + {totals["failed"]} failed of {totals["total"]} total)</span></div>'
            "</div>"
        )
    )


def _view_docs(request: Request) -> str:
    """Full project documentation, rendered as HTML in the console."""
    slug = request.query_params.get("doc", "readme")
    docs = [(s, label, _read_doc_file(filename)) for s, label, filename in _DOC_FILES]
    selected = next((d for d in docs if d[0] == slug), docs[0])
    tabs = "".join(
        f'<a href="{UI_PREFIX}/docs?doc={_e(s)}"'
        f'{" class=\"active\"" if s == selected[0] else ""}>'
        f"{_e(label)}</a>"
        for s, label, _ in docs
    )
    body_html = _md_to_html(selected[2]) if selected[2] else (
        '<div class="note"><div>'
        "<strong>Document not found.</strong> The source files are bundled "
        "into the Docker image at build time. If you are running from a "
        "container image, the docs may not be included."
        "</div></div>"
    )
    return (
        f'<div class="docs-tabs">{tabs}</div>'
        f'<div class="card"><div class="pad prose">{body_html}</div></div>'
    )


def build_ui_routes(
    *,
    service: Service,
    identities: IdentityStore,
    audit: AuditLog,
    store: ConfigStore | None = None,
    credentials: CredentialStore | None = None,
    pending: PendingStore | None = None,
    toolkit_proposals: ToolkitProposalStore | None = None,
    sessions: SessionStore | None = None,
    throttle: LoginThrottle | None = None,
) -> list[Route]:
    """Builds the UI routes.

    `store=None` means: read only. Each handler checks the session itself,
    each write handler additionally checks role and CSRF token.
    """
    sessions = sessions or SessionStore()
    throttle = throttle or LoginThrottle()

    def _nonce() -> str:
        return secrets.token_urlsafe(16)

    def _current(request: Request) -> Session | None:
        return sessions.resolve(request.cookies.get(SESSION_COOKIE))

    def _to_login() -> Response:
        return RedirectResponse(f"{UI_PREFIX}/login", status_code=303)

    def _shell(
        request: Request, title: str, body: str, session: Session, *,
        icon: str, active: str, subtitle: str = "", actions: str = "", status: int = 200,
        allow_script: bool = False,
    ) -> Response:
        nonce = _nonce()
        # `allow_script` is opted into only by the routes that render the
        # interactive access map (Overview and /ui/access-map, see
        # `build_ui_routes`) -- everywhere else this stays False and the
        # page gets no `script-src` at all, same as before.
        script_nonce = _nonce() if allow_script else None
        script_tag = (
            f'<script nonce="{script_nonce}" src="{ACCESS_MAP_JS_PATH}"></script>'
            if script_nonce else ""
        )
        change_n, toolkit_n = _request_pending_counts(pending, toolkit_proposals)
        return _respond(
            request,
            _page(title, body, session=session, subtitle=subtitle, icon=icon,
                  active=active, nonce=nonce, actions=actions,
                  # Without writable Tier 2 there is no account page: it
                  # could offer nothing but an error message.
                  account=store is not None, script_tag=script_tag,
                  nav_badge=change_n + toolkit_n),
            nonce,
            status,
            script_nonce=script_nonce,
        )

    def guarded(view: Callable[[Request, Session], str], title: str, active: str, *,
                icon: str, subtitle: str = "",
                actions: Callable[[Session], str] | None = None,
                allow_script: bool = False):
        """Binds a view to a valid session.

        Every read handler runs through this wrapper, every write
        handler through `writer`. `test_ui.py` counts the registered routes and
        requires a redirect for each without a session -- a future
        forgotten guard thus shows up in the test, not in production.
        """

        async def handler(request: Request) -> Response:
            session = _current(request)
            if session is None:
                return _to_login()
            return _shell(
                request, title, view(request, session), session, icon=icon,
                active=active, subtitle=subtitle,
                actions=actions(session) if actions else "",
                allow_script=allow_script,
            )

        return handler

    def _csrf_ok(session: Session, form: FormData) -> bool:
        # Constant time, so the comparison reveals nothing about the token.
        return hmac.compare_digest(str(form.get("_csrf") or ""), session.csrf)

    def _csrf_refused(request: Request, session: Session) -> Response:
        return _shell(
            request, "Rejected",
            _note(
                "<strong>Missing or stale form token.</strong> The request "
                "did not originate from a page this session rendered. If "
                "you had the page open for a long time, reload and retry.",
                tone="bad",
            ),
            session, icon="ban", active="none", status=403,
        )

    def session_post(handler: Callable[[Request, Session, FormData], Any]):
        """Wrapper for forms that do not require the admin role.

        Exactly one falls under this: your own password. It needs a session
        and CSRF token like every write form, but not `admin` --
        otherwise a `viewer` could never change their password.
        """

        async def wrapped(request: Request) -> Response:
            session = _current(request)
            if session is None:
                return _to_login()
            if store is None:
                return RedirectResponse(f"{UI_PREFIX}/", status_code=303)
            form = await request.form()
            if not _csrf_ok(session, form):
                audit.write(
                    {
                        "kind": "admin_denied",
                        "actor": session.identity,
                        "path": request.url.path,
                        "reason": "csrf_mismatch",
                    }
                )
                return _csrf_refused(request, session)
            return await handler(request, session, form)

        return wrapped

    def writer(handler: Callable[[Request, Session, FormData], Any]):
        """Wrapper for everything that writes: session, role, CSRF."""

        async def wrapped(request: Request) -> Response:
            session = _current(request)
            if session is None:
                return _to_login()
            if store is None or not session.can_write:
                audit.write(
                    {
                        "kind": "admin_denied",
                        "actor": session.identity,
                        "role": session.role,
                        "path": request.url.path,
                        "reason": "read_only" if store is None else "role_required",
                    }
                )
                return _shell(
                    request, "Not permitted",
                    _note(
                        "<strong>This account cannot change anything.</strong> "
                        "Writing requires <code>role: admin</code>"
                        + ("" if store is not None else " and a writable configuration")
                        + ".",
                        tone="bad",
                    ),
                    session, icon="ban", active="none", status=403,
                )
            form = await request.form()
            if not _csrf_ok(session, form):
                audit.write(
                    {
                        "kind": "admin_denied",
                        "actor": session.identity,
                        "path": request.url.path,
                        "reason": "csrf_mismatch",
                    }
                )
                return _csrf_refused(request, session)
            return await handler(request, session, form)

        return wrapped

    # -- Login ---------------------------------------------------------

    async def login_form(request: Request) -> Response:
        if _current(request) is not None:
            return RedirectResponse(f"{UI_PREFIX}/", status_code=303)
        nonce = _nonce()
        return _respond(request, _login_page(nonce), nonce)

    async def login_submit(request: Request) -> Response:
        client = request.client.host if request.client else "unknown"
        nonce = _nonce()

        if throttle.blocked(client):
            audit.auth_failure(reason="ui_login_throttled", detail=client)
            return _respond(
                request,
                _login_page(nonce, "Too many failed attempts. Try again later."),
                nonce,
            )

        form = await request.form()
        # The ID comes unvalidated from the form and lands immediately in the
        # audit log and back in the field. Truncated so nobody inflates the log
        # with a megabyte per failed attempt.
        supplied = str(form.get("identity") or "").strip()[:64]
        password = str(form.get("password") or "")
        identity = (
            identities.authenticate_console(supplied, password)
            if supplied and password
            else None
        )

        if identity is None:
            # The response never names the reason: whether the ID exists, whether
            # it has a console role, or whether only the password was wrong,
            # is none of the sender business. The log has it in full.
            throttle.record_failure(client)
            audit.auth_failure(
                reason="ui_login_failed",
                detail=f"identity={supplied!r} from {client}",
            )
            return _respond(
                request, _login_page(nonce, "Sign-in failed.", supplied), nonce
            )

        throttle.reset(client)
        sid = sessions.create(identity.id, identity.role)
        audit.write(
            {
                "kind": "ui_login",
                "identity": identity.id,
                "role": identity.role,
                "client": client,
            }
        )
        response = RedirectResponse(f"{UI_PREFIX}/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            sid,
            httponly=True,
            # Strict: the browser does not send the cookie on any foreign-initiated
            # navigation. Together with the CSRF token in the form and the
            # fact that /mcp does not look at cookies anyway, no surface remains.
            samesite="strict",
            secure=request.url.scheme == "https",
            path=UI_PREFIX,
            max_age=sessions.ttl,
        )
        return response

    async def logout(request: Request) -> Response:
        sessions.destroy(request.cookies.get(SESSION_COOKIE))
        response = RedirectResponse(f"{UI_PREFIX}/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path=UI_PREFIX)
        return response

    # -- Own account -----------------------------------------------------

    def _account_shell(
        request: Request, session: Session, *, error: str = "",
        done: bool = False, status: int = 200,
    ) -> Response:
        assert store is not None
        return _shell(
            request, "Account",
            _account_page(
                session, rev=store.identities_revision(), error=error, done=done
            ),
            session, icon="lock", active="none",
            subtitle=(
                "Your console password. The API token of an identity lives on "
                "the identities page and is a separate credential."
            ),
            status=status,
        )

    async def account_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None:
            return RedirectResponse(f"{UI_PREFIX}/", status_code=303)
        return _account_shell(request, session)

    async def account_password(
        request: Request, session: Session, form: FormData
    ) -> Response:
        assert store is not None
        current = str(form.get("current") or "")
        password = str(form.get("password") or "")
        confirm = str(form.get("confirm") or "")
        if password != confirm:
            return _account_shell(
                request, session,
                error="The two new passwords do not match.",
                status=400,
            )
        try:
            store.set_password(
                session.identity,
                password,
                actor=session.identity,
                rev=str(form.get("rev") or ""),
                current_password=current,
                require_current=True,
            )
        except (WriteRefused, ConfigError) as exc:
            # A wrong current password is a failed attempt and belongs
            # in the log -- an open session is the most convenient place for
            # someone to guess a password.
            audit.auth_failure(
                reason="ui_password_change_failed",
                detail=f"identity={session.identity!r}: {exc}",
            )
            return _account_shell(request, session, error=str(exc), status=400)

        # End all other sessions of this identity. Anyone changing their
        # password often does so for exactly this reason: nothing should
        # remain open elsewhere. The current session stays -- otherwise
        # success would be indistinguishable from a sign-out.
        sessions.drop_identity(
            session.identity, keep=request.cookies.get(SESSION_COOKIE)
        )
        return _account_shell(request, session, done=True)

    # -- Write tools ---------------------------------------------------

    def _tools_actions(session: Session) -> str:
        if not (session.can_write and store is not None):
            return ""
        return (
            f'<a class="btn primary" href="{UI_PREFIX}/tools/new">'
            f'{_icon("plus", 14)}New tool</a>'
        )

    async def tool_new_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/tools", status_code=303)
        if not service.tier1.toolkits:
            # Without a toolkit there is nothing for a tool to
            # build on. Offering an empty form would be an invitation into
            # an error message.
            return _shell(
                request, "New tool", _no_toolkits_note(), session,
                icon="plus", active="/tools",
            )
        return _shell(
            request, "New tool",
            _tool_editor(service, session, yaml_text=_tool_scaffold(service),
                         rev=store.tools_revision(), replaces=None),
            session, icon="plus", active="/tools",
            subtitle="The definition is checked against Tier 1 before it is stored.",
        )

    async def tool_edit_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/tools", status_code=303)
        tool_id = request.query_params.get("id", "")
        spec = service.catalog.flat_spec_of(tool_id)
        if spec is None:
            return RedirectResponse(f"{UI_PREFIX}/tools", status_code=303)
        return _shell(
            request, f"Edit {tool_id}",
            _tool_editor(service, session, yaml_text=tool_to_yaml(spec),
                         rev=store.tools_revision(), replaces=tool_id),
            session, icon="pencil", active="/tools",
        )

    async def tool_save(request: Request, session: Session, form: FormData) -> Response:
        replaces = str(form.get("replaces") or "") or None
        rev = str(form.get("rev") or "")
        text = str(form.get("yaml") or "")
        assert store is not None
        try:
            spec = load_tool_yaml(text)
            store.save_tool(spec, actor=session.identity, rev=rev, replaces=replaces)
        except (WriteRefused, ConfigError) as exc:
            return _shell(
                request, f"Edit {replaces}" if replaces else "New tool",
                _tool_editor(service, session, yaml_text=text, rev=rev,
                             replaces=replaces, error=str(exc)),
                session, icon="pencil", active="/tools", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/tools", status_code=303)

    async def tool_toggle(request: Request, session: Session, form: FormData) -> Response:
        assert store is not None
        try:
            store.set_tool_enabled(
                str(form.get("id") or ""),
                str(form.get("enabled") or "") == "1",
                actor=session.identity,
                rev=str(form.get("rev") or ""),
            )
        except (WriteRefused, ConfigError) as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/tools", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/tools", status_code=303)

    async def tool_delete_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/tools", status_code=303)
        tool_id = request.query_params.get("id", "")
        # tool_id here is the bare definition id (FR-8.3h); a destination
        # expansion of it (tool_id@nas1) counts as a holder too, since
        # deleting/disabling the definition takes every destination with it.
        holders = sorted(
            i.id for i in identities.identities.values() if i.holds_definition(tool_id)
        )
        detail = (
            "The full definition is written to the audit log, so it can be "
            "restored from there."
        )
        if holders:
            detail += (
                " These identities hold a right to it and would keep a dangling "
                f"grant: {_e(', '.join(holders))}."
            )
        return _shell(
            request, "Delete tool",
            _confirm(
                session,
                question=f"Delete {tool_id}?",
                detail=detail,
                action=f"{UI_PREFIX}/tools/delete",
                fields={"id": tool_id, "rev": store.tools_revision()},
                back=f"{UI_PREFIX}/tools",
            ),
            session, icon="trash", active="/tools",
        )

    async def tool_delete(request: Request, session: Session, form: FormData) -> Response:
        assert store is not None
        try:
            store.delete_tool(
                str(form.get("id") or ""),
                actor=session.identity,
                rev=str(form.get("rev") or ""),
            )
        except (WriteRefused, ConfigError) as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/tools", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/tools", status_code=303)

    # -- Integrations ---------------------------------------------------------
    # Read-only browsing/picking; the actual write still goes through
    # `tool_save` above -- an integration only ever pre-fills that same form.

    async def integration_gallery(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        return _shell(
            request, "Integrations", _view_integrations(service, session, store), session,
            icon="package", active="/tools/integrations",
            subtitle="Starter definitions for common services, built on the http/truenas/docker/ssh executors.",
        )

    async def integration_pick(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        integration = INTEGRATIONS.get(request.query_params.get("key", ""))
        if integration is None:
            return RedirectResponse(f"{UI_PREFIX}/tools/integrations", status_code=303)
        return _shell(
            request, integration.display_name,
            _view_integration_picker(integration, service, session), session,
            icon="package", active="/tools/integrations",
        )

    async def integration_tool_new_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/tools/integrations", status_code=303)
        integration = INTEGRATIONS.get(request.query_params.get("key", ""))
        if integration is None:
            return RedirectResponse(f"{UI_PREFIX}/tools/integrations", status_code=303)
        tool_id = request.query_params.get("tool", "")
        spec = next((s for s in integration.tool_specs if s["id"] == tool_id), None)
        if spec is None:
            return RedirectResponse(
                f"{UI_PREFIX}/tools/integrations/pick?key={integration.key}", status_code=303
            )
        if integration.key not in service.tier1.toolkits:
            return _shell(
                request, integration.display_name,
                _note(
                    f"<strong>The {_e(integration.key)!s} toolkit is not configured "
                    "yet.</strong> Add it from the reference page and redeploy "
                    "before creating tools from this integration.",
                    tone="bad",
                ),
                session, icon="package", active="/tools/integrations",
            )
        # The same editor, the same YAML textarea, the same save path as a
        # hand-written definition (`tool_save` -> `store.save_tool` ->
        # `parse_tool_spec`) -- an integration never gets a shortcut around Tier 1.
        return _shell(
            request, f"New tool from {integration.display_name}",
            _tool_editor(service, session, yaml_text=tool_to_yaml(spec),
                         rev=store.tools_revision(), replaces=None),
            session, icon="plus", active="/tools/integrations",
            subtitle="Pre-filled from the integration -- still checked against Tier 1 before it is stored.",
        )

    async def toolkit_reference(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        return _shell(
            request, "Toolkit reference", _view_toolkit_reference(), session,
            icon="lock", active="none",
            subtitle="Copy-pasteable Tier 1 blocks. Toolkit creation stays a manual, deploy-time edit (FR-4.11).",
        )

    # -- Write identities -------------------------------------------

    def _identities_actions(session: Session) -> str:
        if not (session.can_write and store is not None):
            return ""
        return (
            f'<a class="btn primary" href="{UI_PREFIX}/identities/new">'
            f'{_icon("plus", 14)}New identity</a>'
        )

    async def identity_new_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/identities", status_code=303)
        return _shell(
            request, "New identity",
            _identity_editor(
                service, session,
                values={"id": "", "role": "agent", "tools": [], "scopes": []},
                rev=store.identities_revision(), replaces=None,
            ),
            session, icon="plus", active="/identities",
        )

    async def identity_edit_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/identities", status_code=303)
        identity_id = request.query_params.get("id", "")
        identity = identities.identities.get(identity_id)
        if identity is None:
            return RedirectResponse(f"{UI_PREFIX}/identities", status_code=303)
        return _shell(
            request, f"Edit {identity_id}",
            _identity_editor(
                service, session,
                values={
                    "id": identity.id,
                    "role": identity.role,
                    "tools": sorted(identity.tools),
                    "scopes": list(identity.scopes),
                },
                rev=store.identities_revision(), replaces=identity_id,
            ),
            session, icon="pencil", active="/identities",
        )

    def _form_values(form: FormData) -> dict[str, Any]:
        return {
            "id": str(form.get("id") or "").strip(),
            "role": str(form.get("role") or "agent"),
            "tools": [str(v) for v in form.getlist("tools")],
            "scopes": [
                line.strip()
                for line in str(form.get("scopes") or "").splitlines()
                if line.strip()
            ],
        }

    async def identity_create(request: Request, session: Session, form: FormData) -> Response:
        assert store is not None
        values = _form_values(form)
        rev = str(form.get("rev") or "")
        try:
            token = store.create_identity(
                identity_id=values["id"], role=values["role"], tools=values["tools"],
                scopes=values["scopes"], actor=session.identity, rev=rev,
                password=str(form.get("password") or ""),
            )
        except (WriteRefused, ConfigError) as exc:
            return _shell(
                request, "New identity",
                _identity_editor(service, session, values=values, rev=rev,
                                 replaces=None, error=str(exc)),
                session, icon="plus", active="/identities", status=400,
            )
        # The plaintext is rendered, not redirected: it must never appear in
        # a URL where history or log could capture it.
        return _shell(
            request, "Token issued",
            _token_page(values["id"], token, f"{UI_PREFIX}/identities"),
            session, icon="key", active="/identities",
        )

    async def identity_update(request: Request, session: Session, form: FormData) -> Response:
        assert store is not None
        values = _form_values(form)
        rev = str(form.get("rev") or "")
        replaces = str(form.get("replaces") or "")
        password = str(form.get("password") or "")
        try:
            store.save_identity(
                identity_id=values["id"], role=values["role"], tools=values["tools"],
                scopes=values["scopes"], actor=session.identity, rev=rev,
                replaces=replaces, password=password,
            )
        except (WriteRefused, ConfigError) as exc:
            return _shell(
                request, f"Edit {replaces}",
                _identity_editor(service, session, values=values, rev=rev,
                                 replaces=replaces, error=str(exc)),
                session, icon="pencil", active="/identities", status=400,
            )
        # Renamed or locked out of the UI: existing sessions of the old
        # identity must not continue. A new password ends them
        # too -- otherwise a taken-over session would remain open exactly when
        # an administrator is trying to close it.
        locked_out = values["id"] != replaces or values["role"] not in UI_ROLES
        if locked_out or password:
            keep = None
            if not locked_out and replaces == session.identity:
                # Anyone setting their own password here stays signed in.
                keep = request.cookies.get(SESSION_COOKIE)
            sessions.drop_identity(replaces, keep=keep)
        return RedirectResponse(f"{UI_PREFIX}/identities", status_code=303)

    async def identity_rotate(request: Request, session: Session, form: FormData) -> Response:
        assert store is not None
        identity_id = str(form.get("id") or "")
        try:
            token = store.rotate_token(
                identity_id, actor=session.identity, rev=str(form.get("rev") or "")
            )
        except (WriteRefused, ConfigError) as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/identities", status=400,
            )
        # The old token is dead. The console session has not depended on the
        # token since its own sign-in -- it is still terminated: a
        # rotation is the response to a suspicion, and then nothing of
        # this identity should remain open. The price is a re-login.
        if identity_id != session.identity:
            sessions.drop_identity(identity_id)
        return _shell(
            request, "Token issued",
            _token_page(identity_id, token, f"{UI_PREFIX}/identities"),
            session, icon="key", active="/identities",
        )

    async def identity_delete_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/identities", status_code=303)
        identity_id = request.query_params.get("id", "")
        return _shell(
            request, "Delete identity",
            _confirm(
                session,
                question=f"Delete {identity_id}?",
                detail=(
                    "Its token stops working immediately. Any agent still using "
                    "it will receive an authentication failure on the next call."
                ),
                action=f"{UI_PREFIX}/identities/delete",
                fields={"id": identity_id, "rev": store.identities_revision()},
                back=f"{UI_PREFIX}/identities",
            ),
            session, icon="trash", active="/identities",
        )

    async def identity_delete(request: Request, session: Session, form: FormData) -> Response:
        assert store is not None
        identity_id = str(form.get("id") or "")
        try:
            store.delete_identity(
                identity_id, actor=session.identity, rev=str(form.get("rev") or "")
            )
        except (WriteRefused, ConfigError) as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/identities", status=400,
            )
        sessions.drop_identity(identity_id)
        if identity_id == session.identity:
            return RedirectResponse(f"{UI_PREFIX}/login", status_code=303)
        return RedirectResponse(f"{UI_PREFIX}/identities", status_code=303)

    # -- Write credentials -------------------------------------------

    def _credentials_actions(session: Session) -> str:
        if not (session.can_write and store is not None and credentials is not None):
            return ""
        return (
            f'<a class="btn primary" href="{UI_PREFIX}/credentials/new">'
            f'{_icon("plus", 14)}New credential</a>'
        )

    async def credential_new_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or credentials is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)
        return _shell(
            request, "New credential",
            _credential_editor(session, rev=credentials.revision()),
            session, icon="plus", active="/credentials",
        )

    async def credential_create(request: Request, session: Session, form: FormData) -> Response:
        if credentials is None:
            return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)
        rev = str(form.get("rev") or "")
        try:
            credentials.create(
                str(form.get("name") or "").strip(),
                kind=str(form.get("kind") or ""),
                header=str(form.get("header") or "").strip() or None,
                value=str(form.get("value") or ""),
                actor=session.identity, rev=rev,
            )
        except (CredentialWriteRefused, ConfigError) as exc:
            return _shell(
                request, "New credential",
                _credential_editor(session, rev=rev, error=str(exc)),
                session, icon="plus", active="/credentials", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)

    async def credential_rotate_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or credentials is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)
        name = request.query_params.get("name", "")
        return _shell(
            request, f"Rotate {name}",
            _credential_rotate_editor(session, name=name, rev=credentials.revision()),
            session, icon="refresh", active="/credentials",
        )

    async def credential_rotate(request: Request, session: Session, form: FormData) -> Response:
        if credentials is None:
            return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)
        name = str(form.get("name") or "")
        rev = str(form.get("rev") or "")
        try:
            overlap = int(form.get("overlap_seconds") or "0")
        except ValueError:
            overlap = 0
        try:
            credentials.rotate(
                name, value=str(form.get("value") or ""), overlap_seconds=overlap,
                actor=session.identity, rev=rev,
            )
        except (CredentialWriteRefused, ConfigError) as exc:
            return _shell(
                request, f"Rotate {name}",
                _credential_rotate_editor(session, name=name, rev=rev, error=str(exc)),
                session, icon="refresh", active="/credentials", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)

    async def credential_delete_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or credentials is None or not session.can_write:
            return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)
        name = request.query_params.get("name", "")
        return _shell(
            request, "Delete credential",
            _confirm(
                session,
                question=f"Delete {name}?",
                detail=(
                    "Any toolkit that references this credential can no longer "
                    "authenticate -- its tools will fail at call time, not silently."
                ),
                action=f"{UI_PREFIX}/credentials/delete",
                fields={"name": name, "rev": credentials.revision()},
                back=f"{UI_PREFIX}/credentials",
            ),
            session, icon="trash", active="/credentials",
        )

    async def credential_delete(request: Request, session: Session, form: FormData) -> Response:
        if credentials is None:
            return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)
        name = str(form.get("name") or "")
        try:
            credentials.delete(name, actor=session.identity, rev=str(form.get("rev") or ""))
        except (CredentialWriteRefused, ConfigError) as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/credentials", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/credentials", status_code=303)

    # -- Pending (FR-2.8/2.9) --------------------------------------------
    # Approve/reject go through `writer`, exactly like every other admin
    # write: session, `role: admin`, CSRF. `apply_pending`/`pending.reject`
    # are the only functions that decide a proposal -- neither is reachable
    # from `/admin/mcp` (see `admin_service.py`).

    async def pending_reject_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write or pending is None:
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=change", status_code=303)
        item = pending.get(request.query_params.get("id", ""))
        if item is None or item.status != "pending":
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=change", status_code=303)
        return _shell(
            request, "Reject proposal", _pending_reject_confirm(session, item),
            session, icon="ban", active="/requests",
        )

    async def pending_approve(request: Request, session: Session, form: FormData) -> Response:
        assert store is not None
        if pending is None:
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=change", status_code=303)
        action_id = str(form.get("id") or "")
        try:
            apply_pending(store, pending, action_id, decided_by=session.identity)
        except (PendingWriteRefused, WriteRefused, ConfigError) as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/requests", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/requests?tab=change", status_code=303)

    async def pending_reject(request: Request, session: Session, form: FormData) -> Response:
        if pending is None:
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=change", status_code=303)
        action_id = str(form.get("id") or "")
        reason = str(form.get("reason") or "")
        try:
            pending.reject(action_id, decided_by=session.identity, reason=reason)
        except PendingWriteRefused as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/requests", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/requests?tab=change", status_code=303)

    # -- Toolkits (plan "Follow-up 2") ------------------------------------
    # A categorically different severity from Change above: a toolkit
    # proposal changes Tier 1, not Tier 2. Deploy/reject go through
    # `writer` like every other admin write (session, `role: admin`,
    # CSRF), but there is no code path from `/admin/mcp` that reaches
    # either -- `ToolkitProposalStore.deploy`/`.reject` are not in
    # `AdminService`'s dispatch table (see `admin_service.py`).

    async def toolkit_deploy_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write or toolkit_proposals is None:
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=toolkit", status_code=303)
        item = toolkit_proposals.get(request.query_params.get("id", ""))
        if item is None or item.status != "pending":
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=toolkit", status_code=303)
        return _shell(
            request, "Approve & deploy toolkit", _toolkit_deploy_confirm(session, item),
            session, icon="alert", active="/requests",
        )

    async def toolkit_deploy(request: Request, session: Session, form: FormData) -> Response:
        if toolkit_proposals is None:
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=toolkit", status_code=303)
        proposal_id = str(form.get("id") or "")
        try:
            toolkit_proposals.deploy(proposal_id, decided_by=session.identity)
        except (ToolkitProposalWriteRefused, ConfigError) as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/requests", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/requests?tab=toolkit", status_code=303)

    async def toolkit_reject_form(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        if store is None or not session.can_write or toolkit_proposals is None:
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=toolkit", status_code=303)
        item = toolkit_proposals.get(request.query_params.get("id", ""))
        if item is None or item.status != "pending":
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=toolkit", status_code=303)
        return _shell(
            request, "Reject proposal", _toolkit_reject_confirm(session, item),
            session, icon="ban", active="/requests",
        )

    async def toolkit_reject(request: Request, session: Session, form: FormData) -> Response:
        if toolkit_proposals is None:
            return RedirectResponse(f"{UI_PREFIX}/requests?tab=toolkit", status_code=303)
        proposal_id = str(form.get("id") or "")
        reason = str(form.get("reason") or "")
        try:
            toolkit_proposals.reject(proposal_id, decided_by=session.identity, reason=reason)
        except ToolkitProposalWriteRefused as exc:
            return _shell(
                request, "Rejected", _note(f"<strong>Rejected.</strong> {_e(exc)}", tone="bad"),
                session, icon="ban", active="/requests", status=400,
            )
        return RedirectResponse(f"{UI_PREFIX}/requests?tab=toolkit", status_code=303)

    async def probe_executors_action(request: Request) -> Response:
        # Not gated by `writer`: this reads reachability, it does not
        # touch config, so it works the same in a read-only deployment
        # as the `/health/ready` endpoint it wraps for the UI.
        session = _current(request)
        if session is None:
            return _to_login()
        form = await request.form()
        if not _csrf_ok(session, form):
            audit.write(
                {
                    "kind": "admin_denied",
                    "actor": session.identity,
                    "path": request.url.path,
                    "reason": "csrf_mismatch",
                }
            )
            return _csrf_refused(request, session)
        await service.probe_executors()
        return RedirectResponse(f"{UI_PREFIX}/", status_code=303)

    # -- Misc -----------------------------------------------------------

    async def root(_request: Request) -> Response:
        return RedirectResponse(f"{UI_PREFIX}/", status_code=303)

    async def favicon(_request: Request) -> Response:
        # Inline SVG instead of 204: otherwise the browser keeps asking.
        return Response(
            _FAVICON,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    async def access_map_data(request: Request) -> Response:
        """JSON node/edge model behind the interactive access map.

        Session-gated like every other read route (see `guarded`), just
        without the HTML shell around it -- this is an XHR sibling of
        `/ui/access-map`, not a public API.
        """
        session = _current(request)
        if session is None:
            return _to_login()
        records, _ = read_audit(
            os.path.join(service.tier1.audit_dir, "audit.jsonl"), limit=400
        )
        data = _access_graph_data(service, identities, records)
        return Response(
            json.dumps(data), media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    async def access_map_js(request: Request) -> Response:
        session = _current(request)
        if session is None:
            return _to_login()
        return Response(
            _ACCESS_MAP_JS, media_type="application/javascript",
            headers={"Cache-Control": "no-store"},
        )

    return [
        Route("/", root, methods=["GET"]),
        Route("/favicon.ico", favicon, methods=["GET"]),
        Route(f"{UI_PREFIX}/login", login_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/login", login_submit, methods=["POST"]),
        Route(f"{UI_PREFIX}/logout", logout, methods=["POST"]),
        Route(
            f"{UI_PREFIX}/",
            guarded(
                lambda r, s: _view_overview(service, identities, store, r, s),
                "Overview", "", icon="gauge", allow_script=True,
                subtitle=(
                    "What actually applies at runtime. The Tier 1 boundaries come "
                    "from <code>toolkits.yaml</code> and cannot change until the "
                    "next redeploy."
                ),
            ),
            methods=["GET"],
        ),
        Route(f"{UI_PREFIX}/probe-executors", probe_executors_action, methods=["POST"]),
        Route(
            f"{UI_PREFIX}/access-map",
            guarded(
                lambda r, s: _view_access_map(service, identities, r),
                "Access map", "none", icon="share", allow_script=True,
            ),
            methods=["GET"],
        ),
        Route(f"{UI_PREFIX}/access-map/data", access_map_data, methods=["GET"]),
        Route(ACCESS_MAP_JS_PATH, access_map_js, methods=["GET"]),
        Route(
            f"{UI_PREFIX}/tools",
            guarded(
                lambda r, s: _view_tools(service, identities, s, store),
                "Tools", "/tools", icon="sliders", actions=_tools_actions,
                subtitle=(
                    "Defining and granting are two separate steps: a tool with no "
                    "grantees exists, but is invisible to every agent."
                ),
            ),
            methods=["GET"],
        ),
        Route(f"{UI_PREFIX}/tools/new", tool_new_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/tools/new", writer(tool_save), methods=["POST"]),
        Route(f"{UI_PREFIX}/tools/edit", tool_edit_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/tools/edit", writer(tool_save), methods=["POST"]),
        Route(f"{UI_PREFIX}/tools/toggle", writer(tool_toggle), methods=["POST"]),
        Route(f"{UI_PREFIX}/tools/delete", tool_delete_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/tools/delete", writer(tool_delete), methods=["POST"]),
        Route(f"{UI_PREFIX}/tools/integrations", integration_gallery, methods=["GET"]),
        Route(f"{UI_PREFIX}/tools/integrations/pick", integration_pick, methods=["GET"]),
        Route(f"{UI_PREFIX}/tools/integrations/new", integration_tool_new_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/toolkits/reference", toolkit_reference, methods=["GET"]),
        Route(
            f"{UI_PREFIX}/identities",
            guarded(
                lambda r, s: _view_identities(service, identities, s, store),
                "Identities", "/identities", icon="key", actions=_identities_actions,
                subtitle=(
                    "Rights attach to individual tool IDs, never to a whole "
                    "toolkit. API tokens and console passwords are stored as "
                    "scrypt hashes and are never shown here."
                ),
            ),
            methods=["GET"],
        ),
        Route(f"{UI_PREFIX}/identities/new", identity_new_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/identities/new", writer(identity_create), methods=["POST"]),
        Route(f"{UI_PREFIX}/identities/edit", identity_edit_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/identities/edit", writer(identity_update), methods=["POST"]),
        Route(f"{UI_PREFIX}/identities/rotate", writer(identity_rotate), methods=["POST"]),
        Route(f"{UI_PREFIX}/identities/delete", identity_delete_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/identities/delete", writer(identity_delete), methods=["POST"]),
        Route(
            f"{UI_PREFIX}/credentials",
            guarded(
                lambda r, s: _view_credentials(service, s, store, credentials),
                "Credentials", "/credentials", icon="lock", actions=_credentials_actions,
                subtitle=(
                    "Named secrets a toolkit's <code>credential:</code> field "
                    "refers to. Write-only: create, rotate, delete -- never read."
                ),
            ),
            methods=["GET"],
        ),
        Route(f"{UI_PREFIX}/credentials/new", credential_new_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/credentials/new", writer(credential_create), methods=["POST"]),
        Route(f"{UI_PREFIX}/credentials/rotate", credential_rotate_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/credentials/rotate", writer(credential_rotate), methods=["POST"]),
        Route(f"{UI_PREFIX}/credentials/delete", credential_delete_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/credentials/delete", writer(credential_delete), methods=["POST"]),
        Route(
            f"{UI_PREFIX}/requests",
            guarded(
                lambda r, s: _view_requests(r, s, service, store, pending, toolkit_proposals),
                "Requests", "/requests", icon="share",
                subtitle=(
                    "Proposals from an admin-role agent on /admin/mcp: tool, "
                    "grant, and role changes on the Change tab, new Tier 1 "
                    "toolkits on the Toolkit tab. Only a human can approve "
                    "or reject one."
                ),
            ),
            methods=["GET"],
        ),
        Route(f"{UI_PREFIX}/pending/reject", pending_reject_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/pending/approve", writer(pending_approve), methods=["POST"]),
        Route(f"{UI_PREFIX}/pending/reject", writer(pending_reject), methods=["POST"]),
        Route(f"{UI_PREFIX}/toolkits/deploy", toolkit_deploy_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/toolkits/deploy", writer(toolkit_deploy), methods=["POST"]),
        Route(f"{UI_PREFIX}/toolkits/reject", toolkit_reject_form, methods=["GET"]),
        Route(f"{UI_PREFIX}/toolkits/reject", writer(toolkit_reject), methods=["POST"]),
        Route(f"{UI_PREFIX}/account", account_form, methods=["GET"]),
        Route(
            f"{UI_PREFIX}/account/password",
            session_post(account_password),
            methods=["POST"],
        ),
        Route(
            f"{UI_PREFIX}/stats",
            guarded(
                lambda r, s: _view_stats(service, identities, r),
                "Stats", "/stats", icon="bar-chart",
                subtitle=(
                    "Aggregate call statistics &mdash; outcomes, latency, "
                    "toolkit and identity activity, admin changes. Window is "
                    "best-effort over the tail of the current audit log."
                ),
            ),
            methods=["GET"],
        ),
        Route(
            f"{UI_PREFIX}/audit",
            guarded(
                lambda r, s: _view_audit(service, r),
                "Audit log", "/audit", icon="clock",
                subtitle=(
                    "The real reason for a denial is recorded here in full &ndash; "
                    "even when the agent only received an opaque answer. Admin "
                    "changes land here too."
                ),
            ),
            methods=["GET"],
        ),
        Route(
            f"{UI_PREFIX}/docs",
            guarded(
                lambda r, s: _view_docs(r),
                "Docs", "/docs", icon="book",
                subtitle=(
                    "Full project documentation &mdash; README, requirements, "
                    "agents guide, and release notes. Readable in the console "
                    "so agents and operators have the same reference."
                ),
            ),
            methods=["GET"],
        ),
    ]


def has_admin(identities: IdentityStore) -> bool:
    """Is there anyone who may write?"""
    return any(i.role == ADMIN_ROLE for i in identities.identities.values())


def has_ui_identity(identities: IdentityStore) -> bool:
    """Is there anyone at all who could sign in?

    Role *and* password: since console sign-in, a UI role without
    a password is not access. A server that delivers a login form
    that nobody can get past is worse than one without a console --
    it looks usable.
    """
    return any(i.can_sign_in for i in identities.identities.values())
