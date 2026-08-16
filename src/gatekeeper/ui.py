"""Betriebs- und Verwaltungsoberflaeche.

Zeigt, was zur Laufzeit gilt -- Ebene-1-Grenzen, Katalog, Rechteprofile,
Audit-Log -- und laesst Ebene 2 bearbeiten: Tools anlegen und aendern,
Identitaeten verwalten, Tokens ausstellen.

Fuenf Entwurfsentscheidungen tragen diese Schicht:

1. **Die Sitzung gilt nie fuer /mcp.** Der MCP-Endpunkt authentifiziert
   ausschliesslich ueber den `Authorization`-Header, und genau das macht ihn
   CSRF-fest: ein Browser haengt einen solchen Header nicht von sich aus an,
   eine fremde Seite kann ihn also nicht erzeugen. Ein Cookie dagegen wird
   automatisch mitgeschickt. Die Sitzung hier liest nur `ui.py` --
   `AuthMiddleware` kennt sie nicht.

2. **Angemeldet wird mit Kennung und Passwort, nicht mit dem Token**
   (FR-11.5). Der Token ist der Nachweis der API; ihn in ein Anmeldeformular
   zu tippen hiesse, ihn durch Zwischenablage, Passwortspeicher und Verlauf
   zu schicken -- und dasselbe Geheimnis oeffnete danach beides. Getrennte
   Nachweise heissen: ein verlorenes Konsolenpasswort ruft keine Tools auf,
   ein verlorener Token oeffnet keine Oberflaeche, und jeder von beiden laesst
   sich einzeln wechseln.

3. **Jedes schreibende Formular traegt ein CSRF-Token.** Mit Schreibzugriff
   wird das Cookie erstmals zur Waffe: eine fremde Seite koennte ein Formular
   auf `/ui/...` abschicken. `SameSite=Strict` verhindert das bereits, aber
   nicht in jeder Konstellation -- eine Seite auf derselben Site zaehlt nicht
   als fremd. Das Token im Formular schliesst die Luecke.

4. **Kein JavaScript.** Die CSP verbietet Skripte vollstaendig. Das folgt aus
   der Datenlage: das Audit-Log zeigt Parameterwerte von Agenten, bei
   abgelehnten Aufrufen unvalidierte. Ohne Skriptausfuehrung bleibt ein
   eingeschleustes `<script>` folgenlos, auch wenn die Maskierung versagt.
   Graph, Diagramm und alle Formulare kommen daher ohne Code im Browser aus.

5. **Lesen und Schreiben sind getrennte Rollen.** `viewer` sieht alles,
   `admin` darf aendern. Ohne diese Trennung haette jeder, der ins Audit-Log
   schauen soll, zugleich das Recht, Tools anzulegen.

Alle ausgegebenen Texte sind englisch; Kommentare bleiben deutsch.
"""

from __future__ import annotations

import dataclasses
import hmac
import html
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from .audit import AuditLog
from .catalog import ToolDef
from .errors import ConfigError
from .identity import (
    ADMIN_ROLE,
    MIN_PASSWORD_LENGTH,
    ROLES,
    UI_ROLES,
    IdentityStore,
)
from .service import Service
from .store import ConfigStore, WriteRefused, load_tool_yaml, tool_to_yaml

#: Praefix aller UI-Pfade. `AuthMiddleware` laesst genau dieses Praefix ohne
#: Bearer-Token durch -- die Handler pruefen stattdessen die Sitzung.
UI_PREFIX = "/ui"

#: Pfade, die ein Browser von sich aus anfaesst, sobald jemand die Adresse
#: eintippt. Ohne eigene Behandlung liefe jeder Besuch in die Token-Pflicht und
#: erzeugte zwei `auth_failure`-Eintraege -- der Fehlversuch ist aber der
#: wichtigste Befund im Audit-Log, und er ist wertlos, wenn er zwischen
#: Favicon-Rauschen steht. Gilt nur bei eingeschaltetem UI.
UI_COMPANION_PATHS = frozenset({"/", "/favicon.ico"})

SESSION_COOKIE = "gatekeeper_ui"
SESSION_TTL_SECONDS = 8 * 3600

#: Hoechstens so viele Bytes vom Ende der Logdatei lesen. Das Log darf 32 MB
#: gross werden; es vollstaendig zu parsen wuerde die Seite unbrauchbar machen.
AUDIT_READ_BYTES = 2 * 1024 * 1024
AUDIT_DEFAULT_LIMIT = 200


# -- Sitzungen -------------------------------------------------------------


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
    """Sitzungen im Arbeitsspeicher.

    Bewusst nicht persistiert: ein Neustart meldet alle ab. Der Verlust ist
    eine erneute Anmeldung, der Gewinn ist, dass ein Sitzungs-Token keinen
    Neustart ueberlebt und nirgends auf Platte landet.
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
        """Meldet alle Sitzungen einer Identitaet ab.

        Wird nach Loeschung, Rollenentzug und Passwortwechsel aufgerufen: eine
        bestehende Sitzung wuerde sonst weiterlaufen, obwohl der Zugang
        entzogen oder das Geheimnis ausgetauscht ist.

        `keep` verschont genau eine Sitzung -- die, die den Wechsel selbst
        veranlasst hat. Ohne diese Ausnahme wuerde die Selbstbedienung den
        Anwender fuer eine erfolgreiche Aenderung abmelden.
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
    """Bremst Rateversuche gegen das Anmeldeformular.

    Der scrypt-Vergleich kostet je Versuch rund 50 ms pro hinterlegter
    Identitaet und bremst damit schon von sich aus. Das Formular ist aber die
    erste Flaeche, die ein Mensch im Browser anfassen kann -- eine harte
    Obergrenze je Herkunftsadresse ist hier billiger als die Diskussion, ob
    scrypt allein reicht.
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


# -- Audit-Log lesen -------------------------------------------------------


def read_audit(
    path: str,
    *,
    limit: int = AUDIT_DEFAULT_LIMIT,
    identity: str = "",
    tool: str = "",
    outcome: str = "",
) -> tuple[list[dict[str, Any]], bool]:
    """Liest die juengsten Eintraege der aktuellen Logdatei.

    Gibt `(eintraege, gekuerzt)` zurueck. `gekuerzt` sagt, dass aelteres
    Material existiert, das hier nicht sichtbar ist -- entweder weil die Datei
    laenger als `AUDIT_READ_BYTES` ist oder weil bereits rotiert wurde. Das UI
    weist darauf hin, damit niemand die Abwesenheit eines Eintrags fuer einen
    Beweis haelt.
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
        # Die erste Zeile ist angeschnitten und damit kein gueltiges JSON.
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
    """Aufrufe je Stundenfach als `(gelungen, nicht gelungen)`.

    Beide Seiten werden auf die volle Stunde abgerundet, bevor gerechnet wird.
    Nur die Gegenwart abzurunden waere ein stiller Fehler: ein Eintrag aus der
    laufenden Stunde liegt dann *nach* der abgerundeten Gegenwart, bekommt ein
    negatives Alter und faellt aus jedem Fach heraus -- das Diagramm bliebe
    leer, obwohl gerade eben Aufrufe stattgefunden haben.
    """
    current = (now or datetime.now(timezone.utc)).replace(
        minute=0, second=0, microsecond=0
    )
    buckets = [(0, 0) for _ in range(hours)]
    for record in records:
        if record.get("kind") != "call":
            continue
        stamp = _parse_ts(record.get("ts"))
        if stamp is None:
            continue
        hour = stamp.astimezone(timezone.utc).replace(
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


# -- Bildmarken ------------------------------------------------------------

_FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<path fill="#2f81f7" d="M16 2 4 7v9c0 7 5 12 12 14 7-2 12-7 12-14V7z"/>'
    '<path fill="#fff" d="M13 15v-2a3 3 0 0 1 6 0v2h1.2v6.5h-8.4V15z"/>'
    '<path fill="#2f81f7" d="M15 13.2a1 1 0 0 1 2 0V15h-2z"/>'
    "</svg>"
)

#: Strichgrafiken, inline. Keine externe Quelle -- der Container hat kein Netz,
#: und die CSP laesst ohnehin nichts Fremdes zu.
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
}


def _icon(name: str, size: int = 16) -> str:
    return (
        f'<svg class="icon" width="{size}" height="{size}" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.7" '
        f'stroke-linecap="round" stroke-linejoin="round">{_ICONS.get(name, "")}</svg>'
    )


# -- HTML ------------------------------------------------------------------

_STYLE = """
:root {
  --bg: #eef1f6;
  --surface: #ffffff;
  --sunken: #f6f8fc;
  --line: #dee5ee;
  --fg: #0e141c;
  --muted: #5b6a7d;
  --accent: #0b62c4;
  --accent-soft: rgba(11,98,196,.10);
  --ok: #0c7a4f;   --ok-soft: rgba(12,122,79,.12);
  --deny: #bb2740; --deny-soft: rgba(187,39,64,.10);
  --warn: #8a5600; --warn-soft: rgba(138,86,0,.13);
  --shadow: 0 1px 2px rgba(16,24,40,.05), 0 10px 26px -16px rgba(16,24,40,.26);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #090d13;
    --surface: #111823;
    --sunken: #0d131c;
    --line: #202b39;
    --fg: #e4ecf5;
    --muted: #8695a8;
    --accent: #58a6ff;
    --accent-soft: rgba(88,166,255,.14);
    --ok: #46c08a;   --ok-soft: rgba(70,192,138,.14);
    --deny: #ff8296; --deny-soft: rgba(255,130,150,.14);
    --warn: #e0b341; --warn-soft: rgba(224,179,65,.15);
    --shadow: 0 1px 2px rgba(0,0,0,.5), 0 12px 32px -18px rgba(0,0,0,.9);
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; color: var(--fg); background: var(--bg);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.icon { flex: none; vertical-align: -.18em; }
.mono, code, input, select, textarea { font-family: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace; }
.muted { color: var(--muted); }

/* -- Geruest -- */
.app { display: grid; grid-template-columns: 236px 1fr; min-height: 100vh; }
.side {
  background: var(--surface); border-right: 1px solid var(--line);
  display: flex; flex-direction: column; gap: .25rem;
  position: sticky; top: 0; height: 100vh; padding: .9rem .7rem;
}
.brand {
  display: flex; align-items: center; gap: .55rem; padding: .35rem .5rem 1rem;
  font-weight: 650; letter-spacing: -.015em; font-size: 1.02rem;
}
.brand .icon { color: var(--accent); }
.brand em {
  font-style: normal; font-weight: 500; font-size: .68rem; color: var(--muted);
  border: 1px solid var(--line); border-radius: 999px; padding: .08rem .4rem;
}
.brand em.rw { color: var(--accent); border-color: var(--accent); }
.side nav { display: flex; flex-direction: column; gap: .12rem; }
.side nav a {
  display: flex; align-items: center; gap: .6rem;
  padding: .52rem .6rem; border-radius: 8px; text-decoration: none;
  color: var(--muted); font-size: .9rem; border-left: 2px solid transparent;
}
.side nav a:hover { background: var(--sunken); color: var(--fg); }
.side nav a.active {
  background: var(--accent-soft); color: var(--accent);
  font-weight: 600; border-left-color: var(--accent);
}
.side-foot { margin-top: auto; border-top: 1px solid var(--line); padding-top: .7rem; }
.who { display: flex; align-items: center; gap: .5rem; margin: 0; font-size: .84rem; }
.who b { font-weight: 600; flex: 1; overflow: hidden; text-overflow: ellipsis; }
.who .icon { color: var(--muted); }

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
  .app { grid-template-columns: 1fr; }
  .side {
    position: static; height: auto; flex-direction: row; align-items: center;
    flex-wrap: wrap; gap: .5rem; border-right: none; border-bottom: 1px solid var(--line);
  }
  .brand { padding: .2rem .3rem; }
  .side nav { flex-direction: row; flex: 1 1 320px; overflow-x: auto; scrollbar-width: none; }
  .side nav::-webkit-scrollbar { display: none; }
  .side nav a { white-space: nowrap; border-left: none; border-bottom: 2px solid transparent; }
  .side nav a.active { border-left: none; border-bottom-color: var(--accent); }
  .side-foot { margin: 0; border: none; padding: 0; }
  .topbar, main { padding-left: 1rem; padding-right: 1rem; }
}

/* -- Bausteine -- */
h2 {
  display: flex; align-items: center; gap: .45rem;
  font-size: .78rem; text-transform: uppercase; letter-spacing: .07em;
  color: var(--muted); margin: 1.6rem 0 .65rem; font-weight: 650;
}
h2 .icon { color: var(--muted); }
.card {
  background: var(--surface); border: 1px solid var(--line);
  border-radius: 11px; box-shadow: var(--shadow); margin-bottom: .8rem;
}
.card > .pad { padding: .9rem 1rem; }
.card-head {
  display: flex; align-items: center; gap: .5rem; flex-wrap: wrap;
  padding: .7rem 1rem; border-bottom: 1px solid var(--line);
  background: var(--sunken); border-radius: 11px 11px 0 0;
}
.card-head .name { font-weight: 650; letter-spacing: -.01em; }
.card-head .spacer { flex: 1; }
.card-head h3 {
  margin: 0; font-size: .82rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); font-weight: 650; display: flex; align-items: center; gap: .4rem;
}

.grid { display: grid; gap: .7rem; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }
.stat {
  display: flex; align-items: center; gap: .75rem;
  background: var(--surface); border: 1px solid var(--line);
  border-radius: 11px; padding: .8rem .9rem; box-shadow: var(--shadow);
}
.stat .chip {
  width: 34px; height: 34px; border-radius: 9px; flex: none;
  display: grid; place-items: center; background: var(--accent-soft); color: var(--accent);
}
.stat.t-deny .chip { background: var(--deny-soft); color: var(--deny); }
.stat.t-ok .chip { background: var(--ok-soft); color: var(--ok); }
.stat.t-warn .chip { background: var(--warn-soft); color: var(--warn); }
.stat .n { font-size: 1.45rem; font-weight: 650; line-height: 1.1; letter-spacing: -.02em; }
.stat .l { color: var(--muted); font-size: .79rem; }

.split { display: grid; grid-template-columns: minmax(0,1fr) 330px; gap: .8rem; align-items: start; }
@media (max-width: 1080px) { .split { grid-template-columns: 1fr; } }

.pill {
  display: inline-flex; align-items: center; gap: .25rem;
  padding: .12rem .48rem; border-radius: 999px;
  font-size: .755rem; font-weight: 500; white-space: nowrap;
  background: var(--sunken); border: 1px solid var(--line); color: var(--muted);
}
.pill.accent { background: var(--accent-soft); border-color: transparent; color: var(--accent); }
.pill.ok     { background: var(--ok-soft);     border-color: transparent; color: var(--ok); }
.pill.deny   { background: var(--deny-soft);   border-color: transparent; color: var(--deny); }
.pill.warn   { background: var(--warn-soft);   border-color: transparent; color: var(--warn); }
.pills { display: flex; flex-wrap: wrap; gap: .28rem; }
code {
  background: var(--sunken); border: 1px solid var(--line);
  padding: .06rem .3rem; border-radius: 5px; font-size: .84em;
}

.rows { display: grid; }
.row { display: grid; grid-template-columns: minmax(150px, 190px) 1fr; gap: .45rem 1rem; padding: .55rem 1rem; align-items: start; }
.row + .row { border-top: 1px solid var(--line); }
.row-l { display: flex; align-items: center; gap: .4rem; color: var(--muted); font-size: .83rem; }
@media (max-width: 620px) { .row { grid-template-columns: 1fr; gap: .25rem; } }

/* -- Tabellen -- */
.wrap { overflow-x: auto; border-radius: 11px; }
table { width: 100%; border-collapse: collapse; font-size: .87rem; }
thead th {
  position: sticky; top: 0; background: var(--sunken); z-index: 1;
  text-align: left; padding: .58rem .7rem; color: var(--muted);
  font-size: .72rem; font-weight: 650; text-transform: uppercase;
  letter-spacing: .06em; border-bottom: 1px solid var(--line); white-space: nowrap;
}
tbody td { padding: .6rem .7rem; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--sunken); }
tbody tr.t-ok   td:first-child { box-shadow: inset 3px 0 var(--ok); }
tbody tr.t-deny td:first-child { box-shadow: inset 3px 0 var(--deny); }
tbody tr.t-warn td:first-child { box-shadow: inset 3px 0 var(--warn); }
.tool-id { font-weight: 600; letter-spacing: -.01em; }
.argv {
  display: block; background: var(--sunken); border: 1px solid var(--line);
  border-radius: 7px; padding: .38rem .48rem; margin-top: .28rem;
  font-size: .77rem; line-height: 1.45; white-space: pre-wrap; word-break: break-word;
  max-width: 30ch; color: var(--muted);
}
.param + .param { margin-top: .45rem; }
.param-h { display: flex; align-items: center; gap: .3rem; flex-wrap: wrap; }
.param-d { color: var(--muted); font-size: .77rem; margin-top: .1rem; }
td.ops { white-space: nowrap; }
td.ops form { display: inline; }

/* -- Zugriffskarte -- */
.graph { width: 100%; height: auto; display: block; }
.graph text { font-family: inherit; }
.g-box { fill: var(--sunken); stroke: var(--line); transition: fill .18s, stroke .18s, stroke-width .18s; }
.g-box.hub { fill: var(--accent-soft); stroke: var(--accent); }
.g-box.deny { fill: var(--deny-soft); stroke: var(--deny); }
.g-box.ok { fill: var(--ok-soft); stroke: var(--ok); }
.g-t { fill: var(--fg); font-size: 11.5px; font-weight: 600; pointer-events: none; }
.g-s { fill: var(--muted); font-size: 9.5px; pointer-events: none; }
.g-count { fill: var(--accent); font-size: 10px; font-weight: 700; pointer-events: none; }
.g-e { fill: none; stroke: var(--ok); stroke-width: 1.5; opacity: .55; transition: opacity .18s, stroke-width .18s; }
.g-e.deny { stroke: var(--deny); stroke-dasharray: 5 4; opacity: .7; }
.g-e.none { stroke: var(--line); stroke-dasharray: 2 3; opacity: .5; }
.g-e.hot { stroke-width: 2.8; opacity: .9; }
.g-n { fill: var(--muted); font-size: 9px; pointer-events: none; }
.g-bg { fill: transparent; }
.g-node { cursor: help; }
.g-node:hover .g-box { fill: var(--accent-soft); stroke: var(--accent); stroke-width: 2; }
.g-node:hover .g-box.deny { fill: var(--deny-soft); stroke: var(--deny); stroke-width: 2; }
.g-node:hover .g-box.ok { fill: var(--ok-soft); stroke: var(--ok); stroke-width: 2; }
.g-node:hover .g-t { fill: var(--accent); }
.g-edge-group { cursor: help; }
.g-edge-group:hover .g-e { opacity: 1; stroke-width: 3; }
.legend { display: flex; gap: .8rem; flex-wrap: wrap; font-size: .78rem; color: var(--muted); }
.legend i { display: inline-block; width: 14px; height: 0; margin-right: .3rem; vertical-align: middle; }
.legend .l-ok i { border-top: 2px solid var(--ok); }
.legend .l-deny i { border-top: 2px dashed var(--deny); }
.legend .l-hot i { border-top: 3px solid var(--accent); }

/* -- Aktivitaet -- */
.chart { width: 100%; height: auto; display: block; }
.c-ok { fill: var(--ok); }
.c-deny { fill: var(--deny); }
.c-base { fill: var(--line); }
.c-ax { fill: var(--muted); font-size: 9px; font-family: inherit; }
.feed { display: flex; flex-direction: column; }
.feed-item { display: flex; gap: .55rem; padding: .55rem 1rem; align-items: baseline; border-top: 1px solid var(--line); font-size: .82rem; }
.feed-item .dot { width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--muted); }
.feed-item.t-ok .dot { background: var(--ok); }
.feed-item.t-deny .dot { background: var(--deny); }
.feed-item.t-warn .dot { background: var(--warn); }
.feed-item.t-accent .dot { background: var(--accent); }
.feed-item .txt { flex: 1; min-width: 0; }
.feed-item .txt b { font-weight: 600; }
.feed-item .when { color: var(--muted); font-size: .74rem; white-space: nowrap; }

/* -- Hinweise -- */
.note {
  display: flex; gap: .55rem; align-items: flex-start;
  background: var(--warn-soft); color: var(--warn);
  border-left: 3px solid var(--warn); border-radius: 8px;
  padding: .65rem .8rem; margin-bottom: .8rem; font-size: .85rem;
}
.note.bad { background: var(--deny-soft); color: var(--deny); border-left-color: var(--deny); }
.note.good { background: var(--ok-soft); color: var(--ok); border-left-color: var(--ok); }
.note .icon { margin-top: .1rem; }
.note strong { font-weight: 650; }
.note ul { margin: .3rem 0 0; padding-left: 1.1rem; }

/* -- Formulare -- */
.filter {
  display: flex; gap: .5rem; flex-wrap: wrap; align-items: flex-end;
  background: var(--surface); border: 1px solid var(--line);
  border-radius: 11px; padding: .75rem .9rem; margin-bottom: .8rem; box-shadow: var(--shadow);
}
.filter label, .field { display: flex; flex-direction: column; gap: .22rem; }
.field { margin-bottom: .9rem; }
.filter span, .field > span {
  font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); font-weight: 650;
}
.field .hint { text-transform: none; letter-spacing: 0; font-weight: 400; font-size: .78rem; }
input, select, button, textarea {
  font-size: .87rem; padding: .4rem .58rem; border-radius: 7px;
  border: 1px solid var(--line); background: var(--surface); color: var(--fg);
}
textarea { width: 100%; min-height: 26rem; line-height: 1.5; resize: vertical; tab-size: 2; }
input:focus, select:focus, button:focus-visible, textarea:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
button {
  cursor: pointer; font-weight: 600; font-family: inherit;
  background: var(--accent); border-color: var(--accent); color: #fff;
  display: inline-flex; align-items: center; gap: .3rem;
}
button.ghost { background: transparent; border-color: var(--line); color: var(--muted); }
button.ghost:hover { color: var(--fg); border-color: var(--muted); }
button.danger { background: transparent; border-color: var(--deny); color: var(--deny); }
button.danger:hover { background: var(--deny-soft); }
button.solid-danger { background: var(--deny); border-color: var(--deny); color: #fff; }
a.btn {
  text-decoration: none; font-size: .87rem; padding: .4rem .58rem; border-radius: 7px;
  border: 1px solid var(--line); color: var(--muted); font-weight: 600;
  display: inline-flex; align-items: center; gap: .3rem;
}
a.btn:hover { color: var(--fg); border-color: var(--muted); }
a.btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
a.reset { align-self: center; color: var(--muted); text-decoration: none; font-size: .83rem; padding: .4rem .3rem; }
a.reset:hover { color: var(--accent); }
.checks { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: .3rem; }
.checks label { display: flex; align-items: center; gap: .45rem; font-size: .85rem; padding: .25rem .35rem; border-radius: 6px; }
.checks label:hover { background: var(--sunken); }
.checks input { width: auto; padding: 0; }
.editor { max-width: 900px; }
.secret {
  background: var(--sunken); border: 1px dashed var(--accent); border-radius: 8px;
  padding: .7rem .8rem; font-size: .9rem; word-break: break-all; margin: .5rem 0;
}

/* -- Anmeldung -- */
.login { max-width: 390px; margin: 13vh auto; padding: 0 1.15rem; }
.login .card { margin: 0; }
.login .pad { padding: 1.6rem 1.5rem; }
.login .mark { width: 46px; height: 46px; border-radius: 12px; display: grid; place-items: center; background: var(--accent-soft); color: var(--accent); margin-bottom: .9rem; }
.login h1 { font-size: 1.28rem; margin: 0; letter-spacing: -.02em; }
.login p { color: var(--muted); font-size: .87rem; margin: .4rem 0 1.2rem; }
.login form { display: flex; flex-direction: column; gap: .6rem; }
.login input { width: 100%; padding: .55rem .7rem; }
.login button { padding: .55rem .7rem; justify-content: center; }
.login p.foot { font-size: .8rem; margin: .9rem 0 0; }
.err { display: flex; align-items: center; gap: .4rem; color: var(--deny); font-size: .85rem; margin: .9rem 0 0; }
"""

#: Die Oberflaeche ist durchgehend englisch -- Kommentare und Doku bleiben
#: deutsch wie im uebrigen Projekt.
_NAV = (
    ("", "Overview", "gauge"),
    ("/tools", "Tools", "sliders"),
    ("/identities", "Identities", "key"),
    ("/audit", "Audit", "clock"),
)


def _e(value: Any) -> str:
    """Escapen -- ausnahmslos.

    Alles, was hier durchlaeuft, kann von einem Agenten stammen: Audit-Eintraege
    halten bei abgelehnten Aufrufen die *unvalidierten* Argumente fest, damit im
    Log steht, was tatsaechlich versucht wurde.
    """
    return html.escape("" if value is None else str(value), quote=True)


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
) -> str:
    nav = "".join(
        f'<a href="{UI_PREFIX}{path or "/"}"'
        f'{" class=\"active\"" if path == active else ""}>'
        f"{_icon(name_icon, 16)}{_e(label)}</a>"
        for path, label, name_icon in _NAV
    )
    badge = (
        '<em class="rw">read &amp; write</em>'
        if session.can_write
        else "<em>read-only</em>"
    )
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(title)} - gatekeeper</title>"
        f'<style nonce="{nonce}">{_STYLE}</style></head><body><div class="app">'
        '<aside class="side">'
        f'<div class="brand">{_icon("shield", 20)}gatekeeper{badge}</div>'
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
        + f"</div><main>{body}</main></div></div></body></html>"
    )


def _pills(values: Any, *, tone: str = "") -> str:
    items = list(values or ())
    if not items:
        return '<span class="muted">&ndash;</span>'
    css = " ".join(filter(None, ["pill", tone, "mono"]))
    return (
        '<div class="pills">'
        + "".join(f'<span class="{css}">{_e(v)}</span>' for v in items)
        + "</div>"
    )


def _note(text: str, *, icon: str = "alert", tone: str = "") -> str:
    return f'<div class="note {tone}">{_icon(icon, 16)}<div>{text}</div></div>'


def _stat(number: Any, label: str, icon: str, tone: str = "") -> str:
    return (
        f'<div class="stat {tone}"><div class="chip">{_icon(icon, 18)}</div>'
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


def _respond(request: Request, html_text: str, nonce: str, status: int = 200) -> Response:
    response = HTMLResponse(html_text, status_code=status)
    # Ohne Skripte und ohne externe Quellen. Der Nonce gilt nur dem einen
    # <style>-Block. Graph, Diagramm und Formulare sind Inline-HTML/SVG und
    # brauchen daher weder eine Bildquelle noch Code im Browser.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        f"style-src 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Ein UI mit Rechte- und Audit-Daten gehoert in keinen Cache.
    response.headers["Cache-Control"] = "no-store"
    return response


# -- Zugriffskarte ---------------------------------------------------------


def _svg_node(
    x: float, y: float, w: float, h: float, label: str, sub: str, css: str,
    *, tooltip: str = "", count_text: str = "",
) -> str:
    """Ein Knoten der Zugriffskarte mit optionalem Tooltip und Zaehler.

    Der Tooltip laeuft ueber ein natives SVG-``<title>``-Element: der Browser
    zeigt ihn beim Darueberfahren an, ohne dass Skripte noetig waeren. Der
    Zaehler erscheint als dritte Textzeile, wenn ``count_text`` nicht leer ist.
    """
    title = f"<title>{_e(tooltip)}</title>" if tooltip else ""
    count = (
        f'<text class="g-count" x="{x + w / 2:.0f}" y="{y + h / 2 + 22:.0f}" '
        f'text-anchor="middle">{_e(count_text)}</text>'
        if count_text
        else ""
    )
    return (
        f'<rect class="g-box {css}" x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" '
        f'height="{h:.0f}" rx="8"/>'
        f'<text class="g-t" x="{x + w / 2:.0f}" y="{y + h / 2 - 2:.0f}" '
        f'text-anchor="middle">{_e(label)}</text>'
        f'<text class="g-s" x="{x + w / 2:.0f}" y="{y + h / 2 + 11:.0f}" '
        f'text-anchor="middle">{_e(sub)}</text>'
        f"{count}"
        f"{title}"
    )


def _call_stats(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Zaehlt Aufrufe je Identitaet: {id: {ok, denied, failed, total}}."""
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
    """Zaehlt Aufrufe je Toolkit durch Aufloesen der Tool-ID.

    ``{toolkit: {ok, denied, failed, total}}``. Ein Aufruf, dessen Tool in
    keinem bekannten Toolkit liegt, wird unter ``_unknown`` zusammengefasst.
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


def _access_graph(
    service: Service, identities: IdentityStore,
    records: list[dict[str, Any]] | None = None,
) -> str:
    """Wer erreicht was -- als serverseitig berechnetes SVG.

    Die Karte beantwortet die Frage, fuer die es sonst drei Dateien
    nebeneinander braucht: welche Identitaet kommt ueber welches Toolkit an
    welche Ressource, und was ist fuer alle gesperrt. Kanten sind aggregiert;
    einzeln gezeichnet waeren es bei zehn Tools und vier Identitaeten vierzig
    Linien und keine Aussage mehr.

    Mit ``records`` (Audit-Log) werden zusaetzlich gezeigt: Aufrufzaehler je
    Identitaet und je Toolkit, Erfolgs-/Abweisungs-/Fehleraufschluesselung im
    Tooltip, und hervorgehobene Kanten fuer viel frequentierte Wege.
    """
    idents = sorted(
        (i for i in identities.identities.values() if i.role not in UI_ROLES or i.tools),
        key=lambda i: i.id,
    ) or sorted(identities.identities.values(), key=lambda i: i.id)
    toolkits = sorted(service.tier1.toolkits.items())
    protected = sorted(
        {r for tk in service.tier1.toolkits.values() for r in tk.protected_resources}
    )

    tools_by_kit: dict[str, set[str]] = {name: set() for name, _ in toolkits}
    for tool in service.catalog.tools.values():
        tools_by_kit.setdefault(tool.toolkit, set()).add(tool.id)

    audit_records = records or []
    ident_stats = _call_stats(audit_records)
    kit_stats = _tool_call_stats(audit_records, tools_by_kit)

    # Schwellenwert fuer "heisse" Kanten: das 75. Perzentil der Gesamtzahl,
    # mindestens aber 3 Aufrufe -- sonst gibt es bei wenig Traffic kein
    # Hervorheben, was richtig ist, weil nichts hervorzuheben ist.
    all_totals = [s["total"] for s in ident_stats.values()] + [
        s["total"] for s in kit_stats.values()
    ]
    hot_threshold = max(
        sorted(all_totals)[int(len(all_totals) * 0.75)] if all_totals else 0,
        3,
    )

    nw, nh, gap = 132.0, 52.0, 14.0
    right_items = len(toolkits) + len(protected)
    lanes = max(len(idents), right_items, 1)
    height = max(lanes * (nh + gap) + 30, 210.0)
    width = 640.0
    lx, cx, rx = 8.0, 254.0, 500.0
    cw = 132.0

    def lane_y(index: int, count: int) -> float:
        span = count * nh + max(count - 1, 0) * gap
        return (height - span) / 2 + index * (nh + gap)

    def _tooltip_line(label: str, value: int) -> str:
        return f"  {label}: {value}\n" if value else ""

    edges, nodes = [], []
    hub_y = height / 2 - nh / 2
    hub_cy = height / 2

    for index, identity in enumerate(idents):
        y = lane_y(index, len(idents))
        granted = len(identity.tools)
        stats = ident_stats.get(identity.id, {"ok": 0, "denied": 0, "failed": 0, "total": 0})
        total = stats["total"]
        sub = f"{granted} tools" if granted else "no tool rights"
        count_text = f"{total} calls" if total else ""
        tooltip = identity.id
        if granted:
            tooltip += f"\n  tools: {granted}"
        tooltip += "\n  calls:"
        tooltip += _tooltip_line("ok", stats["ok"])
        tooltip += _tooltip_line("denied", stats["denied"])
        tooltip += _tooltip_line("failed", stats["failed"])
        if not total:
            tooltip += "  (none in log)"
        nodes.append(
            f'<g class="g-node">'
            + _svg_node(
                lx, y, nw, nh, identity.id, sub,
                "ok" if granted else "",
                tooltip=tooltip, count_text=count_text,
            )
            + "</g>"
        )
        x1, y1 = lx + nw, y + nh / 2
        edge_css = "g-e" if granted else "g-e none"
        if total >= hot_threshold and total > 0:
            edge_css += " hot"
        edge_tooltip = f"{identity.id} -> gatekeeper\n  {total} calls"
        if stats["denied"]:
            edge_tooltip += f"  ({stats['denied']} denied)"
        edges.append(
            f'<g class="g-edge-group"><path class="{edge_css}" '
            f'd="M{x1:.0f} {y1:.0f} '
            f"C{x1 + 60:.0f} {y1:.0f} {cx - 60:.0f} {hub_cy:.0f} "
            f'{cx:.0f} {hub_cy:.0f}"/>'
            f"<title>{_e(edge_tooltip)}</title></g>"
        )

    for index, (name, _tk) in enumerate(toolkits):
        y = lane_y(index, right_items)
        tool_count = len(tools_by_kit.get(name, ()))
        stats = kit_stats.get(name, {"ok": 0, "denied": 0, "failed": 0, "total": 0})
        total = stats["total"]
        sub = f"{tool_count} tools"
        count_text = f"{total} calls" if total else ""
        tooltip = f"{name}\n  tools: {tool_count}\n  calls:"
        tooltip += _tooltip_line("ok", stats["ok"])
        tooltip += _tooltip_line("denied", stats["denied"])
        tooltip += _tooltip_line("failed", stats["failed"])
        if not total:
            tooltip += "  (none in log)"
        nodes.append(
            f'<g class="g-node">'
            + _svg_node(
                rx, y, nw, nh, name, sub, "",
                tooltip=tooltip, count_text=count_text,
            )
            + "</g>"
        )
        y2 = y + nh / 2
        edge_css = "g-e"
        if total >= hot_threshold and total > 0:
            edge_css += " hot"
        edge_tooltip = f"gatekeeper -> {name}\n  {total} calls"
        if stats["denied"]:
            edge_tooltip += f"  ({stats['denied']} denied)"
        edges.append(
            f'<g class="g-edge-group"><path class="{edge_css}" '
            f'd="M{cx + cw:.0f} {hub_cy:.0f} '
            f"C{cx + cw + 60:.0f} {hub_cy:.0f} {rx - 60:.0f} {y2:.0f} "
            f'{rx:.0f} {y2:.0f}"/>'
            f"<title>{_e(edge_tooltip)}</title></g>"
        )

    for index, resource in enumerate(protected):
        y = lane_y(len(toolkits) + index, right_items)
        nodes.append(
            f'<g class="g-node">'
            + _svg_node(
                rx, y, nw, nh, resource, "blocked", "deny",
                tooltip=f"{resource}\n  protected for all identities (FR-4.12)",
            )
            + "</g>"
        )
        y2 = y + nh / 2
        edges.append(
            f'<g class="g-edge-group"><path class="g-e deny" '
            f'd="M{cx + cw:.0f} {hub_cy:.0f} '
            f"C{cx + cw + 60:.0f} {hub_cy:.0f} {rx - 60:.0f} {y2:.0f} "
            f'{rx:.0f} {y2:.0f}"/>'
            f"<title>{_e(resource + ' — blocked for all')}</title></g>"
        )

    total_calls = sum(s["total"] for s in ident_stats.values())
    hub_tooltip = "gatekeeper\n  the only path\n  "
    hub_tooltip += f"{total_calls} total calls"
    hub = (
        f'<g class="g-node">'
        + _svg_node(cx, hub_y, cw, nh, "gatekeeper", "the only path", "hub",
                    tooltip=hub_tooltip)
        + "</g>"
    )
    return (
        f'<svg class="graph" viewBox="0 0 {width:.0f} {height:.0f}" '
        f'role="img" aria-label="Access map">'
        f'{"".join(edges)}{"".join(nodes)}{hub}'
        f'<text class="g-n" x="{lx:.0f}" y="14">IDENTITIES</text>'
        f'<text class="g-n" x="{rx:.0f}" y="14">TOOLKITS AND BLOCKED</text>'
        "</svg>"
    )


# -- Aktivitaet ------------------------------------------------------------


def _activity_chart(records: list[dict[str, Any]], hours: int = 12) -> str:
    """Aufrufe je Stunde, gelungen gegen abgelehnt -- als gestapelte Balken."""
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
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
    items = []
    for record in records[:limit]:
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
        items.append(
            f'<div class="feed-item {tone}"><span class="dot"></span>'
            f'<span class="txt">{what}</span>'
            f'<span class="when mono">{_e(clock)}</span></div>'
        )
    return (
        "".join(items)
        or '<div class="feed-item"><span class="txt muted">No activity yet.</span></div>'
    )


# -- Views: lesen ----------------------------------------------------------

# -- Aufruf-Pipeline -------------------------------------------------------


def _call_flow_pipeline() -> str:
    """Die 8 Schichten, die jeder Aufruf durchlaeuft -- als horizontales SVG.

    Jede Schicht ist ein Knoten mit Namen und kurzer Erklaerung. Die Pfeile
    zeigen den Weg vom Agenten bis zur Ausfuehrung. Das Diagramm beantwortet
    die Frage, die sonst nur der Code beantwortet: in welcher Reihenfolge
    greifen die Schutzmechanismen, und was tut jede Schicht.
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
    bw, bh, gap = 120.0, 52.0, 10.0
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
            f'<rect class="g-box" x="{x:.0f}" y="{y:.0f}" width="{bw:.0f}" '
            f'height="{bh:.0f}" rx="7"/>'
            f'<text class="g-t" x="{x + bw / 2:.0f}" y="{y + bh / 2 - 4:.0f}" '
            f'text-anchor="middle">{_e(name)}</text>'
            f'<text class="g-s" x="{x + bw / 2:.0f}" y="{y + bh / 2 + 12:.0f}" '
            f'text-anchor="middle">{_e(desc)}</text>'
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


# -- Tool-Matrix -----------------------------------------------------------


def _tool_matrix(service: Service, identities: IdentityStore) -> str:
    """Jedes Tool als Zeile: Status, Kategorie, Idempotenz, wer darf es.

    Die Matrix beantwortet auf einen Blick: welche Tools gibt es, sind sie
    aktiv, sind sie idempotent, und welche Identitaeten duerfen sie aufrufen.
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
        grants = "".join(
            '<span class="pill ok">' if tool.id in i.tools else '<span class="pill">-</span>'
            for i in idents
        )
        rows.append(
            f"<tr>"
            f'<td><code class="tool-id">{_e(tool.id)}</code></td>'
            f"<td>{status}</td>"
            f"<td>{category}</td>"
            f"<td>{idem}</td>"
            f'<td class="pills">{grants}</td>'
            "</tr>"
        )

    id_cols = "".join(
        f'<th class="mono" title="{_e(i.id)}">{_e(i.id[:8])}</th>' for i in idents
    )
    return (
        '<div class="wrap"><table>'
        "<thead><tr>"
        "<th>Tool</th><th>Status</th><th>Category</th><th>Idempotent</th>"
        f"<th>{id_cols}</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _view_overview(service: Service, identities: IdentityStore, store: ConfigStore | None) -> str:
    ready = service.executor_ready
    catalog = service.catalog
    active = sum(1 for t in catalog.tools.values() if t.enabled)
    blocked = len(catalog.disabled_by_tier1)
    protected = {r for tk in service.tier1.toolkits.values() for r in tk.protected_resources}
    records, _ = read_audit(os.path.join(service.tier1.audit_dir, "audit.jsonl"), limit=400)

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
        + _stat(len(protected), "Protected resources", "lock", "t-deny")
        + _stat(blocked, "Tools blocked", "ban", "t-deny" if blocked else "")
        + "</div>"
    )

    # Aufruf-Pipeline: die 8 Schichten, die jeder Aufruf durchlaeuft.
    parts.append(
        '<div class="card">'
        f'<div class="card-head"><h3>{_icon("layers", 14)}Call flow &ndash; 8 layers every request passes</h3></div>'
        f'<div class="pad">{_call_flow_pipeline()}</div>'
        "</div>"
    )

    if ready:
        exec_cells = '<div class="pills">' + "".join(
            f'<span class="pill {"ok" if ok else "deny"}">'
            f'{_icon("check" if ok else "ban", 13)}{_e(name)}: '
            f'{"reachable" if ok else "unreachable"}</span>'
            for name, ok in sorted(ready.items())
        ) + "</div>"
    else:
        exec_cells = (
            '<span class="muted">not probed yet &ndash; '
            "call <code>/health/ready</code></span>"
        )

    parts.append(
        '<div class="split"><div>'
        '<div class="card">'
        f'<div class="card-head"><h3>{_icon("share", 14)}Access map</h3></div>'
        f'<div class="pad">{_access_graph(service, identities, records)}'
        '<div class="legend" style="margin-top:.6rem">'
        '<span class="l-ok"><i></i>granted</span>'
        '<span class="l-deny"><i></i>blocked for everyone (FR-4.12)</span>'
        '<span class="l-hot"><i></i>high traffic</span>'
        "</div></div></div>"
        "</div><div>"
        '<div class="card">'
        f'<div class="card-head"><h3>{_icon("activity", 14)}Calls, last 12 h</h3></div>'
        f'<div class="pad">{_activity_chart(records)}</div>'
        f'<div class="feed">{_feed(records)}</div>'
        "</div>"
        '<div class="card">'
        f'<div class="card-head"><h3>{_icon("server", 14)}Executors</h3></div>'
        f'<div class="pad">{exec_cells}</div></div>'
        "</div></div>"
    )

    # Tool-Matrix: jedes Tool als Zeile mit Status, Kategorie, Idempotenz
    # und wer es aufrufen darf. Beantwortet die Frage, die die Zugriffskarte
    # nur aggregiert zeigt: welches konkrete Tool ist fuer wen freigegeben.
    if catalog.tools:
        parts.append(
            '<div class="card">'
            f'<div class="card-head"><h3>{_icon("sliders", 14)}Tool matrix &ndash; '
            f'{len(catalog.tools)} tools</h3></div>'
            f'<div class="pad">{_tool_matrix(service, identities)}</div>'
            "</div>"
        )

    parts.append(
        f'<h2>{_icon("lock", 14)}Tier 1 &ndash; immutable at runtime</h2>'
        + _note(
            "These boundaries come from <code>toolkits.yaml</code> and cannot be "
            "edited here, by anyone, at any time. Changing them requires a "
            "redeploy (FR-4.11) &ndash; that is what makes every tool below safe "
            "to create from a web form.",
            icon="lock",
        )
    )
    for name, tk in sorted(service.tier1.toolkits.items()):
        parts.append(
            '<div class="card">'
            f'<div class="card-head"><span class="name mono">{_e(name)}</span>'
            f'<span class="pill accent">{_icon("server", 12)}{_e(tk.executor)}</span></div>'
            '<div class="rows">'
            f'<div class="row"><div class="row-l">{_icon("chip", 14)}Binaries</div>'
            f"<div>{_pills(tk.binaries)}</div></div>"
            f'<div class="row"><div class="row-l">{_icon("ban", 14)}Denied arguments</div>'
            f"<div>{_pills(tk.denied_args, tone='deny')}</div></div>"
            f'<div class="row"><div class="row-l">{_icon("folder", 14)}Path roots</div>'
            f"<div>{_pills(tk.path_roots)}</div></div>"
            f'<div class="row"><div class="row-l">{_icon("lock", 14)}Protected resources</div>'
            f"<div>{_pills(tk.protected_resources, tone='deny')}</div></div>"
            f'<div class="row"><div class="row-l">{_icon("gauge", 14)}Ceilings</div>'
            f'<div>{_pills([f"timeout {tk.max_timeout_seconds}s", f"output {tk.max_output_bytes} B"])}</div></div>'
            "</div></div>"
        )

    limits = "".join(
        f"<tr><td><code>{_e(cat)}</code></td>"
        f"<td class='mono'>{lim.count}</td><td class='mono'>{lim.window_seconds} s</td></tr>"
        for cat, lim in sorted(service.tier1.rate_limits.items())
    )
    parts.append(
        f'<h2>{_icon("gauge", 14)}Rate limits</h2>'
        '<div class="card wrap"><table>'
        "<thead><tr><th>Category</th><th>Calls</th><th>Window</th></tr></thead>"
        f"<tbody>{limits}</tbody></table></div>"
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
    rows = []
    for tool in sorted(service.catalog.tools.values(), key=lambda t: t.id):
        callers = sorted(i.id for i in identities.identities.values() if tool.id in i.tools)
        marks = [
            f'<span class="pill {"ok" if tool.category == "read" else "warn"}">'
            f"{_e(tool.category)}</span>",
            '<span class="pill">idempotent</span>'
            if tool.idempotent
            else '<span class="pill deny">not idempotent</span>',
        ]
        if not tool.enabled:
            marks.append('<span class="pill deny">disabled</span>')

        ops = ""
        if session.can_write and store is not None:
            fields = {"id": tool.id, "rev": rev}
            ops = (
                f'<a class="btn" title="Edit" '
                f'href="{UI_PREFIX}/tools/edit?id={_e(tool.id)}">{_icon("pencil", 14)}</a>'
                + _post_button(
                    f"{UI_PREFIX}/tools/toggle",
                    "Disable" if tool.enabled else "Enable",
                    "power",
                    session,
                    fields={**fields, "enabled": "0" if tool.enabled else "1"},
                )
                + f'<a class="btn" title="Delete" '
                f'href="{UI_PREFIX}/tools/delete?id={_e(tool.id)}">{_icon("trash", 14)}</a>'
            )

        rows.append(
            f'<tr class="{"t-ok" if tool.category == "read" else "t-warn"}">'
            f'<td><div class="mono tool-id">{_e(tool.id)}</div>'
            f'<div class="muted">{_e(tool.title)}</div>'
            f'<div class="pills">{"".join(marks)}</div></td>'
            f'<td><span class="mono">{_e(tool.binary)}</span>'
            f'<code class="argv">{_e(" ".join(tool.argv))}</code></td>'
            f"<td>{_param_cell(tool)}</td>"
            f"<td>{_pills(tool.required_scopes, tone='accent')}</td>"
            f"<td class='mono muted'>{tool.timeout_seconds}s<br>{tool.max_output_bytes} B</td>"
            "<td>"
            + (_pills(callers) if callers else '<span class="pill deny">nobody</span>')
            + "</td>"
            + (f'<td class="ops">{ops}</td>' if session.can_write else "")
            + "</tr>"
        )

    if not rows and not service.tier1.toolkits:
        return _no_toolkits_note()

    if not rows:
        # Der Normalzustand nach der Installation. Eine leere Tabelle waere
        # hier eine Sackgasse -- sie sagt nicht, ob etwas fehlt oder ob so
        # gedacht ist.
        hint = (
            f'<p><a class="btn primary" href="{UI_PREFIX}/tools/new">'
            f'{_icon("plus", 14)}Create the first tool</a></p>'
            if session.can_write and store is not None
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

    head_ops = "<th>Actions</th>" if session.can_write else ""
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
    return (
        broken
        + '<div class="card wrap"><table><thead><tr>'
        "<th>Tool</th><th>Execution</th><th>Parameters</th><th>Scopes</th>"
        f"<th>Ceilings</th><th>Granted to</th>{head_ops}"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


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
        # Zwei Nachweise, zwei Anzeigen: der Token oeffnet /mcp, das Passwort
        # die Konsole. Wer nur die Rolle sieht, haelt einen `admin` ohne
        # Passwort faelschlich fuer einen Zugang.
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
            # Agentendaten. json.dumps macht daraus einen String, _e macht ihn
            # unschaedlich -- in dieser Reihenfolge.
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


# -- Views: schreiben ------------------------------------------------------

def _tool_scaffold(service: Service) -> str:
    """Geruest fuer eine neue Definition, aus der echten Ebene 1 gebaut.

    Frueher stand hier ein fertiges Docker-Tool mit fremden Pfaden. Das war
    doppelt falsch: es sah aus wie eine Voreinstellung, und auf einem System
    ohne dieses Toolkit liess es sich nicht einmal speichern. Das Geruest nimmt
    jetzt das erste konfigurierte Toolkit und dessen tatsaechliche Werte -- es
    ist damit auf jedem Deployment ein gueltiger Ausgangspunkt.
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
    """Was zu tun ist, wenn Ebene 1 leer ist.

    Der Zustand nach `init`. Er ist erklaerungsbeduerftig, weil er sich nicht
    hier beheben laesst -- und das ist keine Luecke, sondern der Kern des
    Entwurfs: was moeglich sein soll, entscheidet der Deploy, nicht die
    laufende Oberflaeche.
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
    """Die Grenzen neben dem Editor -- nicht als Zierde.

    Wer ein Tool schreibt, muss wissen, welche Binaries erlaubt sind und welche
    Argumente gesperrt. Steht das nicht daneben, wird der Editor zum Ratespiel
    mit Fehlermeldung.
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
            f'<div>{_pills([f"timeout &le; {tk.max_timeout_seconds}s", f"output &le; {tk.max_output_bytes} B"])}</div>'
            "</div></div></div>"
        )
    return "".join(cards)


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
    """Selbstbedienung: das eigene Konsolenpasswort aendern.

    Auch ein `viewer` kommt hier hinein, obwohl er sonst nichts schreiben
    darf. Das ist kein Loch in der Rollentrennung: geaendert wird
    ausschliesslich das eigene Passwort, und ein Zugang, dessen Passwort nur
    ein anderer wechseln kann, wird nie gewechselt.
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
        f'<textarea name="scopes" rows="4" style="min-height:6rem" spellcheck="false">'
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
    """Die Anmeldung: Kennung und Passwort, nicht der API-Token.

    Das Feld hiess frueher `token`, und genau das war der Fehler: derselbe
    Nachweis oeffnete `/mcp` und die Konsole, und er musste dafuer durch eine
    Zwischenablage und einen Browser-Passwortspeicher wandern (FR-11.5). Wer
    hier einen Token eintippt, kommt nicht mehr hinein -- der Hinweis unter
    dem Formular sagt das, bevor jemand es dreimal versucht.
    """
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Sign in - gatekeeper</title>"
        f'<style nonce="{nonce}">{_STYLE}</style></head><body>'
        '<main class="login"><div class="card"><div class="pad">'
        f'<div class="mark">{_icon("shield", 24)}</div>'
        "<h1>gatekeeper</h1>"
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
        "</div></div></main></body></html>"
    )


def build_ui_routes(
    *,
    service: Service,
    identities: IdentityStore,
    audit: AuditLog,
    store: ConfigStore | None = None,
    sessions: SessionStore | None = None,
    throttle: LoginThrottle | None = None,
) -> list[Route]:
    """Baut die UI-Routen.

    `store=None` heisst: nur lesen. Jeder Handler prueft die Sitzung selbst,
    jeder schreibende zusaetzlich Rolle und CSRF-Token.
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
    ) -> Response:
        nonce = _nonce()
        return _respond(
            request,
            _page(title, body, session=session, subtitle=subtitle, icon=icon,
                  active=active, nonce=nonce, actions=actions,
                  # Ohne beschreibbare Ebene 2 gibt es keine Kontoseite: sie
                  # koennte nichts als eine Fehlermeldung anbieten.
                  account=store is not None),
            nonce,
            status,
        )

    def guarded(view: Callable[[Request, Session], str], title: str, active: str, *,
                icon: str, subtitle: str = "",
                actions: Callable[[Session], str] | None = None):
        """Bindet einen View an eine gueltige Sitzung.

        Jeder lesende Handler laeuft durch diese Huelle, jeder schreibende
        durch `writer`. `test_ui.py` zaehlt die registrierten Routen ab und
        verlangt fuer jede eine Umleitung ohne Sitzung -- eine kuenftig
        vergessene Absicherung faellt damit im Test auf, nicht im Betrieb.
        """

        async def handler(request: Request) -> Response:
            session = _current(request)
            if session is None:
                return _to_login()
            return _shell(
                request, title, view(request, session), session, icon=icon,
                active=active, subtitle=subtitle,
                actions=actions(session) if actions else "",
            )

        return handler

    def _csrf_ok(session: Session, form: FormData) -> bool:
        # Konstante Zeit, damit der Vergleich nichts ueber das Token verraet.
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
            session, icon="ban", active="", status=403,
        )

    def session_post(handler: Callable[[Request, Session, FormData], Any]):
        """Huelle fuer Formulare, die keine Admin-Rolle verlangen.

        Genau eines faellt darunter: das eigene Passwort. Es braucht Sitzung
        und CSRF-Token wie jedes schreibende Formular, aber nicht `admin` --
        sonst koennte ein `viewer` sein Passwort nie wechseln.
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
        """Huelle fuer alles, was schreibt: Sitzung, Rolle, CSRF."""

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
                    session, icon="ban", active="", status=403,
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

    # -- Anmeldung ---------------------------------------------------------

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
        # Die Kennung kommt ungeprueft aus dem Formular und landet gleich im
        # Audit-Log und wieder im Feld. Gekuerzt, damit niemand das Log mit
        # einem Megabyte je Fehlversuch aufblaeht.
        supplied = str(form.get("identity") or "").strip()[:64]
        password = str(form.get("password") or "")
        identity = (
            identities.authenticate_console(supplied, password)
            if supplied and password
            else None
        )

        if identity is None:
            # Die Antwort nennt nie den Grund: ob die Kennung existiert, ob
            # sie eine Konsolenrolle hat oder ob nur das Passwort falsch war,
            # geht den Absender nichts an. Im Log steht es vollstaendig.
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
            # Strict: der Browser schickt das Cookie bei keiner fremdinitiierten
            # Navigation mit. Zusammen mit dem CSRF-Token im Formular und damit,
            # dass /mcp Cookies ohnehin nicht ansieht, bleibt keine Flaeche.
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

    # -- Eigenes Konto -----------------------------------------------------

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
            session, icon="lock", active="",
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
            # Ein falsches aktuelles Passwort ist ein Fehlversuch und gehoert
            # ins Log -- eine offene Sitzung ist die bequemste Stelle, an der
            # jemand ein Passwort raet.
            audit.auth_failure(
                reason="ui_password_change_failed",
                detail=f"identity={session.identity!r}: {exc}",
            )
            return _account_shell(request, session, error=str(exc), status=400)

        # Alle uebrigen Sitzungen dieser Identitaet beenden. Wer sein Passwort
        # wechselt, tut das oft genau deswegen: es soll anderswo nichts mehr
        # offen sein. Die eigene Sitzung bleibt -- sonst waere der Erfolg von
        # einem Rauswurf nicht zu unterscheiden.
        sessions.drop_identity(
            session.identity, keep=request.cookies.get(SESSION_COOKIE)
        )
        return _account_shell(request, session, done=True)

    # -- Tools schreiben ---------------------------------------------------

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
            # Ohne Toolkit gibt es nichts, worauf sich ein Tool stuetzen
            # koennte. Ein leeres Formular anzubieten waere eine Einladung in
            # eine Fehlermeldung.
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
        spec = service.catalog.raw_of(tool_id)
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
        holders = sorted(i.id for i in identities.identities.values() if tool_id in i.tools)
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

    # -- Identitaeten schreiben -------------------------------------------

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
        # Der Klartext wird gerendert, nicht umgeleitet: er darf nirgends in
        # einer URL stehen, wo ihn Verlauf oder Log auffangen wuerden.
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
        # Umbenannt oder aus dem UI ausgesperrt: bestehende Sitzungen der alten
        # Identitaet duerfen nicht weiterlaufen. Ein neues Passwort beendet sie
        # ebenfalls -- sonst bliebe eine uebernommene Sitzung genau dann offen,
        # wenn ein Administrator sie gerade schliessen will.
        locked_out = values["id"] != replaces or values["role"] not in UI_ROLES
        if locked_out or password:
            keep = None
            if not locked_out and replaces == session.identity:
                # Wer sein eigenes Passwort hier setzt, bleibt angemeldet.
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
        # Der alte Token ist tot. Die Konsolensitzung haengt seit der eigenen
        # Anmeldung nicht mehr am Token -- beendet wird sie trotzdem: eine
        # Rotation ist die Antwort auf einen Verdacht, und dann soll von
        # dieser Identitaet nichts offen bleiben. Der Preis ist eine erneute
        # Anmeldung.
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

    # -- Beiwerk -----------------------------------------------------------

    async def root(_request: Request) -> Response:
        return RedirectResponse(f"{UI_PREFIX}/", status_code=303)

    async def favicon(_request: Request) -> Response:
        # Inline-SVG statt 204: der Browser hoert sonst nicht auf zu fragen.
        return Response(
            _FAVICON,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
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
                lambda r, s: _view_overview(service, identities, store),
                "Overview", "", icon="gauge",
                subtitle=(
                    "What actually applies at runtime. The Tier 1 boundaries come "
                    "from <code>toolkits.yaml</code> and cannot change until the "
                    "next redeploy."
                ),
            ),
            methods=["GET"],
        ),
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
        Route(f"{UI_PREFIX}/account", account_form, methods=["GET"]),
        Route(
            f"{UI_PREFIX}/account/password",
            session_post(account_password),
            methods=["POST"],
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
    ]


def has_admin(identities: IdentityStore) -> bool:
    """Gibt es jemanden, der schreiben darf?"""
    return any(i.role == ADMIN_ROLE for i in identities.identities.values())


def has_ui_identity(identities: IdentityStore) -> bool:
    """Gibt es ueberhaupt jemanden, der sich anmelden koennte?

    Rolle *und* Passwort: seit der Konsolenanmeldung ist eine UI-Rolle ohne
    Passwort kein Zugang. Ein Server, der eine Anmeldemaske ausliefert,
    hinter die niemand kommt, ist schlimmer als einer ohne Oberflaeche --
    er sieht benutzbar aus.
    """
    return any(i.can_sign_in for i in identities.identities.values())
