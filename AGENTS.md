# AGENTS.md — gatekeeper

> **MCP-Server für kontrollierte Host-Operationen.** Agenten bekommen keine Shell,
> sondern eine feste Menge geprüfter Aktionen — jede mit eigenem Token, eigenen
> Rechten und vollständigem Audit. Zwei Sicherheitsebenen: Tier 1 (immutable
> Deploy-Grenzen) und Tier 2 (laufzeitveränderlicher Katalog + Identitäten).

## Quick Facts

| | |
|---|---|
| **Repo** | `davidsteg/gatekeeper` |
| **Version** | 0.3.2 (siehe `pyproject.toml` + `src/gatekeeper/__init__.py`) |
| **Sprache** | Python 3.12+, keine optionalen Abhängigkeiten im Betrieb |
| **Tests** | 156 pytest, 1 skipped — alle müssen grün vor Push |
| **Lokaler Klone** | `/opt/data/gatekeeper` |
| **Container** | `gatekeeper`, Port `30221→8080`, Image `davidsteg/gatekeeper:latest` |
| **Deploy-Mounts** | `/mnt/raid/dev/gatekeeper/config → /etc/gatekeeper`, `/mnt/raid/dev/gatekeeper/logs`, `/var/run/docker.sock` |
| **Config-Host** | `10.10.200.90`, UI unter `http://10.10.200.90:30221/ui/` |
| **Container-User** | `568:568` (unprivilegiert), `group_add: 999` (docker.sock GID) |

## Release-Workflow (verbindlich)

**Jede Änderung auf `main` ist ein Release.** Keine Sammel-Releases.

1. **Version bump** — `pyproject.toml` + `src/gatekeeper/__init__.py` (beide im selben Commit)
2. **RELEASE.md** — Abschnitt `## <version>` (ohne `v`-Präfix), newest first
3. **Commit** — `git commit -m "description (vX.Y.Z)"`
4. **Push** — `git push origin main`
5. **GitHub Action** baut Image → push nach Docker Hub → tag `vX.Y.Z` → GitHub Release

### Versionierung

- **MAJOR** — Tier 1 ändert Bedeutung, oder bestehendes Deployment startet nicht mehr
- **MINOR** — neue Toolkits, Executoren, UI-Features, neues Verhalten
- **PATCH** — Bugfixes, auch sicherheitsrelevante

### Git-Remote (Token)

Der GitHub PAT ist in der git remote URL eingebettet. Vor dem Push setzen:

```bash
# Token aus Memory oder bestehender remote URL extrahieren
git remote set-url origin "https://<PAT>@github.com/davidsteg/gatekeeper.git"
```

Kein `gh` CLI nötig. Token NICHT in Dateien speichern — nur in der remote URL.

## Testing

```bash
cd /opt/data/gatekeeper
uv run python -m pytest tests/ -q
```

- 156 Tests, ~45s Laufzeit
- Keine System-pip — immer `uv run`
- Target: alle grün vor Push

## Projektstruktur

```
src/gatekeeper/
  __init__.py      __version__ — IMMER mit pyproject.toml synchron halten
  __main__.py      Entry point: CLI (serve/check/token/init/password), SIGHUP handler
  server.py        MCP protocol, ASGI middleware, health/metrics routes, CSP headers
  service.py       Call pipeline: auth→authorize→registry→validate→argv→exec→audit
  tier1.py         Immutable deploy-time boundaries from toolkits.yaml (Tier 1)
  catalog.py       Tool definitions, validation against Tier 1
  validate.py      Parameter validation, argv construction (NO shell, structured args)
  execute.py       Process execution, timeouts, output caps, resource locks
  identity.py      scrypt token hashing, constant-time verify, IdentityStore, roles
  audit.py         JSON Lines audit log with rotation and redaction
  store.py         Tier 2 write access (ConfigStore), atomic file writes
  ui.py            Operations console at /ui — no JavaScript, CSP-locked, SVG diagrams
  errors.py        DenialReason enum, opaque denial for catalog info
  ratelimit.py     Per-identity, per-category sliding window rate limiter
config/
  toolkits.yaml    Tier 1 — immutable at runtime (binary allowlist, denied args, path roots, protected resources, ceilings)
  tools.yaml       Seed catalog — mutable via UI
  identities.example.yaml
  examples/        Fertige Vorlagen: identities.yaml, toolkits.yaml, tools.yaml
tests/
  test_behaviour.py, test_negative_corpus.py, test_integration_mcp.py,
  test_ui.py, test_ui_admin.py, conftest.py
```

## Zwei-Ebenen-Sicherheitsmodell

| Tier | File | Mutable at runtime | Changed via |
|------|------|:--:|-------------|
| 1 | `toolkits.yaml` | ✗ | Redeploy only (FR-4.11) |
| 2 | `tools.yaml`, `identities.yaml` | ✓ | Admin UI at `/ui` |

**Key invariant:** `store.py` hat KEINE Funktion die `toolkits.yaml` schreibt. Die UI kann Tools anlegen aber niemals Toolkits.

Tier 1 definiert: binary allowlist, denied args, path roots, protected resources, ceilings.
Tier 2 definiert: tool catalog, identities, grants, scopes.

## Rollen

| Rolle | MCP (`/mcp`) | Konsole (`/ui`) lesen | Tier 2 ändern |
|---|:--:|:--:|:--:|
| `agent` | ✓ | — | — |
| `viewer` | — | ✓ | — |
| `admin` | — | ✓ | ✓ |

Login: Console-Password (nicht API-Token). Token gehört zu `/mcp`, Passwort zu `/ui`.

## UI-Architektur (`ui.py`)

**Kein JavaScript.** CSP: `default-src 'none'; style-src 'nonce-...'; img-src 'self' data:; form-action 'self'`.

Alle Diagramme sind server-rendered SVG:
- **Access map** — `_access_graph()`: Identitäten → Hub → Toolkits/Blocked, mit Call-Counts aus Audit-Log, Hover-Tooltips via `<title>`, hot-edge highlighting
- **Call flow pipeline** — `_call_flow_pipeline()`: 8 Schichten als horizontales SVG
- **Tool matrix** — `_tool_matrix()`: HTML-Tabelle, ein Tool pro Zeile
- **Activity chart** — `_activity_chart()`: Calls/Stunde als gestapelte Balken (ok/denied)
- **Activity feed** — `_feed()`: Letzte Aufrufe als Timeline

CSS-Klassen für Graph: `.graph`, `.g-box`, `.g-t`, `.g-s`, `.g-e`, `.g-node`, `.g-edge-group`, `.g-count`, `.g-n`, `.legend`
CSS-Klassen für Chart: `.chart`, `.c-ok`, `.c-deny`, `.c-base`, `.c-ax`

Version wird in Sidebar und Login-Seite angezeigt: `<span class="ver">vX.Y.Z</span>`.

## SIGHUP Reload

```bash
docker kill -s HUP gatekeeper
```

Lädt alle drei Config-Dateien atomar neu. Bei Fehler bleibt alter Zustand. Rate-Limiter wird zurückgesetzt.

## Deploy (lokaler Container)

```bash
# Pull + recreate
docker pull davidsteg/gatekeeper:latest
docker kill gatekeeper && docker rm gatekeeper
docker run -d \
  --name gatekeeper \
  --user 568:568 \
  --group-add 999 \
  --restart unless-stopped \
  -p 30221:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:rw \
  -v /mnt/raid/dev/gatekeeper/config:/etc/gatekeeper:rw \
  -v /mnt/raid:/mnt/raid:rw \
  -v /mnt/raid/dev/gatekeeper/logs:/mnt/raid/dev/gatekeeper/logs:rw \
  -e GATEKEEPER_LOG_LEVEL=INFO \
  davidsteg/gatekeeper:latest serve --ui
```

## Bekannte Pitfalls

- **`__init__.py` version drift** — beide Files (`pyproject.toml` + `__init__.py`) im selben Commit bumpen
- **RELEASE.md merge conflicts** — `git pull --rebase`, beide Sektionen in chronologischer Reihenfolge halten (newest first)
- **Kein `v`-Präfix in RELEASE.md** — Sektion headers sind `## 0.3.2`, nicht `## v0.3.2`
- **Stale local clone** — `git fetch origin && git log --oneline origin/main -5` vor Arbeitsbeginn
- **Docker Hub Secrets** — `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN` müssen in GitHub Repo Settings → Secrets gesetzt sein, sonst schlägt Image-Push fehl
- **`latest` tag bewegt sich** — für Betrieb feste Version pinnen (NFR-5)
- **`/mnt/raid/misc` ist read-only** — `write_file`/`patch` blockiert. `terminal` + Python `open().write()` nutzen

## Docker Hub Secrets (Status: fehlend)

| Name | Wert |
|------|-------|
| `DOCKERHUB_USERNAME` | `davidsteg` |
| `DOCKERHUB_TOKEN` | Docker Hub access token (muss gesetzt werden) |

Ohne diese schlägt der `image` Job bei "Log in to Docker Hub" fehl.

## Audit-Log Format

JSON Lines, ein Record pro Zeile:
```json
{"kind": "call", "identity": "dev", "tool": "docker_ps", "tool_version": 1, "parameters": {}, "scopes": [], "outcome": "ok", "exit_code": 0, "duration_ms": 42, "ts": "2026-08-16T10:00:00+0000"}
```

Kinds: `call`, `auth_failure`, `startup`, `admin_change`, `ui_login`.
Outcomes für `call`: `ok`, `denied`, `failed`, `unknown` (timeout bei nicht-idempotent).

## Was als nächstes ansteht

- **Stage 2+4 offen** — siehe REQUIREMENTS.md §14
- **ZFS und TrueNAS-API** — brauchen `truenas`-Executor
- **Dienst-APIs** (Sonarr/Radarr/Jellyfin) — brauchen `http`-Executor + Credential-Store
- **`write_external`** — noch nicht implementiert
- **Credential-Store** — für Secret-Masking in Container-Logs