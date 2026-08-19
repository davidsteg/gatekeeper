# AGENTS.md — gatekeeper

> **MCP server for controlled host operations.** Agents do not get a shell,
> but a fixed set of validated actions — each with its own token, own
> permissions, and full audit. Two security tiers: Tier 1 (immutable
> deploy-time boundaries) and Tier 2 (runtime-mutable catalog + identities).

## Quick Facts

| | |
|---|---|
| **Repo** | `davidsteg/gatekeeper` |
| **Version** | 0.3.2 (see `pyproject.toml` + `src/gatekeeper/__init__.py`) |
| **Language** | Python 3.12+, no optional dependencies at runtime |
| **Tests** | 156 pytest, 1 skipped — all must pass before push |
| **Local clone** | `/opt/data/gatekeeper` |
| **Container** | `gatekeeper`, port `30221→8080`, image `davidsteg/gatekeeper:latest` |
| **Deploy mounts** | `/mnt/raid/dev/gatekeeper/config → /etc/gatekeeper`, `/mnt/raid/dev/gatekeeper/logs`, `/var/run/docker.sock` |
| **Config host** | `10.10.200.90`, UI at `http://10.10.200.90:30221/ui/` |
| **Container user** | `568:568` (unprivileged), `group_add: 999` (docker.sock GID) |

## Release Workflow (mandatory)

**Every change on `main` is a release.** No batch releases.

1. **Version bump** — `pyproject.toml` + `src/gatekeeper/__init__.py` (both in the same commit)
2. **RELEASE.md** — add section `## <version>` (without `v` prefix), newest first
3. **Commit** — `git commit -m "description (vX.Y.Z)"`
4. **Push** — `git push origin main`
5. **GitHub Action** builds image → push to Docker Hub → tag `vX.Y.Z` → GitHub Release

### Versioning

- **MAJOR** — Tier 1 changes meaning, or existing deployment does not start anymore
- **MINOR** — new toolkits, executors, UI features, new behavior
- **PATCH** — bug fixes, including security-relevant ones

### Git Remote (Token)

The GitHub PAT is embedded in the git remote URL. Set it before pushing:

```bash
# Extract token from memory or existing remote URL
git remote set-url origin "https://<PAT>@github.com/davidsteg/gatekeeper.git"
```

No `gh` CLI needed. Do NOT store the token in files — only in the remote URL.

## Testing

```bash
cd /opt/data/gatekeeper
uv run python -m pytest tests/ -q
```

- 156 tests, ~45s runtime
- No system pip — always use `uv run`
- Target: all green before push

## Project Structure

```
src/gatekeeper/
  __init__.py      __version__ — ALWAYS keep in sync with pyproject.toml
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
  examples/        Ready-made templates: identities.yaml, toolkits.yaml, tools.yaml
tests/
  test_behaviour.py, test_negative_corpus.py, test_integration_mcp.py,
  test_ui.py, test_ui_admin.py, conftest.py
```

## Two-Tier Security Model

| Tier | File | Mutable at runtime | Changed via |
|------|------|:--:|-------------|
| 1 | `toolkits.yaml` | ✗ | Redeploy only (FR-4.11) |
| 2 | `tools.yaml`, `identities.yaml` | ✓ | Admin UI at `/ui` |

**Key invariant:** `store.py` has NO function that writes `toolkits.yaml`. The UI can create tools but never toolkits.

Tier 1 defines: binary allowlist, denied args, path roots, protected resources, ceilings.
Tier 2 defines: tool catalog, identities, grants, scopes.

## Roles

| Role | MCP (`/mcp`) | Console (`/ui`) read | Tier 2 write |
|---|:--:|:--:|:--:|
| `agent` | ✓ | — | — |
| `viewer` | — | ✓ | — |
| `admin` | — | ✓ | ✓ |

Login: console password (not API token). Token belongs to `/mcp`, password to `/ui`.

## UI Architecture (`ui.py`)

**No JavaScript.** CSP: `default-src 'none'; style-src 'nonce-...'; img-src 'self' data:; form-action 'self'`.

All diagrams are server-rendered SVG:
- **Access map** — `_access_graph()`: identities → hub → toolkits/blocked, with call counts from audit log, hover tooltips via `<title>`, hot-edge highlighting
- **Call flow pipeline** — `_call_flow_pipeline()`: 8 layers as horizontal SVG
- **Tool matrix** — `_tool_matrix()`: HTML table, one tool per row
- **Activity chart** — `_activity_chart()`: calls/hour as stacked bars (ok/denied)
- **Activity feed** — `_feed()`: recent calls as timeline

CSS classes for graph: `.graph`, `.g-box`, `.g-t`, `.g-s`, `.g-e`, `.g-node`, `.g-edge-group`, `.g-count`, `.g-n`, `.legend`
CSS classes for chart: `.chart`, `.c-ok`, `.c-deny`, `.c-base`, `.c-ax`

Version is shown in sidebar and login page: `<span class="ver">vX.Y.Z</span>`.

## SIGHUP Reload

```bash
docker kill -s HUP gatekeeper
```

Reloads all three config files atomically. On failure, previous state remains. Rate limiter is reset.

## Deploy (local container)

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

## Known Pitfalls

- **`__init__.py` version drift** — bump both files (`pyproject.toml` + `__init__.py`) in the same commit
- **RELEASE.md merge conflicts** — `git pull --rebase`, keep both sections in chronological order (newest first)
- **No `v` prefix in RELEASE.md** — section headers are `## 0.3.2`, not `## v0.3.2`
- **Stale local clone** — `git fetch origin && git log --oneline origin/main -5` before starting work
- **Docker Hub Secrets** — `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN` must be set in GitHub Repo Settings → Secrets, otherwise image push fails
- **`latest` tag moves** — pin a fixed version for production (NFR-5)
- **`/mnt/raid/misc` is read-only** — `write_file`/`patch` is blocked. Use `terminal` + Python `open().write()`

## Docker Hub Secrets (status: missing)

| Name | Value |
|------|-------|
| `DOCKERHUB_USERNAME` | `davidsteg` |
| `DOCKERHUB_TOKEN` | Docker Hub access token (must be set) |

Without these, the `image` job fails at "Log in to Docker Hub".

## Audit Log Format

JSON Lines, one record per line:
```json
{"kind": "call", "identity": "dev", "tool": "docker_ps", "tool_version": 1, "parameters": {}, "scopes": [], "outcome": "ok", "exit_code": 0, "duration_ms": 42, "ts": "2026-08-16T10:00:00+0000"}
```

Kinds: `call`, `auth_failure`, `startup`, `admin_change`, `ui_login`.
Outcomes for `call`: `ok`, `denied`, `failed`, `unknown` (timeout on non-idempotent).

## What's Next

- **Stage 4 open** — see REQUIREMENTS.md §14
- **`http` executor, `truenas` executor, and the credential store are implemented**
  (`execute_http.py`, `execute_truenas.py`, `credentials.py`) — Sonarr, Radarr,
  Jellyfin, Bazarr, Tdarr, Prowlarr, Home Assistant, n8n, Uptime Kuma, Immich,
  Telegram, Google (static-key subset), and TrueNAS have starter presets in
  `presets.py`, reachable from `/ui/tools/presets`. See `/ui/toolkits/reference`
  or `gatekeeper preset show <key>` for the toolkit YAML to add.
- **OAuth2** — not implemented; the `http` executor supports static credentials
  only (FR-8.11). Google APIs that require OAuth (Calendar, Gmail, Drive, …)
  are out of scope for the `google_api` preset.
- **`ssh` executor** — optional per §17, not implemented
- **TrueNAS SCRAM-SHA-512 mutual auth** — API-key auth is implemented; SCRAM
  is TrueNAS 26's preferred alternative and remains a follow-up