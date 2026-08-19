# Architecture

Project documentation — what the system is and how it's put together. For how
an *agent* should behave while working in this repo (release steps, testing,
pitfalls), see [AGENTS.md](../AGENTS.md). For the full requirements and
rationale behind every design decision, see [REQUIREMENTS.md](../REQUIREMENTS.md).

## Two-tier security model

| Tier | File | Mutable at runtime | Changed via |
|------|------|:--:|-------------|
| 1 | `toolkits.yaml` | ✗ | Redeploy only (FR-4.11) |
| 2 | `tools.yaml`, `identities.yaml`, `credentials.yaml` | ✓ | Admin UI at `/ui` |

**Key invariant:** `store.py` has no function that writes `toolkits.yaml`. The
console can create tools, identities, and credentials — never a toolkit.

- **Tier 1** defines: which executor a toolkit uses, its allowlist (binaries /
  HTTP target+CIDR / RPC methods), denied args, path roots, protected
  resources, ceilings.
- **Tier 2** defines: the tool catalog, identities and grants, scopes, and
  named credential values.

## Roles

| Role | MCP (`/mcp`) | Console (`/ui`) read | Tier 2 write |
|---|:--:|:--:|:--:|
| `agent` | ✓ | — | — |
| `viewer` | — | ✓ | — |
| `admin` | — | ✓ | ✓ |

Console login uses the console password, not the API token. The token
authenticates `/mcp`; the password opens `/ui`. Losing one does not expose
the other.

## Executors

Every toolkit picks exactly one executor; a tool never chooses its own
(FR-8.1) — it inherits its toolkit's.

| Executor | Reaches | Mechanism |
|---|---|---|
| `docker` | Docker operations | mounted Docker socket, `docker compose ...` |
| `local` | Container-local diagnostics | direct subprocess, allowlisted binaries |
| `http` | LAN/SaaS APIs (Sonarr, Radarr, Home Assistant, GitHub, …) | HTTP request; base URL, method, and path prefix come from the toolkit, never a parameter |
| `truenas` | ZFS, pool status, dataset management | JSON-RPC 2.0 over WebSocket (TrueNAS's REST v2.0 is deprecated) |

`http` toolkit boundaries (`tier1.py`'s `Toolkit`): `base_url`,
`allowed_methods`, `allowed_path_prefixes`, `allowed_cidrs`, `credential`,
`follow_redirects` (always `false` — not a configurable knob, FR-8.8).
`execute_http.py` resolves the target host itself and checks the resolved IP
against `allowed_cidrs` immediately before connecting — a hostname-only check
would leave a DNS-rebinding gap between the check and the actual connect.

`truenas` toolkit boundaries: `ws_url`, `allowed_rpc_methods`, `credential`.
The whitelist acts on JSON-RPC method *names* — a method not listed
structurally does not exist for any tool, there is no separate "permission"
to deny it (`execute_truenas.py`).

## Credential store

`credentials.py` — named, encrypted-at-rest secrets a toolkit references by
name via its (Tier 1) `credential:` field. **Write-only**: create, rotate,
delete — no operation, for no role, ever returns a value (FR-10.2). The
*binding* of toolkit → credential name is Tier 1 (redeploy-only); the
credential *value* is Tier 2 (rotatable at runtime, with an optional overlap
window so in-flight calls with the old value don't break).

Master key: `GATEKEEPER_CREDENTIAL_KEY` (or `GATEKEEPER_CREDENTIAL_KEY_FILE`
pointing at a mounted secret) — generate one with `gatekeeper credential-key`.
Never generated implicitly, never stored next to the ciphertext.

Masking: known credential values are scrubbed (`***`) out of tool output and
audit log entries via `audit.Redactor`, refreshed whenever a credential is
created or rotated.

## Presets

`presets.py` — a small library of starter definitions (toolkit YAML block +
2-3 starter tools + an inline-SVG logo) for common services: Sonarr, Radarr,
Jellyfin, Bazarr, Tdarr, Prowlarr, Home Assistant, n8n, Uptime Kuma, Immich,
Telegram, Google API (static-key subset), TrueNAS. Reachable from
`/ui/tools/presets` — picking a preset's tool pre-fills the *existing* tool
editor, then goes through the exact same Tier 1 validation as hand-written
YAML. Presets never create a toolkit; `/ui/toolkits/reference` (or
`gatekeeper preset show <key>`) prints the YAML block for a human to paste
into `toolkits.yaml` by hand.

No OAuth2 — the `http` executor supports static credentials only (bearer,
API-key header, basic). Services that require an authorization-code flow are
out of scope for their preset (documented per-preset in `Preset.notes`).

## Project structure

```
src/gatekeeper/
  __init__.py       __version__ -- keep in sync with pyproject.toml
  __main__.py        Entry point: CLI (serve/check/init/token/password/
                      credential-key/preset), bootstrap, SIGHUP handler
  server.py           MCP protocol, ASGI middleware, health/metrics routes
  service.py          Call pipeline: auth -> authorize -> registry ->
                       validate -> build request -> execute -> audit;
                       dispatches to execute.py / execute_http.py /
                       execute_truenas.py by toolkit.executor
  tier1.py            Immutable deploy-time boundaries from toolkits.yaml
  catalog.py          Tool definitions, validation against Tier 1
  validate.py         Parameter validation, argv/HTTP-request/RPC-call
                       construction (no shell, structured args/requests)
  execute.py           Process execution (docker/local): timeouts, output
                       caps, resource locks
  execute_http.py      The `http` executor: SSRF-safe target resolution,
                       no-redirect-follow, credential-as-header injection
  execute_truenas.py   The `truenas` executor: JSON-RPC 2.0 over WebSocket
  credentials.py       The write-only, encrypted credential store
  presets.py           Starter toolkit/tool definitions + logos for common
                       services, used by /ui/tools/presets
  identity.py          scrypt token hashing, constant-time verify,
                       IdentityStore, roles
  audit.py             JSON Lines audit log with rotation and redaction
  store.py             Tier 2 write access (ConfigStore), atomic file writes
  _atomic.py           Shared atomic-write/revision helpers (store.py and
                       credentials.py both use these, independently)
  ui.py                Operations console at /ui -- no JavaScript,
                       CSP-locked, server-rendered SVG diagrams
  errors.py            DenialReason enum, opaque denial for catalog info
  ratelimit.py         Per-identity, per-category sliding window limiter
config/
  toolkits.yaml         Tier 1 -- immutable at runtime
  tools.yaml             Seed catalog -- mutable via UI
  examples/               Ready-made templates: identities.yaml,
                         toolkits.yaml (incl. a working http + truenas
                         entry), tools.yaml
tests/
  test_behaviour.py, test_negative_corpus.py, test_integration_mcp.py,
  test_ui.py, test_ui_admin.py, test_credentials.py, test_execute_http.py,
  test_execute_truenas.py, test_presets.py, test_ui_credentials.py,
  test_ui_presets.py, conftest.py
```

## UI architecture (`ui.py`)

**No JavaScript.** CSP: `default-src 'none'; style-src 'nonce-...';
img-src 'self' data:; form-action 'self'`. Any per-service logo (presets)
ships as inline SVG in `presets.py`, never a hotlinked image.

All diagrams are server-rendered SVG:
- **Access map** — `_access_graph()`: identities -> hub -> toolkits/blocked,
  call counts from the audit log, hover tooltips via `<title>`
- **Call flow pipeline** — `_call_flow_pipeline()`: the layers a request
  passes, as a horizontal SVG
- **Tool matrix** — `_tool_matrix()`: HTML table, one tool per row
- **Activity chart** — `_activity_chart()`: calls/hour as stacked bars
- **Activity feed** — `_feed()`: recent calls as a timeline

## Audit log format

JSON Lines, one record per line:
```json
{"kind": "call", "identity": "dev", "tool": "docker.compose_ps", "tool_version": 1, "parameters": {}, "scopes": [], "outcome": "ok", "exit_code": 0, "duration_ms": 42, "ts": "2026-08-16T10:00:00+0000"}
```

Kinds: `call`, `auth_failure`, `startup`, `admin_change`, `admin_denied`,
`ui_login`. Outcomes for `call`: `ok`, `denied`, `failed`, `unknown`
(timeout on a non-idempotent tool — the operation may have completed on the
other side, so it is not reported as a failure that would provoke a retry).

## Roadmap / known gaps

See [ROADMAP.md](ROADMAP.md).
