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

### Destinations (multi-host per toolkit)

A `docker`/`http`/`truenas` toolkit may declare several named **destinations**
in `toolkits.yaml` (Tier 1, FR-8.3g) — each just a connection target
(`docker_host`, `base_url`, or `ws_url`) plus an optional credential
override; every other boundary (binaries, denied args, path roots, allowed
methods/CIDRs, limits) stays on the toolkit and is identical across all its
destinations (FR-4.9 — those answer "what," not "where"). At catalog-load
time, a tool defined against such a toolkit expands into one
independently-grantable ID per destination — `docker.compose_up` becomes
`docker.compose_up@nas1` and `docker.compose_up@nas2` — with no change to
how grants work (FR-8.3h). The agent can never select or influence which
destination a call reaches: it's fixed in the tool ID itself at deploy/load
time, the same principle as `http`'s "scheme and host live exclusively in
the toolkit" (FR-8.3i extends FR-8.7). A toolkit with no `destinations`
behaves exactly as before this existed (FR-8.3j).

## Credential store

`credentials.py` — named, encrypted-at-rest secrets a toolkit (or one of its
destinations, overriding the toolkit's own) references by name via a
`credential:` field. **Write-only**: create, rotate, delete — no operation,
for no role, ever returns a value (FR-10.2). The *binding* of toolkit/
destination → credential name is Tier 1 (redeploy-only); the credential
*value* is Tier 2 (rotatable at runtime, with an optional overlap window so
in-flight calls with the old value don't break). Kinds: `api_key_header`,
`bearer`, `basic`, `ws_api_key`, `url_path`, and `docker_tls` (a JSON
`{cert, key, ca}` bundle for a TLS-secured remote Docker destination,
materialized to a private temp dir by `service.py` on first use).

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

Logos are each service's real mark (not a generic monogram), sourced from
[homarr-labs/dashboard-icons](https://github.com/homarr-labs/dashboard-icons)
(Apache License 2.0, attributed in `presets.py`'s `_BRAND_LOGOS`) — Tdarr is
the one exception, with no usable SVG found there, and falls back to a
plain colored-circle monogram. Every fetched SVG has its `style=""`
attributes and any `<style>` block resolved into plain presentation
attributes (`fill="#hex"`, not CSS) and its ids/classes namespaced per
preset: the console's CSP (`style-src 'nonce-...'`) silently drops any
`style` it doesn't carry the nonce for, and the gallery renders every logo
on one page at once, so an unnamespaced id or class in one service's SVG
can collide with another's.

No OAuth2 — the `http` executor supports static credentials only (bearer,
API-key header, basic). Services that require an authorization-code flow are
out of scope for their preset (documented per-preset in `Preset.notes`).

## Project structure

```
src/gatekeeper/
  __init__.py       __version__, derived from pyproject.toml at import
                      time -- never a second hardcoded string to drift
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

The version badge (sidebar and login page) is a link into a **release-notes
popup** (`_release_notes_modal()`): a pure-CSS modal using the `:target`
selector, no JavaScript needed to open/close it. Content comes from
`RELEASE.md`, parsed by `_parse_release_notes()`/`_render_release_body()`
(only `## <version>` headings start a new entry; bold/inline-code render,
everything else is escaped). The file ships inside the container image
(`GATEKEEPER_RELEASE_NOTES`, default `/usr/share/gatekeeper/RELEASE.md`) or
is found next to `pyproject.toml` in a dev checkout.

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
