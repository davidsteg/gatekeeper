# Architecture

Project documentation — what the system is and how it's put together. For how
an *agent* should behave while working in this repo (release steps, testing,
pitfalls), see [AGENTS.md](../AGENTS.md). For the full requirements and
rationale behind every design decision, see [REQUIREMENTS.md](../REQUIREMENTS.md).

## Two-tier security model

| Tier | File | Mutable at runtime | Changed via |
|------|------|:--:|-------------|
| 1 | `toolkits.yaml` | ✗ | Redeploy only (FR-4.11) |
| 2 | `tools.yaml`, `identities.yaml`, `credentials.yaml`, `pending.yaml` | ✓ | Admin UI at `/ui`, or `admin.*` on `/admin/mcp` for low-risk changes (queued to `pending.yaml` otherwise -- see below) |

**Key invariant:** `store.py` has no function that writes `toolkits.yaml`. The
console can create tools, identities, and credentials — never a toolkit.

- **Tier 1** defines: which executor a toolkit uses, its allowlist (binaries /
  HTTP target+CIDR / RPC methods), denied args, path roots, protected
  resources, ceilings.
- **Tier 2** defines: the tool catalog, identities and grants, scopes, and
  named credential values.

## Roles

| Role | MCP (`/mcp`) | Admin MCP (`/admin/mcp`) | Console (`/ui`) read | Tier 2 write |
|---|:--:|:--:|:--:|:--:|
| `agent` | ✓ | ✗ | — | — |
| `viewer` | — | ✗ | ✓ | — |
| `admin` | ✗ | ✓ | ✓ | ✓ |

Console login uses the console password, not the API token. The token
authenticates `/mcp`; the password opens `/ui`. Losing one does not expose
the other.

`/admin/mcp` is a second MCP endpoint, isolated by construction (FR-2.8/2.9):
a separate `Server` instance with a hand-written, fixed `admin.*` tool list
that shares no catalog/tool registry with `/mcp`. `AuthMiddleware` role-gates
each mount -- an `admin`-role token is rejected outright on `/mcp`, and every
other role is rejected outright on `/admin/mcp`, so a token never opens the
"wrong" endpoint even in principle. See [`admin_service.py`](../src/gatekeeper/admin_service.py)
for which `admin.*` actions apply immediately versus land in the
`pending.yaml` queue for a human to approve at `/ui/pending` -- `approve`/
`reject` are not reachable from `/admin/mcp` at all, so an agent cannot
approve its own proposal.

## Executors

Every toolkit picks exactly one executor; a tool never chooses its own
(FR-8.1) — it inherits its toolkit's.

| Executor | Reaches | Mechanism |
|---|---|---|
| `docker` | Docker operations | mounted Docker socket, `docker compose ...` |
| `local` | Container-local diagnostics | direct subprocess, allowlisted binaries |
| `http` | LAN/SaaS APIs (Sonarr, Radarr, Home Assistant, pfSense, GitHub, …) | HTTP request; base URL, method, and path prefix come from the toolkit, never a parameter |
| `truenas` | ZFS, pool status, dataset management | JSON-RPC 2.0 over WebSocket (TrueNAS's REST v2.0 is deprecated) |
| `ssh` | A remote Linux host's allowlisted binaries | binary + argv (same shape as `docker`/`local`), run over an SSH exec channel |

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

`ssh` toolkit boundaries: `ssh_host`, `ssh_port`, `ssh_user`,
`ssh_known_hosts` (required — the exact `ssh-keyscan` output pinning the
host key, since an SSH connection with host-key checking disabled is
trivially MITM-able), plus the same `binaries`/`denied_args`/`path_roots`
allowlist `docker`/`local` already use. A tool on an `ssh` toolkit is
shaped identically to one on `docker`/`local` (binary + argv) — the only
difference is that `execute_ssh.py` runs the resolved argv on the remote
host over an SSH exec channel instead of a local subprocess. That channel
is unavoidably shell-interpreted on the server side (RFC 4254's exec
request is a single command string, and essentially every sshd hands it to
the login shell) — `execute_ssh.py` mitigates this the same way a
parameter's regex allowlist does elsewhere, but as defense in depth on top
of it: every argv element is `shlex.quote`d before being joined into that
string. No general "Linux CLI"/arbitrary-command tool exists or is
planned — only fixed, allowlisted binaries per tool, exactly like
`docker`/`local` (REQUIREMENTS.md §17).

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
`bearer`, `basic`, `ws_api_key`, `url_path`, `url_query` (FR-8.14's other
documented exception besides `url_path` — a query-string param, for a
service with no header-auth option at all, e.g. SABnzbd's classic API),
`docker_tls` (a JSON `{cert, key, ca}` bundle for a TLS-secured remote
Docker destination, materialized to a private temp dir by `service.py` on
first use), and `ssh_private_key` (PEM private key text for the `ssh`
executor — the matching public key must already be in the remote host's
`authorized_keys`; gatekeeper is a credential *consumer*, it never pushes
one).

Master key: `GATEKEEPER_CREDENTIAL_KEY` (or `GATEKEEPER_CREDENTIAL_KEY_FILE`
pointing at a mounted secret) — generate one with `gatekeeper credential-key`.
Never generated implicitly, never stored next to the ciphertext.

Masking: known credential values are scrubbed (`***`) out of tool output and
audit log entries via `audit.Redactor`, refreshed whenever a credential is
created or rotated.

## Integrations

`integrations.py` — a small library of starter definitions (toolkit YAML block +
2-4 starter tools + an inline-SVG logo) for 20 services: Sonarr, Radarr,
Jellyfin, Bazarr, Tdarr, Prowlarr, Home Assistant, n8n, Uptime Kuma, Immich,
Telegram, Google API (static-key subset), TrueNAS, pfSense, Jellystat,
Netdata, SABnzbd, Paperless-ngx, Docker, and Linux-over-SSH. Most are
`http`-shaped; Docker reuses the `docker` executor's own toolkit/tool shape
(binaries/denied_args/path_roots, mirroring `config/examples/toolkits.yaml`)
and Linux reuses the `ssh` executor's, via `_tool_argv()` rather than the
http-shaped `_tool()` helper. Reachable from `/ui/tools/integrations` —
picking an integration's tool pre-fills the *existing* tool editor, then
goes through the exact same Tier 1 validation as hand-written YAML.
Integrations never create a toolkit; `/ui/toolkits/reference` (or
`gatekeeper integration show <key>`) prints the YAML block for a human to
paste into `toolkits.yaml` by hand.

Logos are each service's real mark (not a generic monogram), sourced from
[homarr-labs/dashboard-icons](https://github.com/homarr-labs/dashboard-icons)
(Apache License 2.0, attributed in `integrations.py`'s `_BRAND_LOGOS`) —
Tdarr and Jellystat are the two exceptions (Jellystat's only available mark
there turned out to be a raster PNG wrapped in an `<image>` tag, rejected
by the same "no embedded bitmap" rule as an external one), and fall back to
a plain colored-circle monogram. Every fetched SVG has its `style=""`
attributes and any `<style>` block resolved into plain presentation
attributes (`fill="#hex"`, not CSS) and its ids/classes namespaced per
integration: the console's CSP (`style-src 'nonce-...'`) silently drops any
`style` it doesn't carry the nonce for, and the gallery renders every logo
on one page at once, so an unnamespaced id or class in one service's SVG
can collide with another's.

No OAuth2 — the `http` executor supports static credentials only (bearer,
API-key header, basic). Services that require an authorization-code flow are
out of scope for their integration (documented per-integration in `Integration.notes`).

## Project structure

```
src/gatekeeper/
  __init__.py       __version__, derived from pyproject.toml at import
                      time -- never a second hardcoded string to drift
  __main__.py        Entry point: CLI (serve/check/init/token/password/
                      credential-key/integration), bootstrap, SIGHUP handler
  server.py           MCP protocol, ASGI middleware, health/metrics routes;
                       composes /mcp and /admin/mcp into one Starlette app
                       with a combined lifespan (two independent
                       StreamableHTTPSessionManagers, one per Server)
  _authctx.py          Shared "identity out of the MCP request context"
                       helper -- used by server.py and admin_server.py so
                       neither imports the other
  admin_server.py      The `admin.*` MCP surface -- a second, fixed-tool-list
                       Server wired to AdminService, sharing no catalog/tool
                       registry with the agent-facing one (FR-2.8/2.9)
  admin_service.py     Dispatch for every admin.* action: read-only /
                       always-auto-apply / always-pending / category-
                       conditional (tool_enable, tool_update). approve/reject
                       are not methods here and not reachable from
                       /admin/mcp -- see pending.py
  pending.py            The pending-actions queue (pending.yaml) an
                       admin-role agent's higher-risk admin.* calls land in;
                       approved only via /ui/pending (human + CSRF)
  service.py          Call pipeline: auth -> authorize -> registry ->
                       validate -> build request -> execute -> audit;
                       dispatches to execute.py / execute_http.py /
                       execute_truenas.py / execute_ssh.py by toolkit.executor
  tier1.py            Immutable deploy-time boundaries from toolkits.yaml
  catalog.py          Tool definitions, validation against Tier 1;
                       append-only version history per tool id (nested
                       `versions:`/`current_version`, FR-3.3) -- a legacy
                       flat tools.yaml entry loads as an implicit version 1
  validate.py         Parameter validation, argv/HTTP-request/RPC-call
                       construction (no shell, structured args/requests)
  execute.py           Process execution (docker/local): timeouts, output
                       caps, resource locks
  execute_http.py      The `http` executor: SSRF-safe target resolution,
                       no-redirect-follow, credential-as-header injection
  execute_truenas.py   The `truenas` executor: JSON-RPC 2.0 over WebSocket
  execute_ssh.py        The `ssh` executor: binary+argv over an SSH exec
                       channel, mandatory host-key pinning
  credentials.py       The write-only, encrypted credential store
  integrations.py      Starter toolkit/tool definitions + logos for 20
                       services, used by /ui/tools/integrations
  identity.py          scrypt token hashing, constant-time verify,
                       IdentityStore, roles
  audit.py             JSON Lines audit log with rotation and redaction
  store.py             Tier 2 write access (ConfigStore), atomic file writes;
                       save_tool appends a version (never overwrites),
                       delete_tool soft-deletes (deleted: true, history kept)
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
                         toolkits.yaml (incl. a working http + truenas +
                         ssh entry), tools.yaml
tests/
  test_behaviour.py, test_negative_corpus.py, test_integration_mcp.py,
  test_ui.py, test_ui_admin.py, test_credentials.py, test_execute_http.py,
  test_execute_truenas.py, test_execute_ssh.py, test_integrations.py,
  test_ui_credentials.py, test_ui_integrations.py, test_admin_mcp.py,
  test_catalog_versioning.py, test_pending.py, conftest.py
```

## UI architecture (`ui.py`)

**Script-free by default.** CSP: `default-src 'none'; style-src
'nonce-...'; img-src 'self' data:; form-action 'self'`. Any per-service logo
(integrations) ships as inline SVG in `integrations.py`, never a hotlinked
image. The **one exception** is the interactive access map: the two routes
that render it (Overview and `/ui/access-map`) opt into a nonce-scoped
`script-src`/`connect-src 'self'` (see `_shell`'s `allow_script` param,
`_respond`) for a small vendored JS file, `access-map.js`
(`_ACCESS_MAP_JS`) — never widened beyond those two routes; every other
page still gets no `script-src` at all (enforced by
`test_access_map_scopes_script_src_to_itself` in `test_ui.py`).

Most diagrams are still server-rendered SVG or HTML built with no client
code:
- **Access map** — `_access_graph_data()` on the server serializes the
  identity/toolkit/destination/protected-resource graph (plus live call
  counts from the audit log) to JSON at `/ui/access-map/data`;
  `access-map.js` fetches it and renders a pannable, zoomable SVG
  client-side (wheel/drag/pinch, `+`/`−`/Fit controls), groups nodes into
  clusters past a threshold, and opens a detail side panel on click.
  Embedded directly on Overview and as a larger dedicated page at
  `/ui/access-map` (which also offers a dense identity×toolkit table,
  `_toolkit_access_matrix()`, once past `ACCESS_MAP_TABLE_THRESHOLD` nodes).
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
