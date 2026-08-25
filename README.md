# gatekeeper

**A controlled MCP server for host operations.** Agents get a curated set of safe, audited actions instead of a shell. Each tool has its own token, granular permissions, and full audit trail.

→ [Full requirements](REQUIREMENTS.md) | [Architecture](docs/ARCHITECTURE.md) | [Deployment](docs/DEPLOYMENT.md) | [Roadmap](docs/ROADMAP.md) | [For agents](AGENTS.md) | [Release notes](RELEASE.md)

---

## What it does

Imagine you want an AI agent to safely operate Docker stacks on your homelab. Giving it shell access is too risky. gatekeeper sits in the middle:

- **Agent requests** `docker.compose_up` for a specific stack
- **gatekeeper checks**: Does this agent have permission? Is the stack name valid? Is the resource protected?
- **gatekeeper executes** the exact command, never a shell
- **Everything is logged** with who did what, when, and why

No shell injection. No command confusion. No hidden side effects.

### Key guarantees

- **No shell interpreter** — only safe argv-based execution
- **Two-tier config** — deploy-time safety (Tier 1) + runtime flexibility (Tier 2)
- **Granular permissions** — per-tool, per-identity, scoped by resource
- **Complete audit trail** — every call logged, even the rejected ones
- **Empty on install** — nothing ships preconfigured; every capability is an audited decision
- **Not just local commands** — `http`, `truenas`, and `ssh` executors reach outside
  APIs and remote hosts the same way, with SSRF-safe target checks, mandatory SSH
  host-key pinning, and secrets kept in a write-only credential store; see
  [Integrations](#integrations-add-sonarr-pfsense-and-18-others-without-writing-yaml) below

---

## Quick start

```bash
# Development
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q

# Validate config without starting
gatekeeper --toolkits config/toolkits.yaml --tools config/tools.yaml \
  --identities config/identities.yaml check
```

---

## The console UI

Once started with `--ui`, gatekeeper hosts an admin dashboard at `/ui` where you:

- **View access** — who can call what, which resources are protected
- **Manage tools** — add, edit, enable/disable without restarting
- **Grant permissions** — link identities to tools with scopes
- **Monitor audit log** — search activity, track denials, find mistakes
- **See statistics** — aggregate call stats, success rates, latency, admin activity at `/ui/stats`
- **Change passwords** — rotate console access for people

### Overview: At a glance

![](.readme-assets/overview.png)

**Left column:** navigation. **Top row:** counts. **Access map:** which identities reach which toolkits (green=granted, red-dashed=protected). **Call history:** recent activity.

### Tools: Manage the catalog

![](.readme-assets/tools.png)

Toggle between **Cards** (grouped by toolkit, one card per tool with parameters, scopes, and limits) and **Matrix** (a dense table: status, category, idempotency, and who may call each tool).

Each tool is a template — a fixed action, not a free-form command. For a local binary that's a program path, arguments, and parameter rules; for an HTTP service (see Integrations below) it's a method and path instead, shown as `REQUEST` on the card. Either way the editor shows the Tier 1 limits it has to stay inside, so you know what's allowed before you save. Defining and granting are two steps — a tool with no grantees exists but is invisible to every agent.

### Integrations: add Sonarr, pfSense, and 19 others without writing YAML

![](.readme-assets/integrations.png)

Reaching an outside service (Sonarr, Radarr, Home Assistant, pfSense, n8n, TrueNAS, a plain Linux host over SSH, …) used to mean nothing — gatekeeper could only run local commands and Docker. Now it has `http`, `truenas`, and `ssh` executors alongside `docker`, and a library of 21 starter integrations for common homelab/SaaS services so you don't have to write the request shapes by hand:

```
 1. Pick a card                2. Paste its YAML once           3. Create a tool
 ┌─────────────┐               (deploy-time, one-time)          ┌─────────────┐
 │  So Sonarr   │  ───────►    toolkits.yaml + redeploy  ──────►│ ✓ list_series │
 └─────────────┘               (never done by the console)      └─────────────┘
```

The toolkit itself (which host, which address range, which credential) is still a
deploy-time decision you paste into `toolkits.yaml` by hand and redeploy — the
console can create *tools*, never *toolkits*, on purpose (that boundary is what
keeps a compromised admin session from reaching an address nobody approved).
Once a toolkit exists, picking one of its starter tools drops you straight into
the same editor as above, pre-filled instead of blank — still checked against
the same limits before it's saved.

### Credentials: store a secret without ever showing it again

![](.readme-assets/credentials.png)

Sonarr's API key, a Home Assistant token, TrueNAS's key — each gets a name here, encrypted at rest. After it's saved there is no "view" button anywhere, for any role: create, rotate, and delete are the only three things you can do with it. gatekeeper injects it into the request itself when a tool calls out; it never comes back through the console, the audit log, or a tool's response.

An agent never sees a key and never sends one. It asks for a tool by name; gatekeeper looks up which credential that tool's toolkit is bound to, decrypts it, and attaches it the way the target service expects:

| Kind | How it reaches the request | Typical service |
| --- | --- | --- |
| `api_key_header` | A named header you choose | Sonarr, Radarr, Prowlarr, Bazarr, Jellyseerr (`X-Api-Key`), Jellyfin (`X-Emby-Token`) |
| `bearer` | `Authorization: Bearer …` | Home Assistant, Netdata |
| `basic` | `Authorization: Basic …` (value stored as `user:pass`) | anything with HTTP basic auth |
| `url_query` | A query parameter — the one documented exception, for services with no header option at all | SABnzbd (`?apikey=`) |
| `url_path` | Substituted into the toolkit's `base_url` | Telegram's bot API |
| `ws_api_key` | The JSON-RPC login call, not a header | TrueNAS |
| `docker_tls` | A PEM bundle materialized to a private temp dir | a TLS-secured remote Docker daemon |
| `ssh_private_key` | The key the `ssh` executor authenticates with | Linux-over-SSH |

The binding lives in `toolkits.yaml` (Tier 1, deploy-time) as a single line — `credential: sonarr` — and names the secret, never holds it. The console cannot repoint a toolkit at a different credential, which is why a compromised admin session cannot make one service's key travel to another host.

Two things follow for the audit log. Every call record names the credential it used (`"credentials": ["sonarr"]`) so you know what to rotate after a leak — and the value itself is masked everywhere it could surface: in the record, in the tool's own response before that response reaches the agent, and in any field whose name looks like a secret. Setting up the master key that encrypts all of this is step 1 of [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#credentials-from-zero-to-a-working-call).

An admin agent on `/admin/mcp` can propose a new credential's *name*, *kind*, and *header* (`admin.cred_propose`) — but never a value; the tool has no such parameter, and one sent anyway is refused, not stored. The proposal waits in `/ui/requests` until a human reviews exactly what was proposed and types the secret themselves, the same write-only guarantee as creating one by hand.

### Identities: Manage access

![](.readme-assets/identities.png)

Create agents, viewers, admins. Each gets a token (for `/mcp`) and/or password (for `/ui`). Grant per-tool access with scopes. Change passwords on `/ui/account`. Rotate tokens to force reconnection.

### Audit log: Search activity

![](.readme-assets/audit.png)

Every call logged—granted and denied. Real denial reasons stored, opaque message sent to agent. Search by identity, tool, timestamp. Export for compliance.

---

## Deployment

### 1. Choose storage

```bash
# On TrueNAS/ZFS
zfs create <pool>/raid/gatekeeper
```

### 2. Set up directories

```bash
mkdir -p /mnt/raid/gatekeeper/config /mnt/raid/gatekeeper/logs
chown -R 568:568 /mnt/raid/gatekeeper
```

### 3. Start (first time auto-configures)

```bash
docker compose up -d
docker compose logs gatekeeper | grep 'Administrator'
```

Output shows the admin password and API token—**shown once only**. After login, change password under `/ui/account`.

Config files created:
- `toolkits.yaml` (Tier 1: deploy-time, immutable) — empty, add your clusters
- `tools.yaml` (Tier 2: runtime, changes via UI) — empty, build from examples
- `identities.yaml` (Tier 2: runtime) — one admin account

### 4. Add permissions (Tier 1)

Edit `toolkits.yaml` — this is deploy-time config. Example for Docker:

```yaml
toolkits:
  docker:
    executor: docker
    binaries:
      - /usr/bin/docker
    denied_args: [rm, kill, exec, build, push, login, system, prune, cp, --privileged, -v, --volumes, --rmi]
    path_roots:
      - /mnt/raid
    protected_resources: [gatekeeper, dockhand, traefik]  # these cannot be touched
    max_timeout_seconds: 300
    max_output_bytes: 262144
```

See [toolkits example](config/examples/toolkits.yaml) for full reference.

A `file` toolkit (`executor: file` — read/write/patch/list, no binary and no
argv) performs its operations as the container user. If it has to reach files
owned by somebody else, it can declare `run_as: "3001:3001"` (or an account
name); operations then run as that user, and only for that toolkit. It needs
`CAP_SETUID` and `CAP_SETGID` — in practice `user: "0:0"` *and* `cap_add:
[SETUID, SETGID]`, since Docker grants those to uid 0 alone. Changing it over
`/admin/mcp` needs a human approval at `/ui/requests`, and where the privilege
is missing the calls fail rather than quietly running as the container user — see
[DEPLOYMENT.md](docs/DEPLOYMENT.md#running-file-operations-as-another-user-run_as).

### 5. Create tools and grant access

Use the `/ui` console (logged in as admin) or copy from [tools example](config/examples/tools.yaml).

Example tool:

```yaml
- id: docker.compose_ps
  toolkit: docker
  binary: /usr/bin/docker
  category: read
  idempotent: true
  enabled: true
  argv: ["compose", "-p", "{stack}", "-f", "{compose_path}", "ps", "--format", "json"]
  parameters:
    stack:
      type: string
      required: true
      pattern: "^[a-z0-9][a-z0-9_-]{0,62}$"
    compose_path:
      type: path
      derived: "/mnt/raid/{stack}/compose.yaml"
      must_resolve_under: /mnt/raid
  required_scopes: ["stack:{stack}"]
  timeout_seconds: 30
  max_output_bytes: 65536
```

Then grant access: go to **Identities**, pick an agent, add `docker.compose_ps` with scope `stack:*` or `stack:media-*`.

### 6. Connect an agent

In the agent's MCP config:

```yaml
mcp_servers:
  gatekeeper:
    transport: streamable_http
    url: http://<host>:8080/mcp
    headers:
      Authorization: "Bearer gk_..."
```

The agent now sees only tools it has permission for.

---

## Authentication: Two systems

### Console (human, `/ui`)

- **Who**: viewers and admins
- **Credential**: password (console login only)
- **Session**: separate cookie-based session
- **Change it**: `/ui/account` (requires old password)

### API (agent, `/mcp`)

- **Who**: agents, viewers, admins
- **Credential**: token (in `Authorization: Bearer` header)
- **Session**: stateless, token-based
- **Rotate it**: `/ui` under Identities (for admins/viewers) or via CLI for new tokens

These are intentionally separate. A leaked console password doesn't open `/mcp`. A leaked token doesn't open the dashboard.

---

## What admins can do

From the `/ui` console (when logged in):

- **Add/edit/disable/delete tools** — modify Tier 2 (runtime)
- **Create/edit/delete identities** — manage users and agents
- **Grant/revoke tool access** — assign permissions and scopes
- **Change passwords and rotate tokens** — via Identities view or personal account
- **View audit log** — search, filter, export

### What they can't do (by design)

- **Edit Tier 1** — no route to write `toolkits.yaml`. Binary allowlist, denied args, path roots, protected resources are deploy-time only. This is intentional: Tier 1 is the outer boundary that makes tool creation safe.
- **Bypass the sandbox** — every tool definition runs through the same Tier 1 validation as startup loading. A malformed tool is rejected, not loosened.
- **Hide actions** — everything goes to the audit log with the admin's identity. Deletions record the full definition so they're recoverable.

### Protections

- **Last admin protected** — can't delete or demote the last admin with a console password
- **CSRF token on writes** — every form includes a session-scoped token
- **Optimistic locking** — forms know the file revision; concurrent edits are detected and rejected
- **Atomic writes** — temp file + fsync + atomic rename; crashes leave the old file intact
- **After write, re-read** — the UI doesn't assume the write succeeded; it reloads from disk

---

## Self-service catalog management via `/admin/mcp`

A second MCP endpoint, `/admin/mcp`, lets an `admin`-role agent (e.g. an
always-on orchestrator like Hermes) manage the tool catalog and grants the
same way a human does at `/ui`, without a human being the bottleneck for
every routine change.

- **Isolated by construction, not by filter.** `/admin/mcp` is a second,
  hand-written `admin.*` tool list on its own `Server` instance, sharing no
  catalog with `/mcp`. `admin`-role tokens are rejected outright on `/mcp`;
  every other role is rejected outright on `/admin/mcp`.
- **Low-risk changes apply immediately:** read-only queries, creating a new
  tool (always created disabled), disabling a tool, and enabling/updating a
  `read`-category tool.
- **Everything that expands what an agent can do goes to a pending queue**
  at `/ui/requests` (Change tab) instead: enabling/updating a
  `write`/`write_external` tool, deleting a tool, granting access
  (`admin.grant_set`), and changing an identity's role (`admin.role_set`).
  A human approves or rejects from the console — the applied change and
  its audit entry are identical to a human doing the same edit directly.
- **Self-approval is impossible, structurally.** `approve`/`reject` are not
  part of the `admin.*` tool list and have no code path from `/admin/mcp` —
  there is no permission check to bypass, because the capability doesn't
  exist there.
- **Tool definitions are versioned and append-only** (`tool_update` never
  overwrites; old versions stay fetchable) and deletions are soft
  (`admin.tool_delete` marks a definition deleted with its history intact,
  rather than erasing it).
- **Drafting a new toolkit is possible, deploying it never is — from here.**
  `admin.toolkit_list` reads the live Tier 1 configuration; `admin.toolkit_propose`
  drafts a brand-new toolkit, `admin.toolkit_update` proposes a narrow
  edit, and `admin.toolkit_delete` proposes removing one (refused at
  deploy time if a tool still references it) — all three always land in
  their own review surface, the Toolkit tab of `/ui/requests` — never the
  Change tab — a toolkit changes what is *possible* at all (Tier 1), not
  just who can do what (Tier 2), so it gets a heavier,
  explicit confirmation. A human clicking "Approve & Deploy" is the only
  thing that ever writes `toolkits.yaml`: gatekeeper validates the merged
  config with the same loader startup uses, writes it atomically, and
  reloads it into the running process immediately — no redeploy, no
  restart, and still no path from `/admin/mcp` to make it happen on its own.

See [`admin_service.py`](src/gatekeeper/admin_service.py) for the exact
per-action rules and [REQUIREMENTS.md §3](REQUIREMENTS.md) (FR-2.8–FR-3.7)
for the full spec.

---

## Audit & visibility

### Call flow (8 layers every request passes)

Each request passes through 8 validation stages:

1. **MCP protocol** — JSON-RPC 2.0 via Streamable HTTP
2. **Auth** — Bearer token verification
3. **Authorize** — does this identity have permission?
4. **Registry** — is the tool known?
5. **Validate** — are the parameters OK?
6. **Build the request** — substitute parameters into argv / an HTTP
   request / a JSON-RPC call (whichever the toolkit's executor uses), and
   check the result against denied args / target allowlist / RPC whitelist
7. **Execute** — run the process or call, enforce timeout & output limits
8. **Audit** — log the result

Any layer can deny; all denials look the same to the agent ("Unknown tool, or not available"). The audit log knows the real reason.

### Audit log format

JSON Lines, one entry per call:

```json
{"timestamp":"2026-08-16T12:39:48Z","identity":"homelab","tool":"diag.uptime","status":"ok","exit":0,...}
```

Stored in `audit.dir` from `toolkits.yaml`. Automatically rotated (default: 10 files × 32MB each). Search from `/ui/audit` with filters.

---

## Security notes

- **The Docker socket is root-equivalent on the host.** A bug here is a host compromise. That's why the config is two-tier (outer safety boundary) and the negative corpus of attack tests is kept.
- **Container logs can leak secrets gatekeeper doesn't manage.** Agents with `docker.compose_logs` see that container's own environment variables verbatim — gatekeeper only knows to redact secrets it holds itself. Anything created through the credential store (Credentials page) *is* masked out of tool output and the audit log wherever it appears (FR-10.6); an arbitrary secret baked into a container's env is not, because gatekeeper has no way to know it's one.
- **Admin access is powerful.** An admin can create any tool within Tier 1 bounds, grant it to agents, and they'll run. Treat console password like a host SSH key: one per person, changed regularly, `viewer` role for observers.
- **No shell history in passwords.** Always use `gatekeeper password --identity <id>` without `--password <value>` to avoid the password landing in shell history.
- **TLS required for `/ui`.** Console cookies run without `Secure` flag over HTTP. Deploy behind a reverse proxy with HTTPS, or on a private network only.

---

## Development & contribution

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for:
- Code structure and invariants
- The two-tier security model, executors, and credential store
- Security-critical modules and the UI architecture

See [REQUIREMENTS.md](REQUIREMENTS.md) for:
- Complete feature list
- Functional and non-functional requirements
- Specification of each guarantee

See [AGENTS.md](AGENTS.md) if you're an AI agent working in this repo — release
workflow, testing, and known pitfalls.

---

## What's not here (yet)

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full list with rationale.
Short version: OAuth2 is supported for Google Workspace via the `google`
executor (0.38.0); no `destinations:` on an `ssh` toolkit (one toolkit per
host), no TrueNAS SCRAM mutual auth, and no nested `params_template` values
for the `truenas` executor.

---

## License & attribution

Built for a homelab. Designed to be paranoid about safety. Used in production.
