<div align="center">
<img src=".readme-assets/logo.svg" width="112" alt="gatekeeper logo">

# gatekeeper

**An MCP server that gives AI agents a fixed set of audited actions instead of a shell.**

<a href="https://github.com/davidsteg/gatekeeper/releases"><img alt="Release" src="https://img.shields.io/github/v/release/davidsteg/gatekeeper?label=release&color=3b5bdb"></a> <a href="https://hub.docker.com/r/davidsteg/gatekeeper"><img alt="Docker image" src="https://img.shields.io/badge/docker-davidsteg%2Fgatekeeper-3b5bdb?logo=docker&logoColor=white"></a> <img alt="Platform" src="https://img.shields.io/badge/platform-linux%2Famd64-555"> <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-b7410e?logo=rust&logoColor=white">

[Quick start](#quick-start) · [Console tour](#a-tour-of-the-console) · [Architecture](docs/ARCHITECTURE.md) · [Deployment](docs/DEPLOYMENT.md) · [Requirements](REQUIREMENTS.md) · [Roadmap](docs/ROADMAP.md) · [Release notes](RELEASE.md)

</div>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".readme-assets/overview-dark.png">
  <img alt="The gatekeeper console's Overview page: counts, a 12-hour activity chart, recent events and the access map of identities to toolkits" src=".readme-assets/overview-light.png">
</picture>

---

## Why gatekeeper

You want an AI agent to run your homelab: restart a Docker stack, look at a
ZFS pool, read a mailbox, push a feature branch. Handing it a shell is too
much power, and a shell is impossible to audit in any useful way.

gatekeeper sits in the middle. Each agent gets an API token and sees only the
tools it has been granted. Every call goes through the same pipeline:

```mermaid
flowchart LR
    A["Agent<br/>(MCP client)"] -->|"docker.compose_up<br/>stack=immich"| G
    subgraph G["gatekeeper"]
        direction TB
        V["Authenticate · authorize · validate"] --> X["Build exact argv / request<br/>(never a shell)"]
    end
    G --> H["Docker, TrueNAS, SSH host,<br/>HTTP API, mailbox, …"]
    G -.->|every call, allowed or not| L[("Audit log<br/>JSON Lines")]
```

- **The agent asks** for a tool by name, for example `docker.compose_up` with `stack=immich`.
- **gatekeeper checks** that this identity holds the tool, that the parameters match their rules, that the scope (`stack:immich`) is granted and the stack is not protected.
- **gatekeeper runs** exactly the command or request the tool defines. There is no shell anywhere, so there is nothing to inject into.
- **Everything is logged**, including every denial with its real reason. The agent only ever sees "Unknown tool, or not available".

## Highlights

- **No shell, ever.** Commands run as argv lists; HTTP, JSON-RPC and SSH calls are built from fixed templates.
- **Two-tier configuration.** Tier 1 (`toolkits.yaml`) is the outer boundary, set at deploy time: which binaries, hosts, paths and methods exist at all. Tier 2 (tools, identities, credentials) is edited at runtime, and every edit is validated against Tier 1.
- **Per-tool, per-identity grants** with resource scopes such as `stack:media-*`.
- **Complete audit trail** of every call, sign-in and admin change, rotated on disk.
- **Write-only credential store.** Secrets are encrypted at rest, injected into requests by gatekeeper, and masked out of tool output and the audit log. Nobody can read one back, not even an admin.
- **Secrets the caller brings stay secret.** A parameter marked `secret: true` (a dataset passphrase) reaches the TrueNAS API and nothing else: `***` in the audit log, masked in the output, refused anywhere but a `truenas` tool's `params`.
- **Secret-shaped values are masked** in `docker`, `local`, `ssh` and `file` output (`DB_PASSWORD=[redacted]`, URL passwords, private keys).
- **Agents can manage the catalog, humans approve.** An admin agent on `/admin/mcp` proposes tools, grants, credentials and toolkits; anything that widens access waits for a human in the console.
- **Empty on install.** Nothing ships preconfigured; every capability is a decision you made and can find in the log.
- **A console that works on a phone**, with live updates, light and dark mode, and a home-screen install.

### Twelve executors

| Executor | Reaches | Executor | Reaches |
| --- | --- | --- | --- |
| `local` | a binary inside the container | `google` | Gmail, Calendar, Drive (OAuth) |
| `docker` | Docker Compose stacks, local or remote over TLS | `microsoft` | Outlook mail (OAuth) |
| `http` | any REST API (Sonarr, Home Assistant, GitHub, …) | `opencode` | a headless opencode coding agent |
| `ssh` | a Linux host, with mandatory host-key pinning | `kuma` | Uptime Kuma monitors |
| `truenas` | the TrueNAS JSON-RPC API | `git` | a `feat/*` push to GitHub |
| `file` | read, write, patch, list and delete files under fixed roots | `agent` | a mailbox between identities |

Outbound targets are checked against SSRF rules, host and CIDR allowlists, and
method and path-prefix allowlists. **Toolkits → Reference YAML** in the console
prints a copy-pasteable starting block for each executor, and
[config/examples/toolkits.yaml](config/examples/toolkits.yaml) is the long
form with the reasoning.

---

## A tour of the console

Start gatekeeper with `serve --ui` and the admin console is at `/app`. It is a
React app backed by a typed JSON API at `/api/v1`, and it signs in with a
console password (an API token is refused there). The screenshots below come
from a demo configuration with made-up hosts and activity.

### Requests: agents propose, humans decide

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".readme-assets/requests-dark.png">
  <img alt="The Requests page with pending grant and credential proposals from the admin agent hermes" src=".readme-assets/requests-light.png">
</picture>

When an admin agent asks for something that expands what an agent can do
(a grant, enabling a write tool, a new credential slot), it lands here. The
review shows exactly what changes: which tools get added, whether they are
enabled, and their category. A credential proposal carries a name and a kind,
never a value; the human types the secret on approval.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".readme-assets/requests-toolkit-dark.png">
  <img alt="The Toolkit tab of the Requests page showing a proposed http toolkit for Sonarr with Approve and deploy" src=".readme-assets/requests-toolkit-light.png">
</picture>

Toolkit proposals get their own tab and a heavier confirmation, because they
change what is possible at all. Only a human clicking **Approve and deploy**
writes `toolkits.yaml`; gatekeeper validates the merged file with the startup
loader, writes it atomically and reloads it without a restart.

### Stats: what your agents actually do

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".readme-assets/stats-dark.png">
  <img alt="The Stats page: totals, a 24-hour activity chart, calls by toolkit and identity, top tools, latency and admin actions" src=".readme-assets/stats-light.png">
</picture>

Calls, success rate, denials and failures over 24 hours, 7 or 30 days, broken
down by toolkit and identity. **Top tools** lists the busiest tools, across
everything or for one toolkit picked from the dropdown. Latency shows average
and p95 per toolkit.

### Audit log: the real reason for every denial

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".readme-assets/audit-dark.png">
  <img alt="The Audit log page with calls, denials with reasons such as not_granted and scope_mismatch, sign-ins and admin changes" src=".readme-assets/audit-light.png">
</picture>

Every call, granted or denied, plus sign-ins and admin changes. The agent gets
an opaque answer; the log keeps the real reason (`not_granted`,
`scope_mismatch`, `protected_resource`, …), the client address, the duration
and which credential a call used, so you know what to rotate after a leak.
Each call also records what it actually ran (the argv, the HTTP request line
and body, the RPC method), with secrets masked and long values cut, and the
Detail column shows it. Filter by identity, tool and outcome. On disk it is JSON Lines in `audit.dir`,
ready for any log shipper.

### Tools: templates, not commands

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".readme-assets/tools-dark.png">
  <img alt="The Tools page in card view, grouped by toolkit, with category, status, grantees and scopes per tool" src=".readme-assets/tools-light.png">
</picture>

Each tool is a fixed action: a binary with an argv template and parameter
rules, or a method and path on an HTTP toolkit. Switch between **Cards**
(grouped by toolkit) and **Matrix** (status, category, idempotency and who may
call each tool). The editor shows the Tier 1 limits a tool has to stay
inside. Defining and granting are separate steps: a tool with no grantees
exists but no agent can see it.

### Identities and credentials

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".readme-assets/identities-dark.png">
  <img alt="The Identities page with agents, their granted tools and scopes" src=".readme-assets/identities-light.png">
</picture>

Identities are agents, viewers and admins. Agents get an API token for `/mcp`;
people get a console password. Grants name individual tool IDs, never a whole
toolkit, plus scopes. Tokens and passwords are stored as scrypt hashes.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".readme-assets/credentials-dark.png">
  <img alt="The Credentials page: write-only secrets with kind, usage and Rotate and Delete actions, and a warning for referenced but missing credentials" src=".readme-assets/credentials-light.png">
</picture>

A credential is created, rotated or deleted, and that is all. There is no
view button for any role. A toolkit refers to a credential by name
(`credential: sonarr`), and gatekeeper attaches it the way the service
expects:

| Kind | How it reaches the request | Typical service |
| --- | --- | --- |
| `api_key_header` | a header you name, optionally wrapped with `header_format` | Sonarr, Radarr (`X-Api-Key`), Jellyfin |
| `bearer` | `Authorization: Bearer …` (for `git`, the push token) | Home Assistant, GitHub |
| `basic` | `Authorization: Basic …` (for `kuma`, the Socket.IO login) | HTTP basic auth, Uptime Kuma |
| `url_query` | a query parameter, for services with no header option | SABnzbd |
| `url_path` | substituted into the toolkit's `base_url` | Telegram's bot API |
| `ws_api_key` | the JSON-RPC login call | TrueNAS |
| `docker_tls` | a PEM bundle in a private temp dir | a TLS-secured remote Docker daemon |
| `ssh_private_key` | the key the `ssh` executor authenticates with | Linux over SSH |
| `oauth2` | a refresh token captured by **Connect Google / Microsoft** | Gmail, Calendar, Drive, Outlook |

If a toolkit names a credential that does not exist yet, startup warns and the
page says so; calls through it are refused until a value is entered. Setting
up the master key is step one of
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#credentials-from-zero-to-a-working-call).

---

## Quick start

The image is published as
[`davidsteg/gatekeeper`](https://hub.docker.com/r/davidsteg/gatekeeper) for
**linux/amd64**. Pin a fixed version (the one on the
[latest release](https://github.com/davidsteg/gatekeeper/releases/latest)),
not `latest`: this service can hold root-equivalent access to the host.

### 1. Prepare a directory

```bash
mkdir -p /mnt/raid/gatekeeper/config /mnt/raid/gatekeeper/logs
chown -R 568:568 /mnt/raid/gatekeeper
```

### 2. Start it

Use [compose.yaml](compose.yaml) as the template: it runs unprivileged
(`568:568`), read-only, with all capabilities dropped, and every line is
commented. Uncomment `command: ["serve", "--ui"]` to get the console, then:

```bash
docker compose up -d
docker compose logs gatekeeper | grep 'Administrator'
```

The first start finds an empty config directory and creates an empty
`toolkits.yaml`, an empty `tools.yaml` and an `identities.yaml` with one
admin. The admin's console password and API token are printed to the log
**once**. Sign in at `http://<host>:8080/app` and change the password under
**Account**.

### 3. Define what is possible (Tier 1)

Edit `toolkits.yaml` on the host. This is deploy-time configuration; the
console can never write it on its own. A Docker toolkit looks like this:

```yaml
toolkits:
  docker:
    executor: docker
    binaries: [/usr/bin/docker]
    denied_args: [rm, kill, exec, build, push, login, system, prune, cp, --privileged, -v, --volumes, --rmi]
    path_roots: [/mnt/raid]
    protected_resources: [gatekeeper, traefik]   # these stacks cannot be touched
    max_timeout_seconds: 300
    max_output_bytes: 262144
```

Reload with `SIGHUP` or a restart. See
[config/examples/toolkits.yaml](config/examples/toolkits.yaml) for every
executor.

> **`local` means a program inside this container, not on the host.** ZFS is
> the classic trap: `zfs` talks to the host kernel through `/dev/zfs`, so
> installing it in the image would not help. Pool and dataset work belongs on
> the `truenas` executor, and anything without an API on `ssh`. Startup warns
> by name when a `local` toolkit points at a binary the image does not have.

### 4. Create a tool and grant it

In the console under **Tools → New tool**, or in `tools.yaml`
([examples](config/examples/tools.yaml)):

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

Then open **Identities**, pick an agent, and grant `docker.compose_ps` with
the scope `stack:*` or `stack:media-*`.

### 5. Connect an agent

```yaml
mcp_servers:
  gatekeeper:
    transport: streamable_http
    url: http://<host>:8080/mcp
    headers:
      Authorization: "Bearer gk_..."
```

The agent now sees exactly the tools it was granted, and nothing else.

---

## How it works

### Every call passes eight layers

1. **MCP**: JSON-RPC 2.0 over Streamable HTTP.
2. **Auth**: the bearer token is matched to an identity.
3. **Authorize**: does this identity hold this tool, with this scope?
4. **Registry**: is the tool known and enabled?
5. **Validate**: types, patterns, path resolution, protected resources.
6. **Build**: parameters are substituted into argv, an HTTP request or an RPC call, then checked again against denied args and the target allowlists.
7. **Execute**: the process or call runs with a timeout and an output cap.
8. **Audit**: the result is written to the log.

Any layer can deny, and every denial looks the same to the agent.

### Two ways in, kept apart

| | Console (`/app`) | MCP (`/mcp`) |
| --- | --- | --- |
| **Who** | viewers and admins | agents (admin agents use `/admin/mcp`) |
| **Credential** | console password | API token in `Authorization: Bearer` |
| **Session** | cookie scoped to `/api/v1`, CSRF token on writes | none that carries authority: every request is authenticated on its own |

A leaked console password does not open `/mcp`, and a leaked token does not
open the console.

### What admins can and cannot do

From the console an admin adds, edits and disables tools, manages identities,
grants and scopes, rotates tokens and handles credentials. Every write is
checked against Tier 1, sent with the revision it read (`If-Match`), written
atomically (temp file, fsync, rename) and re-read from disk afterwards. The
last admin with a console password cannot be deleted or demoted.

What an admin cannot do is edit Tier 1. There is no route that writes
`toolkits.yaml` except **Approve and deploy** on a toolkit proposal, which a
human has to click. Deletions are logged with the full definition, so nothing
disappears without a trace.

### Agents that manage the catalog: `/admin/mcp`

A second MCP endpoint gives an `admin`-role agent (an orchestrator such as
Hermes) the same management tools a human has, as a separate, hand-written
`admin.*` tool list. Admin tokens are refused on `/mcp`, and every other role
is refused on `/admin/mcp`.

- **Applied at once:** read-only queries, creating a tool (always disabled), disabling a tool, and enabling or updating a `read` tool.
- **Queued for a human** at `/app/requests`: enabling or updating a `write`/`write_external` tool, deleting a tool, grants (`admin.grant_set`), role changes, credential slots (`admin.cred_propose`, `admin.cred_update`) and toolkit changes (`admin.toolkit_propose`, `admin.toolkit_update`, `admin.toolkit_delete`, `admin.credential_bind`).
- **Self-approval does not exist.** Approve and reject are not in the `admin.*` tool list, so there is no permission check to get around.
- Tool definitions are versioned and append-only, and deletions are soft.
- `admin.release_notes` (and `GET /release`) return this deployment's release notes, so an agent proposing changes can read the release rule it has to follow.

See [`admin_service.rs`](rust/src/admin_service.rs) for the per-action rules
and [REQUIREMENTS.md](REQUIREMENTS.md) (FR-2.8 to FR-3.7) for the spec.

### Also built in

- **Agent mailbox.** `agent.send_message` and `agent.read_messages` let identities leave each other messages. The sender is always the authenticated identity; delivery happens on the recipient's next call.
- **Release-bound artifacts.** Files built from fixed repository paths can ship inside the image with a sha256 manifest and be read or handed over through `artifact.*` tools. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#release-bound-artifacts).
- **`run_as` for file toolkits.** A `file` toolkit can perform its operations as another user when the container has `CAP_SETUID`/`CAP_SETGID`. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#running-file-operations-as-another-user-run_as).
- **Health endpoints** at `/health/live` and `/health/ready`, the latter probing each executor.

---

## Security notes

- **The Docker socket is root-equivalent.** A bug here is a host compromise, which is why the boundary is two-tier and the repository keeps a corpus of attack tests.
- **Output masking is not a guarantee.** Values from the credential store are masked everywhere. Other secrets are masked by shape on `docker`, `local`, `ssh` and `file` toolkits (`redact_secrets`, on by default there), which catches the usual config and log formats but not a secret under a harmless-looking name. Grant tools that print whole configs sparingly.
- **Admin access is powerful.** An admin can create any tool within Tier 1 and grant it. Treat a console password like an SSH key, and give observers the `viewer` role.
- **Use TLS for the console.** The session cookie is marked `Secure` only over HTTPS (directly or via a trusted proxy's `X-Forwarded-Proto`). Run behind a reverse proxy or on a private network.
- **Keep passwords out of shell history:** run `gatekeeper password --identity <id>` without `--password`.

---

## Development

gatekeeper is a Rust crate in [rust/](rust/); it builds on Linux only
(privilege dropping, `SIGHUP` reload, `/proc`). The console lives in
[frontend/](frontend/). The only Python left is the vendored Google and
Microsoft CLI scripts in [scripts/](scripts/), which the image runs as
subprocesses.

```bash
cd rust && cargo build && cargo test          # the server
cd frontend && npm ci --ignore-scripts && npm test   # the console
python -m pytest -q                           # scripts/ and Dockerfile checks
```

`npm run dev` in `frontend/` serves the console on `:5173` against a local
`cargo run -- serve --ui`. [AGENTS.md](AGENTS.md) has the full test matrix,
the release workflow and the known pitfalls;
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) covers the code structure,
security model and executors.

## What's not here (yet)

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full list with reasons. In
short: no `destinations:` on an `ssh` toolkit (one toolkit per host), no
TrueNAS SCRAM mutual auth, and secret parameters only on the `truenas`
executor. gatekeeper also never continues an agent session: the
recovery supervisor was removed in 0.52.0, and the orchestrating agent handles
results and follow-ups itself
([migration notes](docs/DEPLOYMENT.md#removed-recovery-supervisor)).

---

<div align="center">

Built for a homelab. Paranoid about safety. Used in production.

</div>
