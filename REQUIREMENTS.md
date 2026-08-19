# gatekeeper — Requirements Document

**Purpose:** Controlled MCP server as the sole channel for host operations **and external API access**. It provides the *foundation* — protocol, authentication, permissions, parameter validation, execution, audit. The concrete tools are managed at runtime by an admin agent via an API.

**Status:** Draft v2
**Replaces:** v1 (static tool catalog in code)
**Deployment:** Docker container on TrueNAS, via Dockhand, following homelab rules (ZFS dataset, chown 568:568)

---

## 1. What Changes Compared to v1

v1 defined the whitelist as code: the server knew `docker compose up`, `zfs create`, etc. hard-compiled. v2 reverses this — **the whitelist is data**, managed via an admin API.

This shifts the security boundary and is the most important design decision of this document:

> In v1: *the server can only do what is compiled in.*
> In v2: *the server can only do what the admin has defined — within the boundaries locked down at deploy time.*

Without this second half of the sentence, the admin token would be a master key for arbitrary host commands, and the entire protective effect of gatekeeper would be a matter of an agent's diligence. Therefore §6 defines a **two-level model** that provably locks down the admin API.

The tool catalog from v1 does not disappear — it becomes the **seed catalog** (§7), loaded on first start and thereafter maintained via the API.

---

## 2. Architecture Layers

A call always passes through all layers, in this order:

| # | Layer | Responsibility |
|---|---------|---------|
| 1 | **MCP Transport** | JSON-RPC 2.0, `tools/list`, `tools/call` |
| 2 | **Authentication** | Token → identity (agent or admin) |
| 3 | **Authorization** | Is this identity allowed to call this tool with these resources? |
| 4 | **Tool Registry** | Look up the active tool definition |
| 5 | **Parameter Validation** | Type, regex, path resolution, resource scope |
| 6 | **argv Construction** | Structured command construction, **never** a shell string |
| 7 | **Executor** | Execution via a backend type enabled at deploy time |
| 8 | **Audit** | Logging of result, duration, exit code |

Layers 2, 3, 5, 6, 7, 8 are the foundation and live in code. Layer 4 is runtime configuration.

---

## 3. Functional Requirements — MCP Protocol

- **FR-1.1** Implements MCP via **Streamable HTTP** (Spec ≥ 2025-03-26), so that Hermes agents can use the server as an `mcp_servers` entry in their `config.yaml`.
- **FR-1.2** The HTTP+SSE transport mentioned in v1 is deprecated in the MCP spec. It will **only** be additionally implemented if the deployed Hermes version does not support Streamable HTTP (→ §17, open question).
- **FR-1.3** Exposes `tools/list` and `tools/call`.
- **FR-1.4** `tools/list` returns results **filtered per identity** — an agent sees only tools it is also allowed to call. Tools not visible to it do not exist for it.
- **FR-1.5** When the admin changes the catalog, the server sends `notifications/tools/list_changed` to all affected connected clients. Without this, agents continue working with an outdated toolset.
- **FR-1.6** Two separate endpoints: `/mcp` for agents, `/admin/mcp` for administration (see FR-4.2).

---

## 4. Functional Requirements — Authentication & Identity

- **FR-2.1** Each agent (homelab, media, dev) receives its own API token. No shared access.
- **FR-2.2** Each token is linked to exactly one identity; each identity carries a role (`agent` or `admin`) and a permission profile (§7).
- **FR-2.3** Unknown or invalid token → HTTP 401, no tool access, audit entry.
- **FR-2.4** Tokens are persisted **only as hashes** (argon2id or scrypt). The configuration file never contains plaintext tokens and is therefore not secret-critical — relevant because it resides in the dataset with `chown 568:568` per homelab rules.
- **FR-2.5** Token comparison is done in constant time.
- **FR-2.6** The plaintext token exists in only two places: once at generation time (output to the operator) and in the `config.yaml` of the respective agent.
- **FR-2.7** Tokens can be revoked without requiring other tokens to be reissued.

### Separation of Agent / Admin

- **FR-2.8** The admin token is **not** an agent token with additional permissions, but a separate role on a separate endpoint (`/admin/mcp`).
- **FR-2.9** Admin tools **never** appear in `tools/list` of the agent endpoint, not even for the admin token. A compromised agent path cannot reach catalog management.
- **FR-2.10** The admin endpoint can optionally be additionally restricted at the network level (bind address / source IP).

---

## 5. Functional Requirements — Tool Registry & Admin API

The new heart. The admin agent manages the tool catalog via MCP tools in the `admin.*` namespace on `/admin/mcp`.

- **FR-3.1** Minimum scope of admin operations:

  | Tool | Effect |
  |------|---------|
  | `admin.tool_list` | All definitions including version and status |
  | `admin.tool_get` | One definition in full text |
  | `admin.tool_create` | Create a new definition (always `enabled: false`) |
  | `admin.tool_update` | Create a new **version** of a definition |
  | `admin.tool_enable` / `admin.tool_disable` | Toggle activation |
  | `admin.tool_delete` | Retire a definition (soft delete, history preserved) |
  | `admin.tool_validate` | Validate a definition **without** saving it |
  | `admin.grant_list` / `admin.grant_set` | Permission profiles per identity |
  | `admin.cred_list` | Only **names**, type, creation date, last rotation — **never values** |
  | `admin.cred_set` | Create or rotate a value (write-only, §11) |
  | `admin.cred_delete` | Remove a credential |
  | `admin.cred_pubkey` | Output the public part of an SSH key (FR-10.9) |
  | `admin.audit_query` | Search the audit log |

- **FR-3.2** **New definitions are inactive after `create`.** Activation is a separate, separately audited call. Prevents a typo or a half-finished agent run from immediately going live.
- **FR-3.3** Definitions are **versioned and append-only**. `tool_update` creates version *n+1*, overwrites nothing. Each audit entry references the definition version that was actually executed — otherwise it is impossible to reconstruct afterwards what a call at time *T* actually did.
- **FR-3.4** `admin.tool_validate` and every `create`/`update` fully check the definition against the deploy boundaries from §6. A definition that violates these is **rejected and not stored**.
- **FR-3.5** Every catalog change is audited with before/after state, admin identity, and timestamp (§12).
- **FR-3.6** The catalog is persisted in the dataset and survives container restarts.
- **FR-3.7** The admin cannot grant itself permissions beyond §6. `admin.grant_set` can only assign subsets of the deploy framework to agents.

---

## 6. Functional Requirements — Security Boundaries (Two-Level Model)

**This is the requirement that makes v2 justifiable at all.** Without it, the admin token is equivalent to root on the host.

### Level 1 — Deploy Time, Immutable at Runtime

Defined in the container configuration (env / mounted file). **Not** changeable via the admin API. Changes require redeploy.

- **FR-4.1 Binary Allowlist:** A list of permitted executable programs with absolute paths, e.g. `/usr/bin/docker`, `/usr/bin/uptime`. A tool definition whose executable is not exactly in this list is rejected. The admin cannot define `rm` if `rm` is not enabled.
- **FR-4.2 Argument Prohibitions per Binary:** Optional blocklist of subcommands and flags, e.g. for `/usr/bin/docker` blocking `rm`, `--privileged`, `exec`. Catches the case where an allowed binary has destructive modes.
- **FR-4.3 Path Roots:** List of permitted base directories (e.g. `/mnt/raid`). Every path parameter must resolve via `realpath` to be under one of them. Prevents symlink escape despite a cleanly validated stack name.
- **FR-4.4 Executor Enablement:** Which executor types (§10) are available at all.
- **FR-4.5 Hard Upper Limits:** Maximum timeout, maximum output size, maximum parallelism. A tool definition may stay below these limits, never exceed them.

### Level 2 — Runtime, Admin API

Freely configurable within Level 1: tool definitions, parameter schemas, permission profiles, timeouts below the upper limit.

- **FR-4.6** The server rejects every definition that violates Level 1 — on `create`, on `update`, **and again on every execution**. Double checking because Level 1 may have been tightened by a redeploy while older definitions still sit in the catalog.
- **FR-4.7** On startup, the server logs all definitions that violate the current Level 1 and automatically deactivates them, rather than silently tolerating them.

### Level 1 Is Declared per Toolkit

- **FR-4.8** A **toolkit** is the unit at which Level-1 boundaries are attached: `{Executor, Credential, allowed binaries and subcommands, path roots, default limits}`. FR-4.1 through FR-4.5 apply **per toolkit**, not globally.
- **FR-4.9** A globally maintained allowlist would inevitably be the union of all toolkit needs and thus overly broad: `diag.uptime` needs no path root under `/mnt/raid`, but `docker.compose_up` does. The toolkit boundary prevents the permissions of one tool from implicitly benefiting another.
- **FR-4.10** Every tool belongs to **exactly one** toolkit and inherits its boundaries. A tool can tighten its toolkit's boundaries, never extend them.
- **FR-4.11** Toolkits are declared **exclusively at deploy time**. The admin API can create tools, but not a toolkit — otherwise Level 1 would again be mutable at runtime.
- **FR-4.12 Protected Resources.** Level 1 maintains per toolkit a blocklist of resources that no tool may touch — regardless of permissions and scopes. Mandatory entries:
  - `gatekeeper` itself. A `docker.compose_down` on its own stack terminates the process mid-call: the response never reaches the agent, which interprets it as a timeout and possibly retries — but nobody is left to answer. Recovery then requires manual intervention on the host.
  - `ix-dockhand`. Dockhand is the deployment mechanism (§14). Whoever shuts it down loses the tool to turn it back on.
  - Reverse proxy and everything through which admin access runs.

  Level 1 can check syntax and target paths, but not semantics: `docker compose down` is the same operation to the validator, whether it targets a media stack or its own runtime environment. This blocklist is the only place where such knowledge can be stored.

```yaml
# Level-1 configuration (deploy time, not changeable via admin API)
toolkits:
  docker:
    executor: docker
    binaries: ["/usr/bin/docker"]
    denied_args: ["rm", "exec", "--privileged", "system prune"]
    path_roots: ["/mnt/raid"]
    max_timeout_seconds: 300
    max_output_bytes: 262144
  diag:
    executor: local
    binaries: ["/usr/bin/uptime", "/usr/bin/free", "/usr/bin/df"]
    path_roots: []          # intentionally empty — no tool here accepts paths
    max_timeout_seconds: 10
    max_output_bytes: 16384
  github:
    executor: http
    base_url: "https://api.github.com"     # host is fixed here, never a parameter
    allowed_methods: ["GET", "POST"]
    allowed_path_prefixes: ["/repos/davidsteg/", "/user/repos"]
    allowed_cidrs: ["140.82.112.0/20", "192.30.252.0/22"]
    credential: env:GITHUB_TOKEN           # injected server-side, never visible
    follow_redirects: false
    max_timeout_seconds: 20
    max_output_bytes: 131072
```

---

## 7. Functional Requirements — Tool Definition Model

- **FR-5.1** A tool definition consists at minimum of: `id`, `toolkit`, `version`, `title`, `description`, `category` (`read` \| `write` \| `write_external`), `argv` or request template, `parameters`, `timeout_seconds`, `max_output_bytes`, `required_scopes`, `enabled`. The executor is **not** selected at the tool level, but inherited from the toolkit (FR-4.8).
- **FR-5.1a** `category` has three values: `read`, `write`, and **`write_external`**. The latter denotes actions with externally visible effects — creating an issue, sending a message, publishing something. This distinction is necessary because `docker.compose_up` and `github.create_issue` are both "write" but have fundamentally different consequences: one is reversible and stays in-house, the other is public and permanent. `write_external` requires an explicit grant, is never co-granted via a category rule, and logs the complete request payload (FR-9.1).
- **FR-5.1b** Tool IDs follow the pattern `<toolkit>.<action>` — `docker.compose_up`, `zfs.create`, `diag.uptime`, `admin.tool_list`. This makes toolkit membership immediately readable for agent, audit log, and permission profile, and `admin` is simply the toolkit reachable only on `/admin/mcp`.
- **FR-5.2** `description` is delivered to the agent as the MCP tool description and is therefore security-relevant for *usability*: it must clearly tell the model what the tool does and what it does not.
- **FR-5.3 argv Template Instead of Shell String:** `argv` is a **list**. Each list element is resolved individually.
- **FR-5.4** **One parameter always expands to exactly one argv element.** A parameter value cannot structurally produce additional arguments, regardless of its content. This — not a character blacklist — is the actual protection against command chaining.
- **FR-5.5** Derived parameters (`derived`): values that the server computes from a template itself and that the agent **cannot** pass in, e.g. `compose_path` from `stack`.
- **FR-5.6** Parameter types at minimum: `string` (with mandatory `pattern`), `enum`, `integer` (with bounds), `path` (with `must_resolve_under`), `boolean` (flag mapping, no free value).
- **FR-5.7** A `string` parameter **without** `pattern` is rejected. There is no unvalidated free-text parameter.

### Example (Seed Catalog)

```yaml
- id: docker.compose_up
  toolkit: docker          # Executor, binaries, path roots, and limits come from here
  version: 3
  title: "Start stack"
  description: "Starts a Docker Compose stack via 'docker compose up -d'."
  category: write
  enabled: true
  argv: ["compose", "-p", "{stack}", "-f", "{compose_path}", "up", "-d"]
  parameters:
    stack:
      type: string
      pattern: "^[a-z0-9][a-z0-9_-]{0,62}$"
      required: true
    compose_path:
      type: path
      derived: "/mnt/raid/{stack}/compose.yaml"
      must_resolve_under: "/mnt/raid"
  timeout_seconds: 120
  max_output_bytes: 65536
  required_scopes: ["stack:{stack}"]
```

---

## 8. Functional Requirements — Parameter Validation & Execution

- **FR-6.1** **No shell interpreter** is used. Execution exclusively via argv list (`shell=False`). No concatenation of agent inputs into a command string.
- **FR-6.2** Validation is done as an **allowlist** (regex/enum per parameter), not as a blacklist of forbidden characters. A metacharacter blocklist is functionally ineffective with FR-6.1 and was also incomplete in v1 (missing were, among others, newline, `\`, `*`, `?`, `'`, `"`, `#`, `!`).
- **FR-6.3** As defense-in-depth, control characters and null bytes in all parameters are still rejected — with an audit entry, because their occurrence is an attack indicator.
- **FR-6.4 Timeout:** Every call has a hard timeout. On expiry, the process tree is terminated and the call is audited as a failure.
- **FR-6.5 Output Limitation:** stdout/stderr are truncated at `max_output_bytes`, with indication in the result. Without this, a single `logs` command can produce gigabyte-sized responses.
- **FR-6.6** Log-like tools enforce a quantity limit (e.g. `--tail`) as a mandatory parameter with an upper bound.
- **FR-6.7 Concurrency:** Serialization per resource (e.g. stack name). Two simultaneous `up -d` on the same stack must not overlap.
- **FR-6.8 Rate Limiting:** Per identity, separate for `read` and `write`.
- **FR-6.9 A Timeout Is Not Proof of Non-Execution.** FR-6.4 terminates the call after the deadline expires — but on the other side, the operation may have long since completed. For `docker.compose_up` this is inconsequential because the operation is idempotent. For `write_external` it is not: an aborted `github.create_issue` may have created the issue. From this follows:
  - gatekeeper **never** automatically retries a call.
  - A timeout on `write` or `write_external` is returned to the agent as **"outcome unknown"**, not as a failure. A timeout reported as a failure provokes exactly the retry that creates the duplicate.
  - If the target service supports idempotency keys, gatekeeper sets them.
  - The unclear outcome is audited as such and is findable via the UI.
- **FR-6.10 Idempotency Belongs in the Tool Definition.** Every definition declares whether it is idempotent. Non-idempotent tools are marked as such in the description for the agent — a model that knows this repeats blindly less often.

---

## 9. Functional Requirements — Permission Model

v1 only knew `read` vs. `write`. That is not enough: the matrix assigned the dev agent "only dev stacks" — a restriction on **resources**, not on verbs.

- **FR-7.1** A permission profile has two dimensions:
  1. **Tools** — which tool IDs (or categories) the identity is allowed to call.
  2. **Scopes** — to which resources, as patterns: `stack:media-*`, `dataset:tank/raid/dev-*`.
- **FR-7.2** A tool declares in `required_scopes` which scope a call claims — with the substituted parameter values. The call is only allowed if the profile covers the resulting scope.
- **FR-7.3** Default is **deny**. Permissions not explicitly granted do not exist.
- **FR-7.4** Permission profiles are manageable via `admin.grant_set` and are versioned like tool definitions.
- **FR-7.5 No Grants at Toolkit Level.** Permissions are granted **on tool IDs**, never on an entire toolkit. A grant of the form "media may read `toolkit:docker`" would be convenient, but would mean: if the admin agent creates another read tool in the docker toolkit tomorrow, media automatically has it. On a SaaS tool platform that is harmless; here it is a permission escalation path without a human intermediate step. The toolkit is a carrier of boundaries and grouping — **not** of permissions.
- **FR-7.6** Consequently, when a new tool is created, it initially has **no** identity as an authorized party. Assignment is a separate, audited `grant_set` call — the second deliberate step alongside activation from FR-3.2.
- **FR-7.7 Rejections Reveal Nothing About the Catalog.** If an agent calls a tool that exists but for which it lacks permission, the response is **identical** to that for a non-existent tool. Otherwise `tools/call` becomes an oracle with which the complete catalog can be queried — and FR-1.4, which is supposed to make tools invisible, would be undermined. The asymmetry is intentional: **minimally informative toward the agent, maximally informative toward the audit log** (FR-9.2 records the real rejection reason).

### Initial Matrix (Seed, thereafter maintainable via API)

| Identity | Tools | Scopes |
|-----------|-------|--------|
| **homelab** | Docker read+write, `truenas.*` additionally, diagnostics | all stacks, `dataset:<pool>/raid/*` |
| **media** | Docker read (`ps`, `logs`), diagnostics, `sonarr.*`, `radarr.*`, `jellyfin.*` read | `stack:media-*`, `stack:jellyfin*` |
| **dev** | Docker read+write, ZFS additionally, diagnostics, `github.*` read | `stack:dev-*`, `dataset:<pool>/raid/dev-*`, `repo:davidsteg/*` |
| **admin** | exclusively `admin.*` on `/admin/mcp` | — |

---

## 10. Functional Requirements — Executors

The point v1 left open: *how* does a container reach the host at all. The foundation defines executor **types**; which of them are active is a Level-1 decision (FR-4.4).

| Type | Reaches | Mechanism | Status |
|-----|----------|-------------|--------|
| `docker` | Docker operations | mounted Docker socket | **v1 active** |
| `local` | Container-local diagnostics | process in container | **v1 active** |
| `http` | SaaS and LAN APIs (GitHub, *arr, Uptime Kuma …) | HTTP request with toolkit credential | **v1 active** |
| `truenas` | ZFS, pool status, dataset management | JSON-RPC 2.0 over WebSocket, API key | **v1 active** |
| `ssh` | Host commands without API equivalent (`ps`, `top`) | SSH with host-side restricted key | v1 optional (§17) |

- **FR-8.1** Tools do not select an executor themselves — they belong to a toolkit, and the toolkit binds the executor (FR-4.8). A toolkit whose executor is not enabled at deploy time is rejected along with all its associated tools.
- **FR-8.2** The `docker` executor gets the socket. This is **root-equivalent on the host** and stands in tension with NFR-1. This is deliberately accepted because gatekeeper is exactly the whitelist *that restricts this access* — but it means: a bug in gatekeeper is a root bug. From this follows the strictness of §6.
- **FR-8.3** ZFS is **not** reachable via the Docker socket — `zfs create` is not a Docker operation. ZFS runs via the `truenas` executor.

### Destinations (Multi-Host per Toolkit)

A toolkit is otherwise bound to exactly one target: `docker` to one socket/host, `http` to one `base_url`, `truenas` to one `ws_url`. A homelab commonly has more than one host worth reaching with the same toolkit boundary — a second Docker daemon, a second instance of the same service — and duplicating an entire toolkit definition (binaries, denied args, path roots, limits) just to change *where* it connects would be exactly the union-of-needs problem FR-4.9 already warns against, inverted into needless duplication instead of needless breadth.

- **FR-8.3g** A toolkit MAY declare a list of named **destinations** (deploy-time, Level 1, `toolkits.yaml`). A destination carries only connection information — `docker_host`/`docker_tls` for `docker`, `base_url` for `http`, `ws_url` for `truenas` — and an optional credential override. It never carries binaries, denied args, path roots, allowed methods/prefixes/CIDRs, or limits: those describe *what* is allowed and stay on the toolkit, identical across every destination it declares (FR-4.9).
- **FR-8.3h** A tool defined against a toolkit with N declared destinations is expanded at catalog-load time into N independently-grantable tool IDs, `<toolkit>.<action>@<destination>` (e.g. `docker.compose_up@nas1`). The YAML definition is written once, with a bare ID; the destination-qualified IDs exist only in the loaded catalog. Grants (FR-7.5) attach to these concrete IDs exactly like any other tool ID — no new grant mechanism, no destination parameter, no wildcard.
- **FR-8.3i The Agent Can Never Choose a Destination** (extends FR-8.7 beyond the `http` executor). There is no parameter, header, or field through which a call to `docker.compose_up@nas1` can execute against `nas2`. The destination is fixed in the tool ID itself, decided once at deploy/catalog-load time — identical in spirit to "scheme and host live exclusively in the toolkit."
- **FR-8.3j** A toolkit with no declared destinations behaves exactly as in v1: a single implicit target, sourced from the toolkit's own field (`docker_host`/`base_url`/`ws_url`) or, for `docker` with none set, the deploy environment's `DOCKER_HOST`. Existing `toolkits.yaml` files require no changes.

### The `truenas` Executor

- **FR-8.3a** **The TrueNAS REST API v2.0 is deprecated as of 25.04 and removed in TrueNAS 26.** The authoritative interface is the versioned **JSON-RPC 2.0 API over WebSocket**. An implementation against `/api/v2.0/…` would be obsolete upon release and would break on the next TrueNAS upgrade.
- **FR-8.3b** It follows that `truenas` is **not** an `http` toolkit, but its own executor type — persistent WebSocket connection, JSON-RPC method calls instead of path templates, its own reconnect and timeout handling.
- **FR-8.3c** The whitelist acts here on **method names** instead of on binaries or path prefixes: the toolkit declares allowed JSON-RPC methods (`pool.dataset.create`, `pool.dataset.query`, `pool.query`). Everything else does not exist — in particular not `pool.dataset.delete`.
- **FR-8.3d** Parameters are passed as JSON-RPC params, not interpolated as strings. The injection question therefore does not arise structurally; the validation from §7 still applies (dataset names, prefix restriction to `<pool>/raid/*`).
- **FR-8.3e** Authentication via TrueNAS API key from the credential store (§11). TrueNAS 26 additionally offers SCRAM-SHA-512 mutual auth for API keys — preferred when available.
- **FR-8.3f** This eliminates the original reason for `ssh`. The `ssh` executor remains relevant only for host diagnostics without API equivalent (`ps aux`, `top`) and is optional in v1.
- **FR-8.4 Correction to the Diagnostics List from v1:** The commands listed there do not consistently return host values in the container. Definitions must account for this:

  | Command | In Container | Consequence |
  |----------|--------------|------------|
  | `uptime`, `free -h`, `cat /proc/loadavg` | Host values (shared `/proc`) | `local` suffices |
  | `df -h` | only container mounts | `/mnt/raid` must be mounted |
  | `ps aux`, `top -bn1` | only container processes | needs `pid: host` or `ssh` |
  | `zpool status` | not available | needs `truenas` or `ssh` |

### The `http` Executor (SaaS and LAN APIs)

The same control concept as for process execution, translated to HTTP. What the argv template is there, the URL template is here.

- **FR-8.5** A tool definition with an `http` toolkit consists of method, path template, optional query and body templates. **Scheme and host live exclusively in the toolkit**, never in the tool definition and never in a parameter.
- **FR-8.6 Target Allowlist (Level 1):** The toolkit declares `base_url`, allowed HTTP methods, and allowed path prefixes. A definition outside these boundaries is rejected — just like the binary allowlist.
- **FR-8.7 The Agent Can Never Determine the Target.** Parameters fill exclusively path segments, query values, and body fields — URL-encoded, **one parameter = exactly one segment or one value**. This is the HTTP equivalent of FR-5.4: a parameter value cannot structurally produce an additional path segment or a different host. `..` in path segments is rejected, not normalized.
- **FR-8.8 Redirects Are Not Followed.** A 3xx is returned as a result, not executed. Otherwise the target allowlist would be worthless because the target server determines the redirect.
- **FR-8.9 SSRF Protection:** The resolved IP is checked against a per-toolkit IP/CIDR allowlist, **after** DNS resolution and immediately before connection establishment (against DNS rebinding). In the homelab, many legitimate targets are private — hence explicit allowlist instead of a blanket ban on private ranges.
- **FR-8.10 Credentials** come from the toolkit, are injected server-side as headers, and **never** appear in tool definition, parameters, response, or audit log. An agent cannot set, read, or overwrite a credential.
- **FR-8.11 No OAuth in v1.** Static credentials are supported: bearer token, API key header, basic auth. Authorization code flows, token refresh, and callback management are a separate subsystem and are justified only when a concrete service enforces them (→ §17 and Appendix B).
- **FR-8.12 Responses from External APIs Are Not Trustworthy.** Issue texts, commit messages, ticket descriptions, and file names can contain **prompt injection** and flow directly into the context of the calling agent. This is a new risk class compared to host outputs, which essentially consist of own logs. From this follows:
  - Size limitation as in FR-6.5, additionally limiting the field count for list responses.
  - Responses are marked in the MCP result as **external, untrusted data**, so that the agent does not treat them as instructions.
  - This marking is a mitigation, not a solution. The actual control remains that an agent only possesses tools whose abuse is tolerable — in particular FR-5.1a applies.

### Toolkit Catalog v1

Each service is its own toolkit with its own target allowlist and its own credential. This is the point where the toolkit abstraction pays off: a compromised Sonarr credential cannot reach Jellyfin, and neither can reach Docker.

| Toolkit | Executor | Authentication | v1 Categories |
|---------|----------|-------------------|---------------|
| `docker` | `docker` | Socket | `read`, `write` |
| `diag` | `local` | — | `read` |
| `truenas` | `truenas` | API key (WebSocket JSON-RPC) | `read`, `write` (additive) |
| `sonarr` | `http` | `X-Api-Key` header | `read`, `write` |
| `radarr` | `http` | `X-Api-Key` header | `read`, `write` |
| `jellyfin` | `http` | API key header | `read` |
| `github` | `http` | Bearer (PAT) | `read`, optional `write_external` |
| `admin` | — | Admin token, only `/admin/mcp` | — |

- **FR-8.13** All mentioned services authenticate via **static API keys in headers**. None enforces OAuth. FR-8.11 is therefore not merely a simplification for the v1 scope, but the fully sufficient solution.
- **FR-8.14** `sonarr`, `radarr`, and `jellyfin` accept the API key **also as a query parameter** (`?apikey=…`). This is to be avoided: query strings end up in the target system's access logs. gatekeeper sends credentials exclusively as headers.
- **FR-8.15** These services reside in the LAN. `allowed_cidrs` (FR-8.9) contains private address ranges for them — the IP allowlist is the only effective target restriction here and must therefore be scoped narrowly per toolkit, not as a blanket `192.168.0.0/16`.

---

## 11. Functional Requirements — Credential Management

gatekeeper holds these credentials anyway in order to execute the tools. Managing them explicitly is better than scattering them across env variables. The boundary to maintain here:

> gatekeeper is a **credential consumer with lifecycle management — not a credential provider.**

- **FR-10.1** Credentials are named objects (`cred:truenas`, `cred:sonarr`, `cred:ssh-host`). Toolkits reference them by name; they never appear in tool definitions. Kinds include `api_key_header`, `bearer`, `basic`, `ws_api_key`, `url_path`, and `docker_tls` (a JSON bundle of client cert/key/ca PEM material for a TLS-secured remote Docker destination, FR-8.3g) — each interpreted by the executor that needs it, never read back through the UI or admin API (FR-10.2 applies uniformly).
- **FR-10.2 Write-Only — the Most Important Requirement of This Section.** There is **no** operation, for **no** role, that returns a credential value: not via the admin API, not via the UI, not via a diagnostic tool. Create, rotate, delete — yes. Read — never. Otherwise gatekeeper turns from a protective wall into a central exfiltration point: a compromised admin access would disclose all the homelab's keys at once.
- **FR-10.3 Encryption at Rest** (AES-GCM or Fernet). **The master key does not reside in the same dataset as the ciphertext** — otherwise the encryption is decoration. Master key from env variable or separately mounted secret, set exclusively at deploy time.
- **FR-10.4 Mapping to the Levels from §6:** The *binding* — which toolkit uses which credential name — is **Level 1** and only changeable via redeploy. The *value* is **Level 2** and rotatable at runtime. This keeps the security model intact: the admin agent can renew the Sonarr key, but cannot redirect the `docker` toolkit to a foreign credential.
- **FR-10.5 Rotation Without Redeploy:** New value under existing name, with optional overlap phase so that in-flight calls do not break.
- **FR-10.6 Output Masking:** Before returning to the agent **and** before writing to the audit log, known credential values in stdout, stderr, and HTTP responses are replaced with `***`. This covers FR-9.6 (container logs regularly contain env variables) as well as foreign APIs that echo back an erroneous key in the error message.
- **FR-10.7 Usage Tracking:** The audit log records which tool used which credential **name** — never the value. Only this way can it be determined after an incident what needs to be rotated.
- **FR-10.8 No Passthrough:** No tool hands a credential to an agent. Agents call tools, gatekeeper authenticates. An agent does not even learn whether a particular credential exists.

### SSH Credentials

- **FR-10.9** Private SSH keys are subject to FR-10.2 like any other credential. The **public** part is readable — it must be placed in the host's `authorized_keys`.
- **FR-10.10 Host-Side Restriction Is Mandatory**, not a recommendation: entry in `authorized_keys` with `command="…"`, `restrict`, `no-pty`, `no-port-forwarding`.
- **FR-10.11** This gives the SSH path **exactly the second enforcement layer that the Docker socket lacks.** A compromised gatekeeper can do anything via the socket; via a key restricted this way, only what the host itself permits. This reverses the assessment from §10: properly restricted SSH is not the riskier, but the **better secured** variant compared to the Docker socket.
- **FR-10.12** gatekeeper cannot verify the restriction on the host itself. The toolkit must therefore explicitly declare it (`ssh_key_restricted: true`) — a deliberate assurance by the operator, logged at every startup. Without this declaration, the toolkit does not start. An assurance is weaker than a verification; this is stated here as such rather than papered over.

---

## 12. Functional Requirements — Audit

- **FR-9.1** Every call is logged: timestamp, identity (token ID, **never** the token), tool ID **and version**, parameters, claimed scope, exit code, duration, output truncated yes/no.
- **FR-9.2** Rejected calls are likewise logged, with rejection reason (401, permission missing, validation, Level-1 violation, rate limit, timeout).
- **FR-9.3** Catalog and permission changes are logged with before/after state.
- **FR-9.4** Logs are append-only, structured (JSON Lines), and reside under `/mnt/raid/gatekeeper/logs/`.
- **FR-9.5** **Rotation and Retention Period Are Mandatory.** Append-only without limit fills the disk.
- **FR-9.6** Outputs can contain secrets (`docker compose logs` regularly shows env variables and API keys). It is to be decided whether outputs go to the audit log, are filtered, or only metadata is logged (§17).

---

## 13. Non-Functional Requirements

- **NFR-1 (Security):** Container runs as an unprivileged user. Host access exclusively via enabled executors. No interactive shell access. Limitation: see FR-8.2 regarding the Docker socket.
- **NFR-2 (Performance):** < 2 s for `read`, < 30 s for `write` (`docker compose up`). Timeout upper limit configurable.
- **NFR-3 (Availability):** `restart: unless-stopped`; health probes `/health/live`, `/health/ready`, and `/health/startup` **without** authentication, but without any information about catalog or identities. The distinction is relevant because "process running" and "executors reachable" are different statements — a gatekeeper without a Docker socket is `live`, but not `ready`.
- **NFR-3a (Metrics):** Prometheus endpoint `/metrics` with call, error, and latency counters per tool and identity. Access-protected like the admin endpoint.
- **NFR-4 (Maintainability):** Level-1 boundaries and seed catalog in configuration files, not in code. Runtime catalog persisted in the dataset.
- **NFR-5 (Portability):** Docker image from the repo `davidsteg/gatekeeper`, tag pinned.
- **NFR-6 (Stack):** Python with the official MCP SDK (FastMCP). A separate FastAPI is **not** needed — FastMCP brings Starlette/uvicorn; `/healthz` is mounted as an additional route.
- **NFR-7 (Observability):** On startup, the server logs active Level-1 boundaries, enabled executors, number of active tools and identities.
- **NFR-8 (Verifiability of Security Boundaries):** This entire document claims that Level 1 holds. This claim needs evidence that is re-provided on every change — otherwise it is a statement of intent. Required is a **negative test corpus** that runs in CI and consists exclusively of cases that **must fail**:

  | Attack Class | Expectation |
  |----------------|-----------|
  | Metacharacters, line breaks, null bytes in every parameter type | rejected, audited |
  | Path traversal and symlink escape from `path_roots` | rejected |
  | Tool definition with non-enabled binary or toolkit | rejected at `create` **and** at execution |
  | Parameter that produces a second argv element or path segment | structurally impossible |
  | URL parameter that changes host or scheme | rejected |
  | Target server responds with 3xx to a foreign host | not followed |
  | DNS that resolves to a different IP after the check | connection rejected |
  | Output that contains a credential value | masked, in response **and** audit log |
  | Call of an existing tool without permission | response identical to "unknown tool" |
  | Access to a protected resource per FR-4.12 | rejected |

  A green test run proves no security. A red one proves its absence — and that is exactly what the corpus is for.
- **NFR-9 (Failure Behavior):** If an executor is unreachable — TrueNAS WebSocket down, Sonarr off — its tools fail **fast and unambiguously**, instead of hanging until timeout. Circuit breaker per toolkit, state visible in `/health/ready` and `/metrics`.
- **NFR-10 (Invalid Credentials):** If a target service responds with 401/403, this is indistinguishable from a permission error for the agent. gatekeeper translates this case into a clear message ("Credential `cred:sonarr` is rejected by the service") and marks the credential as needing review. Externally rotated keys are the most common failure reason in the homelab.

---

## 14. Deployment (Following Homelab Rules)

1. **Create ZFS dataset** (never `mkdir`): `zfs create <pool>/raid/gatekeeper`
2. **chown 568:568** on dataset and `compose.yaml` (Dockhand rule)
3. Subdirectories `config/`, `catalog/`, `logs/` in the dataset
4. **compose.yaml** in the dataset with service `gatekeeper`, Docker socket mount, Level-1 configuration
5. **Deploy via Dockhand:**
   `docker exec ix-dockhand-dockhand-1 docker compose -p gatekeeper -f /mnt/raid/gatekeeper/compose.yaml up -d`
6. **Image tag pinned** (not `:latest`), `autoUpdate: false`
7. Generate tokens, hashes into configuration, plaintext into the respective agent's `config.yaml`
8. **Extend agent `config.yaml`** with `mcp_servers.gatekeeper`

### Implementation Order

The scope has grown considerably between v1 and v2: from "fifteen allowed commands" to MCP server, auth, dynamic catalog, admin API, four executor types, encrypted credential store, audit, and UI. This is feasible, but not in one pass — and the order is not arbitrary.

| Stage | Content | Result |
|-------|--------|----------|
| **1** | MCP + Auth + Audit + `docker` + `diag`, catalog as **static seed file** | Replaces the n8n host-ops workflow. From here on, each agent has its own token — the original core problem is solved. |
| **2** | Credential store (§11) + `truenas` + `http` with **exclusively `read`** | ZFS and service queries. No write access to external services, so small attack surface with large benefit. |
| **3** | Admin API (§5), catalog becomes dynamic | Only now does an agent write the catalog. |
| **4** | Admin UI (§15), then `write_external` | Human approval exists **before** externally visible write access becomes possible. |

Two points in this are deliberately set against intuition:

**The admin API comes late, even though it is the leitmotif of v2.** A static seed catalog delivers practically the same benefit — the tools are the same — and the admin API is the largest new attack surface of the design. Building it first would mean building the foundation on the riskiest part before the simple case even runs.

**`write_external` comes last, after the UI.** Externally visible write access is the only category with consequences that cannot be undone. They should only become possible once the approval view from FR-11.4 exists.

Each stage is operational on its own. If the project stops after stage 1 or 2, something useful has still been created — not half a system.

---

## 15. Admin UI (Expansion Stage, Not v1)

In v2, an **agent** writes the tool catalog. The approval from FR-3.2 is thus the only point where a human is still in the loop — and so far it exists only as an API call that the same agent can make itself. Without a human-facing interface, the "gate" in gatekeeper is entirely agent-to-agent. This is the actual reason for a UI; convenience is the side effect.

- **FR-11.1** The UI is exclusively a **client of the admin API**. No own catalog logic, no second write path, no duplicated validation.
- **FR-11.2** Scope is deliberately **read-mostly**:
  - Audit log, filterable by identity, tool, time range, result
  - Catalog with version history and **diff between versions**
  - Permission profiles per identity including effective scopes
  - Status of Level-1 boundaries and enabled executors
- **FR-11.3** Only write operations: `enable`/`disable` of a definition and token revocation. **No tool authoring in the UI.** Definitions are written by the admin agent — authoring in the UI would enlarge the attack surface exactly where it is most expensive.
- **FR-11.4** **Approval View** as core function: new and changed definitions with complete argv template, parameter schema, result of the Level-1 check, and diff to the previous version. Approval is a deliberate action with context, not a checkbox in a list.
- **FR-11.5** Own, **session-based** authentication — not the admin bearer token. The token does not belong in a browser. A UI login is its own identity with its own audit trail.
- **FR-11.6** The UI hangs on the admin endpoint and inherits its network restriction (FR-2.10). Not publicly reachable.
- **FR-11.7** The UI is the place where a newly generated plaintext token is displayed **exactly once** — better than output in a logfile (cf. FR-2.6).
- **FR-11.8** Optional and disableable. gatekeeper remains fully functional without a UI; the UI is delivered as a separate container or as a disableable route.

**Cheaper Alternative, If the UI Is Not Built:** Grafana/Loki on the JSON Lines logs for the audit view, plus the admin agent in chat for catalog and permission queries. Costs no additional code, but loses the approval view from FR-11.4 — i.e. exactly the part that establishes human control.

---

## 16. Scope Boundaries (What gatekeeper Is NOT)

- **Not** a generic automation tool — workflows, schedules, and triggers remain in n8n. gatekeeper responds to calls, it initiates nothing.
- **Not** a generic HTTP proxy — the `http` executor reaches exclusively the hosts and path prefixes fixed in Level 1. There is no tool "fetch arbitrary URL", and there cannot be one (FR-8.6/8.7).
- **Not** an OAuth broker — static credentials yes, authorization code flows no (FR-8.11).
- **Not** a general-purpose secret store. gatekeeper manages exclusively the credentials that it **itself** needs for execution, and never returns a value (FR-10.2). Anyone looking for a vault for other consumers needs Vault or Infisical — not this.
- **Not** a full Docker API proxy — no arbitrary container access.
- **Not** a replacement for Dockhand — Dockhand remains the deployment mechanism.
- **Not** a ZFS management tool — only additive operations, and only per executor decision.
- **Not** protection against a compromised admin token beyond Level 1 — the admin token is the most critical secret of the system.
- **Not** a dashboard for container operations — the UI from §15 shows gatekeeper itself, not the state of the managed stacks.

---

## 17. Open Questions / Decisions

- [ ] **Which TrueNAS version is running?** Directly determines the implementation: from 25.04 REST is deprecated, from 26 removed (FR-8.3a). From 26, SCRAM-SHA-512 mutual auth for API keys is additionally available.
- [ ] **Master Key Storage — Conflict with Homelab Rule.** FR-10.3 requires that the master key **not** reside in the same dataset as the encrypted credential store. The homelab convention places `compose.yaml` exactly there. If the key sits as an env variable in that file, encryption is ineffective. Options: Docker secret, separately mounted file outside `/mnt/raid/gatekeeper/`, or delivery via Dockhand. **This question blocks the credential store.**
- [ ] **Enable `ssh` executor in v1?** Per FR-8.3f, only host diagnostics without API equivalent (`ps aux`, `top`) remain for it. Is that worth the additional key, or does `pid: host` on the container suffice?
- [ ] **Credential Bootstrap:** Do the first API keys come in via `admin.cred_set` after startup, or via a one-time mounted file that is then removed?
- [ ] **Hermes Transport:** Does the deployed version support Streamable HTTP, or is the deprecated SSE transport additionally needed?
- [ ] **Admin Interface:** MCP tools on `/admin/mcp` (recommendation, because the admin agent speaks MCP natively) or a separate REST API?
- [ ] **Audit of Outputs:** Full, filtered, or metadata only? Affects FR-9.6 (secrets in container logs).
- [ ] **Admin Token Bootstrap:** Generate on first start and write to log, or exclusively specify via Level-1 configuration?
- [ ] **Create repo `davidsteg/gatekeeper`?**
- [ ] **n8n Workflow:** Disable (not delete) after parallel operation — define time period.
- [ ] **Credential Duplication with n8n.** Since gatekeeper also calls service APIs, the area overlaps: n8n already holds its own credentials for Sonarr, Radarr, Jellyfin, and GitHub. Two stores for the same keys means double rotation and two audit trails that are individually incomplete. Three paths: n8n keeps its credentials (simple, but permanently duplicated), n8n calls services via gatekeeper in the future (one store, but n8n then needs its own agent token), or responsibilities are cleanly separated per service. This question arises only from stage 2 — deciding it now prevents the duplication from simply creeping in.
- [ ] **Admin UI (§15):** Build, or Grafana/Loki alternative? If building: separate container or route in the gatekeeper image?
- [ ] **UI Authentication:** Local users in the gatekeeper container, or upstream auth proxy (Authentik/Authelia), if present in the homelab?
- [ ] **Approval Mandatory?** Should `enable` be possible only via the UI (true four-eyes principle vis-à-vis the admin agent), or also via `admin.tool_enable`?
- [ ] **Toolkit Catalog Complete?** Current: `docker`, `diag`, `truenas`, `sonarr`, `radarr`, `jellyfin`, `github`, `admin`. Are Prowlarr, Bazarr, Uptime Kuma, ntfy/Pushover missing?
- [ ] **Which Agent Gets Which Service Toolkit?** Obvious: `media` → `sonarr`/`radarr`/`jellyfin`, `dev` → `github`, `homelab` → `truenas`. To be confirmed, since FR-7.5 explicitly enforces grants on tool IDs.
- [ ] **Allow `write_external` at All?** A purely read-only SaaS access (read issues, query status) has a drastically smaller attack surface than write access. Should v1 remain limited to `read`?
- [ ] **Deployment Target for the Level-1 File:** Env variables or mounted `toolkits.yaml` in the dataset? The latter is more readable but must be protected against write access from the container (read-only mount).

---

## Appendix A — Tracking v1 → v2

| v1 | Remaining in v2 |
|----|----------------|
| FR-1.1 MCP via HTTP/SSE | FR-1.1/1.2 — corrected to Streamable HTTP |
| FR-1.2 tools/list, tools/call | FR-1.3, extended with filtering (FR-1.4) and change notification (FR-1.5) |
| FR-2.1–2.3 Per-agent auth | FR-2.1–2.3, extended with hashing and admin role |
| FR-3.1 Only known actions | FR-3.x + §6 — now data-driven instead of compiled in |
| FR-3.2 Base action list | §7 seed catalog; diagnostics list corrected by FR-8.4 |
| FR-3.3 No destructive actions | FR-4.1/4.2 — binary allowlist and argument prohibitions at Level 1 |
| FR-4.1/4.2 Structured parameters | FR-5.3/5.4, FR-6.1 |
| FR-4.3 Metacharacter blacklist | **Downgraded** to FR-6.3 (defense-in-depth); primary protection is FR-5.4 |
| FR-4.4 Parameter validation | FR-5.6/5.7, FR-6.2, extended with path resolution (FR-4.3) |
| FR-5.x Audit | FR-9.x, extended with rotation, version reference, catalog changes |
| FR-6.x read/write separation | FR-7.1 — extended by the resource dimension |
| §4 Permission matrix | §9 — now two-dimensional and maintainable via API |

---

## Appendix B — Evaluated Alternatives

Recorded so that the build-vs-buy decision remains traceable and can be re-examined when requirements change.

### Composio (`composio.dev`) — Adopted as Model, Not as Basis

Tool platform for agents: 1000+ toolkits, hosted OAuth flows, MCP endpoints with tool filtering per `user_id`.

**Adopted:** the toolkit→tool hierarchy (FR-4.8 through FR-4.11), the naming convention `<toolkit>.<action>` (FR-5.1a), credentials at the toolkit rather than the tool.

**Deliberately Not Adopted:**
- **Grants at toolkit level** — see FR-7.5. Convenient there, permission escalation path here.
- **Breadth as value.** Composio's value is reach, gatekeeper's value is narrowness. Tool search and easy onboarding solve a problem that does not exist at ~15 tools, and weaken the assurance "the agent sees exactly what it is allowed to".
- **Multi-tenancy** (per-user connected accounts, hosted auth flows, `user_id` isolation) — SaaS overhead for a single-tenant homelab container.
- **Custom tools "in-process"** — exactly the code path that gatekeeper must not have.

**When to Re-evaluate:** as soon as a required service **enforces OAuth**. Authorization code flow, token refresh, callback management, and encrypted token storage per provider are a separate subsystem — exactly Composio's core business. The obvious form then is not replacement, but Composio as an upstream **credential broker**: gatekeeper keeps catalog, permissions, validation, and audit, but fetches the currently valid token from there. As long as services accept API keys (FR-8.11), the question does not arise.

**Why Not a Basis:** Composio's tools call SaaS APIs with OAuth scopes. Behind each call are still two enforcement layers — the scope and the provider's authorization. gatekeeper executes processes on the host that owns the storage, via a root-equivalent socket. **There is no downstream instance.** Level 1 (§6) exists precisely for this reason; Composio needs nothing comparable.

### SageMCP (`github.com/sagemcp/SageMCP`) — Reviewed, Not Adopted

"Multi-tenant MCP Server Platform": MCP gateway with 23 connectors and 340 tools, OAuth/API key auth, three-tier key scoping (`platform_admin` / `tenant_admin` / `tenant_user`), admin UI for enabling/disabling individual tools, rate limiting per tenant, structured JSON logging, health probes, Prometheus metrics. FastAPI/Python, React, PostgreSQL, Apache-2.0.

**Substantial overlap** with the foundation of this document: per-identity tokens, dynamically managed tool catalog, admin UI with tool enablement, audit log, health endpoints, rate limiting. This is evidence that the structure chosen here is a convergent pattern, not an idiosyncratic path.

**Why Still Not a Basis:**
1. **It does not execute host commands.** SageMCP proxies to OAuth SaaS services and starts external MCP servers as stdio subprocesses. Exactly the layer that defines gatekeeper — argv templates, binary allowlist, path roots, injection defense, Level 1 — does not exist there, because it was never needed there.
2. **Tool policy ≠ parameter validation.** Their enablement decides *whether* a tool is usable. gatekeeper must decide whether *this call with these parameters on this resource* is permitted. There is no equivalent to `stack:media-*` (FR-7.1).
3. **Maturity in the security path.** 44 stars, 103 commits, early-to-mid stage. As a dependency that holds a root-equivalent Docker socket, their bugs would be immediate root bugs on the host.
4. **Operational load.** PostgreSQL, React frontend, Kubernetes Helm charts, server pooling with LRU for 5,000 instances — dimensioned for multi-tenancy, not for three agents in a homelab.

**Adopted Ideas:** the health probe triad (`/health/live`, `/health/ready`, `/health/startup`) instead of a single `/healthz`, a Prometheus `/metrics` endpoint, encryption of sensitive configuration values at rest.

**When to Re-evaluate:** when gatekeeper grows beyond the homelab scope — multiple tenants, many agents, SaaS connectors alongside host ops. The obvious form then is not replacement, but **composition**: SageMCP's `GenericMCPConnector` can integrate gatekeeper as an external MCP server. gatekeeper remains the narrow, verifiable host component; the tenant logistics sit above it.