# Architecture

Project documentation — what the system is and how it's put together. For how
an *agent* should behave while working in this repo (release steps, testing,
pitfalls), see [AGENTS.md](../AGENTS.md). For the full requirements and
rationale behind every design decision, see [REQUIREMENTS.md](../REQUIREMENTS.md).

See [DIAGRAMS.md](DIAGRAMS.md) for the system architecture, call pipeline,
and Tier 2 change-approval flow diagrams.

## Two-tier security model

| Tier | File | Mutable at runtime | Changed via |
|------|------|:--:|-------------|
| 1 | `toolkits.yaml` | ✗ | Redeploy only (FR-4.11) |
| 2 | `tools.yaml`, `identities.yaml`, `credentials.yaml`, `pending.yaml` | ✓ | Admin UI at `/ui`, or `admin.*` on `/admin/mcp` for low-risk changes (queued to `pending.yaml` otherwise -- see below) |

A toolkit **proposal** (`toolkit_proposals.yaml`) is the one deliberate,
narrow exception: an `admin.toolkit_propose` call from `/admin/mcp` can
draft a brand-new Tier 1 toolkit, `admin.toolkit_update` can propose a
narrowly-scoped change (`executor`/`binaries`/`denied_args`/`run_as` only,
never `path_roots`/`protected_resources`/limits) to an *existing* one,
`admin.toolkit_delete` can propose removing an *existing* one (refused at
deploy time if any non-deleted tool still references it), and
`admin.credential_bind` can propose pointing an *existing* toolkit at an
*existing* credential slot (two names, never a value; toolkit-level only,
so a destination's own `credential:` override stays deploy-time) -- but
either way it only ever lands in this separate Tier 2 file -- never
`pending.yaml` --
and only a human clicking "Approve & Deploy" at `/ui/requests` (Toolkit
tab) writes it into `toolkits.yaml` and reloads it into the running
process (`Service.reload_config`, no restart). See
[`toolkit_proposals.py`](../src/gatekeeper/toolkit_proposals.py).

**Key invariant:** `store.py` (`ConfigStore`, Tier 2 writes) has no function
that writes `toolkits.yaml`. The console can create tools, identities, and
credentials through it — never a toolkit. The one exception lives entirely
outside `store.py`: `toolkit_proposals.py`'s `ToolkitProposalStore.deploy`,
reachable only from a human clicking "Approve & Deploy" at `/ui/toolkits`,
never automatically and never from `/admin/mcp` (see below).

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
`pending.yaml` queue for a human to approve at `/ui/requests` (Change tab)
-- `approve`/`reject` are not reachable from `/admin/mcp` at all, so an
agent cannot approve its own proposal. `admin.cred_propose` also lands in
`pending.yaml`, but its own approval never goes through `apply_pending`/its
`_APPLIERS` table (those are `store.py`-shaped): the dedicated
`/ui/pending/credential-fill` route calls `PendingStore.approve()` directly,
with the human-typed secret value as its `apply` callback's only extra
input -- the value itself is never written to `pending.yaml`, only the
proposed name/kind/header are. `admin.toolkit_propose` is separate
again: it never applies and never touches `pending.yaml`, only the
dedicated `toolkit_proposals.yaml`/`/ui/requests` (Toolkit tab) surface
described above -- a toolkit
changes Tier 1, not Tier 2, so it is deliberately not reachable through the
same review path as an ordinary tool/grant change.

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
| `google` | Gmail, Calendar, Drive (the bundled CLI also carries `contacts`/`sheets`/`docs`) | local subprocess (`google_api.py`), OAuth2 refresh token materialized to a per-call tempfile; whitelisted by action string |
| `microsoft` | Outlook mail via Microsoft Graph | local subprocess (`microsoft_api.py`), OAuth2 refresh token materialized to a per-call tempfile; whitelisted by action string |
| `opencode` | A headless opencode coding-agent server | HTTP; one operation = one fixed multi-request workflow, whitelisted by operation name |
| `agent` | Other gatekeeper identities | in-process mailbox (`messages.yaml`); no shell, no credential. Network only if the operator sets `GATEKEEPER_NOTIFY_URL` (best-effort delivery webhook, never agent-controllable) |

`http` toolkit boundaries (`tier1.py`'s `Toolkit`): `base_url`,
`allowed_methods`, `allowed_path_prefixes`, `allowed_cidrs`, `credential`,
`follow_redirects` (always `false` — not a configurable knob, FR-8.8).
`execute_http.py` resolves the target host itself and checks the resolved IP
against `allowed_cidrs` immediately before connecting — a hostname-only check
would leave a DNS-rebinding gap between the check and the actual connect.
A tool may carry its own `base_url` (tools.yaml, optional): when set,
`service.call` applies it over the toolkit's value the way a destination
override does (FR-8.3g/h), and the executor resolves and SSRF-checks *that*
host against the same `allowed_cidrs` — the override changes the target, not
the target restrictions.

`opencode` toolkit boundaries: `base_url`, `allowed_cidrs`, `credential`
(all three exactly as for `http`, including the pre-connect resolved-IP
check), plus `allowed_opencode_operations` and `path_roots`. It is its own
executor rather than an `http` toolkit because the useful unit of work is
not a request: `ask` is a session creation plus a message, `run` is a
session, an async dispatch and a poll loop. As `http` tools those would be
three or four agent round trips per task, with the session id and every
raw intermediate response travelling through the agent's context. So the
whitelist acts on *operation names* the way `truenas`'s acts on RPC method
names, the request paths live in `execute_opencode.py`'s one `_EP` table
and nowhere else, and no parameter on any operation carries a URL, a host
or a path. The two agent-supplied values that leave the parameter
allowlist behind are checked before execution and again in the executor:
`session_id` against a character set that cannot introduce a path segment
(it is the only value that ever reaches a request path), and `directory`
— sent as opencode's `x-opencode-directory` header, which is what lets one
toolkit fan out across repositories — against the toolkit's `path_roots`.
That check is lexical, not `realpath`-based, and its existence half runs
only where the matching root is visible in gatekeeper's own filesystem:
the path names a directory in the *opencode container's* namespace, so
resolving symlinks would resolve them in the wrong one.

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

`agent` toolkit boundaries: `mailbox_path`, `allowed_agent_operations`,
`max_message_bytes`, `max_mailbox_messages`. It is the only executor with
no target field at all -- it reaches nothing outside the container, so
what Tier 1 fixes instead is *where the mailbox file lives* and *how big
it may get*, neither influenceable by a parameter. The whitelist acts on
operation names the way `truenas`'s acts on RPC method names: a toolkit
listing only `read_messages` is a mailbox an identity may empty but never
fill. Destinations are refused -- a local file is not a target to connect
to.

### Agent-to-agent messaging (the mailbox)

`messages.py` + `execute_agent.py`. Two operations: `agent.send_message`
leaves a message in another gatekeeper identity's mailbox,
`agent.read_messages` returns the ones addressed to the caller and marks
them read.

**It is a mailbox because it cannot be a push.** MCP gives a server no way
to hand a running client an unsolicited payload. The one notification a
client acts on is `notifications/tools/list_changed` (see "Telling
connected agents the catalog changed" below), and it carries no payload by
design -- that emptiness is what makes a single fan-out compatible with
FR-1.4, and it is also what makes it useless as a transport for a message.
So delivery is "on the recipient's next `read_messages` call", never
"immediately". Reliable and restart-safe, with no client-side change.

Two values are deliberately **not** parameters, and `catalog.py` refuses a
tool definition that declares them:

* the **sender** -- `service.call` passes the authenticated identity, so
  `from` on a delivered message is a fact, not a claim;
* the **mailbox** -- `read_messages` reads the calling identity's own and
  has no argument to widen it. FR-1.4 makes an agent's *tools* invisible to
  other identities; this is the same statement for its messages.

**The store is plaintext.** `messages.yaml` is not the credential store:
nothing in it is encrypted at rest. Known credential values are scrubbed on
the way *in* (FR-10.6, applied before persistence rather than only on the
way out), so a secret gatekeeper holds cannot be laundered into a mailbox --
but that covers exactly the secrets gatekeeper knows. `read_messages`
output is marked `external_untrusted` (FR-8.12): another agent wrote that
text, and that agent may itself have been fed by a foreign API.

Bounds: one message is capped at `max_message_bytes`; a recipient's mailbox
at `max_mailbox_messages`. Read messages beyond the cap are pruned
oldest-first, but a delivery that would push the *unread* count past it is
refused -- an unread message is the only copy of what somebody meant to say.

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
2-7 starter tools + an inline-SVG logo) for 22 services: Sonarr, Radarr,
Jellyfin, Bazarr, Tdarr, Prowlarr, Home Assistant, n8n, Uptime Kuma, Immich,
Telegram, Google API (static-key subset), TrueNAS, pfSense, Jellystat,
Jellyseerr, Netdata, SABnzbd, Paperless-ngx, Docker, Linux-over-SSH, and
opencode. Most are
`http`-shaped; Docker reuses the `docker` executor's own toolkit/tool shape
(binaries/denied_args/path_roots, mirroring `config/examples/toolkits.yaml`)
and Linux reuses the `ssh` executor's, via `_tool_argv()` rather than the
http-shaped `_tool()` helper; opencode uses `_opencode_tool()`, whose tools
carry an `opencode_operation` and no request shape at all. Reachable from `/ui/tools/integrations` —
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
integration: the console's CSP (`style-src 'self' 'nonce-...'`, which no
`style` attribute matches) silently drops any
`style` it doesn't carry the nonce for, and the gallery renders every logo
on one page at once, so an unnamespaced id or class in one service's SVG
can collide with another's.

No OAuth2 in the `http` executor — it supports static credentials only
(bearer, API-key header, basic). Services that require an authorization-code
flow use the `google` executor instead (added 0.38.0), which runs
`google_api.py` as a local subprocess and materializes an `oauth2`
credential bundle to a per-call tempfile — see `execute_google.py`.
The script itself is baked into the image at
`/opt/gatekeeper/google/google_api.py` (since 0.40.1); a toolkit whose
`google_script` names a path that no longer exists — the host path
0.38/0.40.0 deployments mounted in — falls back to that copy and warns
naming both paths, at startup and on the call.

The refresh token in that bundle is obtained by the console itself
(0.46.0): `GET /ui/oauth/google/authorize` builds Google's consent URL
from the credential's `client_id`, and `GET /ui/oauth/google/callback`
exchanges the returned code and writes the refresh token back into the
same credential (`rotate` when it exists, `create` when it does not),
together with a `scopes` list — Google's own `scope` field from the token
response, not the list the consent URL asked for, because an operator may
clear a checkbox and narrow the grant. That list is what a refresh is
allowed to ask for: a request covering anything outside the grant is
answered with `invalid_scope` and the refresh fails as a whole, so it
travels into the per-call token file and `google_api.py` reads it from
there instead of guessing.
Both routes are session-gated and `role: admin`, neither is in
`server.PUBLIC_PATHS`, and neither renders, logs, or echoes a token, a
code, or the client secret — the pages say "ok" or "error" (FR-10.2/10.7).
The scopes asked for are the union of every `google` toolkit's
`required_scopes` (`Tier1.google_oauth_scopes`), read at request time,
falling back to a documented default set (`ui.DEFAULT_GOOGLE_SCOPES`,
which `google_api.SCOPES` mirrors for token files written before scopes
were stored). What carries the flow across
Google's cross-site redirect — which a `SameSite=Strict` session cookie
does not survive — is a single-use `state` bound to the operator, the
credential, and the redirect URI (`ui.OAuthStateStore`).

The `microsoft` executor is the same arrangement for Outlook mail
(outlook.com/hotmail.com and work accounts alike):
`GET /ui/oauth/microsoft/authorize` and
`GET /ui/oauth/microsoft/callback` against
`login.microsoftonline.com/common/oauth2/v2.0/{authorize,token}`, writing
the same `oauth2` bundle plus a `provider: microsoft` field, which
`service._oauth_token_env` uses to refuse a credential from the other
identity platform rather than let it fail as an unexplained 401.
`microsoft_api.py` calls Microsoft Graph v1.0 (`/me/mailFolders`,
`/me/messages`, `/me/sendMail`) with a Bearer token it mints from the
refresh token; it imports nothing outside the standard library, because
it runs as a subprocess and may not share gatekeeper's environment.
Every gate in the two route handlers is shared with the Google pair
(`ui._oauth_authorize`/`_oauth_callback`, parameterized by
`ui.OAuthProviderSpec`), including the state binding — a state minted by
one provider's flow is not redeemable at the other's callback. Two
things are Microsoft's own: the flow carries PKCE (S256), so an
intercepted code is not redeemable without a verifier that never left
this process; and `offline_access` is what makes Microsoft return a
refresh token at all, yet Microsoft omits it from the token response's
`scope` field — `ui._granted_microsoft_scopes` adds the reserved scopes
the consent screen asked for back, or the next refresh would stop asking
for it and the credential would go quietly read-only.

### Three names for one operation

Three names describe one operation on both CLI-backed executors (`google`
and `microsoft`), and they are not interchangeable:

| | Outlook example | Google example | Who owns it |
|---|---|---|---|
| **Tool ID** | `outlook.list_messages` | `drive.create_folder` | tools.yaml / the console; dotted, lowercase + underscore (catalog.py's `id` rule). What an agent calls over `/mcp`. |
| **Action ID** | `mail list` | `drive create-folder` | `microsoft_action` / `google_action` on the tool, and the toolkit's `allowed_microsoft_actions` / `allowed_google_actions`. Tier 1 matches the two as an **exact string** — no normalization, at catalog load and again in the executor. |
| **CLI argv** | `mail list --folder inbox --max 10` | `drive create-folder <name> --parent <id>` | the bundled CLI's argparse grammar: `microsoft_api.py` (`mail` + `list`/`get`/`folders`/`send`), `google_api.py` (`gmail`/`calendar`/`drive`/`contacts`/`sheets`/`docs`, each with its own actions). Built by `execute_microsoft._build_argv` / `execute_google._build_argv`. |

The tool ID is never compared against a whitelist, and nothing derives one
name from another: `drive.create_folder` and `drive create-folder` differ
in more than the separator, and a `google_action` written as `drive
create_folder` is an `invalid choice` at the CLI even though the tool ID
spells it that way.

On the Microsoft side a deployment may legitimately spell its action IDs
after its tool IDs — whitelist and `microsoft_action` both reading
`list_messages` — which is internally consistent, passes every Tier 1
check, and used to reach the CLI as `mail list_messages`, i.e. `invalid
choice` on every call.
`execute_microsoft.MICROSOFT_ACTION_ALIASES` is the bridge: a fixed
four-entry table (`list_messages`→`list`, `get_message`→`get`,
`list_folders`→`folders`, `send_mail`→`send`) applied when the argv is
assembled, *after* the whitelist check, so it translates spelling and
widens nothing — a toolkit listing only the three read actions still
refuses a send under either name. An action the table has never heard of
is passed through untouched and fails at the CLI, which is the right
outcome for a name nobody vetted.

There is no counterpart table on the `google` side: a `google_action` is
expected to be the CLI's own spelling already, which every shipped google
tool and starter integration uses. What both executors do supply is the
*service* token when the action ID omits it (`labels` → `gmail labels`),
and both take it from the toolkit's name.
`execute_google._service_prefix` recognizes `gmail`/`calendar`/`drive`
(`GOOGLE_SERVICES`) and prefixes nothing for a toolkit whose name matches
none of them, so an action on the CLI's `contacts`, `sheets` or `docs`
services has to name its service itself (`sheets get`, not `get`).
`execute_microsoft` has exactly one service (`mail`) and therefore always
has an answer.

`google_args`/`microsoft_args` map a parameter to its argv shape, and
both are read by one parser (`catalog._parse_cli_args`) and built by one
function (`validate._build_cli_args`), because the two CLIs take the
same argv shape. An entry is exactly one of three:

| Declaration | Argv | Parameter |
|---|---|---|
| `{positional: true}` | the bare value | any type |
| `{flag: --name}` | `--name <value>` | any type |
| `{switch: --name}` | `--name`, or nothing at all | must be `type: boolean` |

A parameter the tool declares **optional and the agent did not supply is
left off the argv**, so the CLI's own default applies (`--folder` →
inbox, `--max` → 10): the MCP input schema lists only `required: true`
names in its `required` array, so denying those calls would make a tool
unusable exactly as its own schema documents it. A *positional* with no
value is still a denial (dropping it would shift the next positional
into its place), as is a mapping naming a parameter the tool never
declared.

### Booleans: `switch:`, not `flag:`

A `flag:` entry always emits a value, so a boolean behind one becomes
`--unread true`. That is not what either bundled CLI takes: `--raw-query`
(`drive search`), `--unread` (`mail list`) and `--html` (both send
actions) are argparse `store_true` options, which reject a value and exit
2 over it. `switch:` is the valueless declaration for exactly that shape:

```yaml
google_args:
  query:
    positional: true
  raw_query:
    switch: --raw-query      # emitted when true, absent when false
parameters:
  raw_query:
    type: boolean
    required: false
    description: Treat the query as a raw Drive API query.
```

`true` emits the fixed token **exactly once**; `false` and "not supplied"
both emit nothing, which is precisely what `store_true`'s own default
means. The boolean never reaches the argv, so a switch contributes one
token from the tool definition or none — there is no element an agent
could put its own text in, and no way to smuggle a second argument
through one entry.

A switch is validated at **load**, not at call time, because unlike a
valued entry it has nothing that could be missing — it would emit its
flag from a declaration nobody could satisfy. `catalog._parse_cli_args`
rejects a switch that also sets `flag`/`positional`, one whose parameter
is absent or not `type: boolean`, and one whose flag is not a single
option token (`SWITCH_RE`: no whitespace, no `=`, no `{placeholder}`).
`config/examples/tools.yaml` and the `google` integration's
`drive.search` starter tool carry the worked example.

tests/test_cli_arg_contract.py pins all of this: the argv for both
providers, the rejected declarations, a census holding every shipped
boolean to a `switch:`, and the two CLIs' own argparse grammars — run
in-process with the action handler replaced, so `--raw-query` is checked
to actually arrive as `raw_query is True`, and `--raw-query true` to
actually exit 2. The same file runs every shipped google and microsoft
tool's *minimal* argv — required parameters only, every optional one
omitted — through the real CLI as a subprocess, with `HERMES_HOME`
pointed at an empty directory: each call dies at authentication, after
argparse has accepted the argv and before any request leaves the
process.

## Recovery supervisor (`recovery.py`)

The supervisor is off unless `recovery.enabled: true` is set in toolkits.yaml.
Its job is to get a stuck Hermes task moving again without a human typing
"continue", and nothing more. The Hermes side is specified in
[HERMES_ADAPTER.md](HERMES_ADAPTER.md) and does not exist yet.

**Who owns what.** Hermes owns planning, delegation, Kanban tasks, result checks
and user replies. Gatekeeper owns permissions, execution and operation status.
The supervisor owns incidents, cooldowns, duplicate protection, one rescue
consultation, and one continuation key per incident. It never executes a tool,
never retries one for the agent, and never plans.

```
tools/call (+ _meta.hermes) ──► Service.call ──► executor
                                    │ outcome
                                    ▼
                           RecoverySupervisor ──► recovery.yaml
          guidance in the   ◄───────┤   ├──► rescue model (diagnostic, no tools)
          tool response             │   ├──► decision provider (optional, off)
                                    │   └──► Hermes adapter: /status /continue /continuation
POST /recovery/events ──────────────┘
```

**Keys and ordering.** Incidents are keyed by `(installation, board_id, task_id)`
plus a `task_generation`. The installation comes from the identity. A
client-supplied installation, or a profile outside the installation's list,
drops the correlation on a tool call and gets a 403 on an event. A client
whose MCP stack cannot send per-call `_meta` (Hermes v0.21.6) sends the same
object as the reserved argument `_hermes_recovery`, which `server.on_call_tool`
strips from every call before the pipeline sees it. Ordering uses
the integer `turn_seq`, never the opaque `turn_id`. Every correlated call and
event needs an `event_id`, and duplicates are dropped across restarts.

**Fixed rules, in order.**

| Failure or event | What happens |
|---|---|
| Explicit user stop | Incident suppressed, cooldown or not. Never overridden. |
| Task completed, cancelled or superseded | Only that task and generation is closed. A worker's completion never closes its parent. A higher generation starts a fresh lifecycle. |
| Permission or policy denial | Blocked at once. One identical text for every FR-7.7-opaque reason. |
| Rate limit, or client-reported breaker cooldown | One status check when the cooldown ends, then a continuation if the turn is stopped. |
| `unknown` outcome on a non-idempotent tool | "Check status first". An exact repeat is refused with `recovery_hold` until a successful read on the same toolkit. |
| Invalid arguments, missing dependency | After `trigger_after` failures: targeted correction. |
| Other repeated failure | After `trigger_after` failures: the optional decision provider may choose among the actions the rules still allow. Otherwise one rescue consultation (if configured), then "change approach". |

`max_recoveries_per_task` bounds guidance and continuation rounds across all
of a task's incidents.

**Continuation.** `/continue` carries `expected_turn_seq` and a stable
`idempotency_key`. The adapter validates ownership, that no turn is active, and
the sequence number atomically. A rejection because a user message won the race
(`turn_active`, `superseded`, `turn_seq_mismatch`) costs no recovery. An
ambiguous delivery (a timeout, a 5xx, or Gatekeeper crashing after it recorded
"sending") is resolved through `/continuation`, never by blind re-sending. At
most one re-send is made, with the same key.

**Delivery is not recovery.** The incident moves through four stages:

1. `accepted`: the adapter returned a `continuation_id`.
2. Started: `/status` shows that id on an active turn.
3. `active`: an executed tool call carries that id.
4. `recovered`: `last_progress_at` moved past acceptance.

`task_completed` then marks the incident `resolved`. If no activity arrives
within `ack_timeout_seconds`, the outcome is `unacknowledged`. If no progress
follows activity within `progress_timeout_seconds`, it is
`blocked:no_progress_after_continuation`.

**Crash coverage.** Hermes emits `interrupted` on startup for turns that were
active when it went down. Independently, an open incident with no traffic for
`reconcile_after_seconds` is checked against `/status`, at most `max_reconciles`
times.

**v1 limit.** A turn that stops without any prior Gatekeeper failure has no
incident and is not resumed.

**Rescue.** An OpenAI-compatible `chat/completions` call with no tools. The
exact `model` is checked against `GET /models` before first use. Calls are
capped by `timeout_seconds`, `max_tokens`, one per incident and `max_per_hour`.
The advice is labeled untrusted. A failure ends as `blocked:rescue_failed`.

**Decision provider (optional, off).** A small interface: the input is redacted
attempts, status, remaining budget and `allowed_actions`; the output is a
validated `{action, rationale, evidence}` from a fixed enum. It is consulted
only at the "other repeated failure" step, after every fixed rule has run.
Anything else (a disallowed action, invalid output, a timeout, an unavailable
provider) falls back to the deterministic choice. Shadow mode logs the proposal
but applies the deterministic choice. No concrete provider is registered, so
enabling it is a startup error until a provider (for example Jev) is verified.
See HERMES_ADAPTER.md §7.

**Lifecycle route.** `POST /recovery/events` (bearer auth, agent role) executes
nothing, so it can be used while Hermes's breaker around the tools is open.
`GET /recovery/incidents` is read-only, scoped to the caller's installation.

**State and logs.** `recovery.yaml` is written atomically and holds incidents,
task ledgers, seen event ids, holds, and continuation keys. Every transition is
a JSON line on the `gatekeeper.recovery` logger and a `"kind": "recovery"` audit
record. Those carry the incident, task, consultation and continuation ids; for
decisions, they also carry the provider, model, proposed and accepted action.
They never carry prompts.

**Rollback.** Set `recovery.enabled: false` and SIGHUP. Every hook returns
immediately, `/recovery/*` answers 404, and no hold is enforced.
`recovery.yaml` can be deleted afterwards.

## Release-bound artifacts (`artifacts.py`, `artifact` executor)

Some files Gatekeeper serves to agents: the Hermes adapter contract
(`docs/HERMES_ADAPTER.md`) and the adapter itself
(`contrib/hermes-recovery-adapter/`). Each is bound to exactly one commit.

**Git is the only source.** Nothing is uploaded. The image build runs
`python -m gatekeeper.artifacts`, which packages those fixed repository paths
into `/opt/gatekeeper/artifacts/`, together with a `manifest.json` (schema,
release, commit, and per file its sha256, size and source path). The commit
comes from CI (`GATEKEEPER_COMMIT`); a local build says `unknown`. The tar.gz
is deterministic: entries sorted, mtime 0, owner root, line endings
normalized. The release job copies those exact files out of the published
image for the GitHub release; it does not rebuild them, because gzip output
depends on the zlib build. One image carries the artifacts of its own release
only.

**Serving.** `ArtifactStore` reads the directory read-only and verifies every
file against the manifest at load; a mismatching file is disabled. All bytes
leave through one function, `ArtifactStore.stream`, which re-verifies the
sha256 over exactly the bytes it hands on.

| Surface | What it does |
|---|---|
| `artifact.list` / `artifact.info` | release, commit, sha256, size, download path |
| `artifact.read` | text artifacts inline (the contract), within `max_output_bytes` |
| `artifact.transfer` | copies into the toolkit's `handover_dir` (see below) |
| `GET /artifacts/{id}[/{version}]` | authenticated download (bearer token); `X-Artifact-SHA256`, `X-Artifact-Commit`, ETag |

**Gates.** Every surface requires all three of:

1. The artifact must be in an `artifact` toolkit's `allowed_artifacts`.
2. The caller must hold the scope `artifact:<id>`.
3. A version, if given, must be the commit or a prefix of at least 7 hex
   digits.

Anything else, including an unknown id or a missing scope, is one
indistinguishable answer (FR-7.7). The tools have no path, URL or target
parameter; `catalog.py` refuses a tool that declares one.

**Transfer.** `artifact.transfer` writes to
`<handover_dir>/<id>/<version>/<file>`. `handover_dir` is Tier 1; the rest of
the path comes from the manifest. The transfer:

- reads through `ArtifactStore.stream`, the same path the HTTP download uses;
- writes to a temp file, verifies the sha256 and only then renames;
- writes nothing when verification fails;
- leaves a target with the same sha256 alone (idempotent);
- refuses a different existing file instead of overwriting it.

Files belong to the Gatekeeper process user; `run_as` is not supported on
`artifact` toolkits and is refused at load. No credential is involved anywhere.

## Project structure

```
src/gatekeeper/
  __init__.py       __version__, derived from pyproject.toml at import
                      time -- never a second hardcoded string to drift
  __main__.py        Entry point: CLI (serve/check/init/token/password/
                      credential-key/integration), bootstrap, SIGHUP handler
  release_notes.py    Where RELEASE.md is and how it splits into versions
                       -- one copy, read by the console popup, /release and
                       admin.release_notes alike
  server.py           MCP protocol, ASGI middleware, health/metrics/release
                       routes;
                       composes /mcp and /admin/mcp into one Starlette app
                       with a combined lifespan (two independent
                       StreamableHTTPSessionManagers, one per Server).
                       /mcp retains sessions, /admin/mcp is stateless --
                       see "Telling connected agents the catalog changed"
  notifications.py     CatalogNotifier: fans notifications/tools/
                       list_changed out to every connected agent, on both
                       protocol eras. Owned by Service, so the writes that
                       change a catalog announce it without knowing about
                       the ASGI layer
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
                       approved only via /ui/requests, Change tab (human + CSRF)
  toolkit_proposals.py  ToolkitProposalStore (toolkit_proposals.yaml) --
                       admin.toolkit_propose (new toolkit, kind="create"),
                       admin.toolkit_update (executor/binaries/
                       denied_args/run_as change to an existing one,
                       kind="update"), admin.toolkit_delete (remove an
                       existing one, kind="delete") and
                       admin.credential_bind (point an existing toolkit at
                       an existing credential name, kind="bind") all land
                       here, never pending.yaml.
                       deploy() merges/removes + validates via load_tier1()
                       before writing toolkits.yaml, then calls
                       Service.reload_config() in-process (no restart).
                       Only reachable from
                       /ui/requests, Toolkit tab (human + CSRF)
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
  execute_microsoft.py The `microsoft` executor: the `google` one with
                       Microsoft Graph behind it -- runs
                       `_microsoft_api/microsoft_api.py` (stdlib only,
                       baked into the image at
                       /opt/gatekeeper/microsoft/) and parses its JSON,
                       whitelisted by action string. Shares
                       execute_google's subprocess runner and
                       execute_http's JSON cap
  execute_opencode.py  The `opencode` executor: one operation = one fixed
                       multi-request workflow against a headless opencode
                       server; reuses execute_http's SSRF/credential/JSON-cap
                       helpers, request paths fixed in its own `_EP` table
  execute_agent.py     The `agent` executor: two in-process mailbox
                        operations (send_message/read_messages), no shell
                        -- the sender is the authenticated identity,
                        never a parameter. Optional deploy-time delivery
                        webhook (`_notify_delivery`) when
                        GATEKEEPER_NOTIFY_URL is set; best-effort, never
                        agent-controllable, never fails a delivery
  messages.py          The mailbox file (messages.yaml) behind it, written
                       with `_atomic.py`'s primitives like pending.yaml
  execute_truenas.py   The `truenas` executor: JSON-RPC 2.0 over WebSocket
  execute_ssh.py        The `ssh` executor: binary+argv over an SSH exec
                       channel, mandatory host-key pinning
  credentials.py       The write-only, encrypted credential store
  integrations.py      Starter toolkit/tool definitions + logos for 22
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
  artifacts.py         Release-bound artifacts: deterministic build from repo
                       paths (image build), read-only store with sha256
                       verification -- see "Release-bound artifacts"
  execute_artifact.py  `artifact` executor: list/info/read/transfer
  recovery.py          Recovery supervisor (feature-flagged): incidents in
                       recovery.yaml, classification, cooldowns, rescue
                       consultation, Hermes continuation -- see "Recovery
                       supervisor"
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
  test_execute_truenas.py, test_execute_ssh.py, test_execute_opencode.py,
  test_integrations.py, test_agent_messaging.py,
  test_ui_credentials.py, test_ui_integrations.py, test_admin_mcp.py,
  test_catalog_versioning.py, test_pending.py, test_notifications.py,
  test_mcp_live_catalog.py, conftest.py
```

## UI architecture (`ui.py`)

**Script-free, with no exception.** CSP (`_respond`): `default-src 'none';
style-src 'self' 'nonce-...'; img-src 'self' data: https://cdn.jsdelivr.net;
manifest-src 'self'; worker-src 'self'; form-action 'self';
frame-ancestors 'none'; base-uri 'none'`. There is no `script-src`
directive at all, so `default-src 'none'` covers scripts on every page —
the invariant `ui.py`'s module docstring states. Any per-service logo
(integrations) ships as inline SVG in `integrations.py`, never a hotlinked
image.

`style-src` carries `'self'` because the stylesheet is no longer inlined
into each page: `_STYLE` is served once from a content-addressed route,
`/ui/static/gatekeeper.<sha256-16>.css` (`_STYLE_PATH`, in
`UI_COMPANION_PATHS`), with `Cache-Control: public, max-age=31536000,
immutable`. The URL is derived from the stylesheet's own hash, so a changed
style is a changed URL and no cache outlives an upgrade. The nonce
allowance stays for the per-page `<style>` blocks. Cache policy splits by
content: HTML shells keep `no-store` (permission and audit data), the
stylesheet is immutable. Every `/ui` route is additionally wrapped in
Starlette's `GZipMiddleware` (`minimum_size=500`) in `build_ui_routes()`.

Diagrams are server-rendered SVG or HTML, built with no client code:
- **Access map** — `_access_matrix()`: a server-rendered identity×toolkit
  HTML grid, one row per identity, a heat class per cell from the audit
  log's call counts (`_view_access_map`, with a `?q=` filter over identity,
  role, toolkit and executor names). Embedded on Overview and as a
  dedicated page at `/ui/access-map`. The Cytoscape.js graph and its
  client-side successor are both gone (0.20.0) — `_access_graph_data()`
  survives as a JSON view of the same graph with no route of its own, used
  only by `test_destinations.py`.
- **Tool matrix** — `_tool_matrix()`: HTML table, one tool per row; the
  `/ui/tools` Cards/Matrix toggle (`?view=matrix`) switches to it in place
  of the per-toolkit tool cards
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

The modal embeds only the newest `RELEASE_NOTES_MODAL_SECTIONS` (3)
entries and links the rest to `/ui/docs?doc=release`, which renders the
same file in full. The cap is about page weight, not about the parser:
every page in the console carries this modal, so embedding all of
`RELEASE.md` put ~290 KB of HTML on every single response and grew by one
entry per release, forever. `_load_release_notes()` still parses and
caches every section.

## Audit log format

JSON Lines, one record per line:
```json
{"kind": "call", "identity": "dev", "tool": "docker.compose_ps", "tool_version": 1, "parameters": {}, "scopes": [], "outcome": "ok", "exit_code": 0, "duration_ms": 42, "ts": "2026-08-16T10:00:00+0000"}
```

Kinds: `call`, `auth_failure`, `startup`, `admin_change`, `admin_denied`,
`ui_login`. Outcomes for `call`: `ok`, `denied`, `failed`, `unknown`
(timeout on a non-idempotent tool — the operation may have completed on the
other side, so it is not reported as a failure that would provoke a retry).

## Telling connected agents the catalog changed

A Tier 2 write reloads the state it wrote, synchronously and in-process, so
`tools/list` is live from the very next request. What used to be missing is
the other half: **nothing told a client to ask again.** MCP clients fetch
the tool list once when the session is established and keep it, so a tool
created by `admin.tool_create` stayed invisible to every already-connected
agent until it reconnected.

`notifications.py`'s `CatalogNotifier` closes that gap. It lives on the
`Service`, so the two places that can change what an agent may call --
`ConfigStore._write_tools` / `_write_identities` and `Service.reload_config`
(the SIGHUP and toolkit-deploy path) -- announce the change without knowing
anything about the transport. The announcement is fire-and-forget by
design: an admin write must not fail, or wait, because a client went away.

How the notification reaches a client depends on the protocol era, and
`/mcp` serves both:

| Era | `tools.listChanged` comes from | Delivered on |
|---|---|---|
| 2026-07-28+ | serving `subscriptions/listen` | the listen stream the client opened (a long-lived POST) |
| 2025-11-25 and earlier | `NotificationOptions(tools_changed=True)` in the `initialize` reply | the standalone SSE stream from `GET /mcp` |

The second row is why `/mcp` runs **stateful** (`stateless_http=False`)
while `/admin/mcp` stays stateless: a standalone stream only exists if the
transport keeps the session between requests. Sessions are tracked by the
`Mcp-Session-Id` the transport assigns, dropped when the client sends
`DELETE /mcp`, reaped after an hour with no request
(`server.SESSION_IDLE_TIMEOUT_SECONDS`), and bounded by an LRU so a client
that vanishes without either cannot grow the map. `/admin/mcp` has nothing
to announce -- its tool list is a fixed constant -- so it gains nothing from
holding sessions.

The notification carries no payload. It says "your list is stale", not what
changed, so broadcasting it to every session tells no agent anything about
another agent's catalog -- which is what makes a single fan-out compatible
with FR-1.4's per-identity filtering of `tools/list` itself.

## Scale: single instance, blocking I/O by design

gatekeeper runs as one process (`ratelimit.py`'s `RateLimiter` says so
directly: "with multiple instances the counter would need to be shared").
Within that scope, several hot paths do plain synchronous file I/O on the
asyncio event loop rather than using a thread pool or an async file API:

- `AuditLog.write` (`audit.py`) opens and appends the log file per call.
- `CredentialStore._raw()` (`credentials.py`) re-reads and re-parses
  `credentials.yaml`, and re-runs Fernet decryption, on every credential
  resolution -- there is no in-memory cache of the decrypted value.
- `ui.py`'s `read_audit` reads the audit log on every render of a page
  that shows it. It walks backwards from EOF in `AUDIT_CHUNK_BYTES`
  (256 KB) chunks and stops once it has the `limit` records the page
  asks for, so a typical 200-row page decodes one chunk rather than the
  whole window; `AUDIT_READ_BYTES` (2 MB) remains the floor it will not
  read past, and reaching it is what sets the `truncated` flag.

The console's read pages are the exception: every view behind `guarded`
renders on a worker thread (`asyncio.to_thread`), because a page's cost
grows with data the operator does not control -- a few hundred decided
proposals once made each page take seconds, with every MCP call queued
behind it. `pending.yaml` and `toolkit_proposals.yaml` are additionally
parsed once per distinct content (`_atomic.load_cached`), since every page
counts their pending entries for the sidebar badge.

This is a deliberate choice, not an oversight: at the scale gatekeeper
targets (per NFR-5/§14, a handful of agents against a single homelab
instance), the cost of each is a few milliseconds against local disk, and
the code stays straightforward to read and audit -- which matters more
here than shaving milliseconds off a request rate this project was never
sized for. It stops being free past roughly the point where either
concurrent call volume or `credentials.yaml`'s size make a single-digit-
millisecond block on the event loop start queuing noticeably, or where the
audit log's read cost per UI page load becomes the visible bottleneck
(watch `read_audit`'s truncation behavior on a directory nearing
`audit_max_bytes` per file as the practical early signal). If gatekeeper
ever needs to scale past a single instance or a much higher call rate,
these three are the first places to revisit -- alongside `RateLimiter`
itself, which already documents its own single-instance assumption.

## Roadmap / known gaps

See [ROADMAP.md](ROADMAP.md).
