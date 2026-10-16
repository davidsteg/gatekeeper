# Roadmap / known gaps

Project documentation of what is and isn't built. See
[REQUIREMENTS.md](../REQUIREMENTS.md) for the full specification behind each
item.

## Implemented

- Console JSON API at `/api/v1`: session sign-in with the console password, CSRF, ETag /
  If-Match, viewer/admin roles, bearer tokens refused; overview, tools,
  identities, credential metadata, toolkits, requests, audit,
  stats, bundled docs and release notes, plus every console write and
  OAuth sign-in (`api/`)
- The console at `/app` (the only console since 1.0.0): Vite + React + TypeScript,
  types generated from the API schema, served by gatekeeper under a
  `script-src 'self'` + Trusted Types CSP, built in a Node-only Dockerfile
  stage, with its own CI job (`frontend/`). `/ui` paths redirect there
  (1.0.0); only the OAuth callbacks stay under `/ui/oauth/`, as the
  redirect URIs registered with Google and Microsoft
- Two-tier config (Tier 1 immutable / Tier 2 runtime-mutable)
- `docker` and `local` executors
- `http` executor — SSRF-safe, no redirects followed, credential-as-header
  injection, response size/field capping, external-data marking (`execute_http.py`)
- `truenas` executor — JSON-RPC 2.0 over WebSocket, RPC-method whitelist
  (`execute_truenas.py`)
- `ssh` executor — reuses the `docker`/`local` binary+argv tool shape
  exactly (REQUIREMENTS.md §17), executed on a remote host over SSH;
  mandatory host-key pinning (`ssh_known_hosts`, no MITM-prone
  `known_hosts=None`), each argv element `shlex.quote`d before joining
  into the single command string SSH's exec channel requires
  (`execute_ssh.py`). One toolkit = one host; no destinations support yet
  (see below).
- `microsoft` executor — Outlook mail over Microsoft Graph
  (`execute_microsoft.py` + `_microsoft_api/microsoft_api.py`): list
  messages, get message, list folders, send mail, whitelisted by
  action string per toolkit. The console signs in from
  `/app/credentials` (authorization code + PKCE against
  the `common` authority, so outlook.com/hotmail.com accounts work)
  and stores the refresh token and the granted scopes in the same
  `oauth2` credential kind the `google` executor uses.
- `opencode` executor — drives a headless opencode coding-agent server
  over its own HTTP API (`execute_opencode.py`). Eight operations
  (`ask`/`run`/`fire`/`check`/`review_changes`/`abort`/`providers`/
  `health`), whitelisted by name per toolkit the way `truenas` whitelists
  RPC methods; one operation is a fixed multi-request workflow, so a task
  is one agent round trip rather than four. Reuses `execute_http.py`'s
  SSRF check (resolved IP re-checked before *every* request), credential
  header injection, and JSON field capping. A `directory` parameter,
  checked against the toolkit's `path_roots`, becomes opencode's
  `x-opencode-directory` header — one toolkit therefore serves every
  project root listed there.
- `kuma` executor (1.12.0) — Uptime Kuma monitors over Socket.IO
  (`execute_kuma.py`), the only interface Kuma offers for them. Four
  operations, whitelisted by name per toolkit: `monitor_list` (projected
  fields only, no secrets), `monitor_add_http` (type, method and
  notifications fixed; name, URL, interval 30–3600 s and accepted status
  from a fixed set), `monitor_pause`/`monitor_resume` (only monitors
  gatekeeper created, recognised by their description). No delete, edit,
  notification or settings change exists in the module. Login is a `basic`
  credential in the store; the target check is `execute_http.py`'s.
- `agent` executor — a mailbox between gatekeeper identities
  (`execute_agent.py`, `messages.py`). `agent.send_message` addresses
  another identity, `agent.read_messages` collects the caller's own and
  marks them read. Deliberately a **mailbox, not a push**: MCP gives a
  server no way to hand a running client an unsolicited payload, and the
  one notification a client acts on (`tools/list_changed`) carries none by
  design — so delivery is on the recipient's next call, without any
  client-side change. The sender is the authenticated identity and the
  mailbox is the calling one; neither is a parameter, and `catalog.py`
  refuses a tool definition that declares them. Messages sit in plaintext
  in `mailbox_path` (known credential values scrubbed on the way in);
  `read_messages` output is marked `external_untrusted` (FR-8.12).
- Credential store — write-only, encrypted at rest (`credentials.py`).
  Kinds: `api_key_header`, `bearer`, `basic`, `ws_api_key`, `url_path`,
  `url_query`, `docker_tls`, `ssh_private_key`
- Destinations — a `docker`/`http`/`truenas` toolkit may declare several
  named targets (e.g. two Docker hosts); tools expand at catalog-load time
  into destination-qualified, independently-grantable IDs
  (`docker.compose_up@nas1`) — REQUIREMENTS.md FR-8.3g-j (`tier1.py`,
  `catalog.py`)
- Toolkit reference — one copy-pasteable toolkit block per executor at
  `/app/toolkits/reference` (`toolkit_reference.py`). The per-service
  Integrations library (`integrations.py`, `/app/tools/integrations`,
  `gatekeeper integration`) was removed in 1.4.0.
- `write_external` category — distinct rate-limit bucket, agent-facing
  "cannot be undone" warning, requires an explicit grant
- **Live catalog change notification (FR-1.5)** — `/mcp` advertises
  `tools.listChanged: true` and sends `notifications/tools/list_changed` to
  every connected session whenever a write changes what an agent may call
  (tool create/update/enable/disable/delete, grant and role changes, a
  deployed toolkit proposal, a SIGHUP reload). Both protocol eras are
  served: a `subscriptions/listen` stream at 2026-07-28+, the standalone
  `GET /mcp` SSE stream before it (`notifications.py`)

- **Release-bound artifacts (`artifact` executor, 0.50.0)** — fixed
  repository paths built into the image and bound to the release commit.
  They are listed, read and checksummed over MCP, downloadable over
  authenticated HTTP, and transferable into a Tier 1 `handover_dir` with
  sha256 verification. The GitHub release carries the same manifest. No
  sources are declared since 0.52.0, when the Hermes recovery adapter (the
  only artifact) was removed.

## Not implemented (by design or not yet)

- **A browser smoke test of the console in CI.** The console migration is
  finished (JSON API 0.53.0, SPA 0.54.0, writes 0.55.0, request decisions
  0.56.0, parity 0.57.0, cutover 1.0.0), and vitest covers the pages, but a
  Playwright run against the built image is not in CI yet.

- **Artifact transfers as another user (`run_as`) and older artifact
  versions.** A transfer writes as the Gatekeeper process user. An image
  serves only its own release's artifacts.

- **Session recovery or continuation, by design (removed in 0.52.0).**
  Gatekeeper never wakes, continues or re-prompts an agent session. The
  recovery supervisor (0.48.0–0.51.0), its rescue and decision providers,
  `/recovery/*` and the Hermes recovery adapter were removed: deployments
  run unchanged official Hermes images, whose native orchestration already
  handles worker result → wake → check → targeted follow-up. Not to be
  rebuilt as a replacement supervisor.

- **Pushing a message into an agent's *running* session.** Not a gap in the
  mailbox above — a protocol limit. An MCP client does not listen for
  arbitrary server-initiated payloads; the only notification a client like
  Hermes acts on is `notifications/tools/list_changed`, and it carries no
  payload by design (see `notifications.py`). So the earliest a message can
  reach agent B is B's next tool call, and `agent.read_messages` is that
  call. Closing this would mean changing the *client*, not gatekeeper — an
  out-of-band channel (a webhook into the agent's host, a session-side
  poller) rather than anything the MCP surface can offer. Deliberately not
  faked: a "notify" that only fires when the recipient happens to call
  something anyway is the mailbox with a misleading name.
- **Nested `params_template` values** — the `truenas` executor's
  `params_template` (`validate.py`'s `build_rpc_call`) only substitutes
  flat string placeholders into a positional argument list; it cannot
  build a single positional argument that is itself an object. This is
  why `config/examples/tools.yaml` has a TrueNAS `zfs.snapshot.delete`
  (single string `id` argument) but no `zfs.snapshot.create`, whose real
  signature takes one nested object (`{dataset, name, recursive}`).
  Extending `params_template` to accept nested dict values, substituting
  their leaves the same way, would close this.
- **OAuth2 — done for Google Workspace (0.38.0).** The `google` executor
  runs `google_api.py` as a local subprocess, materializes an `oauth2`
  credential bundle (client_id/client_secret/refresh_token, plus the
  scopes the grant covers) to a per-call tempfile, and parses JSON
  output. Starter tools cover Gmail, Calendar and Drive; the bundled
  `google_api.py` also dispatches `contacts`, `sheets` and `docs`, which a
  toolkit may whitelist as action strings although no starter tool ships
  for them. The refresh token is obtained in the console since 0.46.0
  (started from `/app/credentials` since 1.0.0; the callback is still
  `/ui/oauth/google/callback`), so no
  setup script outside gatekeeper handles it. Microsoft went the other way
  (0.46.3): its own `microsoft` executor and its own consent routes, a
  sibling of the Google pair rather than a toolkit on it, because the
  Google routes' endpoints and scope prefix are constants rather than
  configuration — the shared parts are factored into
  `ui._oauth_authorize`/`_oauth_callback` (see "Implemented" above).
- **`ssh` destinations** — a `docker`/`http`/`truenas`/`opencode` toolkit
  can declare several named destinations (see below); `ssh` toolkits can't
  yet (`tier1.py` rejects a `destinations:` list on an `ssh` toolkit) — one
  toolkit per host for now, add another toolkit for a second host.
- **The opencode request paths track an external API.** They live in one
  table (`execute_opencode.py`'s `_EP`) precisely so a future opencode
  release that moves an endpoint is a one-line change rather than a hunt
  through eight workflows. The response *readers* are deliberately
  tolerant for the same reason: several field names are accepted for each
  value, and an operation whose summary came back empty attaches the raw
  (capped) payload instead, so an upstream rename costs a less tidy answer
  and is visible in the response — never a silently empty one.
- **Kuma's next auth line is not supported yet.** The executor logs in
  with Kuma's socket `login` event (1.23 and 2.0). Kuma's development
  branch moves sign-in to an HTTP session cookie; once that ships, the
  login half of `execute_kuma.py` needs a second path. A Kuma account
  with 2FA cannot be used at all (there is nobody to type the code).
- **No opencode session listing.** `check`/`review_changes`/`abort` all
  take a session id an agent got from `ask`/`run`/`fire`; there is no
  "list every session on this server" operation, which would hand one
  identity a view of work started under another.
- **TrueNAS SCRAM-SHA-512 mutual auth** — API-key auth
  (`auth.login_with_api_key`) is implemented and is the baseline; SCRAM is
  TrueNAS 26's preferred alternative and is a follow-up, not a blocker.
- **Persistent/pooled TrueNAS WebSocket connections** — each call currently
  opens its own connection, authenticates, sends one request, and closes.
  Simpler and correct for infrequent management calls; a pooled/reconnecting
  connection manager is a valid later optimization that would not change the
  tool definition contract (method + params).
- **Retention for decided proposals** — `pending.yaml` and
  `toolkit_proposals.yaml` keep every approved/rejected/stale/deployed item
  forever (466 on one deployment as of 0.47.4). Page loads no longer pay for
  that (0.47.3 caches the parse, shows the requests archive on
  demand), but every propose/decide still re-parses and rewrites the whole
  file — ~170 ms at that size, growing linearly. Moving items decided more
  than N days ago into a separate history file would cap it. Deferred: years
  from mattering at current growth, and the decisions are already in the
  audit log, so the open questions are where the archive view reads from
  and when the move runs. Revisit when approving a request feels slow.
- **API versioning** — MCP is the only interface; no separate HTTP API for
  tools.
- **Per-destination `allowed_cidrs`/`allowed_methods`/`allowed_path_prefixes`** —
  an `http` toolkit's SSRF/target restrictions (FR-8.9/8.15) are still
  toolkit-wide, shared across every destination it declares (`tier1.py`'s
  `Destination` carries only the connection target, not the toolkit's other
  boundaries — FR-4.9). Doesn't let a call to one destination reach another
  (the target itself stays fixed per destination, FR-8.3i), but the CIDR
  allowlist a single destination's SSRF check accepts is wider than
  strictly necessary when destinations sit on different subnets. Narrowing
  this per destination is a deliberate follow-up, not done here to avoid
  widening `Destination`'s scope past "where," not "what," in the same
  pass that introduced it.
- **`Toolkit`/`Destination` as a tagged union per executor** — both remain
  flat dataclasses carrying every executor's fields at once (docker/http/
  truenas/ssh), relying on convention (irrelevant fields stay `None`/default)
  rather than the type system to keep e.g. a `docker` toolkit from also
  setting `base_url`. A `Toolkit.target: DockerTarget | HttpTarget |
  TruenasTarget` redesign would make that class of mistake unrepresentable,
  but touches every executor's call sites — a larger, riskier change than
  fits alongside a feature addition; a candidate for its own pass.
