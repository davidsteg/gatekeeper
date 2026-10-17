# Deployment

Project documentation for operating a running gatekeeper instance. For
release/versioning procedure, see [RELEASE.md](../RELEASE.md). For agent
workflow, see [AGENTS.md](../AGENTS.md).

## Environment variables

| Variable | Purpose |
|---|---|
| `GATEKEEPER_CONFIG_DIR` | Where `toolkits.yaml` lives (Tier 1, may be read-only) |
| `GATEKEEPER_STATE_DIR` | Where `tools.yaml`, `identities.yaml`, `credentials.yaml` live (Tier 2, must be writable if `--ui` writes are enabled) |
| `GATEKEEPER_AUDIT_DIR` | Audit-log directory a **fresh** `init` writes into `toolkits.yaml`. `/var/log/gatekeeper` in the container image; unset elsewhere, which falls back to `<state-dir>/logs`. Never rewrites an existing `audit.dir` — that value is Tier 1 and authoritative. See [Where the audit log goes](#where-the-audit-log-goes) |
| `GATEKEEPER_CREDENTIAL_KEY` | Fernet master key for the credential store (generate with `gatekeeper credential-key`) |
| `GATEKEEPER_CREDENTIAL_KEY_FILE` | Path to a file holding that same key, for a separately mounted secret instead of a plain env var |
| `GATEKEEPER_RELEASE_NOTES` | Path to `RELEASE.md`, for the console's Release notes page (`/app/release-notes`). Defaults to `/usr/share/gatekeeper/RELEASE.md` in the container image; a dev checkout finds the file next to `pyproject.toml` on its own and never needs this set |
| `GATEKEEPER_LOG_LEVEL` | Python logging level, default `INFO` |
| `GATEKEEPER_UI` | `1`/`true` enables the console without passing `--ui` |
| `GATEKEEPER_UI_READ_ONLY` | `1`/`true` disables console writes regardless of role |
| `GATEKEEPER_NO_BOOTSTRAP` | `1`/`true` disables first-start auto-bootstrap |
| `GATEKEEPER_HOST` / `GATEKEEPER_PORT` | Bind address for `serve` |
| `GATEKEEPER_TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of reverse proxies allowed to set `X-Forwarded-For`/`X-Forwarded-Proto`, or `X-Real-IP` when no `X-Forwarded-For` is sent (or `*` to trust any peer). See [Behind a reverse proxy](#behind-a-reverse-proxy) below — unset is not safe for the common container topology |
| `GATEKEEPER_NOTIFY_URL` | If set, every `agent.send_message` delivery POSTs the message (JSON) to this URL as a best-effort webhook — signed for the Hermes webhook adapter (generic HMAC V2): X-Webhook-Timestamp (unix seconds) + X-Webhook-Signature-V2 = hex HMAC-SHA256 of <timestamp>.<body>, 3s timeout, failures only logged and never failing the delivery. Unset (the default) means no POST at all |
| `GATEKEEPER_NOTIFY_SECRET` | HMAC-SHA256 secret for X-Webhook-Signature-V2 on the delivery webhook; empty when unset, which still signs (with the empty secret) |
| `GATEKEEPER_BASE_URL` | Public origin of the console (e.g. `https://gatekeeper.example.com`), used to build the Google OAuth `redirect_uri`. Only needed behind a proxy that rewrites the host and does not forward it — unset, the request's own base URL is used. See [Google OAuth sign-in](#google-oauth-sign-in) |
| `DOCKER_HOST` | Passed through to the `docker` executor's child process only |

A `credentials.yaml` with any entries in it, but no master key configured,
aborts startup (fail closed) rather than running with masking silently
disabled.

## Google OAuth sign-in

A `google` toolkit authenticates with an `oauth2` credential holding
`client_id`, `client_secret`, `refresh_token` and `scopes`. The first two
come from an OAuth client in the Google Cloud console and are typed into
`/app/credentials`; the other two are produced by the console itself
(0.46.0):

1. In the Google Cloud console, add this **exact** string to the OAuth
   client's *Authorized redirect URIs*:

   ```
   https://<your-gatekeeper-host>/ui/oauth/google/callback
   ```

   Google compares it character for character — a mismatch is answered
   with `redirect_uri_mismatch` and nothing else. The path is the same
   one 0.x used: the 1.0.0 console moved to `/app`, but this callback
   stayed at `/ui/oauth/google/callback`, so a client registered before
   1.0.0 needs no change. Step 3 shows the value this deployment will
   actually send; use that one rather than typing it from here.

2. Create the credential at `/app/credentials` as kind `oauth2`, with the
   value `{"client_id": "...", "client_secret": "..."}`.

3. On `/app/credentials`, under *Sign in with a provider*, click
   **Connect Google: `<name>`**. The console shows the redirect URI it
   will send and the scopes it will ask for; **Continue to Google** opens
   the consent screen. Once you have worked through it, Google returns to
   the callback above, the refresh token is written back into the same
   credential, encrypted, together with the scopes the grant actually
   covers, and you land on `/app/credentials` again. The token is never
   displayed — the page says only whether it worked.

   The scopes are stored because a refresh needs them: Google renews a
   token for a named set of scopes and refuses the refresh outright with
   `invalid_scope` if that set is not covered by what was consented to.
   They travel into the per-call token file as its `scopes` field, which
   is where `google_api.py` reads them. A credential written before the
   console recorded scopes has none, and falls back to the default set
   listed below — if such a credential refuses to refresh, run **Connect
   Google** once more and the exact grant is recorded.

Behind a proxy that rewrites the host, set `GATEKEEPER_BASE_URL` to the
public origin, otherwise the redirect URI is built from the internal one
and will not match what you registered.

Which scopes the consent screen asks for is Tier 1: each `google` toolkit
may carry a `required_scopes:` list (bare names like `gmail.send`, or full
scope URLs), and the console asks for the union across all of them. With
none declared, the default set is `gmail.readonly`, `gmail.send`,
`gmail.modify`, `calendar.events`, `calendar.events.readonly`, `drive`,
`drive.file`, `drive.metadata.readonly`, `spreadsheets`, `contacts`.

A sign-in that returns no refresh token means Google considers the client
already granted: remove gatekeeper under the Google account's third-party
connections and run through it again.

## Credentials: from zero to a working call

A freshly deployed toolkit that needs auth answers `401`/`403` until all
three of these are true. They are separate on purpose — the master key is a
deploy secret, the binding is Tier 1, and the value itself is Tier 2.

**1. Generate and mount the master key.** Once per deployment, not per
service. Without it the store cannot encrypt anything, and a
`credentials.yaml` that already has entries aborts startup rather than
running unmasked.

```bash
docker exec gatekeeper gatekeeper credential-key
```

Put the output in the container's environment as `GATEKEEPER_CREDENTIAL_KEY`,
or write it to a mounted file and point `GATEKEEPER_CREDENTIAL_KEY_FILE` at
that path — the file variant keeps the key out of `docker inspect`. Losing
this key means every stored credential must be entered again; it is not
recoverable from the ciphertext.

**2. Bind each toolkit to a credential name.** In `toolkits.yaml`, one line
per toolkit:

```yaml
toolkits:
  jellyfin:
    executor: http
    base_url: "http://10.10.200.20:8096"
    credential: jellyfin        # <- the name, never the key itself
```

This is Tier 1: edited by hand at deploy time and never by the console, which
is what stops a compromised admin session from pointing one service's key at
another host. The name is free-form; matching it to the toolkit name is only
a convention. Nothing else in the toolkit block changes — `base_url`,
`allowed_cidrs`, `allowed_methods` and `allowed_path_prefixes` stay as they
are. Redeploy (or send `SIGHUP`, see below) so Tier 1 is re-read.

**3. Enter the values in the console.** `/app/credentials` → *Add credential*,
once per service. Name must equal the `credential:` value from step 2; kind
and header follow the service (see the table in the README's Credentials
section — most homelab services are `api_key_header`, SABnzbd is the one
`url_query` case). The value is write-only from the moment you save it: no
role, no route, and no export ever shows it again.

**4. Enable the tools.** A tool with no grantees exists but is invisible to
every agent — `/app/tools` to enable, `/app/identities` to grant.

To verify, call one read-only tool and check `/app/audit`: a successful record
names the credential it used (`"credentials": ["jellyfin"]`) and contains the
value nowhere. A `credential_unavailable` denial means step 2 and step 3
disagree about the name.

## Wiring an opencode server (`executor: opencode`)

The `opencode` executor talks to a **headless opencode server** over its
HTTP API. gatekeeper does not start, supervise, or contain opencode — it
is a separate container you run yourself, exactly like Sonarr behind an
`http` toolkit.

**1. Run opencode headless and note its address.** The server listens on
port `4096` inside its container; whatever host address that maps to is
what goes in `base_url`.

**2. Add the toolkit** (Tier 1 — `toolkits.yaml`, redeploy, never the
console). Copy the block from
[`config/examples/toolkits.yaml`](../config/examples/toolkits.yaml) or
`/app/toolkits/reference`, then edit three lines:

- `base_url` — scheme, host, port. The only place any of the three ever
  appears; no tool and no parameter can influence the target.
- `allowed_cidrs` — the narrow `/32` of that one host (FR-8.15). This is
  what the executor re-checks the *resolved* IP against before every
  request of a workflow, so a hostname that later resolves elsewhere is
  refused mid-workflow, not just at the start.
- `path_roots` — the project roots opencode may be pointed at. An agent's
  `directory` parameter is checked against these; a toolkit with no
  `path_roots` accepts no `directory` at all, and a tool that offers one
  anyway fails at load time rather than on the first call.

Narrow `allowed_opencode_operations` while you are there: a toolkit that
should only report on somebody else's sessions lists
`check`/`review_changes`/`health` and simply never mentions `run`.

**3. Mount the project roots into both containers, at the same paths.**
opencode resolves `directory` in its own filesystem; gatekeeper resolves
`path_roots` in its own. When the same host directory is mounted at the
same path in both, gatekeeper additionally catches a typo'd directory
before the call goes out. When it is not mounted into gatekeeper at all,
the `path_roots` containment check still applies — only the existence
check is skipped, because this container genuinely cannot answer it.

**4. Auth is optional and off by default.** opencode ships with no
authentication. If the server is reachable by anything other than
gatekeeper, set `OPENCODE_SERVER_PASSWORD` on it, create a `basic`
credential at `/app/credentials` whose value is `<user>:<password>`, and
name it with `credential:` on the toolkit — it is then sent as an
`Authorization: Basic` header, and never appears in a tool definition, a
response, or the audit log.

**5. Create the tools, enable them, grant them.** Copy the entries from
[`config/examples/tools.yaml`](../config/examples/tools.yaml) into the tool
editor at `/app/tools/new`, or have an admin agent create them over
`/admin/mcp`. They ship
`enabled: false`, like every other starter definition.

**6. Reconnect the agent, do not restart the container** — see the next
section for why. Then check `opencode.health` first: it answers
`{"healthy": true, "version": ...}` and needs neither a session nor a
project directory, which makes it the cheapest confirmation that the
address, the CIDR allowlist, and (if configured) the credential are all
right.

Two things worth deciding deliberately before granting:

- **`run` and `fire` let another agent edit files.** They are
  `write_external` in the shipped definitions for that reason. What they
  can reach is exactly `path_roots`, so keep it to the repositories you
  mean.
- **A timed-out `run` is `unknown`, not `failed`.** The prompt reached
  opencode and the session keeps working on the other side; the response
  says so and carries the session id. The follow-up is `check`, never a
  retry — a retry would start the same work a second time.

## Wiring Uptime Kuma (`executor: kuma`)

Uptime Kuma has no REST API for monitors; its UI creates and pauses them
over Socket.IO, and so does the `kuma` executor. It logs in with Kuma's
socket `login` event, which Uptime Kuma 1.23 and 2.0 both have.

**1. A Kuma account without 2FA.** gatekeeper cannot type a TOTP code, so
a login with 2FA is refused with a message saying so. Kuma 1.x has a single
account; if yours has 2FA, this executor cannot use it.

**2. The credential.** At `/app/credentials`, create `kuma` with kind
`basic` and the value `<username>:<password>`. It is sent only inside the
Socket.IO login and never comes back in a response or the audit log.

**3. The toolkit** (Tier 1 — `toolkits.yaml`, redeploy). Copy the `kuma`
block from `/app/toolkits/reference` or
[`config/examples/toolkits.yaml`](../config/examples/toolkits.yaml), then
set `base_url` (the address you open Kuma's UI at, e.g.
`http://192.168.1.42:3001`) and `allowed_cidrs` to that one host's `/32`,
or `allowed_hosts` for a public name. The WebSocket goes to the checked
address directly, never through a proxy. Leave out the operations you do
not want in `allowed_kuma_operations`: a list with only `monitor_list` is a
read-only toolkit.

**4. The tools.** Copy the four `kuma.*` entries from
[`config/examples/tools.yaml`](../config/examples/tools.yaml). Narrow the
`url` pattern to the domains you mean if you can. `kuma.monitor_list` is
`read` and is applied at once; the other three are `write`, so a proposal
for them waits at `/app/requests`, and catalog loading refuses a write
operation declared `read`. They ship `enabled: false`.

What the agent can and cannot do:

- `monitor_add_http` makes an HTTP(s) GET monitor from `name`, `url`,
  `interval` (30–3600 s) and `expected_status`. No notifications are
  attached; add them in Kuma's UI. The monitor's description is set to
  `Managed by gatekeeper (toolkit <name>)`.
- `monitor_pause`/`monitor_resume` work only on monitors whose description
  starts with `Managed by gatekeeper`. Any other monitor is refused before
  anything is sent. To let gatekeeper manage a hand-made monitor, put that
  text at the start of its description yourself.
- There is no delete and no edit. Remove a monitor in Kuma's UI.
- A timeout after an add or pause was sent is `unknown`: check with
  `kuma.monitor_list` before trying again, or the monitor may exist twice.

## Wiring a feat/* push to GitHub (`executor: git`)

A worker commits into a checkout on the host; gatekeeper pushes the branch.
The worker never holds the token, and file contents never pass through the
call.

**1. The token.** At `/app/credentials`, use the `github` slot if you
already have one (kind `bearer`), or create it: a fine-grained GitHub token
limited to the repository, with *Contents: read and write*. Branch
protection on `main` is still worth having; gatekeeper never builds a push
to it, but the token itself could.

**2. The repository in the container.** Mount the checkout into the
gatekeeper container, read-only is enough:
`- /srv/work/gatekeeper:/repos/gatekeeper:ro`. gatekeeper only reads it:
the branch is fetched into a throwaway repository, so the checkout's own
remotes, hooks and credential settings play no part. The gatekeeper user
(uid 568 by default) must be able to read the files.

**3. The toolkit** (Tier 1 — `toolkits.yaml`, redeploy). Copy the `git`
block from `/app/toolkits/reference` or
[`config/examples/toolkits.yaml`](../config/examples/toolkits.yaml); each
entry under `repos` is a name, the mounted `path` and the one https
`remote` it may push to.

**4. The tool and the grant.** Copy `gkrepo.push` from
[`config/examples/tools.yaml`](../config/examples/tools.yaml), set the
`repo` enum to your repo names, enable it and grant it to the identity that
should push (only that one, e.g. `homelab`). It is category `write`, so a
proposal for it waits at `/app/requests`.

What a call can and cannot do:

- It pushes `feat/<name>` to `feat/<name>` on the listed remote, as a
  fast-forward. Anything else — `main`, another prefix, a refspec, `..` —
  is refused before git runs. There is no force and no delete; a
  non-fast-forward comes back as refused, with nothing changed.
- The answer is `status` (`created`, `updated`, `up_to_date`), the remote
  branch's `old` and `new` SHA, and up to 20 pushed commits as short SHA
  and subject, with `commits_total`.
- `git` is in the image since 1.14.0.

## A new tool does not appear in an agent session

Reported as an admin/agent split: `admin.tool_create` + `admin.tool_enable`
+ `grant_set` all succeed, `admin.tool_list` and `admin.grant_list` show the
new tools, and the agent's `/mcp` session does not — until the container is
restarted.

**Since 0.42.0 this should not happen.** gatekeeper now sends
`notifications/tools/list_changed` on every write that can change what an
agent may call, and advertises `tools.listChanged: true` so clients act on
it. If a session still does not see a new tool, work through it in this
order:

1. **Does the client say it supports the notification?** Check the
   capability the server advertised at connect time. On the 2026-07-28 wire
   the client must open a `subscriptions/listen` stream to receive anything
   at all — a client that never opens one gets no change notifications, by
   spec. On 2025-era wires it must keep the `GET /mcp` stream open.
2. **Is the session still the one that connected?** A session with no
   request for an hour is reaped
   (`server.SESSION_IDLE_TIMEOUT_SECONDS`); the client's next request gets
   a 404 and it re-initializes, which re-fetches anyway.
3. **Did the client re-fetch and still not see it?** Then it is a grant or
   a Tier 1 problem, not a staleness one — check `admin.grant_list` and
   `/health/startup`'s `disabled_by_tier1`.

**The server has never been the stale half**, so it is not worth
re-investigating: every Tier 2 write reloads the state it just wrote,
synchronously, in the same process — `ConfigStore._write_tools` reassigns
`service.catalog` from the file, and `_write_identities` swaps the identity
contents in place. `tools/list` is answered from those objects on every
request. `test_mcp_live_catalog.py` asserts that against a live MCP session,
alongside the notification itself.

A **client reconnect** remains the manual fallback, and is still cheaper
than `docker restart gatekeeper` — it does not interrupt anything else the
container is doing.

## Config reload without a restart

```bash
docker kill -s HUP gatekeeper
```

Reloads `toolkits.yaml`, `tools.yaml`, and `identities.yaml` atomically. On
failure, the previous in-memory state is kept. The rate limiter is reset.
`credentials.yaml` is not part of this reload — it is read fresh on every
credential-store operation.

**Note (agent environments):** `signal.SIGHUP` does not exist on Windows.
`cmd_serve` registers a SIGHUP handler unconditionally, so `gatekeeper serve`
crashes immediately if invoked directly on a Windows dev machine. To smoke-test
the app on Windows, build the ASGI app directly (`server.build_app(...)`) in a
small script instead of going through `cmd_serve`/the CLI, and run it with
`uvicorn.run(...)` yourself — see the pattern used for UI screenshots in this
project's development history. This is a dev-environment workaround only; the
container image runs on Linux and is unaffected.

## Removed: recovery supervisor

Gatekeeper 0.52.0 removes the recovery supervisor (0.48.0–0.51.0) together
with its Hermes recovery adapter. Gatekeeper no longer tracks incidents,
holds repeats (`recovery_hold`), consults a rescue or decision model, or
continues a Hermes session; `POST /recovery/events` and
`GET /recovery/incidents` answer 404; `_meta.hermes` is ignored and
`_hermes_recovery` is an ordinary unknown argument. Deployments use
unchanged official Hermes images and their native orchestration.

**What an upgrade does with old configuration:**

| Left in place | 0.52.0 behavior |
|---|---|
| `recovery:` block that enables anything (`enabled: true` at any level, e.g. `rescue.enabled`, `decision.enabled`) | Refused at load (`gatekeeper check`, start, SIGHUP): *"'recovery' enables a feature that no longer exists …"*. A failed SIGHUP keeps the running config. |
| `recovery:` block with everything disabled | Loads, logs *"the 'recovery:' block is ignored"* with the same hint. |
| `artifact` toolkit with `allowed_artifacts: [hermes-adapter-contract, hermes-recovery-adapter]` | Loads, logs that the image no longer builds them. Its tools answer "unknown artifact"; `/health/ready` reports the toolkit `false` (degraded) while it serves nothing. |
| Scopes `artifact:hermes-…`, grants on `artifact.*` tools | Inert; remove them with the toolkit. |

**Migration:**

1. Delete the `recovery:` block from `toolkits.yaml`.
2. If an `artifact` toolkit only allowed the two removed artifacts, delete
   it, its `artifact.*` tools, the tool grants and the `artifact:` scopes
   of the identities that used them. Change nothing else.
3. `gatekeeper check`, then deploy the new image.

**Left on disk on purpose (archive or delete later, by hand).** The upgrade
reads none of these and deletes none of them:

- `<GATEKEEPER_STATE_DIR>/recovery.yaml` (or the old `recovery.state_file`)
  and its atomic-write leftovers next to it.
- Audit lines with `"kind": "recovery"` in `audit.jsonl` and its rotations
  — history, keep with the audit log.
- Credential-store entries the `recovery:` block named (adapter HMAC
  secrets such as `hermes-homelab-recovery`, a rescue API key). The
  console shows them without a "Used by" row once the block is gone.
- The former `handover_dir` (e.g. `/mnt/raid/agent/recovery-adapter-handover`)
  with transferred adapter archives, its mount in compose, and any adapter
  journals, backups or NAS test data on the Hermes side.

## Release-bound artifacts

The image carries the files listed in `artifacts.SOURCES` under
`/opt/gatekeeper/artifacts/`, bound to the release commit by
`manifest.json`. **0.52.0 declares no sources** (the Hermes recovery
adapter, the only artifact so far, was removed), so the manifest is empty
and an `artifact` toolkit has nothing to serve until a source is added. The
mechanism is unchanged. To hand artifacts to an agent, mount the handover
directory and add a toolkit:

```yaml
# toolkits.yaml (Tier 1)
toolkits:
  artifact:
    executor: artifact
    allowed_artifact_operations: [list, info, read, transfer]
    allowed_artifacts: [<artifact id>]
    handover_dir: /mnt/raid/agent/artifact-handover   # must be mounted read-write
```

```yaml
# tools.yaml (or via the console): one tool per operation
tools:
  - {id: artifact.list, toolkit: artifact, version: 1, enabled: true, title: List artifacts,
     description: Release-bound artifacts of this Gatekeeper, category: read, idempotent: true,
     artifact_operation: list, parameters: {}, required_scopes: [],
     timeout_seconds: 30, max_output_bytes: 65536}
  - {id: artifact.transfer, toolkit: artifact, version: 1, enabled: true, title: Transfer artifact,
     description: Copy an artifact into the handover directory and verify its sha256,
     category: write, idempotent: true, artifact_operation: transfer,
     parameters: {artifact: {type: string, required: true, pattern: "^[a-z0-9-]+$", description: Artifact id},
                  version: {type: string, pattern: "^[0-9a-f]{7,40}$", description: Commit (optional)}},
     required_scopes: [], timeout_seconds: 60, max_output_bytes: 65536}
  # artifact.info / artifact.read: like transfer, artifact_operation info / read, category read
```

Grant the tools to the identity, and give it the scope `artifact:*` (or
`artifact:<id>` per artifact). The same scope allows the authenticated
download:

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" -D - -O -J \
  https://gatekeeper.example/artifacts/<artifact id>
```

The `X-Artifact-SHA256` and `X-Artifact-Commit` headers name what was sent.
The files the image serves are also attached to the GitHub release
(`gatekeeper-<version>-artifacts.json` is the manifest).

## Behind a reverse proxy

`gatekeeper serve` runs directly under uvicorn, which by default trusts
`X-Forwarded-For`/`X-Forwarded-Proto` only from a proxy on `127.0.0.1`. A
reverse proxy in its own container (Traefik, Caddy, nginx, or any other
sidecar) is **not** `127.0.0.1` to gatekeeper — it connects from its own
container address — so without configuration those headers are silently
ignored and every request appears to originate from the proxy. This is the
standard homelab/container topology, and left unconfigured it degrades
three things at once:

- **The console's login throttle locks out everyone at once.** `LoginThrottle`
  keys on the apparent client address; with every request attributed to the
  proxy, one attacker's failed logins block every real user for five
  minutes, and every attacker shares one budget instead of getting their own.
- **The audit log records the wrong actor.** `ui_login`/`ui_login_failed`
  entries show the proxy's address for every sign-in, not the person who
  actually signed in — undercutting the audit trail this project exists to
  provide.
- **The session cookie's `Secure` flag never activates.** The console API
  (`/api/v1`) sets it from the request's scheme; behind a TLS-terminating
  proxy that scheme is `http` internally even though the browser is on
  `https`.

Fix it by naming the proxy's actual address (its container name resolves to
an IP on the shared Docker network, or use the network's CIDR):

```bash
docker run -d \
  --name gatekeeper \
  ... \
  -e GATEKEEPER_TRUSTED_PROXIES=172.18.0.0/16 \
  davidsteg/gatekeeper:latest serve --ui
```

or `serve --trusted-proxies 172.18.0.0/16` directly. This is not a
gatekeeper-specific mechanism — it configures uvicorn's own
`ProxyHeadersMiddleware`, which then rewrites the client address and scheme
*before* any of gatekeeper's own code sees the request, so nothing else
needs to change. Only name proxies gatekeeper actually shares a network
with; `*` trusts any peer and should stay reserved for a network gatekeeper
does not share with anything untrusted.

A proxy that sends `X-Real-IP` instead of `X-Forwarded-For` (nginx's common
`proxy_set_header X-Real-IP $remote_addr;`, some ingress controllers) works
with the same list since 1.7.0: the header counts only from a trusted proxy,
and only when no `X-Forwarded-For` came along.

### Every caller shows the same `172.x.x.1`

If the audit log's Who column shows one address such as `172.16.29.1` for
every caller, that is the Docker bridge gateway of gatekeeper's own
network, not a proxy. Docker rewrote the source address on the way in, and
the caller's real address never reached gatekeeper in any form: there is
no header to trust. **Do not** put that gateway in
`GATEKEEPER_TRUSTED_PROXIES` to fix it. Nothing behind it sends a
forwarding header, and any caller could then claim any address by sending
one itself.

The address is rewritten when:

- **The caller is another container on the same host** that reaches
  gatekeeper through the host's address and published port
  (`http://10.0.0.10:30221/mcp`). The hairpin goes through Docker's NAT and
  arrives masqueraded. Put both containers on one user-defined network
  (`docker network create agents`, then `--network agents` or `networks:`
  in compose for each) and point the caller at
  `http://gatekeeper:8080/mcp`. Each container then shows its own address.
- **Docker's userland proxy (`docker-proxy`) carries the connection**
  instead of iptables, which is how connections from the host itself, IPv6
  connections to an IPv4-only container, and hosts with Docker's iptables
  management off are served.
  Use IPv4 to reach gatekeeper, or run it with `--network host` (and
  `serve --port 30221`, without `-p`), which removes the NAT entirely.
- **A Kubernetes `NodePort` or `LoadBalancer` Service** forwards with the
  default `externalTrafficPolicy: Cluster`, which SNATs. Set
  `externalTrafficPolicy: Local` on the Service, or put an ingress in front
  that sends `X-Forwarded-For` and list the ingress's address here.

The console lives at `/app` and talks to `/api/v1`, both on the same port
as `/mcp`. A proxy must forward `/app`, `/api/v1` and `/ui/oauth/*` (the
OAuth callbacks, which kept their 0.x paths because they are the redirect
URIs registered with Google and Microsoft), next to `/mcp` and
`/admin/mcp`. Forwarding the rest of `/ui` is optional: since 1.0.0 it only
redirects old bookmarks to `/app`. None of these need extra headers or
CORS: the API is same-origin only and refuses `Authorization` headers. Do not let the proxy
rewrite or drop gatekeeper's `Content-Security-Policy` header. `/app`
depends on it (REQUIREMENTS.md FR-11.9), and a proxy that adds its own CSP
must not loosen it.

The console's live updates (1.3.0) are one long-lived `GET /api/v1/events`
per open tab, a Server-Sent Events stream. gatekeeper sends
`X-Accel-Buffering: no`, which nginx honours; another proxy must not buffer
`text/event-stream` responses, and its read timeout must be longer than
15 seconds (the stream's heartbeat). A proxy that cannot stream only costs
the live part: the console notices the stream is not up, says "Polling" in
the sidebar, and refreshes every 15 seconds as before.

## Deploy (example container)

```bash
docker pull davidsteg/gatekeeper:latest
docker kill gatekeeper && docker rm gatekeeper
docker run -d \
  --name gatekeeper \
  --user 568:568 \
  --group-add 999 \
  --restart unless-stopped \
  -p 30221:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:rw \
  -v /path/to/config:/etc/gatekeeper:rw \
  -v /path/to/data:/path/to/data:rw \
  -v /path/to/logs:/var/log/gatekeeper:rw \
  -e GATEKEEPER_LOG_LEVEL=INFO \
  davidsteg/gatekeeper:latest serve --ui
```

Adjust mounts/UID/GID/ports to your host. `--user`/`--group-add` should match
an unprivileged user plus the Docker socket's group, not root.

### Where the audit log goes

Two different paths, and conflating them is the usual confusion: the left
side of a `-v` is *your storage layout* and can be anything; the right side
is the path **inside the container**, and that one should be standard.
Since 0.33.0 the image declares `GATEKEEPER_AUDIT_DIR=/var/log/gatekeeper`,
so a fresh `init` writes that into `toolkits.yaml` and the mount above puts
your storage behind it.

Precedence, highest first: `gatekeeper init --audit-dir`, then
`$GATEKEEPER_AUDIT_DIR`, then `<state-dir>/logs`. The last is what a bare
`pip install` gets — self-contained, so a checkout stays runnable from any
directory without needing write access to `/var/log`.

Note what this is *not*: the value only seeds a **new** `toolkits.yaml`.
`audit.dir` in an existing one is Tier 1 and authoritative — nothing
rewrites it, so an upgrade never moves your log. To move it deliberately,
edit that line and repoint the mount to match.

**Not `/etc/gatekeeper`.** The audit log rotates (`max_bytes`,
`keep_files`), and a configuration directory written to every few seconds
cannot be mounted `:ro` — which would rule out the hardening below, where
Tier 1 is made immutable at runtime. Keeping the two apart is also what
lets them have different retention and different backups: the config is
small and rarely changes, the log grows and is the record of every
root-equivalent operation this service brokered.

`latest` always points at the newest build. For **production**, pin a fixed
version and its image digest — `latest` moving underneath a running
deployment without anyone deciding to is exactly what NFR-5 says not to do.

## Running file operations as another user (`run_as`)

A `file` toolkit performs its read/write/patch/list operations as whatever
user gatekeeper runs as — `568:568` in every example above. A directory that
belongs to somebody else with mode `0700` is then unreachable, however the
toolkit's `path_roots` are written. `run_as` on that toolkit (Tier 1,
`toolkits.yaml`, `file` executor only) says which user its operations should
run as instead:

```yaml
toolkits:
  agentcfg:
    executor: file
    path_roots:
      - /mnt/raid/agent
    protected_resources: [gatekeeper, dockhand, traefik]
    # Either an account that exists inside the container image:
    #   run_as: hermes
    # or, for a host uid that has no passwd entry in the image, the
    # numeric pair -- the same notation as compose's own `user:`.
    run_as: "3001:3001"
    max_timeout_seconds: 15
    max_output_bytes: 262144
```

**This costs the container its unprivileged start, so scope it deliberately.**
Becoming another user requires privilege the shipped `user: "568:568"` +
`cap_drop: ALL` container deliberately does not have. To honour `run_as`, the
container starts as root and is given back exactly two capabilities:

```yaml
    user: "0:0"          # replaces the shipped `user: "568:568"` line
    cap_drop:
      - ALL
    cap_add:
      - SETUID
      - SETGID
```

**Both halves are required, and `cap_add` alone does nothing.** This is the
one mistake worth naming outright, because it looks like it should work and
the container starts perfectly happily either way: Docker puts `cap_add`
entries in the permitted set of **uid 0 only**. A container that still says
`user: "568:568"` and gains `cap_add: [SETUID, SETGID]` comes up with an
empty `CapEff` — the capabilities were granted and are simultaneously
unusable. Changing `user:` is what makes them real. Edit the existing
`user:` line rather than adding a second one; a compose file with two
`user:` keys keeps the last, which may not be the one you just wrote.

`no-new-privileges: true` stays on — it blocks privilege *gain* through
setuid binaries on `execve`, which is unrelated to a privileged process
dropping to a lesser user.

### Recommended profile: start as root, give it up immediately

The block above leaves the process at uid 0 for its entire life to serve
calls that need the privilege for milliseconds. Everything it writes — the
audit log, `tools.yaml`, every `file` toolkit without `run_as` — comes out
root-owned, and the container that mediates root-equivalent access to the
host is itself root the whole time.

`GATEKEEPER_DROP_TO` closes that gap. The container still starts as root
with the two capabilities; gatekeeper then becomes the unprivileged user
*itself*, before argparse and before any file is touched, keeping exactly
`CAP_SETUID` and `CAP_SETGID`, and keeping the supplementary groups the
container was started with — `group_add: "999"` for the Docker socket
survives the drop, minus root's own group 0:

```yaml
    user: "0:0"                       # start privileged...
    cap_drop:
      - ALL
    cap_add:
      - SETUID
      - SETGID
    environment:
      GATEKEEPER_DROP_TO: "568:568"   # ...and stop being, right away
```

Startup then reports `568:568` with `CapEff=00000000000000c0`, files land
owned by 568 exactly as in the unprivileged profile, and `run_as` works —
because `_runas.py` asks the kernel for `CAP_SETUID`, not for uid 0.

`no-new-privileges: true` stays on and does not conflict. It governs what
`execve` may *grant from a file*; the capabilities travel in the process's
ambient set, which is not a grant from a file. That is asserted rather than
argued: a test sets `no_new_privs`, performs the drop, `exec`s a plain
binary and reads the capabilities back out of the child's
`/proc/self/status`.

Two properties worth knowing before choosing it:

- **It is not a boundary against a compromised gatekeeper.** A process
  holding `CAP_SETUID` can call `setuid(0)` whenever it likes. Against an
  attacker with code execution *inside* this process, 568-with-CAP_SETUID
  is worth about what `user: "0:0"` is worth. What it does buy is real but
  narrower: file ownership, a smaller blast radius for the ordinary bugs
  that are not code execution, and a capability set of exactly two entries
  instead of root's full complement. Choose it for those reasons.
- **The capabilities are handed back when nothing needs them.** The drop
  runs before the configuration is read, so the two are kept on the chance
  a toolkit wants them. If no toolkit declares `run_as`, startup discards
  them and logs that it did — the common case ends up holding nothing.

If the drop cannot be performed — root without `cap_add`, or a container
that is not root at all — startup **fails** with exit 2 rather than serving
as root while the log claims otherwise.

The setting is deliberately not baked into the image. A container started
with `user: "0:0"` and no `cap_add` would then refuse to boot, and that is
somebody's working deployment today.

#### Keeping extra capabilities for `run_as: root` (`GATEKEEPER_KEEP_CAPS`)

The drop above keeps exactly `CAP_SETUID` and `CAP_SETGID`. A deployment
that also grants `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` through
`cap_add` — so a `run_as: root` child can read files owned by other users
— would otherwise see those extras silently discarded by the drop. The
base two are hardcoded; anything beyond them has to be named explicitly:

```yaml
    user: "0:0"
    cap_drop:
      - ALL
    cap_add:
      - SETUID
      - SETGID
      - DAC_OVERRIDE           # let the run_as child bypass file perms
      - DAC_READ_SEARCH        # (read + traverse)
    environment:
      GATEKEEPER_DROP_TO: "568:568"
      GATEKEEPER_KEEP_CAPS: "DAC_OVERRIDE,DAC_READ_SEARCH"
```

`GATEKEEPER_KEEP_CAPS` takes a comma-separated list of capability names in
Docker `cap_add` notation (`DAC_OVERRIDE`, with or without the `CAP_`
prefix). The named extras are kept in the **permitted**, **inheritable**
and **ambient** sets but **not the effective set**: the server process
itself cannot use them — only the `run_as` child can, after inheriting them
from the ambient set on `execve`. This is the narrowest split that lets a
privileged child read files owned by other users without the server itself
being able to.

An unknown capability name is a startup error, not a silent skip — the
operator typed it for a reason, and carrying on without the capability they
asked for would produce the exact "looks like a bug" failure this section
exists to make legible.

When no toolkit declares `run_as`, startup discards the extras along with
the base two (see `discard_capabilities`). A future toolkit that adds
`run_as` would re-add the base two on the next start; the extras would
need `GATEKEEPER_KEEP_CAPS` again, which is the deploy-time gate.

### If the container still comes up as 568

The failure worth naming on its own, because it looks like a bug in
gatekeeper and is not: `user: "0:0"` is set, `cap_add` is set, the container
was recreated — and `docker exec` still reports `Uid: 568` with an empty
`CapEff`.

First check whether `GATEKEEPER_DROP_TO` is set. If it is, gatekeeper did
this on purpose and it worked — see the profile above; `CapEff` should then
read `00000000000000c0` rather than zero, and an empty one means the drop
failed, which aborts startup rather than reaching this state.

With that setting **unset**, gatekeeper does not change its own uid. There
is no entrypoint script, no `PUID`/`PGID` convention, no
`gosu`/`su-exec`/`setpriv` wrapper, and no `setuid` in the startup path.
Only two modules in the tree change identity at all — `_selfdrop.py`, which
runs solely when that variable is set, and the short-lived `run_as` helper
*child*, after the server has already forked and exec'd it. A test
(`test_no_internal_drop.py`) parses every module and fails the build if a
third one ever appears. So an unconfigured process observed at 568 was
**started** at 568, and looking for an internal drop will not find one.

What starts it there is the image's own default, `USER 568:568` in the
Dockerfile. A compose `user:` overrides that unconditionally — so if the
process is 568, the `user:` never reached this container. In order of how
often each one is the answer:

1. **Two `user:` keys in the service.** The most likely, and the one that
   hides best: a YAML mapping with a repeated key does not merge, compose
   keeps one, and if it keeps `"568:568"` you get exactly this state. Search
   the file rather than trusting a scroll: `grep -n 'user:' compose.yaml`
   must return one uncommented line.
2. **Restarted, not recreated.** `docker restart` reuses the existing
   container with the settings it was *created* with. Only `docker compose
   up -d` (or `--force-recreate`) applies a changed `user:`.
3. **A different file than the one edited.** The deploy names an explicit
   path — for the Dockhand invocation at the top of `compose.yaml`, that is
   `/mnt/raid/gatekeeper/compose.yaml`, not a checkout elsewhere.

`docker inspect -f '{{.Config.User}}' gatekeeper` settles all three: it
reports what the container was actually created with. If that says `568:568`
while the file says `0:0`, the problem is between the file and the daemon,
and nothing inside the container will explain it.

### Refusing to start when `run_as` cannot work

An unprivileged container with a `run_as` toolkit starts, passes its
healthcheck, and looks entirely fine — every `run_as` call fails, and
nothing says so unless somebody reads the log. Set
`GATEKEEPER_REQUIRE_RUN_AS=1` to make that state refuse to boot instead:

```yaml
    environment:
      GATEKEEPER_REQUIRE_RUN_AS: "1"
```

Startup then exits `2` with the reason. It is deliberately opt-in: a toolkit
may carry `run_as` for a call nobody makes today, and aborting on that would
turn a merely over-declared deployment into one that will not start. Switch
it on where `run_as` is load bearing — then a misconfigured redeploy fails
loudly at the point it happens, rather than at the first agent call.

### Confirming the privilege is actually there

"The container was recreated" is not the same fact as "the process holds the
capabilities", and the two come apart exactly in the `cap_add`-without-`user`
case above. Two ways to check, neither of which requires making an agent
call:

```bash
# What the container was asked for:
docker inspect -f '{{.Config.User}} {{.HostConfig.CapAdd}}' gatekeeper
#   0:0 [SETUID SETGID]        <- correct
#   568:568 [SETUID SETGID]    <- capabilities granted but unusable

# What the process actually got:
docker exec gatekeeper grep -E '^(Uid|CapEff):' /proc/self/status
#   Uid:  0 0 0 0
#   CapEff:  00000000000000c0        <- bits 6 (SETGID) and 7 (SETUID)
#   CapEff:  0000000000000000        <- nothing; run_as calls will fail
```

Startup says the same thing in the log, and says it as a checked fact rather
than as a restatement of the YAML. One `WARNING` per toolkit that declares
`run_as`, then one line about whether the privilege exists:

```
WARNING  Toolkit 'agentcfg': file operations run as '3001:3001', not as this process (0:0).
INFO     run_as is usable: this process (0:0, CapEff=00000000000000c0) holds CAP_SETUID and CAP_SETGID.
```

```
ERROR    run_as is NOT usable: this process (568:568, CapEff=0000000000000000) holds no
         privilege to change user, so every call on 'agentcfg' will fail rather than fall
         back. Both halves are needed -- 'user: "0:0"' AND 'cap_add: [SETUID, SETGID]';
         the container is not running as root, so 'cap_add' alone grants nothing --
         Docker puts those capabilities in uid 0's permitted set only.
```

### If something else drops privileges first

gatekeeper itself never changes its own uid — it runs as whatever the
container started it as, and only the short-lived `run_as` helper child ever
calls `setresuid`. But a deployment that wraps the entrypoint in its own
`gosu`/`setpriv`/`su-exec` step, or a base image that drops to a service
account before `exec`ing, hands gatekeeper a process that is no longer root.
Leaving root clears the capability sets, so unless that wrapper deliberately
keeps them, `run_as` stops working and the `CapEff=0000000000000000` line
above is what you will see.

Keeping them across such a drop is the wrapper's job, and takes two things:
`prctl(PR_SET_KEEPCAPS, 1)` before the `setuid`, so the permitted set
survives the uid change, and raising the two capabilities into the *ambient*
set, so they survive the following `execve` as well. `setpriv` does both:

```bash
setpriv --reuid=568 --regid=568 --clear-groups \
        --inh-caps=+setuid,+setgid --ambient-caps=+setuid,+setgid \
        gatekeeper serve
```

gatekeeper accepts that configuration: what it checks is whether it holds
`CAP_SETUID` and `CAP_SETGID`, not whether it is uid 0, so an unprivileged
process that kept the two capabilities can still honour `run_as`. The helper
child then clears its whole capability set explicitly after assuming the
target user — a change between two non-root uids does not clear it the way
leaving root does, and a `run_as` child that kept `CAP_SETUID` would be one
call away from being root again.

Ambient capabilities are inherited by every `execve`, so on its own this setup
would hand `CAP_SETUID`/`CAP_SETGID` to every process gatekeeper spawns — a
`local` toolkit's `docker`, `df`, `free` and `cat`, none of which has any use
for them. gatekeeper does not leave that to the deployment: a `local` binary
is exec'd through a wrapper that empties its own capability sets first,
verifies they are empty, and **refuses to run the binary** if they are not.
Only the `run_as` helper keeps them. The cost is one extra `exec` per `local`
call, and it is paid only here — where there are no ambient capabilities to
strip, binaries are spawned directly, exactly as before.

This is more moving parts than `user: "0:0"`, and it is not the
recommended path. It is documented because the failure it produces is silent
at startup and confusing at the first call.

Three things worth being deliberate about before doing this:

- **Prefer the owner over root — `run_as: root` usually reaches *less*.**
  This is the one that surprises people, so it is worth stating as
  mechanics rather than advice. "Root can read any file" is not a property
  of uid 0; it is `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`, two
  ordinary capabilities. `cap_drop: ALL` takes them away from root along
  with everything else, and `cap_add: [SETUID, SETGID]` does not give them
  back. In the recommended container, uid 0 is therefore checked against
  file modes exactly like anybody else — so against
  `-rw------- 568 568 compose.yaml` it gets `Permission denied`, while
  `run_as: "568:568"` reads the file without holding any capability at
  all. Granting `cap_add: DAC_OVERRIDE` would "fix" it by handing the
  container read access to every file on every mount; naming the owning
  uid fixes it properly. Startup warns when a toolkit says `run_as: root`
  in a container without those capabilities, and a denial from such a call
  says which uid it ran as and why root was not enough.

  When the owning uid is genuinely unknown at deploy time and `run_as:
  root` must reach foreign files, `GATEKEEPER_KEEP_CAPS` (see above) lets
  the extras survive the startup drop into the child's ambient set. It is
  the explicit, audited alternative to granting the whole container
  `CAP_DAC_OVERRIDE` in the effective set — the server itself still
  cannot use it, only the `run_as` child can. Use it when naming the
  owning uid is not possible; prefer the owning uid when it is.
- **Only the toolkits that declare it are affected.** A `file` toolkit
  without `run_as` still runs in-process as the container user, and
  `http`/`docker`/`local`/`truenas`/`ssh` toolkits are untouched — `run_as`
  is rejected on them at startup. Give the elevated toolkit its own narrow
  `path_roots` rather than adding `run_as` to an existing broad one.
- **The capabilities are the boundary, not the YAML.** Since 0.29.0 an
  admin-role agent can *propose* a `run_as` change over `/admin/mcp`
  (`admin.toolkit_update`), which a human then approves at `/app/requests`.
  What no proposal can touch is this section's `cap_add` block, or the
  toolkit's `path_roots` — so the question "may anything here run as
  another user at all, and over which directories" stays exactly where you
  answer it now, at deploy. Grant the capabilities only if you mean it.
- **Every ancestor directory has to be traversable by that user.** Ordinary
  Unix rules, but the easy one to trip over: `run_as: "3001:3001"` reaching
  `/mnt/raid/agent/hermes-media/config.yaml` needs `x` on `/mnt/raid` and
  `/mnt/raid/agent` for uid 3001, not only on the last directory. A
  `Permission denied` naming the file when the file itself is readable is
  almost always a parent directory.
- **Per-tool `run_as` overrides the toolkit's (since 0.36.0).** A tool
  spec can carry its own `run_as`, which wins over the toolkit's. The
  common case: a toolkit with `run_as: root` for write tools, and a read
  tool on the same toolkit that sets `run_as: ""` to run as the container
  user instead. `None` (or unset) inherits the toolkit's value; an empty
  string explicitly clears it. The field is `tools.yaml` (Tier 1), not
  agent-supplied — it narrows the toolkit's authority, never widens it.

If the container is not privileged enough to assume that user, calls on that
toolkit **fail** with a message saying so — they never quietly run as the
container user instead. The message names which of the two halves is
missing, `user:` or `cap_add:`, and prints the process's `CapEff` so the
answer does not depend on trusting the compose file.

## A known deployment (reference)

One running instance, for agents that operate against it directly:

| | |
|---|---|
| **Local clone** | `/opt/example/gatekeeper` |
| **Container** | `gatekeeper`, port `30221→8080`, image `davidsteg/gatekeeper:latest` |
| **Deploy mounts** | `<data-root>/gatekeeper/config → /etc/gatekeeper`, `<data-root>/gatekeeper/logs → /var/log/gatekeeper`, `/var/run/docker.sock` |
| **Host** | `10.0.0.10` (example), console at `http://10.0.0.10:30221/app/` |
| **Container user** | `568:568` (unprivileged), `group_add: 999` (docker.sock GID) |

Before starting work against this clone: `git fetch origin && git log
--oneline origin/main -5` — a stale local clone is a common source of
confusing diffs.

### Docker Hub secrets

Image push requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` in the
GitHub repo's Settings → Secrets. Without them, the `image` job fails at
"Log in to Docker Hub" — the `tests` job (including the `RELEASE.md` check)
still runs and gates the build either way.
