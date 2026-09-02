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
| `GATEKEEPER_RELEASE_NOTES` | Path to `RELEASE.md`, for the console's release-notes popup. Defaults to `/usr/share/gatekeeper/RELEASE.md` in the container image; a dev checkout finds the file next to `pyproject.toml` on its own and never needs this set |
| `GATEKEEPER_LOG_LEVEL` | Python logging level, default `INFO` |
| `GATEKEEPER_UI` | `1`/`true` enables the console without passing `--ui` |
| `GATEKEEPER_UI_READ_ONLY` | `1`/`true` disables console writes regardless of role |
| `GATEKEEPER_NO_BOOTSTRAP` | `1`/`true` disables first-start auto-bootstrap |
| `GATEKEEPER_HOST` / `GATEKEEPER_PORT` | Bind address for `serve` |
| `GATEKEEPER_TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of reverse proxies allowed to set `X-Forwarded-For`/`X-Forwarded-Proto` (or `*` to trust any peer). See [Behind a reverse proxy](#behind-a-reverse-proxy) below — unset is not safe for the common container topology |
| `DOCKER_HOST` | Passed through to the `docker` executor's child process only |

A `credentials.yaml` with any entries in it, but no master key configured,
aborts startup (fail closed) rather than running with masking silently
disabled.

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

**3. Enter the values in the console.** `/ui/credentials` → *Add credential*,
once per service. Name must equal the `credential:` value from step 2; kind
and header follow the service (see the table in the README's Credentials
section — most homelab services are `api_key_header`, SABnzbd is the one
`url_query` case). The value is write-only from the moment you save it: no
role, no route, and no export ever shows it again.

**4. Enable the tools.** A tool with no grantees exists but is invisible to
every agent — `/ui/tools` to enable, `/ui/identities` to grant.

To verify, call one read-only tool and check `/ui/audit`: a successful record
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
`/ui/toolkits/reference`, then edit three lines:

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
credential at `/ui/credentials` whose value is `<user>:<password>`, and
name it with `credential:` on the toolkit — it is then sent as an
`Authorization: Basic` header, and never appears in a tool definition, a
response, or the audit log.

**5. Create the tools, enable them, grant them.** Either from
`/ui/tools/integrations` (the *opencode* card carries all seven starter
tools) or by copying the entries from
[`config/examples/tools.yaml`](../config/examples/tools.yaml). They ship
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

## A new tool does not appear in an agent session

Reported as an admin/agent split: `admin.tool_create` + `admin.tool_enable`
+ `grant_set` all succeed, `admin.tool_list` and `admin.grant_list` show the
new tools, and the agent's `/mcp` session does not — until the container is
restarted.

**The server is not the stale half.** Every Tier 2 write reloads the state
it just wrote, synchronously, in the same process: `ConfigStore._write_tools`
reassigns `service.catalog` from the file, and `_write_identities` swaps the
identity contents in place. `tools/list` is answered from those objects on
every request, so the first request after the write already contains the new
tool — and it is callable on the same connection. Two tests in
`test_mcp_live_catalog.py` assert exactly that against a live MCP session, so
"the catalog is a startup snapshot" can be ruled out without re-checking.

What is missing is the other half of the handshake: **nothing tells a
connected client to ask again.** Most MCP clients fetch `tools/list` once
when the session is established and keep that list for the session's
lifetime. MCP's mechanism for invalidating it is a
`notifications/tools/list_changed`, which gatekeeper does not send — and
cannot today, because `/mcp` runs `stateless_http=True`: each request gets
its own short-lived transport, so there is no retained session to push a
notification into. Restarting the container "fixes" it only because it forces
every client to reconnect and re-fetch.

So the remedy is a **client reconnect, not a container restart** — cheaper,
and it does not interrupt anything else the container is doing. In practice
that means restarting the agent's MCP connection (in most hosts, reloading
the MCP server entry or the session), not `docker restart gatekeeper`.

Making this automatic requires `/mcp` to hold sessions so the notification
has somewhere to go. That is a wire-protocol change for every connected
agent, not a bug fix, and is deliberately not made silently.

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
- **The session cookie's `Secure` flag never activates.** `ui.py` sets it
  from the request's scheme; behind a TLS-terminating proxy that scheme is
  `http` internally even though the browser is on `https`.

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
  (`admin.toolkit_update`), which a human then approves at `/ui/requests`.
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
| **Host** | `10.0.0.10` (example), console at `http://10.0.0.10:30221/ui/` |
| **Container user** | `568:568` (unprivileged), `group_add: 999` (docker.sock GID) |

Before starting work against this clone: `git fetch origin && git log
--oneline origin/main -5` — a stale local clone is a common source of
confusing diffs.

### Docker Hub secrets

Image push requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` in the
GitHub repo's Settings → Secrets. Without them, the `image` job fails at
"Log in to Docker Hub" — the `tests` job (including the `RELEASE.md` check)
still runs and gates the build either way.
