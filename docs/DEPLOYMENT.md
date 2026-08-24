# Deployment

Project documentation for operating a running gatekeeper instance. For
release/versioning procedure, see [RELEASE.md](../RELEASE.md). For agent
workflow, see [AGENTS.md](../AGENTS.md).

## Environment variables

| Variable | Purpose |
|---|---|
| `GATEKEEPER_CONFIG_DIR` | Where `toolkits.yaml` lives (Tier 1, may be read-only) |
| `GATEKEEPER_STATE_DIR` | Where `tools.yaml`, `identities.yaml`, `credentials.yaml` live (Tier 2, must be writable if `--ui` writes are enabled) |
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
  -v /path/to/logs:/path/to/logs:rw \
  -e GATEKEEPER_LOG_LEVEL=INFO \
  davidsteg/gatekeeper:latest serve --ui
```

Adjust mounts/UID/GID/ports to your host. `--user`/`--group-add` should match
an unprivileged user plus the Docker socket's group, not root.

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

This is more moving parts than `user: "0:0"`, and it is not the
recommended path. It is documented because the failure it produces is silent
at startup and confusing at the first call.

Three things worth being deliberate about before doing this:

- **Prefer the owner over root.** `run_as: "3001:3001"` (the uid that owns
  the files) is bounded by that user's own permissions. `run_as: root` is
  not, and additionally needs `CAP_DAC_OVERRIDE` to read a directory it does
  not own — a capability that reads every file on every mount. If the goal is
  "reach this one agent's config directory", the owning uid is the answer and
  root is not.
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
| **Deploy mounts** | `<data-root>/gatekeeper/config → /etc/gatekeeper`, `<data-root>/gatekeeper/logs`, `/var/run/docker.sock` |
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
