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

## A known deployment (reference)

One running instance, for agents that operate against it directly:

| | |
|---|---|
| **Local clone** | `/opt/data/gatekeeper` |
| **Container** | `gatekeeper`, port `30221→8080`, image `davidsteg/gatekeeper:latest` |
| **Deploy mounts** | `<data-root>/gatekeeper/config → /etc/gatekeeper`, `<data-root>/gatekeeper/logs`, `/var/run/docker.sock` |
| **Host** | `10.10.200.90`, console at `http://10.10.200.90:30221/ui/` |
| **Container user** | `568:568` (unprivileged), `group_add: 999` (docker.sock GID) |

Before starting work against this clone: `git fetch origin && git log
--oneline origin/main -5` — a stale local clone is a common source of
confusing diffs.

### Docker Hub secrets

Image push requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` in the
GitHub repo's Settings → Secrets. Without them, the `image` job fails at
"Log in to Docker Hub" — the `tests` job (including the `RELEASE.md` check)
still runs and gates the build either way.
