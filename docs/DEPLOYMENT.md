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
| `GATEKEEPER_LOG_LEVEL` | Python logging level, default `INFO` |
| `GATEKEEPER_UI` | `1`/`true` enables the console without passing `--ui` |
| `GATEKEEPER_UI_READ_ONLY` | `1`/`true` disables console writes regardless of role |
| `GATEKEEPER_NO_BOOTSTRAP` | `1`/`true` disables first-start auto-bootstrap |
| `GATEKEEPER_HOST` / `GATEKEEPER_PORT` | Bind address for `serve` |
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
