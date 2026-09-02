# syntax=docker/dockerfile:1

# --- Build ----------------------------------------------------------------
FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml constraints.txt ./
COPY src ./src

# constraints.txt pins the direct dependencies to the exact versions this
# project is tested against, so two builds of the same commit resolve the
# same dependency tree instead of drifting with whatever pyproject.toml's
# ">=" floors happen to satisfy that day -- see constraints.txt's own
# comment for why it stops at direct dependencies rather than a full
# transitive lock (this image is built for both amd64 and arm64).
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install . -c constraints.txt

# --- Docker CLI + Compose plugin ------------------------------------------
# Only the client, no daemon. gatekeeper talks to the host's Docker daemon
# via the mounted socket.
#
# The static Docker tarball contains ONLY the docker binary. `docker compose`
# is a CLI plugin and must be installed separately -- without it, every
# compose tool fails at runtime with "unknown shorthand flag: 'p'".
FROM debian:bookworm-slim AS docker-cli

ARG DOCKER_VERSION=27.3.1
ARG COMPOSE_VERSION=2.29.7
ARG TARGETARCH=amd64

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && case "${TARGETARCH}" in \
      amd64) DOCKER_ARCH=x86_64 ;; \
      arm64) DOCKER_ARCH=aarch64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-${DOCKER_VERSION}.tgz" \
    -o /tmp/docker.tgz \
 && tar -xzf /tmp/docker.tgz -C /tmp \
 && install -m 0755 /tmp/docker/docker /usr/bin/docker \
 && rm -rf /tmp/docker /tmp/docker.tgz \
 && mkdir -p /usr/local/lib/docker/cli-plugins \
 && curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${DOCKER_ARCH}" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose \
 && chmod 0755 /usr/local/lib/docker/cli-plugins/docker-compose

# --- Runtime --------------------------------------------------------------
FROM python:3.12-slim

# procps provides /usr/bin/free, coreutils provides /usr/bin/df and /bin/cat.
# Binaries must be at the exact paths listed in toolkits.yaml --
# gatekeeper does not rely on PATH resolution (FR-4.1).
# tzdata makes the container's 'TZ' env var actually work (see compose.yaml):
# without it, python:3.12-slim has no timezone database and TZ=America/New_York
# is silently ignored -- which would leave the 0.37.x local-time display
# reporting UTC.
#
# NOT installed, deliberately: zfsutils-linux (`zfs`, `zpool`). A toolkit
# pointing a `local` executor at /usr/bin/zfs is a config error no image
# change can fix, so adding the package here would buy a different error
# message and nothing else:
#
#   1. ZFS userland is a thin wrapper over ioctl() on /dev/zfs, served by
#      the host's kernel module. compose.yaml mounts no devices, adds no
#      capabilities and runs read_only as uid 568, so `zfs list` gets
#      "Failed to load ZFS module stack" whether or not the binary exists.
#   2. Mounting /dev/zfs to fix (1) would be a second root-equivalent hole
#      next to the Docker socket -- and a worse-behaved one. FR-8.2 accepts
#      exactly one such hole because gatekeeper is the whitelist that
#      constrains it; that argument does not extend to a device whose ioctl
#      surface includes `zfs destroy` and `zfs rollback` and which
#      denied_args cannot narrow, `zfs` being one binary with a hundred
#      subcommands.
#   3. Debian bookworm ships zfsutils-linux in *contrib*, not main, so this
#      apt line would fail outright without editing sources.list -- and at
#      2.1.11 it is two minor versions behind the OpenZFS 2.3.x kernel
#      module a current TrueNAS runs.
#
# FR-8.3/8.4 already settle where ZFS belongs: the `truenas` executor
# (JSON-RPC over WebSocket), or `ssh` for what has no API equivalent --
# where the binaries are /usr/sbin/zfs and /usr/sbin/zpool, on the host,
# not /usr/bin/* in here. Startup warns when a `local` toolkit names a
# binary this image lacks, so the next attempt says so at boot.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends procps tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && test -x /usr/bin/uptime && test -x /usr/bin/free \
 && test -x /usr/bin/df && test -x /bin/cat

COPY --from=docker-cli /usr/bin/docker /usr/bin/docker
COPY --from=docker-cli /usr/local/lib/docker/cli-plugins /usr/local/lib/docker/cli-plugins
COPY --from=build /opt/venv /opt/venv

# RELEASE.md is not part of the Python package (it lives at repo root, not
# under src/gatekeeper/) -- the console's release-notes popup reads it from
# this fixed path in production. GATEKEEPER_RELEASE_NOTES can override it;
# a dev/editable checkout finds the file next to pyproject.toml instead and
# never needs this at all (see ui.py's _release_notes()).
COPY RELEASE.md /usr/share/gatekeeper/RELEASE.md

# Project documentation — bundled into the image so the /ui/docs page
# has the full docs without runtime file access or network.
COPY README.md REQUIREMENTS.md AGENTS.md /opt/gatekeeper-docs/
COPY RELEASE.md /opt/gatekeeper-docs/RELEASE.md

# google-workspace skill scripts, baked into the image for the `google`
# executor (0.40.0). The toolkit's `google_script` points at
# /opt/gatekeeper/google/google_api.py. The sibling _hermes_home.py is
# imported by google_api.py (it adds its own directory to sys.path), so
# both must live in the same directory. The OAuth token is materialized
# to $HOME/.hermes/google_token.json per call by service.py -- no secret
# is baked into the image, only the script.
COPY src/gatekeeper/_google_api/ /opt/gatekeeper/google/

# Verify at build time that 'docker compose' actually resolves. Without this
# check, a missing plugin would only surface on the first agent call.
RUN docker compose version

# NFR-1: unprivileged user. 568 is the homelab convention (apps).
#
# HOME has to move with USER, and this is not cosmetic. python:3.12-slim
# leaves HOME=/root; a `USER 568:568` that does not override it hands the
# runtime user a home directory it cannot read. The docker CLI derives its
# config directory from HOME, and that directory is the *first* entry of
# its cli-plugin search path -- so uid 568 got
#
#   WARNING: Error loading config file: open /root/.docker/config.json:
#            permission denied
#
# followed by `compose` failing to resolve as a plugin. docker then falls
# through to its root command, where `-p` is not a flag, and answers
# `unknown shorthand flag: 'p' in -p` with exit 125 -- exactly the symptom
# the comment above the runtime apt line predicts for a missing plugin,
# reached here by an unreadable config dir rather than an absent file.
RUN groupadd -g 568 apps && useradd -u 568 -g 568 -M -s /usr/sbin/nologin apps \
 && mkdir -p /home/apps/.docker \
 && chown -R 568:568 /home/apps

# /var/log is where logs go (FHS), and keeping the audit log out of
# /etc/gatekeeper is what lets that mount be :ro -- a configuration
# directory somebody writes to every few seconds cannot be read-only, and
# then Tier 1 cannot be made immutable at runtime. Only the default for a
# fresh 'init'; an existing toolkits.yaml keeps whatever it already says.
ENV PATH="/opt/venv/bin:${PATH}" \
    HOME=/home/apps \
    DOCKER_CONFIG=/home/apps/.docker \
    GATEKEEPER_CONFIG_DIR=/etc/gatekeeper \
    GATEKEEPER_AUDIT_DIR=/var/log/gatekeeper \
    GATEKEEPER_PORT=8080 \
    GATEKEEPER_RELEASE_NOTES=/usr/share/gatekeeper/RELEASE.md \
    PYTHONUNBUFFERED=1

USER 568:568

# The compose check again, as the user that actually runs it.
#
# The one above passes as root, whose own HOME is readable -- so it stayed
# green through 0.41.0 and 0.41.1 while every compose call in production
# failed. A build-time check that runs as a different user than the
# workload verifies the wrong thing; this line is the one that would have
# caught it, and it is placed here, after USER, for that reason alone.
RUN docker compose version
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=3).status==200 else 1)"]

ENTRYPOINT ["gatekeeper"]
CMD ["serve"]