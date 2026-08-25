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

# Verify at build time that 'docker compose' actually resolves. Without this
# check, a missing plugin would only surface on the first agent call.
RUN docker compose version

# NFR-1: unprivileged user. 568 is the homelab convention (apps).
RUN groupadd -g 568 apps && useradd -u 568 -g 568 -M -s /usr/sbin/nologin apps

# /var/log is where logs go (FHS), and keeping the audit log out of
# /etc/gatekeeper is what lets that mount be :ro -- a configuration
# directory somebody writes to every few seconds cannot be read-only, and
# then Tier 1 cannot be made immutable at runtime. Only the default for a
# fresh 'init'; an existing toolkits.yaml keeps whatever it already says.
ENV PATH="/opt/venv/bin:${PATH}" \
    GATEKEEPER_CONFIG_DIR=/etc/gatekeeper \
    GATEKEEPER_AUDIT_DIR=/var/log/gatekeeper \
    GATEKEEPER_PORT=8080 \
    GATEKEEPER_RELEASE_NOTES=/usr/share/gatekeeper/RELEASE.md \
    PYTHONUNBUFFERED=1

USER 568:568
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=3).status==200 else 1)"]

ENTRYPOINT ["gatekeeper"]
CMD ["serve"]