# syntax=docker/dockerfile:1

# --- Build ----------------------------------------------------------------
FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml ./
COPY src ./src

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install .

# --- Docker-CLI + Compose-Plugin ------------------------------------------
# Nur der Client, kein Daemon. gatekeeper spricht ueber den gemounteten Socket
# mit dem Docker-Daemon des Hosts.
#
# Das statische Docker-Tarball enthaelt NUR das docker-Binary. `docker compose`
# ist ein CLI-Plugin und muss getrennt installiert werden -- ohne das scheitert
# jedes compose-Tool zur Laufzeit mit "unknown shorthand flag: 'p'".
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
      *) echo "nicht unterstuetzte Architektur: ${TARGETARCH}" >&2; exit 1 ;; \
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

# --- Laufzeit -------------------------------------------------------------
FROM python:3.12-slim

# procps liefert /usr/bin/free, coreutils /usr/bin/df und /bin/cat.
# Die Binaries muessen exakt an den in toolkits.yaml gelisteten Pfaden liegen -
# gatekeeper laesst PATH nicht entscheiden (FR-4.1).
RUN apt-get update \
 && apt-get install -y --no-install-recommends procps \
 && rm -rf /var/lib/apt/lists/* \
 && test -x /usr/bin/uptime && test -x /usr/bin/free \
 && test -x /usr/bin/df && test -x /bin/cat

COPY --from=docker-cli /usr/bin/docker /usr/bin/docker
COPY --from=docker-cli /usr/local/lib/docker/cli-plugins /usr/local/lib/docker/cli-plugins
COPY --from=build /opt/venv /opt/venv

# Beim Bau nachweisen, dass 'docker compose' tatsaechlich aufloest. Ohne diese
# Pruefung faellt ein fehlendes Plugin erst beim ersten Agentenaufruf auf.
RUN docker compose version

# NFR-1: unprivilegierter Benutzer. 568 ist die Homelab-Konvention (apps).
RUN groupadd -g 568 apps && useradd -u 568 -g 568 -M -s /usr/sbin/nologin apps

ENV PATH="/opt/venv/bin:${PATH}" \
    GATEKEEPER_CONFIG_DIR=/etc/gatekeeper \
    GATEKEEPER_PORT=8080 \
    PYTHONUNBUFFERED=1

USER 568:568
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=3).status==200 else 1)"]

ENTRYPOINT ["gatekeeper"]
CMD ["serve"]
