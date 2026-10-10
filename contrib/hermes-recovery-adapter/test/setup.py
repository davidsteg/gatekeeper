"""Bring up the isolated live-test instance (never touches production).

  python setup.py up      fresh secrets, fresh volume, start both containers
  python setup.py down    stop and remove containers and the test volume
  python setup.py restart restart the Hermes gateway container (state kept)

Containers (pinned Hermes image, see README.md):
  hermes-test          gateway + API server (host port 18642)
  hermes-test-adapter  the sidecar, own container on hermes-test-net (host 18790)
Host processes started separately: fake_model.py (18770), gk_serve.py (18780).
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "out")
IMAGE = ("nousresearch/hermes-agent:v0.21.6@sha256:"
         "55e192fba0cd4fde61142abbff5adeacff40efdb482ccd0ff877924bd274f909")
VOLUME = "hermes-test-data"
NETWORK = "hermes-test-net"
HOST = "host.docker.internal"


def sh(*args: str, check: bool = True, capture: bool = False) -> str:
    print("+", " ".join(a if "KEY" not in a and "TOKEN" not in a and "SECRET" not in a else a.split("=")[0] + "=***"
                       for a in args), flush=True)
    r = subprocess.run(args, check=check, text=True, capture_output=capture)
    return (r.stdout or "") if capture else ""


def down() -> None:
    sh("docker", "rm", "-f", "hermes-test-adapter", "hermes-test", check=False)
    sh("docker", "volume", "rm", "-f", VOLUME, check=False)
    sh("docker", "network", "rm", NETWORK, check=False)


def up() -> None:
    down()
    os.makedirs(OUT, exist_ok=True)
    s = {"gatekeeper_token": "gk_" + secrets.token_urlsafe(24), "adapter_secret": secrets.token_hex(24),
         "hermes_api_key": secrets.token_hex(16)}
    json.dump(s, open(os.path.join(OUT, "secrets.json"), "w", encoding="utf-8"))
    seed = os.path.join(OUT, "seed")
    os.makedirs(seed, exist_ok=True)
    with open(os.path.join(seed, "config.yaml"), "w", encoding="utf-8") as f:
        f.write(f"""model:
  provider: custom
  default: fake-model
  base_url: http://{HOST}:18770/v1
  api_key: test-not-a-secret
  api_mode: chat_completions
agent:
  max_turns: 4
plugins:
  enabled: [gatekeeper-recovery]
mcp_servers:
  gatekeeper:
    url: http://{HOST}:18780/mcp
    headers:
      Authorization: "Bearer {s['gatekeeper_token']}"
""")
    with open(os.path.join(seed, ".env"), "w", encoding="utf-8") as f:
        f.write(f"API_SERVER_ENABLED=true\nAPI_SERVER_HOST=0.0.0.0\nAPI_SERVER_KEY={s['hermes_api_key']}\n")
    sh("docker", "volume", "create", VOLUME)
    sh("docker", "network", "create", NETWORK)
    # Seed the volume: config, env, and the plugin (copied, so the journal and
    # plugin live on the Linux volume, not on a Windows bind mount).
    sh("docker", "run", "--rm", "--entrypoint", "sh", "-v", f"{VOLUME}:/opt/data",
       "-v", f"{seed}:/seed:ro", "-v", f"{os.path.join(ROOT, 'plugin')}:/plugin:ro", IMAGE, "-c",
       "mkdir -p /opt/data/plugins && cp /seed/config.yaml /seed/.env /opt/data/ && "
       "cp -r /plugin/gatekeeper-recovery /opt/data/plugins/ && chown -R 10000:10000 /opt/data")
    sh("docker", "run", "-d", "--name", "hermes-test", "--network", NETWORK, "--add-host", f"{HOST}:host-gateway",
       "-v", f"{VOLUME}:/opt/data", "-p", "127.0.0.1:18642:8642", IMAGE, "gateway", "run")
    import time
    time.sleep(15)
    sh("docker", "exec", "-u", "hermes", "hermes-test", "hermes", "tools", "enable", "kanban",
       "--platform", "api_server")
    sh("docker", "exec", "-u", "hermes", "hermes-test", "hermes", "kanban", "init")
    out = sh("docker", "exec", "-u", "hermes", "hermes-test", "hermes", "kanban", "create",
             "Orchestrate: check the stack", "--body", "Live recovery acceptance test task",
             "--initial-status", "blocked", "--json", capture=True)
    task = json.loads(out[out.index("{"):])["id"]
    json.dump({"board": "default", "task": task}, open(os.path.join(OUT, "task.json"), "w"))
    print("kanban task", task)
    sh("docker", "restart", "hermes-test")
    start_adapter(s)


def start_adapter(s: dict) -> None:
    sh("docker", "rm", "-f", "hermes-test-adapter", check=False)
    sh("docker", "run", "-d", "--name", "hermes-test-adapter", "--network", NETWORK,
       "--add-host", f"{HOST}:host-gateway", "-p", "127.0.0.1:18790:8650", "--user", "10000:10000", "-v", f"{VOLUME}:/opt/data", "-v", f"{os.path.join(ROOT, 'sidecar')}:/adapter:ro",
       "-e", "ADAPTER_INSTALLATION=test", "-e", f"ADAPTER_SECRET={s['adapter_secret']}",
       "-e", f"GATEKEEPER_URL=http://{HOST}:18780", "-e", f"GATEKEEPER_TOKEN={s['gatekeeper_token']}",
       "-e", f"HERMES_API_KEY={s['hermes_api_key']}", "-e", "HERMES_HOME=/opt/data",
       "-e", "HERMES_API_URL=http://hermes-test:8642",
       "--entrypoint", "python3", IMAGE, "/adapter/adapter.py")


def restart() -> None:
    sh("docker", "restart", "hermes-test")  # the sidecar has its own network; it keeps running


def adapter() -> None:
    start_adapter(json.load(open(os.path.join(OUT, "secrets.json"), encoding="utf-8")))


def sync_plugin() -> None:
    sh("docker", "cp", os.path.join(ROOT, "plugin", "gatekeeper-recovery") + "/.", "hermes-test:/opt/data/plugins/gatekeeper-recovery/")
    sh("docker", "exec", "hermes-test", "chown", "-R", "10000:10000", "/opt/data/plugins")


if __name__ == "__main__":
    {"up": up, "down": down, "restart": restart, "adapter": adapter, "sync": sync_plugin}[sys.argv[1]]()
