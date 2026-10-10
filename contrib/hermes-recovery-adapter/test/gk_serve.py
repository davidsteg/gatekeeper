"""Run the real Gatekeeper (from a Gatekeeper checkout, normally this repository) for the
live test. Windows has no SIGHUP, so this builds the ASGI app directly and
runs uvicorn (docs/DEPLOYMENT.md), with a throwaway test configuration.

usage: python gk_serve.py <gatekeeper-checkout> [--keep]
Writes test/out/gk/{toolkits,tools,identities}.yaml, recovery.yaml, logs/.
Reads secrets from test/out/secrets.json (created by setup.py).
"""

from __future__ import annotations

import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out", "gk")
CHECKOUT = sys.argv[1]
sys.path.insert(0, os.path.join(CHECKOUT, "src"))

import uvicorn  # noqa: E402
import yaml  # noqa: E402

from gatekeeper.audit import AuditLog  # noqa: E402
from gatekeeper.catalog import load_catalog  # noqa: E402
from gatekeeper.identity import hash_token, load_identities  # noqa: E402
from gatekeeper.recovery import IncidentStore, RecoverySupervisor  # noqa: E402
from gatekeeper.server import build_app  # noqa: E402
from gatekeeper.service import Service  # noqa: E402
from gatekeeper.tier1 import load_tier1  # noqa: E402

secrets = json.load(open(os.path.join(HERE, "out", "secrets.json"), encoding="utf-8"))
if "--keep" not in sys.argv and os.path.isdir(OUT):
    shutil.rmtree(OUT)
os.makedirs(os.path.join(OUT, "root"), exist_ok=True)
PY = os.path.realpath(sys.executable)

with open(os.path.join(OUT, "toolkits.yaml"), "w", encoding="utf-8") as f:
    yaml.safe_dump({
        "toolkits": {"demo": {"executor": "local", "binaries": [PY], "path_roots": [os.path.join(OUT, "root")],
                              "max_timeout_seconds": 30, "max_output_bytes": 8192}},
        "audit": {"dir": os.path.join(OUT, "logs")},
        "recovery": {
            "enabled": True, "state_file": os.path.join(OUT, "recovery.yaml"),
            "trigger_after": 2, "tick_seconds": 1, "status_poll_seconds": 2,
            "ack_timeout_seconds": 180, "progress_timeout_seconds": 300,
            "installations": {"test": {
                "identities": ["hermes-test"], "profiles": ["default"],
                "adapter_url": "http://127.0.0.1:18790/recovery", "credential": "adapter-hmac"}},
        },
    }, f)
common = {"toolkit": "demo", "binary": PY, "version": 1, "enabled": True, "max_output_bytes": 4096,
          "timeout_seconds": 10, "required_scopes": []}
with open(os.path.join(OUT, "tools.yaml"), "w", encoding="utf-8") as f:
    yaml.safe_dump({"tools": [
        {**common, "id": "demo.fail", "title": "Check NAS (fails)", "description": "Checks a target; fails.",
         "category": "read", "idempotent": True,
         "argv": ["-c", "import sys; sys.stderr.write('connection refused to ' + sys.argv[1] + '\\n'); sys.exit(3)",
                  "{target}"],
         "parameters": {"target": {"type": "string", "required": True, "pattern": "^[a-z]+$",
                                   "description": "target"}}},
        {**common, "id": "demo.read", "title": "Read stack state", "description": "Reads the stack state.",
         "category": "read", "idempotent": True, "argv": ["-c", "print('stack ok')"], "parameters": {}},
    ]}, f)
with open(os.path.join(OUT, "identities.yaml"), "w", encoding="utf-8") as f:
    yaml.safe_dump({"identities": [{
        "id": "hermes-test", "role": "agent", "token_hash": hash_token(secrets["gatekeeper_token"]),
        "tools": ["demo.fail", "demo.read"], "scopes": []}]}, f)

tier1 = load_tier1(os.path.join(OUT, "toolkits.yaml"))
catalog = load_catalog(os.path.join(OUT, "tools.yaml"), tier1)
identities = load_identities(os.path.join(OUT, "identities.yaml"))
audit = AuditLog(os.path.join(OUT, "logs"))
service = Service(tier1=tier1, catalog=catalog, audit=audit, identities=identities)
service.recovery = RecoverySupervisor(
    config_source=lambda: service.tier1.recovery,
    store=IncidentStore(os.path.join(OUT, "recovery.yaml")),
    audit=audit,
    secret_resolver={"adapter-hmac": secrets["adapter_secret"]}.get,
)
app = build_app(service=service, identities=identities, audit=audit, host="0.0.0.0")
uvicorn.run(app, host="0.0.0.0", port=18780, log_level="warning")
