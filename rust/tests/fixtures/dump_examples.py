"""Dumps what the Python loaders make of config/examples, as the golden
fixture for rust/tests/examples.rs. Usage: dump_examples.py <repo> > out.json"""
import dataclasses
import json
import sys

sys.path.insert(0, sys.argv[1] + "/src")
from gatekeeper.catalog import load_catalog  # noqa: E402
from gatekeeper.tier1 import load_tier1  # noqa: E402

ex = sys.argv[1] + "/config/examples/"
t = load_tier1(ex + "toolkits.yaml")


def tk(k):
    d = dataclasses.asdict(k)
    return {a: (list(b) if isinstance(b, tuple) else b) for a, b in d.items()}


out = {
    "toolkits": {n: tk(k) for n, k in t.toolkits.items()},
    "destinations": {n: dataclasses.asdict(d) for n, d in t.destinations.items()},
    "rate_limits": {k: [v.count, v.window_seconds] for k, v in t.rate_limits.items()},
    "max_concurrent": t.max_concurrent,
    "audit_dir": t.audit_dir,
    "audit_max_bytes": t.audit_max_bytes,
    "audit_keep_files": t.audit_keep_files,
    "credential_references": {k: list(v) for k, v in t.credential_references().items()},
    "google_oauth_scopes": list(t.google_oauth_scopes()),
    "microsoft_oauth_scopes": list(t.microsoft_oauth_scopes()),
    "catalogs": {},
}
import os, tempfile, yaml  # noqa: E401,E402

raw = yaml.safe_load(open(ex + "toolkits.yaml"))
raw["toolkits"]["file"] = {"executor": "file", "path_roots": ["/mnt/raid"],
                           "protected_resources": ["/mnt/raid/gatekeeper"]}
tmp = tempfile.mkdtemp()
with open(os.path.join(tmp, "toolkits.yaml"), "w") as fh:
    yaml.safe_dump(raw, fh)
t_file = load_tier1(os.path.join(tmp, "toolkits.yaml"))

for f, tier in [("tools.yaml", t), ("agent-tools.yaml", t), ("file-tools.yaml", t),
                ("file-tools.yaml+file", t_file)]:
    c = load_catalog(ex + f.split("+")[0], tier)
    tools = {}
    for tid, tool in c.tools.items():
        tools[tid] = {
            "toolkit": tool.toolkit, "version": tool.version, "title": tool.title,
            "description": tool.description,
            "category": tool.category, "enabled": tool.enabled, "idempotent": tool.idempotent,
            "ssh_dispatch": tool.ssh_dispatch,
            "required_scopes": list(tool.required_scopes),
            "timeout_seconds": tool.timeout_seconds, "max_output_bytes": tool.max_output_bytes,
            "binary": tool.binary, "argv": list(tool.argv),
            "http_method": tool.http_method, "path_template": tool.path_template,
            "query_template": tool.query_template, "body_template": tool.body_template,
            "body_raw_param": tool.body_raw_param, "base_url": tool.base_url,
            "rpc_method": tool.rpc_method, "params_template": tool.params_template,
            "file_operation": tool.file_operation, "google_action": tool.google_action,
            "google_args": tool.google_args, "microsoft_action": tool.microsoft_action,
            "microsoft_args": tool.microsoft_args,
            "opencode_operation": tool.opencode_operation,
            "agent_operation": tool.agent_operation,
            "artifact_operation": tool.artifact_operation,
            "kuma_operation": tool.kuma_operation,
            "git_operation": tool.git_operation,
            "run_as": tool.run_as, "destination": tool.destination,
            "input_schema": tool.input_schema(),
            "agent_description": tool.agent_description(),
        }
    out["catalogs"][f] = {
        "tools": tools,
        "disabled_by_tier1": c.disabled_by_tier1,
        "rejected": [[s, r] for s, r in c.rejected],
        "raw_count": len(c.raw),
        "flat_specs": {e["id"]: c.flat_spec_of(e["id"]) for e in c.raw},
        "grantable": {e["id"]: c.grantable_ids(e["id"]) for e in c.raw},
    }
print(json.dumps(out, indent=1))
