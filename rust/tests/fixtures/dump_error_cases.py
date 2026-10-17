"""Golden error messages for rust/tests/error_parity.rs.

Each case is a Tier 1 document (and optionally one tool spec parsed
against it); the fixture records the exact `ConfigError` text Python
produces, or null when it loads. Usage:
    dump_error_cases.py <repo> > error_cases_golden.json
"""
import copy
import json
import os
import sys
import tempfile

import yaml

sys.path.insert(0, sys.argv[1] + "/src")
from gatekeeper.catalog import parse_tool_spec  # noqa: E402
from gatekeeper.errors import ConfigError, Tier1Violation  # noqa: E402
from gatekeeper.tier1 import load_tier1  # noqa: E402

SH = "/bin/sh"
KH = "host ssh-ed25519 AAAAC3Nza"

BASE = {
    "local": {"executor": "local", "binaries": [SH], "path_roots": ["/srv"],
              "denied_args": ["rm"], "max_timeout_seconds": 30, "max_output_bytes": 8192},
    "dock": {"executor": "docker", "binaries": [SH]},
    "web": {"executor": "http", "base_url": "http://sonarr.lan:8989", "allowed_methods": ["GET", "POST"],
            "allowed_path_prefixes": ["/api/"], "allowed_cidrs": ["10.0.0.0/8"]},
    "gh": {"executor": "http", "base_url": "https://api.github.com", "allowed_methods": ["GET"],
           "allowed_path_prefixes": ["/repos/"], "allowed_hosts": ["api.github.com"]},
    "nas": {"executor": "truenas", "ws_url": "wss://nas/api/current", "allowed_rpc_methods": ["pool.query"]},
    "box": {"executor": "ssh", "binaries": [SH], "ssh_host": "box", "ssh_user": "gk", "ssh_known_hosts": KH},
    "files": {"executor": "file", "path_roots": ["/srv"], "run_as": "3001:3001"},
    "gmail": {"executor": "google", "google_script": "/opt/g.py", "allowed_google_actions": ["gmail search"],
              "required_scopes": ["gmail.readonly"]},
    "outlook": {"executor": "microsoft", "microsoft_script": "/opt/m.py",
                "allowed_microsoft_actions": ["mail list"]},
    "oc": {"executor": "opencode", "base_url": "http://oc:4096", "allowed_cidrs": ["10.0.0.0/8"],
           "allowed_opencode_operations": ["ask", "check", "health"], "path_roots": ["/work"]},
    "agent": {"executor": "agent", "mailbox_path": "/data/messages.yaml",
              "allowed_agent_operations": ["send_message", "read_messages", "mailbox_status"]},
    "art": {"executor": "artifact", "allowed_artifact_operations": ["list", "info", "transfer"],
            "allowed_artifacts": ["hermes-skill"], "handover_dir": "/handover"},
    "kuma": {"executor": "kuma", "base_url": "http://kuma.lan:3001", "allowed_cidrs": ["10.0.0.0/8"],
             "credential": "kuma", "allowed_kuma_operations": ["monitor_list", "monitor_add_http", "monitor_pause"]},
}

# (name, toolkit name, field overrides; None deletes the field)
TOOLKIT_CASES = [
    ("not_mapping", "local", "__replace__", ["x"]),
    ("no_executor", "local", "executor", None),
    ("bad_executor", "local", "executor", "podman"),
    ("bad_executor_int", "local", "executor", 5),
    ("zero_timeout", "local", "max_timeout_seconds", 0),
    ("str_timeout", "local", "max_timeout_seconds", "45"),
    ("float_output", "local", "max_output_bytes", 100.7),
    ("bad_int", "local", "max_output_bytes", "lots"),
    ("cred_not_str", "local", "credential", ["x"]),
    ("runas_on_local", "local", "run_as", "hermes"),
    ("runas_bad", "files", "run_as", "3001"),
    ("runas_range", "files", "run_as", "4294967296:0"),
    ("runas_empty", "files", "run_as", "   "),
    ("runas_name", "files", "run_as", " hermes "),
    ("scopes_on_http", "web", "required_scopes", ["x"]),
    ("scopes_not_list", "gmail", "required_scopes", "gmail.send"),
    ("no_binaries", "local", "binaries", None),
    ("empty_binaries", "local", "binaries", []),
    ("relative_binary", "local", "binaries", ["sh"]),
    ("binaries_not_strs", "local", "binaries", [1]),
    ("docker_host_bad", "dock", "docker_host", "not-a-url"),
    ("docker_host_unix", "dock", "docker_host", "unix:///var/run/docker.sock"),
    ("docker_host_tcp", "dock", "docker_host", "tcp://nas2.lan:2376"),
    ("docker_host_http", "dock", "docker_host", "http://nas2.lan:2376"),
    ("ssh_no_host", "box", "ssh_host", None),
    ("ssh_port_range", "box", "ssh_port", 70000),
    ("ssh_port_str", "box", "ssh_port", "2222"),
    ("ssh_no_user", "box", "ssh_user", None),
    ("ssh_empty_kh", "box", "ssh_known_hosts", "  \n"),
    ("ssh_dest", "box", "destinations", ["d_docker"]),
    ("http_no_base", "web", "base_url", None),
    ("http_bad_base", "web", "base_url", "sonarr.lan:8989"),
    ("http_ftp_base", "web", "base_url", "ftp://x"),
    ("http_no_methods", "web", "allowed_methods", []),
    ("http_bad_methods", "web", "allowed_methods", ["GET", "FETCH", "BREW"]),
    ("http_no_prefix", "web", "allowed_path_prefixes", None),
    ("http_bad_prefix", "web", "allowed_path_prefixes", ["api/"]),
    ("http_no_cidrs", "web", "allowed_cidrs", []),
    ("http_bad_cidr", "web", "allowed_cidrs", ["10.0.0.0/33"]),
    ("http_follow", "web", "follow_redirects", True),
    ("http_follow_false", "web", "follow_redirects", False),
    ("truenas_bad_ws", "nas", "ws_url", "https://nas"),
    ("truenas_no_methods", "nas", "allowed_rpc_methods", []),
    ("google_relative", "gmail", "google_script", "g.py"),
    ("google_container_empty", "gmail", "google_container", ""),
    ("google_container", "gmail", "google_container", "hermes"),
    ("google_no_actions", "gmail", "allowed_google_actions", []),
    ("ms_relative", "outlook", "microsoft_script", "m.py"),
    ("ms_container_empty", "outlook", "microsoft_container", ""),
    ("ms_no_actions", "outlook", "allowed_microsoft_actions", None),
    ("oc_credential_placeholder", "oc", "base_url", "http://oc:4096/{credential}"),
    ("oc_no_cidrs", "oc", "allowed_cidrs", None),
    ("oc_bad_cidr", "oc", "allowed_cidrs", ["oc.lan"]),
    ("oc_unknown_ops", "oc", "allowed_opencode_operations", ["ask", "shell", "exec"]),
    ("oc_no_ops", "oc", "allowed_opencode_operations", []),
    ("agent_relative", "agent", "mailbox_path", "messages.yaml"),
    ("agent_dotdot", "agent", "mailbox_path", "/data/../etc/m.yaml"),
    ("agent_unknown_ops", "agent", "allowed_agent_operations", ["send_message", "broadcast"]),
    ("agent_ceiling", "agent", "max_message_bytes", 0),
    ("agent_subset", "agent", "allowed_agent_operations", ["read_messages"]),
    ("agent_dest", "agent", "destinations", ["d_docker"]),
    ("art_unknown_ops", "art", "allowed_artifact_operations", ["list", "delete"]),
    ("art_empty_ops", "art", "allowed_artifact_operations", []),
    ("art_no_artifacts", "art", "allowed_artifacts", []),
    ("art_removed", "art", "allowed_artifacts", ["hermes-recovery-adapter", "x"]),
    ("art_bad_handover", "art", "handover_dir", "/a/../b"),
    ("art_no_handover", "art", "handover_dir", None),
    ("art_dest", "art", "destinations", ["d_docker"]),
    ("local_dest", "local", "destinations", ["d_docker"]),
    ("unknown_dest", "dock", "destinations", ["ghost"]),
    ("dock_dest_shape", "dock", "destinations", ["d_http"]),
    ("http_dest_shape", "web", "destinations", ["d_docker"]),
    ("oc_dest_shape", "oc", "destinations", ["d_docker"]),
    ("nas_dest_shape", "nas", "destinations", ["d_http"]),
    ("hosts_and_cidrs", "web", "allowed_hosts", ["sonarr.lan"]),
    ("hosts_normalized", "web", "allowed_hosts", ["SONARR.lan.", " sonarr.lan ", "sonarr.lan"]),
    ("hosts_wildcard", "web", "allowed_hosts", ["*.lan"]),
    ("hosts_question", "web", "allowed_hosts", ["sonarr?.lan"]),
    ("hosts_ipv4", "web", "allowed_hosts", ["10.0.0.1"]),
    ("hosts_ipv6", "web", "allowed_hosts", ["::1"]),
    ("hosts_ipv6_bracketed", "web", "allowed_hosts", ["[fe80::1]"]),
    ("hosts_ipv4_leading_zero", "web", "allowed_hosts", ["010.0.0.1"]),
    ("hosts_single_label", "web", "allowed_hosts", ["localhost"]),
    ("hosts_url", "web", "allowed_hosts", ["https://sonarr.lan"]),
    ("hosts_underscore", "web", "allowed_hosts", ["bad_host.lan"]),
    ("hosts_dash", "web", "allowed_hosts", ["-x.lan"]),
    ("hosts_dash_end", "web", "allowed_hosts", ["x-.lan"]),
    ("hosts_long_label", "web", "allowed_hosts", ["a" * 64 + ".lan"]),
    ("hosts_too_long", "web", "allowed_hosts", [".".join(["a" * 63] * 4) + ".lan"]),
    ("hosts_empty_entry", "web", "allowed_hosts", [""]),
    ("hosts_empty_label", "web", "allowed_hosts", ["a..lan"]),
    ("hosts_not_list", "web", "allowed_hosts", "sonarr.lan"),
    ("hosts_not_strs", "web", "allowed_hosts", [1]),
    ("hosts_other_host", "web", "allowed_hosts", ["api.github.com"]),
    ("hosts_empty_list", "web", "allowed_hosts", []),
    ("hosts_only", "gh", "allowed_cidrs", None),
    ("hosts_cidrs_narrow", "gh", "allowed_cidrs", ["140.82.112.0/20"]),
    ("hosts_cidrs_bad", "gh", "allowed_cidrs", ["x"]),
    ("hosts_none_cidrs_none", "gh", "allowed_hosts", None),
    ("hosts_cidrs_not_list", "gh", "allowed_cidrs", "10.0.0.0/8"),
    ("hosts_dest_ok", "gh", "__replace__", {**BASE["gh"], "allowed_hosts": ["api.github.com", "x.lan"],
                                            "destinations": ["d_http"]}),
    ("hosts_dest_outside", "gh", "destinations", ["d_http"]),
    ("hosts_on_local", "local", "allowed_hosts", ["api.github.com"]),
    ("hosts_on_nas_empty", "nas", "allowed_hosts", []),
    ("hosts_on_file", "files", "allowed_hosts", ["x.lan"]),
    ("oc_hosts_ok", "oc", "__replace__", {**BASE["oc"], "base_url": "http://oc.lan:4096",
                                          "allowed_hosts": ["oc.lan"]}),
    ("oc_hosts_other", "oc", "allowed_hosts", ["oc.example.com"]),
    ("oc_hosts_bad", "oc", "allowed_hosts", ["oc"]),
    ("kuma_no_base", "kuma", "base_url", None),
    ("kuma_bad_base", "kuma", "base_url", "ws://kuma.lan:3001"),
    ("kuma_credential_placeholder", "kuma", "base_url", "http://kuma.lan:3001/{credential}"),
    ("kuma_no_cidrs", "kuma", "allowed_cidrs", None),
    ("kuma_no_credential", "kuma", "credential", None),
    ("kuma_empty_credential", "kuma", "credential", ""),
    ("kuma_no_ops", "kuma", "allowed_kuma_operations", None),
    ("kuma_empty_ops", "kuma", "allowed_kuma_operations", []),
    ("kuma_unknown_ops", "kuma", "allowed_kuma_operations", ["monitor_list", "monitor_delete", "edit"]),
    ("kuma_ops_not_list", "kuma", "allowed_kuma_operations", "monitor_list"),
    ("kuma_dest", "kuma", "destinations", ["d_http"]),
    ("kuma_hosts_ok", "kuma", "__replace__", {**BASE["kuma"], "base_url": "https://kuma.example.org",
                                              "allowed_cidrs": None, "allowed_hosts": ["kuma.example.org"]}),
    ("kuma_hosts_other", "kuma", "allowed_hosts", ["status.example.org"]),
    ("kuma_follow", "kuma", "follow_redirects", True),
    ("denied_not_list", "local", "denied_args", "rm"),
    ("roots_not_strs", "local", "path_roots", [1, 2]),
]

DESTS = {"d_docker": {"docker_host": "unix:///var/run/docker.sock"},
         "d_http": {"base_url": "http://x.lan", "credential": "c"}}

TOP_CASES = [
    ("toolkits_list", {"toolkits": ["x"]}),
    ("dest_list", {"toolkits": {}, "destinations": ["x"]}),
    ("dest_not_mapping", {"toolkits": {}, "destinations": {"a": "x"}}),
    ("dest_bad_docker", {"toolkits": {}, "destinations": {"a": {"docker_host": "nope"}}}),
    ("dest_bad_base", {"toolkits": {}, "destinations": {"a": {"base_url": "x"}}}),
    ("dest_bad_ws", {"toolkits": {}, "destinations": {"a": {"ws_url": "http://x"}}}),
    ("dest_bad_cred", {"toolkits": {}, "destinations": {"a": {"credential": 5}}}),
    ("recovery_enabled", {"toolkits": {}, "recovery": {"hermes": {"enabled": True}}}),
    ("recovery_inert", {"toolkits": {}, "recovery": {"enabled": False}}),
    ("empty", {}),
    ("rate_limits", {"toolkits": {}, "rate_limits": {"read": {"count": 5}, "custom": {"window_seconds": "7"}},
                     "max_concurrent": "8", "audit": {"dir": "/x", "max_bytes": 10, "keep_files": 2}}),
]


def write_and_load(doc):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "toolkits.yaml")
    with open(p, "w") as fh:
        yaml.safe_dump(doc, fh)
    try:
        t = load_tier1(p)
    except ConfigError as exc:
        return None, {"error": str(exc).replace(p, "<path>")}
    except (ValueError, TypeError) as exc:
        return None, {"error": str(exc), "python_crash": type(exc).__name__}
    return t, {"error": None, "summary": summary(t)}


def summary(t):
    return {
        "toolkits": {n: {"executor": k.executor, "run_as": k.run_as, "ssh_port": k.ssh_port,
                         "max_timeout_seconds": k.max_timeout_seconds,
                         "max_output_bytes": k.max_output_bytes, "docker_host": k.docker_host,
                         "destinations": list(k.destinations), "required_scopes": list(k.required_scopes),
                         "google_container": k.google_container,
                         "allowed_hosts": list(k.allowed_hosts),
                         "allowed_cidrs": list(k.allowed_cidrs)}
                     for n, k in t.toolkits.items()},
        "rate_limits": {k: [v.count, v.window_seconds] for k, v in t.rate_limits.items()},
        "max_concurrent": t.max_concurrent, "audit": [t.audit_dir, t.audit_max_bytes, t.audit_keep_files],
        "credential_references": {k: list(v) for k, v in t.credential_references().items()},
    }


out = {"toolkit_cases": [], "top_cases": [], "tool_cases": []}
for name, tk, field, value in TOOLKIT_CASES:
    toolkits = copy.deepcopy(BASE)
    if field == "__replace__":
        toolkits[tk] = value
    elif value is None:
        toolkits[tk].pop(field, None)
    else:
        toolkits[tk][field] = value
    doc = {"toolkits": toolkits, "destinations": DESTS, "audit": {"dir": "/tmp/x"}}
    _, res = write_and_load(doc)
    out["toolkit_cases"].append({"name": name, "doc": doc, **res})
for name, doc in TOP_CASES:
    _, res = write_and_load(doc)
    out["top_cases"].append({"name": name, "doc": doc, **res})

# -- Tool specs against the BASE Tier 1 --------------------------------------
tier1, _ = write_and_load({"toolkits": BASE, "destinations": DESTS, "audit": {"dir": "/tmp/x"}})


def tool(tid, tk, **kw):
    spec = {"id": tid, "toolkit": tk, "title": "t", "description": "d", "category": "read",
            "enabled": True, "parameters": {}, "required_scopes": [], "timeout_seconds": 5,
            "max_output_bytes": 1024}
    spec.update(kw)
    return spec


S = {"type": "string", "pattern": "^[a-z]+$", "required": True, "description": "s"}
KID = {"type": "integer", "required": True, "minimum": 1, "description": "id"}
KADD = {"name": S, "url": {**S, "pattern": "^https?://[a-z.]+/$"},
        "interval": {"type": "integer", "minimum": 30, "maximum": 3600, "description": "s"},
        "expected_status": {"type": "enum", "values": ["200-299", "401"], "description": "s"}}
TOOL_CASES = [
    ("not_mapping", ["x"]),
    ("bad_id", tool("Local.x", "local", binary=SH)),
    ("id_none", tool(None, "local", binary=SH)),
    ("id_no_dot", tool("local", "local", binary=SH)),
    ("no_toolkit", tool("local.x", None, binary=SH)),
    ("prefix_mismatch", tool("local.x", "web", binary=SH)),
    ("unknown_toolkit", tool("ghost.x", "ghost")),
    ("bad_category", tool("local.x", "local", binary=SH, category="delete")),
    ("no_category", tool("local.x", "local", binary=SH, category=None)),
    ("param_not_mapping", tool("local.x", "local", binary=SH, parameters={"a": "x"})),
    ("param_bad_type", tool("local.x", "local", binary=SH, parameters={"a": {"type": "float"}})),
    ("param_no_type", tool("local.x", "local", binary=SH, parameters={"a": {}})),
    ("param_pattern_list", tool("local.x", "local", binary=SH, parameters={"a": {"type": "string", "pattern": ["a"]}})),
    ("param_pattern_int", tool("local.x", "local", binary=SH, parameters={"a": {"type": "string", "pattern": 5}})),
    ("param_free_text", tool("local.x", "local", binary=SH, parameters={"a": {"type": "string"}})),
    ("param_empty_pattern", tool("local.x", "local", binary=SH, parameters={"a": {"type": "string", "pattern": ""}})),
    ("enum_no_values", tool("local.x", "local", binary=SH, parameters={"a": {"type": "enum"}})),
    ("path_no_derived", tool("local.x", "local", binary=SH, parameters={"a": {"type": "path", "must_resolve_under": "/srv"}})),
    ("path_no_root", tool("local.x", "local", binary=SH, parameters={"a": {"type": "path", "derived": "/srv/x"}})),
    ("path_outside", tool("local.x", "local", binary=SH, parameters={"a": {"type": "path", "derived": "/etc/x", "must_resolve_under": "/etc"}})),
    ("path_inside", tool("local.x", "local", binary=SH, parameters={"a": {"type": "path", "derived": "/srv/x", "must_resolve_under": "/srv/sub"}})),
    ("no_binary", tool("local.x", "local")),
    ("binary_not_allowed", tool("local.x", "local", binary="/bin/bash")),
    ("argv_not_list", tool("local.x", "local", binary=SH, argv="x")),
    ("argv_denied", tool("local.x", "local", binary=SH, argv=["rm", "x"])),
    ("argv_unknown_placeholder", tool("local.x", "local", binary=SH, argv=["{nope}"])),
    ("scope_unknown_placeholder", tool("local.x", "local", binary=SH, required_scopes=["stack:{nope}"])),
    ("derived_unknown_placeholder", tool("local.x", "local", binary=SH, parameters={"d": {"type": "string", "derived": "{zz}"}})),
    ("timeout_exceeds", tool("local.x", "local", binary=SH, timeout_seconds=31)),
    ("output_exceeds", tool("local.x", "local", binary=SH, max_output_bytes=8193)),
    ("bad_version", tool("local.x", "local", binary=SH, version="two")),
    ("ok_local", tool("local.x", "local", binary=SH, argv=["-c", "{a}"], parameters={"a": S},
                      required_scopes="ab", version="3", idempotent=1)),
    ("gh_override_host_outside", tool("gh.x", "gh", method="GET", path="/repos/x",
                                      base_url="https://evil.example.com")),
    ("gh_override_host_case", tool("gh.x", "gh", method="GET", path="/repos/x",
                                   base_url="https://API.GitHub.com.")),
    ("gh_override_no_host", tool("gh.x", "gh", method="GET", path="/repos/x",
                                 base_url="http://")),
    ("web_override_any_host", tool("web.x", "web", method="GET", path="/api/x",
                                   base_url="https://evil.example.com")),
    ("http_no_method", tool("web.x", "web", path="/api/x")),
    ("http_bad_path", tool("web.x", "web", method="GET", path="api/x")),
    ("http_method_denied", tool("web.x", "web", method="DELETE", path="/api/x")),
    ("http_prefix_denied", tool("web.x", "web", method="GET", path="/apix/{a}", parameters={"a": S})),
    ("http_query_not_strs", tool("web.x", "web", method="GET", path="/api/x", query={"a": 1})),
    ("http_query_placeholder", tool("web.x", "web", method="GET", path="/api/x", query={"a": "{q}"})),
    ("http_body_placeholder", tool("web.x", "web", method="POST", path="/api/x", body={"a": [{"b": "{q}"}]})),
    ("http_raw_two_keys", tool("web.x", "web", method="POST", path="/api/x", body={"raw_param": "a", "z": 1, "b": 2}, parameters={"a": S})),
    ("http_raw_not_str", tool("web.x", "web", method="POST", path="/api/x", body={"raw_param": ""})),
    ("http_base_bad", tool("web.x", "web", method="GET", path="/api/x", base_url="nope")),
    ("truenas_no_method", tool("nas.x", "nas")),
    ("truenas_params_bad", tool("nas.x", "nas", method="pool.query", params=["x"])),
    ("truenas_method_denied", tool("nas.x", "nas", method="pool.delete")),
    ("file_no_op", tool("files.x", "files")),
    ("file_bad_op", tool("files.x", "files", file_operation="delete")),
    ("file_bad_runas", tool("files.x", "files", operation="read", run_as="a b")),
    ("google_no_action", tool("gmail.x", "gmail")),
    ("google_action_denied", tool("gmail.x", "gmail", google_action="gmail send")),
    ("google_path_root", tool("gmail.x", "gmail", google_action="gmail search", parameters={"p": {"type": "path", "derived": "/srv/a", "must_resolve_under": "/srv"}})),
    ("ms_no_action", tool("outlook.x", "outlook", microsoft_action="")),
    ("ms_action_denied", tool("outlook.x", "outlook", microsoft_action="mail send")),
    ("oc_no_op", tool("oc.x", "oc")),
    ("oc_unknown_op", tool("oc.x", "oc", opencode_operation="shell")),
    ("oc_missing_prompt", tool("oc.x", "oc", opencode_operation="ask")),
    ("oc_prompt_optional", tool("oc.x", "oc", opencode_operation="ask", parameters={"prompt": {**S, "required": False}})),
    ("oc_extra_param", tool("oc.x", "oc", opencode_operation="ask", parameters={"prompt": S, "dir": S, "a": S})),
    ("oc_health_params", tool("oc.x", "oc", opencode_operation="health", parameters={"x": S})),
    ("oc_op_denied", tool("oc.x", "oc", operation="abort", parameters={"session_id": S})),
    ("agent_unknown_op", tool("agent.x", "agent", agent_operation="broadcast")),
    ("agent_missing_to", tool("agent.x", "agent", agent_operation="send_message", parameters={"body": S})),
    ("agent_from", tool("agent.x", "agent", agent_operation="send_message", parameters={"body": S, "to": S, "from": S})),
    ("agent_status_params", tool("agent.x", "agent", agent_operation="mailbox_status", parameters={"x": S})),
    ("art_unknown_op", tool("art.x", "art", artifact_operation="delete")),
    ("art_missing", tool("art.x", "art", artifact_operation="info")),
    ("art_extra", tool("art.x", "art", artifact_operation="list", parameters={"x": S})),
    ("art_denied", tool("art.x", "art", artifact_operation="read", parameters={"artifact": S})),
    ("kuma_no_op", tool("kuma.x", "kuma")),
    ("kuma_unknown_op", tool("kuma.x", "kuma", kuma_operation="monitor_delete")),
    ("kuma_op_alias", tool("kuma.x", "kuma", operation="monitor_list")),
    ("kuma_op_denied", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_resume", parameters={"monitor_id": KID})),
    ("kuma_write_as_read", tool("kuma.x", "kuma", kuma_operation="monitor_pause", parameters={"monitor_id": KID})),
    ("kuma_add_ok", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http", parameters=KADD)),
    ("kuma_add_missing_url", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http", parameters={"name": S})),
    ("kuma_add_extra", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http", parameters={**KADD, "method": S})),
    ("kuma_interval_wide", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http",
                                parameters={**KADD, "interval": {**KADD["interval"], "maximum": 86400}})),
    ("kuma_interval_low", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http",
                               parameters={**KADD, "interval": {**KADD["interval"], "minimum": 20}})),
    ("kuma_interval_float", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http",
                                 parameters={**KADD, "interval": {**KADD["interval"], "minimum": 30.5, "maximum": 3600.0}})),
    ("kuma_interval_unbounded", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http",
                                     parameters={**KADD, "interval": {"type": "integer", "description": "s"}})),
    ("kuma_interval_string", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http",
                                  parameters={**KADD, "interval": S})),
    ("kuma_status_wide", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http",
                              parameters={**KADD, "expected_status": {"type": "enum", "values": ["200", "500"], "description": "s"}})),
    ("kuma_status_string", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http",
                                parameters={**KADD, "expected_status": S})),
    ("kuma_url_enum", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_add_http",
                           parameters={**KADD, "url": {"type": "enum", "values": ["https://x.org/"], "required": True, "description": "u"}})),
    ("kuma_id_zero", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_pause",
                          parameters={"monitor_id": {**KID, "minimum": 0}})),
    ("kuma_id_unbounded", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_pause",
                               parameters={"monitor_id": {"type": "integer", "required": True, "description": "i"}})),
    ("kuma_id_string", tool("kuma.x", "kuma", category="write", kuma_operation="monitor_pause", parameters={"monitor_id": S})),
]
for name, spec in TOOL_CASES:
    try:
        t = parse_tool_spec(spec, tier1)
        res = {"error": None, "tier1_violation": False,
               "summary": {"version": t.version, "idempotent": t.idempotent,
                           "required_scopes": list(t.required_scopes),
                           "input_schema": t.input_schema(), "body_template": t.body_template,
                           "run_as": t.run_as}}
    except Tier1Violation as exc:
        res = {"error": str(exc), "tier1_violation": True}
    except ConfigError as exc:
        res = {"error": str(exc), "tier1_violation": False}
    except (ValueError, TypeError) as exc:
        res = {"error": str(exc), "python_crash": type(exc).__name__}
    out["tool_cases"].append({"name": name, "spec": spec, **res})
print(json.dumps(out, indent=1))
