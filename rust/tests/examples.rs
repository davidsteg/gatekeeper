//! Every file in `config/examples/` loads in Rust exactly as it does in
//! Python.
//!
//! `tests/fixtures/examples_golden.json` is what the Python loaders make
//! of the examples, written by `tests/fixtures/dump_examples.py` (run it
//! with the repo root as argument and redirect stdout into the JSON file
//! whenever the examples change): every toolkit field,
//! every parsed tool field, the MCP `inputSchema`, the agent description,
//! the disabled/rejected lists, `flat_spec_of` and `grantable_ids`.

mod common;

use common::examples_dir;
use gatekeeper::catalog::{load_catalog, CliArg, ToolDef};
use gatekeeper::tier1::{load_tier1, Tier1, Toolkit};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

fn opt_args(a: &Option<IndexMap<String, CliArg>>) -> Value {
    match a {
        None => Value::Null,
        Some(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), v.to_value())).collect()),
    }
}

fn toolkit_value(t: &Toolkit) -> Value {
    json!({
        "name": t.name, "executor": t.executor, "binaries": t.binaries,
        "denied_args": t.denied_args, "path_roots": t.path_roots,
        "protected_resources": t.protected_resources,
        "max_timeout_seconds": t.max_timeout_seconds, "max_output_bytes": t.max_output_bytes,
        "credential": t.credential, "base_url": t.base_url, "allowed_methods": t.allowed_methods,
        "allowed_path_prefixes": t.allowed_path_prefixes, "allowed_cidrs": t.allowed_cidrs,
        "ws_url": t.ws_url, "allowed_rpc_methods": t.allowed_rpc_methods,
        "destinations": t.destinations, "docker_host": t.docker_host, "docker_tls": t.docker_tls,
        "ssh_host": t.ssh_host, "ssh_port": t.ssh_port, "ssh_user": t.ssh_user,
        "ssh_known_hosts": t.ssh_known_hosts, "run_as": t.run_as,
        "google_script": t.google_script, "google_container": t.google_container,
        "allowed_google_actions": t.allowed_google_actions, "required_scopes": t.required_scopes,
        "microsoft_script": t.microsoft_script, "microsoft_container": t.microsoft_container,
        "allowed_microsoft_actions": t.allowed_microsoft_actions,
        "allowed_opencode_operations": t.allowed_opencode_operations,
        "mailbox_path": t.mailbox_path, "allowed_agent_operations": t.allowed_agent_operations,
        "allowed_artifact_operations": t.allowed_artifact_operations,
        "allowed_artifacts": t.allowed_artifacts, "handover_dir": t.handover_dir,
        "max_message_bytes": t.max_message_bytes, "max_mailbox_messages": t.max_mailbox_messages,
    })
}

fn tool_value(t: &ToolDef) -> Value {
    json!({
        "toolkit": t.toolkit, "version": t.version, "title": t.title,
        "description": t.description, "category": t.category, "enabled": t.enabled,
        "idempotent": t.idempotent, "ssh_dispatch": t.ssh_dispatch,
        "required_scopes": t.required_scopes, "timeout_seconds": t.timeout_seconds,
        "max_output_bytes": t.max_output_bytes, "binary": t.binary, "argv": t.argv,
        "http_method": t.http_method, "path_template": t.path_template,
        "query_template": t.query_template, "body_template": t.body_template,
        "body_raw_param": t.body_raw_param, "base_url": t.base_url, "rpc_method": t.rpc_method,
        "params_template": t.params_template, "file_operation": t.file_operation,
        "google_action": t.google_action, "google_args": opt_args(&t.google_args),
        "microsoft_action": t.microsoft_action, "microsoft_args": opt_args(&t.microsoft_args),
        "opencode_operation": t.opencode_operation, "agent_operation": t.agent_operation,
        "artifact_operation": t.artifact_operation, "run_as": t.run_as,
        "destination": t.destination, "input_schema": t.input_schema(),
        "agent_description": t.agent_description(),
    })
}

/// The example toolkits plus the `file` toolkit `file-tools.yaml` expects.
fn tier1_with_file_toolkit(tmp: &std::path::Path) -> Tier1 {
    let text = std::fs::read_to_string(examples_dir().join("toolkits.yaml")).unwrap();
    let mut raw = gatekeeper::yaml::load(&text).unwrap();
    raw["toolkits"]["file"] = json!({
        "executor": "file", "path_roots": ["/mnt/raid"],
        "protected_resources": ["/mnt/raid/gatekeeper"],
    });
    common::tier1_from(tmp, &raw).unwrap()
}

fn dump(tier1: &Tier1) -> Value {
    let ex = examples_dir();
    let tmp = tempfile::tempdir().unwrap();
    let t_file = tier1_with_file_toolkit(tmp.path());
    let mut catalogs = Map::new();
    for (f, tier) in [
        ("tools.yaml", tier1),
        ("agent-tools.yaml", tier1),
        ("file-tools.yaml", tier1),
        ("file-tools.yaml+file", &t_file),
    ] {
        let file = f.split('+').next().unwrap();
        let c = load_catalog(ex.join(file).to_str().unwrap(), tier, false).unwrap();
        let tools: Map<String, Value> = c.tools.iter().map(|(k, t)| (k.clone(), tool_value(t))).collect();
        let ids: Vec<String> =
            c.raw.iter().map(|e| e["id"].as_str().unwrap().to_string()).collect();
        let flat: Map<String, Value> = ids
            .iter()
            .map(|id| (id.clone(), c.flat_spec_of(id).map(Value::Object).unwrap_or(Value::Null)))
            .collect();
        let grantable: Map<String, Value> = ids.iter().map(|id| (id.clone(), json!(c.grantable_ids(id)))).collect();
        catalogs.insert(
            f.to_string(),
            json!({
                "tools": tools,
                "disabled_by_tier1": c.disabled_by_tier1,
                "rejected": c.rejected.iter().map(|(s, r)| json!([s, r])).collect::<Vec<_>>(),
                "raw_count": c.raw.len(),
                "flat_specs": flat,
                "grantable": grantable,
            }),
        );
    }
    json!({
        "toolkits": tier1.toolkits.iter().map(|(k, t)| (k.clone(), toolkit_value(t))).collect::<Map<_, _>>(),
        "destinations": tier1.destinations.iter().map(|(k, d)| (k.clone(), json!({
            "name": d.name, "docker_host": d.docker_host, "docker_tls": d.docker_tls,
            "base_url": d.base_url, "ws_url": d.ws_url, "credential": d.credential,
        }))).collect::<Map<_, _>>(),
        "rate_limits": tier1.rate_limits.iter().map(|(k, r)| (k.clone(), json!([r.count, r.window_seconds]))).collect::<Map<_, _>>(),
        "max_concurrent": tier1.max_concurrent,
        "audit_dir": tier1.audit_dir,
        "audit_max_bytes": tier1.audit_max_bytes,
        "audit_keep_files": tier1.audit_keep_files,
        "credential_references": tier1.credential_references(),
        "google_oauth_scopes": tier1.google_oauth_scopes(),
        "microsoft_oauth_scopes": tier1.microsoft_oauth_scopes(),
        "catalogs": catalogs,
    })
}

/// Reports the first differing path, which a plain `assert_eq!` on two
/// 130 KB documents would bury.
fn diff(path: &str, a: &Value, b: &Value) -> Option<String> {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for k in x.keys().chain(y.keys()) {
                let (va, vb) = (x.get(k).unwrap_or(&Value::Null), y.get(k).unwrap_or(&Value::Null));
                if let Some(d) = diff(&format!("{path}.{k}"), va, vb) {
                    return Some(d);
                }
            }
            None
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            x.iter().zip(y).enumerate().find_map(|(i, (p, q))| diff(&format!("{path}[{i}]"), p, q))
        }
        _ if a == b => None,
        _ => Some(format!("{path}: rust={a} python={b}")),
    }
}

#[test]
fn examples_load_exactly_as_in_python() {
    let tier1 = load_tier1(examples_dir().join("toolkits.yaml").to_str().unwrap()).unwrap();
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/examples_golden.json")).unwrap();
    let ours = dump(&tier1);
    if let Some(d) = diff("$", &ours, &golden) {
        panic!("Rust and Python disagree about config/examples: {d}");
    }
    // Key order of the published schemas matters to clients that diff
    // them; compare the JSON text too.
    for (f, cat) in golden["catalogs"].as_object().unwrap() {
        for (id, tool) in cat["tools"].as_object().unwrap() {
            assert_eq!(
                serde_json::to_string(&ours["catalogs"][f]["tools"][id]["input_schema"]).unwrap(),
                serde_json::to_string(&tool["input_schema"]).unwrap(),
                "{f} {id}"
            );
        }
    }
}

#[test]
fn examples_load_strictly() {
    let ex = examples_dir();
    let tier1 = load_tier1(ex.join("toolkits.yaml").to_str().unwrap()).unwrap();
    for f in ["tools.yaml", "agent-tools.yaml"] {
        let c = load_catalog(ex.join(f).to_str().unwrap(), &tier1, true).unwrap();
        assert!(!c.tools.is_empty(), "{f}");
    }
    let tmp = tempfile::tempdir().unwrap();
    let t_file = tier1_with_file_toolkit(tmp.path());
    let c = load_catalog(ex.join("file-tools.yaml").to_str().unwrap(), &t_file, true).unwrap();
    assert!(c.tools.contains_key("file.read"));
}
