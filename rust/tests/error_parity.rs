//! Error-message parity with Python, table-driven.
//!
//! `fixtures/error_cases_golden.json` holds ~150 Tier 1 documents and tool
//! specs -- one per validation branch of the retired Python `tier1.py`/
//! `catalog.py` -- with the exact `ConfigError` text Python produced for
//! each, or a summary of what loaded. It was generated from the Python
//! implementation and is frozen since that was removed (1.17.0): a change
//! to a message is a change to this file, made by hand. Operators grep
//! logs for these messages, so they must match character for character.
//!
//! Where Python crashed with an uncaught `ValueError` (`python_crash` in the
//! fixture), the Rust port reports a `ConfigError` with the same text.

mod common;

use gatekeeper::catalog::parse_tool_spec;
use gatekeeper::tier1::{load_tier1, Tier1};
use serde_json::{json, Value};

fn golden() -> Value {
    serde_json::from_str(include_str!("fixtures/error_cases_golden.json")).unwrap()
}

fn load(doc: &Value) -> (Result<Tier1, String>, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("toolkits.yaml");
    std::fs::write(&path, gatekeeper::yaml::dump(doc)).unwrap();
    let p = path.to_str().unwrap().to_string();
    (load_tier1(&p).map_err(|e| e.message.replace(&p, "<path>")), p)
}

fn summary(t: &Tier1) -> Value {
    json!({
        "toolkits": t.toolkits.iter().map(|(n, k)| (n.clone(), json!({
            "executor": k.executor, "run_as": k.run_as, "ssh_port": k.ssh_port,
            "max_timeout_seconds": k.max_timeout_seconds, "max_output_bytes": k.max_output_bytes,
            "docker_host": k.docker_host, "destinations": k.destinations,
            "required_scopes": k.required_scopes, "google_container": k.google_container,
            "allowed_hosts": k.allowed_hosts, "allowed_cidrs": k.allowed_cidrs,
        }))).collect::<serde_json::Map<_, _>>(),
        "rate_limits": t.rate_limits.iter().map(|(k, r)| (k.clone(), json!([r.count, r.window_seconds]))).collect::<serde_json::Map<_, _>>(),
        "max_concurrent": t.max_concurrent,
        "audit": [t.audit_dir, t.audit_max_bytes, t.audit_keep_files],
        "credential_references": t.credential_references(),
    })
}

fn check_tier1_cases(key: &str) -> usize {
    let g = golden();
    let mut failures = Vec::new();
    let cases = g[key].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let (result, _) = load(&case["doc"]);
        match (&result, &case["error"]) {
            (Err(ours), Value::String(theirs)) if ours == theirs => {}
            (Ok(t), Value::Null) => {
                if summary(t) != case["summary"] {
                    failures.push(format!("{name}: summary rust={} python={}", summary(t), case["summary"]));
                }
            }
            (r, theirs) => failures.push(format!("{name}:\n  rust:   {:?}\n  python: {theirs}", r.as_ref().map(|_| "loaded"))),
        }
    }
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
    cases.len()
}

#[test]
fn toolkit_errors_match_python() {
    assert!(check_tier1_cases("toolkit_cases") > 70);
}

#[test]
fn top_level_errors_match_python() {
    assert!(check_tier1_cases("top_cases") > 10);
}

#[test]
fn tool_errors_match_python() {
    let g = golden();
    // The Tier 1 the tool cases were parsed against: the first toolkit
    // case's document minus its mutation is BASE; rebuild it from the
    // case that changes nothing observable ("http_follow_false").
    let base = g["toolkit_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "http_follow_false")
        .unwrap()["doc"]
        .clone();
    let mut base = base;
    base["toolkits"]["web"].as_object_mut().unwrap().remove("follow_redirects");
    let (tier1, _) = load(&base);
    let tier1 = tier1.unwrap();

    let mut failures = Vec::new();
    let cases = g["tool_cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        match (parse_tool_spec(&case["spec"], &tier1), &case["error"]) {
            (Err(ours), Value::String(theirs)) => {
                if &ours.message != theirs {
                    failures.push(format!("{name}:\n  rust:   {}\n  python: {theirs}", ours.message));
                } else if case.get("tier1_violation").and_then(Value::as_bool).is_some_and(|v| v != ours.is_tier1_violation()) {
                    failures.push(format!("{name}: Tier1Violation kind differs"));
                }
            }
            (Ok(t), Value::Null) => {
                let ours = json!({
                    "version": t.version, "idempotent": t.idempotent, "required_scopes": t.required_scopes,
                    "input_schema": t.input_schema(), "body_template": t.body_template, "run_as": t.run_as,
                });
                if ours != case["summary"] {
                    failures.push(format!("{name}: summary rust={ours} python={}", case["summary"]));
                }
            }
            (Ok(_), theirs) => failures.push(format!("{name}: rust loaded, python: {theirs}")),
            (Err(e), _) => failures.push(format!("{name}: rust error {}, python loaded", e.message)),
        }
    }
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
    assert!(cases.len() > 60);
}
