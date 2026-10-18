//! `ToolkitProposalStore` and `Service::reload_config` (ports of
//! `tests/test_toolkit_proposals.py`, `test_toolkit_update.py` and
//! `test_reload_config.py`).

mod app_env;

use std::sync::Arc;

use app_env::*;
use gatekeeper::errors::ConfigError;
use gatekeeper::toolkit_proposals::{ToolkitProposal, UPDATE_WRITABLE_FIELDS};
use serde_json::{json, Map, Value};

fn toolkit_spec(e_sandbox: &std::path::Path) -> Map<String, Value> {
    obj(json!({
        "executor": "local", "binaries": [SH], "denied_args": [],
        "path_roots": [e_sandbox.to_str().unwrap()], "protected_resources": [],
        "max_timeout_seconds": 10, "max_output_bytes": 4096,
    }))
}

/// `_env`: one `local` toolkit "demo", no tools, one admin.
fn env() -> AppEnv {
    // The sandbox path is only known after build, so the toolkit is
    // rewritten and reloaded once the env exists.
    let e = builder().tools(vec![]).build();
    let doc = json!({"toolkits": {"demo": Value::Object(toolkit_spec(&e.sandbox))},
                     "audit": {"dir": e.tmp.join("logs").to_str().unwrap()}});
    write(std::path::Path::new(&e.toolkits_path), &gatekeeper::yaml::dump(&doc));
    assert!(e.service.reload_config(&e.toolkits_path, &e.tools_path, &e.identities_path).is_none());
    e
}

fn propose(e: &AppEnv, name: &str, spec: Value, kind: &str) -> Result<ToolkitProposal, ConfigError> {
    e.proposals.propose(name, obj(spec), "hermes", kind)
}

fn propose_create(e: &AppEnv, name: &str) -> ToolkitProposal {
    e.proposals.propose(name, toolkit_spec(&e.sandbox), "hermes", "create").unwrap()
}

fn toolkits_text(e: &AppEnv) -> String {
    e.read(&e.toolkits_path)
}

// -- Propose / list ------------------------------------------------------------

#[test]
fn propose_then_list() {
    let e = env();
    let item = propose_create(&e, "zfs");
    assert_eq!(item.status, "pending");
    assert_eq!(item.name, "zfs");
    let listed = e.proposals.list(None).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, item.id);
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().name, "zfs");
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "toolkit_propose").unwrap();
    assert_eq!(line["target"], "zfs");
}

#[test]
fn list_filters_by_status() {
    let e = env();
    let item = propose_create(&e, "zfs");
    e.proposals.reject(&item.id, "root", "not now").unwrap();
    assert_eq!(e.proposals.list(Some("rejected")).unwrap()[0].id, item.id);
    assert!(e.proposals.list(Some("pending")).unwrap().is_empty());
}

#[test]
fn reject_leaves_toolkits_yaml_unchanged() {
    let e = env();
    let before = toolkits_text(&e);
    let item = propose_create(&e, "zfs");
    let rejected = e.proposals.reject(&item.id, "root", "not needed").unwrap();
    assert_eq!(rejected.status, "rejected");
    assert_eq!(rejected.reason.as_deref(), Some("not needed"));
    assert_eq!(toolkits_text(&e), before);
}

#[test]
fn reject_already_decided_refused() {
    let e = env();
    let item = propose_create(&e, "zfs");
    e.proposals.reject(&item.id, "root", "").unwrap();
    let err = e.proposals.reject(&item.id, "root", "").unwrap_err();
    assert!(err.is_write_refused());
    assert_eq!(err.message, format!("Toolkit proposal '{}' is already 'rejected'.", item.id));
}

#[test]
fn deploy_rejects_name_collision_and_leaves_toolkits_yaml_untouched() {
    let e = env();
    let item = propose_create(&e, "late");
    let mut raw = e.load_yaml(&e.toolkits_path);
    raw["toolkits"]["late"] = Value::Object(toolkit_spec(&e.sandbox));
    write(std::path::Path::new(&e.toolkits_path), &gatekeeper::yaml::dump(&raw));
    let before = toolkits_text(&e);
    let old = e.service.tier1();
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert!(err.message.contains("already exists"));
    assert!(err.message.contains("Reject this proposal"));
    assert_eq!(toolkits_text(&e), before);
    assert!(Arc::ptr_eq(&old, &e.service.tier1()));
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().status, "pending");
}

#[test]
fn propose_refuses_an_existing_name_and_queues_nothing() {
    let e = env();
    let err = e.proposals.propose("demo", toolkit_spec(&e.sandbox), "hermes", "create").unwrap_err();
    assert!(err.message.contains("already exists"));
    assert!(err.message.contains("different name"));
    assert!(err.message.contains("admin.toolkit_update"));
    assert!(err.message.contains("reload"));
    assert!(err.message.starts_with("A toolkit named 'demo' already exists in toolkits.yaml"));
    assert!(e.proposals.list(None).unwrap().is_empty());
}

#[test]
fn propose_refuses_a_second_pending_create_for_one_name() {
    let e = env();
    let first = propose_create(&e, "zfs");
    let err = e.proposals.propose("zfs", toolkit_spec(&e.sandbox), "hermes", "create").unwrap_err();
    assert!(err.message.contains(&first.id));
    e.proposals.withdraw(&first.id, "hermes").unwrap();
    propose_create(&e, "zfs");
}

#[test]
fn propose_input_checks() {
    let e = env();
    assert_eq!(propose(&e, "", json!({}), "create").unwrap_err().message, "A toolkit proposal needs a non-empty 'name'.");
    assert_eq!(propose(&e, "x", json!({}), "rename").unwrap_err().message, "Unknown proposal kind 'rename'.");
    assert_eq!(
        propose(&e, "demo", json!({}), "update").unwrap_err().message,
        "An update proposal needs at least one changed field."
    );
}

#[test]
fn withdraw_by_proposer_closes_it_and_leaves_toolkits_yaml_alone() {
    let e = env();
    let before = toolkits_text(&e);
    let item = propose_create(&e, "zfs");
    let withdrawn = e.proposals.withdraw(&item.id, "hermes").unwrap();
    assert_eq!(withdrawn.status, "withdrawn");
    assert_eq!(withdrawn.decided_by.as_deref(), Some("hermes"));
    assert!(e.proposals.list(Some("pending")).unwrap().is_empty());
    assert_eq!(toolkits_text(&e), before);
    assert!(e.proposals.deploy(&item.id, "root").is_err());
    assert!(e
        .audit_lines()
        .iter()
        .any(|r| r["action"] == "toolkit_withdraw" && r["proposal_id"] == json!(item.id)));
}

#[test]
fn withdraw_refuses_someone_elses_proposal() {
    let e = env();
    let item = propose_create(&e, "zfs");
    let err = e.proposals.withdraw(&item.id, "other-agent").unwrap_err();
    assert!(err.message.contains("only the proposer"));
    assert_eq!(
        err.message,
        format!(
            "Toolkit proposal '{}' was filed by 'hermes'; only the proposer can withdraw it. A human can \
             reject it at /app/requests (Toolkit tab).",
            item.id
        )
    );
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().status, "pending");
}

#[test]
fn withdraw_refuses_a_decided_proposal() {
    let e = env();
    let item = propose_create(&e, "zfs");
    e.proposals.reject(&item.id, "root", "").unwrap();
    assert!(e.proposals.withdraw(&item.id, "hermes").is_err());
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().status, "rejected");
}

#[test]
fn deploy_rejects_tier1_invalid_proposal_and_leaves_state_untouched() {
    let e = env();
    let before = toolkits_text(&e);
    let old_t = e.service.tier1();
    let old_c = e.service.catalog();
    let item = propose(&e, "broken", json!({"binaries": [SH]}), "create").unwrap();
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert!(err.message.to_lowercase().contains("invalid"));
    assert!(err.message.starts_with("Proposed toolkit 'broken' is invalid: "));
    assert_eq!(toolkits_text(&e), before);
    assert!(Arc::ptr_eq(&old_t, &e.service.tier1()));
    assert!(Arc::ptr_eq(&old_c, &e.service.catalog()));
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().status, "pending");
    // No validation temp file left behind.
    let stray: Vec<_> = std::fs::read_dir(&e.tmp)
        .unwrap()
        .filter_map(|d| d.ok())
        .filter(|d| d.file_name().to_string_lossy().starts_with(".gk-"))
        .collect();
    assert!(stray.is_empty());
}

#[test]
fn deploy_writes_atomically_reloads_and_becomes_live_without_restart() {
    let e = env();
    assert!(!e.service.tier1().toolkits.contains_key("zfs"));
    let item = propose_create(&e, "zfs");
    let deployed = e.proposals.deploy(&item.id, "root").unwrap();
    assert_eq!(deployed.status, "deployed");
    assert_eq!(deployed.decided_by.as_deref(), Some("root"));
    let names: Vec<String> = e.service.tier1().toolkits.keys().cloned().collect();
    assert_eq!(names, ["demo", "zfs"]);
    let on_disk = e.load_yaml(&e.toolkits_path);
    assert!(on_disk["toolkits"].get("zfs").is_some() && on_disk["toolkits"].get("demo").is_some());
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().status, "deployed");
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "toolkit_deploy").unwrap();
    assert_eq!(line["before_toolkits"], json!(["demo"]));
    assert_eq!(line["after_toolkits"], json!(["demo", "zfs"]));
    assert_eq!(line["original_actor"], "hermes");
    assert!(line.get("before_fields").is_none());
}

#[test]
fn deploy_already_decided_and_unknown_refused() {
    let e = env();
    let item = propose_create(&e, "zfs");
    e.proposals.deploy(&item.id, "root").unwrap();
    assert!(e.proposals.deploy(&item.id, "root").unwrap_err().message.to_lowercase().contains("already"));
    assert_eq!(
        e.proposals.deploy("does-not-exist", "root").unwrap_err().message,
        "No toolkit proposal 'does-not-exist'."
    );
}

// -- Delete --------------------------------------------------------------------

fn write_tools(e: &AppEnv, entries: Value) {
    write(std::path::Path::new(&e.tools_path), &gatekeeper::yaml::dump(&json!({ "tools": entries })));
}

#[test]
fn delete_propose_rejects_nonempty_spec() {
    let e = env();
    let err = propose(&e, "demo", json!({"executor": "local"}), "delete").unwrap_err();
    assert!(err.message.contains("no 'spec'"));
}

#[test]
fn deploy_delete_removes_toolkit_and_reloads() {
    let e = env();
    let item = propose(&e, "demo", json!({}), "delete").unwrap();
    assert_eq!(e.proposals.deploy(&item.id, "root").unwrap().status, "deployed");
    assert!(!e.service.tier1().toolkits.contains_key("demo"));
    assert!(e.load_yaml(&e.toolkits_path)["toolkits"].get("demo").is_none());
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "toolkit_delete_deploy").unwrap();
    assert!(line["before_fields"]["demo"].is_object());
    assert_eq!(line["after_fields"], json!({}));
}

#[test]
fn deploy_delete_rejects_missing_toolkit_and_leaves_state_untouched() {
    let e = env();
    let before = toolkits_text(&e);
    let old = e.service.tier1();
    let item = propose(&e, "ghost", json!({}), "delete").unwrap();
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert_eq!(
        err.message,
        "No toolkit named 'ghost' exists in toolkits.yaml -- it may already have been removed. Reject this proposal."
    );
    assert_eq!(toolkits_text(&e), before);
    assert!(Arc::ptr_eq(&old, &e.service.tier1()));
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().status, "pending");
}

#[test]
fn deploy_delete_rejects_when_tool_still_references_toolkit() {
    let e = env();
    let before = toolkits_text(&e);
    write_tools(&e, json!([{"id": "demo.run", "toolkit": "demo"}]));
    let item = propose(&e, "demo", json!({}), "delete").unwrap();
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert_eq!(
        err.message,
        "Toolkit 'demo' is still referenced by 1 tool(s): ['demo.run']. Delete or reassign those tools first."
    );
    assert_eq!(toolkits_text(&e), before);
    assert!(e.service.tier1().toolkits.contains_key("demo"));
}

#[test]
fn deploy_delete_ignores_soft_deleted_referencing_tool() {
    let e = env();
    write_tools(
        &e,
        json!([{"id": "demo.run", "toolkit": "demo", "enabled": true, "deleted": true,
                "current_version": 1, "versions": [{"version": 1, "spec": {"toolkit": "demo"}}]}]),
    );
    let item = propose(&e, "demo", json!({}), "delete").unwrap();
    assert_eq!(e.proposals.deploy(&item.id, "root").unwrap().status, "deployed");
    assert!(!e.service.tier1().toolkits.contains_key("demo"));
}

// -- run_as via an update proposal ------------------------------------------------

fn env_with_file_toolkit(extra: Value) -> AppEnv {
    let e = env();
    let mut raw = e.load_yaml(&e.toolkits_path);
    let mut files = obj(json!({
        "executor": "file", "binaries": [], "path_roots": [e.sandbox.to_str().unwrap()],
        "protected_resources": [], "max_timeout_seconds": 10, "max_output_bytes": 4096,
    }));
    files.extend(obj(extra));
    raw["toolkits"]["files"] = Value::Object(files);
    write(std::path::Path::new(&e.toolkits_path), &gatekeeper::yaml::dump(&raw));
    assert!(e.service.reload_config(&e.toolkits_path, &e.tools_path, &e.identities_path).is_none());
    e
}

#[test]
fn propose_run_as_update_creates_a_proposal() {
    let e = env_with_file_toolkit(json!({}));
    let item = propose(&e, "files", json!({"run_as": "3001:3001"}), "update").unwrap();
    assert_eq!(item.kind, "update");
    assert_eq!(Value::Object(item.spec), json!({"run_as": "3001:3001"}));
    let item = propose(&e, "files", json!({"run_as": "root"}), "update").unwrap();
    assert_eq!(Value::Object(e.proposals.get(&item.id).unwrap().unwrap().spec), json!({"run_as": "root"}));
}

#[test]
fn propose_rejects_a_malformed_run_as_immediately() {
    let e = env_with_file_toolkit(json!({}));
    for value in ["3001", "", "ro ot", "../root", "ro/ot", "3001:"] {
        let err = propose(&e, "files", json!({"run_as": value}), "update").unwrap_err();
        assert!(err.message.contains("run_as"), "{value}: {}", err.message);
        assert!(err.message.starts_with("Cannot propose this 'run_as': "));
    }
    assert!(e.proposals.list(None).unwrap().is_empty());
}

#[test]
fn deploy_run_as_update_writes_it_and_reloads() {
    let e = env_with_file_toolkit(json!({}));
    assert_eq!(e.service.tier1().toolkits["files"].run_as, None);
    let item = propose(&e, "files", json!({"run_as": "3001:3001"}), "update").unwrap();
    assert_eq!(e.proposals.deploy(&item.id, "root").unwrap().status, "deployed");
    let raw = e.load_yaml(&e.toolkits_path);
    assert_eq!(raw["toolkits"]["files"]["run_as"], "3001:3001");
    assert_eq!(raw["toolkits"]["files"]["path_roots"], json!([e.sandbox.to_str().unwrap()]));
    assert_eq!(e.service.tier1().toolkits["files"].run_as.as_deref(), Some("3001:3001"));
    assert_eq!(e.service.tier1().toolkits["demo"].run_as, None);
    assert!(raw["toolkits"]["demo"].get("run_as").is_none());
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "toolkit_update_deploy").unwrap();
    assert_eq!(line["before_fields"], json!({"run_as": null}));
    assert_eq!(line["after_fields"], json!({"run_as": "3001:3001"}));
}

#[test]
fn deploy_refuses_run_as_on_a_non_file_toolkit() {
    let e = env_with_file_toolkit(json!({}));
    let before = toolkits_text(&e);
    let item = propose(&e, "demo", json!({"run_as": "root"}), "update").unwrap();
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert!(err.message.contains("run_as"));
    assert_eq!(toolkits_text(&e), before);
}

#[test]
fn run_as_and_executor_can_change_in_one_proposal() {
    let e = env_with_file_toolkit(json!({}));
    let item =
        propose(&e, "demo", json!({"executor": "file", "binaries": [], "run_as": "3001:3001"}), "update").unwrap();
    e.proposals.deploy(&item.id, "root").unwrap();
    let t = e.service.tier1();
    assert_eq!(t.toolkits["demo"].executor, "file");
    assert_eq!(t.toolkits["demo"].run_as.as_deref(), Some("3001:3001"));
}

#[test]
fn protected_resources_stays_redeploy_only() {
    let e = env_with_file_toolkit(json!({}));
    let err = propose(&e, "files", json!({"protected_resources": []}), "update").unwrap_err();
    assert!(err.message.contains("protected_resources"));
    let err = propose(&e, "files", json!({"protected_resources": [], "limits": 1}), "update").unwrap_err();
    assert_eq!(
        err.message,
        "Cannot propose changing ['limits', 'protected_resources'] -- only ['allowed_cidrs', 'allowed_hosts', \
         'allowed_methods', 'allowed_path_prefixes', 'binaries', 'denied_args', 'executor', 'max_output_bytes', \
         'max_timeout_seconds', 'path_roots', 'run_as'] are writable via an update proposal. protected_resources \
         has no proposal path -- edit toolkits.yaml and reload (SIGHUP or restart)."
    );
}

#[test]
fn update_writable_fields_is_exactly_these() {
    // allowed_hosts/allowed_cidrs joined in 1.10.0 (network targets by
    // proposal, allowed_hosts tests); path_roots and friends did not.
    // 1.11.0: an http toolkit's methods/path prefixes and the two limits.
    // 1.22.0: path_roots.
    let mut f = UPDATE_WRITABLE_FIELDS.to_vec();
    f.sort();
    assert_eq!(
        f,
        [
            "allowed_cidrs", "allowed_hosts", "allowed_methods", "allowed_path_prefixes", "binaries", "denied_args",
            "executor", "max_output_bytes", "max_timeout_seconds", "path_roots", "run_as",
        ]
    );
}

#[test]
fn deploy_run_as_null_clears_it() {
    let e = env_with_file_toolkit(json!({"run_as": "3001:3001"}));
    assert_eq!(e.service.tier1().toolkits["files"].run_as.as_deref(), Some("3001:3001"));
    let item = propose(&e, "files", json!({"run_as": null}), "update").unwrap();
    e.proposals.deploy(&item.id, "root").unwrap();
    assert_eq!(e.service.tier1().toolkits["files"].run_as, None);
}

#[test]
fn deploy_update_rejects_unknown_toolkit_and_rechecks_fields() {
    let e = env();
    let before = toolkits_text(&e);
    let item = propose(&e, "does-not-exist", json!({"executor": "file"}), "update").unwrap();
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert!(err.message.contains("No toolkit named"));
    assert_eq!(toolkits_text(&e), before);
    // A hand-edited proposal file is re-checked at deploy.
    let item = propose(&e, "demo", json!({"executor": "local"}), "update").unwrap();
    let path = e.proposals.path.clone();
    let mut raw = e.load_yaml(&path);
    for p in raw["proposals"].as_array_mut().unwrap() {
        if p["id"] == json!(item.id) {
            p["spec"]["protected_resources"] = json!([]);
        }
    }
    write(std::path::Path::new(&path), &gatekeeper::yaml::dump(&raw));
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert_eq!(
        err.message,
        "Cannot change ['protected_resources'] at runtime -- only ['allowed_cidrs', 'allowed_hosts', \
         'allowed_methods', 'allowed_path_prefixes', 'binaries', 'denied_args', 'executor', 'max_output_bytes', \
         'max_timeout_seconds', 'path_roots', 'run_as'] are writable via an update proposal."
    );
    // A path_roots edited into the file is held to the same rules as one
    // proposed: "/" never deploys.
    let item = propose(&e, "demo", json!({"executor": "local"}), "update").unwrap();
    let mut raw = e.load_yaml(&path);
    for p in raw["proposals"].as_array_mut().unwrap() {
        if p["id"] == json!(item.id) {
            p["spec"]["path_roots"] = json!(["/"]);
        }
    }
    write(std::path::Path::new(&path), &gatekeeper::yaml::dump(&raw));
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert!(err.message.contains("is the filesystem root"), "{}", err.message);
    assert_eq!(toolkits_text(&e), before);
}

// -- kind="bind" ---------------------------------------------------------------

#[test]
fn bind_propose_carries_only_the_credential_name() {
    let e = env();
    let before = toolkits_text(&e);
    let item = propose(&e, "demo", json!({"credential": "sonarr-api-key"}), "bind").unwrap();
    assert_eq!(item.kind, "bind");
    assert_eq!(Value::Object(item.spec), json!({"credential": "sonarr-api-key"}));
    assert_eq!(toolkits_text(&e), before);
    assert_eq!(e.service.tier1().toolkits["demo"].credential, None);
}

#[test]
fn bind_propose_refuses_any_second_field() {
    let e = env();
    for spec in [
        json!({"credential": "sonarr-api-key", "value": "s3cret"}),
        json!({"credential": "sonarr-api-key", "path_roots": ["/"]}),
        json!({"credential": "sonarr-api-key", "destination": "sonarr-lan"}),
        json!({"credential": "sonarr-api-key", "executor": "http"}),
    ] {
        let err = propose(&e, "demo", spec, "bind").unwrap_err();
        assert!(err.message.contains("exactly"), "{}", err.message);
    }
    let err = propose(&e, "demo", json!({"credential": "k", "value": "s"}), "bind").unwrap_err();
    assert_eq!(err.message, "A bind proposal carries exactly {'credential': <name>} and nothing else -- got ['value'] as well.");
    let err = propose(&e, "demo", json!({}), "bind").unwrap_err();
    assert_eq!(err.message, "A bind proposal carries exactly {'credential': <name>} and nothing else.");
    let err = propose(&e, "demo", json!({"credential": ""}), "bind").unwrap_err();
    assert_eq!(err.message, "A bind proposal's 'credential' must be a non-empty credential name.");
    assert!(e.proposals.list(None).unwrap().is_empty());
}

#[test]
fn deploy_bind_writes_the_binding_and_reloads() {
    let e = env();
    let before = e.load_yaml(&e.toolkits_path)["toolkits"]["demo"].clone();
    let item = propose(&e, "demo", json!({"credential": "sonarr-api-key"}), "bind").unwrap();
    assert_eq!(e.proposals.deploy(&item.id, "root").unwrap().status, "deployed");
    let t = e.service.tier1();
    assert_eq!(t.toolkits["demo"].credential.as_deref(), Some("sonarr-api-key"));
    let refs: Vec<(String, Vec<String>)> = t.credential_references().into_iter().collect();
    assert_eq!(refs, [("sonarr-api-key".to_string(), vec!["demo".to_string()])]);
    let after = e.load_yaml(&e.toolkits_path)["toolkits"]["demo"].clone();
    let mut expected = before.clone();
    expected["credential"] = json!("sonarr-api-key");
    assert_eq!(after, expected);
    let actions: Vec<Value> = e.audit_lines().into_iter().map(|l| l["action"].clone()).collect();
    assert!(actions.contains(&json!("credential_bind_propose")));
    assert!(actions.contains(&json!("credential_bind_deploy")));
}

#[test]
fn deploy_bind_can_redirect_an_existing_binding() {
    let e = env();
    let first = propose(&e, "demo", json!({"credential": "old-key"}), "bind").unwrap();
    e.proposals.deploy(&first.id, "root").unwrap();
    let second = propose(&e, "demo", json!({"credential": "new-key"}), "bind").unwrap();
    e.proposals.deploy(&second.id, "root").unwrap();
    assert_eq!(e.service.tier1().toolkits["demo"].credential.as_deref(), Some("new-key"));
    let line = e.audit_lines().into_iter().rev().find(|l| l["action"] == "credential_bind_deploy").unwrap();
    assert_eq!(line["before_fields"], json!({"credential": "old-key"}));
}

#[test]
fn deploy_bind_rejects_missing_toolkit_and_leaves_state_untouched() {
    let e = env();
    let before = toolkits_text(&e);
    let item = propose(&e, "ghost", json!({"credential": "k"}), "bind").unwrap();
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert!(err.message.contains("ghost"));
    assert_eq!(toolkits_text(&e), before);
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().status, "pending");
}

#[test]
fn deploy_bind_rechecks_the_spec_it_wrote_earlier() {
    let e = env();
    let item = propose(&e, "demo", json!({"credential": "sonarr-api-key"}), "bind").unwrap();
    let path = e.proposals.path.clone();
    let mut raw = e.load_yaml(&path);
    raw["proposals"][0]["spec"]["path_roots"] = json!(["/"]);
    write(std::path::Path::new(&path), &gatekeeper::yaml::dump(&raw));
    let before = toolkits_text(&e);
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert_eq!(err.message, "A bind proposal may only set 'credential' -- this one also carries ['path_roots'].");
    assert_eq!(toolkits_text(&e), before);
}

#[test]
fn deploy_bind_to_a_credential_with_no_slot_still_deploys() {
    let e = env();
    let item = propose(&e, "demo", json!({"credential": "not-in-any-store"}), "bind").unwrap();
    e.proposals.deploy(&item.id, "root").unwrap();
    assert_eq!(e.service.tier1().toolkits["demo"].credential.as_deref(), Some("not-in-any-store"));
}

#[test]
fn bind_reject_leaves_toolkits_yaml_unchanged() {
    let e = env();
    let before = toolkits_text(&e);
    let item = propose(&e, "demo", json!({"credential": "k"}), "bind").unwrap();
    assert_eq!(e.proposals.reject(&item.id, "root", "wrong").unwrap().status, "rejected");
    assert_eq!(toolkits_text(&e), before);
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "toolkit_reject").unwrap();
    assert_eq!(line["original_actor"], "hermes");
    assert_eq!(line["reason"], "wrong");
}

// -- admin.toolkit_update (test_toolkit_update.py) ----------------------------------

#[test]
fn toolkit_update_only_proposes_never_applies() {
    let e = env();
    let admin = e.admin();
    let result = admin
        .call("hermes", "toolkit_update", &args(json!({"name": "demo", "updates": {"executor": "file", "binaries": [], "denied_args": []}})))
        .unwrap();
    assert_eq!(result["applied"], false);
    assert_eq!(result["pending"], true);
    assert!(result["proposal_id"].is_string());
    assert_eq!(e.service.tier1().toolkits["demo"].executor, "local");
    let items = e.proposals.list(None).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!((items[0].kind.as_str(), items[0].name.as_str(), items[0].status.as_str()), ("update", "demo", "pending"));
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "toolkit_update_propose").unwrap();
    assert_eq!(line["target"], "demo");
}

#[test]
fn toolkit_update_rejects_security_critical_fields_and_empty_updates() {
    let e = env();
    let admin = e.admin();
    let err = admin
        .call("hermes", "toolkit_update", &args(json!({"name": "demo", "updates": {"protected_resources": []}})))
        .unwrap_err();
    assert!(err.message.contains("protected_resources"));
    let err = admin.call("hermes", "toolkit_update", &args(json!({"name": "demo", "updates": {"path_roots": ["/"]}}))).unwrap_err();
    assert!(err.message.contains("path_roots"));
    let result = admin.call("hermes", "toolkit_update", &args(json!({"name": "demo", "updates": {}}))).unwrap();
    assert_eq!(result, json!({"applied": false, "error": "No updates provided."}));
    assert!(e.proposals.list(None).unwrap().is_empty());
}

#[test]
fn deploy_update_merges_only_the_proposed_fields() {
    let e = env();
    let item = propose(&e, "demo", json!({"executor": "file", "binaries": [], "denied_args": []}), "update").unwrap();
    assert_eq!(e.proposals.deploy(&item.id, "root").unwrap().status, "deployed");
    let t = e.service.tier1();
    assert_eq!(t.toolkits["demo"].executor, "file");
    assert!(t.toolkits["demo"].binaries.is_empty());
    assert_eq!(t.toolkits["demo"].path_roots, [e.sandbox.to_str().unwrap()]);
    let on_disk = e.load_yaml(&e.toolkits_path);
    assert_eq!(on_disk["toolkits"]["demo"]["executor"], "file");
}

// -- reload_config (test_reload_config.py) -----------------------------------------

#[test]
fn reload_success_swaps_tier1_and_catalog() {
    let e = env();
    let old_limiter = e.service.limiter();
    let mut raw = e.load_yaml(&e.toolkits_path);
    raw["toolkits"]["extra"] = Value::Object(toolkit_spec(&e.sandbox));
    write(std::path::Path::new(&e.toolkits_path), &gatekeeper::yaml::dump(&raw));
    assert_eq!(e.service.reload_config(&e.toolkits_path, &e.tools_path, &e.identities_path), None);
    let names: Vec<String> = e.service.tier1().toolkits.keys().cloned().collect();
    assert_eq!(names, ["demo", "extra"]);
    assert!(!Arc::ptr_eq(&old_limiter, &e.service.limiter()));
}

fn assert_reload_fails(e: &AppEnv, file: &str, text: Option<&str>, label: &str) {
    let old_t = e.service.tier1();
    let old_c = e.service.catalog();
    let old_l = e.service.limiter();
    match text {
        Some(text) => {
            write(std::path::Path::new(file), text);
        }
        None => std::fs::remove_file(file).unwrap(),
    }
    let error = e.service.reload_config(&e.toolkits_path, &e.tools_path, &e.identities_path).unwrap();
    assert!(error.starts_with(&format!("{label}: ")), "{error}");
    assert!(Arc::ptr_eq(&old_t, &e.service.tier1()));
    assert!(Arc::ptr_eq(&old_c, &e.service.catalog()));
    assert!(Arc::ptr_eq(&old_l, &e.service.limiter()));
}

#[test]
fn reload_invalid_files_leave_old_state_untouched() {
    let e = env();
    assert_reload_fails(&e, &e.toolkits_path.clone(), Some("toolkits: [not, a, mapping]\n"), "toolkits.yaml");
    let e = env();
    assert_reload_fails(&e, &e.tools_path.clone(), Some("tools: not-a-list\n"), "tools.yaml");
    let e = env();
    assert_reload_fails(&e, &e.identities_path.clone(), Some("identities: not-a-list\n"), "identities.yaml");
    let e = env();
    assert_reload_fails(&e, &e.toolkits_path.clone(), None, "toolkits.yaml");
}

#[test]
fn reload_does_not_swap_identities() {
    // PORT NOTE parity: identities.yaml is loaded (and must parse) but the
    // live store is not replaced by a reload.
    let e = env();
    let before = e.identities.read().clone();
    write(
        std::path::Path::new(&e.identities_path),
        &gatekeeper::yaml::dump(&json!({"identities": [
            {"id": "other", "role": "agent", "token_hash": gatekeeper::identity::hash_token("t"), "tools": [], "scopes": []}
        ]})),
    );
    assert_eq!(e.service.reload_config(&e.toolkits_path, &e.tools_path, &e.identities_path), None);
    assert_eq!(*e.identities.read(), before);
}

// -- path_roots via an update proposal (1.22.0) -------------------------------------

/// `env()` plus an http toolkit "github" with one root, `<sandbox>/scratch`,
/// and a from_file-style tool whose path must resolve under it.
fn env_with_github(with_tool: bool) -> (AppEnv, String) {
    let e = env();
    let scratch = e.sandbox.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let scratch = scratch.to_str().unwrap().to_string();
    let mut raw = e.load_yaml(&e.toolkits_path);
    raw["toolkits"]["github"] = json!({
        "executor": "http", "base_url": "http://127.0.0.1:9", "allowed_methods": ["POST"],
        "allowed_path_prefixes": ["/repos/"], "allowed_cidrs": ["127.0.0.1/32"], "path_roots": [scratch],
    });
    write(std::path::Path::new(&e.toolkits_path), &gatekeeper::yaml::dump(&raw));
    if with_tool {
        write_tools(&e, github_tool(&scratch));
    }
    assert!(e.service.reload_config(&e.toolkits_path, &e.tools_path, &e.identities_path).is_none());
    (e, scratch)
}

fn github_tool(scratch: &str) -> Value {
    json!([{"id": "github.blob_from_file", "toolkit": "github", "enabled": true, "category": "write",
            "title": "t", "description": "d", "method": "POST", "path": "/repos/x/git/blobs",
            "max_file_bytes": 1024,
            "parameters": {
                "file": {"type": "string", "pattern": "^[a-z]+$", "required": true},
                "path": {"type": "path", "derived": format!("{scratch}/{{file}}"), "must_resolve_under": scratch},
            },
            "body": {"content": {"from_file": "path", "encoding": "base64"}}}])
}

fn listed_roots(admin: &gatekeeper::admin_service::AdminService, name: &str) -> Value {
    let listed = admin.call("hermes", "toolkit_list", &args(json!({}))).unwrap();
    listed["toolkits"].as_array().unwrap().iter().find(|t| t["name"] == name).unwrap()["path_roots"].clone()
}

#[test]
fn path_roots_update_is_pending_then_live_after_approval_without_a_file_edit() {
    let (e, scratch) = env_with_github(true);
    assert!(e.service.catalog().tools.contains_key("github.blob_from_file"));
    let uploads = e.sandbox.join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();
    let uploads = uploads.to_str().unwrap().to_string();
    let admin = e.admin();
    let before = toolkits_text(&e);

    let result = admin
        .call("hermes", "toolkit_update", &args(json!({"name": "github", "updates": {"path_roots": [scratch, uploads]}})))
        .unwrap();
    assert_eq!((result["applied"].clone(), result["pending"].clone()), (json!(false), json!(true)));
    // Pending changes nothing: not the file, not the running Tier 1.
    assert_eq!(toolkits_text(&e), before);
    assert_eq!(listed_roots(&admin, "github"), json!([scratch]));

    // The human's approval (what /api/v1/requests/toolkits/<id>/deploy
    // calls) writes and reloads -- no hand edit, no SIGHUP.
    let id = result["proposal_id"].as_str().unwrap();
    assert_eq!(e.proposals.deploy(id, "root").unwrap().status, "deployed");
    assert_eq!(listed_roots(&admin, "github"), json!([scratch, uploads]));
    assert_eq!(e.load_yaml(&e.toolkits_path)["toolkits"]["github"]["path_roots"], json!([scratch, uploads]));
    assert!(e.service.catalog().tools.contains_key("github.blob_from_file"));
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "toolkit_update_deploy").unwrap();
    assert_eq!(line["before_fields"], json!({"path_roots": [scratch]}));
    assert_eq!(line["after_fields"], json!({"path_roots": [scratch, uploads]}));
}

#[test]
fn path_roots_entries_must_be_absolute_existing_directories_other_than_root() {
    let (e, scratch) = env_with_github(false);
    let file = e.sandbox.join("a-file");
    write(&file, "x");
    let missing = e.sandbox.join("nope");
    for (roots, why) in [
        (json!(["relative/dir"]), "'relative/dir' is not an absolute path."),
        (json!([format!("{scratch}/../..")]), "contains '..'."),
        (json!(["/"]), "'/' is the filesystem root, which would put every path in reach."),
        (json!(["//./"]), "is the filesystem root"),
        (json!([missing.to_str().unwrap()]), "does not exist in this container."),
        (json!([file.to_str().unwrap()]), "is not a directory in this container."),
        (json!([1]), "entry 1 is not a string."),
        (json!("/srv"), "it must be a list of absolute directory paths."),
    ] {
        let err = propose(&e, "github", json!({"path_roots": roots}), "update").unwrap_err();
        assert!(err.message.contains(why), "{roots}: {}", err.message);
        assert!(err.message.starts_with("Cannot propose path_roots"), "{}", err.message);
    }
    assert!(e.proposals.list(None).unwrap().is_empty());
}

#[test]
fn path_roots_that_strand_a_tool_are_refused_naming_it() {
    let (e, scratch) = env_with_github(true);
    let other = e.sandbox.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let other = other.to_str().unwrap().to_string();
    let err = propose(&e, "github", json!({"path_roots": [other]}), "update").unwrap_err();
    assert_eq!(
        err.message,
        format!(
            "Cannot change path_roots of toolkit 'github' to ['{other}']: 1 tool(s) would lie outside them: \
             'github.blob_from_file' (must_resolve_under '{scratch}'). Change or delete those tools first, or keep \
             their roots in the list."
        )
    );
    // Narrowing to an empty list strands it too.
    assert!(propose(&e, "github", json!({"path_roots": []}), "update").unwrap_err().message.contains("blob_from_file"));
    // A parent of its root keeps it.
    let parent = e.sandbox.to_str().unwrap().to_string();
    assert!(propose(&e, "github", json!({"path_roots": [parent]}), "update").is_ok());
}

#[test]
fn deploy_rechecks_path_roots_against_the_disk_and_tools_as_they_are_now() {
    let (e, scratch) = env_with_github(false);
    let extra = e.sandbox.join("extra");
    std::fs::create_dir_all(&extra).unwrap();
    let extra_s = extra.to_str().unwrap().to_string();
    // The directory vanishes while the proposal waits.
    let item = propose(&e, "github", json!({"path_roots": [scratch.clone(), extra_s.clone()]}), "update").unwrap();
    std::fs::remove_dir(&extra).unwrap();
    let before = toolkits_text(&e);
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert!(err.message.contains("does not exist in this container."), "{}", err.message);
    assert_eq!(toolkits_text(&e), before);
    assert_eq!(e.proposals.get(&item.id).unwrap().unwrap().status, "pending");

    // A tool under the old root arrives while a narrowing waits.
    std::fs::create_dir_all(&extra).unwrap();
    let item = propose(&e, "github", json!({"path_roots": [extra_s]}), "update").unwrap();
    write_tools(&e, github_tool(&scratch));
    let err = e.proposals.deploy(&item.id, "root").unwrap_err();
    assert!(err.message.contains("'github.blob_from_file'"), "{}", err.message);
    assert_eq!(toolkits_text(&e), before);
}

#[test]
fn path_roots_cannot_be_proposed_for_an_ssh_toolkit() {
    let e = env();
    let mut raw = e.load_yaml(&e.toolkits_path);
    raw["toolkits"]["remote"] = json!({"executor": "ssh"});
    write(std::path::Path::new(&e.toolkits_path), &gatekeeper::yaml::dump(&raw));
    let sandbox = e.sandbox.to_str().unwrap().to_string();
    let err = propose(&e, "remote", json!({"path_roots": [sandbox]}), "update").unwrap_err();
    assert!(err.message.contains("reads them on the remote host"), "{}", err.message);
}
