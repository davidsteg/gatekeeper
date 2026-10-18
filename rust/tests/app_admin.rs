//! `AdminService`, `apply_pending` and `sweep_vanished_pendings` (the
//! AdminService-level parts of `tests/test_admin_mcp.py`, plus
//! `test_pending.py`'s apply/sweep and `test_cred_update.py`'s admin parts).

mod app_env;

use app_env::*;
use gatekeeper::admin_service::{apply_pending, sweep_vanished_pendings, AdminService, EXPOSED};
use gatekeeper::catalog::load_catalog;
use gatekeeper::errors::{ConfigError, ConfigErrorKind};
use gatekeeper::identity::{generate_token, hash_token};
use gatekeeper::pending::{STALE_CHANGED_REASON, STALE_TAKEN_REASON, STALE_VANISHED_REASON};
use serde_json::{json, Map, Value};

fn ids() -> Vec<Value> {
    vec![
        json!({"id": "hermes", "role": "admin", "token_hash": hash_token(&generate_token()), "tools": [], "scopes": []}),
        json!({"id": "root", "role": "admin", "token_hash": hash_token(&generate_token()),
               "password_hash": hash_token(ROOT_PASSWORD), "tools": [], "scopes": []}),
        json!({"id": "bot", "role": "agent", "token_hash": hash_token(&generate_token()),
               "tools": ["demo.show"], "scopes": ["stack:*"]}),
        json!({"id": "eye", "role": "viewer", "token_hash": hash_token(&generate_token()),
               "password_hash": hash_token(EYE_PASSWORD), "tools": [], "scopes": []}),
    ]
}

fn env() -> AppEnv {
    builder().identities(ids()).build()
}

fn env_creds() -> AppEnv {
    builder().identities(ids()).credentials().build()
}

fn call(admin: &AdminService, name: &str, a: Value) -> Result<Value, ConfigError> {
    admin.call("hermes", name, &args(a))
}

fn is_admin_err(e: &ConfigError) -> bool {
    e.kind == ConfigErrorKind::AdminAction
}

fn sh_tool(id: &str, category: &str, enabled: bool) -> Value {
    json!({
        "id": id, "toolkit": "demo", "binary": SH, "title": "n", "description": "d",
        "category": category, "idempotent": category == "read", "enabled": enabled,
        "argv": ["-c", "echo done"], "parameters": {}, "required_scopes": [],
        "timeout_seconds": 5, "max_output_bytes": 4096,
    })
}

fn approve(e: &AppEnv, id: &str) -> Result<Value, ConfigError> {
    apply_pending(&e.store, &e.pending, id, "root", e.credentials.as_deref())
}

fn create_cred(e: &AppEnv, name: &str, kind: &str, header: Option<&str>, value: &str) {
    e.credentials.as_ref().unwrap().create(name, kind, value, header, None, None, "root", "").unwrap();
}

fn cred_names(e: &AppEnv) -> Vec<String> {
    e.credentials.as_ref().unwrap().names(None).unwrap().into_iter().map(|m| m.name).collect()
}

// -- Allowlist -------------------------------------------------------------------

#[test]
fn approve_reject_and_deploy_are_not_exposed() {
    for name in ["approve", "reject", "toolkit_deploy", "toolkit_reject", "credential_bind_deploy"] {
        assert!(!EXPOSED.contains(&name));
    }
    let e = env();
    let admin = e.admin();
    for name in ["approve", "toolkit_deploy", "credential_bind_deploy"] {
        let err = call(&admin, name, json!({"id": "whatever"})).unwrap_err();
        assert!(is_admin_err(&err));
    }
}

// -- tool_create / tool_validate ---------------------------------------------------

#[test]
fn tool_create_rejects_tier1_violation_and_validate_agrees() {
    let e = env();
    let admin = e.admin();
    let mut bad = sh_tool("demo.hack", "read", false);
    bad["binary"] = json!("/not/allowed/binary");
    assert!(call(&admin, "tool_create", json!({"spec": bad.clone()})).is_err());
    let payload = call(&admin, "tool_validate", json!({"spec": bad})).unwrap();
    assert_eq!(payload["ok"], false);
    assert!(payload["error"].is_string());
    let ok = call(&admin, "tool_validate", json!({"spec": sh_tool("demo.fine", "read", false)})).unwrap();
    assert_eq!(ok, json!({"ok": true, "id": "demo.fine", "category": "read"}));
}

#[test]
fn tool_validate_create_and_update_refuse_unknown_fields() {
    let e = env();
    let admin = e.admin();
    let mut bogus = sh_tool("demo.bogus", "read", false);
    bogus["zzz_bogus_key"] = json!(true);
    let payload = call(&admin, "tool_validate", json!({"spec": bogus.clone()})).unwrap();
    assert_eq!(payload["ok"], false);
    assert_eq!(
        payload["error"],
        "tool 'demo.bogus': unknown fields ['zzz_bogus_key'] -- nothing reads them for a tool on the \
         'local' executor, so the tool would not do what they say. Remove or correct them."
    );
    assert!(call(&admin, "tool_create", json!({"spec": bogus.clone()})).is_err());
    assert!(!e.store.service.catalog().tools.contains_key("demo.bogus"));

    // A misspelt parameter field, and a field of another executor.
    let mut typo = sh_tool("demo.typo", "read", false);
    typo["parameters"] = json!({"n": {"type": "integer", "minimun": 1}});
    let err = call(&admin, "tool_validate", json!({"spec": typo})).unwrap()["error"].clone();
    assert!(err.as_str().unwrap().contains("['parameters.n.minimun']"), "{err}");
    let mut foreign = sh_tool("demo.foreign", "read", false);
    foreign["method"] = json!("GET");
    let err = call(&admin, "tool_validate", json!({"spec": foreign})).unwrap()["error"].clone();
    assert!(err.as_str().unwrap().contains("['method']"), "{err}");

    // `executor` is fine when it names the toolkit's own.
    let mut labelled = sh_tool("demo.labelled", "read", false);
    labelled["executor"] = json!("local");
    assert_eq!(call(&admin, "tool_validate", json!({"spec": labelled.clone()})).unwrap()["ok"], true);
    labelled["executor"] = json!("http");
    let err = call(&admin, "tool_validate", json!({"spec": labelled})).unwrap()["error"].clone();
    assert!(err.as_str().unwrap().contains("executor='http' does not match toolkit 'demo'"), "{err}");

    // tool_update goes through the same check.
    call(&admin, "tool_create", json!({"spec": sh_tool("demo.later", "read", false)})).unwrap();
    let mut changed = sh_tool("demo.later", "read", false);
    changed["zzz_bogus_key"] = json!(1);
    assert!(call(&admin, "tool_update", json!({"id": "demo.later", "spec": changed})).is_err());
}

#[test]
fn unknown_fields_only_warn_at_startup() {
    // A stored tool that already carries one keeps loading.
    let e = env();
    let mut legacy = sh_tool("demo.legacy", "read", true);
    legacy["zzz_bogus_key"] = json!(true);
    let path = e.tmp.join("legacy-tools.yaml");
    std::fs::write(&path, gatekeeper::yaml::dump(&json!({"tools": [legacy]}))).unwrap();
    let catalog = load_catalog(path.to_str().unwrap(), &e.store.service.tier1(), true).unwrap();
    assert!(catalog.tools.contains_key("demo.legacy"));
    assert_eq!(catalog.unknown_fields.len(), 1);
    assert!(catalog.unknown_fields[0].contains("['zzz_bogus_key']"));
}

#[test]
fn tool_create_always_disabled_even_if_spec_says_enabled() {
    let e = env();
    let admin = e.admin();
    let payload = call(&admin, "tool_create", json!({"spec": sh_tool("demo.newread", "read", true)})).unwrap();
    assert_eq!(payload, json!({"applied": true, "id": "demo.newread"}));
    assert!(!e.service.catalog().tools["demo.newread"].enabled);
}

/// A `files` toolkit next to `demo`: `files.read` is read-only by what it
/// runs, `files.write` writes whatever its label says.
fn files_env() -> AppEnv {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_str().unwrap().to_string();
    let _ = dir.keep();
    let mut tier1 = demo_tier1_doc(std::path::Path::new(&root), std::path::Path::new(&root));
    tier1["toolkits"]["files"] = json!({"executor": "file", "path_roots": [root]});
    let mut tools = vec![];
    for op in ["read", "write"] {
        tools.push(file_tool(op, "read", false));
    }
    builder().tier1(tier1).tools(tools).build()
}

fn file_tool(op: &str, category: &str, enabled: bool) -> Value {
    let mut params = json!({"path": {"type": "string", "required": true, "pattern": "^/.*"}});
    if op == "write" {
        params["content"] = json!({"type": "string", "required": true, "pattern": "[\\s\\S]*",
                                   "allow_control_characters": true});
    }
    json!({"id": format!("files.{op}"), "toolkit": "files", "title": "n", "description": "d",
           "category": category, "file_operation": op, "enabled": enabled, "parameters": params})
}

#[test]
fn tool_enable_auto_applies_only_what_is_read_only_by_what_it_runs() {
    let e = files_env();
    let admin = e.admin();
    let payload = call(&admin, "tool_enable", json!({"id": "files.read"})).unwrap();
    assert_eq!(payload["applied"], true);
    assert!(e.service.catalog().tools["files.read"].enabled);
    assert!(e.pending.list(None).unwrap().is_empty());

    // Labelled read by whoever wrote it, but a write: a human decides.
    let payload = call(&admin, "tool_enable", json!({"id": "files.write"})).unwrap();
    assert_eq!(payload["pending"], true);
    assert!(!e.service.catalog().tools["files.write"].enabled);
}

#[test]
fn tool_enable_of_an_argv_tool_waits_even_when_labelled_read() {
    let e = env();
    e.store.set_tool_enabled("demo.show", false, "root", &e.store.tools_revision()).unwrap();
    let payload = call(&e.admin(), "tool_enable", json!({"id": "demo.show"})).unwrap();
    assert_eq!(payload["pending"], true);
    assert!(!e.service.catalog().tools["demo.show"].enabled);
}

#[test]
fn tool_update_cannot_relabel_a_granted_tool_into_applying_unreviewed() {
    let e = env();
    let admin = e.admin();
    // demo.show is granted to bot; new argv, still "read".
    let mut spec = sh_tool("demo.show", "read", true);
    spec["argv"] = json!(["-c", "echo PWNED"]);
    let payload = call(&admin, "tool_update", json!({"id": "demo.show", "spec": spec})).unwrap();
    assert_eq!(payload["pending"], true);

    let e = files_env();
    let admin = e.admin();
    // A write turned into a read is still a change a human approves ...
    let mut spec = file_tool("read", "read", false);
    spec["id"] = json!("files.write");
    let payload = call(&admin, "tool_update", json!({"id": "files.write", "spec": spec})).unwrap();
    assert_eq!(payload["pending"], true);
    // ... and a read-only tool updated to another read-only one applies.
    let mut spec = file_tool("read", "read", false);
    spec["description"] = json!("changed");
    let payload = call(&admin, "tool_update", json!({"id": "files.read", "spec": spec})).unwrap();
    assert_eq!(payload["applied"], true);
}

#[test]
fn tool_enable_write_category_creates_pending_item() {
    let e = env();
    let admin = e.admin();
    call(&admin, "tool_create", json!({"spec": sh_tool("demo.writeit", "write", false)})).unwrap();
    let payload = call(&admin, "tool_enable", json!({"id": "demo.writeit"})).unwrap();
    assert_eq!(payload["applied"], false);
    assert_eq!(payload["pending"], true);
    assert!(!e.service.catalog().tools["demo.writeit"].enabled);
    let items = e.pending.list(Some("pending")).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!((items[0].action.as_str(), items[0].actor.as_str()), ("tool_enable", "hermes"));
}

#[test]
fn tool_delete_grant_set_role_set_always_pending() {
    let e = env();
    let admin = e.admin();
    let payload = call(&admin, "tool_delete", json!({"id": "demo.show"})).unwrap();
    assert_eq!(payload["pending"], true);
    assert!(e.service.catalog().tools.contains_key("demo.show"));
    let payload = call(&admin, "grant_set", json!({"identity_id": "bot", "tools": ["demo.echo"]})).unwrap();
    assert_eq!(payload["pending"], true);
    let payload = call(&admin, "role_set", json!({"identity_id": "eye", "role": "admin"})).unwrap();
    assert_eq!(payload["pending"], true);
    let actions: Vec<String> = e.pending.list(Some("pending")).unwrap().into_iter().map(|i| i.action).collect();
    assert_eq!(actions, ["tool_delete", "grant_set", "role_set"]);
}

#[test]
fn role_set_refusals_queue_nothing() {
    let e = env();
    let admin = e.admin();
    assert!(call(&admin, "role_set", json!({"identity_id": "ghost", "role": "viewer"})).is_err());
    // `bot` has no console password, and role_set carries none.
    assert!(call(&admin, "role_set", json!({"identity_id": "bot", "role": "viewer"})).is_err());
    assert!(e.pending.list(None).unwrap().is_empty());
}

#[tokio::test]
async fn approved_pending_change_becomes_callable() {
    let e = env();
    let admin = e.admin();
    let mut spec = sh_tool("demo.approved_write", "write", false);
    spec["argv"] = json!(["-c", "echo done"]);
    call(&admin, "tool_create", json!({"spec": spec})).unwrap();
    call(&admin, "tool_enable", json!({"id": "demo.approved_write"})).unwrap();
    let item = e.pending.list(Some("pending")).unwrap().remove(0);
    e.store
        .save_identity(
            "bot",
            "agent",
            &["demo.show".into(), "demo.approved_write".into()],
            &["stack:*".into()],
            "root",
            &e.store.identities_revision(),
            Some("bot"),
            "",
        )
        .unwrap();
    approve(&e, &item.id).unwrap();
    assert!(e.service.catalog().tools["demo.approved_write"].enabled);
    let result = e.service.call(&e.identity("bot"), "demo.approved_write", &Map::new(), None).await.unwrap();
    assert_eq!(result.outcome, "ok");
    assert!(result.stdout.contains("done"));
}

// -- Toolkit proposals ----------------------------------------------------------------

#[test]
fn toolkit_list_reflects_live_tier1() {
    let e = env();
    let listed = call(&e.admin(), "toolkit_list", json!({})).unwrap();
    let names: Vec<&str> = listed["toolkits"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["demo"]);
    assert_eq!(listed["toolkits"][0]["run_as"], Value::Null);
}

#[test]
fn toolkit_propose_lands_in_proposal_store_never_pending() {
    let e = env();
    let payload = call(&e.admin(), "toolkit_propose", json!({"name": "zfs", "spec": {"executor": "local", "binaries": [SH]}}))
        .unwrap();
    assert_eq!((payload["pending"].clone(), payload["applied"].clone()), (json!(true), json!(false)));
    let proposed = e.proposals.list(Some("pending")).unwrap();
    assert_eq!((proposed[0].name.as_str(), proposed[0].actor.as_str()), ("zfs", "hermes"));
    assert!(e.pending.list(None).unwrap().is_empty());
}

#[test]
fn toolkit_propose_refuses_an_existing_name_at_submit() {
    let e = env();
    let err = call(&e.admin(), "toolkit_propose", json!({"name": "demo", "spec": {"executor": "local", "binaries": [SH]}}))
        .unwrap_err();
    assert!(err.message.contains("already exists") && err.message.contains("admin.toolkit_update"));
    assert!(e.proposals.list(None).unwrap().is_empty());
}

#[test]
fn proposal_list_and_withdraw_round_trip() {
    let e = env();
    let admin = e.admin();
    let created =
        call(&admin, "toolkit_propose", json!({"name": "zfs", "spec": {"executor": "local", "binaries": [SH]}})).unwrap();
    call(&admin, "toolkit_delete", json!({"name": "demo"})).unwrap();
    let listed = call(&admin, "proposal_list", json!({"kind": "create"})).unwrap();
    let ids: Vec<&Value> = listed["proposals"].as_array().unwrap().iter().map(|p| &p["id"]).collect();
    assert_eq!(ids, [&created["proposal_id"]]);
    let everything = call(&admin, "proposal_list", json!({})).unwrap();
    let mut kinds: Vec<&str> = everything["proposals"].as_array().unwrap().iter().map(|p| p["kind"].as_str().unwrap()).collect();
    kinds.sort();
    assert_eq!(kinds, ["create", "delete"]);

    let pid = created["proposal_id"].as_str().unwrap();
    assert!(admin.call("root", "proposal_withdraw", &args(json!({"proposal_id": pid}))).is_err());
    assert_eq!(e.proposals.get(pid).unwrap().unwrap().status, "pending");
    let result = call(&admin, "proposal_withdraw", json!({"proposal_id": pid})).unwrap();
    assert_eq!(result["withdrawn"], true);
    let left = call(&admin, "proposal_list", json!({"status": "withdrawn"})).unwrap();
    assert_eq!(left["proposals"][0]["id"], created["proposal_id"]);
    assert!(e.pending.list(None).unwrap().is_empty());
}

#[test]
fn toolkit_update_accepts_run_as_and_refuses_a_malformed_one() {
    let e = env();
    let admin = e.admin();
    let payload = call(&admin, "toolkit_update", json!({"name": "demo", "updates": {"run_as": "3001:3001"}})).unwrap();
    assert_eq!(payload["pending"], true);
    let proposed = e.proposals.list(Some("pending")).unwrap();
    assert_eq!(proposed[0].kind, "update");
    assert_eq!(Value::Object(proposed[0].spec.clone()), json!({"run_as": "3001:3001"}));
    let e = env();
    assert!(call(&e.admin(), "toolkit_update", json!({"name": "demo", "updates": {"run_as": "3001"}})).is_err());
    assert!(e.proposals.list(None).unwrap().is_empty());
}

#[test]
fn toolkit_delete_always_pending() {
    let e = env();
    let payload = call(&e.admin(), "toolkit_delete", json!({"name": "demo"})).unwrap();
    assert_eq!((payload["pending"].clone(), payload["applied"].clone()), (json!(true), json!(false)));
    let proposed = e.proposals.list(Some("pending")).unwrap();
    assert_eq!((proposed[0].name.as_str(), proposed[0].kind.as_str()), ("demo", "delete"));
    assert!(e.pending.list(None).unwrap().is_empty());
}

#[test]
fn toolkit_update_and_delete_refuse_an_unknown_toolkit_immediately() {
    let e = env();
    let admin = e.admin();
    let sandbox = e.sandbox.to_str().unwrap().to_string();
    for (tool, a) in [
        ("toolkit_update", json!({"name": "__nonexistent__", "updates": {"path_roots": [sandbox]}})),
        ("toolkit_delete", json!({"name": "__nonexistent__"})),
    ] {
        let err = call(&admin, tool, a).unwrap_err();
        assert!(is_admin_err(&err), "{tool}");
        assert_eq!(
            err.message,
            "No toolkit named '__nonexistent__' in the running configuration (known toolkits: ['demo']). Check \
             admin.toolkit_list.",
            "{tool}"
        );
    }
    assert!(e.proposals.list(None).unwrap().is_empty());
}

// -- cred_propose -------------------------------------------------------------------

#[test]
fn cred_propose_always_pending_and_writes_nothing() {
    let e = env_creds();
    let payload =
        call(&e.admin(), "cred_propose", json!({"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"})).unwrap();
    assert_eq!((payload["applied"].clone(), payload["pending"].clone()), (json!(false), json!(true)));
    let items = e.pending.list(Some("pending")).unwrap();
    assert_eq!(items[0].action, "cred_propose");
    assert_eq!(
        Value::Object(items[0].payload.clone()),
        json!({"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key", "probe_url": null})
    );
    assert!(cred_names(&e).is_empty());
}

#[test]
fn cred_propose_refusals() {
    let e = env_creds();
    let admin = e.admin();
    assert!(call(&admin, "cred_propose", json!({"name": "sonarr", "kind": "made_up_kind"})).is_err());
    assert!(call(&admin, "cred_propose", json!({"name": "sonarr", "kind": "api_key_header"})).is_err());
    let err = call(
        &admin,
        "cred_propose",
        json!({"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key", "value": "sneaked-in-secret"}),
    )
    .unwrap_err();
    assert!(!err.message.contains("sneaked-in-secret"));
    create_cred(&e, "sonarr", "api_key_header", Some("X-Api-Key"), "already-here");
    let err = call(&admin, "cred_propose", json!({"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"}))
        .unwrap_err();
    assert_eq!(err.message, "A credential named 'sonarr' already exists.");
    assert!(e.pending.list(None).unwrap().is_empty());

    let e = env();
    assert!(call(&e.admin(), "cred_propose", json!({"name": "sonarr", "kind": "api_key_header", "header": "X"})).is_err());
    assert!(e.pending.list(None).unwrap().is_empty());
}

// -- credential_bind ------------------------------------------------------------------

#[test]
fn credential_bind_queues_and_never_auto_applies() {
    let e = env_creds();
    create_cred(&e, "sonarr-api-key", "api_key_header", Some("X-Api-Key"), "filled-in-by-a-human");
    let payload = call(&e.admin(), "credential_bind", json!({"toolkit": "demo", "credential": "sonarr-api-key"})).unwrap();
    assert_eq!((payload["applied"].clone(), payload["pending"].clone()), (json!(false), json!(true)));
    let items = e.proposals.list(Some("pending")).unwrap();
    assert_eq!((items[0].kind.as_str(), items[0].name.as_str()), ("bind", "demo"));
    assert_eq!(Value::Object(items[0].spec.clone()), json!({"credential": "sonarr-api-key"}));
    assert_eq!(e.service.tier1().toolkits["demo"].credential, None);
    assert!(e.load_yaml(&e.toolkits_path)["toolkits"]["demo"].get("credential").is_none());
    assert!(e.pending.list(None).unwrap().is_empty());
}

#[test]
fn credential_bind_refusals() {
    let e = env_creds();
    create_cred(&e, "sonarr-api-key", "api_key_header", Some("X-Api-Key"), "v");
    let admin = e.admin();
    let err = call(&admin, "credential_bind", json!({"toolkit": "no-such-toolkit", "credential": "sonarr-api-key"})).unwrap_err();
    assert!(err.message.contains("no-such-toolkit"));
    let err = call(&admin, "credential_bind", json!({"toolkit": "demo", "credential": "never-created"})).unwrap_err();
    assert!(err.message.contains("never-created"));
    let err = call(
        &admin,
        "credential_bind",
        json!({"toolkit": "demo", "credential": "sonarr-api-key", "value": "sneaked-in-secret"}),
    )
    .unwrap_err();
    assert!(!err.message.contains("sneaked-in-secret"));
    for extra in [
        json!({"secret": "s"}),
        json!({"token": "t"}),
        json!({"password": "p"}),
        json!({"api_key": "k"}),
        json!({"destination": "sonarr-lan"}),
        json!({"path_roots": ["/"]}),
        json!({"protected_resources": []}),
        json!({"max_output_bytes": 1u64 << 30}),
    ] {
        let mut a = json!({"toolkit": "demo", "credential": "sonarr-api-key"});
        a.as_object_mut().unwrap().extend(obj(extra));
        assert!(call(&admin, "credential_bind", a).is_err());
    }
    assert!(e.proposals.list(None).unwrap().is_empty());
    let proposals_file = e.tmp.join("toolkit_proposals.yaml");
    if proposals_file.exists() {
        assert!(!std::fs::read_to_string(proposals_file).unwrap().contains("sneaked-in-secret"));
    }

    let e = env();
    assert!(call(&e.admin(), "credential_bind", json!({"toolkit": "demo", "credential": "sonarr-api-key"})).is_err());
    assert!(e.proposals.list(None).unwrap().is_empty());
}

// -- cred_delete ------------------------------------------------------------------------

#[test]
fn cred_delete_removes_an_unbound_slot_and_audits_only_the_name() {
    let e = env_creds();
    create_cred(&e, "paperless-token", "bearer", None, "super-secret-token-xyz");
    let admin = e.admin();
    let payload = call(&admin, "cred_delete", json!({"name": "paperless-token"})).unwrap();
    assert_eq!(payload, json!({"applied": true, "name": "paperless-token"}));
    let listed = call(&admin, "cred_list", json!({})).unwrap();
    assert_eq!(listed["credentials"], json!([]));
    let deletions: Vec<Value> = e.audit_lines().into_iter().filter(|l| l["action"] == "credential_delete").collect();
    assert_eq!(deletions.len(), 1);
    assert_eq!((deletions[0]["target"].clone(), deletions[0]["actor"].clone()), (json!("paperless-token"), json!("hermes")));
    assert!(!e.audit_text().contains("super-secret-token-xyz"));
}

#[test]
fn cred_delete_refusals() {
    let e = env_creds();
    create_cred(&e, "paperless-token", "bearer", None, "v");
    let err = call(&e.admin(), "cred_delete", json!({"name": "never-created"})).unwrap_err();
    assert!(err.message.contains("never-created"));
    assert_eq!(cred_names(&e), ["paperless-token"]);
    let e = env();
    assert!(call(&e.admin(), "cred_delete", json!({"name": "paperless-token"})).is_err());
}

#[test]
fn cred_delete_refuses_a_slot_a_toolkit_or_destination_still_binds() {
    let e = builder()
        .identities(ids())
        .tools(vec![])
        .credentials()
        .tier1(json!({"toolkits": {"paperless": {
            "executor": "http", "base_url": "https://paperless.lan", "allowed_methods": ["GET"],
            "allowed_path_prefixes": ["/api/"], "allowed_cidrs": ["10.0.0.0/8"],
            "credential": "paperless-token", "max_timeout_seconds": 10, "max_output_bytes": 65536,
        }}}))
        .build();
    create_cred(&e, "paperless-token", "bearer", None, "v");
    let err = e.admin().cred_delete("hermes", &args(json!({"name": "paperless-token"}))).unwrap_err();
    assert!(is_admin_err(&err) && err.message.contains("paperless"));
    assert_eq!(cred_names(&e), ["paperless-token"]);

    let e = builder()
        .identities(ids())
        .tools(vec![])
        .credentials()
        .tier1(json!({
            "destinations": {"nas2": {"docker_host": "tcp://nas2.lan:2376", "docker_tls": true,
                                       "credential": "docker-nas2-tls"}},
            "toolkits": {"docker": {"executor": "docker", "binaries": ["/usr/bin/docker"],
                                    "destinations": ["nas2"], "max_timeout_seconds": 10,
                                    "max_output_bytes": 65536}},
        }))
        .build();
    create_cred(&e, "docker-nas2-tls", "docker_tls", None, "{}");
    let err = e.admin().cred_delete("hermes", &args(json!({"name": "docker-nas2-tls"}))).unwrap_err();
    assert!(err.message.contains("nas2"));
    assert_eq!(cred_names(&e), ["docker-nas2-tls"]);
}

// -- apply_pending (test_pending.py) -----------------------------------------------------

fn propose(e: &AppEnv, action: &str, payload: Value, base_rev: &str) -> gatekeeper::pending::PendingAction {
    e.pending.propose(action, "hermes", obj(payload), base_rev).unwrap()
}

fn tool_delete(e: &AppEnv, id: &str) -> gatekeeper::pending::PendingAction {
    propose(e, "tool_delete", json!({"id": id}), &e.store.tool_revision(id))
}

/// Drops a tool's entry from tools.yaml entirely and reloads the catalog
/// (a vanished target, not a tombstone).
fn remove_tool_entry(e: &AppEnv, tool_id: &str) {
    let raw = e.load_yaml(&e.tools_path);
    let kept: Vec<Value> = raw["tools"].as_array().unwrap().iter().filter(|s| s["id"] != tool_id).cloned().collect();
    write(std::path::Path::new(&e.tools_path), &gatekeeper::yaml::dump(&json!({ "tools": kept })));
    e.service.set_catalog(load_catalog(&e.tools_path, &e.service.tier1(), false).unwrap());
}

fn tools_of(e: &AppEnv, id: &str) -> Vec<String> {
    e.identity(id).tools.into_iter().collect()
}

#[test]
fn approve_tool_delete_applies_and_soft_deletes() {
    let e = env();
    let item = tool_delete(&e, "demo.show");
    approve(&e, &item.id).unwrap();
    assert!(!e.service.catalog().tools.contains_key("demo.show"));
    assert_eq!(e.service.catalog().raw_of("demo.show").unwrap()["deleted"], true);
    let approved = e.pending.get(&item.id).unwrap().unwrap();
    assert_eq!((approved.status.as_str(), approved.decided_by.as_deref()), ("approved", Some("root")));
}

#[test]
fn approve_grant_set_and_role_set_update_identities() {
    let e = env();
    let item = propose(
        &e,
        "grant_set",
        json!({"identity_id": "bot", "role": "agent", "tools": ["demo.show", "demo.echo"], "scopes": []}),
        &e.store.identity_revision("bot"),
    );
    approve(&e, &item.id).unwrap();
    assert_eq!(tools_of(&e, "bot"), ["demo.echo", "demo.show"]);

    e.store
        .save_identity("hermes", "admin", &[], &[], "root", &e.store.identities_revision(), Some("hermes"), &"x".repeat(20))
        .unwrap();
    let item = propose(
        &e,
        "role_set",
        json!({"identity_id": "hermes", "role": "viewer", "tools": [], "scopes": []}),
        &e.store.identity_revision("hermes"),
    );
    approve(&e, &item.id).unwrap();
    assert_eq!(e.identity("hermes").role, "viewer");
}

#[test]
fn approve_nonexistent_or_unknown_action_refused() {
    let e = env();
    let err = approve(&e, "nope").unwrap_err();
    assert!(err.is_write_refused());
    assert_eq!(err.message, "No pending action 'nope'.");
    let item = propose(&e, "identity_delete", json!({"id": "root"}), "");
    assert_eq!(approve(&e, &item.id).unwrap_err().message, "Unknown pending action type 'identity_delete'.");
}

#[test]
fn approve_not_stale_when_unrelated_tool_changes() {
    let e = env();
    let item = tool_delete(&e, "demo.show");
    e.store.set_tool_enabled("demo.echo", false, "root", &e.store.tools_revision()).unwrap();
    approve(&e, &item.id).unwrap();
    assert!(!e.service.catalog().tools.contains_key("demo.show"));
    assert_eq!(e.pending.get(&item.id).unwrap().unwrap().status, "approved");
}

#[test]
fn approve_marks_stale_when_same_tool_changes_and_cannot_be_approved_again() {
    let e = env();
    let item = tool_delete(&e, "demo.show");
    e.store.set_tool_enabled("demo.show", false, "root", &e.store.tools_revision()).unwrap();
    let err = approve(&e, &item.id).unwrap_err();
    assert!(err.message.to_lowercase().contains("stale"));
    let marked = e.pending.get(&item.id).unwrap().unwrap();
    assert_eq!(marked.status, "stale");
    assert_eq!(marked.reason.as_deref(), Some(STALE_CHANGED_REASON));
    assert!(!e.service.catalog().tools["demo.show"].enabled);
    let err = approve(&e, &item.id).unwrap_err().message.to_lowercase();
    assert!(err.contains("already") || err.contains("stale"));
}

#[test]
fn approve_role_set_marks_stale_when_identity_moved_or_vanished() {
    let e = env();
    let item = propose(
        &e,
        "role_set",
        json!({"identity_id": "bot", "role": "viewer", "tools": [], "scopes": []}),
        &e.store.identity_revision("bot"),
    );
    e.store
        .save_identity("bot", "agent", &["demo.show".into()], &[], "root", &e.store.identities_revision(), Some("bot"), "")
        .unwrap();
    assert!(approve(&e, &item.id).unwrap_err().message.to_lowercase().contains("stale"));
    assert_eq!(e.pending.get(&item.id).unwrap().unwrap().status, "stale");
    assert_eq!(e.identity("bot").role, "agent");

    let e = env();
    let item = propose(
        &e,
        "role_set",
        json!({"identity_id": "bot", "role": "viewer", "tools": [], "scopes": []}),
        &e.store.identity_revision("bot"),
    );
    e.store.delete_identity("bot", "root", &e.store.identities_revision()).unwrap();
    assert_eq!(e.store.identity_revision("bot"), "");
    assert!(approve(&e, &item.id).unwrap_err().message.to_lowercase().contains("stale"));
    assert_eq!(e.pending.get(&item.id).unwrap().unwrap().status, "stale");
}

#[test]
fn vanished_tool_target_is_stale_not_a_crash() {
    let e = env();
    let item = tool_delete(&e, "demo.show");
    remove_tool_entry(&e, "demo.show");
    assert_eq!(e.store.tool_revision("demo.show"), "");
    let err = approve(&e, &item.id).unwrap_err().message.to_lowercase();
    assert!(err.contains("stale") && !err.contains("no tool with id"));
    let marked = e.pending.get(&item.id).unwrap().unwrap();
    assert_eq!(marked.status, "stale");
    assert_eq!(marked.decided_by.as_deref(), Some("root"));
    assert!(marked.reason.unwrap_or_default().contains("no longer exists"));
    assert!(approve(&e, &item.id).unwrap_err().message.to_lowercase().contains("already"));

    // Rejecting never needs a live target.
    let e = env();
    let item = tool_delete(&e, "demo.show");
    remove_tool_entry(&e, "demo.show");
    let rejected = e.pending.reject(&item.id, "root", "toolkit restructured").unwrap();
    assert_eq!(rejected.status, "rejected");
}

#[test]
fn two_pending_items_for_different_records_do_not_invalidate_each_other() {
    let e = env();
    e.store
        .save_identity("hermes", "admin", &[], &[], "root", &e.store.identities_revision(), Some("hermes"), &"x".repeat(20))
        .unwrap();
    let bot = propose(
        &e,
        "grant_set",
        json!({"identity_id": "bot", "role": "agent", "tools": ["demo.show"], "scopes": []}),
        &e.store.identity_revision("bot"),
    );
    let hermes = propose(
        &e,
        "role_set",
        json!({"identity_id": "hermes", "role": "viewer", "tools": [], "scopes": []}),
        &e.store.identity_revision("hermes"),
    );
    approve(&e, &bot.id).unwrap();
    approve(&e, &hermes.id).unwrap();
    assert_eq!(e.identity("hermes").role, "viewer");

    let show = tool_delete(&e, "demo.show");
    let echo = tool_delete(&e, "demo.echo");
    approve(&e, &show.id).unwrap();
    approve(&e, &echo.id).unwrap();
    assert!(e.service.catalog().tools.is_empty());
}

#[test]
fn approve_marks_stale_when_the_payload_names_no_target() {
    let e = env();
    let item = propose(&e, "tool_update", json!({"spec": {"id": "demo.show"}}), &e.store.tool_revision("demo.show"));
    assert!(approve(&e, &item.id).unwrap_err().message.to_lowercase().contains("stale"));
    assert_eq!(e.pending.get(&item.id).unwrap().unwrap().status, "stale");
}

// -- sweep_vanished_pendings ----------------------------------------------------------------

fn sweep(e: &AppEnv) -> Vec<String> {
    sweep_vanished_pendings(&e.store, &e.pending, e.credentials.as_deref(), "gatekeeper")
        .unwrap()
        .into_iter()
        .map(|i| i.id)
        .collect()
}

#[test]
fn sweep_closes_a_vanished_target_once_and_audits_it() {
    let e = env();
    let item = tool_delete(&e, "demo.show");
    remove_tool_entry(&e, "demo.show");
    assert_eq!(e.pending.get(&item.id).unwrap().unwrap().status, "pending");
    assert_eq!(sweep(&e), [item.id.clone()]);
    let healed = e.pending.get(&item.id).unwrap().unwrap();
    assert_eq!(healed.status, "stale");
    assert_eq!(healed.reason.as_deref(), Some(STALE_VANISHED_REASON));
    assert!(healed.decided_at.is_some());
    let rev = e.pending.revision();
    assert!(sweep(&e).is_empty());
    assert!(sweep(&e).is_empty());
    assert_eq!(e.pending.revision(), rev);
    let stales: Vec<Value> = e.audit_lines().into_iter().filter(|l| l["action"] == "pending_stale").collect();
    assert_eq!(stales.len(), 1);
    assert_eq!(stales[0]["target"], json!(item.id));
    assert_eq!(stales[0]["proposed_action"], "tool_delete");
}

#[test]
fn sweep_leaves_live_unborn_cred_propose_and_decided_items_alone() {
    let e = env();
    let untouched = tool_delete(&e, "demo.show");
    let moved = propose(&e, "tool_enable", json!({"id": "demo.echo"}), &e.store.tool_revision("demo.echo"));
    e.store.set_tool_enabled("demo.echo", false, "root", &e.store.tools_revision()).unwrap();
    let unborn = propose(&e, "tool_delete", json!({"id": "demo.ghost"}), "");
    let cred = propose(&e, "cred_propose", json!({"name": "bazarr-api-key", "kind": "bearer", "header": null}), "deadbeefdeadbeef");
    assert!(sweep(&e).is_empty());
    for id in [&untouched.id, &moved.id, &unborn.id, &cred.id] {
        assert_eq!(e.pending.get(id).unwrap().unwrap().status, "pending");
    }
    e.pending.reject(&untouched.id, "root", "not needed").unwrap();
    remove_tool_entry(&e, "demo.show");
    assert!(sweep(&e).is_empty());
    assert_eq!(e.pending.get(&untouched.id).unwrap().unwrap().reason.as_deref(), Some("not needed"));
}

#[test]
fn sweep_covers_every_target_based_kind() {
    let e = env_creds();
    create_cred(&e, "sonarr", "bearer", None, "v");
    let spec = e.service.catalog().flat_spec_of("demo.show").unwrap();
    let creds = e.credentials.as_ref().unwrap();
    let show_rev = e.store.tool_revision("demo.show");
    let bot_rev = e.store.identity_revision("bot");
    propose(&e, "tool_delete", json!({"id": "demo.show"}), &show_rev);
    propose(&e, "tool_enable", json!({"id": "demo.show"}), &show_rev);
    propose(&e, "tool_update", json!({"spec": spec, "replaces": "demo.show"}), &show_rev);
    propose(&e, "grant_set", json!({"identity_id": "bot", "role": "agent", "tools": [], "scopes": []}), &bot_rev);
    propose(&e, "role_set", json!({"identity_id": "bot", "role": "viewer", "tools": [], "scopes": []}), &bot_rev);
    propose(
        &e,
        "cred_update",
        json!({"name": "sonarr", "new_name": null, "kind": "api_key_header", "header": "X-Api-Key", "probe_url": null}),
        &creds.record_revision("sonarr").unwrap(),
    );
    remove_tool_entry(&e, "demo.show");
    e.store.delete_identity("bot", "root", &e.store.identities_revision()).unwrap();
    creds.delete("sonarr", "root", &creds.revision()).unwrap();
    let mut closed: Vec<String> = sweep_vanished_pendings(&e.store, &e.pending, Some(creds), "gatekeeper")
        .unwrap()
        .into_iter()
        .map(|i| i.action)
        .collect();
    closed.sort();
    assert_eq!(closed, ["cred_update", "grant_set", "role_set", "tool_delete", "tool_enable", "tool_update"]);
}

#[test]
fn admin_pending_list_self_heals_and_reports_the_healed_state() {
    let e = env();
    let item = tool_delete(&e, "demo.show");
    remove_tool_entry(&e, "demo.show");
    let admin = e.admin();
    let listed = call(&admin, "pending_list", json!({})).unwrap();
    let statuses: Vec<&Value> =
        listed["pending"].as_array().unwrap().iter().filter(|p| p["id"] == json!(item.id)).map(|p| &p["status"]).collect();
    assert_eq!(statuses, [&json!("stale")]);
    assert_eq!(call(&admin, "pending_list", json!({"status": "pending"})).unwrap()["pending"], json!([]));
}

// -- cred_update (test_cred_update.py) ----------------------------------------------------------

const SECRET: &str = "jellyfin-token-0123456789abcdef";

fn cred_env(bound: bool) -> AppEnv {
    let mut toolkit = json!({
        "executor": "http", "base_url": "https://jellyfin.lan", "allowed_methods": ["GET", "POST"],
        "allowed_path_prefixes": ["/Library/"], "allowed_cidrs": ["10.0.0.0/8"],
        "max_timeout_seconds": 10, "max_output_bytes": 65536,
    });
    if bound {
        toolkit["credential"] = json!("jellyfin");
    }
    let e = builder().identities(ids()).tools(vec![]).credentials().tier1(json!({"toolkits": {"jellyfin": toolkit}})).build();
    create_cred(&e, "jellyfin", "api_key_header", Some("X-Emby-Token"), SECRET);
    e
}

fn meta(e: &AppEnv, name: &str) -> gatekeeper::credentials::CredentialMeta {
    e.credentials.as_ref().unwrap().names(None).unwrap().into_iter().find(|m| m.name == name).unwrap()
}

fn cred_update(e: &AppEnv, a: Value) -> Result<Value, ConfigError> {
    e.admin().cred_update("hermes", &args(a))
}

fn pid(v: &Value) -> String {
    v["pending_id"].as_str().unwrap().to_string()
}

#[test]
fn header_repair_on_a_bound_slot_keeps_the_value() {
    let e = cred_env(true);
    let creds = e.credentials.as_ref().unwrap();
    creds.mark_suspect("jellyfin", "auth_failed").unwrap();
    let result = cred_update(&e, json!({"name": "jellyfin", "header": "Authorization"})).unwrap();
    assert_eq!((result["applied"].clone(), result["pending"].clone()), (json!(false), json!(true)));
    assert_eq!(meta(&e, "jellyfin").header.as_deref(), Some("X-Emby-Token"));
    approve(&e, &pid(&result)).unwrap();
    let m = meta(&e, "jellyfin");
    assert_eq!((m.kind.as_str(), m.header.as_deref()), ("api_key_header", Some("Authorization")));
    assert_eq!(m.suspect_status, None);
    assert_eq!(creds.resolve("jellyfin").unwrap().unwrap().value, SECRET);
    assert_eq!(e.pending.get(&pid(&result)).unwrap().unwrap().status, "approved");
}

#[test]
fn cred_update_proposal_and_audit_carry_no_value() {
    let e = cred_env(true);
    let result = cred_update(&e, json!({"name": "jellyfin", "header": "Authorization"})).unwrap();
    approve(&e, &pid(&result)).unwrap();
    assert!(!e.audit_text().contains(SECRET));
    let updates: Vec<Value> = e.audit_lines().into_iter().filter(|l| l["action"] == "credential_update").collect();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0]["target"], "jellyfin");
    assert_eq!(updates[0]["header"], "Authorization");
    assert_eq!(updates[0]["changed"], json!(["header"]));
    assert!(!e.read(&e.pending.path).contains(SECRET));
}

#[test]
fn cred_update_refusals() {
    let e = cred_env(true);
    for arg in ["value", "secret", "token", "api_key"] {
        let mut a = json!({"name": "jellyfin"});
        a[arg] = json!("sneaked-in");
        let err = cred_update(&e, a).unwrap_err();
        assert!(is_admin_err(&err) && err.message.contains(arg) && !err.message.contains("sneaked-in"));
    }
    assert!(cred_update(&e, json!({"name": "nope", "header": "Authorization"})).unwrap_err().message.contains("nope"));
    assert!(cred_update(&e, json!({"name": "jellyfin", "header": "X-Emby-Token"}))
        .unwrap_err()
        .message
        .contains("Nothing to change"));
    assert!(cred_update(&e, json!({"name": "jellyfin", "kind": "docker_tls"})).unwrap_err().message.contains("docker_tls"));
    for header in ["X-Token\r\nX-Evil: 1", "Bad Header", "a:b"] {
        assert!(cred_update(&e, json!({"name": "jellyfin", "header": header}))
            .unwrap_err()
            .message
            .contains("not a valid header"));
    }
    assert!(cred_update(&e, json!({"name": "jellyfin", "new_name": "jellyfin2"}))
        .unwrap_err()
        .message
        .contains("still referenced"));
    for (fmt, reason) in [
        ("MediaBrowser Token=x", "exactly once"),
        ("{value} {value}", "exactly once"),
        ("MediaBrowser Token=\"{value}\"\r\nX-Evil: 1", "one line"),
    ] {
        assert!(cred_update(&e, json!({"name": "jellyfin", "header_format": fmt})).unwrap_err().message.contains(reason));
    }
    assert!(cred_update(&e, json!({"name": "jellyfin", "kind": "bearer", "header_format": "Token {value}"}))
        .unwrap_err()
        .message
        .contains("api_key_header"));
    assert!(e.pending.list(None).unwrap().is_empty());
    // The store refuses a cross-shape kind change too.
    let creds = e.credentials.as_ref().unwrap();
    let err = creds.update("jellyfin", "oauth2", None, None, None, None, "root", &creds.revision()).unwrap_err();
    assert!(err.message.contains("oauth2"));
}

#[test]
fn switching_to_a_headerless_kind_drops_the_header() {
    let e = cred_env(true);
    let result = cred_update(&e, json!({"name": "jellyfin", "kind": "bearer"})).unwrap();
    assert_eq!(e.pending.get(&pid(&result)).unwrap().unwrap().payload["header"], Value::Null);
    approve(&e, &pid(&result)).unwrap();
    let m = meta(&e, "jellyfin");
    assert_eq!((m.kind.as_str(), m.header), ("bearer", None));
    assert!(cred_update(&e, json!({"name": "jellyfin", "kind": "url_path", "header": "X-Token"}))
        .unwrap_err()
        .message
        .contains("takes no 'header'"));
}

#[test]
fn rename_of_an_unbound_slot_keeps_the_value() {
    let e = cred_env(false);
    let result = cred_update(&e, json!({"name": "jellyfin", "new_name": "jellyfin-main", "header": "Authorization"})).unwrap();
    approve(&e, &pid(&result)).unwrap();
    assert_eq!(cred_names(&e), ["jellyfin-main"]);
    assert_eq!(e.credentials.as_ref().unwrap().resolve("jellyfin-main").unwrap().unwrap().value, SECRET);
    let update = e.audit_lines().into_iter().find(|l| l["action"] == "credential_update").unwrap();
    assert_eq!(update["new_name"], "jellyfin-main");
    assert_eq!(update["changed"], json!(["name", "header"]));
}

#[test]
fn rename_onto_a_taken_name_is_refused_and_later_closed() {
    let e = cred_env(false);
    create_cred(&e, "emby", "bearer", None, "other");
    assert!(cred_update(&e, json!({"name": "jellyfin", "new_name": "emby"})).unwrap_err().message.contains("already exists"));
    let result = cred_update(&e, json!({"name": "jellyfin", "new_name": "media"})).unwrap();
    create_cred(&e, "media", "bearer", None, "x");
    call(&e.admin(), "pending_list", json!({})).unwrap();
    let closed = e.pending.get(&pid(&result)).unwrap().unwrap();
    assert_eq!((closed.status.as_str(), closed.reason.as_deref()), ("stale", Some(STALE_TAKEN_REASON)));
}

#[test]
fn slot_changed_meanwhile_stales_but_a_suspect_mark_does_not() {
    let e = cred_env(true);
    let first = cred_update(&e, json!({"name": "jellyfin", "header": "Authorization"})).unwrap();
    let second = cred_update(&e, json!({"name": "jellyfin", "header": "X-Token"})).unwrap();
    approve(&e, &pid(&first)).unwrap();
    assert!(approve(&e, &pid(&second)).unwrap_err().message.contains("stale"));
    let item = e.pending.get(&pid(&second)).unwrap().unwrap();
    assert_eq!((item.status.as_str(), item.reason.as_deref()), ("stale", Some(STALE_CHANGED_REASON)));
    assert_eq!(meta(&e, "jellyfin").header.as_deref(), Some("Authorization"));

    let e = cred_env(true);
    let result = cred_update(&e, json!({"name": "jellyfin", "header": "Authorization"})).unwrap();
    e.credentials.as_ref().unwrap().mark_suspect("jellyfin", "auth_failed").unwrap();
    approve(&e, &pid(&result)).unwrap();
    assert_eq!(meta(&e, "jellyfin").header.as_deref(), Some("Authorization"));
}

#[test]
fn deleted_slot_closes_the_proposal_and_no_store_keeps_it_pending() {
    let e = cred_env(false);
    let result = cred_update(&e, json!({"name": "jellyfin", "header": "Authorization"})).unwrap();
    let creds = e.credentials.as_ref().unwrap();
    creds.delete("jellyfin", "root", &creds.revision()).unwrap();
    call(&e.admin(), "pending_list", json!({})).unwrap();
    assert_eq!(e.pending.get(&pid(&result)).unwrap().unwrap().status, "stale");

    let e = cred_env(true);
    let result = cred_update(&e, json!({"name": "jellyfin", "header": "Authorization"})).unwrap();
    let err = apply_pending(&e.store, &e.pending, &pid(&result), "root", None).unwrap_err();
    assert_eq!(err.kind, ConfigErrorKind::WriteRefused);
    assert_eq!(e.pending.get(&pid(&result)).unwrap().unwrap().status, "pending");
}

#[test]
fn header_format_is_proposed_applied_and_dropped_with_the_kind() {
    let e = cred_env(true);
    let result = cred_update(
        &e,
        json!({"name": "jellyfin", "header": "Authorization", "header_format": "MediaBrowser Token=\"{value}\""}),
    )
    .unwrap();
    approve(&e, &pid(&result)).unwrap();
    let m = meta(&e, "jellyfin");
    assert_eq!(
        (m.header.as_deref(), m.header_format.as_deref()),
        (Some("Authorization"), Some("MediaBrowser Token=\"{value}\""))
    );
    let update = e.audit_lines().into_iter().find(|l| l["action"] == "credential_update").unwrap();
    assert_eq!(update["changed"], json!(["header", "header_format"]));
    assert!(!e.audit_text().contains(SECRET));

    let second = cred_update(&e, json!({"name": "jellyfin", "kind": "bearer"})).unwrap();
    assert_eq!(e.pending.get(&pid(&second)).unwrap().unwrap().payload["header_format"], Value::Null);
    approve(&e, &pid(&second)).unwrap();
    assert_eq!(meta(&e, "jellyfin").header_format, None);
}

#[test]
fn cred_propose_carries_a_header_format() {
    let e = cred_env(true);
    let admin = e.admin();
    let result = admin
        .cred_propose(
            "hermes",
            &args(json!({"name": "emby", "kind": "api_key_header", "header": "Authorization",
                         "header_format": "MediaBrowser Token=\"{value}\""})),
        )
        .unwrap();
    assert_eq!(e.pending.get(&pid(&result)).unwrap().unwrap().payload["header_format"], "MediaBrowser Token=\"{value}\"");
    let err = admin
        .cred_propose("hermes", &args(json!({"name": "emby2", "kind": "api_key_header", "header": "X", "header_format": "x"})))
        .unwrap_err();
    assert!(err.message.contains("exactly once"));
}

// -- cred_list warnings (1.22.0) ---------------------------------------------------------

#[test]
fn cred_list_warns_about_an_authorization_header_without_a_format() {
    let e = env_creds();
    create_cred(&e, "github", "api_key_header", Some("Authorization"), "ghp_value");
    create_cred(&e, "paperless-token", "bearer", None, "v");
    let listed = call(&e.admin(), "cred_list", json!({})).unwrap();
    let by_name = |name: &str| listed["credentials"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap().clone();
    let warnings = by_name("github")["warnings"].clone();
    assert_eq!(warnings.as_array().unwrap().len(), 1);
    assert!(warnings[0].as_str().unwrap().contains("no header_format"));
    assert_eq!(by_name("paperless-token")["warnings"], json!([]));
    assert!(!listed.to_string().contains("ghp_value"));
}
