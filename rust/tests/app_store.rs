//! Tier 2 writes through `ConfigStore` (port of `tests/test_store_admin.py`)
//! plus `set_password_in_file`, `load_tool_yaml` and the fingerprints.

mod app_env;

use app_env::*;
use gatekeeper::catalog::load_catalog;
use gatekeeper::errors::ConfigError;
use gatekeeper::identity::{generate_token, hash_token, load_identities};
use gatekeeper::store::{fingerprint, load_tool_yaml, set_password_in_file, tool_to_yaml};
use serde_json::{json, Value};

fn spec(extra: Value) -> serde_json::Map<String, Value> {
    let mut base = obj(json!({
        "id": "demo.ping", "toolkit": "demo", "binary": SH, "title": "x", "description": "x",
        "category": "read", "idempotent": true, "enabled": true, "argv": [],
        "parameters": {}, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 1024,
    }));
    for (k, v) in obj(extra) {
        base.insert(k, v);
    }
    base
}

fn msg(e: ConfigError) -> String {
    e.message
}

#[test]
fn admin_cannot_exceed_tier1_ceilings() {
    let e = AppEnv::new();
    let err = e
        .store
        .save_tool(&spec(json!({"id": "demo.toolong", "timeout_seconds": 99999})), "root", &e.tools_rev(), None)
        .unwrap_err();
    assert!(err.message.contains("exceeds"), "{}", err.message);
    assert!(!e.service.catalog().tools.contains_key("demo.toolong"));
}

#[test]
fn admin_cannot_introduce_a_foreign_binary() {
    let e = AppEnv::new();
    let err = e
        .store
        .save_tool(&spec(json!({"id": "demo.evil", "binary": "/bin/bash", "argv": ["-c", "id"]})), "root", &e.tools_rev(), None)
        .unwrap_err();
    assert!(err.message.contains("allowlist"), "{}", err.message);
}

#[test]
fn admin_cannot_use_a_denied_argument() {
    let e = AppEnv::new();
    let err = e
        .store
        .save_tool(
            &spec(json!({"id": "demo.rm", "category": "write", "idempotent": false, "argv": ["rm", "-rf"]})),
            "root",
            &e.tools_rev(),
            None,
        )
        .unwrap_err();
    assert!(err.message.contains("denied argument"), "{}", err.message);
}

#[test]
fn free_text_parameter_still_refused() {
    let e = AppEnv::new();
    let err = e
        .store
        .save_tool(
            &spec(json!({"id": "demo.freetext", "argv": ["-c", "true", "{anything}"],
                         "parameters": {"anything": {"type": "string", "required": true, "description": "x"}}})),
            "root",
            &e.tools_rev(),
            None,
        )
        .unwrap_err();
    assert!(err.message.contains("pattern"), "{}", err.message);
}

#[test]
fn create_edit_disable_delete_roundtrip() {
    let e = AppEnv::new();
    let s = spec(json!({"version": 1, "title": "Ping", "argv": ["-c", "echo pong"]}));
    assert_eq!(e.store.save_tool(&s, "root", &e.tools_rev(), None).unwrap(), "demo.ping");
    assert!(e.service.catalog().tools.contains_key("demo.ping"));
    let on_disk = e.load_yaml(&e.tools_path);
    assert!(on_disk["tools"].as_array().unwrap().iter().any(|t| t["id"] == "demo.ping"));

    let mut edited = s.clone();
    edited.insert("title".into(), json!("Ping v2"));
    e.store.save_tool(&edited, "root", &e.tools_rev(), Some("demo.ping")).unwrap();
    assert_eq!(e.service.catalog().tools["demo.ping"].title, "Ping v2");

    e.store.set_tool_enabled("demo.ping", false, "root", &e.tools_rev()).unwrap();
    assert!(!e.service.catalog().tools["demo.ping"].enabled);

    e.store.delete_tool("demo.ping", "root", &e.tools_rev()).unwrap();
    assert!(!e.service.catalog().tools.contains_key("demo.ping"));
    // Soft delete: the history is still on disk, and the id cannot be reused.
    let on_disk = e.load_yaml(&e.tools_path);
    let entry = on_disk["tools"].as_array().unwrap().iter().find(|t| t["id"] == "demo.ping").unwrap().clone();
    assert_eq!(entry["deleted"], true);
    assert_eq!(entry["versions"].as_array().unwrap().len(), 2);
    let err = e.store.save_tool(&s, "root", &e.tools_rev(), None).unwrap_err();
    assert_eq!(err.message, "A tool with ID 'demo.ping' already exists.");
    // Deleting twice is refused.
    assert_eq!(msg(e.store.delete_tool("demo.ping", "root", &e.tools_rev()).unwrap_err()), "No tool with ID 'demo.ping'.");
}

#[test]
fn audit_records_create_and_update_with_previous_id() {
    let e = AppEnv::new();
    let s = spec(json!({}));
    e.store.save_tool(&s, "root", &e.tools_rev(), None).unwrap();
    let mut renamed = s.clone();
    renamed.insert("id".into(), json!("demo.pong"));
    e.store.save_tool(&renamed, "root", &e.tools_rev(), Some("demo.ping")).unwrap();
    let lines = e.audit_lines();
    let create = lines.iter().find(|l| l["action"] == "tool_create").unwrap();
    assert_eq!(create["previous_id"], Value::Null);
    assert_eq!(create["target"], "demo.ping");
    let update = lines.iter().find(|l| l["action"] == "tool_update").unwrap();
    assert_eq!(update["previous_id"], "demo.ping");
    assert_eq!(update["target"], "demo.pong");
}

#[test]
fn replacing_an_unknown_tool_is_refused() {
    let e = AppEnv::new();
    let err = e.store.save_tool(&spec(json!({})), "root", &e.tools_rev(), Some("demo.nothing")).unwrap_err();
    assert_eq!(err.message, "No tool with ID 'demo.nothing'.");
    assert!(err.is_write_refused());
}

#[test]
fn written_file_reloads_cleanly() {
    let e = AppEnv::new();
    e.store.set_tool_enabled("demo.echo", false, "root", &e.tools_rev()).unwrap();
    let fresh = load_catalog(&e.tools_path, &e.service.tier1(), true).unwrap();
    assert!(!fresh.tools["demo.echo"].enabled);
    let a: std::collections::BTreeSet<_> = fresh.tools.keys().collect();
    let cat = e.service.catalog();
    let b: std::collections::BTreeSet<_> = cat.tools.keys().collect();
    assert_eq!(a, b);
}

#[test]
fn identity_lifecycle() {
    let e = AppEnv::new();
    let token = e
        .store
        .create_identity("fresh", "agent", &["demo.show".into()], &["stack:media-*".into()], "root", &e.ids_rev(), "")
        .unwrap();
    assert!(token.starts_with("gk_"));
    assert_eq!(e.identities.read().authenticate(&token).unwrap().id, "fresh");

    e.store
        .save_identity(
            "fresh",
            "agent",
            &["demo.show".into(), "demo.echo".into()],
            &["stack:*".into()],
            "root",
            &e.ids_rev(),
            Some("fresh"),
            "",
        )
        .unwrap();
    let tools: Vec<String> = e.identity("fresh").tools.into_iter().collect();
    assert_eq!(tools, ["demo.echo", "demo.show"]);
    assert!(e.identities.read().authenticate(&token).is_some());

    let rotated = e.store.rotate_token("fresh", "root", &e.ids_rev()).unwrap();
    assert!(e.identities.read().authenticate(&rotated).is_some());
    assert!(e.identities.read().authenticate(&token).is_none(), "old token must be dead");

    e.store.delete_identity("fresh", "root", &e.ids_rev()).unwrap();
    assert!(e.identities.read().authenticate(&rotated).is_none());
}

#[test]
fn new_identity_token_is_never_logged() {
    let e = AppEnv::new();
    let token = e.store.create_identity("quiet", "agent", &[], &[], "root", &e.ids_rev(), "").unwrap();
    let log = e.audit_text();
    assert!(!log.contains(&token));
    assert!(log.contains("identity_create"));
}

#[test]
fn cannot_delete_the_last_admin() {
    let e = AppEnv::new();
    let err = e.store.delete_identity("root", "root", &e.ids_rev()).unwrap_err();
    assert!(err.is_write_refused());
    assert!(err.message.contains("no identity with role 'admin'"));
    assert_eq!(
        err.message,
        "Refused: deleting 'root' would leave no identity with role 'admin', and nobody could sign in to create one."
    );
    assert!(e.identities.read().identities.contains_key("root"));
}

#[test]
fn cannot_demote_the_last_admin() {
    let e = AppEnv::new();
    assert!(e.store.save_identity("root", "viewer", &[], &[], "root", &e.ids_rev(), Some("root"), "").is_err());
    assert_eq!(e.identity("root").role, "admin");
}

#[test]
fn stale_revision_is_refused() {
    let e = AppEnv::new();
    let stale = e.tools_rev();
    e.store.set_tool_enabled("demo.echo", false, "a", &stale).unwrap();
    let err = e.store.set_tool_enabled("demo.show", false, "b", &stale).unwrap_err();
    assert!(err.message.contains("changed since"));
}

#[test]
fn unknown_tool_right_is_refused() {
    let e = AppEnv::new();
    let err = e.store.create_identity("typo", "agent", &["demo.tpyo".into()], &[], "root", &e.ids_rev(), "").unwrap_err();
    assert_eq!(err.message, "Unknown tool IDs: demo.tpyo");
}

#[test]
fn duplicate_ids_are_refused() {
    let e = AppEnv::new();
    let err = e.store.create_identity("root", "admin", &[], &[], "root", &e.ids_rev(), "").unwrap_err();
    assert_eq!(err.message, "An identity 'root' already exists.");
}

#[test]
fn invalid_identity_ids_and_roles_are_refused() {
    let e = AppEnv::new();
    let err = e.store.create_identity("a b", "agent", &[], &[], "root", &e.ids_rev(), "").unwrap_err();
    assert_eq!(err.message, "Identity ID must be alphanumeric (dashes and underscores allowed).");
    let err = e.store.create_identity("-", "agent", &[], &[], "root", &e.ids_rev(), "").unwrap_err();
    assert!(err.message.starts_with("Identity ID must be alphanumeric"));
    let err = e.store.create_identity("ok-id_1", "god", &[], &[], "root", &e.ids_rev(), "").unwrap_err();
    assert_eq!(err.message, "Unknown role 'god'.");
}

#[test]
fn save_identity_without_replaces_points_to_create() {
    let e = AppEnv::new();
    let err = e.store.save_identity("newbie", "agent", &[], &[], "root", &e.ids_rev(), None, "").unwrap_err();
    assert_eq!(err.message, "Use create_identity() for new entries -- a token is required.");
}

#[test]
fn deleting_a_tool_records_the_definition() {
    let e = AppEnv::new();
    e.store.delete_tool("demo.echo", "root", &e.tools_rev()).unwrap();
    let lines = e.audit_lines();
    let deletion = lines.iter().rev().find(|l| l["action"] == "tool_delete").unwrap();
    assert_eq!(deletion["spec"]["id"], "demo.echo");
    assert!(!deletion["spec"]["argv"].as_array().unwrap().is_empty());
}

#[test]
fn dangling_grant_is_recorded() {
    let e = AppEnv::new();
    e.store.delete_tool("demo.show", "root", &e.tools_rev()).unwrap();
    let lines = e.audit_lines();
    let note = lines.iter().rev().find(|l| l["action"] == "dangling_grant").unwrap();
    assert_eq!(note["kind"], "admin_note");
    assert!(note["identities"].as_array().unwrap().contains(&json!("bot")));
}

#[test]
fn write_refused_on_read_only_directory() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores permission bits
    }
    let e = AppEnv::new();
    let dir = std::path::Path::new(&e.tools_path).parent().unwrap().to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let err = e.store.set_tool_enabled("demo.echo", false, "root", &e.tools_rev()).unwrap_err();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(err.message, "tools.yaml is not writable. The file or its directory is mounted read-only.");
}

#[test]
fn bad_yaml_is_reported_not_raised_raw() {
    let err = load_tool_yaml("id: [unclosed").unwrap_err();
    assert!(err.message.contains("Not valid YAML"));
    assert!(err.is_write_refused());
    let err = load_tool_yaml("tools:\n  - id: a.b\n").unwrap_err();
    assert!(err.message.contains("one tool definition"));
    let err = load_tool_yaml("- a\n- b\n").unwrap_err();
    assert_eq!(err.message, "Expected a single tool definition as a YAML mapping.");
    let ok = load_tool_yaml("id: a.b\ntitle: T\n").unwrap();
    assert_eq!(ok["id"], "a.b");
    // tool_to_yaml round-trips.
    assert_eq!(load_tool_yaml(&tool_to_yaml(&ok)).unwrap(), ok);
}

#[test]
fn console_password_is_stored_only_as_a_hash() {
    let e = AppEnv::new();
    let secret = "a-fresh-console-password";
    e.store.set_password("eye", secret, "root", &e.ids_rev(), "", false).unwrap();
    let on_disk = e.read(&e.identities_path);
    assert!(!on_disk.contains(secret));
    assert!(on_disk.contains("password_hash: scrypt$"));
    let log = e.audit_text();
    assert!(!log.contains(secret));
    assert!(log.contains("password_set"));
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "password_set").unwrap();
    assert_eq!(line["self_service"], false);
    assert_eq!(e.identities.read().authenticate_console("eye", secret).unwrap().role, "viewer");
}

#[test]
fn self_service_needs_the_current_password() {
    let e = AppEnv::new();
    let err = e.store.set_password("eye", "another-long-password", "eye", &e.ids_rev(), "wrong", true).unwrap_err();
    assert_eq!(err.message, "The current password is not correct.");
    e.store.set_password("eye", "another-long-password", "eye", &e.ids_rev(), EYE_PASSWORD, true).unwrap();
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "password_set").unwrap();
    assert_eq!(line["self_service"], true);
}

#[test]
fn a_short_password_is_refused() {
    let e = AppEnv::new();
    let err = e.store.set_password("eye", "short", "root", &e.ids_rev(), "", false).unwrap_err();
    assert_eq!(err.message, "The console password must be at least 12 characters long.");
}

#[test]
fn an_agent_gets_no_console_password() {
    let e = AppEnv::new();
    let err = e.store.set_password("bot", "a-password-anyway", "root", &e.ids_rev(), "", false).unwrap_err();
    assert_eq!(
        err.message,
        "'bot' has role 'agent' and does not sign in to the console. A password would change nothing."
    );
    let err = e
        .store
        .create_identity("bot2", "agent", &[], &[], "root", &e.ids_rev(), "a-password-anyway")
        .unwrap_err();
    assert_eq!(
        err.message,
        "role 'agent' cannot sign in to the console, so a password would be a door without a room. \
         Choose viewer or admin instead."
    );
}

#[test]
fn a_console_role_needs_a_password_from_the_start() {
    let e = AppEnv::new();
    let err = e.store.create_identity("ghost", "viewer", &[], &[], "root", &e.ids_rev(), "").unwrap_err();
    assert_eq!(err.message, "role 'viewer' signs in to the console and therefore needs a password.");
    assert!(!e.identities.read().identities.contains_key("ghost"));
}

#[test]
fn promoting_an_agent_requires_a_password() {
    let e = AppEnv::new();
    let err = e
        .store
        .save_identity("bot", "viewer", &["demo.show".into()], &["stack:*".into()], "root", &e.ids_rev(), Some("bot"), "")
        .unwrap_err();
    assert_eq!(
        err.message,
        "role 'viewer' needs a console password -- without one, 'bot' could not sign in. Set one in this form."
    );
    assert_eq!(e.identity("bot").role, "agent");
}

#[test]
fn demoting_drops_the_password() {
    let e = AppEnv::new();
    e.store.save_identity("eye", "agent", &[], &[], "root", &e.ids_rev(), Some("eye"), "").unwrap();
    assert_eq!(e.identity("eye").password_hash, "");
    let on_disk = e.load_yaml(&e.identities_path);
    let entry = on_disk["identities"].as_array().unwrap().iter().find(|i| i["id"] == "eye").unwrap().clone();
    assert!(entry.get("password_hash").is_none());
    let line = e.audit_lines().into_iter().find(|l| l["action"] == "identity_update").unwrap();
    assert_eq!(line["password_changed"], false);
    assert_eq!(line["previous_id"], Value::Null);
}

#[test]
fn the_last_signed_in_admin_cannot_lose_the_console() {
    let e = AppEnv::new();
    let mut payload = e.load_yaml(&e.identities_path);
    payload["identities"].as_array_mut().unwrap().push(json!({
        "id": "halfadmin", "role": "admin", "token_hash": hash_token(&generate_token()),
        "tools": [], "scopes": [],
    }));
    write(std::path::Path::new(&e.identities_path), &gatekeeper::yaml::dump(&payload));
    e.identities.write().identities = load_identities(&e.identities_path).unwrap().identities;

    let err = e.store.delete_identity("root", "root", &e.ids_rev()).unwrap_err();
    assert!(err.message.contains("console password"));
    assert_eq!(
        err.message,
        "Refused: deleting 'root' would leave no administrator with a console password, and nobody could sign in to set one."
    );
    assert!(e.identities.read().identities.contains_key("root"));
}

#[test]
fn a_password_on_an_agent_role_never_reaches_the_file() {
    let e = AppEnv::new();
    let before = e.read(&e.identities_path);
    let err = e
        .store
        .save_identity("eye", "agent", &[], &[], "root", &e.ids_rev(), Some("eye"), "a-password-for-nobody")
        .unwrap_err();
    assert!(err.message.contains("door without a room"));
    assert_eq!(e.read(&e.identities_path), before);
    assert_eq!(load_identities(&e.identities_path).unwrap().identities["eye"].role, "viewer");
}

#[test]
fn bare_tool_ids_expand_to_destination_ids() {
    // A multi-destination toolkit's tools exist only as `<id>@<dest>`.
    let e = builder()
        .tier1(json!({
            "toolkits": {"dock": {"executor": "docker", "binaries": ["/usr/bin/docker"],
                                  "destinations": ["nas1", "nas2"]}},
            "destinations": {"nas1": {"docker_host": "tcp://10.0.0.1:2375"},
                             "nas2": {"docker_host": "tcp://10.0.0.2:2375"}},
        }))
        .tools(vec![json!({
            "id": "dock.ps", "toolkit": "dock", "binary": "/usr/bin/docker", "title": "ps",
            "description": "ps", "category": "read", "idempotent": true, "enabled": true,
            "argv": ["ps"], "parameters": {}, "required_scopes": [],
            "timeout_seconds": 5, "max_output_bytes": 1024,
        })])
        .build();
    e.store.create_identity("x", "agent", &["dock.ps".into()], &[], "root", &e.ids_rev(), "").unwrap();
    let tools: Vec<String> = e.identity("x").tools.into_iter().collect();
    assert_eq!(tools, ["dock.ps@nas1", "dock.ps@nas2"]);
}

#[test]
fn set_password_in_file_messages() {
    let e = AppEnv::new();
    let p = e.identities_path.clone();
    let err = set_password_in_file(&p, "nobody", "long-enough-password").unwrap_err();
    assert_eq!(err.message, format!("No identity 'nobody' in {p}. Known: bot, eye, root"));
    let err = set_password_in_file(&p, "bot", "long-enough-password").unwrap_err();
    assert_eq!(
        err.message,
        "'bot' has role 'agent' and does not sign in to the console. Only viewer and admin do."
    );
    let err = set_password_in_file(&p, "eye", "short").unwrap_err();
    assert_eq!(err.message, "The console password must be at least 12 characters long.");
    set_password_in_file(&p, "eye", "long-enough-password").unwrap();
    let fresh = load_identities(&p).unwrap();
    assert!(fresh.authenticate_console("eye", "long-enough-password").is_some());
}

#[test]
fn fingerprints_match_python() {
    // python3 -c 'import json,hashlib; print(hashlib.sha256(json.dumps(
    //   {"id":"a","b":[1,"ü"]}, sort_keys=True, default=str).encode()).hexdigest()[:16])'
    assert_eq!(fingerprint(None), "");
    assert_eq!(fingerprint(Some(&json!({"id": "a", "b": [1, "ü"]}))), "850f1eebaf983985");
}

#[test]
fn per_record_revisions_ignore_other_records() {
    let e = AppEnv::new();
    let show = e.store.tool_revision("demo.show");
    let bot = e.store.identity_revision("bot");
    assert_eq!(show.len(), 16);
    assert_eq!(e.store.tool_revision("demo.nothing"), "");
    assert_eq!(e.store.identity_revision("nobody"), "");
    e.store.set_tool_enabled("demo.echo", false, "root", &e.tools_rev()).unwrap();
    e.store.set_password("eye", "another-long-password", "root", &e.ids_rev(), "", false).unwrap();
    assert_eq!(e.store.tool_revision("demo.show"), show);
    assert_eq!(e.store.identity_revision("bot"), bot);
    e.store.set_tool_enabled("demo.show", false, "root", &e.tools_rev()).unwrap();
    assert_ne!(e.store.tool_revision("demo.show"), show);
    let w = e.store.writability();
    assert_eq!(serde_json::Value::Object(w), json!({"tools": true, "identities": true}));
}
