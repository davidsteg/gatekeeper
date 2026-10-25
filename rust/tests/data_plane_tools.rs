//! The 1.25.0 tool features the CastorCloud node builds on: a fixed
//! `stdin` text, file `delete`, a fixed file `mode`, a secret file
//! `content`, and the opt-in `structuredContent`; plus the 1.28.0 bound
//! on `delete` (`delete: {max_entries, files_only}`).

mod app_env;

use std::os::unix::fs::PermissionsExt;

use app_env::*;
use gatekeeper::catalog::load_catalog;
use gatekeeper::tier1::load_tier1;
use serde_json::{json, Value};

const SQL: &str = "SELECT 1;\nSELECT 'two lines';\n";
const SECRET: &str = "cGFzc3dvcmQtdGhhdC1tdXN0LW5vdC1sZWFr";

fn local_tier1(structured: bool) -> Value {
    json!({"toolkits": {"db": {"executor": "local", "binaries": ["/bin/cat"],
        "max_timeout_seconds": 10, "max_output_bytes": 4096, "structured_content": structured}}})
}

fn cat_tool() -> Value {
    json!({"id": "db.migrate", "toolkit": "db", "binary": "/bin/cat", "version": 1,
           "title": "Migrate", "description": "Feeds the fixed script to the binary.",
           "category": "write", "idempotent": true, "enabled": true,
           "argv": [], "stdin": SQL, "parameters": {}, "required_scopes": [],
           "timeout_seconds": 10, "max_output_bytes": 4096})
}

#[tokio::test]
async fn a_fixed_stdin_reaches_the_process_and_only_its_size_is_logged() {
    let e = builder().tier1(local_tier1(false)).tools(vec![cat_tool()]).build();
    let who = agent("node", &["db.migrate"], &[]);
    let result = e.service.call(&who, "db.migrate", &args(json!({})), None).await.unwrap();
    assert_eq!(result.outcome, "ok", "{}", result.stderr);
    assert_eq!(result.stdout, SQL);
    assert!(!result.structured);
    let record = e.audit_lines().pop().unwrap();
    assert_eq!(record["command"], format!("/bin/cat < [stdin: {} bytes]", SQL.len()));
}

#[tokio::test]
async fn structured_content_is_opt_in_per_toolkit() {
    let e = builder().tier1(local_tier1(true)).tools(vec![cat_tool()]).build();
    let who = agent("node", &["db.migrate"], &[]);
    let result = e.service.call(&who, "db.migrate", &args(json!({})), None).await.unwrap();
    assert!(result.structured);
}

fn file_env(tools: Vec<Value>) -> (AppEnv, String) {
    let root = tempfile::tempdir().unwrap().keep();
    let root = root.to_str().unwrap().to_string();
    let tk = json!({"executor": "file", "path_roots": [root], "protected_resources": ["gatekeeper"]});
    (builder().tier1(json!({"toolkits": {"files": tk}})).tools(tools).build(), root)
}

fn path_param() -> Value {
    json!({"type": "string", "required": true, "pattern": "^/.*"})
}

fn file_tool(id: &str, op: &str, extra: Value) -> Value {
    let mut spec = json!({"id": id, "toolkit": "files", "category": "write", "file_operation": op,
                          "enabled": true, "parameters": {"path": path_param()}});
    for (k, v) in extra.as_object().unwrap() {
        spec[k] = v.clone();
    }
    spec
}

fn content_param(secret: bool) -> Value {
    json!({"type": "string", "required": true, "pattern": "[\\s\\S]*",
           "allow_control_characters": true, "secret": secret})
}

#[tokio::test]
async fn delete_removes_a_tree_but_never_a_root_or_a_protected_resource() {
    let (e, root) = file_env(vec![file_tool("files.delete", "delete", json!({}))]);
    let who = agent("node", &["files.delete"], &[]);
    std::fs::create_dir_all(format!("{root}/t/alpha/sub")).unwrap();
    std::fs::write(format!("{root}/t/alpha/sub/f"), "x").unwrap();
    let call = |p: String| {
        let e = &e;
        let who = &who;
        async move { e.service.call(who, "files.delete", &args(json!({"path": p})), None).await.unwrap() }
    };

    let r = call(format!("{root}/t/alpha")).await;
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
    assert!(!std::path::Path::new(&format!("{root}/t/alpha")).exists());

    // Deleting again: nothing there, which is not a failure.
    let r = call(format!("{root}/t/alpha")).await;
    assert_eq!(r.outcome, "ok", "{}", r.stderr);

    let r = call(root.clone()).await;
    assert_ne!(r.outcome, "ok");
    assert!(std::path::Path::new(&root).exists());

    std::fs::create_dir_all(format!("{root}/t/beta/gatekeeper")).unwrap();
    let r = call(format!("{root}/t/beta")).await;
    assert_ne!(r.outcome, "ok");
    assert!(r.stderr.contains("protected"), "{}", r.stderr);
    assert!(std::path::Path::new(&format!("{root}/t/beta/gatekeeper")).exists());

    // A symlink inside the tree is removed, not followed.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("keep"), "x").unwrap();
    std::fs::create_dir_all(format!("{root}/t/gamma")).unwrap();
    std::os::unix::fs::symlink(outside.path(), format!("{root}/t/gamma/link")).unwrap();
    let r = call(format!("{root}/t/gamma")).await;
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
    assert!(outside.path().join("keep").exists());
}

#[tokio::test]
async fn a_delete_block_bounds_the_tree_before_anything_goes() {
    let bounded = file_tool("files.prune", "delete", json!({"delete": {"max_entries": 2, "files_only": true}}));
    let (e, root) = file_env(vec![bounded]);
    let who = agent("node", &["files.prune"], &[]);
    let call = |p: String| {
        let e = &e;
        let who = &who;
        async move { e.service.call(who, "files.prune", &args(json!({"path": p})), None).await.unwrap() }
    };

    std::fs::create_dir_all(format!("{root}/many")).unwrap();
    for name in ["a", "b", "c"] {
        std::fs::write(format!("{root}/many/{name}"), "x").unwrap();
    }
    let r = call(format!("{root}/many")).await;
    assert_eq!(r.outcome, "failed");
    assert!(r.stderr.contains("more than 2 entries (max_entries)"), "{}", r.stderr);
    assert!(std::path::Path::new(&format!("{root}/many/a")).exists());

    std::fs::create_dir_all(format!("{root}/nested/sub")).unwrap();
    let r = call(format!("{root}/nested")).await;
    assert!(r.stderr.contains("sub-directory 'sub' (files_only)"), "{}", r.stderr);
    assert!(std::path::Path::new(&format!("{root}/nested/sub")).exists());

    std::fs::create_dir_all(format!("{root}/two")).unwrap();
    std::fs::write(format!("{root}/two/a"), "x").unwrap();
    std::fs::write(format!("{root}/two/b"), "x").unwrap();
    let r = call(format!("{root}/two")).await;
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
    assert!(!std::path::Path::new(&format!("{root}/two")).exists());

    // A symlinked directory in the path is refused, not resolved to its target.
    std::fs::create_dir_all(format!("{root}/real")).unwrap();
    std::fs::write(format!("{root}/real/f"), "x").unwrap();
    std::os::unix::fs::symlink(format!("{root}/real"), format!("{root}/alias")).unwrap();
    let r = call(format!("{root}/alias/f")).await;
    assert_ne!(r.outcome, "ok");
    assert!(std::path::Path::new(&format!("{root}/real/f")).exists());
}

#[tokio::test]
async fn a_fixed_mode_and_a_secret_content_that_stays_out_of_the_log() {
    let tool = file_tool(
        "files.put_key",
        "write",
        json!({"mode": "0600", "parameters": {"path": path_param(), "content": content_param(true)}}),
    );
    let (e, root) = file_env(vec![tool]);
    let who = agent("node", &["files.put_key"], &[]);
    let path = format!("{root}/key");
    let r = e.service.call(&who, "files.put_key", &args(json!({"path": path, "content": SECRET})), None).await.unwrap();
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), SECRET);
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let record = e.audit_lines().pop().unwrap();
    assert_eq!(record["parameters"]["content"], "***");
    assert!(!e.audit_text().contains(SECRET));
}

fn refused(tier1: Value, tool: Value) -> String {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = tier1;
    doc["audit"] = json!({"dir": dir.path().join("logs").to_str().unwrap()});
    let t1 = write(&dir.path().join("toolkits.yaml"), &gatekeeper::yaml::dump(&doc));
    let t2 = write(&dir.path().join("tools.yaml"), &gatekeeper::yaml::dump(&json!({"tools": [tool]})));
    let tier1 = load_tier1(&t1).unwrap();
    match load_catalog(&t2, &tier1, true) {
        Ok(_) => panic!("loaded"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn the_good_definitions_load_strictly() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = local_tier1(true);
    doc["audit"] = json!({"dir": dir.path().join("logs").to_str().unwrap()});
    let t1 = write(&dir.path().join("toolkits.yaml"), &gatekeeper::yaml::dump(&doc));
    let t2 = write(&dir.path().join("tools.yaml"), &gatekeeper::yaml::dump(&json!({"tools": [cat_tool()]})));
    load_catalog(&t2, &load_tier1(&t1).unwrap(), true).unwrap();
}

#[test]
fn bad_definitions_are_refused_at_load() {
    let files = json!({"toolkits": {"files": {"executor": "file", "path_roots": ["/tmp"]}}});
    let content = json!({"path": path_param(), "content": content_param(false)});
    for (mode, op) in [(json!("0777"), "write"), (json!(384), "write"), (json!("0644"), "patch")] {
        let tool = file_tool("files.x", op, json!({"mode": mode, "category": "write", "parameters": content}));
        assert!(refused(files.clone(), tool).contains("'mode'"));
    }
    let delete = file_tool("files.x", "delete", json!({"category": "read"}));
    assert!(refused(files.clone(), delete).contains("delete"));
    for (block, want) in [
        (json!({"max_entries": 0}), "'delete.max_entries'"),
        (json!({"max_entries": 100_001}), "MAX_DELETE_ENTRIES"),
        (json!({"max_entries": "5"}), "'delete.max_entries'"),
        (json!({"files_only": "yes"}), "'delete.files_only'"),
        (json!({"depth": 3}), "unknown keys ['depth']"),
        (json!([1]), "'delete' must be a mapping"),
    ] {
        let tool = file_tool("files.x", "delete", json!({"delete": block}));
        let err = refused(files.clone(), tool);
        assert!(err.contains(want), "{err}");
    }
    let not_delete = file_tool("files.x", "write", json!({"delete": {"max_entries": 5},
        "parameters": {"path": path_param(), "content": content_param(false)}}));
    assert!(refused(files.clone(), not_delete).contains("only apply to file_operation: delete"));

    // A secret is not allowed into a path, nor onto a local command line.
    let secret_path = file_tool(
        "files.x",
        "write",
        json!({"parameters": {"path": {"type": "string", "required": true, "pattern": "^/.*", "secret": true},
                              "content": content_param(false)}}),
    );
    assert!(refused(files, secret_path).contains("secret"));
    let mut echo = cat_tool();
    echo["argv"] = json!(["{x}"]);
    echo["parameters"] = json!({"x": {"type": "string", "required": true, "pattern": "^.*$", "secret": true}});
    assert!(refused(local_tier1(false), echo).contains("secret"));

    // stdin is fixed text, and only on docker/local.
    let mut long = cat_tool();
    long["stdin"] = json!("x".repeat(65537));
    assert!(refused(local_tier1(false), long).contains("stdin"));
    let ssh = json!({"toolkits": {"db": {"executor": "ssh", "ssh_host": "h.lan", "ssh_user": "u",
        "ssh_known_hosts": "h.lan ssh-ed25519 AAAAC3Nza", "binaries": ["/bin/cat"],
        "max_timeout_seconds": 10, "max_output_bytes": 4096}}});
    let msg = refused(ssh, cat_tool());
    assert!(msg.contains("stdin"), "{msg}");
}
