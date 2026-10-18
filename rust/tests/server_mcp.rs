//! Both MCP mounts of the real application over a loopback socket (ports
//! of `test_mcp_live_catalog.py`, the wiring parts of
//! `test_notifications.py`, the MCP parts of `test_admin_mcp.py`, and the
//! `SessionReaper` half of `test_realip.py`).

mod app_env;
mod server_env;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use app_env::*;
use gatekeeper::mcp::SessionChannel;
use serde_json::{json, Value};
use server_env::*;

/// The reported sequence: tool_create, tool_enable, grant_set.
fn create_and_grant(env: &AppEnv, tool_id: &str) {
    let mut spec = env.service.catalog().raw[0].as_object().unwrap().clone();
    spec.insert("id".into(), json!(tool_id));
    spec.remove("versions");
    let new_id = env.store.save_tool(&spec, "admin", &env.tools_rev(), None).unwrap();
    env.store.set_tool_enabled(&new_id, true, "admin", &env.tools_rev()).unwrap();
    let existing = env.identity("full");
    let mut tools: Vec<String> = existing.tools.iter().cloned().collect();
    tools.push(new_id);
    env.store
        .save_identity("full", "agent", &tools, &existing.scopes, "admin", &env.ids_rev(), Some("full"), "")
        .unwrap();
}

// -- test_mcp_live_catalog.py ---------------------------------------------------------

#[tokio::test]
async fn the_server_side_is_live_without_a_restart() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    assert!(!client.tool_names().await.contains(&"demo.brandnew".to_string()));
    create_and_grant(&env, "demo.brandnew");
    assert!(client.tool_names().await.contains(&"demo.brandnew".to_string()));
}

#[tokio::test]
async fn a_new_tool_is_callable_on_the_same_session() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    create_and_grant(&env, "demo.freshcall");
    let (text, _) = client.call_text("demo.freshcall", json!({"stack": "media-a"})).await;
    assert!(!text.contains("does not exist"), "{text}");
    assert!(!text.to_lowercase().contains("not authorized"), "{text}");
    assert_ne!(text, gatekeeper::errors::OPAQUE_DENIAL);
}

#[tokio::test]
async fn initialize_advertises_tools_list_changed() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    assert_eq!(client.init["result"]["capabilities"]["tools"]["listChanged"], true);
    // The agent mount retains sessions (test_notifications.py).
    assert!(client.session.is_some());
    assert_eq!(gatekeeper::server::SESSION_IDLE_TIMEOUT_SECONDS, 3600);
}

#[tokio::test]
async fn discover_advertises_tools_list_changed() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut client = Mcp::modern(&base, "/mcp", &tokens.full);
    let d = client.request("server/discover", json!({})).await;
    assert_eq!(d["result"]["capabilities"]["tools"]["listChanged"], true);
    assert_eq!(
        d["result"]["_meta"]["io.modelcontextprotocol/serverInfo"],
        json!({"name": "gatekeeper", "version": gatekeeper::VERSION})
    );
}

async fn listen(base: &str, token: &str) -> Frames {
    let r = post_json(
        base,
        "/mcp",
        Some(token),
        json!({"jsonrpc": "2.0", "id": 40, "method": "subscriptions/listen", "params": {
            "notifications": {"toolsListChanged": true},
            "_meta": {"io.modelcontextprotocol/protocolVersion": MODERN,
                      "io.modelcontextprotocol/clientCapabilities": {},
                      "io.modelcontextprotocol/clientInfo": {"name": "rust-test", "version": "1"}}}}),
        &[("mcp-protocol-version", MODERN), ("mcp-method", "subscriptions/listen")],
    )
    .await;
    assert_eq!(r.status(), 200);
    let mut frames = Frames::new(r);
    let ack = frames.next().await.unwrap();
    assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
    assert_eq!(ack["params"]["notifications"], json!({"toolsListChanged": true}));
    frames
}

#[tokio::test]
async fn a_tool_change_notifies_a_listening_session() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut stream = listen(&base, &tokens.full).await;
    create_and_grant(&env, "demo.announced");
    assert_eq!(stream.next().await.unwrap()["method"], "notifications/tools/list_changed");
    // The re-fetch it prompts is not empty.
    let names = Mcp::modern(&base, "/mcp", &tokens.full).tool_names().await;
    assert!(names.contains(&"demo.announced".to_string()));
}

#[tokio::test]
async fn every_listening_session_is_notified_not_just_one() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut first = listen(&base, &tokens.full).await;
    let mut second = listen(&base, &tokens.narrow).await;
    create_and_grant(&env, "demo.fanout");
    for stream in [&mut first, &mut second] {
        assert_eq!(stream.next().await.unwrap()["method"], "notifications/tools/list_changed");
    }
}

#[tokio::test]
async fn a_handshake_era_session_is_notified_on_its_standalone_stream() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    let sid = client.session.clone().unwrap();
    let r = http()
        .get(format!("{base}/mcp"))
        .bearer_auth(&tokens.full)
        .header("accept", "text/event-stream")
        .header("mcp-session-id", &sid)
        .header("mcp-protocol-version", "2025-11-25")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let mut stream = Frames::new(r);
    // The GET stream registers asynchronously; change until it delivers.
    let mut delivered = None;
    for i in 0..20 {
        create_and_grant(&env, &format!("demo.standalone{i}"));
        if let Ok(Some(frame)) = tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
            delivered = Some(frame);
            break;
        }
    }
    assert_eq!(delivered.expect("a frame")["method"], "notifications/tools/list_changed");
}

// -- test_notifications.py: which writes announce ---------------------------------------

#[derive(Default)]
struct FakeSession {
    sent: AtomicUsize,
}

impl SessionChannel for FakeSession {
    fn send_tool_list_changed(&self) -> Result<(), ()> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn every_catalog_write_announces_a_change() {
    let (env, _) = standard_env();
    let notifier = env.service.catalog_notifier.clone();
    notifier.bind_current();
    let session = Arc::new(FakeSession::default());
    notifier.track_channel("abc", session.clone());

    let mut spec = env.service.catalog().raw[0].as_object().unwrap().clone();
    spec.insert("id".into(), json!("demo.created"));
    spec.remove("versions");
    let mut count = 0;
    let mut announced = |label: &str| {
        let now = session.sent.load(Ordering::SeqCst);
        assert!(now > count, "{label} did not announce");
        count = now;
    };

    env.store.save_tool(&spec, "admin", &env.tools_rev(), None).unwrap();
    settle().await;
    announced("tool_create");
    env.store.set_tool_enabled("demo.created", true, "admin", &env.tools_rev()).unwrap();
    settle().await;
    announced("tool_enable");
    env.store.set_tool_enabled("demo.created", false, "admin", &env.tools_rev()).unwrap();
    settle().await;
    announced("tool_disable");
    env.store.delete_tool("demo.created", "admin", &env.tools_rev()).unwrap();
    settle().await;
    announced("tool_delete");
    let existing = env.identity("full");
    let tools: Vec<String> = existing.tools.iter().cloned().collect();
    env.store
        .save_identity("full", "agent", &tools, &existing.scopes, "admin", &env.ids_rev(), Some("full"), "")
        .unwrap();
    settle().await;
    announced("grant_set");
}

#[tokio::test]
async fn a_tier1_reload_announces_a_change() {
    let (env, _) = standard_env();
    let notifier = env.service.catalog_notifier.clone();
    notifier.bind_current();
    let session = Arc::new(FakeSession::default());
    notifier.track_channel("abc", session.clone());
    let before = session.sent.load(Ordering::SeqCst);
    let error = env.service.reload_config(&env.toolkits_path, &env.tools_path, &env.identities_path);
    assert_eq!(error, None);
    settle().await;
    assert_eq!(session.sent.load(Ordering::SeqCst), before + 1);
}

// -- SessionReaper (test_realip.py) ---------------------------------------------------------

#[tokio::test]
async fn a_delete_on_mcp_forgets_the_session() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    let sid = client.session.clone().unwrap();
    let notifier = &env.service.catalog_notifier;
    assert!(notifier.is_tracked(&sid));
    // An unauthenticated DELETE never reaches the reaper.
    let r = http().delete(format!("{base}/mcp")).header("mcp-session-id", &sid).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert!(notifier.is_tracked(&sid));
    let r = http()
        .delete(format!("{base}/mcp"))
        .bearer_auth(&tokens.full)
        .header("mcp-session-id", &sid)
        .header("mcp-protocol-version", "2025-11-25")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(!notifier.is_tracked(&sid));
}

// -- test_admin_mcp.py: the MCP wiring ----------------------------------------------------

struct AdminEnv {
    env: AppEnv,
    base: String,
    hermes: String,
    root: String,
    bot: String,
    eye: String,
}

async fn admin_env(with_credentials: bool) -> AdminEnv {
    let (hermes, hermes_t) = server_env::identity("hermes", "admin", &[], &[], None);
    let (root, root_t) = server_env::identity("root", "admin", &[], &[], Some(ROOT_PASSWORD));
    let (bot, bot_t) = server_env::identity("bot", "agent", &["demo.show"], &["stack:*"], None);
    let (eye, eye_t) = server_env::identity("eye", "viewer", &[], &[], Some(EYE_PASSWORD));
    let mut b = builder().identities(vec![hermes, root, bot, eye]);
    if with_credentials {
        b = b.credentials();
    }
    let env = b.build();
    let base = serve(full_app(&env)).await;
    AdminEnv { env, base, hermes: hermes_t, root: root_t, bot: bot_t, eye: eye_t }
}

fn payload(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

#[tokio::test]
async fn both_mcp_endpoints_answer_over_one_app() {
    let a = admin_env(false).await;
    let agent_tools = Mcp::connect(&a.base, "/mcp", &a.bot).await.tool_names().await;
    let admin_tools = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await.tool_names().await;
    assert!(agent_tools.contains(&"demo.show".to_string()));
    assert!(admin_tools.contains(&"admin.tool_list".to_string()));
    assert!(admin_tools.contains(&"admin.tool_get".to_string()));
    // Modern clients reach both as well.
    assert!(Mcp::modern(&a.base, "/admin/mcp", &a.root).tool_names().await.contains(&"admin.tool_list".to_string()));
}

#[tokio::test]
async fn admin_tools_never_appear_on_mcp_and_vice_versa() {
    let a = admin_env(false).await;
    let names = Mcp::connect(&a.base, "/admin/mcp", &a.root).await.tool_names().await;
    assert!(names.iter().all(|n| n.starts_with("admin.")));
    assert!(!names.contains(&"demo.show".to_string()));
    // The fixed list, exactly as the module defines it.
    let listed = Mcp::modern(&a.base, "/admin/mcp", &a.root).list_tools().await;
    assert_eq!(listed, gatekeeper::admin_server::admin_tools());
}

#[tokio::test]
async fn each_mount_rejects_the_other_roles_tokens() {
    let a = admin_env(false).await;
    for (path, token) in [("/mcp", &a.hermes), ("/mcp", &a.root), ("/admin/mcp", &a.bot), ("/admin/mcp", &a.eye)] {
        let r = post_json(&a.base, path, Some(token), json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}), &[]).await;
        assert_eq!(r.status(), 401, "{path}");
    }
    // The stateless admin mount hands out no session.
    let client = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await;
    assert!(client.session.is_none());
}

#[tokio::test]
async fn tool_create_and_validate_reject_a_tier1_violation() {
    let a = admin_env(false).await;
    let bad = |id: &str| {
        json!({"id": id, "toolkit": "demo", "binary": "/not/allowed/binary", "title": "x", "description": "x",
               "category": "read", "idempotent": true, "enabled": false, "argv": [], "parameters": {},
               "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096})
    };
    let mut client = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await;
    let (_, is_error) = client.call_text("admin.tool_create", json!({"spec": bad("demo.hack")})).await;
    assert!(is_error);
    let (text, _) = client.call_text("admin.tool_validate", json!({"spec": bad("demo.hack2")})).await;
    assert_eq!(payload(&text)["ok"], false);
}

#[tokio::test]
async fn tool_create_is_always_disabled_and_rendered_like_json_dumps() {
    let a = admin_env(false).await;
    let spec = json!({"id": "demo.newread", "toolkit": "demo", "binary": SH, "title": "n", "description": "d",
                      "category": "read", "idempotent": true, "enabled": true, "argv": ["-c", "echo 1"],
                      "parameters": {}, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096});
    let mut client = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await;
    let (text, is_error) = client.call_text("admin.tool_create", json!({"spec": spec})).await;
    assert!(!is_error, "{text}");
    let p = payload(&text);
    assert_eq!(p["applied"], true);
    // `json.dumps(result, default=str)`: Python's separators and escaping.
    assert_eq!(text, gatekeeper::pyjson::dumps(&p));
    assert!(text.contains("\"applied\": true"));
    assert!(!a.env.service.catalog().tools["demo.newread"].enabled);
}

#[tokio::test]
async fn approve_and_reject_are_unreachable() {
    let a = admin_env(false).await;
    let mut client = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await;
    let names: BTreeSet<String> = client.tool_names().await.into_iter().collect();
    for absent in ["admin.approve", "admin.reject", "admin.toolkit_deploy", "admin.toolkit_reject"] {
        assert!(!names.contains(absent), "{absent}");
    }
    let (text, is_error) = client.call_text("admin.approve", json!({"id": "whatever"})).await;
    assert!(is_error);
    assert_eq!(text, "Unknown admin tool 'approve'.");
    let (_, is_error) = client.call_text("admin.toolkit_deploy", json!({"proposal_id": "x"})).await;
    assert!(is_error);
}

#[tokio::test]
async fn the_schemas_agents_read() {
    let a = admin_env(true).await;
    let tools = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await.list_tools().await;
    let schema = |name: &str| tools.iter().find(|t| t["name"] == name).unwrap()["inputSchema"].clone();
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<BTreeSet<String>>();

    let updates = &schema("admin.toolkit_update")["properties"]["updates"];
    assert_eq!(keys(&updates["properties"]), [
        "executor", "binaries", "denied_args", "run_as", "allowed_hosts", "allowed_cidrs",
        "allowed_methods", "allowed_path_prefixes", "max_timeout_seconds", "max_output_bytes",
    ]
    .map(String::from)
    .into());
    assert_eq!(updates["additionalProperties"], false);
    assert!(updates["properties"]["run_as"]["type"].as_array().unwrap().contains(&json!("null")));

    let cred = schema("admin.cred_propose");
    assert!(cred["properties"].get("value").is_none());
    assert_eq!(cred["additionalProperties"], false);

    let bind = schema("admin.credential_bind");
    assert_eq!(keys(&bind["properties"]), ["toolkit", "credential"].map(String::from).into());
    let mut required: Vec<&str> = bind["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    required.sort();
    assert_eq!(required, ["credential", "toolkit"]);
    assert_eq!(bind["additionalProperties"], false);

    let delete = schema("admin.cred_delete");
    assert_eq!(keys(&delete["properties"]), ["name"].map(String::from).into());
    assert_eq!(delete["required"], json!(["name"]));
    assert_eq!(delete["additionalProperties"], false);
}

#[tokio::test]
async fn release_notes_are_reachable_over_admin_mcp() {
    let a = admin_env(false).await;
    let before = std::fs::read_to_string(&a.env.tools_path).unwrap();
    let mut client = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await;
    let (text, _) = client.call_text("admin.release_notes", json!({})).await;
    let p = payload(&text);
    assert_eq!(p["current_version"], gatekeeper::VERSION);
    // PORT NOTE: Python compared with `__version__`; see server_http.rs.
    assert_eq!(p["releases"][0]["version"], json!(gatekeeper::release_notes::load()[0].0));
    assert_eq!(p["count"], 10);
    assert_eq!(p["truncated"], true);
    let (text, _) = client.call_text("admin.release_notes", json!({"full": true})).await;
    assert!(payload(&text)["markdown"].as_str().unwrap().contains("## Procedure"));
    let (text, is_error) = client.call_text("admin.release_notes", json!({"version": "99.99.99"})).await;
    assert!(is_error && text.contains("99.99.99"), "{text}");
    // Read-only: no pending item, no file write.
    assert!(a.env.pending.list(None).unwrap().is_empty());
    assert_eq!(std::fs::read_to_string(&a.env.tools_path).unwrap(), before);
}

#[tokio::test]
async fn admin_server_reports_the_real_version() {
    let a = admin_env(false).await;
    let client = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await;
    let result = &client.init["result"];
    assert_eq!(result["serverInfo"], json!({"name": "gatekeeper-admin", "version": gatekeeper::VERSION}));
    assert_eq!(result["instructions"], gatekeeper::admin_server::INSTRUCTIONS);
    // A fixed list has nothing to announce.
    assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
}

#[tokio::test]
async fn a_pending_change_goes_to_the_queue_not_live() {
    let a = admin_env(false).await;
    let write_spec = json!({"id": "demo.writeit", "toolkit": "demo", "binary": SH, "title": "w", "description": "d",
                            "category": "write", "idempotent": false, "enabled": false, "argv": ["-c", "echo done"],
                            "parameters": {}, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096});
    let mut client = Mcp::connect(&a.base, "/admin/mcp", &a.hermes).await;
    client.call_text("admin.tool_create", json!({"spec": write_spec})).await;
    let (text, is_error) = client.call_text("admin.tool_enable", json!({"id": "demo.writeit"})).await;
    assert!(!is_error, "{text}");
    let p = payload(&text);
    assert_eq!(p["applied"], false);
    assert_eq!(p["pending"], true);
    assert_eq!(a.env.pending.list(Some("pending")).unwrap().len(), 1);
    assert!(!a.env.service.catalog().tools["demo.writeit"].enabled);
}

/// The Rust list against the Python module it was generated from
/// (`admin_server._TOOLS`, dumped into `fixtures/admin_tools_golden.json`
/// when the Python implementation was removed, 1.17.0).
#[test]
fn the_admin_tool_list_matches_the_python_module() {
    let python_tools: Value = serde_json::from_str(include_str!("fixtures/admin_tools_golden.json")).unwrap();
    let rust_tools = Value::Array(gatekeeper::admin_server::admin_tools().to_vec());
    // Same content, same key order.
    assert_eq!(serde_json::to_string(&python_tools).unwrap(), serde_json::to_string(&rust_tools).unwrap());
}
