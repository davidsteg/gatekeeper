//! Tests for the `kuma` executor (port of `tests/test_execute_kuma.py`).
//!
//! Against a real Socket.IO-over-WebSocket server on loopback, speaking the
//! Engine.IO v4 framing Kuma's own server does -- not a mocked send(). What
//! matters here is what goes on the wire (no delete, no foreign monitor, no
//! secret coming back) and that is exactly what a mock would assume away.

use std::collections::BTreeMap;
use std::sync::Arc;

use futures::StreamExt;
use indexmap::IndexMap;
use parking_lot::Mutex;

use super::*;
use crate::credentials::tests::env;
use crate::errors::ConfigResult;
use crate::tier1::{load_tier1, Tier1};

const PASSWORD: &str = "kuma-secret-pw-123";
const FOREIGN_SECRET: &str = "hand-made-basic-auth-secret";

/// Kuma's socket API as far as this executor uses it.
struct FakeKuma {
    version: String,
    two_factor: bool,
    stall: Option<String>,
    received: Vec<(String, Vec<Value>)>,
    monitors: BTreeMap<i64, Value>,
    /// The `notificationList` pushed after login; `None` sends none.
    notifications: Option<Value>,
}

impl FakeKuma {
    fn new() -> Self {
        let mut monitors = BTreeMap::new();
        monitors.insert(
            1,
            json!({
                "id": 1, "name": "Router", "type": "http", "active": 1, "interval": 60,
                "url": format!("https://admin:{FOREIGN_SECRET}@router.lan/status?token={FOREIGN_SECRET}"),
                "basic_auth_pass": FOREIGN_SECRET,
                "headers": format!("{{\"X-Key\": \"{FOREIGN_SECRET}\"}}"),
                "description": "set up by hand",
            }),
        );
        monitors.insert(
            2,
            json!({
                "id": 2, "name": "Blog", "type": "http", "active": 1, "interval": 300,
                "url": "https://blog.example.org/", "description": "Managed by gatekeeper (toolkit kuma)",
            }),
        );
        // Kuma pushes whole notification rows; `config` holds the secrets.
        let notifications = Some(json!([
            {"id": 1, "name": "Telegram", "active": 1, "config": format!("{{\"telegramBotToken\":\"{FOREIGN_SECRET}\"}}")},
            {"id": 4, "name": "Mail", "active": 1, "config": "{}"},
        ]));
        FakeKuma {
            version: "1.23.16".into(),
            two_factor: false,
            stall: None,
            received: Vec::new(),
            monitors,
            notifications,
        }
    }
}

type Shared = Arc<Mutex<FakeKuma>>;

struct Kuma {
    port: u16,
    state: Shared,
}

impl Kuma {
    fn events(&self) -> Vec<String> {
        self.state.lock().received.iter().map(|(n, _)| n.clone()).collect()
    }
    fn received_args(&self, event: &str) -> Vec<Value> {
        self.state.lock().received.iter().filter(|(n, _)| n == event).map(|(_, a)| a[0].clone()).collect()
    }
    fn active(&self, id: i64) -> Value {
        self.state.lock().monitors[&id]["active"].clone()
    }
}

async fn handler(stream: tokio::net::TcpStream, state: Shared) {
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else { return };
    let send = |text: String| Message::text(text);
    if ws
        .send(send(
            r#"0{"sid":"e1","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}"#.into(),
        ))
        .await
        .is_err()
    {
        return;
    }
    let mut logged_in = false;
    while let Some(Ok(msg)) = ws.next().await {
        let Message::Text(frame) = msg else { continue };
        let frame = frame.as_str().to_string();
        if frame == "40" {
            let _ = ws.send(send(r#"40{"sid":"s1"}"#.into())).await;
            let _ = ws.send(send(r#"42["info",{"primaryBaseURL":null}]"#.into())).await;
            // A server ping mid-session must be answered, not mistaken for data.
            let _ = ws.send(send("2".into())).await;
            continue;
        }
        if frame == "3" || !frame.starts_with("42") {
            continue;
        }
        let body = &frame[2..];
        let digits = leading_digits(body);
        let ack = &body[..digits];
        let args: Vec<Value> = serde_json::from_str(&body[digits..]).unwrap();
        let event = args[0].as_str().unwrap().to_string();
        let rest = args[1..].to_vec();
        let (stall, version, two_factor) = {
            let mut s = state.lock();
            s.received.push((event.clone(), rest.clone()));
            (s.stall.clone(), s.version.clone(), s.two_factor)
        };
        if stall.as_deref() == Some(event.as_str()) {
            // Never answers; keeps reading so a close is still answered.
            continue;
        }
        let answer = if event == "login" {
            let creds = &rest[0];
            let answer = if creds["username"] != "gk" || creds["password"] != PASSWORD {
                json!({"ok": false, "msg": "Incorrect username or password."})
            } else if two_factor && creds.get("token").is_none_or(|t| !py_truthy(t)) {
                json!({"tokenRequired": true})
            } else {
                logged_in = true;
                json!({"ok": true, "token": "jwt"})
            };
            let _ = ws.send(send(format!("43{ack}{}", json!([answer])))).await;
            if logged_in {
                let monitors: Map<String, Value> =
                    state.lock().monitors.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
                let _ = ws.send(send(format!("42{}", json!(["monitorList", monitors])))).await;
                let _ = ws.send(send(format!("42{}", json!(["info", {"version": version}])))).await;
                let notifications = state.lock().notifications.clone();
                if let Some(list) = notifications {
                    let _ = ws.send(send(format!("42{}", json!(["notificationList", list])))).await;
                }
            }
            continue;
        } else if !logged_in {
            json!({"ok": false, "msg": "You are not logged in."})
        } else {
            let mut s = state.lock();
            match event.as_str() {
                "add" => {
                    let new_id = s.monitors.keys().max().unwrap() + 1;
                    let mut monitor = rest[0].clone();
                    monitor["id"] = json!(new_id);
                    monitor["active"] = json!(1);
                    s.monitors.insert(new_id, monitor);
                    json!({"ok": true, "msg": "Added Successfully.", "monitorID": new_id})
                }
                "getMonitor" => match rest[0].as_i64().and_then(|id| s.monitors.get(&id)) {
                    Some(m) => json!({"ok": true, "monitor": m}),
                    None => json!({"ok": false, "msg": "Cannot read properties of null"}),
                },
                "pauseMonitor" | "resumeMonitor" => {
                    let id = rest[0].as_i64().unwrap();
                    let m = s.monitors.get_mut(&id).unwrap();
                    m["active"] = json!(if event == "pauseMonitor" { 0 } else { 1 });
                    json!({"ok": true, "msg": "Done."})
                }
                _ => json!({"ok": false, "msg": "unexpected"}),
            }
        };
        if ws.send(send(format!("43{ack}{}", json!([answer])))).await.is_err() {
            return;
        }
    }
}

async fn kuma() -> Kuma {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state: Shared = Arc::new(Mutex::new(FakeKuma::new()));
    let s2 = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(handler(stream, s2.clone()));
        }
    });
    Kuma { port, state }
}

const ALL_OPS: [&str; 5] = ["monitor_list", "monitor_add_http", "monitor_add_port", "monitor_pause", "monitor_resume"];

fn try_tier1(dir: &std::path::Path, port: u16, overrides: Value) -> ConfigResult<Tier1> {
    let mut spec = json!({
        "executor": "kuma", "base_url": format!("http://127.0.0.1:{port}"),
        "allowed_cidrs": ["127.0.0.1/32"], "credential": "kuma",
        "allowed_kuma_operations": ALL_OPS, "max_timeout_seconds": 30,
        "allowed_monitor_targets": ["10.10.200.0/24", "nas.lan"],
    });
    for (k, v) in overrides.as_object().unwrap() {
        spec[k] = v.clone();
    }
    let doc = json!({"toolkits": {"kuma": spec}, "audit": {"dir": dir.join("logs").to_str().unwrap()}});
    let path = dir.join("toolkits.yaml");
    std::fs::write(&path, crate::yaml::dump(&doc)).unwrap();
    load_tier1(path.to_str().unwrap())
}

fn tier1(dir: &std::path::Path, port: u16, overrides: Value) -> Tier1 {
    try_tier1(dir, port, overrides).unwrap()
}

fn create_login(store: &CredentialStore, kind: &str, value: &str) {
    store.create("kuma", kind, value, None, None, None, "test", "").unwrap();
}

fn vals(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

async fn run_op(toolkit: &Toolkit, store: &CredentialStore, operation: &str, values: &[(&str, &str)]) -> ExecResult {
    run_with(toolkit, store, operation, values, 5.0, None).await
}

async fn run_with(
    toolkit: &Toolkit,
    store: &CredentialStore,
    operation: &str,
    values: &[(&str, &str)],
    timeout: f64,
    idempotent: Option<bool>,
) -> ExecResult {
    let idempotent = idempotent.unwrap_or(operation == "monitor_list");
    run(operation, &vals(values), toolkit, Some(store), timeout, 65536, idempotent, None).await.unwrap()
}

// -- Operations -------------------------------------------------------------

#[tokio::test]
async fn list_projects_monitors_and_leaks_no_secret() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_list", &[]).await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    assert!(result.external_untrusted);
    let payload: Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(payload["count"], 2);
    let monitors = payload["monitors"].as_array().unwrap();
    let router = monitors.iter().find(|m| m["id"] == 1).unwrap();
    assert_eq!(
        router,
        &json!({"id": 1, "name": "Router", "type": "http", "url": "https://router.lan/status",
                "active": true, "interval": 60, "managed": false})
    );
    assert_eq!(monitors.iter().find(|m| m["id"] == 2).unwrap()["managed"], true);
    // Sorted by name: Blog before Router.
    assert_eq!(monitors[0]["name"], "Blog");
    assert!(!result.stdout.contains(FOREIGN_SECRET) && !result.stdout.contains(PASSWORD));
    assert_eq!(k.events(), vec!["login"]);
}

#[tokio::test]
async fn add_http_sends_a_fixed_http_monitor() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_op(
        t.toolkit("kuma").unwrap(),
        &e.store,
        "monitor_add_http",
        &[("name", "Docs"), ("url", "https://docs.example.org/health"), ("interval", "120"), ("expected_status", "200-299")],
    )
    .await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    let out: Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(out["monitor_id"], 3);
    assert_eq!(out["active"], true);
    let sent = k.received_args("add");
    assert_eq!(sent.len(), 1);
    let sent = sent[0].as_object().unwrap();
    assert_eq!(sent["type"], "http");
    assert_eq!(sent["method"], "GET");
    assert_eq!(sent["url"], "https://docs.example.org/health");
    assert_eq!(sent["interval"], 120);
    assert_eq!(sent["timeout"], 48);
    assert_eq!(sent["accepted_statuscodes"], json!(["200-299"]));
    assert_eq!(sent["notificationIDList"], json!({}));
    assert!(sent["description"].as_str().unwrap().starts_with(MANAGED_MARKER));
    // A 1.x server has no column for these; sending them would fail the insert.
    assert!(!sent.contains_key("conditions") && !sent.contains_key("rabbitmqNodes"));
    for key in ["headers", "body", "basic_auth_user", "basic_auth_pass"] {
        assert!(!sent.contains_key(key), "{key}");
    }
}

#[tokio::test]
async fn add_http_on_kuma_2_sends_its_extra_fields() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    k.state.lock().version = "2.0.2".into();
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result =
        run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_add_http", &[("name", "X"), ("url", "http://x.lan/")]).await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    let sent = &k.received_args("add")[0];
    assert_eq!(sent["conditions"], json!([]));
    assert_eq!(sent["rabbitmqNodes"], json!([]));
    assert_eq!(sent["interval"], 60);
    assert_eq!(sent["accepted_statuscodes"], json!(["200-299"]));
}

#[tokio::test]
async fn pause_and_resume_a_managed_monitor() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let tk = t.toolkit("kuma").unwrap();
    let paused = run_op(tk, &e.store, "monitor_pause", &[("monitor_id", "2")]).await;
    assert_eq!(paused.outcome, OUTCOME_OK, "{}", paused.stderr);
    assert_eq!(k.active(2), 0);
    assert_eq!(
        serde_json::from_str::<Value>(&paused.stdout).unwrap(),
        json!({"monitor_id": 2, "name": "Blog", "active": false})
    );
    let resumed = run_op(tk, &e.store, "monitor_resume", &[("monitor_id", "2")]).await;
    assert_eq!(resumed.outcome, OUTCOME_OK);
    assert_eq!(k.active(2), 1);
}

#[tokio::test]
async fn a_foreign_monitor_is_refused_before_anything_is_sent() {
    for operation in ["monitor_pause", "monitor_resume"] {
        let e = env();
        create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
        let k = kuma().await;
        let t = tier1(e.dir.path(), k.port, json!({}));
        let result = run_op(t.toolkit("kuma").unwrap(), &e.store, operation, &[("monitor_id", "1")]).await;
        assert_eq!(result.outcome, OUTCOME_FAILED);
        assert_eq!(result.denial_reason.as_deref(), Some("tier1_violation"));
        assert!(result.stderr.contains("not created through gatekeeper"), "{}", result.stderr);
        assert_eq!(k.events(), vec!["login", "getMonitor"]);
        assert_eq!(k.active(1), 1);
        assert!(!result.stderr.contains(FOREIGN_SECRET));
    }
}

#[tokio::test]
async fn missing_monitor_is_a_plain_failure() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_pause", &[("monitor_id", "99")]).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(result.stderr, "Monitor 99 does not exist.");
    assert_eq!(result.exit_code, Some(1));
    assert!(!k.events().contains(&"pauseMonitor".to_string()));
}

// -- Login --------------------------------------------------------------------

#[tokio::test]
async fn wrong_password_fails_without_echoing_it() {
    let e = env();
    create_login(&e.store, "basic", "gk:wrong-password-xyz");
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_list", &[]).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(result.denial_reason.as_deref(), Some("credential_unavailable"));
    assert!(result.stderr.contains("Incorrect username or password"), "{}", result.stderr);
    let all = format!("{}{}", result.stderr, result.denial_detail.clone().unwrap_or_default());
    assert!(!all.contains("wrong-password-xyz"));
}

#[tokio::test]
async fn two_factor_account_is_refused_with_a_reason() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    k.state.lock().two_factor = true;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_list", &[]).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert!(result.stderr.contains("2FA"), "{}", result.stderr);
}

#[tokio::test]
async fn non_basic_credential_is_refused_before_logging_in() {
    let e = env();
    create_login(&e.store, "bearer", "token-abc");
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_list", &[]).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(
        result.stderr,
        "Credential 'kuma' must be kind 'basic' with the value 'username:password' of the Kuma login."
    );
    assert!(!k.events().contains(&"login".to_string()));
}

#[tokio::test]
async fn missing_credential_is_refused() {
    let e = env();
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_list", &[]).await;
    assert_eq!(result.stderr, "Credential 'kuma' is not configured yet.");
    assert_eq!(result.denial_reason.as_deref(), Some("credential_unavailable"));
    let none = run("monitor_list", &vals(&[]), t.toolkit("kuma").unwrap(), None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(none.stderr, "This toolkit needs the Kuma login in the credential store.");
    assert!(k.events().is_empty());
}

// -- Floors that hold regardless of the tool definition -----------------------

#[tokio::test]
async fn operation_outside_the_toolkit_list_never_connects() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({"allowed_kuma_operations": ["monitor_list"]}));
    let result =
        run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_add_http", &[("name", "x"), ("url", "https://x.org/")]).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(result.denial_reason.as_deref(), Some("tier1_violation"));
    assert_eq!(result.stderr, "Kuma operation 'monitor_add_http' is not allowed for this toolkit.");
    assert!(k.events().is_empty());
}

#[tokio::test]
async fn address_outside_allowed_cidrs_never_connects() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({"allowed_cidrs": ["10.0.0.0/8"]}));
    let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_list", &[]).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(result.denial_reason.as_deref(), Some("cidr_not_allowed"));
    assert!(k.events().is_empty());
}

#[tokio::test]
async fn refused_connection_names_the_checked_address() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let t = tier1(e.dir.path(), port, json!({}));
    let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_list", &[]).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(
        result.stderr,
        format!(
            "Could not connect to Uptime Kuma at http://127.0.0.1:{port}: [Errno 111] Connect call failed ('127.0.0.1', {port})"
        )
    );
    assert!(result.external_untrusted);
}

#[tokio::test]
async fn add_values_are_checked_by_the_executor_itself() {
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[("name", "x"), ("url", "ftp://x.org/")], "http(s) URL"),
        (&[("name", "x"), ("url", "https://user:pw@x.org/")], "user or password"),
        (&[("name", "x"), ("url", "https://x.org/"), ("interval", "10")], "interval"),
        (&[("name", "x"), ("url", "https://x.org/"), ("interval", "86400")], "interval"),
        (&[("name", "x"), ("url", "https://x.org/"), ("expected_status", "500")], "expected_status"),
        (&[("name", " "), ("url", "https://x.org/")], "name"),
    ];
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    for (values, fragment) in cases {
        let result = run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_add_http", values).await;
        assert_eq!(result.outcome, OUTCOME_FAILED);
        assert!(result.stderr.contains(fragment), "{fragment}: {}", result.stderr);
        assert_eq!(result.denial_reason.as_deref(), Some("param_invalid"));
    }
    assert!(k.events().is_empty());
}

#[test]
fn check_values_messages_match_python() {
    let add = |pairs: &[(&str, &str)]| check_values("monitor_add_http", &vals(pairs)).map_err(|d| d.detail);
    assert_eq!(add(&[("name", "x"), ("url", "https://x.org/")]), Ok(()));
    assert_eq!(
        add(&[("name", "x"), ("url", "https://x.org:99999/")]),
        Err("Parameter 'url' is not a valid URL.".into())
    );
    assert_eq!(add(&[("name", "x"), ("url", "http://[::1/")]), Err("Parameter 'url' is not a valid URL.".into()));
    assert_eq!(add(&[("name", "x"), ("url", "http://[1.2.3.4]/")]), Err("Parameter 'url' is not a valid URL.".into()));
    assert_eq!(add(&[("name", "x"), ("url", "http://[::1]/")]), Ok(()));
    assert_eq!(add(&[("name", "x"), ("url", "http://a\u{ff0f}b/")]), Err("Parameter 'url' is not a valid URL.".into()));
    assert_eq!(add(&[("name", "x"), ("url", "x.org")]), Err("Parameter 'url' must be an absolute http(s) URL.".into()));
    assert_eq!(
        add(&[("name", "x"), ("url", "https://@x.org/")]),
        Err("Parameter 'url' must not carry a user or password.".into())
    );
    assert_eq!(
        add(&[("name", "x"), ("url", "https://x.org/a b")]),
        Err("Parameter 'url' must not contain whitespace.".into())
    );
    assert_eq!(
        add(&[("name", "x"), ("url", "https://x.org/a\u{1c}b")]),
        Err("Parameter 'url' must not contain whitespace.".into())
    );
    assert_eq!(
        add(&[("name", "x"), ("url", "https://x.org/"), ("interval", "")]),
        Err("Parameter 'interval' must be 30-3600 seconds.".into())
    );
    assert_eq!(
        add(&[("name", "x"), ("url", "https://x.org/"), ("expected_status", "500")]),
        Err("Parameter 'expected_status' must be one of ['200', '200-299', '201', '202', '204', '300-399', '301', '302', '400-499', '401', '403', '404'].".into())
    );
    assert_eq!(add(&[("name", &"n".repeat(151)), ("url", "https://x.org/")]), Err("Parameter 'name' must be 1-150 characters.".into()));
    assert_eq!(add(&[("name", "\u{3000}\t"), ("url", "https://x.org/")]), Err("Parameter 'name' must be 1-150 characters.".into()));
    for id in ["0", "-1", "", "x"] {
        assert_eq!(
            check_values("monitor_pause", &vals(&[("monitor_id", id)])).map_err(|d| d.detail),
            Err("Parameter 'monitor_id' must be a positive integer.".into())
        );
    }
    assert_eq!(check_values("monitor_resume", &vals(&[("monitor_id", "007")])), Ok(()));
    assert_eq!(check_values("monitor_list", &vals(&[])), Ok(()));
}

#[test]
fn public_url_drops_userinfo_query_and_fragment() {
    let u = |s: &str| public_url(Some(&json!(s)));
    assert_eq!(u("https://a:b@Router.LAN:0443/x?t=1#f"), json!("https://router.lan:443/x"));
    assert_eq!(u("http://[::1]:80"), json!("http://[::1]:80"));
    assert_eq!(u("http://h:bad/"), Value::Null);
    assert_eq!(u("/relative"), Value::Null);
    assert_eq!(u(""), Value::Null);
    assert_eq!(public_url(Some(&json!(5))), Value::Null);
    assert_eq!(public_url(None), Value::Null);
}

#[test]
fn socket_url_and_major_version() {
    assert_eq!(
        socket_url("https://kuma.example.org/base/").unwrap(),
        ("wss://kuma.example.org/base/socket.io/?EIO=4&transport=websocket".into(), "kuma.example.org".into(), 443)
    );
    assert_eq!(
        socket_url("http://127.0.0.1:3001").unwrap(),
        ("ws://127.0.0.1:3001/socket.io/?EIO=4&transport=websocket".into(), "127.0.0.1".into(), 3001)
    );
    assert_eq!(major_version(Some(&[json!({"version": "v2.0.0-beta.1"})])), 2);
    assert_eq!(major_version(Some(&[json!({"version": "1.23.16"})])), 1);
    assert_eq!(major_version(Some(&[json!({"primaryBaseURL": null})])), 1);
    assert_eq!(major_version(None), 1);
    let settings = MonitorSettings { interval: 30, maxretries: 0, retry_interval: 30, notification_ids: vec![] };
    assert_eq!(http_monitor("n", "u", "200", &settings, "tk", 1)["timeout"], 24);
}

#[tokio::test]
async fn timeout_after_add_was_sent_is_unknown() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    k.state.lock().stall = Some("add".into());
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_with(
        t.toolkit("kuma").unwrap(),
        &e.store,
        "monitor_add_http",
        &[("name", "x"), ("url", "https://x.org/")],
        1.0,
        None,
    )
    .await;
    assert_eq!(result.outcome, OUTCOME_UNKNOWN);
    assert_eq!(
        result.stderr,
        "Timeout of 1s exceeded. The outcome is UNKNOWN: the request may have reached Uptime Kuma. \
         List the monitors before trying again."
    );
}

#[tokio::test]
async fn timeout_before_any_write_is_a_plain_failure() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    k.state.lock().stall = Some("getMonitor".into());
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result =
        run_with(t.toolkit("kuma").unwrap(), &e.store, "monitor_pause", &[("monitor_id", "2")], 1.0, None).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(result.stderr, "Timeout of 1s exceeded.");
}

#[tokio::test]
async fn probe_is_tcp_only() {
    let e = env();
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    assert!(probe(t.toolkit("kuma").unwrap()).await);
    assert!(k.events().is_empty());
}

// -- Tier 1 -------------------------------------------------------------------

#[test]
fn tier1_refuses_an_incomplete_kuma_toolkit() {
    let e = env();
    let cases = [
        (json!({"credential": null}), "needs 'credential'"),
        (json!({"allowed_kuma_operations": ["monitor_delete"]}), "unknown: ['monitor_delete']"),
        (json!({"allowed_kuma_operations": []}), "non-empty subset"),
        (json!({"allowed_cidrs": null}), "allowed_cidrs"),
        (json!({"base_url": "ws://127.0.0.1:3001"}), "base_url"),
    ];
    for (overrides, fragment) in cases {
        let err = try_tier1(e.dir.path(), 3001, overrides).unwrap_err();
        assert!(err.message.contains(fragment), "{fragment}: {}", err.message);
    }
    let err = try_tier1(e.dir.path(), 3001, json!({"allowed_kuma_operations": ["monitor_delete"]})).unwrap_err();
    assert_eq!(
        err.message,
        "toolkit 'kuma': allowed_kuma_operations must be a non-empty subset of ['monitor_add_http', \
         'monitor_add_port', 'monitor_list', 'monitor_pause', 'monitor_resume'] (unknown: ['monitor_delete'])"
    );
    let err = try_tier1(e.dir.path(), 3001, json!({"credential": ""})).unwrap_err();
    assert_eq!(
        err.message,
        "toolkit 'kuma': a kuma toolkit needs 'credential' -- the name of a 'basic' credential holding \
         the Kuma login as username:password"
    );
    let err = try_tier1(e.dir.path(), 3001, json!({"base_url": "http://x:1/{credential}"})).unwrap_err();
    assert_eq!(
        err.message,
        "toolkit 'kuma': base_url must not contain a '{credential}' placeholder -- the kuma executor \
         logs in with its credential, and would send this literally."
    );
}

#[test]
fn kuma_toolkit_takes_allowed_hosts() {
    let e = env();
    let t = tier1(
        e.dir.path(),
        3001,
        json!({"base_url": "https://kuma.example.org", "allowed_cidrs": null, "allowed_hosts": ["kuma.example.org"]}),
    );
    assert_eq!(t.toolkit("kuma").unwrap().allowed_hosts, vec!["kuma.example.org".to_string()]);
}

// -- Catalog ------------------------------------------------------------------

fn add_params() -> Value {
    json!({
        "name": {"type": "string", "required": true, "pattern": "^[A-Za-z0-9 ._-]{1,80}$", "description": "name"},
        "url": {"type": "string", "required": true,
                "pattern": "^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$", "description": "url"},
        "interval": {"type": "integer", "minimum": 30, "maximum": 3600, "description": "seconds"},
        "expected_status": {"type": "enum", "values": ["200-299", "401"], "description": "status"},
    })
}

fn tools() -> Vec<Value> {
    let common = |id: &str, title: &str, category: &str, idempotent: bool, op: &str, params: Value| {
        json!({"toolkit": "kuma", "version": 1, "enabled": true, "required_scopes": [],
               "timeout_seconds": 20, "max_output_bytes": 65536, "description": "kuma",
               "id": id, "title": title, "category": category, "idempotent": idempotent,
               "kuma_operation": op, "parameters": params})
    };
    let id_param = json!({"monitor_id": {"type": "integer", "required": true, "minimum": 1, "description": "id"}});
    vec![
        common("kuma.monitor_list", "List", "read", true, "monitor_list", json!({})),
        common("kuma.monitor_add_http", "Add", "write", false, "monitor_add_http", add_params()),
        common("kuma.monitor_pause", "Pause", "write", true, "monitor_pause", id_param),
    ]
}

fn make_catalog(dir: &std::path::Path, tier1: &Tier1, tools: &[Value]) -> ConfigResult<crate::catalog::Catalog> {
    let path = dir.join("tools.yaml");
    std::fs::write(&path, crate::yaml::dump(&json!({ "tools": tools }))).unwrap();
    crate::catalog::load_catalog(path.to_str().unwrap(), tier1, true)
}

#[test]
fn example_tools_load() {
    let e = env();
    let catalog = make_catalog(e.dir.path(), &tier1(e.dir.path(), 3001, json!({})), &tools()).unwrap();
    assert_eq!(catalog.tools["kuma.monitor_add_http"].kuma_operation.as_deref(), Some("monitor_add_http"));
}

#[test]
fn catalog_refuses_a_definition_wider_than_the_executor() {
    let mut wide_interval = add_params();
    wide_interval["interval"]["maximum"] = json!(86400);
    let mut open_interval = add_params();
    open_interval["interval"] = json!({"type": "integer", "description": "s"});
    let mut bad_status = add_params();
    bad_status["expected_status"] = json!({"type": "enum", "values": ["500"], "description": "s"});
    let mut extra = add_params();
    extra["type"] = json!({"type": "enum", "values": ["dns"], "description": "t"});
    let only_url = json!({"url": add_params()["url"]});
    let cases = [
        (json!({"category": "read"}), "must be 'write'"),
        (json!({"parameters": wide_interval}), "interval"),
        (json!({"parameters": open_interval}), "interval"),
        (json!({"parameters": bad_status}), "expected_status"),
        (json!({"parameters": extra}), "does not read ['type']"),
        (json!({"parameters": only_url}), "'name'"),
        (json!({"kuma_operation": "monitor_delete"}), "unknown"),
    ];
    let e = env();
    let t = tier1(e.dir.path(), 3001, json!({}));
    for (change, fragment) in cases {
        let mut tools = tools();
        for (k, v) in change.as_object().unwrap() {
            tools[1][k] = v.clone();
        }
        let err = make_catalog(e.dir.path(), &t, &tools).unwrap_err();
        assert!(err.message.contains(fragment), "{fragment}: {}", err.message);
    }
}

#[test]
fn catalog_messages_match_python() {
    let e = env();
    let t = tier1(e.dir.path(), 3001, json!({}));
    let parse = |change: Value| {
        let mut spec = tools()[1].clone();
        for (k, v) in change.as_object().unwrap() {
            spec[k] = v.clone();
        }
        crate::catalog::parse_tool_spec(&spec, &t).unwrap_err().message
    };
    assert_eq!(
        parse(json!({"category": "read"})),
        "tool 'kuma.monitor_add_http': kuma operation 'monitor_add_http' changes monitors -- its category \
         must be 'write', not 'read'"
    );
    let mut p = add_params();
    p["interval"]["minimum"] = json!(10);
    assert_eq!(
        parse(json!({"parameters": p})),
        "tool 'kuma.monitor_add_http': parameter 'interval' must be an integer with minimum >= 30 and maximum <= 3600"
    );
    let mut p = add_params();
    p["expected_status"]["values"] = json!(["200", "418"]);
    assert_eq!(
        parse(json!({"parameters": p})),
        "tool 'kuma.monitor_add_http': parameter 'expected_status' must be an enum over ['200', '200-299', \
         '201', '202', '204', '300-399', '301', '302', '400-499', '401', '403', '404']"
    );
    let mut p = add_params();
    p["url"] = json!({"type": "enum", "values": ["https://x.org/"], "required": true, "description": "u"});
    assert_eq!(parse(json!({"parameters": p})), "tool 'kuma.monitor_add_http': parameter 'url' must be a string with a pattern");
    assert_eq!(
        parse(json!({"kuma_operation": "monitor_delete"})),
        "tool 'kuma.monitor_add_http': kuma_operation 'monitor_delete' is unknown (known: ['monitor_add_http', \
         'monitor_add_port', 'monitor_list', 'monitor_pause', 'monitor_resume'])"
    );
    assert_eq!(parse(json!({"kuma_operation": null})), "tool 'kuma.monitor_add_http': field 'kuma_operation' is missing");
    let mut spec = tools()[2].clone();
    spec["parameters"]["monitor_id"]["minimum"] = json!(0);
    assert_eq!(
        crate::catalog::parse_tool_spec(&spec, &t).unwrap_err().message,
        "tool 'kuma.monitor_pause': parameter 'monitor_id' must be an integer with minimum >= 1"
    );
}

#[test]
fn catalog_refuses_an_operation_the_toolkit_does_not_allow() {
    let e = env();
    let t = tier1(e.dir.path(), 3001, json!({"allowed_kuma_operations": ["monitor_list"]}));
    let err = make_catalog(e.dir.path(), &t, &tools()).unwrap_err();
    assert!(err.message.contains("not in the allowlist"), "{}", err.message);
    let err = crate::catalog::parse_tool_spec(&tools()[1], &t).unwrap_err();
    assert!(err.is_tier1_violation());
    assert_eq!(
        err.message,
        "tool 'kuma.monitor_add_http': kuma operation 'monitor_add_http' is not in the allowlist \
         ['monitor_list'] of toolkit 'kuma'"
    );
}

/// config/examples is what an operator copies from; its kuma part must load.
#[test]
fn shipped_example_toolkit_and_tools_load() {
    let e = env();
    let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/examples");
    let toolkits = crate::yaml::load(&std::fs::read_to_string(examples.join("toolkits.yaml")).unwrap()).unwrap();
    let all_tools = crate::yaml::load(&std::fs::read_to_string(examples.join("tools.yaml")).unwrap()).unwrap();
    let tools: Vec<Value> =
        all_tools["tools"].as_array().unwrap().iter().filter(|t| t["toolkit"] == "kuma").cloned().collect();
    let doc = json!({"toolkits": {"kuma": toolkits["toolkits"]["kuma"]},
                     "audit": {"dir": e.dir.path().join("logs").to_str().unwrap()}});
    let path = e.dir.path().join("toolkits.yaml");
    std::fs::write(&path, crate::yaml::dump(&doc)).unwrap();
    let t = load_tier1(path.to_str().unwrap()).unwrap();
    let catalog = make_catalog(e.dir.path(), &t, &tools).unwrap();
    let mut ids: Vec<&String> = catalog.tools.keys().collect();
    ids.sort();
    assert_eq!(ids, ["kuma.monitor_add_http", "kuma.monitor_list", "kuma.monitor_pause", "kuma.monitor_resume"]);
}

// -- Through the service, with audit ------------------------------------------

#[tokio::test]
async fn service_call_is_audited_without_the_password() {
    use crate::service::{CallError, Service, ServiceOptions};
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let dir = e.dir.path();
    let t = tier1(dir, k.port, json!({}));
    // A deliberately loose URL pattern: the executor's own floor, applied
    // in `validate::build_kuma_call`, is what has to refuse the userinfo.
    let mut tools = tools();
    tools[1]["parameters"]["url"]["pattern"] = json!("^\\S{1,200}$");
    let catalog = make_catalog(dir, &t, &tools).unwrap();
    let ipath = dir.join("identities.yaml");
    let ids: Vec<Value> = tools.iter().map(|t| t["id"].clone()).collect();
    std::fs::write(
        &ipath,
        crate::yaml::dump(&json!({"identities": [{
            "id": "hermes", "role": "agent", "token_hash": crate::identity::hash_token(&crate::identity::generate_token()),
            "tools": ids, "scopes": [],
        }]})),
    )
    .unwrap();
    let identities = crate::identity::load_identities(ipath.to_str().unwrap()).unwrap();
    let hermes = identities.identities["hermes"].clone();
    let audit = Arc::new(crate::audit::AuditLog::new(dir.join("logs").to_str().unwrap()).unwrap());
    let store = Arc::new(CredentialStore::new(dir.join("credentials.yaml").to_str().unwrap(), audit.clone()));
    let service = Service::new(ServiceOptions {
        tier1: t,
        catalog,
        audit,
        credentials: Some(store),
        docker_host: None,
        identities: Some(Arc::new(parking_lot::RwLock::new(identities))),
    });

    let listed = service.call(&hermes, "kuma.monitor_list", &Map::new(), None).await.unwrap();
    assert_eq!(listed.outcome, OUTCOME_OK, "{}", listed.stderr);
    let args = json!({"name": "x", "url": "https://u:p@x.org/"});
    match service.call(&hermes, "kuma.monitor_add_http", args.as_object().unwrap(), None).await {
        Err(CallError::Denied(denial)) => {
            assert!(denial.agent_message().contains("user or password"), "{}", denial.agent_message())
        }
        other => panic!("expected a denial, got {other:?}"),
    }
    assert!(!k.events().contains(&"add".to_string()));

    let mut log = String::new();
    for entry in walk(&dir.join("logs")) {
        log.push_str(&std::fs::read_to_string(entry).unwrap());
    }
    let records: Vec<Value> =
        log.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
    let calls: Vec<&str> =
        records.iter().filter(|r| r["kind"] == "call").map(|r| r["tool"].as_str().unwrap()).collect();
    assert_eq!(calls[calls.len() - 2..], ["kuma.monitor_list", "kuma.monitor_add_http"]);
    assert!(!log.contains(PASSWORD) && !log.contains(FOREIGN_SECRET));
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

// -- 1.29.0: port monitors, retries, toolkit notifications --------------------

const NOTIFY: &str = r#"{"kuma_notification_ids": [1, 4]}"#;

fn notify_overrides() -> Value {
    serde_json::from_str(NOTIFY).unwrap()
}

/// The acceptance case of the feature: both add operations, with the
/// values a tool's `fixed:` supplies (60/3/60) and the toolkit's
/// notifications 1 and 4, answer with monitor_id and active.
#[tokio::test]
async fn both_adds_carry_retries_and_exactly_the_toolkit_notifications() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, notify_overrides());
    let fixed = [("interval", "60"), ("maxretries", "3"), ("retry_interval", "60")];
    let mut http: Vec<(&str, &str)> = vec![("name", "Docs"), ("url", "https://docs.example.org/")];
    http.extend(fixed);
    let mut port: Vec<(&str, &str)> = vec![("name", "NAS SSH"), ("hostname", "10.10.200.90"), ("port", "22")];
    port.extend(fixed);
    for (op, values) in [("monitor_add_http", &http), ("monitor_add_port", &port)] {
        let result = run_op(t.toolkit("kuma").unwrap(), &e.store, op, values).await;
        assert_eq!(result.outcome, OUTCOME_OK, "{op}: {}", result.stderr);
        let out: Value = serde_json::from_str(&result.stdout).unwrap();
        assert!(out["monitor_id"].is_u64(), "{op}: {out}");
        assert_eq!(out["active"], true, "{op}");
        assert_eq!(out["notification_ids"], json!([1, 4]));
        assert_eq!((out["interval"].clone(), out["maxretries"].clone(), out["retry_interval"].clone()), (json!(60), json!(3), json!(60)));
        assert!(!result.stdout.contains(FOREIGN_SECRET));
    }
    let sent = k.received_args("add");
    assert_eq!(sent.len(), 2);
    for monitor in &sent {
        assert_eq!(monitor["interval"], 60);
        assert_eq!(monitor["maxretries"], 3);
        assert_eq!(monitor["retryInterval"], 60);
        assert_eq!(monitor["notificationIDList"], json!({"1": true, "4": true}));
    }
    assert_eq!(sent[0]["type"], "http");
    assert_eq!(sent[1]["type"], "port");
    assert_eq!(sent[1]["hostname"], "10.10.200.90");
    assert_eq!(sent[1]["port"], 22);
    assert!(sent[1]["description"].as_str().unwrap().starts_with(MANAGED_MARKER));
    assert!(k.events().iter().all(|e| ["login", "add", "getMonitor"].contains(&e.as_str())), "{:?}", k.events());
}

#[tokio::test]
async fn a_listed_hostname_target_is_accepted_case_insensitively() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({}));
    let result = run_op(
        t.toolkit("kuma").unwrap(),
        &e.store,
        "monitor_add_port",
        &[("name", "NAS"), ("hostname", "NAS.lan"), ("port", "443")],
    )
    .await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    let sent = &k.received_args("add")[0];
    assert_eq!(sent["hostname"], "nas.lan");
    // Without a toolkit list there is nothing to attach, and no retries unless asked.
    assert_eq!(sent["notificationIDList"], json!({}));
    assert_eq!(sent["maxretries"], 0);
    assert_eq!(sent["retryInterval"], 60);
}

#[tokio::test]
async fn port_target_outside_allowed_monitor_targets_sends_nothing() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, notify_overrides());
    for host in ["10.10.201.5", "8.8.8.8", "other.lan", "nas.lan.evil.org"] {
        let result = run_op(
            t.toolkit("kuma").unwrap(),
            &e.store,
            "monitor_add_port",
            &[("name", "x"), ("hostname", host), ("port", "22")],
        )
        .await;
        assert_eq!(result.outcome, OUTCOME_FAILED, "{host}");
        assert_eq!(result.denial_reason.as_deref(), Some("tier1_violation"), "{host}");
        assert!(result.stderr.contains("allowed_monitor_targets"), "{}", result.stderr);
    }
    assert!(k.events().is_empty(), "{:?}", k.events());
}

#[tokio::test]
async fn unknown_notification_id_aborts_before_the_add() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let t = tier1(e.dir.path(), k.port, json!({"kuma_notification_ids": [1, 7]}));
    let result =
        run_op(t.toolkit("kuma").unwrap(), &e.store, "monitor_add_http", &[("name", "x"), ("url", "https://x.org/")]).await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(result.denial_reason.as_deref(), Some("tier1_violation"));
    assert!(result.stderr.contains("Notification ID(s) 7 "), "{}", result.stderr);
    assert!(!result.stderr.contains(FOREIGN_SECRET));
    assert!(k.received_args("add").is_empty());
    assert_eq!(k.state.lock().monitors.len(), 2);
}

#[tokio::test]
async fn no_notification_list_from_kuma_aborts_before_the_add() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    k.state.lock().notifications = None;
    let t = tier1(e.dir.path(), k.port, notify_overrides());
    let result = run_with(
        t.toolkit("kuma").unwrap(),
        &e.store,
        "monitor_add_port",
        &[("name", "x"), ("hostname", "nas.lan"), ("port", "22")],
        10.0,
        None,
    )
    .await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert!(result.stderr.contains("no notification list"), "{}", result.stderr);
    assert!(k.received_args("add").is_empty());
}

#[test]
fn retry_and_port_values_are_bounded_by_the_executor() {
    let http = |extra: &[(&str, &str)]| {
        let mut v = vec![("name", "x"), ("url", "https://x.org/")];
        v.extend_from_slice(extra);
        check_values("monitor_add_http", &vals(&v)).map_err(|d| d.detail)
    };
    assert_eq!(http(&[("maxretries", "0"), ("retry_interval", "20")]), Ok(()));
    assert_eq!(http(&[("maxretries", "10"), ("retry_interval", "3600")]), Ok(()));
    assert_eq!(http(&[("maxretries", "11")]), Err("Parameter 'maxretries' must be 0-10.".into()));
    assert_eq!(http(&[("maxretries", "-1")]), Err("Parameter 'maxretries' must be 0-10.".into()));
    assert_eq!(http(&[("retry_interval", "19")]), Err("Parameter 'retry_interval' must be 20-3600 seconds.".into()));
    assert_eq!(http(&[("retry_interval", "3601")]), Err("Parameter 'retry_interval' must be 20-3600 seconds.".into()));
    let port = |pairs: &[(&str, &str)]| check_values("monitor_add_port", &vals(pairs)).map_err(|d| d.detail);
    assert_eq!(port(&[("name", "x"), ("hostname", "nas.lan"), ("port", "22")]), Ok(()));
    assert_eq!(port(&[("name", "x"), ("hostname", "10.0.0.1"), ("port", "65535")]), Ok(()));
    for bad in ["0", "65536", "", "x", "-1"] {
        assert_eq!(
            port(&[("name", "x"), ("hostname", "nas.lan"), ("port", bad)]),
            Err("Parameter 'port' must be 1-65535.".into()),
            "{bad}"
        );
    }
    for bad in ["", "tcp://nas.lan", "nas.lan:22", "nas.lan/x", "user@nas.lan", "-nas.lan", "nas..lan", "[::1]", "::1", "nas lan"] {
        let err = port(&[("name", "x"), ("hostname", bad), ("port", "22")]).unwrap_err();
        assert!(err.starts_with("Parameter 'hostname' must be a hostname or an IPv4 address"), "{bad}: {err}");
    }
    assert_eq!(
        port(&[("name", &"n".repeat(61)), ("hostname", "nas.lan"), ("port", "22")]),
        Err("Parameter 'name' must be 1-60 characters.".into())
    );
    assert_eq!(port(&[("name", &"n".repeat(60)), ("hostname", "nas.lan"), ("port", "22")]), Ok(()));
    assert_eq!(
        port(&[("name", "x"), ("hostname", "nas.lan"), ("port", "22"), ("interval", "29")]),
        Err("Parameter 'interval' must be 30-3600 seconds.".into())
    );
}

#[test]
fn tier1_checks_the_new_kuma_toolkit_fields() {
    let e = env();
    let t = tier1(e.dir.path(), 3001, json!({"kuma_notification_ids": [4, 1], "allowed_monitor_targets": ["10.1.2.3/16", "NAS.lan"]}));
    let tk = t.toolkit("kuma").unwrap();
    assert_eq!(tk.kuma_notification_ids, vec![4, 1]);
    assert_eq!(tk.allowed_monitor_targets, vec!["10.1.0.0/16".to_string(), "nas.lan".to_string()]);
    let cases = [
        (json!({"kuma_notification_ids": [0]}), "kuma_notification_ids entry 0 is not a positive integer"),
        (json!({"kuma_notification_ids": ["1"]}), "is not a positive integer"),
        (json!({"kuma_notification_ids": [1, 1]}), "lists 1 twice"),
        (json!({"kuma_notification_ids": 1}), "must be a list"),
        (json!({"allowed_monitor_targets": ["https://nas.lan"]}), "neither a CIDR nor a hostname"),
        (json!({"allowed_monitor_targets": []}), "monitor_add_port needs 'allowed_monitor_targets'"),
        (json!({"allowed_monitor_targets": null}), "monitor_add_port needs 'allowed_monitor_targets'"),
    ];
    for (overrides, fragment) in cases {
        let err = try_tier1(e.dir.path(), 3001, overrides).unwrap_err();
        assert!(err.message.contains(fragment), "{fragment}: {}", err.message);
    }
    // Without monitor_add_port the list may stay empty.
    let ok = try_tier1(
        e.dir.path(),
        3001,
        json!({"allowed_kuma_operations": ["monitor_list"], "allowed_monitor_targets": null}),
    );
    assert!(ok.is_ok());
}

#[test]
fn monitor_target_check_matches_networks_and_exact_hostnames() {
    let e = env();
    let t = tier1(e.dir.path(), 3001, json!({}));
    let tk = t.toolkit("kuma").unwrap();
    for ok in ["10.10.200.1", "10.10.200.255", "nas.lan", "NAS.LAN"] {
        assert!(check_monitor_target(tk, ok).is_ok(), "{ok}");
    }
    for bad in ["10.10.201.1", "127.0.0.1", "lan", "x.nas.lan", "10.10.200.0.nip.io"] {
        assert!(check_monitor_target(tk, bad).is_err(), "{bad}");
    }
}

// -- 1.29.0: `fixed:` and the shipped example tools ----------------------------

/// `config/examples/kuma-tools.yaml` against a toolkit `uptimekuma`.
fn example_kuma_tools(dir: &std::path::Path, port: u16, notify: Value) -> (Tier1, crate::catalog::Catalog) {
    let mut spec = json!({
        "executor": "kuma", "base_url": format!("http://127.0.0.1:{port}"),
        "allowed_cidrs": ["127.0.0.1/32"], "credential": "kuma",
        "allowed_kuma_operations": ["monitor_list", "monitor_add_http", "monitor_add_port"],
        "allowed_monitor_targets": ["10.10.200.0/24", "nas.lan"], "max_timeout_seconds": 30,
    });
    spec["kuma_notification_ids"] = notify;
    let doc = json!({"toolkits": {"uptimekuma": spec}, "audit": {"dir": dir.join("logs").to_str().unwrap()}});
    let path = dir.join("toolkits.yaml");
    std::fs::write(&path, crate::yaml::dump(&doc)).unwrap();
    let t = load_tier1(path.to_str().unwrap()).unwrap();
    let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/examples/kuma-tools.yaml");
    let catalog = crate::catalog::load_catalog(examples.to_str().unwrap(), &t, true).unwrap();
    (t, catalog)
}

#[test]
fn example_kuma_tools_load_with_their_fixed_values() {
    let e = env();
    let (_, catalog) = example_kuma_tools(e.dir.path(), 3001, json!([1, 4]));
    for id in ["uptimekuma.monitor_add", "uptimekuma.monitor_add_port"] {
        let tool = &catalog.tools[id];
        let fixed: Vec<(&str, i64)> = tool.kuma_fixed.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(fixed, [("interval", 60), ("maxretries", 3), ("retry_interval", 60)], "{id}");
        // A fixed value is not something the caller can send.
        let schema = tool.input_schema();
        for key in ["interval", "maxretries", "retry_interval"] {
            assert!(schema["properties"].get(key).is_none(), "{id} {key}");
        }
    }
}

#[test]
fn fixed_values_are_merged_and_cannot_be_overridden() {
    let e = env();
    let (_, catalog) = example_kuma_tools(e.dir.path(), 3001, json!([1, 4]));
    let tool = &catalog.tools["uptimekuma.monitor_add_port"];
    let args = json!({"name": "NAS", "hostname": "nas.lan", "port": 22});
    let values = crate::validate::resolve_parameters(tool, args.as_object().unwrap()).unwrap();
    assert_eq!(values.get("interval").map(String::as_str), Some("60"));
    assert_eq!(values.get("maxretries").map(String::as_str), Some("3"));
    assert_eq!(values.get("retry_interval").map(String::as_str), Some("60"));
    let args = json!({"name": "NAS", "hostname": "nas.lan", "port": 22, "maxretries": 0});
    let err = crate::validate::resolve_parameters(tool, args.as_object().unwrap()).unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamUnknown, "{}", err.detail);
}

#[test]
fn catalog_checks_fixed_against_the_executor_bounds() {
    let e = env();
    let t = tier1(e.dir.path(), 3001, json!({}));
    let parse = |fixed: Value, params: Value| {
        let mut spec = tools()[1].clone();
        spec["fixed"] = fixed;
        if !params.is_null() {
            spec["parameters"] = params;
        }
        crate::catalog::parse_tool_spec(&spec, &t).map(|_| ()).map_err(|e| e.message)
    };
    let mut no_interval = add_params();
    no_interval.as_object_mut().unwrap().remove("interval");
    assert_eq!(parse(json!({"maxretries": 3, "retry_interval": 60}), Value::Null), Ok(()));
    assert_eq!(parse(json!({"interval": 60}), no_interval.clone()), Ok(()));
    let cases = [
        (json!({"interval": 60}), Value::Null, "'interval' is both in 'fixed' and declared as a parameter"),
        (json!({"interval": 10}), no_interval.clone(), "fixed.interval must be an integer from 30 to 3600, not 10"),
        (json!({"maxretries": 11}), Value::Null, "fixed.maxretries must be an integer from 0 to 10, not 11"),
        (json!({"retry_interval": 19}), Value::Null, "fixed.retry_interval must be an integer from 20 to 3600, not 19"),
        (json!({"maxretries": "3"}), Value::Null, "fixed.maxretries must be an integer"),
        (json!({"expected_status": "200"}), Value::Null, "'fixed' cannot set 'expected_status'"),
        (json!([60]), Value::Null, "'fixed' must be a mapping"),
    ];
    for (fixed, params, fragment) in cases {
        let err = parse(fixed, params).unwrap_err();
        assert!(err.contains(fragment), "{fragment}: {err}");
    }
    // An operation that does not read the key cannot fix it.
    let mut spec = tools()[2].clone();
    spec["fixed"] = json!({"interval": 60});
    let err = crate::catalog::parse_tool_spec(&spec, &t).unwrap_err().message;
    assert!(err.contains("does not read 'interval'"), "{err}");
    // A parameter declared wider than the executor bound is refused too.
    let mut p = add_params();
    p["maxretries"] = json!({"type": "integer", "minimum": 0, "maximum": 50, "description": "r"});
    let err = parse(Value::Null, p).unwrap_err();
    assert!(err.contains("'maxretries' must be an integer with minimum >= 0 and maximum <= 10"), "{err}");
}

/// End to end through the example tool: the caller sends only name,
/// hostname and port; Kuma gets 60/3/60 and notifications 1 and 4.
#[tokio::test]
async fn example_port_tool_end_to_end() {
    let e = env();
    create_login(&e.store, "basic", &format!("gk:{PASSWORD}"));
    let k = kuma().await;
    let (t, catalog) = example_kuma_tools(e.dir.path(), k.port, json!([1, 4]));
    let tool = &catalog.tools["uptimekuma.monitor_add_port"];
    let args = json!({"name": "NAS SSH", "hostname": "10.10.200.90", "port": 22});
    let values = crate::validate::resolve_parameters(tool, args.as_object().unwrap()).unwrap();
    let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let result = run_op(t.toolkit("uptimekuma").unwrap(), &e.store, "monitor_add_port", &pairs).await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    let sent = &k.received_args("add")[0];
    assert_eq!((sent["interval"].clone(), sent["maxretries"].clone(), sent["retryInterval"].clone()), (json!(60), json!(3), json!(60)));
    assert_eq!(sent["notificationIDList"], json!({"1": true, "4": true}));
    let out: Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(out["monitor_id"], 3);
    assert_eq!(out["active"], true);
}
