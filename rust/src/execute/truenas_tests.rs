//! Tests for the `truenas` executor (port of `tests/test_execute_truenas.py`).
//!
//! Against a real JSON-RPC-over-WebSocket server, not a mock: the property
//! that matters -- a method not on the allowlist is refused by gatekeeper
//! itself, before anything is sent -- is exactly what a mocked send()
//! would assume away.

use std::sync::Arc;

use super::*;
use crate::credentials::tests::env;
use crate::tier1::{load_tier1, Tier1};

/// Every method frame the fake server received.
type Seen = Arc<parking_lot::Mutex<Vec<Value>>>;

async fn fake_truenas<S>(stream: S, seen: Seen)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else { return };
    while let Some(Ok(msg)) = ws.next().await {
        let Message::Text(raw) = msg else { continue };
        let request: Value = serde_json::from_str(raw.as_str()).unwrap();
        if request["msg"] == "connect" {
            let _ = ws.send(Message::text(json!({"msg": "connected", "version": "1"}).to_string())).await;
            continue;
        }
        if request["msg"] != "method" {
            continue;
        }
        seen.lock().push(request.clone());
        let method = request["method"].as_str().unwrap_or_default().to_string();
        let id = request["id"].clone();
        let reply = match method.as_str() {
            "auth.login_with_api_key" => {
                json!({"msg": "result", "id": id, "result": request["params"][0] == "correct-key"})
            }
            "pool.query" => json!({"msg": "result", "id": id, "result": [{"name": "tank"}]}),
            "pool.dataset.create" => {
                let name = request["params"].get(0).cloned().unwrap_or(Value::Null);
                json!({"msg": "result", "id": id, "result": {"name": name}})
            }
            // Jobs: 41 succeeds, 42 fails, 43 never ends; anything else is unknown.
            "pool.dataset.unlock" => {
                let job = match request["params"][0].as_str() {
                    Some("ok") => 41,
                    Some("fail") => 42,
                    _ => 43,
                };
                json!({"msg": "result", "id": id, "result": job})
            }
            "core.get_jobs" => {
                let job = request["params"][0][0][2].as_i64().unwrap_or_default();
                let found = match job {
                    41 => json!([{"id": 41, "state": "SUCCESS", "result": {"unlocked": ["tank/a"]},
                                  "arguments": ["secret-args"]}]),
                    42 => json!([{"id": 42, "state": "FAILED", "error": "[EINVAL] bad passphrase",
                                  "arguments": ["secret-args"]}]),
                    43 => json!([{"id": 43, "state": "RUNNING"}]),
                    _ => json!([]),
                };
                json!({"msg": "result", "id": id, "result": found})
            }
            "slow.method" => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                json!({"msg": "result", "id": id, "result": true})
            }
            _ => json!({"msg": "result", "id": id, "error": {"code": -32601, "message": "Method not found"}}),
        };
        if ws.send(Message::text(reply.to_string())).await.is_err() {
            return;
        }
    }
}

async fn ws_server() -> (String, Seen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(fake_truenas(stream, seen2.clone()));
        }
    });
    (format!("ws://127.0.0.1:{port}"), seen)
}

fn toolkit_yaml(dir: &std::path::Path, name: &str, ws_url: &str, methods: &str, credential: bool) -> Tier1 {
    let cred = if credential { "    credential: demo_cred\n" } else { "" };
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "toolkits:\n  demo_truenas:\n    executor: truenas\n    ws_url: \"{ws_url}\"\n    allowed_rpc_methods: {methods}\n{cred}audit:\n  dir: {}\n",
            dir.join("logs").display()
        ),
    )
    .unwrap();
    load_tier1(path.to_str().unwrap()).unwrap()
}

fn params(pairs: &[(&str, &str)]) -> IndexMap<String, Value> {
    pairs.iter().map(|(k, v)| (k.to_string(), Value::String(v.to_string()))).collect()
}

const METHODS: &str = "[\"pool.query\", \"pool.dataset.create\", \"pool.unknown\"]";

#[tokio::test]
async fn allowed_method_succeeds() {
    let e = env();
    e.store.create("demo_cred", "ws_api_key", "correct-key", None, None, None, "test", "").unwrap();
    let (url, _) = ws_server().await;
    let tier1 = toolkit_yaml(e.dir.path(), "tk.yaml", &url, METHODS, true);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.query", &IndexMap::new(), tk, Some(&e.store), 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(r.exit_code, Some(0));
    assert!(r.external_untrusted);
    assert_eq!(serde_json::from_str::<Value>(&r.stdout).unwrap(), json!([{"name": "tank"}]));
}

#[tokio::test]
async fn params_sent_positionally_in_declared_order() {
    let e = env();
    e.store.create("demo_cred", "ws_api_key", "correct-key", None, None, None, "test", "").unwrap();
    let (url, seen) = ws_server().await;
    let tier1 = toolkit_yaml(e.dir.path(), "tk.yaml", &url, METHODS, true);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let p = params(&[("name", "tank/raid/dev-1"), ("comment", "second")]);
    let r = run("pool.dataset.create", &p, tk, Some(&e.store), 5.0, 65536, false, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(serde_json::from_str::<Value>(&r.stdout).unwrap()["name"], "tank/raid/dev-1");
    let frames = seen.lock().clone();
    assert_eq!(frames[0]["method"], "auth.login_with_api_key");
    assert_eq!(frames[1]["params"], json!(["tank/raid/dev-1", "second"]));
}

#[tokio::test]
async fn rpc_error_maps_to_failed_exit_1() {
    let (url, _) = ws_server().await;
    let dir = tempfile::tempdir().unwrap();
    let tier1 = toolkit_yaml(dir.path(), "tk.yaml", &url, METHODS, false);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.unknown", &IndexMap::new(), tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.exit_code, Some(1));
    assert_eq!(r.stdout, "");
    assert_eq!(r.stderr, "{\"code\": -32601, \"message\": \"Method not found\"}");
}

#[tokio::test]
async fn disallowed_method_denied_before_send() {
    let e = env();
    e.store.create("demo_cred", "ws_api_key", "correct-key", None, None, None, "test", "").unwrap();
    let (url, seen) = ws_server().await;
    let tier1 = toolkit_yaml(e.dir.path(), "tk.yaml", &url, METHODS, true);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.dataset.delete", &IndexMap::new(), tk, Some(&e.store), 5.0, 65536, false, None)
        .await
        .unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "RPC method 'pool.dataset.delete' is not allowed for this toolkit.");
    assert!(seen.lock().is_empty());
}

#[tokio::test]
async fn wrong_credential_denied() {
    let e = env();
    e.store.create("demo_cred", "ws_api_key", "wrong-key", None, None, None, "test", "").unwrap();
    let (url, seen) = ws_server().await;
    let tier1 = toolkit_yaml(e.dir.path(), "tk.yaml", &url, METHODS, true);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.query", &IndexMap::new(), tk, Some(&e.store), 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "TrueNAS authentication failed.");
    // The method itself was never sent.
    assert_eq!(seen.lock().len(), 1);
}

#[tokio::test]
async fn missing_credential_store_denied() {
    let (url, _) = ws_server().await;
    let dir = tempfile::tempdir().unwrap();
    let tier1 = toolkit_yaml(dir.path(), "tk.yaml", &url, METHODS, true);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.query", &IndexMap::new(), tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "No credential store is configured, but this toolkit needs one.");
}

#[tokio::test]
async fn timeout_on_non_idempotent_is_unknown() {
    let e = env();
    e.store.create("demo_cred", "ws_api_key", "correct-key", None, None, None, "test", "").unwrap();
    let (url, _) = ws_server().await;
    let tier1 = toolkit_yaml(e.dir.path(), "tk2.yaml", &url, "[\"slow.method\"]", true);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("slow.method", &IndexMap::new(), tk, Some(&e.store), 0.2, 65536, false, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_UNKNOWN);
    assert_eq!(
        r.stderr,
        "Timeout of 0.2s exceeded. The outcome is UNKNOWN: the call may have reached TrueNAS. Do not retry without checking the state first."
    );
}

#[tokio::test]
async fn redaction_scrubs_credential_from_response() {
    let e = env();
    e.store.create("demo_cred", "ws_api_key", "correct-key", None, None, None, "test", "").unwrap();
    let (url, _) = ws_server().await;
    let tier1 = toolkit_yaml(e.dir.path(), "tk.yaml", &url, METHODS, true);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let redact: Redact = Arc::new(|t: &str| t.replace("correct-key", "***"));
    let r = run(
        "pool.dataset.create",
        &params(&[("name", "correct-key-leak")]),
        tk,
        Some(&e.store),
        5.0,
        65536,
        false,
        Some(&redact),
    )
    .await
    .unwrap();
    assert!(!r.stdout.contains("correct-key"));
    assert_eq!(r.stdout, "{\"name\": \"***-leak\"}");
}

#[tokio::test]
async fn truncated_response_is_not_json_rpc() {
    let (url, _) = ws_server().await;
    let dir = tempfile::tempdir().unwrap();
    let tier1 = toolkit_yaml(dir.path(), "tk.yaml", &url, METHODS, false);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.query", &IndexMap::new(), tk, None, 5.0, 10, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert!(r.truncated);
    assert_eq!(r.exit_code, None);
    assert_eq!(r.stdout.len(), 10);
    assert_eq!(r.stderr, "Response was not a JSON-RPC object.");
}

#[tokio::test]
async fn connect_failure_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = toolkit_yaml(dir.path(), "tk3.yaml", "ws://127.0.0.1:1", "[\"pool.query\"]", false);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.query", &IndexMap::new(), tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(
        r.stderr,
        "Could not connect to ws://127.0.0.1:1: [Errno 111] Connect call failed ('127.0.0.1', 1)"
    );
}

#[tokio::test]
async fn probe_reachable_and_unreachable() {
    let (url, _) = ws_server().await;
    let dir = tempfile::tempdir().unwrap();
    let tier1 = toolkit_yaml(dir.path(), "tk.yaml", &url, METHODS, false);
    assert!(probe(tier1.toolkit("demo_truenas").unwrap()).await);
    let tier1 = toolkit_yaml(dir.path(), "tk3.yaml", "ws://127.0.0.1:1", "[\"pool.query\"]", false);
    assert!(!probe(tier1.toolkit("demo_truenas").unwrap()).await);
}

#[test]
fn close_texts_match_websockets() {
    let frame = CloseFrame { code: 1000.into(), reason: "".into() };
    assert_eq!(close_str(Some(&frame)), "1000 (OK)");
    let frame = CloseFrame { code: 4001.into(), reason: "bye".into() };
    assert_eq!(close_str(Some(&frame)), "4001 (private use) bye");
    assert_eq!(close_str(None), "1005 (no status received [internal])");
}

// -- Jobs and pinned TLS (1.24.0) -------------------------------------------------

const JOB_METHODS: &str = "[\"pool.dataset.unlock\", \"core.get_jobs\"]";

async fn unlock(tk: &Toolkit, which: &str, timeout: f64, idempotent: bool) -> ExecResult {
    run_call("pool.dataset.unlock", &params(&[("id", which)]), tk, None, timeout, 65536, idempotent, true, None)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_job_tool_returns_the_jobs_result() {
    let (url, seen) = ws_server().await;
    let dir = tempfile::tempdir().unwrap();
    let tier1 = toolkit_yaml(dir.path(), "tk.yaml", &url, JOB_METHODS, false);
    let tk = tier1.toolkit("demo_truenas").unwrap();

    let ok = unlock(tk, "ok", 5.0, true).await;
    assert_eq!(ok.outcome, OUTCOME_OK, "{}", ok.stderr);
    assert_eq!(serde_json::from_str::<Value>(&ok.stdout).unwrap(), json!({"unlocked": ["tank/a"]}));
    let polled = seen.lock().iter().filter(|f| f["method"] == "core.get_jobs").count();
    assert_eq!(polled, 1);

    let failed = unlock(tk, "fail", 5.0, true).await;
    assert_eq!(failed.outcome, OUTCOME_FAILED);
    assert!(failed.stderr.contains("FAILED") && failed.stderr.contains("bad passphrase"), "{}", failed.stderr);
    // Only state, result and error are read: the job's arguments never come back.
    assert!(!format!("{}{}", ok.stdout, failed.stderr).contains("secret-args"));
}

#[tokio::test]
async fn a_job_that_does_not_end_times_out() {
    let (url, _) = ws_server().await;
    let dir = tempfile::tempdir().unwrap();
    let tier1 = toolkit_yaml(dir.path(), "tk.yaml", &url, JOB_METHODS, false);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let started = Instant::now();
    let r = unlock(tk, "forever", 1.2, false).await;
    assert_eq!(r.outcome, OUTCOME_UNKNOWN, "{}", r.stderr);
    assert!(started.elapsed() < Duration::from_secs(4));
    let r = unlock(tk, "forever", 1.2, true).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
}

#[tokio::test]
async fn without_job_the_job_id_is_the_result() {
    let (url, _) = ws_server().await;
    let dir = tempfile::tempdir().unwrap();
    let tier1 = toolkit_yaml(dir.path(), "tk.yaml", &url, JOB_METHODS, false);
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.dataset.unlock", &params(&[("id", "ok")]), tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.stdout, "41");
}

/// A wss:// fake TrueNAS with a fresh self-signed certificate, and the
/// SHA-256 of that certificate.
async fn wss_server() -> (String, String) {
    use sha2::{Digest, Sha256};
    let cert = rcgen::generate_simple_self_signed(vec!["nas.invalid".to_string()]).unwrap();
    let der = cert.cert.der().clone();
    let pin = hex::encode(Sha256::digest(der.as_ref()));
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    fake_truenas(tls, Seen::default()).await;
                }
            });
        }
    });
    (format!("wss://127.0.0.1:{port}"), pin)
}

fn pinned_yaml(dir: &std::path::Path, ws_url: &str, pins: &str) -> Result<Tier1, ConfigError> {
    let path = dir.join("pinned.yaml");
    std::fs::write(
        &path,
        format!(
            "toolkits:\n  demo_truenas:\n    executor: truenas\n    ws_url: \"{ws_url}\"\n    allowed_rpc_methods: [\"pool.query\"]\n    tls_pin_sha256: {pins}\naudit:\n  dir: {}\n",
            dir.join("logs").display()
        ),
    )
    .unwrap();
    load_tier1(path.to_str().unwrap())
}

#[tokio::test]
async fn a_pinned_certificate_is_accepted_and_any_other_refused() {
    let (url, pin) = wss_server().await;
    let dir = tempfile::tempdir().unwrap();

    let tier1 = pinned_yaml(dir.path(), &url, &format!("[\"{}\"]", pin.to_uppercase())).unwrap();
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.query", &IndexMap::new(), tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert!(probe(tk).await);

    let other = "0".repeat(64);
    let tier1 = pinned_yaml(dir.path(), &url, &format!("[\"{other}\"]")).unwrap();
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let r = run("pool.query", &IndexMap::new(), tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert!(r.stderr.contains("not pinned"), "{}", r.stderr);
    assert!(!probe(tk).await);

    // Without a pin the self-signed certificate is not trusted either.
    let tier1 = toolkit_yaml(dir.path(), "plain.yaml", &url, "[\"pool.query\"]", false);
    let r = run("pool.query", &IndexMap::new(), tier1.toolkit("demo_truenas").unwrap(), None, 5.0, 65536, true, None)
        .await
        .unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
}

#[test]
fn bad_pins_are_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let pin = "a".repeat(64);
    for (url, pins, needle) in [
        ("wss://127.0.0.1:1", "[\"abc\"]".to_string(), "is not a SHA-256"),
        ("wss://127.0.0.1:1", "[]".to_string(), "tls_pin_sha256"),
        ("ws://127.0.0.1:1", format!("[\"{pin}\"]"), "needs a wss:// ws_url"),
    ] {
        let err = pinned_yaml(dir.path(), url, &pins).unwrap_err();
        assert!(err.message.contains(needle), "{}", err.message);
    }
}
