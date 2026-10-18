//! `secret: true` parameters and nested `truenas` params (1.23.0), end to
//! end through `Service::call` against a loopback JSON-RPC server that
//! echoes what it was sent -- the way a real API error can quote its input.

mod app_env;

use std::sync::{Arc, Mutex};

use app_env::*;
use futures::{SinkExt, StreamExt};
use gatekeeper::service::CallError;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

const PASSPHRASE: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

type Seen = Arc<Mutex<Vec<Value>>>;

/// Answers `connect`, then echoes every method call's params back as its
/// result (`pool.dataset.create`) or quotes them in an error (anything else).
async fn echo_server() -> (String, Seen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let seen = seen2.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else { return };
                while let Some(Ok(Message::Text(raw))) = ws.next().await {
                    let request: Value = serde_json::from_str(raw.as_str()).unwrap();
                    let reply = match request["msg"].as_str() {
                        Some("connect") => json!({"msg": "connected", "version": "1"}),
                        Some("method") => {
                            seen.lock().unwrap().push(request.clone());
                            let id = request["id"].clone();
                            if request["method"] == "pool.dataset.create" {
                                json!({"msg": "result", "id": id, "result": request["params"]})
                            } else {
                                json!({"msg": "result", "id": id,
                                       "error": {"code": 22, "message": format!("bad input: {}", request["params"])}})
                            }
                        }
                        _ => continue,
                    };
                    if ws.send(Message::text(reply.to_string())).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (format!("ws://127.0.0.1:{port}"), seen)
}

fn tier1(ws_url: &str) -> Value {
    json!({"toolkits": {"nas": {
        "executor": "truenas",
        "ws_url": ws_url,
        "allowed_rpc_methods": ["pool.dataset.create", "pool.dataset.unlock"],
    }}})
}

fn passphrase_param() -> Value {
    json!({"type": "string", "required": true, "secret": true, "pattern": "^[0-9a-f]{64}$",
           "description": "dataset passphrase"})
}

fn dataset_param() -> Value {
    json!({"type": "string", "required": true, "pattern": "^tank/castor/t/[a-z0-9-]{1,40}$",
           "description": "dataset"})
}

fn tools() -> Vec<Value> {
    vec![
        json!({
            "id": "nas.dataset_create", "toolkit": "nas", "version": 1,
            "title": "Create", "description": "Creates an encrypted dataset.",
            "category": "write", "idempotent": false, "enabled": true,
            "method": "pool.dataset.create",
            "params": {"data": {
                "name": "{dataset}",
                "quota": "{quota}",
                "inherit_encryption": false,
                "encryption": true,
                "encryption_options": {"algorithm": "AES-256-GCM", "passphrase": "{passphrase}"},
            }},
            "parameters": {
                "dataset": dataset_param(),
                "quota": {"type": "integer", "required": true, "minimum": 1, "description": "bytes"},
                "passphrase": passphrase_param(),
            },
            "required_scopes": ["dataset:{dataset}"],
            "timeout_seconds": 10, "max_output_bytes": 65536,
        }),
        json!({
            "id": "nas.dataset_unlock", "toolkit": "nas", "version": 1,
            "title": "Unlock", "description": "Unlocks a dataset.",
            "category": "write", "idempotent": true, "enabled": true,
            "method": "pool.dataset.unlock",
            "params": {
                "id": "{dataset}",
                "options": {"datasets": [{"name": "{dataset}", "passphrase": "{passphrase}"}],
                            "filters": [["name", "=", "{dataset}"]]},
            },
            "parameters": {"dataset": dataset_param(), "passphrase": passphrase_param()},
            "required_scopes": ["dataset:{dataset}"],
            "timeout_seconds": 10, "max_output_bytes": 65536,
        }),
    ]
}

fn castord() -> gatekeeper::identity::Identity {
    agent("castord", &["nas.dataset_create", "nas.dataset_unlock"], &["dataset:tank/castor/t/*"])
}

/// The whole audit file, as text.
fn audit_text(e: &AppEnv) -> String {
    e.audit_lines().iter().map(Value::to_string).collect::<Vec<_>>().join("\n")
}

#[tokio::test]
async fn nested_params_reach_the_api_typed_and_the_secret_stays_out_of_log_and_output() {
    let (url, seen) = echo_server().await;
    let e = builder().tier1(tier1(&url)).tools(tools()).build();
    let a = args(json!({"dataset": "tank/castor/t/alpha", "quota": 1073741824_i64, "passphrase": PASSPHRASE}));
    let result = e.service.call(&castord(), "nas.dataset_create", &a, None).await.unwrap();
    assert_eq!(result.outcome, "ok", "{}", result.stderr);

    // The API got the real value, nested, with the quota as a number.
    let sent = seen.lock().unwrap().last().cloned().unwrap();
    let data = &sent["params"][0];
    assert_eq!(data["name"], "tank/castor/t/alpha");
    assert_eq!(data["quota"], json!(1073741824_i64));
    assert_eq!(data["inherit_encryption"], json!(false));
    assert_eq!(data["encryption_options"]["passphrase"], PASSPHRASE);

    // The echo comes back masked, and the audit record never had it.
    assert!(!result.stdout.contains(PASSPHRASE), "{}", result.stdout);
    assert!(result.stdout.contains("***"));
    let record = e.audit_lines().pop().unwrap();
    assert_eq!(record["parameters"]["passphrase"], "***");
    assert_eq!(record["parameters"]["dataset"], "tank/castor/t/alpha");
    assert!(record["command"].as_str().unwrap().starts_with("pool.dataset.create "));
    assert!(!audit_text(&e).contains(PASSPHRASE));
}

#[tokio::test]
async fn arrays_of_objects_and_of_arrays_and_an_error_quoting_the_secret() {
    let (url, seen) = echo_server().await;
    let e = builder().tier1(tier1(&url)).tools(tools()).build();
    let a = args(json!({"dataset": "tank/castor/t/alpha", "passphrase": PASSPHRASE}));
    let result = e.service.call(&castord(), "nas.dataset_unlock", &a, None).await.unwrap();

    let sent = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(sent["params"][0], "tank/castor/t/alpha");
    assert_eq!(sent["params"][1]["datasets"][0]["passphrase"], PASSPHRASE);
    assert_eq!(sent["params"][1]["filters"], json!([["name", "=", "tank/castor/t/alpha"]]));

    // The server's error quotes the params: masked in what the caller sees.
    assert_ne!(result.outcome, "ok");
    let shown = format!("{}{}{:?}", result.stdout, result.stderr, result.denial_detail);
    assert!(!shown.contains(PASSPHRASE), "{shown}");
    assert!(!audit_text(&e).contains(PASSPHRASE));
}

#[tokio::test]
async fn a_denied_call_does_not_log_the_secret() {
    let (url, _) = echo_server().await;
    let e = builder().tier1(tier1(&url)).tools(tools()).build();
    // Out of scope, and an agent that does not hold the tool at all.
    let a = args(json!({"dataset": "tank/castor/t/alpha", "passphrase": PASSPHRASE}));
    let narrow = agent("narrow", &["nas.dataset_unlock"], &["dataset:tank/castor/t/beta"]);
    let stranger = agent("stranger", &[], &[]);
    for who in [narrow, stranger] {
        let r = e.service.call(&who, "nas.dataset_unlock", &a, None).await;
        assert!(matches!(r, Err(CallError::Denied(_))), "{r:?}");
        let record = e.audit_lines().pop().unwrap();
        assert_eq!(record["outcome"], "denied");
        assert_eq!(record["parameters"]["passphrase"], "***");
    }
    // A value that fails its pattern is denied too, and not logged either.
    let bad = format!("{PASSPHRASE}zz");
    let a = args(json!({"dataset": "tank/castor/t/alpha", "passphrase": bad}));
    let r = e.service.call(&castord(), "nas.dataset_unlock", &a, None).await;
    assert!(matches!(r, Err(CallError::Denied(_))), "{r:?}");
    assert!(!audit_text(&e).contains(PASSPHRASE));
}

#[test]
fn the_schema_marks_a_secret_write_only() {
    let e = builder().tier1(tier1("ws://127.0.0.1:1")).tools(tools()).build();
    let tools = e.service.visible_tools(&castord());
    let create = tools.iter().find(|t| t.name == "nas.dataset_create").unwrap();
    assert_eq!(create.input_schema["properties"]["passphrase"]["writeOnly"], json!(true));
    assert!(create.input_schema["properties"]["dataset"].get("writeOnly").is_none());
}
