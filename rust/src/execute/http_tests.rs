//! Tests for the `http` executor (ports of `tests/test_execute_http.py`
//! and the executor parts of `test_http_raw_body.py`/`test_nested_body.py`).
//!
//! A real loopback HTTP server, not a mocked transport: the properties
//! that matter -- the resolved IP is actually checked before connecting, a
//! redirect is actually not followed, the credential actually lands in a
//! header and nowhere else -- are exactly what a mock would assume away.

use super::*;
use crate::catalog::{parse_tool_spec, ToolDef};
use crate::credentials::tests::{env, Env};
use crate::tier1::{load_tier1, Tier1};
use crate::validate::{build_http_request, HttpRequest, Values};
use hyper::service::service_fn;
use std::io::Write as _;

/// What the loopback server saw: (path, lower-cased headers, body).
type Seen = Arc<parking_lot::Mutex<Vec<(String, Vec<(String, String)>, Vec<u8>)>>>;

fn json_response(status: u16, payload: &Value) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(pyjson::dumps(payload))))
        .unwrap()
}

async fn handle(
    req: hyper::Request<Incoming>,
    seen: Seen,
) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let method = req.method().clone();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    let raw = req.into_body().collect().await.unwrap().to_bytes().to_vec();
    seen.lock().push((path.clone(), headers.clone(), raw.clone()));
    let header_obj: Map<String, Value> =
        headers.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
    if method == hyper::Method::POST {
        if path.starts_with("/api/v1/") {
            let content_type =
                headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.clone()).unwrap_or_default();
            return Ok(json_response(
                200,
                &serde_json::json!({"path": path, "raw": String::from_utf8_lossy(&raw), "content_type": content_type}),
            ));
        }
        let body = if raw.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_slice(&raw)
                .unwrap_or_else(|_| serde_json::json!({"raw": String::from_utf8_lossy(&raw)}))
        };
        return Ok(json_response(200, &serde_json::json!({"path": path, "body": body})));
    }
    if path.starts_with("/api/redirect") {
        return Ok(hyper::Response::builder()
            .status(302)
            .header("Location", "http://evil.example/steal")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    if path.starts_with("/api/slow") {
        tokio::time::sleep(Duration::from_secs(2)).await;
        return Ok(json_response(200, &serde_json::json!({"ok": true})));
    }
    if path.starts_with("/api/authfail") {
        return Ok(json_response(401, &serde_json::json!({"ok": false})));
    }
    if path.starts_with("/api/gzip") {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(br#"{"zipped": [1, 2, 3]}"#).unwrap();
        return Ok(hyper::Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .body(Full::new(Bytes::from(enc.finish().unwrap())))
            .unwrap());
    }
    if path.starts_with("/api/bomb") || path.starts_with("/api/double") {
        // 64 MiB of zeros: about 64 KB of gzip.
        let gzip = |data: &[u8]| {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            enc.write_all(data).unwrap();
            enc.finish().unwrap()
        };
        let once = gzip(&vec![0u8; 64 << 20]);
        let (body, coding) = if path.starts_with("/api/double") { (gzip(&once), "gzip, gzip") } else { (once, "gzip") };
        return Ok(hyper::Response::builder()
            .status(200)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Encoding", coding)
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }
    if path.starts_with("/api/big") {
        let items: Vec<Value> = (0..1000).map(Value::from).collect();
        return Ok(json_response(200, &Value::Array(items)));
    }
    Ok(json_response(200, &serde_json::json!({"path": path, "headers": header_obj})))
}

/// A real loopback HTTP server.
async fn http_server() -> (u16, Seen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let seen = seen2.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| handle(req, seen.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (port, seen)
}

fn write_tier1(dir: &std::path::Path, name: &str, body: &str) -> Tier1 {
    let path = dir.join(name);
    std::fs::write(&path, format!("{body}audit:\n  dir: {}\n", dir.join("logs").display())).unwrap();
    load_tier1(path.to_str().unwrap()).unwrap()
}

fn demo_tier1(dir: &std::path::Path, port: u16, credential: bool) -> Tier1 {
    let cred = if credential { "    credential: demo_cred\n" } else { "" };
    write_tier1(
        dir,
        "toolkits.yaml",
        &format!(
            "toolkits:\n  demo_http:\n    executor: http\n    base_url: \"http://127.0.0.1:{port}\"\n    allowed_methods: [\"GET\", \"POST\"]\n    allowed_path_prefixes: [\"/api/\"]\n    allowed_cidrs: [\"127.0.0.1/32\"]\n{cred}"
        ),
    )
}

fn tool(tier1: &Tier1, overrides: Value) -> ToolDef {
    let mut spec = serde_json::json!({
        "id": "demo_http.get_thing", "toolkit": "demo_http", "version": 1,
        "title": "Get thing", "description": "test", "category": "read", "enabled": true,
        "method": "GET", "path": "/api/thing/{name}",
        "parameters": {"name": {"type": "string", "pattern": "^[a-z]+$", "required": true}},
        "timeout_seconds": 5, "max_output_bytes": 65536,
    });
    for (k, v) in overrides.as_object().unwrap() {
        spec[k] = v.clone();
    }
    parse_tool_spec(&spec, tier1).unwrap()
}

fn values(pairs: &[(&str, &str)]) -> Values {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn create(env: &Env, kind: &str, header: Option<&str>, header_format: Option<&str>, value: &str) {
    env.store.create("demo_cred", kind, value, header, None, header_format, "test", "").unwrap();
}

async fn call(
    req: &HttpRequest,
    tk: &Toolkit,
    store: Option<&CredentialStore>,
    timeout: f64,
    max: i64,
    idempotent: bool,
) -> ExecResult {
    run(&req.method, &req.path, &req.query, req.body.as_ref(), None, tk, store, timeout, max, idempotent, None)
        .await
        .unwrap()
}

fn get_thing(tier1: &Tier1, tk: &Toolkit) -> HttpRequest {
    build_http_request(&tool(tier1, serde_json::json!({})), &values(&[("name", "widgets")]), tk).unwrap()
}

fn stdout_json(r: &ExecResult) -> Value {
    serde_json::from_str(&r.stdout).unwrap()
}

#[tokio::test]
async fn successful_get() {
    let e = env();
    create(&e, "api_key_header", Some("X-Api-Key"), None, "super-secret-abc");
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = call(&get_thing(&tier1, tk), tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(r.exit_code, Some(200));
    assert!(r.external_untrusted);
    let payload = stdout_json(&r);
    assert_eq!(payload["path"], "/api/thing/widgets");
    assert_eq!(payload["headers"]["x-api-key"], "super-secret-abc");
    assert_eq!(payload["headers"]["host"], format!("127.0.0.1:{port}"));
    assert_eq!(payload["headers"]["accept"], "*/*");
    assert_eq!(payload["headers"]["accept-encoding"], "gzip, deflate");
}

#[tokio::test]
async fn url_query_credential_injected_as_query_param() {
    let e = env();
    create(&e, "url_query", Some("apikey"), None, "super-secret-query-key");
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = call(&get_thing(&tier1, tk), tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_OK);
    let payload = stdout_json(&r);
    assert!(payload["path"].as_str().unwrap().contains("apikey=super-secret-query-key"));
    // Never also sent as a header.
    assert!(payload["headers"].get("x-api-key").is_none());
}

#[tokio::test]
async fn header_format_wraps_the_secret() {
    let e = env();
    create(&e, "api_key_header", Some("Authorization"), Some("MediaBrowser Token=\"{value}\""), "jf-token-123");
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = call(&get_thing(&tier1, tk), tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_OK);
    assert_eq!(stdout_json(&r)["headers"]["authorization"], "MediaBrowser Token=\"jf-token-123\"");
}

#[tokio::test]
async fn bearer_and_basic_credentials() {
    let e = env();
    e.store.create("bearer_cred", "bearer", "tok-1", None, None, None, "t", "").unwrap();
    e.store.create("basic_cred", "basic", "user:pass", None, None, None, "t", "").unwrap();
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, false);
    let mut tk = tier1.toolkit("demo_http").unwrap().clone();
    let req = get_thing(&tier1, &tk);
    tk.credential = Some("bearer_cred".into());
    let r = call(&req, &tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(stdout_json(&r)["headers"]["authorization"], "Bearer tok-1");
    tk.credential = Some("basic_cred".into());
    let r = call(&req, &tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(stdout_json(&r)["headers"]["authorization"], "Basic dXNlcjpwYXNz");
}

#[tokio::test]
async fn url_path_credential_fills_base_url() {
    let e = env();
    e.store.create("demo_cred", "url_path", "123:abc", None, None, None, "t", "").unwrap();
    let (port, _) = http_server().await;
    let tier1 = write_tier1(
        e.dir.path(),
        "tk-urlpath.yaml",
        &format!(
            "toolkits:\n  demo_http:\n    executor: http\n    base_url: \"http://127.0.0.1:{port}/api/bot{{credential}}\"\n    allowed_methods: [\"GET\"]\n    allowed_path_prefixes: [\"/\"]\n    allowed_cidrs: [\"127.0.0.1/32\"]\n    credential: demo_cred\n"
        ),
    );
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = run("GET", "/getMe", &IndexMap::new(), None, None, tk, Some(&e.store), 5.0, 65536, true, None)
        .await
        .unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(stdout_json(&r)["path"], "/api/bot123:abc/getMe");
    // The probe skips a base_url that needs a credential.
    assert!(probe(tk).await);
}

#[tokio::test]
async fn credential_masked_when_redacted() {
    let e = env();
    create(&e, "api_key_header", Some("X-Api-Key"), None, "super-secret-abc");
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let req = get_thing(&tier1, tk);
    let redact: Redact = Arc::new(|t: &str| t.replace("super-secret-abc", "***"));
    let r = run(&req.method, &req.path, &req.query, None, None, tk, Some(&e.store), 5.0, 65536, true, Some(&redact))
        .await
        .unwrap();
    assert!(!r.stdout.contains("super-secret-abc"));
    assert!(r.stdout.contains("***"));
}

#[tokio::test]
async fn ssrf_blocked_when_cidr_excludes_target() {
    let e = env();
    let (port, seen) = http_server().await;
    let tier1 = write_tier1(
        e.dir.path(),
        "toolkits2.yaml",
        &format!(
            "toolkits:\n  demo_http:\n    executor: http\n    base_url: \"http://127.0.0.1:{port}\"\n    allowed_methods: [\"GET\"]\n    allowed_path_prefixes: [\"/api/\"]\n    allowed_cidrs: [\"10.0.0.0/8\"]\n"
        ),
    );
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = call(&get_thing(&tier1, tk), tk, None, 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "'127.0.0.1' resolves to 127.0.0.1, which is outside this toolkit's allowed_cidrs.");
    assert!(!r.external_untrusted);
    assert!(seen.lock().is_empty());
    assert!(!probe(tk).await);
}

#[tokio::test]
async fn unresolvable_host_is_executor_unavailable() {
    let e = env();
    let tier1 = write_tier1(
        e.dir.path(),
        "tk-nx.yaml",
        "toolkits:\n  demo_http:\n    executor: http\n    base_url: \"http://nonexistent.invalid\"\n    allowed_methods: [\"GET\"]\n    allowed_path_prefixes: [\"/api/\"]\n    allowed_cidrs: [\"127.0.0.1/32\"]\n",
    );
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = run("GET", "/api/x", &IndexMap::new(), None, None, tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert!(r.stderr.starts_with("Could not resolve 'nonexistent.invalid': [Errno "), "{}", r.stderr);
}

#[tokio::test]
async fn tool_base_url_override_is_what_gets_checked() {
    // service hands the executor a toolkit whose base_url is the tool's
    // override; that URL's host is what is resolved and checked.
    let e = env();
    let (port, _) = http_server().await;
    let tier1 = write_tier1(
        e.dir.path(),
        "tk-override.yaml",
        "toolkits:\n  demo_http:\n    executor: http\n    base_url: \"http://10.255.255.1:9\"\n    allowed_methods: [\"GET\"]\n    allowed_path_prefixes: [\"/api/\"]\n    allowed_cidrs: [\"127.0.0.1/32\"]\n",
    );
    let mut tk = tier1.toolkit("demo_http").unwrap().clone();
    tk.base_url = Some(format!("http://127.0.0.1:{port}"));
    let r = call(&get_thing(&tier1, &tk), &tk, None, 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(stdout_json(&r)["path"], "/api/thing/widgets");
}

#[tokio::test]
async fn redirect_is_reported_not_followed() {
    let e = env();
    create(&e, "api_key_header", Some("X-Api-Key"), None, "k");
    let (port, seen) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let t = tool(&tier1, serde_json::json!({"id": "demo_http.redir", "path": "/api/redirect", "parameters": {}}));
    let req = build_http_request(&t, &Values::new(), tk).unwrap();
    let r = call(&req, tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.exit_code, Some(302));
    assert_eq!(r.stderr, "Redirect (302) to 'http://evil.example/steal', not followed.");
    assert_eq!(seen.lock().len(), 1);
}

#[tokio::test]
async fn timeout_on_non_idempotent_is_unknown() {
    let e = env();
    create(&e, "api_key_header", Some("X-Api-Key"), None, "k");
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let t = tool(
        &tier1,
        serde_json::json!({"id": "demo_http.slow", "path": "/api/slow", "category": "write", "idempotent": false, "parameters": {}}),
    );
    let req = build_http_request(&t, &Values::new(), tk).unwrap();
    let r = call(&req, tk, Some(&e.store), 0.2, 65536, false).await;
    assert_eq!(r.outcome, OUTCOME_UNKNOWN);
    assert_eq!(
        r.stderr,
        "Timeout of 0.2s exceeded. The outcome is UNKNOWN: the request may have reached the target. Do not retry without checking the state first."
    );
    assert!(r.external_untrusted);
}

#[tokio::test]
async fn timeout_on_idempotent_is_failed() {
    let e = env();
    create(&e, "api_key_header", Some("X-Api-Key"), None, "k");
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let t = tool(&tier1, serde_json::json!({"id": "demo_http.slow2", "path": "/api/slow", "parameters": {}}));
    let req = build_http_request(&t, &Values::new(), tk).unwrap();
    let r = call(&req, tk, Some(&e.store), 0.2, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "Timeout of 0.2s exceeded.");
}

#[tokio::test]
async fn response_capped_at_max_output_bytes() {
    let e = env();
    create(&e, "api_key_header", Some("X-Api-Key"), None, "k");
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = call(&get_thing(&tier1, tk), tk, Some(&e.store), 5.0, 10, true).await;
    assert!(r.truncated);
    assert_eq!(r.stdout.len(), 10);
}

#[tokio::test]
async fn json_list_capped_at_max_items() {
    let e = env();
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, false);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = run("GET", "/api/big", &IndexMap::new(), None, None, tk, None, 5.0, 1 << 20, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK);
    assert!(!r.truncated);
    assert_eq!(stdout_json(&r).as_array().unwrap().len(), 500);
}

#[tokio::test]
async fn gzip_response_is_decoded() {
    let e = env();
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, false);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = run("GET", "/api/gzip", &IndexMap::new(), None, None, tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(r.stdout, "{\"zipped\": [1, 2, 3]}");
}

#[tokio::test]
async fn invalid_url_component_denied_not_raised() {
    let e = env();
    create(&e, "api_key_header", Some("X-Api-Key"), None, "k");
    let (port, seen) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let t = tool(
        &tier1,
        serde_json::json!({"id": "demo_http.weird", "parameters": {"name": {"type": "string", "pattern": "^.*$", "required": true}}}),
    );
    let req = build_http_request(&t, &values(&[("name", "a?b")]), tk).unwrap();
    let r = call(&req, tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "Resolved request path is not a valid URL component: Invalid URL component 'path'");
    assert!(seen.lock().is_empty());
}

#[tokio::test]
async fn auth_failure_marks_credential_suspect_without_changing_secret() {
    let e = env();
    create(&e, "api_key_header", Some("X-Api-Key"), None, "super-secret-abc");
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let t = tool(&tier1, serde_json::json!({"id": "demo_http.authfail", "path": "/api/authfail", "parameters": {}}));
    let req = build_http_request(&t, &Values::new(), tk).unwrap();
    let before = e.store.raw().unwrap()["demo_cred"]["ciphertext"].clone();
    let r = call(&req, tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.exit_code, Some(401));
    let meta = &e.store.names(None).unwrap()[0];
    assert_eq!(meta.suspect_status.as_deref(), Some("auth_failed"));
    assert!(meta.suspect_at.is_some());
    assert_eq!(e.store.raw().unwrap()["demo_cred"]["ciphertext"], before);
    assert_eq!(e.store.resolve("demo_cred").unwrap().unwrap().value, "super-secret-abc");
}

#[tokio::test]
async fn credential_kind_mismatch_in_base_url_denied() {
    let e = env();
    e.store.create("demo_cred", "bearer", "should-not-land-in-a-url", None, None, None, "t", "").unwrap();
    let (port, seen) = http_server().await;
    let tier1 = write_tier1(
        e.dir.path(),
        "toolkits5.yaml",
        &format!(
            "toolkits:\n  demo_http:\n    executor: http\n    base_url: \"http://127.0.0.1:{port}/bot{{credential}}\"\n    allowed_methods: [\"GET\"]\n    allowed_path_prefixes: [\"/api/\"]\n    allowed_cidrs: [\"127.0.0.1/32\"]\n    credential: demo_cred\n"
        ),
    );
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = call(&get_thing(&tier1, tk), tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(
        r.stderr,
        "This toolkit's base_url substitutes a credential into the URL path, but 'demo_cred' is kind 'bearer', not 'url_path'. Only a 'url_path' credential may fill this placeholder."
    );
    assert!(seen.lock().is_empty());
}

#[tokio::test]
async fn missing_credential_denied() {
    let e = env();
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, true);
    let tk = tier1.toolkit("demo_http").unwrap();
    let req = get_thing(&tier1, tk);
    let r = call(&req, tk, None, 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "No credential store is configured, but this toolkit needs one.");
    let r = call(&req, tk, Some(&e.store), 5.0, 65536, true).await;
    assert_eq!(r.stderr, "Credential 'demo_cred' is not configured yet.");
}

#[tokio::test]
async fn connection_refused_is_reported() {
    let e = env();
    let tier1 = demo_tier1(e.dir.path(), 1, false);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = run("GET", "/api/x", &IndexMap::new(), None, None, tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "Request failed: All connection attempts failed");
    assert!(r.external_untrusted);
}

#[tokio::test]
async fn probe_reports_reachable_and_unreachable() {
    let e = env();
    let (port, seen) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, false);
    assert!(probe(tier1.toolkit("demo_http").unwrap()).await);
    // TCP only: no request reached the server.
    assert!(seen.lock().is_empty());
    let tier1 = demo_tier1(e.dir.path(), 1, false);
    assert!(!probe(tier1.toolkit("demo_http").unwrap()).await);
}

#[tokio::test]
async fn nested_body_is_sent_as_json() {
    let e = env();
    let (port, seen) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, false);
    let tk = tier1.toolkit("demo_http").unwrap();
    let t = tool(
        &tier1,
        serde_json::json!({
            "id": "demo_http.tdarr", "method": "POST", "path": "/api/cruddb",
            "body": {"data": {"collection": "{collection}", "mode": "getAll", "docID": "", "n": 3}},
            "parameters": {"collection": {"type": "string", "pattern": "^[A-Za-z]+$", "required": true}},
        }),
    );
    let req = build_http_request(&t, &values(&[("collection", "StatisticsJSONDB")]), tk).unwrap();
    let r = call(&req, tk, None, 5.0, 65536, true).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(
        stdout_json(&r)["body"],
        serde_json::json!({"data": {"collection": "StatisticsJSONDB", "mode": "getAll", "docID": "", "n": 3}})
    );
    let (_, headers, raw) = seen.lock()[0].clone();
    // httpx's json= encoding: compact separators.
    assert_eq!(raw, br#"{"data":{"collection":"StatisticsJSONDB","mode":"getAll","docID":"","n":3}}"#);
    assert!(headers.contains(&("content-type".into(), "application/json".into())));
}

#[tokio::test]
async fn bodyless_post_sends_content_length_zero() {
    let e = env();
    let (port, seen) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, false);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = run("POST", "/api/x", &IndexMap::new(), None, None, tk, None, 5.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK);
    assert!(seen.lock()[0].1.contains(&("content-length".into(), "0".into())));
}

// -- Raw JSON body mode (test_http_raw_body.py, executor parts) -----------

const WORKFLOW_JSON: &str = r#"{"name":"nightly-backup", "nodes":[{"name":"Cron","type":"n8n-nodes-base.cron","parameters":{"triggerTimes":{"item":[{"hour":3}]}}}], "connections":{}, "settings":{"saveDataErrorExecution":"all"}, "active":false}"#;

fn n8n(dir: &std::path::Path, port: u16) -> (Tier1, ToolDef) {
    let tier1 = write_tier1(
        dir,
        "tk-n8n.yaml",
        &format!(
            "toolkits:\n  n8n_admin:\n    executor: http\n    base_url: \"http://127.0.0.1:{port}\"\n    allowed_methods: [\"GET\", \"POST\"]\n    allowed_path_prefixes: [\"/api/\"]\n    allowed_cidrs: [\"127.0.0.1/32\"]\n"
        ),
    );
    let spec = serde_json::json!({
        "id": "n8n_admin.workflow_create", "toolkit": "n8n_admin", "version": 1,
        "title": "Create workflow", "description": "d", "category": "write", "idempotent": false,
        "enabled": true, "method": "POST", "path": "/api/v1/workflows",
        "body": {"raw_param": "workflow_json"},
        "parameters": {"workflow_json": {"type": "string", "pattern": "^.{1,30000}$", "required": true, "description": "doc"}},
        "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 65536,
    });
    let t = parse_tool_spec(&spec, &tier1).unwrap();
    (tier1, t)
}

async fn raw_call(req: &HttpRequest, body: Option<&Value>, raw_param: Option<&str>, tk: &Toolkit) -> ExecResult {
    run(&req.method, &req.path, &req.query, body, raw_param, tk, None, 5.0, 65536, false, None).await.unwrap()
}

#[tokio::test]
async fn raw_param_sends_the_string_verbatim_as_json() {
    let e = env();
    let (port, seen) = http_server().await;
    let (tier1, t) = n8n(e.dir.path(), port);
    let tk = tier1.toolkit("n8n_admin").unwrap();
    let req = build_http_request(&t, &values(&[("workflow_json", WORKFLOW_JSON)]), tk).unwrap();
    let r = raw_call(&req, req.body.as_ref(), t.body_raw_param.as_deref(), tk).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    let echo = stdout_json(&r);
    assert_eq!(echo["raw"], WORKFLOW_JSON);
    assert_eq!(echo["content_type"], "application/json");
    let (_, _, raw) = seen.lock().last().unwrap().clone();
    assert_eq!(raw, WORKFLOW_JSON.as_bytes());
}

#[tokio::test]
async fn raw_param_is_excluded_from_the_wrapper_object() {
    let e = env();
    let (port, _) = http_server().await;
    let (tier1, t) = n8n(e.dir.path(), port);
    let tk = tier1.toolkit("n8n_admin").unwrap();
    let req = build_http_request(&t, &values(&[("workflow_json", WORKFLOW_JSON)]), tk).unwrap();
    assert_eq!(req.body, Some(serde_json::json!({"workflow_json": WORKFLOW_JSON})));
    let mut body = req.body.clone().unwrap();
    body["extra"] = "ignored".into();
    let r = raw_call(&req, Some(&body), Some("workflow_json"), tk).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    let sent: Value = serde_json::from_str(stdout_json(&r)["raw"].as_str().unwrap()).unwrap();
    assert!(sent.get("workflow_json").is_none());
    assert!(sent.get("extra").is_none());
    assert_eq!(sent["name"], "nightly-backup");
}

#[tokio::test]
async fn invalid_json_errors_cleanly_without_sending_anything() {
    let e = env();
    let (port, seen) = http_server().await;
    let (tier1, t) = n8n(e.dir.path(), port);
    let tk = tier1.toolkit("n8n_admin").unwrap();
    let req = build_http_request(&t, &values(&[("workflow_json", "{\"name\":\"broken\",")]), tk).unwrap();
    let r = raw_call(&req, req.body.as_ref(), t.body_raw_param.as_deref(), tk).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.exit_code, None);
    assert_eq!(
        r.stderr,
        "Parameter 'workflow_json' must contain valid JSON (it is sent as the request body verbatim), but parsing it failed: Expecting property name enclosed in double quotes: line 1 column 18 (char 17). Nothing was sent."
    );
    assert!(seen.lock().is_empty());
}

#[tokio::test]
async fn missing_raw_param_falls_back_to_wrapping() {
    let e = env();
    let (port, _) = http_server().await;
    let (tier1, t) = n8n(e.dir.path(), port);
    let tk = tier1.toolkit("n8n_admin").unwrap();
    let body = serde_json::json!({"name": "nightly-backup"});
    let r = run("POST", "/api/v1/workflows", &IndexMap::new(), Some(&body), t.body_raw_param.as_deref(), tk, None, 5.0, 65536, false, None)
        .await
        .unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    let echo = stdout_json(&r);
    assert_eq!(serde_json::from_str::<Value>(echo["raw"].as_str().unwrap()).unwrap(), body);
    assert!(echo["content_type"].as_str().unwrap().contains("json"));
}

#[tokio::test]
async fn non_string_raw_value_is_serialized() {
    let e = env();
    let (port, seen) = http_server().await;
    let (tier1, _) = n8n(e.dir.path(), port);
    let tk = tier1.toolkit("n8n_admin").unwrap();
    let body = serde_json::json!({"workflow_json": {"name": "nightly-backup", "active": false}});
    let r = run("POST", "/api/v1/workflows", &IndexMap::new(), Some(&body), Some("workflow_json"), tk, None, 5.0, 65536, false, None)
        .await
        .unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(stdout_json(&r)["content_type"], "application/json");
    // json.dumps(value, ensure_ascii=False): Python's default separators.
    assert_eq!(seen.lock()[0].2, br#"{"name": "nightly-backup", "active": false}"#);
}

// -- Pure helpers -----------------------------------------------------------

#[test]
fn request_path_matches_httpx() {
    // Expected values produced by httpx 0.28.1.
    assert_eq!(request_path("/api/a b").unwrap(), "/api/a%20b");
    assert_eq!(request_path("/api/\u{e4}").unwrap(), "/api/%C3%A4");
    assert_eq!(request_path("/api/a%2Fb").unwrap(), "/api/a%2Fb");
    assert_eq!(request_path("/api/a/../b").unwrap(), "/api/b");
    assert_eq!(request_path("/api/a|b\"<>{}^`").unwrap(), "/api/a|b%22%3C%3E%7B%7D^%60");
    assert_eq!(request_path("/api/a%zz").unwrap(), "/api/a%zz");
    assert_eq!(request_path("/api/x;y=1").unwrap(), "/api/x;y=1");
    assert_eq!(request_path("/api/a\\b").unwrap(), "/api/a\\b");
    assert_eq!(request_path("").unwrap(), "/");
    assert_eq!(request_path("/api/a?b").unwrap_err(), "Invalid URL component 'path'");
    assert_eq!(request_path("/api/a#b").unwrap_err(), "Invalid URL component 'path'");
    assert_eq!(
        request_path("/api/\u{0}").unwrap_err(),
        "Invalid non-printable ASCII character in URL path component, '\\x00' at position 5."
    );
    assert_eq!(
        request_path("/api/a\tb").unwrap_err(),
        "Invalid non-printable ASCII character in URL path component, '\\t' at position 6."
    );
    assert_eq!(request_path("noslash").unwrap_err(), "For absolute URLs, path must be empty or begin with '/'");
}

#[test]
fn urlencode_matches_httpx_params() {
    let mut q = IndexMap::new();
    q.insert("q".to_string(), "a b/c?&=#\u{e4}~*'!()".to_string());
    q.insert("k".to_string(), String::new());
    q.insert("x+".to_string(), "1;2,3:@$".to_string());
    assert_eq!(urlencode(&q), "q=a+b%2Fc%3F%26%3D%23%C3%A4~%2A%27%21%28%29&k=&x%2B=1%3B2%2C3%3A%40%24");
}

#[test]
fn host_info_and_port_follow_urlsplit() {
    let i = host_info("User@Example.LAN:8989");
    assert_eq!(i.hostname, "example.lan");
    assert_eq!(parse_port(&i.port), Ok(Some(8989)));
    let i = host_info("[::1]:80");
    assert_eq!(i.hostname, "::1");
    assert_eq!(parse_port(&i.port), Ok(Some(80)));
    assert_eq!(parse_port(&host_info("h:x1").port).unwrap_err(), "Port could not be cast to integer value as 'x1'");
    assert_eq!(parse_port(&host_info("h:70000").port).unwrap_err(), "Port out of range 0-65535");
    assert_eq!(default_port(Some(0), "https"), 443);
    assert_eq!(default_port(None, "http"), 80);
}

#[test]
fn cap_json_budget() {
    // Expected values produced by Python's `_cap_json`.
    let v = serde_json::json!({"a": [1, 2, 3], "b": {"c": [4, 5]}, "d": 6});
    let mut budget = 4;
    assert_eq!(cap_json(&v, &mut budget), serde_json::json!({"a": [1, 2, 3]}));
    let mut budget = 2;
    assert_eq!(cap_json(&serde_json::json!([[1, 2, 3], 4]), &mut budget), serde_json::json!([[1, 2]]));
    let mut budget = 2;
    assert_eq!(cap_json(&serde_json::json!({"a": 1, "b": [1]}), &mut budget), serde_json::json!({"a": 1, "b": [1]}));
    let mut budget = 0;
    assert_eq!(cap_json(&serde_json::json!([1]), &mut budget), serde_json::json!("...(truncated)..."));
}

#[test]
fn fmt_seconds_like_python() {
    assert_eq!(fmt_seconds(5.0), "5");
    assert_eq!(fmt_seconds(0.2), "0.2");
    assert_eq!(fmt_seconds(0.3), "0.3");
}

#[test]
fn py_json_errors_match_cpython() {
    // (input, json.loads outcome) produced by CPython 3.13.
    let corpus: &[(&str, &str)] = &[
        ("", "Expecting value: line 1 column 1 (char 0)"),
        ("  ", "Expecting value: line 1 column 3 (char 2)"),
        ("[", "Expecting value: line 1 column 2 (char 1)"),
        ("{", "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"),
        ("{\"a\"", "Expecting ':' delimiter: line 1 column 5 (char 4)"),
        ("{\"a\":", "Expecting value: line 1 column 6 (char 5)"),
        ("{\"a\":1", "Expecting ',' delimiter: line 1 column 7 (char 6)"),
        ("{\"a\":1,", "Expecting property name enclosed in double quotes: line 1 column 8 (char 7)"),
        ("{\"a\":1,}", "Illegal trailing comma before end of object: line 1 column 7 (char 6)"),
        ("[1,]", "Illegal trailing comma before end of array: line 1 column 3 (char 2)"),
        ("[1", "Expecting ',' delimiter: line 1 column 3 (char 2)"),
        ("[1 2]", "Expecting ',' delimiter: line 1 column 4 (char 3)"),
        ("\"abc", "Unterminated string starting at: line 1 column 1 (char 0)"),
        ("\"a\\", "Unterminated string starting at: line 1 column 1 (char 0)"),
        ("\"a\\x\"", "Invalid \\escape: line 1 column 3 (char 2)"),
        ("\"\\u12\"", "Invalid \\uXXXX escape: line 1 column 3 (char 2)"),
        ("\"\\u12", "Invalid \\uXXXX escape: line 1 column 3 (char 2)"),
        ("\"\\u12zz\"", "Invalid \\uXXXX escape: line 1 column 3 (char 2)"),
        ("\"\\ud800\\u12\"", "Invalid \\uXXXX escape: line 1 column 9 (char 8)"),
        ("\"\\ud800\\uzzzz\"", "Invalid \\uXXXX escape: line 1 column 9 (char 8)"),
        ("\"a\u{1}\"", "Invalid control character at: line 1 column 3 (char 2)"),
        ("1 2", "Extra data: line 1 column 3 (char 2)"),
        ("-", "Expecting value: line 1 column 1 (char 0)"),
        ("-a", "Expecting value: line 1 column 1 (char 0)"),
        ("01", "Extra data: line 1 column 2 (char 1)"),
        ("1.", "Extra data: line 1 column 2 (char 1)"),
        ("1.e5", "Extra data: line 1 column 2 (char 1)"),
        ("1e", "Extra data: line 1 column 2 (char 1)"),
        ("1e+", "Extra data: line 1 column 2 (char 1)"),
        ("nul", "Expecting value: line 1 column 1 (char 0)"),
        ("NaN", "OK"),
        ("-Infinity", "OK"),
        ("-Inf", "Expecting value: line 1 column 1 (char 0)"),
        ("\u{feff}1", "Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)"),
        ("{1:2}", "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"),
        ("[\n1,\n,]", "Expecting value: line 3 column 1 (char 5)"),
        ("{\"name\":\"broken\",", "Expecting property name enclosed in double quotes: line 1 column 18 (char 17)"),
        ("{\"a\" 1}", "Expecting ':' delimiter: line 1 column 6 (char 5)"),
        ("[,]", "Expecting value: line 1 column 2 (char 1)"),
        ("[]x", "Extra data: line 1 column 3 (char 2)"),
        ("\"\\u1234", "Unterminated string starting at: line 1 column 1 (char 0)"),
        ("{\"a\":}", "Expecting value: line 1 column 6 (char 5)"),
        ("  x", "Expecting value: line 1 column 3 (char 2)"),
        ("\"\\ud800\\u", "Invalid \\uXXXX escape: line 1 column 9 (char 8)"),
        ("\"\\ud800\\u1\"", "Invalid \\uXXXX escape: line 1 column 9 (char 8)"),
        ("\"\\ud800\"", "OK"),
        ("{\"a\":1 \"b\":2}", "Expecting ',' delimiter: line 1 column 8 (char 7)"),
        ("[1,\n  2,\n  x]", "Expecting value: line 3 column 3 (char 11)"),
        ("{\"\u{e9}\":1, x}", "Expecting property name enclosed in double quotes: line 1 column 9 (char 8)"),
        ("tru", "Expecting value: line 1 column 1 (char 0)"),
        ("true false", "Extra data: line 1 column 6 (char 5)"),
        ("{\"a\":[1,{\"b\":}]}", "Expecting value: line 1 column 14 (char 13)"),
        ("\"\\", "Unterminated string starting at: line 1 column 1 (char 0)"),
        ("\"\\u\"", "Invalid \\uXXXX escape: line 1 column 3 (char 2)"),
        ("\"\\u123\"", "Invalid \\uXXXX escape: line 1 column 3 (char 2)"),
        ("\"\\uD834\\uDD1E\"", "OK"),
        ("{\"a\":1}  ", "OK"),
        ("{ }", "OK"),
        ("[ ]", "OK"),
        ("{\"a\":1,\"a\":2}", "OK"),
        ("1.5e", "Extra data: line 1 column 4 (char 3)"),
        ("-0", "OK"),
        ("-01", "Extra data: line 1 column 3 (char 2)"),
        ("[1.]", "Expecting ',' delimiter: line 1 column 3 (char 2)"),
    ];
    for (input, expected) in corpus {
        let got = match py_json_check(input) {
            Ok(()) => "OK".to_string(),
            Err(e) => e,
        };
        assert_eq!(&got, expected, "input {input:?}");
    }
}

#[tokio::test]
async fn compressed_body_inflates_only_up_to_the_cap() {
    let e = env();
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, false);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = run("GET", "/api/bomb", &IndexMap::new(), None, None, tk, None, 30.0, 1000, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert!(r.truncated);
    assert_eq!(r.stdout.len(), 1000);
}

#[tokio::test]
async fn stacked_content_encodings_are_refused() {
    let e = env();
    let (port, _) = http_server().await;
    let tier1 = demo_tier1(e.dir.path(), port, false);
    let tk = tier1.toolkit("demo_http").unwrap();
    let r = run("GET", "/api/double", &IndexMap::new(), None, None, tk, None, 30.0, 1000, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert!(r.stderr.contains("more than one Content-Encoding"), "{}", r.stderr);
}

#[tokio::test]
async fn timeout_covers_a_trickling_body() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    // Headers at once, then one chunk a second: every read is well inside
    // the per-read limit, the whole response is not inside the tool's.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else { return };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await;
        for _ in 0..30 {
            if stream.write_all(b"1\r\nx\r\n").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    });
    let e = env();
    let tier1 = demo_tier1(e.dir.path(), port, false);
    let tk = tier1.toolkit("demo_http").unwrap();
    let started = std::time::Instant::now();
    let r = run("GET", "/api/trickle", &IndexMap::new(), None, None, tk, None, 2.0, 65536, true, None).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED, "{}", r.stdout);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

// -- Body fields from a file (1.21.0) -----------------------------------------

/// A toolkit whose `path_roots` is `<dir>/scratch`, and a blob tool that
/// sends `scratch/<file>` as `content`. `file` takes almost anything, so
/// the checks below are the executor's, not the pattern's.
fn blob(dir: &std::path::Path, port: u16, max_file_bytes: i64) -> (Tier1, ToolDef, String) {
    let root = dir.join("scratch");
    std::fs::create_dir_all(&root).unwrap();
    let root = root.to_str().unwrap().to_string();
    let tier1 = write_tier1(
        dir,
        "tk-blob.yaml",
        &format!(
            "toolkits:\n  gh:\n    executor: http\n    base_url: \"http://127.0.0.1:{port}\"\n    allowed_methods: [\"POST\"]\n    allowed_path_prefixes: [\"/repos/\"]\n    allowed_cidrs: [\"127.0.0.1/32\"]\n    path_roots: [\"{root}\"]\n"
        ),
    );
    let spec = serde_json::json!({
        "id": "gh.blob_create_from_file", "toolkit": "gh", "version": 1,
        "title": "Blob", "description": "d", "category": "write_external", "idempotent": true,
        "enabled": true, "method": "POST", "path": "/repos/x/git/blobs",
        "body": {"content": {"from_file": "path", "encoding": "base64"}, "encoding": "base64"},
        "max_file_bytes": max_file_bytes,
        "parameters": {
            "file": {"type": "string", "pattern": "^[^/][^\\x00]*$", "required": true},
            "path": {"type": "path", "derived": format!("{root}/{{file}}"), "must_resolve_under": root},
        },
        "timeout_seconds": 5, "max_output_bytes": 65536,
    });
    let t = parse_tool_spec(&spec, &tier1).unwrap();
    (tier1, t, root)
}

/// Validates `file` the way `Service::call` does, then runs the request.
async fn blob_call(t: &ToolDef, tk: &Toolkit, file: &str) -> Result<ExecResult, Denied> {
    let mut args = Map::new();
    args.insert("file".into(), Value::String(file.into()));
    let values = crate::validate::resolve_parameters(t, &args)?;
    let req = build_http_request(t, &values, tk)?;
    Ok(run(&req.method, &req.path, &req.query, req.body.as_ref(), None, tk, None, 5.0, 65536, true, None).await.unwrap())
}

fn sent_json(seen: &Seen) -> Value {
    let (_, _, raw) = seen.lock().last().unwrap().clone();
    serde_json::from_slice(&raw).unwrap()
}

#[tokio::test]
async fn from_file_sends_the_content_base64_encoded() {
    use base64::Engine as _;
    let e = env();
    let (port, seen) = http_server().await;
    let (tier1, t, root) = blob(e.dir.path(), port, 1024);
    let tk = tier1.toolkit("gh").unwrap();
    let content = b"line one\nzweite Zeile \xc3\xa4\n\x00\xff binary too";
    std::fs::write(format!("{root}/notes.txt"), content).unwrap();

    let r = blob_call(&t, tk, "notes.txt").await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    let sent = sent_json(&seen);
    assert_eq!(sent["encoding"], "base64");
    assert_eq!(sent["content"], base64::engine::general_purpose::STANDARD.encode(content));
    assert_eq!(r.body_files, vec![(format!("{root}/notes.txt"), content.len() as u64)]);
}

#[tokio::test]
async fn from_file_request_as_built_names_the_file_never_its_content() {
    // What `build_http_request` returns is what the audit log describes.
    let e = env();
    let (port, _) = http_server().await;
    let (tier1, t, root) = blob(e.dir.path(), port, 1024);
    let tk = tier1.toolkit("gh").unwrap();
    std::fs::write(format!("{root}/notes.txt"), "TOP-SECRET-CONTENT").unwrap();
    let mut args = Map::new();
    args.insert("file".into(), "notes.txt".into());
    let values = crate::validate::resolve_parameters(&t, &args).unwrap();
    let req = build_http_request(&t, &values, tk).unwrap();
    let body = req.body.unwrap();
    assert_eq!(body["content"]["from_file"], format!("{root}/notes.txt"));
    assert_eq!(body["content"]["max_file_bytes"], 1024);
    assert!(!body.to_string().contains("TOP-SECRET"));
    assert!(!body.to_string().contains(&base64_of("TOP-SECRET-CONTENT")));
}

fn base64_of(text: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(text)
}

#[tokio::test]
async fn from_file_refuses_a_symlink_that_points_out_of_the_root() {
    let e = env();
    let (port, seen) = http_server().await;
    let (tier1, t, root) = blob(e.dir.path(), port, 1024);
    let tk = tier1.toolkit("gh").unwrap();
    let outside = e.dir.path().join("outside.txt");
    std::fs::write(&outside, "secret").unwrap();
    std::os::unix::fs::symlink(&outside, format!("{root}/escape.txt")).unwrap();
    std::os::unix::fs::symlink(e.dir.path(), format!("{root}/updir")).unwrap();

    for file in ["escape.txt", "updir/outside.txt"] {
        let denial = blob_call(&t, tk, file).await.unwrap_err();
        assert_eq!(denial.reason, DenialReason::PathEscape, "{file}");
    }
    assert!(seen.lock().is_empty());
}

#[test]
fn read_body_file_rechecks_what_it_opened() {
    // The path was checked when the call was validated; by the time the
    // file is opened a component may have been swapped for a symlink.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("scratch");
    std::fs::create_dir_all(&root).unwrap();
    let root = root.to_str().unwrap();
    std::fs::write(dir.path().join("outside.txt"), "secret").unwrap();
    std::fs::write(format!("{root}/inside.txt"), "fine").unwrap();
    // Final component a symlink, even to a file inside the root: not followed.
    std::os::unix::fs::symlink(format!("{root}/inside.txt"), format!("{root}/link.txt")).unwrap();
    let denial = read_body_file(&format!("{root}/link.txt"), root, 1024).unwrap_err();
    assert_eq!(denial.reason, DenialReason::ParamInvalid);
    assert!(denial.detail.contains("symbolic link"), "{}", denial.detail);
    // A directory component that is a symlink out of the root.
    std::os::unix::fs::symlink(dir.path(), format!("{root}/sub")).unwrap();
    let denial = read_body_file(&format!("{root}/sub/outside.txt"), root, 1024).unwrap_err();
    assert_eq!(denial.reason, DenialReason::PathEscape);
    assert!(!denial.detail.contains("secret"));
    assert_eq!(read_body_file(&format!("{root}/inside.txt"), root, 1024).unwrap(), b"fine");
}

#[tokio::test]
async fn from_file_size_limit_is_checked_before_reading() {
    let e = env();
    let (port, seen) = http_server().await;
    let (tier1, t, root) = blob(e.dir.path(), port, 100);
    let tk = tier1.toolkit("gh").unwrap();
    std::fs::write(format!("{root}/exact.txt"), vec![b'a'; 100]).unwrap();
    std::fs::write(format!("{root}/over.txt"), vec![b'a'; 101]).unwrap();
    // 64 GiB, sparse: reading it would take minutes and the memory to
    // hold it; refusing it from its size takes neither.
    let huge = std::fs::File::create(format!("{root}/huge.bin")).unwrap();
    huge.set_len(64 << 30).unwrap();

    let r = blob_call(&t, tk, "exact.txt").await.unwrap();
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    seen.lock().clear();
    for (file, size) in [("over.txt", 101u64), ("huge.bin", 64 << 30)] {
        let started = Instant::now();
        let r = blob_call(&t, tk, file).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(2), "{file}");
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.denial_reason.as_deref(), Some("param_invalid"));
        assert_eq!(
            r.denial_detail.unwrap(),
            format!("Body file '{root}/{file}' is {size} bytes, over this tool's limit of 100. Nothing was read or sent.")
        );
    }
    assert!(seen.lock().is_empty());
}

#[tokio::test]
async fn from_file_refuses_denylisted_names() {
    let e = env();
    let (port, seen) = http_server().await;
    let (tier1, t, root) = blob(e.dir.path(), port, 1024);
    let tk = tier1.toolkit("gh").unwrap();
    for name in ["config.yaml", "Config.YAML", ".env", ".env.local", "id.key", "server.PEM", "credentials", "credentials.json"] {
        std::fs::write(format!("{root}/{name}"), "TOKEN=abc").unwrap();
        let r = blob_call(&t, tk, name).await.unwrap();
        assert_eq!(r.denial_reason.as_deref(), Some("param_invalid"), "{name}");
        assert!(r.denial_detail.as_deref().unwrap().contains("never-send list"), "{name}");
        assert!(!r.stderr.contains("TOKEN"), "{name}");
    }
    for name in ["config.yaml.txt", "my.env", "keys.txt", "notes-credentials.md"] {
        std::fs::write(format!("{root}/{name}"), "ok").unwrap();
        let r = blob_call(&t, tk, name).await.unwrap();
        assert_eq!(r.outcome, OUTCOME_OK, "{name}: {}", r.stderr);
    }
    assert_eq!(seen.lock().len(), 4);
}

#[tokio::test]
async fn from_file_reads_regular_files_only() {
    let e = env();
    let (port, seen) = http_server().await;
    let (tier1, t, root) = blob(e.dir.path(), port, 1024);
    let tk = tier1.toolkit("gh").unwrap();
    std::fs::create_dir(format!("{root}/adir")).unwrap();
    let fifo = std::ffi::CString::new(format!("{root}/fifo")).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    std::fs::write(e.dir.path().join("elsewhere.txt"), "secret").unwrap();
    // A hard link inside the root resolves to the inside path.
    std::fs::hard_link(e.dir.path().join("elsewhere.txt"), format!("{root}/linked.txt")).unwrap();

    for (file, expect) in [
        ("adir", "is not a regular file"),
        ("fifo", "is not a regular file"),
        ("linked.txt", "has 2 hard links"),
        ("missing.txt", "cannot be opened"),
    ] {
        let r = tokio::time::timeout(Duration::from_secs(5), blob_call(&t, tk, file)).await.unwrap().unwrap();
        assert_eq!(r.denial_reason.as_deref(), Some("param_invalid"), "{file}");
        assert!(r.denial_detail.as_deref().unwrap().contains(expect), "{file}: {:?}", r.denial_detail);
    }
    assert!(seen.lock().is_empty());
}
