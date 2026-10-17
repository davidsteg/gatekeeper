//! The console API's wire behaviour where FastAPI/Starlette decide it:
//! validation messages, the order of body parsing / auth / validation,
//! 404/405/307 routing, and the error body shape. Every expectation here
//! was recorded from the Python implementation.

mod api_env;
mod app_env;

use api_env::{api, make_env, Payload, Resp};
use serde_json::json;

fn raw(ct: Option<&'static str>, body: &str) -> Payload {
    Payload::Raw(ct, body.as_bytes().to_vec())
}

fn check(response: &Resp, status: u16, body: &str, what: &str) {
    assert_eq!(response.status, status, "{what}: {}", response.text());
    assert_eq!(response.text(), body, "{what}");
    if !body.is_empty() {
        assert_eq!(response.header("content-type").as_deref(), Some("application/json"), "{what}");
    }
}

#[tokio::test]
async fn login_body_errors() {
    let env = make_env();
    let mut c = env.client();
    let json_ct = Some("application/json");
    for (payload, status, body) in [
        (raw(json_ct, "not json"), 422, r#"{"error":"0: JSON decode error"}"#),
        (raw(json_ct, r#"{"identity":1,"password":"x","z":1}"#), 422, r#"{"error":"identity: Input should be a valid string"}"#),
        (raw(json_ct, "[1]"), 422, r#"{"error":"Input should be a valid dictionary or object to extract fields from"}"#),
        (
            raw(Some("text/plain"), r#"{"identity":"root","password":"x"}"#),
            422,
            r#"{"error":"Input should be a valid dictionary or object to extract fields from"}"#,
        ),
        (raw(None, ""), 422, r#"{"error":"Field required"}"#),
        (raw(json_ct, r#"{"identity":"root","password":"x""#), 422, r#"{"error":"33: JSON decode error"}"#),
    ] {
        let response = c.send("POST", &api("/session"), &[], payload).await;
        check(&response, status, body, "POST /session");
    }
}

#[tokio::test]
async fn write_body_and_query_errors() {
    let env = make_env();
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    let tag = c.etag(&api("/identities")).await;
    let h = [("x-csrf-token", csrf.as_str())];
    let hm = [("x-csrf-token", csrf.as_str()), ("if-match", tag.as_str())];
    let ids_1001: Vec<&str> = vec!["a"; 1001];
    let cases: Vec<(&str, &str, &[(&str, &str)], Payload, u16, &str)> = vec![
        ("PUT", "/identities/x", &hm, Payload::Json(json!({"id": "a".repeat(70), "role": "agent", "tools": "x"})), 422,
         r#"{"error":"id: String should have at most 64 characters"}"#),
        ("PUT", "/identities/x", &hm, Payload::Json(json!({"id": "a", "role": "agent", "tools": [1]})), 422,
         r#"{"error":"tools.0: Input should be a valid string"}"#),
        ("POST", "/credentials/x/rotate", &h, Payload::Json(json!({"value": "a", "overlap_seconds": -1})), 422,
         r#"{"error":"overlap_seconds: Input should be greater than or equal to 0"}"#),
        ("POST", "/credentials/x/rotate", &h, Payload::Json(json!({"value": "a", "overlap_seconds": "5"})), 428,
         r#"{"error":"If-Match is required; send the ETag of the resource you edited."}"#),
        ("POST", "/credentials/x/rotate", &h, Payload::Json(json!({"value": "a", "overlap_seconds": 1.5})), 422,
         r#"{"error":"overlap_seconds: Input should be a valid integer, got a number with a fractional part"}"#),
        ("POST", "/credentials/x/rotate", &h, Payload::Json(json!({"value": "a", "overlap_seconds": true})), 428,
         r#"{"error":"If-Match is required; send the ETag of the resource you edited."}"#),
        ("POST", "/requests/toolkits/x/deploy", &h, Payload::Json(json!({})), 422, r#"{"error":"confirm: Field required"}"#),
        ("POST", "/requests/toolkits/x/deploy", &h, Payload::Json(json!({"confirm": false})), 422,
         r#"{"error":"confirm: Input should be True"}"#),
        ("POST", "/requests/toolkits/x/deploy", &h, Payload::Json(json!({"confirm": 1})), 404, r#"{"error":"No proposal 'x'."}"#),
        ("POST", "/requests/toolkits/x/deploy", &h, Payload::Json(json!({"confirm": "true"})), 422,
         r#"{"error":"confirm: Input should be True"}"#),
        ("PUT", "/tools/x/enabled", &h, Payload::Json(json!({"enabled": "yes"})), 428,
         r#"{"error":"If-Match is required; send the ETag of the resource you edited."}"#),
        ("PUT", "/tools/x/enabled", &h, Payload::Json(json!({"enabled": "maybe"})), 422,
         r#"{"error":"enabled: Input should be a valid boolean, unable to interpret input"}"#),
        ("PUT", "/tools/x/enabled", &h, Payload::Json(json!({"enabled": null})), 422,
         r#"{"error":"enabled: Input should be a valid boolean"}"#),
        ("POST", "/requests/pending/approve-all", &h, Payload::Json(json!({"ids": null})), 422,
         r#"{"error":"ids: Input should be a valid list"}"#),
        ("POST", "/requests/pending/approve-all", &h, Payload::Json(json!({"ids": ids_1001})), 422,
         r#"{"error":"ids: List should have at most 1000 items after validation, not 1001"}"#),
        ("POST", "/requests/pending/approve-all", &h, Payload::None, 422, r#"{"error":"Field required"}"#),
        ("POST", "/requests/pending/x/reject", &h, Payload::None, 422, r#"{"error":"Field required"}"#),
        ("POST", "/requests/pending/x/approve", &h, raw(None, "garbage"), 404, r#"{"error":"No proposal 'x'."}"#),
        ("GET", "/audit?limit=0", &[], Payload::None, 422, r#"{"error":"query.limit: Input should be greater than or equal to 1"}"#),
        ("GET", "/audit?limit=abc", &[], Payload::None, 422,
         r#"{"error":"query.limit: Input should be a valid integer, unable to parse string as an integer"}"#),
        ("GET", "/audit?limit=5&limit=600", &[], Payload::None, 422,
         r#"{"error":"query.limit: Input should be less than or equal to 500"}"#),
        ("GET", "/audit?outcome=bogus", &[], Payload::None, 422,
         r#"{"error":"query.outcome: String should match pattern '^(|ok|denied|failed|unknown)$'"}"#),
        ("GET", "/stats?window=1y", &[], Payload::None, 422,
         r#"{"error":"query.window: String should match pattern '^(24h|7d|30d)$'"}"#),
        ("GET", "/release-notes?limit=0", &[], Payload::None, 422,
         r#"{"error":"query.limit: Input should be greater than or equal to 1"}"#),
        ("GET", "/requests/decided?limit=500", &[], Payload::None, 422,
         r#"{"error":"query.limit: Input should be less than or equal to 200"}"#),
    ];
    for (method, path, headers, payload, status, body) in cases {
        let response = c.send(method, &api(path), headers, payload).await;
        check(&response, status, body, &format!("{method} {path}"));
    }
    let long = format!("/audit?identity={}", "x".repeat(300));
    check(&c.get(&api(&long)).await, 422, r#"{"error":"query.identity: String should have at most 256 characters"}"#, "identity");
}

#[tokio::test]
async fn routing_errors() {
    let env = make_env();
    let mut c = env.client();
    c.login("root").await;
    let not_found = r#"{"error":"Not Found"}"#;
    let not_allowed = r#"{"error":"Method Not Allowed"}"#;
    for (method, path, status, body, allow) in [
        ("GET", "/nonexistent", 404, not_found, None),
        ("POST", "/overview", 405, not_allowed, Some("GET")),
        ("PATCH", "/tools", 405, not_allowed, Some("GET")),
        ("GET", "/tools/a/b", 404, not_found, None),
        ("GET", "/", 404, not_found, None),
        ("GET", "/docs", 404, not_found, None),
        ("OPTIONS", "/overview", 405, not_allowed, Some("GET")),
        ("GET", "/requests/pending/approve-all", 405, not_allowed, Some("POST")),
        ("GET", "/documents/%2e%2e%2fDockerfile", 404, not_found, None),
    ] {
        let response = c.send(method, &api(path), &[], Payload::None).await;
        check(&response, status, body, &format!("{method} {path}"));
        assert_eq!(response.header("allow").as_deref(), allow, "{method} {path}");
        assert_eq!(response.header("cache-control").as_deref(), Some("no-store"));
    }
    // FastAPI adds no HEAD to a GET route.
    let head = c.send("HEAD", &api("/overview"), &[], Payload::None).await;
    assert_eq!((head.status, head.header("allow").as_deref()), (405, Some("GET")));
    // Redirect slashes.
    let slash = c.get(&api("/tools/")).await;
    assert_eq!(slash.status, 307);
    assert_eq!(slash.header("location").unwrap(), "http://gatekeeper.test/api/v1/tools");
    let bare = c.get("/api/v1").await;
    assert_eq!(bare.status, 307);
    assert_eq!(bare.header("location").unwrap(), "http://gatekeeper.test/api/v1/");
}

#[tokio::test]
async fn a_body_decode_error_comes_before_the_session_check() {
    let env = make_env();
    let mut c = env.client();
    let response = c.send("POST", &api("/tools"), &[], raw(Some("application/json"), "{")).await;
    check(&response, 422, r#"{"error":"1: JSON decode error"}"#, "decode before auth");
    let response = c.send("POST", &api("/tools"), &[], raw(Some("application/json"), "{}")).await;
    check(&response, 401, r#"{"error":"Not signed in."}"#, "auth before validation");
}
