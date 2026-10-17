//! `/api/v1`: who gets in, and with what (port of `tests/test_api_auth.py`).
//!
//! Session only (an MCP bearer token is refused), viewer reads / admin
//! writes, read-only mode refuses every write, every mutating request
//! carries a CSRF token, and a write against a stale revision is a 412.

mod api_env;
mod app_env;

use std::sync::Arc;

use api_env::{api, get_paths, make_env, password, read_only_env, ApiEnv, Payload, API};
use gatekeeper::api::deps::{if_match, require_admin, require_session_write, ApiContext, ApiRequest, Fail};
use gatekeeper::api::session::{LoginThrottle, SessionStore, SESSION_COOKIE};
use http::HeaderMap;
use serde_json::json;

#[test]
fn the_schema_lists_the_phase_one_reads() {
    let paths = get_paths(true);
    for want in [
        "/session", "/account", "/overview", "/tools", "/tools/demo.show", "/identities", "/credentials",
        "/toolkits", "/toolkits/reference", "/requests/pending", "/requests/toolkits", "/audit",
        "/release-notes", "/stats", "/documents", "/documents/readme", "/oauth/providers", "/events",
    ] {
        assert!(paths.iter().any(|p| p == want), "{want}");
    }
}

#[tokio::test]
async fn every_read_needs_a_session() {
    let env = make_env();
    let mut c = env.client();
    let mut paths = get_paths(true);
    paths.push("/openapi.json".into());
    for path in paths {
        let response = c.get(&api(&path)).await;
        assert_eq!(response.status, 401, "{path}");
        assert_eq!(response.json(), json!({"error": "Not signed in."}), "{path}");
    }
}

/// FR-11.5: the API token is not a console credential, not even with a
/// valid session cookie next to it.
#[tokio::test]
async fn an_agent_token_opens_nothing() {
    let env = make_env();
    let mut c = env.client();
    let bearer = format!("Bearer {}", env.tokens["bot"]);
    for path in get_paths(true) {
        let response = c.get_h(&api(&path), &[("authorization", &bearer)]).await;
        assert_eq!(response.status, 401, "{path}");
    }
    // An admin's own token is refused just the same.
    c.login("root").await;
    let root_bearer = format!("Bearer {}", env.tokens["root"]);
    assert_eq!(c.get_h(&api("/overview"), &[("authorization", &root_bearer)]).await.status, 401);
    assert_eq!(c.get(&api("/overview")).await.status, 200);
    assert!(env.audit_records().iter().any(|r| r["reason"] == "api_bearer_rejected"));
}

#[tokio::test]
async fn login_with_a_token_instead_of_the_password_fails() {
    let env = make_env();
    let mut c = env.client();
    let response = c.post(&api("/session"), json!({"identity": "root", "password": env.tokens["root"]}), &[]).await;
    assert_eq!(response.status, 401);
    assert_eq!(response.json(), json!({"error": "Sign-in failed."}));
}

#[tokio::test]
async fn an_agent_cannot_sign_in() {
    let env = make_env();
    let mut c = env.client();
    let response = c.post(&api("/session"), json!({"identity": "bot", "password": "x".repeat(20)}), &[]).await;
    assert_eq!(response.status, 401);
    assert!(response.set_cookies().is_empty());
}

/// A cross-site HTML form cannot send application/json, so the login cannot
/// be driven from a foreign page (login CSRF).
#[tokio::test]
async fn login_is_json_only() {
    let env = make_env();
    let mut c = env.client();
    let body = format!(r#"{{"identity": "root", "password": "{}"}}"#, password("root"));
    let response = c.send("POST", &api("/session"), &[], Payload::Raw(Some("text/plain"), body.into_bytes())).await;
    assert!([415, 422].contains(&response.status));
    assert!(response.set_cookies().is_empty());
}

#[tokio::test]
async fn session_cookie_attributes() {
    let env = make_env();
    let mut c = env.client();
    let response = c.post(&api("/session"), json!({"identity": "root", "password": password("root")}), &[]).await;
    let cookie = response.header("set-cookie").unwrap().to_lowercase();
    assert!(cookie.contains("httponly"));
    assert!(cookie.contains("samesite=strict"));
    assert!(cookie.contains(&format!("path={API}").to_lowercase()));
    assert!(!cookie.contains("secure"));
    let records: Vec<_> = env.audit_records().into_iter().filter(|r| r["kind"] == "ui_login").collect();
    assert_eq!(records.last().unwrap()["surface"], "api");
}

#[tokio::test]
async fn the_session_cookie_is_secure_over_https() {
    let env = make_env();
    let mut c = env.client();
    c.scheme = Some("https".into());
    let response = c.post(&api("/session"), json!({"identity": "root", "password": password("root")}), &[]).await;
    assert!(response.header("set-cookie").unwrap().ends_with("; Secure"));
}

#[tokio::test]
async fn login_is_throttled() {
    let env = make_env();
    let mut c = env.client();
    for _ in 0..10 {
        c.post(&api("/session"), json!({"identity": "root", "password": "wrong"}), &[]).await;
    }
    let response = c.post(&api("/session"), json!({"identity": "root", "password": password("root")}), &[]).await;
    assert_eq!(response.status, 429);
}

#[tokio::test]
async fn roles_in_the_session() {
    let env = make_env();
    let ro_env = read_only_env();
    let admin = env.client().login("root").await;
    let viewer = env.client().login("eye").await;
    let ro_admin = ro_env.client().login("root").await;
    assert_eq!((&admin["can_write"], &admin["read_only"]), (&json!(true), &json!(false)));
    assert_eq!((&viewer["can_write"], &viewer["read_only"]), (&json!(false), &json!(false)));
    assert_eq!((&ro_admin["can_write"], &ro_admin["read_only"]), (&json!(false), &json!(true)));
    assert!(admin["csrf"].as_str().is_some_and(|s| !s.is_empty()));
    assert_ne!(admin["csrf"], viewer["csrf"]);
}

#[tokio::test]
async fn logout_needs_the_csrf_token() {
    let env = make_env();
    let mut c = env.client();
    let csrf = c.csrf("eye").await;
    assert_eq!(c.delete(&api("/session"), &[]).await.status, 403);
    let bad = c.delete(&api("/session"), &[("x-csrf-token", &format!("x{csrf}"))]).await;
    assert_eq!(bad.status, 403);
    assert_eq!(c.get(&api("/session")).await.status, 200);
    let ok = c.delete(&api("/session"), &[("x-csrf-token", &csrf)]).await;
    assert_eq!(ok.status, 204);
    assert_eq!(c.get(&api("/session")).await.status, 401);
    assert_eq!(env.denied_reasons(), ["csrf_mismatch", "csrf_mismatch"]);
}

#[tokio::test]
async fn the_schema_is_admin_only() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    assert_eq!(c.get(&api("/openapi.json")).await.status, 403);
    let mut c = env.client();
    c.login("root").await;
    let response = c.get(&api("/openapi.json")).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["servers"], json!([{"url": API}]));
}

/// Swagger/ReDoc pages need inline and CDN scripts -- not served.
#[tokio::test]
async fn no_interactive_docs() {
    let env = make_env();
    let mut c = env.client();
    c.login("root").await;
    for path in ["/docs", "/redoc", "/docs/oauth2-redirect"] {
        assert_eq!(c.get(&api(path)).await.status, 404, "{path}");
    }
}

/// FR-4.11: no route writes a toolkit, whatever the method.
#[tokio::test]
async fn toolkit_writes_do_not_exist() {
    let env = make_env();
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        for path in ["/toolkits", "/toolkits/demo", "/toolkits/reference"] {
            let response = c
                .send(method, &api(path), &[("x-csrf-token", &csrf), ("if-match", "\"x\"")], Payload::Json(json!({})))
                .await;
            assert!([404, 405].contains(&response.status), "{method} {path}");
        }
    }
}

#[tokio::test]
async fn api_responses_carry_security_headers() {
    let env = make_env();
    let mut c = env.client();
    let responses = vec![
        c.get(&api("/session")).await,
        c.post(&api("/session"), json!({"identity": "root", "password": password("root")}), &[]).await,
        c.get(&api("/overview")).await,
        c.get(&api("/nonexistent")).await,
    ];
    for response in responses {
        assert!(response.header("content-security-policy").unwrap().starts_with("default-src 'none'"));
        assert_eq!(response.header("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(response.header("cache-control").unwrap(), "no-store");
    }
}

#[tokio::test]
async fn unknown_api_path_is_a_json_404() {
    let env = make_env();
    let mut c = env.client();
    c.login("root").await;
    let response = c.get(&api("/nonexistent")).await;
    assert_eq!(response.status, 404);
    assert!(response.json().get("error").is_some());
}

// -- The write dependencies, in isolation -------------------------------------
//
// Python pins these on a test-only route; here the dependencies are called
// directly with a request as the router would build it.

fn context(env: &ApiEnv, read_only: bool) -> ApiContext {
    ApiContext {
        service: env.env.service.clone(),
        identities: env.env.identities.clone(),
        audit: env.env.audit.clone(),
        sessions: Arc::new(SessionStore::default()),
        throttle: Arc::new(LoginThrottle::default()),
        store: (!read_only).then(|| env.env.store.clone()),
        credentials: None,
        pending: None,
        toolkit_proposals: None,
        oauth_states: None,
    }
}

fn request(sid: Option<&str>, headers: &[(&str, &str)]) -> ApiRequest {
    let mut map = HeaderMap::new();
    for (k, v) in headers {
        map.append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
    }
    if let Some(sid) = sid {
        map.insert("cookie", format!("{SESSION_COOKIE}={sid}").parse().unwrap());
    }
    ApiRequest {
        method: "POST".into(),
        path: "/_probe".into(),
        query: String::new(),
        headers: map,
        body: Default::default(),
        client: Some("testclient".into()),
        scheme: "http".into(),
        host: "testserver".into(),
    }
}

fn status(result: Result<impl Sized, Fail>) -> u16 {
    match result {
        Ok(_) => 200,
        Err(Fail::Api(e)) => e.status,
        Err(Fail::Validation(_)) => 422,
        Err(Fail::Internal(e)) => panic!("internal: {e}"),
    }
}

fn probe(ctx: &ApiContext, env: &ApiEnv, req: &ApiRequest) -> Result<String, Fail> {
    require_admin(ctx, req)?;
    if_match(req, &env.env.store.tools_revision())
}

#[test]
fn write_requires_admin_csrf_and_if_match() {
    let env = make_env();
    let ctx = context(&env, false);
    let rev = env.env.store.tools_revision();
    let viewer = ctx.sessions.create("eye", "viewer");
    let viewer_csrf = ctx.sessions.resolve(Some(&viewer)).unwrap().csrf;
    assert_eq!(status(probe(&ctx, &env, &request(Some(&viewer), &[("x-csrf-token", &viewer_csrf)]))), 403);

    let sid = ctx.sessions.create("root", "admin");
    let csrf = ctx.sessions.resolve(Some(&sid)).unwrap().csrf;
    let quoted = format!("\"{rev}\"");
    assert_eq!(status(probe(&ctx, &env, &request(Some(&sid), &[("if-match", &quoted)]))), 403);
    assert_eq!(status(probe(&ctx, &env, &request(Some(&sid), &[("x-csrf-token", &csrf)]))), 428);
    match probe(&ctx, &env, &request(Some(&sid), &[("x-csrf-token", &csrf), ("if-match", "\"0123\"")])) {
        Err(Fail::Api(e)) => {
            assert_eq!(e.status, 412);
            assert!(e.message.contains("changed"));
        }
        _ => panic!("expected a 412"),
    }
    for tag in [quoted.clone(), format!("W/\"{rev}\""), rev.clone()] {
        let got = probe(&ctx, &env, &request(Some(&sid), &[("x-csrf-token", &csrf), ("if-match", &tag)]));
        assert_eq!(got.ok().as_deref(), Some(rev.as_str()), "{tag}");
    }
    assert_eq!(env.denied_reasons(), ["role_required", "csrf_mismatch"]);
}

#[test]
fn read_only_mode_refuses_every_write() {
    let env = make_env();
    let ctx = context(&env, true);
    let sid = ctx.sessions.create("root", "admin");
    let csrf = ctx.sessions.resolve(Some(&sid)).unwrap().csrf;
    let rev = env.env.store.tools_revision();
    assert_eq!(status(probe(&ctx, &env, &request(Some(&sid), &[("x-csrf-token", &csrf), ("if-match", &rev)]))), 403);
    assert_eq!(status(require_session_write(&ctx, &request(Some(&sid), &[("x-csrf-token", &csrf)]))), 403);
    assert_eq!(env.denied_reasons(), ["read_only", "read_only"]);
}

#[test]
fn self_service_writes_need_csrf_but_not_admin() {
    let env = make_env();
    let ctx = context(&env, false);
    let sid = ctx.sessions.create("eye", "viewer");
    let csrf = ctx.sessions.resolve(Some(&sid)).unwrap().csrf;
    assert_eq!(status(require_session_write(&ctx, &request(Some(&sid), &[]))), 403);
    assert_eq!(status(require_session_write(&ctx, &request(Some(&sid), &[("x-csrf-token", &csrf)]))), 200);
}
