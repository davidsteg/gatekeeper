//! The console's security properties, pinned on `/api/v1` (port of the
//! console parts of `tests/test_api_security.py`).
//!
//! Not here: the MCP/metrics halves (the console cookie opening nothing on
//! `/mcp`, auth-failure records, prefix matching) belong to the HTTP
//! server's tests, and the reverse-proxy middleware itself is the server's:
//! it hands the console a `RequestClient`, which is what these tests set.
//! The session-store and throttle units live in `src/api/session.rs`.

mod api_env;
mod app_env;

use api_env::{api, make_env, password, ApiEnv, Payload};
use gatekeeper::api::app::ROUTES;
use serde_json::{json, Value};

fn h<'a>(csrf: &'a str, etag: Option<&'a str>) -> Vec<(&'a str, &'a str)> {
    let mut headers = vec![("x-csrf-token", csrf)];
    if let Some(etag) = etag {
        headers.push(("if-match", etag));
    }
    headers
}

fn auth_failures(env: &ApiEnv) -> Vec<Value> {
    env.audit_records().into_iter().filter(|r| r["kind"] == "auth_failure").collect()
}

// -- Sign-in ------------------------------------------------------------------------

#[tokio::test]
async fn a_wrong_password_is_refused_and_audited() {
    let env = make_env();
    let mut c = env.client();
    let response = c.post(&api("/session"), json!({"identity": "root", "password": "wrong-password-here"}), &[]).await;
    assert_eq!(response.status, 401);
    assert!(response.set_cookies().is_empty());
    let last = auth_failures(&env).pop().unwrap();
    assert_eq!(last["reason"], "ui_login_failed");
    assert_eq!(last["detail"], "identity='root' from 127.0.0.1");
}

/// `/api/v1` answers before sign-in, so its body is capped before any route.
#[tokio::test]
async fn an_oversized_body_is_refused_unread() {
    let env = make_env();
    let mut c = env.client();
    let password = "x".repeat(gatekeeper::api::app::MAX_BODY_BYTES);
    let response = c.post(&api("/session"), json!({"identity": "root", "password": password}), &[]).await;
    assert_eq!(response.status, 413);
}

/// Unknown identity, wrong password, an agent: the same answer three times.
#[tokio::test]
async fn sign_in_is_not_a_directory_of_accounts() {
    let env = make_env();
    let mut c = env.client();
    for (who, pw) in [("nosuchuser", password("root")), ("root", "also-not-right"), ("bot", "anything-at-all")] {
        let response = c.post(&api("/session"), json!({"identity": who, "password": pw}), &[]).await;
        assert_eq!(response.status, 401);
        assert_eq!(response.text(), r#"{"error":"Sign-in failed."}"#);
    }
}

// -- Behind a reverse proxy (the server's `RequestClient`) ---------------------------

#[tokio::test]
async fn the_proxied_client_address_is_what_gets_logged() {
    let env = make_env();
    let mut c = env.client();
    c.client_host = Some("203.0.113.7".into());
    let response = c.post(&api("/session"), json!({"identity": "root", "password": "wrong-one"}), &[]).await;
    assert_eq!(response.status, 401);
    let detail = auth_failures(&env).pop().unwrap()["detail"].as_str().unwrap().to_string();
    assert!(detail.contains("203.0.113.7"));
}

#[tokio::test]
async fn an_unknown_client_is_logged_as_unknown() {
    let env = make_env();
    let mut c = env.client();
    c.client_host = None;
    c.post(&api("/session"), json!({"identity": "root", "password": "wrong-one"}), &[]).await;
    assert_eq!(auth_failures(&env).pop().unwrap()["detail"], "identity='root' from unknown");
}

#[tokio::test]
async fn the_session_cookie_is_secure_behind_tls() {
    let env = make_env();
    let mut c = env.client();
    c.scheme = Some("https".into());
    let tls = c.post(&api("/session"), json!({"identity": "root", "password": password("root")}), &[]).await;
    assert_eq!(tls.status, 200);
    assert!(tls.header("set-cookie").unwrap().to_lowercase().contains("secure"));
    let plain = env.client().post(&api("/session"), json!({"identity": "root", "password": password("root")}), &[]).await;
    assert!(!plain.header("set-cookie").unwrap().to_lowercase().contains("secure"));
}

// -- CSRF -----------------------------------------------------------------------------

#[tokio::test]
async fn another_sessions_csrf_token_is_refused() {
    let env = make_env();
    let mut a = env.client();
    let mut b = env.client();
    let csrf_a = a.csrf("root").await;
    b.login("root").await;
    let tag = b.etag(&api("/tools")).await;
    let response = b.put(&api("/tools/demo.echo/enabled"), json!({"enabled": false}), &h(&csrf_a, Some(&tag))).await;
    assert_eq!(response.status, 403);
    assert!(env.env.service.catalog().tools["demo.echo"].enabled);
    assert_eq!(env.denied_reasons().last().unwrap(), "csrf_mismatch");
}

/// Rejected calls log the unvalidated arguments, so an agent can put nearly
/// any text in the audit log. It must leave the API as a JSON string under
/// a CSP that runs nothing and with sniffing off.
#[tokio::test]
async fn agent_data_reaches_the_client_inert() {
    let env = make_env();
    let payload = r#"<script>alert("xss")</script>"#;
    env.env
        .audit
        .write(json!({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "denied",
                      "parameters": {"name": payload}, "detail": payload}))
        .unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let response = c.get(&api("/audit")).await;
    assert!(response.header("content-type").unwrap().starts_with("application/json"));
    assert_eq!(response.header("x-content-type-options").unwrap(), "nosniff");
    assert!(response.header("content-security-policy").unwrap().starts_with("default-src 'none'"));
    let body = response.json();
    let record = body["entries"].as_array().unwrap().iter().find(|r| r["detail"] == payload).unwrap().clone();
    assert_eq!(record["parameters"], json!({"name": payload}));
}

// -- Identity changes end that identity's sessions -----------------------------------

async fn edit_eye(env: &ApiEnv, change: Value) {
    let mut admin = env.client();
    let csrf = admin.csrf("root").await;
    let tag = admin.etag(&api("/identities")).await;
    let mut body = json!({"id": "eye", "role": "viewer", "tools": [], "scopes": [], "password": ""});
    for (k, v) in change.as_object().unwrap() {
        body[k] = v.clone();
    }
    let response = admin.put(&api("/identities/eye"), body, &h(&csrf, Some(&tag))).await;
    assert_eq!(response.status, 200, "{}", response.text());
    assert_eq!(admin.get(&api("/session")).await.status, 200);
}

#[tokio::test]
async fn a_role_change_or_rename_ends_that_identitys_sessions() {
    for change in [json!({"role": "agent"}), json!({"id": "eye2"})] {
        let env = make_env();
        let mut eye = env.client();
        eye.login("eye").await;
        edit_eye(&env, change.clone()).await;
        assert_eq!(eye.get(&api("/session")).await.status, 401, "{change}");
    }
}

#[tokio::test]
async fn a_demoted_admin_loses_the_admin_session() {
    let env = make_env();
    edit_eye(&env, json!({"role": "admin"})).await;
    let mut eye = env.client();
    eye.login("eye").await;
    assert_eq!(eye.get(&api("/session")).await.json()["role"], "admin");
    // Still a console role, so the edit itself keeps the session; the role
    // it carries no longer matches, and that ends it.
    edit_eye(&env, json!({"role": "viewer"})).await;
    assert_eq!(eye.get(&api("/session")).await.status, 401);
}

#[tokio::test]
async fn an_unchanged_identity_keeps_its_sessions() {
    let env = make_env();
    let mut eye = env.client();
    eye.login("eye").await;
    edit_eye(&env, json!({})).await;
    assert_eq!(eye.get(&api("/session")).await.status, 200);
}

#[tokio::test]
async fn rotating_or_deleting_ends_that_identitys_sessions() {
    for action in ["rotate", "delete"] {
        let env = make_env();
        let mut eye = env.client();
        let mut admin = env.client();
        eye.login("eye").await;
        let csrf = admin.csrf("root").await;
        let tag = admin.etag(&api("/identities")).await;
        let response = if action == "rotate" {
            admin.post_empty(&api("/identities/eye/token"), &h(&csrf, Some(&tag))).await
        } else {
            admin.delete(&api("/identities/eye"), &h(&csrf, Some(&tag))).await
        };
        assert_eq!(response.status, 200, "{}", response.text());
        assert_eq!(eye.get(&api("/session")).await.status, 401, "{action}");
        assert_eq!(admin.get(&api("/session")).await.status, 200, "{action}");
    }
}

#[tokio::test]
async fn the_last_admin_cannot_be_removed_or_demoted() {
    let env = make_env();
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    for (method, body) in [("DELETE", None), ("PUT", Some(json!({"id": "root", "role": "viewer"})))] {
        let tag = c.etag(&api("/identities")).await;
        let payload = body.map_or(Payload::None, Payload::Json);
        let response = c.send(method, &api("/identities/root"), &h(&csrf, Some(&tag)), payload).await;
        assert_eq!(response.status, 400, "{method} {}", response.text());
    }
    assert_eq!(c.get(&api("/session")).await.status, 200);
    assert_eq!(env.env.identity("root").role, "admin");
}

// -- FR-4.11 --------------------------------------------------------------------------

/// Toolkits are deploy-time only: the only writes near a toolkit are the
/// deploy/reject of a human-reviewed proposal.
#[test]
fn no_route_writes_a_toolkit() {
    let allowed = ["/requests/toolkits/{proposal_id}/deploy", "/requests/toolkits/{proposal_id}/reject"];
    for route in ROUTES {
        if route.path.contains("toolkit") && !allowed.contains(&route.path) {
            assert_eq!(route.method, "GET", "{} {}", route.method, route.path);
        }
    }
}

// -- Tier 1 still decides, over HTTP ---------------------------------------------------

fn tool_yaml(env: &ApiEnv, override_: Value) -> String {
    let binary = env.env.service.tier1().toolkits["demo"].binaries[0].clone();
    let mut spec = json!({
        "id": "demo.extra", "toolkit": "demo", "binary": binary, "title": "Extra",
        "description": "x", "category": "read", "idempotent": true,
        "argv": ["-c", "print(1)"], "parameters": {}, "required_scopes": [],
        "timeout_seconds": 10, "max_output_bytes": 1024,
    });
    for (k, v) in override_.as_object().unwrap() {
        spec[k] = v.clone();
    }
    gatekeeper::yaml::dump(&spec)
}

#[tokio::test]
async fn tier1_refuses_a_tool_the_console_would_create() {
    for (override_, reason) in [
        (json!({"timeout_seconds": 99999}), "exceeds"),
        (json!({"binary": "/usr/bin/env"}), "allowlist"),
        (
            json!({"argv": ["-c", "print(1)", "{text}"], "parameters": {"text": {"type": "string", "required": true}}}),
            "pattern",
        ),
    ] {
        let env = make_env();
        let mut c = env.client();
        let csrf = c.csrf("root").await;
        let tag = c.etag(&api("/tools")).await;
        let response = c.post(&api("/tools"), json!({"yaml": tool_yaml(&env, override_)}), &h(&csrf, Some(&tag))).await;
        assert_eq!(response.status, 400, "{}", response.text());
        assert!(response.error().to_lowercase().contains(reason), "{reason}: {}", response.error());
        assert!(!env.env.service.catalog().tools.contains_key("demo.extra"));
    }
}

// -- Request decisions that must not go wrong -----------------------------------------

#[tokio::test]
async fn deleting_a_toolkit_a_tool_still_uses_is_refused() {
    let env = make_env();
    let queue = &env.env.proposals;
    let item = queue.propose("demo", app_env::obj(json!({})), "hermes", "delete").unwrap();
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    let response = c.post(&api(&format!("/requests/toolkits/{}/deploy", item.id)), json!({"confirm": true}), &h(&csrf, None)).await;
    assert_eq!(response.status, 400);
    assert!(response.error().contains("still referenced"));
    assert!(env.env.service.tier1().toolkits.contains_key("demo"));
    assert_eq!(queue.get(&item.id).unwrap().unwrap().status, "pending");
}

/// FR-10.4: a redirect must not read as an addition.
#[tokio::test]
async fn a_rebind_shows_the_binding_it_replaces() {
    let env = make_env();
    let queue = &env.env.proposals;
    let first = queue.propose("demo", app_env::obj(json!({"credential": "old-key"})), "hermes", "bind").unwrap();
    queue.deploy(&first.id, "root").unwrap();
    let second = queue.propose("demo", app_env::obj(json!({"credential": "new-key"})), "hermes", "bind").unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let listing = c.get(&api("/requests/toolkits")).await.json();
    let item = listing.as_array().unwrap().iter().find(|p| p["id"] == second.id.as_str()).unwrap().clone();
    assert_eq!(item["current"]["credential"], "old-key");
    assert_eq!(item["spec"]["credential"], "new-key");
}

#[tokio::test]
async fn an_unchanged_grant_still_flags_a_missing_tool() {
    let env = make_env();
    env.env
        .pending
        .propose(
            "grant_set",
            "hermes",
            app_env::obj(json!({"identity_id": "bot", "tools": ["demo.show", "demo.ghost"], "prev_tools": ["demo.show", "demo.ghost"]})),
            &env.env.store.identity_revision("bot"),
        )
        .unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let items = c.get(&api("/requests/pending")).await.json();
    assert_eq!(items.as_array().unwrap().len(), 1);
    let ghost: Vec<&Value> = items[0]["review"]["tools"].as_array().unwrap().iter().filter(|t| t["id"] == "demo.ghost").collect();
    assert_eq!(ghost[0]["state"], "missing");
}

#[tokio::test]
async fn approving_a_delete_whose_tool_is_gone_closes_it_as_stale() {
    let env = make_env();
    let (pending, store) = (&env.env.pending, &env.env.store);
    let item = pending
        .propose("tool_delete", "hermes", app_env::obj(json!({"id": "demo.show"})), &store.tool_revision("demo.show"))
        .unwrap();
    let path = &env.env.tools_path;
    let doc = env.env.load_yaml(path);
    let kept: Vec<Value> = doc["tools"].as_array().unwrap().iter().filter(|s| s["id"] != "demo.show").cloned().collect();
    std::fs::write(path, gatekeeper::yaml::dump(&json!({"tools": kept}))).unwrap();
    env.env.service.set_catalog(gatekeeper::catalog::load_catalog(path, &env.env.service.tier1(), false).unwrap());
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    let response = c.post_empty(&api(&format!("/requests/pending/{}/approve", item.id)), &h(&csrf, None)).await;
    assert_eq!(response.status, 400);
    assert!(response.error().to_lowercase().contains("stale"));
    assert!(!response.text().contains("No tool with ID"));
    assert_eq!(pending.get(&item.id).unwrap().unwrap().status, "stale");
}

// -- What is left of /ui --------------------------------------------------------------

#[tokio::test]
async fn ui_paths_redirect_to_the_same_page_under_app() {
    let env = make_env();
    let mut c = env.client();
    for (path, target) in [
        ("/ui", "/app/"),
        ("/ui/", "/app/"),
        ("/ui/requests", "/app/requests"),
        ("/ui/tools/new", "/app/tools/new"),
        ("/ui//evil.example/x", "/app/evil.example/x"),
        // The query rides along: pages read it.
        ("/ui/requests?tab=change", "/app/requests?tab=change"),
        ("/ui//evil.example?next=//x", "/app/evil.example?next=//x"),
    ] {
        let response = c.get(path).await;
        assert_eq!(response.status, 308, "{path}");
        assert_eq!(response.header("location").unwrap(), target, "{path}");
    }
}

#[tokio::test]
async fn an_old_form_post_is_gone_not_replayed() {
    let env = make_env();
    let mut c = env.client();
    for path in ["/ui/login", "/ui/tools/save", "/ui/pending/approve"] {
        let response = c
            .send("POST", path, &[], Payload::Raw(Some("application/x-www-form-urlencoded"), b"identity=root".to_vec()))
            .await;
        assert_eq!(response.status, 410, "{path}");
        assert!(response.text().contains("/app"));
    }
    assert!(!env.audit_records().iter().any(|r| r["kind"] == "ui_login"));
}

#[tokio::test]
async fn browser_noise_goes_to_app_and_stays_out_of_the_audit_log() {
    let env = make_env();
    let before = auth_failures(&env).len();
    let mut c = env.client();
    let root = c.get("/").await;
    assert_eq!((root.status, root.header("location").unwrap().as_str()), (303, "/app/"));
    let icon = c.get("/favicon.ico").await;
    assert_eq!((icon.status, icon.header("location").unwrap().as_str()), (308, "/app/favicon.svg"));
    assert_eq!(auth_failures(&env).len(), before);
}

#[tokio::test]
async fn an_oauth_callback_without_a_flow_changes_nothing() {
    let env = make_env();
    let mut c = env.client();
    let response = c.get("/ui/oauth/google/callback?code=x&state=forged").await;
    assert_eq!(response.status, 303);
    assert!(response.header("location").unwrap().starts_with("/app/credentials?oauth=state_mismatch"));
}
