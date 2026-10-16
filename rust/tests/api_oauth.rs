//! OAuth sign-in through the console's routes (port of the route parts of
//! `tests/test_api_extras.py`, `tests/test_oauth.py` and
//! `tests/test_microsoft_oauth.py`).
//!
//! The flow's own logic (state, scopes, exchange, storage) is pinned in
//! `src/oauth.rs`; here it runs end to end through `POST
//! /api/v1/oauth/{provider}/authorize` and the `/ui/oauth/*/callback`
//! redirect URIs, with a loopback listener as the provider's token
//! endpoint. What matters: the API start shares the callback's single-use
//! state, an `/app`-started flow returns to `/app` with a result code only,
//! and no response or redirect ever carries token material.

mod api_env;
mod app_env;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use api_env::{api, make_env_with, ApiEnv, Client, Spec, BASE};
use gatekeeper::api::ConsoleOptions;
use gatekeeper::oauth::{
    microsoft_scope_urls, pkce_challenge, TokenEndpoints, BASE_URL_ENV, DEFAULT_GOOGLE_SCOPES,
    DEFAULT_MICROSOFT_SCOPES, GOOGLE_SCOPE_PREFIX, MICROSOFT_OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_PATH,
};
use serde_json::{json, Map, Value};

const CLIENT_ID: &str = "1234.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "GOCSPX-test-client-secret-value";
const OLD_REFRESH: &str = "1//old-refresh-token-value";
const NEW_REFRESH: &str = "1//brand-new-refresh-token-value";
const AUTH_CODE: &str = "4/authorization-code-value";
const ACCESS_TOKEN: &str = "ya29.access-token-value";
const SECRETS: [&str; 5] = [NEW_REFRESH, OLD_REFRESH, CLIENT_SECRET, AUTH_CODE, ACCESS_TOKEN];
const APP_RESULT: &str = "/app/credentials";

// -- A loopback token endpoint -------------------------------------------------------

type Seen = Arc<Mutex<Vec<HashMap<String, String>>>>;

struct FakeTokenEndpoint {
    url: String,
    seen: Seen,
}

/// Answers every POST with `status` and `body`, recording the form.
async fn fake_endpoint(status: u16, body: Value) -> FakeTokenEndpoint {
    use axum::{extract::State, routing::post, Form, Router};
    let seen: Seen = Arc::default();
    let body = body.to_string();
    let handler = move |State(seen): State<Seen>, Form(form): Form<HashMap<String, String>>| {
        let body = body.clone();
        async move {
            seen.lock().unwrap().push(form);
            (http::StatusCode::from_u16(status).unwrap(), [("content-type", "application/json")], body)
        }
    };
    let app = Router::new().route("/token", post(handler)).with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    FakeTokenEndpoint { url: format!("http://{addr}/token"), seen }
}

/// Nothing listens here: an exchange that gets this far fails.
const NEVER: &str = "http://127.0.0.1:9/never";

// -- The environment -------------------------------------------------------------------

fn tier1_doc(executor: &str, credential: &str) -> Value {
    let toolkit = if executor == "google" {
        json!({
            "executor": "google", "binaries": [],
            "google_script": "/opt/gatekeeper/google/google_api.py",
            "allowed_google_actions": ["gmail search", "calendar list"],
            "credential": credential, "max_timeout_seconds": 30, "max_output_bytes": 65536,
        })
    } else {
        json!({
            "executor": "microsoft",
            "microsoft_script": "/opt/gatekeeper/microsoft/microsoft_api.py",
            "allowed_microsoft_actions": ["mail list", "mail send"],
            "credential": credential, "max_timeout_seconds": 30, "max_output_bytes": 65536,
        })
    };
    let name = if executor == "google" { "gmail" } else { "outlook" };
    let mut toolkits = Map::new();
    toolkits.insert(name.into(), toolkit);
    toolkits.insert(
        "demo".into(),
        json!({"executor": "local", "binaries": ["/bin/sh"], "path_roots": [],
               "max_timeout_seconds": 30, "max_output_bytes": 8192}),
    );
    json!({ "toolkits": toolkits })
}

fn oauth_env(executor: &str, credential: &str, bundle: Value, endpoints: TokenEndpoints) -> ApiEnv {
    std::env::remove_var(BASE_URL_ENV);
    let options = ConsoleOptions { token_endpoints: endpoints, ..ConsoleOptions::default() };
    let env = make_env_with(Spec {
        tier1: Some(tier1_doc(executor, credential)),
        tools: Some(Vec::new()),
        options: Some(options),
        ..Spec::default()
    });
    let credentials = env.env.credentials.as_ref().unwrap();
    credentials
        .create(credential, "oauth2", &bundle.to_string(), None, None, None, "root", "")
        .unwrap();
    env
}

/// `test_oauth`'s console: a google toolkit, a half-filled `gws`.
fn google_env(token_url: &str) -> ApiEnv {
    oauth_env(
        "google",
        "gws",
        json!({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "refresh_token": OLD_REFRESH}),
        TokenEndpoints { google: token_url.into(), microsoft: NEVER.into() },
    )
}

/// A microsoft toolkit bound to `msgraph`, client pair only.
fn microsoft_env(token_url: &str) -> ApiEnv {
    oauth_env(
        "microsoft",
        "msgraph",
        json!({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}),
        TokenEndpoints { google: NEVER.into(), microsoft: token_url.into() },
    )
}

fn stored_bundle(env: &ApiEnv, name: &str) -> Value {
    let value = env.env.credentials.as_ref().unwrap().resolve(name).unwrap().unwrap().value;
    serde_json::from_str(&value).unwrap()
}

fn assert_clean(texts: &[&str]) {
    for text in texts {
        for secret in SECRETS {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
    }
}

async fn authorize(c: &mut Client, csrf: Option<&str>, provider: &str, credential: &str) -> api_env::Resp {
    let headers: Vec<(&str, &str)> = csrf.map(|t| vec![("x-csrf-token", t)]).unwrap_or_default();
    c.post(&api(&format!("/oauth/{provider}/authorize")), json!({"credential": credential}), &headers).await
}

/// Signs in as root and starts a flow; returns the authorize JSON.
async fn start(c: &mut Client, provider: &str, credential: &str) -> Value {
    let csrf = c.csrf("root").await;
    let response = authorize(c, Some(&csrf), provider, credential).await;
    assert_eq!(response.status, 200, "{}", response.text());
    response.json()
}

fn consent_params(start: &Value) -> HashMap<String, String> {
    url::Url::parse(start["consent_url"].as_str().unwrap()).unwrap().query_pairs().into_owned().collect()
}

/// Hits the callback, asserts it redirected, returns the Location.
async fn callback(c: &mut Client, path: &str, query: &str) -> String {
    let response = c.get(&format!("{path}?{query}")).await;
    assert_eq!(response.status, 303, "{}", response.text());
    let location = response.header("location").unwrap();
    assert!(location.starts_with(&format!("{APP_RESULT}?")), "{location}");
    // The callback is a redirect, nothing else: no body to leak through.
    assert_clean(&[&response.text()]);
    location
}

fn result(location: &str) -> Vec<(String, String)> {
    let query = location.split_once('?').map_or("", |(_, q)| q);
    url::form_urlencoded::parse(query.as_bytes()).into_owned().collect()
}

fn mismatch(provider: &str) -> Vec<(String, String)> {
    vec![
        ("oauth".into(), "state_mismatch".into()),
        ("provider".into(), provider.into()),
        ("credential".into(), String::new()),
    ]
}

// -- The gate --------------------------------------------------------------------------

/// No session, no state: the only way to get a state is an authenticated
/// authorize, and the callback alone redeems nothing.
#[tokio::test]
async fn starting_a_flow_requires_an_api_session() {
    let env = google_env(NEVER);
    let mut c = env.client();
    let response = authorize(&mut c, None, "google", "gws").await;
    assert_eq!(response.status, 401);
    assert_clean(&[&response.text()]);
    let location = callback(&mut c, OAUTH_CALLBACK_PATH, "").await;
    assert_eq!(result(&location), mismatch("google"));
    assert_eq!(stored_bundle(&env, "gws")["refresh_token"], OLD_REFRESH);
}

#[tokio::test]
async fn a_code_and_an_invented_state_are_not_access() {
    let env = google_env(NEVER);
    let mut c = env.client();
    for query in [
        format!("code={AUTH_CODE}&state=invented"),
        format!("code={AUTH_CODE}"),
        format!("code={AUTH_CODE}&state="),
    ] {
        let location = callback(&mut c, OAUTH_CALLBACK_PATH, &query).await;
        assert_eq!(result(&location), mismatch("google"));
        assert_clean(&[&location]);
    }
    assert_eq!(stored_bundle(&env, "gws")["refresh_token"], OLD_REFRESH);
    assert!(env.env.audit_text().contains("\"result\": \"state_mismatch\""));
}

#[tokio::test]
async fn authorize_needs_an_admin_and_csrf() {
    let env = google_env(NEVER);
    let mut c = env.client();
    assert_eq!(c.post(&api("/oauth/google/authorize"), json!({}), &[]).await.status, 401);
    let viewer = c.csrf("eye").await;
    let response = c.post(&api("/oauth/google/authorize"), json!({}), &[("x-csrf-token", &viewer)]).await;
    assert_eq!(response.status, 403);
    assert!(!response.text().contains("consent_url"));
    c.login("root").await;
    assert_eq!(c.post(&api("/oauth/google/authorize"), json!({}), &[]).await.status, 403);
    let wrong = authorize(&mut c, Some("not-the-csrf-token"), "google", "gws").await;
    assert_eq!(wrong.status, 403);
    assert!(!wrong.text().contains("consent_url"));
}

#[tokio::test]
async fn authorize_refusals() {
    let env = google_env(NEVER);
    env.env
        .credentials
        .as_ref()
        .unwrap()
        .create("sonarr", "bearer", "not-an-oauth-credential", None, None, None, "root", "")
        .unwrap();
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    let missing = authorize(&mut c, Some(&csrf), "google", "nope").await;
    assert_eq!(missing.status, 400);
    assert!(missing.error().contains("does not exist"));
    let bearer = authorize(&mut c, Some(&csrf), "google", "sonarr").await;
    assert_eq!(bearer.status, 400);
    assert!(bearer.error().contains("not oauth2"));
    assert!(!bearer.text().contains("not-an-oauth-credential"));
    let unknown = c.post(&api("/oauth/yahoo/authorize"), json!({}), &[("x-csrf-token", &csrf)]).await;
    assert_eq!(unknown.status, 404);
    let extra = c
        .post(&api("/oauth/google/authorize"), json!({"credential": "gws", "x": 1}), &[("x-csrf-token", &csrf)])
        .await;
    assert_eq!(extra.status, 422);
}

#[tokio::test]
async fn authorize_refuses_a_credential_that_has_no_client_pair() {
    let env = oauth_env(
        "google",
        "gws",
        json!({"client_id": CLIENT_ID}),
        TokenEndpoints { google: NEVER.into(), microsoft: NEVER.into() },
    );
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    let response = authorize(&mut c, Some(&csrf), "google", "gws").await;
    assert_eq!(response.status, 400);
    assert!(response.error().contains("client_id/client_secret"));
    assert!(!env.env.audit_text().contains("\"action\": \"google_authorize\""));
}

// -- The consent URL --------------------------------------------------------------------

#[tokio::test]
async fn authorize_answers_the_consent_url_and_nothing_secret() {
    let env = google_env(NEVER);
    let mut c = env.client();
    let start = start(&mut c, "google", "").await; // the only named one is picked
    let callback_uri = format!("{BASE}{OAUTH_CALLBACK_PATH}");
    assert_eq!(start["credential"], "gws");
    assert_eq!(start["provider"], "google");
    assert_eq!(start["callback_uri"], callback_uri.as_str());
    assert_eq!(start["mismatch_error"], "redirect_uri_mismatch");
    assert!(start["registration_console"].as_str().unwrap().contains("Google Cloud"));
    let params = consent_params(&start);
    assert_eq!(params["client_id"], CLIENT_ID);
    assert_eq!(params["redirect_uri"], callback_uri);
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["access_type"], "offline");
    assert_eq!(params["prompt"], "consent");
    assert!(params["state"].len() >= 32);
    let expected: Vec<String> = DEFAULT_GOOGLE_SCOPES.iter().map(|s| format!("{GOOGLE_SCOPE_PREFIX}{s}")).collect();
    assert_eq!(start["scopes"], json!(expected));
    assert_eq!(params["scope"], expected.join(" "));
    assert_clean(&[&start.to_string()]);
    let log = env.env.audit_text();
    let record: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(record["action"], "google_authorize");
    assert_eq!(record["surface"], "api");
    assert!(!log.contains(CLIENT_SECRET));
}

#[tokio::test]
async fn the_callback_uri_follows_the_request_scheme() {
    let env = google_env(NEVER);
    let mut c = env.client();
    c.scheme = Some("https".into());
    let start = start(&mut c, "google", "gws").await;
    assert_eq!(start["callback_uri"], format!("https://gatekeeper.test{OAUTH_CALLBACK_PATH}"));
}

// -- The callback -----------------------------------------------------------------------

/// The whole point: the token lands in the store, and nowhere else; the
/// `/app`-started flow returns to `/app` with a result code only.
#[tokio::test]
async fn an_app_flow_returns_to_app_with_a_result_code() {
    let scope: Vec<String> = DEFAULT_GOOGLE_SCOPES.iter().map(|s| format!("{GOOGLE_SCOPE_PREFIX}{s}")).collect();
    let endpoint = fake_endpoint(
        200,
        json!({"access_token": ACCESS_TOKEN, "refresh_token": NEW_REFRESH, "expires_in": 3599, "scope": scope.join(" ")}),
    )
    .await;
    let env = google_env(&endpoint.url);
    let mut c = env.client();
    let start = start(&mut c, "google", "gws").await;
    let state = consent_params(&start)["state"].clone();
    let location = callback(&mut c, OAUTH_CALLBACK_PATH, &format!("code={AUTH_CODE}&state={state}")).await;
    assert_eq!(location, "/app/credentials?oauth=ok&provider=google&credential=gws");
    // The exchange got the credential's own client pair and the redirect
    // URI the consent URL named.
    let seen = endpoint.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["code"], AUTH_CODE);
    assert_eq!(seen[0]["client_id"], CLIENT_ID);
    assert_eq!(seen[0]["client_secret"], CLIENT_SECRET);
    assert_eq!(seen[0]["redirect_uri"], format!("{BASE}{OAUTH_CALLBACK_PATH}"));
    assert_eq!(
        stored_bundle(&env, "gws"),
        json!({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "refresh_token": NEW_REFRESH, "scopes": scope})
    );
    // Single use: the same state again changes nothing.
    let again = callback(&mut c, OAUTH_CALLBACK_PATH, &format!("code={AUTH_CODE}&state={state}")).await;
    assert_eq!(again, "/app/credentials?oauth=state_mismatch&provider=google&credential=");
    assert_eq!(endpoint.seen.lock().unwrap().len(), 1);
    assert_clean(&[&location, &start.to_string()]);
    let log = env.env.audit_text();
    assert!(log.contains("\"action\": \"google_callback\""));
    for secret in SECRETS.iter().chain([&CLIENT_ID, &state.as_str()]) {
        assert!(!log.contains(secret), "{secret}");
    }
}

#[tokio::test]
async fn a_denied_app_flow_changes_nothing() {
    let env = google_env(NEVER);
    let mut c = env.client();
    let start = start(&mut c, "google", "gws").await;
    let state = consent_params(&start)["state"].clone();
    let location =
        callback(&mut c, OAUTH_CALLBACK_PATH, &format!("error=access_denied%3Cscript%3E&state={state}")).await;
    // The provider's text is not reflected; only the console's own code is.
    assert_eq!(location, "/app/credentials?oauth=denied&provider=google&credential=gws");
    assert_eq!(stored_bundle(&env, "gws")["refresh_token"], OLD_REFRESH);
    // Single use on failure too.
    let retry = callback(&mut c, OAUTH_CALLBACK_PATH, &format!("code={AUTH_CODE}&state={state}")).await;
    assert_eq!(result(&retry)[0].1, "state_mismatch");
}

/// Issued to `root`, redeemed in a browser signed in as `eye`: the API
/// cookie is scoped to `/api/v1`, so the callback writes as the operator
/// the state names.
#[tokio::test]
async fn a_state_writes_as_the_operator_it_was_issued_to() {
    let endpoint = fake_endpoint(200, json!({"refresh_token": NEW_REFRESH})).await;
    let env = google_env(&endpoint.url);
    let mut starter = env.client();
    let state = consent_params(&start(&mut starter, "google", "gws").await)["state"].clone();
    let mut other = env.client();
    other.login("eye").await;
    let location = callback(&mut other, OAUTH_CALLBACK_PATH, &format!("code={AUTH_CODE}&state={state}")).await;
    assert_eq!(result(&location)[0].1, "ok");
    assert_eq!(stored_bundle(&env, "gws")["refresh_token"], NEW_REFRESH);
    let actors: Vec<Value> = env
        .audit_records()
        .into_iter()
        .filter(|r| r["action"] == "google_callback")
        .map(|r| r["actor"].clone())
        .collect();
    assert_eq!(actors, [json!("root")]);
}

/// The role is re-checked when the credential is written: a demotion
/// between start and callback spends nothing.
#[tokio::test]
async fn a_revoked_admin_cannot_finish_a_flow_it_started() {
    for change in ["demote", "delete"] {
        let env = google_env(NEVER);
        let mut c = env.client();
        let state = consent_params(&start(&mut c, "google", "gws").await)["state"].clone();
        {
            let mut ids = env.env.identities.write();
            if change == "demote" {
                ids.identities.get_mut("root").unwrap().role = "viewer".into();
            } else {
                ids.identities.shift_remove("root");
            }
        }
        let location = callback(&mut c, OAUTH_CALLBACK_PATH, &format!("code={AUTH_CODE}&state={state}")).await;
        assert_eq!(location, "/app/credentials?oauth=role_required&provider=google&credential=gws", "{change}");
        assert_eq!(stored_bundle(&env, "gws")["refresh_token"], OLD_REFRESH);
    }
}

#[tokio::test]
async fn a_failed_exchange_says_so_without_quoting_google() {
    let endpoint = fake_endpoint(400, json!({"error": "invalid_grant", "echo": CLIENT_SECRET})).await;
    for url in [endpoint.url.as_str(), NEVER] {
        let env = google_env(url);
        let mut c = env.client();
        let state = consent_params(&start(&mut c, "google", "gws").await)["state"].clone();
        let location = callback(&mut c, OAUTH_CALLBACK_PATH, &format!("code={AUTH_CODE}&state={state}")).await;
        assert_eq!(location, "/app/credentials?oauth=exchange_failed&provider=google&credential=gws");
        assert_clean(&[&location, &env.env.audit_text()]);
        assert_eq!(stored_bundle(&env, "gws")["refresh_token"], OLD_REFRESH);
    }
}

/// A non-GET write under `/ui` is the legacy console's 410, never a
/// redemption; HEAD is answered like GET (Starlette's `Route`).
#[tokio::test]
async fn the_callback_redeems_on_get_only() {
    let env = google_env(NEVER);
    let mut c = env.client();
    let response = c.post_empty(OAUTH_CALLBACK_PATH, &[]).await;
    assert_eq!(response.status, 410);
    assert!(response.text().starts_with("The /ui console was replaced by /app in gatekeeper 1.0.0."));
    let head = c.send("HEAD", OAUTH_CALLBACK_PATH, &[], api_env::Payload::None).await;
    assert_eq!(head.status, 303);
    assert_eq!(head.header("location").unwrap(), "/app/credentials?oauth=state_mismatch&provider=google&credential=");
}

// -- Providers ---------------------------------------------------------------------------

/// What the credentials page offers follows Tier 1: the google toolkit
/// names `gws`, and a bearer credential nothing names is not offered.
#[tokio::test]
async fn providers_list_the_named_credentials() {
    let env = google_env(NEVER);
    env.env
        .credentials
        .as_ref()
        .unwrap()
        .create("sonarr", "bearer", "not-an-oauth-credential", None, None, None, "root", "")
        .unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let response = c.get(&api("/oauth/providers")).await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.json(),
        json!([{"key": "google", "label": "Google", "credentials": ["gws"], "callback_path": OAUTH_CALLBACK_PATH}])
    );
    assert_clean(&[&response.text()]);
}

#[tokio::test]
async fn the_microsoft_provider_is_listed_with_its_own_callback() {
    let env = microsoft_env(NEVER);
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/oauth/providers")).await.json();
    assert_eq!(body[0]["key"], "microsoft");
    assert_eq!(body[0]["credentials"], json!(["msgraph"]));
    assert_eq!(body[0]["callback_path"], MICROSOFT_OAUTH_CALLBACK_PATH);
}

// -- Microsoft ---------------------------------------------------------------------------

#[tokio::test]
async fn microsoft_flow_carries_pkce_and_stores_what_was_granted() {
    let consented = microsoft_scope_urls(&DEFAULT_MICROSOFT_SCOPES);
    // Microsoft leaves `offline_access` out of the response's scope field.
    let granted: Vec<&String> = consented.iter().filter(|s| *s != "offline_access").collect();
    let granted: Vec<&str> = granted.iter().map(|s| s.as_str()).collect();
    let endpoint = fake_endpoint(
        200,
        json!({"access_token": ACCESS_TOKEN, "refresh_token": NEW_REFRESH, "scope": granted.join(" ")}),
    )
    .await;
    let env = microsoft_env(&endpoint.url);
    let mut c = env.client();
    let start = start(&mut c, "microsoft", "msgraph").await;
    let params = consent_params(&start);
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["redirect_uri"], format!("{BASE}{MICROSOFT_OAUTH_CALLBACK_PATH}"));
    assert_clean(&[&start.to_string()]);
    let location = callback(
        &mut c,
        MICROSOFT_OAUTH_CALLBACK_PATH,
        &format!("code={AUTH_CODE}&state={}", params["state"]),
    )
    .await;
    assert_eq!(location, "/app/credentials?oauth=ok&provider=microsoft&credential=msgraph");
    let seen = endpoint.seen.lock().unwrap().clone();
    assert_eq!(pkce_challenge(&seen[0]["code_verifier"]), params["code_challenge"]);
    let bundle = stored_bundle(&env, "msgraph");
    assert_eq!(bundle["refresh_token"], NEW_REFRESH);
    assert_eq!(bundle["provider"], "microsoft");
    assert!(bundle["scopes"].as_array().unwrap().contains(&json!("offline_access")));
}

/// One state store serves both providers; a state is redeemable only at
/// the callback of the flow that minted it.
#[tokio::test]
async fn a_state_is_not_redeemable_at_the_other_providers_callback() {
    let endpoint = fake_endpoint(200, json!({"refresh_token": NEW_REFRESH})).await;
    let env = microsoft_env(&endpoint.url);
    let mut c = env.client();
    let state = consent_params(&start(&mut c, "microsoft", "msgraph").await)["state"].clone();
    let location = callback(&mut c, OAUTH_CALLBACK_PATH, &format!("code={AUTH_CODE}&state={state}")).await;
    assert_eq!(result(&location), mismatch("google"));
    assert!(endpoint.seen.lock().unwrap().is_empty());
    assert!(stored_bundle(&env, "msgraph").get("refresh_token").is_none());
}
