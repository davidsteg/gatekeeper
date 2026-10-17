//! Shared setup for the `/api/v1` tests (port of `tests/api_env.py`).
//!
//! Builds the console router the server merges when the UI is enabled,
//! sharing every store. Three identities -- an admin and a viewer with
//! console passwords, and an agent with only an API token. Requests go
//! through the real router as HTTP requests (`oneshot`); a small cookie jar
//! plays the browser.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

use axum::body::Body;
use axum::Router;
use bytes::Bytes;
use gatekeeper::api::{console_router_with, ConsoleDeps, ConsoleOptions, RequestClient, API_PREFIX};
use gatekeeper::identity::{generate_token, hash_token};
use http::{HeaderMap, Request};
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::app_env::{self, AppEnv, EYE_PASSWORD, ROOT_PASSWORD};

pub const API: &str = API_PREFIX;
pub const HOST: &str = "gatekeeper.test";
pub const BASE: &str = "http://gatekeeper.test";

pub fn password(identity: &str) -> &'static str {
    match identity {
        "root" => ROOT_PASSWORD,
        "eye" => EYE_PASSWORD,
        other => panic!("no console password for {other}"),
    }
}

pub struct ApiEnv {
    pub env: AppEnv,
    pub router: Router,
    pub tokens: HashMap<String, String>,
}

#[derive(Default)]
pub struct Spec {
    pub read_only: bool,
    pub tier1: Option<Value>,
    pub tools: Option<Vec<Value>>,
    pub options: Option<ConsoleOptions>,
    /// Extra identities appended to the three default ones.
    pub extra_identities: Vec<Value>,
}

pub fn make_env() -> ApiEnv {
    make_env_with(Spec::default())
}

pub fn read_only_env() -> ApiEnv {
    make_env_with(Spec { read_only: true, ..Spec::default() })
}

pub fn make_env_with(spec: Spec) -> ApiEnv {
    let tokens: HashMap<String, String> =
        ["root", "eye", "bot"].iter().map(|id| (id.to_string(), generate_token())).collect();
    let mut identities = vec![
        json!({"id": "root", "role": "admin", "token_hash": hash_token(&tokens["root"]),
               "password_hash": hash_token(ROOT_PASSWORD), "tools": [], "scopes": []}),
        json!({"id": "eye", "role": "viewer", "token_hash": hash_token(&tokens["eye"]),
               "password_hash": hash_token(EYE_PASSWORD), "tools": [], "scopes": []}),
        json!({"id": "bot", "role": "agent", "token_hash": hash_token(&tokens["bot"]),
               "tools": ["demo.show"], "scopes": ["stack:*"]}),
    ];
    identities.extend(spec.extra_identities);
    let mut builder = app_env::builder().identities(identities).credentials();
    if let Some(doc) = spec.tier1 {
        builder = builder.tier1(doc);
    }
    if let Some(tools) = spec.tools {
        builder = builder.tools(tools);
    }
    let env = builder.build();
    let router = router_for(&env, spec.read_only, spec.options.unwrap_or_default());
    ApiEnv { env, router, tokens }
}

pub fn deps_for(env: &AppEnv, read_only: bool) -> ConsoleDeps {
    ConsoleDeps {
        service: env.service.clone(),
        identities: env.identities.clone(),
        audit: env.audit.clone(),
        store: (!read_only).then(|| env.store.clone()),
        credentials: env.credentials.clone(),
        pending: (!read_only).then(|| env.pending.clone()),
        toolkit_proposals: (!read_only).then(|| env.proposals.clone()),
    }
}

pub fn router_for(env: &AppEnv, read_only: bool, options: ConsoleOptions) -> Router {
    console_router_with(deps_for(env, read_only), options)
}

impl ApiEnv {
    pub fn client(&self) -> Client {
        Client::new(self.router.clone())
    }

    pub fn audit_records(&self) -> Vec<Value> {
        self.env.audit_lines()
    }

    pub fn denied_reasons(&self) -> Vec<String> {
        self.audit_records()
            .iter()
            .filter(|r| r["kind"] == "admin_denied")
            .map(|r| r["reason"].as_str().unwrap_or("").to_string())
            .collect()
    }
}

/// One response, fully read.
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", String::from_utf8_lossy(&self.body)))
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).map(|v| v.to_str().unwrap().to_string())
    }
    pub fn error(&self) -> String {
        self.json()["error"].as_str().unwrap_or_else(|| panic!("no error in {}", self.text())).to_string()
    }
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).collect()
    }
}

/// A browser: a cookie jar over the router.
#[derive(Clone)]
pub struct Client {
    router: Router,
    pub cookies: BTreeMap<String, String>,
    pub client_host: Option<String>,
    pub scheme: Option<String>,
}

pub enum Payload {
    None,
    Json(Value),
    Raw(Option<&'static str>, Vec<u8>),
}

impl Client {
    pub fn new(router: Router) -> Client {
        Client { router, cookies: BTreeMap::new(), client_host: Some("127.0.0.1".into()), scheme: None }
    }

    pub async fn send(&mut self, method: &str, path: &str, headers: &[(&str, &str)], payload: Payload) -> Resp {
        let mut builder = Request::builder().method(method).uri(path).header("host", HOST);
        let mut has_ct = false;
        for (k, v) in headers {
            has_ct |= k.eq_ignore_ascii_case("content-type");
            builder = builder.header(*k, *v);
        }
        if path.starts_with(API) && !self.cookies.is_empty() && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
            let jar: Vec<String> = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
            builder = builder.header("cookie", jar.join("; "));
        }
        let body = match payload {
            Payload::None => Body::empty(),
            Payload::Json(v) => {
                if !has_ct {
                    builder = builder.header("content-type", "application/json");
                }
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            Payload::Raw(ct, bytes) => {
                if let (Some(ct), false) = (ct, has_ct) {
                    builder = builder.header("content-type", ct);
                }
                Body::from(bytes)
            }
        };
        let mut request = builder.body(body).unwrap();
        request
            .extensions_mut()
            .insert(RequestClient { host: self.client_host.clone(), scheme: self.scheme.clone() });
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp = Resp { status, headers, body };
        for cookie in resp.set_cookies() {
            let first = cookie.split(';').next().unwrap();
            let (name, value) = first.split_once('=').unwrap();
            if cookie.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_string(), value.to_string());
            }
        }
        resp
    }

    pub async fn get(&mut self, path: &str) -> Resp {
        self.send("GET", path, &[], Payload::None).await
    }
    pub async fn get_h(&mut self, path: &str, headers: &[(&str, &str)]) -> Resp {
        self.send("GET", path, headers, Payload::None).await
    }
    pub async fn post(&mut self, path: &str, body: Value, headers: &[(&str, &str)]) -> Resp {
        self.send("POST", path, headers, Payload::Json(body)).await
    }
    pub async fn put(&mut self, path: &str, body: Value, headers: &[(&str, &str)]) -> Resp {
        self.send("PUT", path, headers, Payload::Json(body)).await
    }
    pub async fn delete(&mut self, path: &str, headers: &[(&str, &str)]) -> Resp {
        self.send("DELETE", path, headers, Payload::None).await
    }
    pub async fn post_empty(&mut self, path: &str, headers: &[(&str, &str)]) -> Resp {
        self.send("POST", path, headers, Payload::None).await
    }

    /// Signs in through the API; returns the session info (with `csrf`).
    pub async fn login(&mut self, identity: &str) -> Value {
        let response = self.post(&format!("{API}/session"), json!({"identity": identity, "password": password(identity)}), &[]).await;
        assert_eq!(response.status, 200, "{}", response.text());
        response.json()
    }

    /// Signs in and returns the CSRF token.
    pub async fn csrf(&mut self, identity: &str) -> String {
        self.login(identity).await["csrf"].as_str().unwrap().to_string()
    }

    /// The `ETag` of a GET, for `If-Match`.
    pub async fn etag(&mut self, path: &str) -> String {
        let response = self.get(path).await;
        assert_eq!(response.status, 200, "{}", response.text());
        response.header("etag").expect("etag")
    }
}

pub fn api(path: &str) -> String {
    format!("{API}{path}")
}

/// Every GET route in the schema, with path parameters filled in.
///
/// `streams = false` leaves out the event stream (`/events`): signed in, it
/// never ends. Its signed-in behaviour is tested over a real socket in
/// `api_events.rs`.
pub fn get_paths(streams: bool) -> Vec<String> {
    let schema: Value = serde_json::from_str(&gatekeeper::api::openapi_json()).unwrap();
    let mut paths = Vec::new();
    for (path, ops) in schema["paths"].as_object().unwrap() {
        let Some(get) = ops.get("get") else { continue };
        let content = &get["responses"]["200"]["content"];
        if !streams && content.get("text/event-stream").is_some() {
            continue;
        }
        paths.push(path.replace("{tool_id}", "demo.show").replace("{slug}", "readme"));
    }
    paths.sort();
    paths
}

/// Appends records to the audit log, as the service would.
pub fn write_audit(env: &ApiEnv, records: &[Value]) {
    use std::io::Write;
    let mut handle = std::fs::OpenOptions::new().create(true).append(true).open(env.env.audit.path()).unwrap();
    for record in records {
        writeln!(handle, "{}", serde_json::to_string(record).unwrap()).unwrap();
    }
}

/// `time.strftime("%Y-%m-%dT%H:%M:%S%z")`.
pub fn now_ts() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string()
}
