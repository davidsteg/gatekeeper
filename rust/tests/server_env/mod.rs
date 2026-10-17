//! Shared setup for the HTTP server tests: identities with known tokens,
//! the real router on a loopback socket, and a small MCP client speaking
//! both protocol eras over raw HTTP (the role the Python SDK `Client`
//! plays in `test_integration_mcp.py` and friends).
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request};
use axum::middleware::{self, Next};
use axum::Router;
use futures::StreamExt;
use gatekeeper::identity::{generate_token, hash_token, hash_token_lookup};
use gatekeeper::server::{build_app, AppOptions};
use serde_json::{json, Value};

use crate::app_env::{builder, AppEnv};

pub const ACCEPT: &str = "application/json, text/event-stream";
pub const MODERN: &str = "2026-07-28";

/// One identity entry with a fresh token. `password` makes it a console
/// account.
pub fn identity(id: &str, role: &str, tools: &[&str], scopes: &[&str], password: Option<&str>) -> (Value, String) {
    let token = generate_token();
    let mut entry = json!({
        "id": id, "role": role, "token_hash": hash_token(&token), "token_lookup": hash_token_lookup(&token),
        "tools": tools, "scopes": scopes,
    });
    if let Some(p) = password {
        entry["password_hash"] = json!(hash_token(p));
    }
    (entry, token)
}

/// The conftest `identities` (full, narrow) plus an admin "root" with a
/// console password, so the store's last-admin rule never trips.
pub struct Tokens {
    pub full: String,
    pub narrow: String,
    pub root: String,
}

pub fn standard_identities() -> (Vec<Value>, Tokens) {
    let (full, full_t) = identity("full", "agent", &["demo.show", "demo.echo"], &["stack:*"], None);
    let (narrow, narrow_t) = identity("narrow", "agent", &["demo.show"], &["stack:media-*"], None);
    let (root, root_t) = identity("root", "admin", &[], &[], Some(crate::app_env::ROOT_PASSWORD));
    (vec![full, narrow, root], Tokens { full: full_t, narrow: narrow_t, root: root_t })
}

/// An `AppEnv` with [`standard_identities`].
pub fn standard_env() -> (AppEnv, Tokens) {
    let (ids, tokens) = standard_identities();
    (builder().identities(ids).build(), tokens)
}

/// `build_app(service=..., identities=..., audit=...)`: read only, no UI.
pub fn read_only_app(env: &AppEnv) -> Router {
    build_app(AppOptions::new(env.service.clone(), env.identities.clone(), env.audit.clone())).unwrap()
}

/// The app with the UI and the writable stores (`api_env.make_env`).
pub fn full_app(env: &AppEnv) -> Router {
    let mut opts = AppOptions::new(env.service.clone(), env.identities.clone(), env.audit.clone());
    opts.ui = true;
    opts.store = Some(env.store.clone());
    opts.pending = Some(env.pending.clone());
    opts.toolkit_proposals = Some(env.proposals.clone());
    opts.credentials = env.credentials.clone();
    build_app(opts).unwrap()
}

/// Serves `app` on an ephemeral loopback port; returns the base URL.
pub async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    format!("http://{addr}")
}

/// Pretends every request came from `peer` (httpx's `ASGITransport(client=...)`).
pub fn from_peer(app: Router, peer: &str) -> Router {
    let ip: std::net::IpAddr = peer.parse().unwrap();
    app.layer(middleware::from_fn(move |mut request: Request, next: Next| async move {
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip, 123)));
        next.run(request).await
    }))
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap()
}

/// Reads `data:` frames off an SSE response, keepalives skipped.
pub struct Frames {
    stream: futures::stream::BoxStream<'static, reqwest::Result<bytes::Bytes>>,
    buf: String,
}

impl Frames {
    pub fn new(r: reqwest::Response) -> Self {
        Frames { stream: r.bytes_stream().boxed(), buf: String::new() }
    }

    pub async fn next(&mut self) -> Option<Value> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let sep = self.buf.find("\r\n\r\n").map(|p| (p, 4)).or_else(|| self.buf.find("\n\n").map(|p| (p, 2)));
                if let Some((pos, len)) = sep {
                    let frame: String = self.buf.drain(..pos + len).collect();
                    if let Some(data) = frame.lines().find_map(|l| l.strip_prefix("data: ")) {
                        return Some(serde_json::from_str(data).unwrap());
                    }
                    continue;
                }
                match self.stream.next().await {
                    Some(Ok(chunk)) => self.buf.push_str(&String::from_utf8_lossy(&chunk)),
                    _ => return None,
                }
            }
        })
        .await
        .expect("no SSE frame within 10s")
    }
}

/// The JSON-RPC message of a response: the first SSE data frame, or the
/// JSON body.
pub async fn message(r: reqwest::Response) -> Value {
    let sse = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    if sse {
        Frames::new(r).next().await.expect("an SSE data frame")
    } else {
        r.json().await.unwrap()
    }
}

/// A connected MCP client with a bearer token.
pub struct Mcp {
    pub http: reqwest::Client,
    pub url: String,
    pub token: String,
    /// `Some` for a handshake-era session.
    pub session: Option<String>,
    pub init: Value,
    next_id: i64,
}

impl Mcp {
    /// A handshake-era session (`initialize` + `notifications/initialized`).
    pub async fn connect(base: &str, path: &str, token: &str) -> Mcp {
        let http = http();
        let url = format!("{base}{path}");
        let r = http
            .post(&url)
            .bearer_auth(token)
            .header("accept", ACCEPT)
            .header("content-type", "application/json")
            .body(
                json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "rust-test", "version": "1"}}})
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "initialize on {path}");
        let session = r.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_string());
        let init = message(r).await;
        let mut req = http
            .post(&url)
            .bearer_auth(token)
            .header("accept", ACCEPT)
            .header("content-type", "application/json")
            .body(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string());
        if let Some(s) = &session {
            req = req.header("mcp-session-id", s);
        }
        assert_eq!(req.send().await.unwrap().status(), 202);
        Mcp { http, url, token: token.into(), session, init, next_id: 1 }
    }

    /// A 2026-07-28 client: no session, every request self-contained.
    pub fn modern(base: &str, path: &str, token: &str) -> Mcp {
        Mcp {
            http: http(),
            url: format!("{base}{path}"),
            token: token.into(),
            session: None,
            init: Value::Null,
            next_id: 1,
        }
    }

    fn is_modern(&self) -> bool {
        self.init.is_null()
    }

    /// One request; returns the whole JSON-RPC response.
    pub async fn request(&mut self, method: &str, mut params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let mut req = self
            .http
            .post(&self.url)
            .bearer_auth(&self.token)
            .header("accept", ACCEPT)
            .header("content-type", "application/json");
        if self.is_modern() {
            params["_meta"] = json!({
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "rust-test", "version": "1"},
            });
            req = req.header("mcp-protocol-version", MODERN).header("mcp-method", method);
            if let Some(name) = params.get("name").and_then(Value::as_str) {
                req = req.header("mcp-name", name);
            }
        } else {
            req = req.header("mcp-protocol-version", "2025-11-25");
        }
        if let Some(s) = &self.session {
            req = req.header("mcp-session-id", s);
        }
        let r = req
            .body(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{method}");
        message(r).await
    }

    pub async fn list_tools(&mut self) -> Vec<Value> {
        let r = self.request("tools/list", json!({})).await;
        r["result"]["tools"].as_array().cloned().unwrap_or_else(|| panic!("tools/list: {r}"))
    }

    pub async fn tool_names(&mut self) -> Vec<String> {
        self.list_tools().await.iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    }

    /// `tools/call`; returns `result` (panics on a JSON-RPC error).
    pub async fn call(&mut self, name: &str, args: Value) -> Value {
        let r = self.request("tools/call", json!({"name": name, "arguments": args})).await;
        r.get("result").cloned().unwrap_or_else(|| panic!("tools/call {name}: {r}"))
    }

    pub async fn call_text(&mut self, name: &str, args: Value) -> (String, bool) {
        let result = self.call(name, args).await;
        (result["content"][0]["text"].as_str().unwrap_or_default().to_string(), result["isError"] == json!(true))
    }
}

/// A raw `POST` with an optional bearer token.
pub async fn post_json(base: &str, path: &str, token: Option<&str>, body: Value, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut req = http().post(format!("{base}{path}")).header("accept", ACCEPT).json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.send().await.unwrap()
}

pub async fn get(base: &str, path: &str, token: Option<&str>) -> reqwest::Response {
    let mut req = http().get(format!("{base}{path}"));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await.unwrap()
}

/// Every audit record of `kind`.
pub fn audit_of(env: &AppEnv, kind: &str) -> Vec<Value> {
    env.audit_lines().into_iter().filter(|r| r["kind"] == kind).collect()
}

pub fn shared<T>(v: T) -> Arc<T> {
    Arc::new(v)
}
