//! Wire tests for `gatekeeper::mcp` over a real loopback socket, covering
//! what `tests/test_mcp_live_catalog.py`, `test_notifications.py`,
//! `test_integration_mcp.py` and `test_admin_mcp.py` expect of the MCP
//! layer: the `listChanged` promise in both eras, delivery on listen and
//! standalone streams to every session, `cacheScope`, the admin mount's
//! identity, the request context (extensions, peer), DELETE/idle reaping,
//! cancellation and `Mcp-Param-*` validation.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::Router;
use futures::StreamExt;
use gatekeeper::mcp::{
    self, CallToolResult, CatalogNotifier, ListToolsResult, McpConfig, McpError, McpHandler, RequestContext, ServerInfo,
};
use serde_json::{json, Map, Value};

const MODERN: &str = "2026-07-28";
const ACCEPT: &str = "application/json, text/event-stream";

#[derive(Clone, Debug, PartialEq)]
struct Identity(String);

struct Probe {
    name: &'static str,
    notifier: Option<CatalogNotifier>,
}

#[async_trait]
impl McpHandler for Probe {
    fn server_info(&self) -> ServerInfo {
        ServerInfo::new(self.name, "1.2.3").with_instructions("probe")
    }

    async fn list_tools(&self, ctx: &RequestContext) -> Result<ListToolsResult, McpError> {
        if let Some(n) = &self.notifier {
            n.track(ctx);
        }
        Ok(ListToolsResult::new(vec![
            json!({"name": "who", "inputSchema": {"type": "object"},
                   "annotations": {"readOnlyHint": true, "idempotentHint": true}}),
            json!({"name": "slow", "inputSchema": {"type": "object"}}),
            json!({"name": "routed", "inputSchema": {"type": "object", "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"}}}}),
        ]))
    }

    async fn call_tool(&self, ctx: &RequestContext, name: &str, args: Map<String, Value>) -> Result<CallToolResult, McpError> {
        match name {
            "who" => {
                let who = ctx.extensions.get::<Identity>().map(|i| i.0.clone()).unwrap_or_default();
                let peer = ctx.peer.map(|p| p.ip().to_string()).unwrap_or_default();
                Ok(CallToolResult::text(format!("{who}@{peer} v{}", ctx.protocol_version), false))
            }
            "slow" => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(CallToolResult::text("slept", false))
            }
            "routed" => Ok(CallToolResult::text(format!("{:?}", args.get("region")), false)),
            _ => Ok(CallToolResult::text("unknown", true)),
        }
    }

    async fn on_initialized(&self, ctx: &RequestContext) {
        if let Some(n) = &self.notifier {
            n.track(ctx);
        }
    }
}

async fn authenticate(mut request: Request, next: Next) -> axum::response::Response {
    request.extensions_mut().insert(Identity("alice".into()));
    next.run(request).await
}

struct Server {
    base: String,
    notifier: CatalogNotifier,
    http: reqwest::Client,
}

async fn serve(idle: Option<Duration>) -> Server {
    serve_with(|agent| agent.session_idle_timeout = idle).await
}

async fn serve_with(configure: impl FnOnce(&mut McpConfig)) -> Server {
    let notifier = CatalogNotifier::new();
    let mut agent = McpConfig::stateful("/mcp").with_notifier(notifier.clone());
    configure(&mut agent);
    let app = Router::new()
        .merge(mcp::router(Arc::new(Probe { name: "agent", notifier: Some(notifier.clone()) }), agent))
        .merge(mcp::router(Arc::new(Probe { name: "gatekeeper-admin", notifier: None }), McpConfig::stateless("/admin/mcp")))
        .layer(middleware::from_fn(authenticate));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    Server { base: format!("http://{addr}"), notifier, http: reqwest::Client::new() }
}

fn meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion": MODERN,
           "io.modelcontextprotocol/clientCapabilities": {},
           "io.modelcontextprotocol/clientInfo": {"name": "wire", "version": "1"}})
}

impl Server {
    /// The request is built now, so the future borrows nothing.
    fn post(&self, path: &str, body: Value, headers: &[(&str, &str)]) -> impl Future<Output = reqwest::Response> + 'static {
        let mut req = self
            .http
            .post(format!("{}{path}", self.base))
            .header("accept", ACCEPT)
            .header("content-type", "application/json")
            .body(body.to_string());
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        async move { req.send().await.unwrap() }
    }

    fn modern(
        &self,
        path: &str,
        id: i64,
        method: &str,
        mut params: Value,
        extra: &[(&str, &str)],
    ) -> impl Future<Output = reqwest::Response> + 'static {
        params["_meta"] = meta();
        let mut headers = vec![("mcp-protocol-version", MODERN), ("mcp-method", method)];
        headers.extend_from_slice(extra);
        self.post(path, json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}), &headers)
    }

    /// `initialize` + `notifications/initialized`; returns (session id, init result).
    async fn handshake(&self) -> (String, Value) {
        let r = self
            .post(
                "/mcp",
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "wire", "version": "1"}}}),
                &[],
            )
            .await;
        assert_eq!(r.status(), 200);
        let sid = r.headers()["mcp-session-id"].to_str().unwrap().to_string();
        let init = first_data(r).await;
        let r = self.post("/mcp", json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), &[("mcp-session-id", &sid)]).await;
        assert_eq!(r.status(), 202);
        (sid, init)
    }
}

/// Reads `data:` frames off an SSE response, keepalives skipped.
struct Frames {
    stream: futures::stream::BoxStream<'static, reqwest::Result<bytes::Bytes>>,
    buf: String,
}

impl Frames {
    fn new(r: reqwest::Response) -> Self {
        Frames { stream: r.bytes_stream().boxed(), buf: String::new() }
    }

    async fn next(&mut self) -> Option<Value> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(pos) = self.buf.find("\r\n\r\n") {
                    let frame: String = self.buf.drain(..pos + 4).collect();
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

async fn first_data(r: reqwest::Response) -> Value {
    Frames::new(r).next().await.expect("an SSE data frame")
}

#[tokio::test]
async fn initialize_advertises_tools_list_changed() {
    let s = serve(None).await;
    let (_, init) = s.handshake().await;
    assert_eq!(init["result"]["capabilities"], json!({"experimental": {}, "tools": {"listChanged": true}}));
    assert_eq!(init["result"]["serverInfo"], json!({"name": "agent", "version": "1.2.3"}));
    // The admin mount has no notifier: no promise to keep.
    let r = s
        .post(
            "/admin/mcp",
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "w", "version": "1"}}}),
            &[],
        )
        .await;
    assert!(r.headers().get("mcp-session-id").is_none());
    let init = first_data(r).await;
    assert_eq!(init["result"]["capabilities"]["tools"]["listChanged"], false);
    assert_eq!(init["result"]["serverInfo"], json!({"name": "gatekeeper-admin", "version": "1.2.3"}));
}

#[tokio::test]
async fn discover_advertises_tools_list_changed_and_the_admin_identity() {
    let s = serve(None).await;
    let r = s.modern("/mcp", 1, "server/discover", json!({}), &[]).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "application/json");
    let d: Value = r.json().await.unwrap();
    assert_eq!(d["result"]["capabilities"], json!({"tools": {"listChanged": true}}));
    assert_eq!(d["result"]["supportedVersions"], json!([MODERN]));
    let d: Value = s.modern("/admin/mcp", 2, "server/discover", json!({}), &[]).await.json().await.unwrap();
    assert_eq!(d["result"]["capabilities"], json!({"tools": {"listChanged": false}}));
    assert_eq!(d["result"]["_meta"]["io.modelcontextprotocol/serverInfo"], json!({"name": "gatekeeper-admin", "version": "1.2.3"}));
}

#[tokio::test]
async fn tools_list_is_private_and_keeps_annotations() {
    let s = serve(None).await;
    let r: Value = s.modern("/mcp", 1, "tools/list", json!({}), &[]).await.json().await.unwrap();
    assert_eq!(r["result"]["cacheScope"], "private");
    assert_eq!(r["result"]["ttlMs"], 0);
    assert_eq!(r["result"]["tools"][0]["annotations"], json!({"idempotentHint": true, "readOnlyHint": true}));
}

#[tokio::test]
async fn the_handler_sees_the_identity_and_the_peer() {
    let s = serve(None).await;
    let r: Value = s.modern("/mcp", 1, "tools/call", json!({"name": "who"}), &[("mcp-name", "who")]).await.json().await.unwrap();
    assert_eq!(r["result"]["content"][0]["text"], "alice@127.0.0.1 v2026-07-28");
    let (sid, _) = s.handshake().await;
    let r = s
        .post("/mcp", json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "who"}}), &[("mcp-session-id", &sid)])
        .await;
    assert_eq!(first_data(r).await["result"]["content"][0]["text"], "alice@127.0.0.1 v2025-06-18");
}

#[tokio::test]
async fn every_listening_session_is_notified() {
    let s = serve(None).await;
    let listen = |id| s.modern("/mcp", id, "subscriptions/listen", json!({"notifications": {"toolsListChanged": true}}), &[]);
    let mut first = Frames::new(listen(40).await);
    let mut second = Frames::new(listen(41).await);
    let ack = first.next().await.unwrap();
    assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
    assert_eq!(ack["params"]["notifications"], json!({"toolsListChanged": true}));
    second.next().await.unwrap();
    assert_eq!(s.notifier.listen_streams(), 2);
    s.notifier.tool_catalog_changed();
    for (frames, id) in [(&mut first, 40), (&mut second, 41)] {
        let event = frames.next().await.unwrap();
        assert_eq!(
            event,
            json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed",
                   "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": id}}})
        );
    }
    // A graceful close ends each stream with its result.
    s.notifier.close_listen_streams();
    let result = first.next().await.unwrap();
    assert_eq!(result["id"], 40);
    assert_eq!(result["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"], 40);
    assert_eq!(result["result"]["resultType"], "complete");
}

#[tokio::test]
async fn every_handshake_session_is_notified_on_its_standalone_stream() {
    let s = serve(None).await;
    let (one, _) = s.handshake().await;
    let (two, _) = s.handshake().await;
    assert_eq!(s.notifier.tracked_sessions(), 2);
    let open = |sid: String| {
        let http = s.http.clone();
        let url = format!("{}/mcp", s.base);
        async move {
            let r = http.get(url).header("accept", "text/event-stream").header("mcp-session-id", sid).send().await.unwrap();
            assert_eq!(r.status(), 200);
            Frames::new(r)
        }
    };
    let mut a = open(one.clone()).await;
    let mut b = open(two.clone()).await;
    // The GET handler has registered the stream once headers are back.
    s.notifier.tool_catalog_changed();
    for frames in [&mut a, &mut b] {
        assert_eq!(frames.next().await.unwrap(), json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}));
    }
    // DELETE ends the session, its stream, and its tracking.
    let r = s.http.delete(format!("{}/mcp", s.base)).header("mcp-session-id", &one).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(a.next().await, None);
    assert_eq!(s.notifier.tracked_sessions(), 1);
    let r = s.post("/mcp", json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}), &[("mcp-session-id", &one)]).await;
    assert_eq!(r.status(), 404);
    // The manager forgot the session on DELETE: no tombstone, no header.
    assert!(r.headers().get("mcp-session-id").is_none());
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"]["message"], "Session not found");
}

#[tokio::test]
async fn an_idle_session_is_reaped() {
    let s = serve(Some(Duration::from_millis(300))).await;
    let (sid, _) = s.handshake().await;
    let ping = || s.post("/mcp", json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}), &[("mcp-session-id", &sid)]);
    // Activity pushes the deadline out.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(ping().await.status(), 200);
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    let r = ping().await;
    assert_eq!(r.status(), 404);
    assert_eq!(
        r.text().await.unwrap(),
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Session not found"}}"#
    );
}

#[tokio::test]
async fn a_cancelled_request_is_answered_with_request_cancelled() {
    let s = serve(None).await;
    let (sid, _) = s.handshake().await;
    let slow = s.post("/mcp", json!({"jsonrpc": "2.0", "id": "c1", "method": "tools/call", "params": {"name": "slow"}}), &[("mcp-session-id", &sid)]);
    let cancel = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        s.post(
            "/mcp",
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "c1"}}),
            &[("mcp-session-id", &sid)],
        )
        .await
    };
    let (slow, cancelled) = tokio::join!(slow, cancel);
    assert_eq!(cancelled.status(), 202);
    assert_eq!(
        first_data(slow).await,
        json!({"jsonrpc": "2.0", "id": "c1", "error": {"code": -32800, "message": "Request cancelled"}})
    );
}

#[tokio::test]
async fn mcp_param_headers_are_checked_against_the_arguments() {
    let s = serve(None).await;
    let call = |region: &'static str| {
        s.modern("/mcp", 1, "tools/call", json!({"name": "routed", "arguments": {"region": "eu"}}), &[("mcp-name", "routed"), ("mcp-param-region", region)])
    };
    let r = call("us").await;
    assert_eq!(r.status(), 400);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"], json!({"code": -32020, "message": "Mcp-Param-Region header does not match the request body's 'region' argument"}));
    let r = call("eu").await;
    assert_eq!(r.status(), 200);
    let r = s.modern("/mcp", 2, "tools/call", json!({"name": "routed", "arguments": {"region": "eu"}}), &[("mcp-name", "routed")]).await;
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"]["message"], "Mcp-Param-Region header is missing but the request body's 'region' argument is present");
}

#[tokio::test]
async fn the_modern_wire_maps_error_codes_to_statuses() {
    let s = serve(None).await;
    let r = s.modern("/mcp", 1, "ping", json!({}), &[]).await;
    assert_eq!(r.status(), 404);
    assert_eq!(
        r.text().await.unwrap(),
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found","data":"ping"}}"#
    );
    // A notification POST is acknowledged and dropped (mcp 2.2.0)...
    let r = s.post("/mcp", json!({"jsonrpc": "2.0", "method": "x"}), &[("mcp-protocol-version", MODERN)]).await;
    assert_eq!(r.status(), 202);
    assert_eq!(r.text().await.unwrap(), "");
    // ...unless it is not one, or names a version this entry does not serve.
    let r = s.post("/mcp", json!({"jsonrpc": "2.0", "method": 5}), &[("mcp-protocol-version", MODERN)]).await;
    assert_eq!(r.status(), 400);
    assert_eq!(
        r.text().await.unwrap(),
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Body must be a single JSON-RPC request or notification object"}}"#
    );
    let r = s.post("/mcp", json!({"jsonrpc": "2.0", "method": "x"}), &[("mcp-protocol-version", "2030-01-01")]).await;
    assert_eq!(r.status(), 400);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["id"], Value::Null);
    assert_eq!(body["error"]["code"], -32022);
    assert_eq!(body["error"]["data"], json!({"supported": [MODERN], "requested": "2030-01-01"}));
    let r = s.http.get(format!("{}/mcp", s.base)).header("mcp-protocol-version", MODERN).send().await.unwrap();
    assert_eq!(r.status(), 405);
    assert_eq!(r.headers()["allow"], "POST");
}

fn ping(s: &Server, sid: &str) -> impl Future<Output = reqwest::Response> + 'static {
    s.post("/mcp", json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}), &[("mcp-session-id", sid)])
}

fn init(s: &Server) -> impl Future<Output = reqwest::Response> + 'static {
    s.post(
        "/mcp",
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "wire", "version": "1"}}}),
        &[],
    )
}

#[tokio::test]
async fn the_session_limit_refuses_new_sessions_with_503() {
    assert_eq!(McpConfig::stateful("/mcp").max_sessions, Some(mcp::DEFAULT_MAX_SESSIONS));
    assert_eq!(mcp::DEFAULT_MAX_SESSIONS, 10_000);
    let s = serve_with(|c| c.max_sessions = Some(2)).await;
    let (one, _) = s.handshake().await;
    let (_two, _) = s.handshake().await;
    let r = init(&s).await;
    assert_eq!(r.status(), 503);
    assert!(r.headers().get("mcp-session-id").is_none());
    assert_eq!(r.headers()["content-type"], "application/json");
    assert_eq!(
        r.text().await.unwrap(),
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Too many open sessions"}}"#
    );
    // Existing sessions are unaffected.
    assert_eq!(ping(&s, &one).await.status(), 200);
    // Room frees up as sessions end.
    let r = s.http.delete(format!("{}/mcp", s.base)).header("mcp-session-id", &one).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(init(&s).await.status(), 200);
    assert_eq!(init(&s).await.status(), 503);
    // The modern wire holds no sessions and is never limited.
    assert_eq!(s.modern("/mcp", 1, "tools/list", json!({}), &[]).await.status(), 200);
    // `None` removes the limit; stateless mounts have none.
    let s = serve_with(|c| c.max_sessions = None).await;
    for _ in 0..3 {
        s.handshake().await;
    }
}

#[tokio::test]
async fn a_refused_opening_request_is_discarded() {
    let s = serve_with(|c| c.max_sessions = Some(1)).await;
    // A POST without a session id that is not an initialize opens nothing:
    // the id it is answered with is forgotten at once...
    let r = s.post("/mcp", json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}), &[]).await;
    assert_eq!(r.status(), 400);
    let refused = r.headers()["mcp-session-id"].to_str().unwrap().to_string();
    let r = ping(&s, &refused).await;
    assert_eq!(r.status(), 404);
    assert!(r.headers().get("mcp-session-id").is_none());
    assert_eq!(
        r.text().await.unwrap(),
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Session not found"}}"#
    );
    let r = s.http.get(format!("{}/mcp", s.base)).header("accept", "text/event-stream").send().await.unwrap();
    assert_eq!(r.status(), 400);
    // ...and takes no room under the limit.
    let (sid, _) = s.handshake().await;
    assert_eq!(ping(&s, &sid).await.status(), 200);
}

#[tokio::test]
async fn an_open_stream_holds_an_idle_session() {
    let s = serve(Some(Duration::from_millis(300))).await;
    let (sid, _) = s.handshake().await;
    let r = s.http.get(format!("{}/mcp", s.base)).header("accept", "text/event-stream").header("mcp-session-id", &sid).send().await.unwrap();
    assert_eq!(r.status(), 200);
    // The countdown is suspended while the GET stream is open...
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(ping(&s, &sid).await.status(), 200);
    // ...and a long request in flight holds it too.
    drop(r);
    let slow = s.post("/mcp", json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "slow"}}), &[("mcp-session-id", &sid)]);
    let slow = tokio::spawn(async move {
        let r = slow.await;
        let mut frames = Frames::new(r);
        tokio::time::timeout(Duration::from_millis(900), frames.next()).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(ping(&s, &sid).await.status(), 200);
    slow.await.unwrap();
    // It restarts once the last request completes.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let r = ping(&s, &sid).await;
    assert_eq!(r.status(), 404);
    assert_eq!(
        r.text().await.unwrap(),
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Session not found"}}"#
    );
}

#[tokio::test]
async fn every_method_body_is_capped() {
    let s = serve_with(|c| c.max_request_body_size = 16).await;
    let sid = "0123456789abcdef";
    let big = "x".repeat(64);
    for method in [http::Method::GET, http::Method::DELETE, http::Method::PUT] {
        let r = s
            .http
            .request(method.clone(), format!("{}/mcp", s.base))
            .header("mcp-session-id", sid)
            .body(big.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 413, "{method}");
        assert_eq!(r.text().await.unwrap(), "Request body too large");
    }
}

#[tokio::test]
async fn an_oversized_delete_still_untracks_the_session() {
    let s = serve_with(|c| c.max_request_body_size = 512).await;
    let (sid, _) = s.handshake().await;
    assert_eq!(s.notifier.tracked_sessions(), 1);
    let r = s.http.delete(format!("{}/mcp", s.base)).header("mcp-session-id", &sid).body("x".repeat(1024)).send().await.unwrap();
    assert_eq!(r.status(), 413);
    // `SessionReaper` runs before the body cap; the session itself lives on.
    assert_eq!(s.notifier.tracked_sessions(), 0);
    assert_eq!(ping(&s, &sid).await.status(), 200);
}
