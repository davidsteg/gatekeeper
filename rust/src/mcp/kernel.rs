//! Per-message dispatch (`mcp.server.runner.ServerRunner`): the version
//! gate, the init gate, the built-in handlers and the outbound shaping.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Map, Value};
use tokio::sync::mpsc;

use super::handler::{McpHandler, RequestContext, ServerInfo};
use super::notifier::CatalogNotifier;
use super::schema::{self, SurfaceError, SPEC_CLIENT_METHODS, SPEC_CLIENT_NOTIFICATION_METHODS};
use super::types::{
    is_handshake_version, is_modern_version, ErrorData, McpError, INTERNAL_ERROR, LATEST_HANDSHAKE_VERSION,
    MODERN_PROTOCOL_VERSIONS, SERVER_INFO_META_KEY,
};

/// Where request-scoped notifications go (the request's own response
/// stream), or `None` when the request has no such stream.
pub(crate) type Sink = Option<mpsc::Sender<Value>>;

pub(crate) async fn notify(sink: &Sink, message: Value) {
    if let Some(tx) = sink {
        if tx.send(message).await.is_err() {
            tracing::debug!("dropped a notification: response stream closed");
        }
    }
}

/// Per-connection protocol state (`mcp.server.connection.Connection`).
pub(crate) struct Conn {
    version: Mutex<String>,
    client_params: Mutex<Option<Value>>,
    initialized: AtomicBool,
}

impl Conn {
    /// A handshake-driven connection: the gate opens on `initialize`.
    pub(crate) fn for_loop() -> Self {
        Conn {
            version: Mutex::new(LATEST_HANDSHAKE_VERSION.to_string()),
            client_params: Mutex::new(None),
            initialized: AtomicBool::new(false),
        }
    }

    /// A born-ready connection at a fixed version (stateless mount, the
    /// 2026-07-28 single exchange).
    pub(crate) fn born_ready(version: &str) -> Self {
        Conn {
            version: Mutex::new(version.to_string()),
            client_params: Mutex::new(None),
            initialized: AtomicBool::new(true),
        }
    }

    pub(crate) fn version(&self) -> String {
        self.version.lock().clone()
    }

    fn initialize_accepted(&self) -> bool {
        self.client_params.lock().is_some() || self.initialized.load(Ordering::SeqCst)
    }
}

pub(crate) struct Kernel {
    pub(crate) handler: Arc<dyn McpHandler>,
    pub(crate) notifier: Option<CatalogNotifier>,
}

fn negotiate(params: Option<&Map<String, Value>>) -> String {
    let requested = params.and_then(|p| p.get("protocolVersion")).and_then(Value::as_str).unwrap_or("");
    if is_handshake_version(requested) {
        requested.to_string()
    } else {
        LATEST_HANDSHAKE_VERSION.to_string()
    }
}

impl Kernel {
    fn info(&self) -> ServerInfo {
        self.handler.server_info()
    }

    /// Whether the mount announces `tools.listChanged`: at 2026-07-28 it is
    /// whether `subscriptions/listen` is served, at the handshake era the
    /// `NotificationOptions(tools_changed=True)` that goes with it.
    fn list_changed(&self) -> bool {
        self.notifier.is_some()
    }

    fn initialize_result(&self, negotiated: &str) -> Value {
        let info = self.info();
        let mut tools = Map::new();
        tools.insert("listChanged".into(), Value::Bool(self.list_changed()));
        let mut caps = Map::new();
        caps.insert("experimental".into(), Value::Object(Map::new()));
        caps.insert("tools".into(), Value::Object(tools));
        let mut m = Map::new();
        m.insert("capabilities".into(), Value::Object(caps));
        if let Some(i) = &info.instructions {
            m.insert("instructions".into(), Value::from(i.clone()));
        }
        m.insert("protocolVersion".into(), Value::from(negotiated));
        m.insert("serverInfo".into(), info.implementation());
        Value::Object(m)
    }

    fn discover_result(&self) -> Value {
        let info = self.info();
        let mut tools = Map::new();
        tools.insert("listChanged".into(), Value::Bool(self.list_changed()));
        let mut caps = Map::new();
        caps.insert("tools".into(), Value::Object(tools));
        let mut m = Map::new();
        m.insert("ttlMs".into(), Value::from(0));
        m.insert("cacheScope".into(), Value::from("private"));
        m.insert("supportedVersions".into(), Value::from(MODERN_PROTOCOL_VERSIONS.to_vec()));
        m.insert("capabilities".into(), Value::Object(caps));
        if let Some(i) = &info.instructions {
            m.insert("instructions".into(), Value::from(i.clone()));
        }
        m.insert("resultType".into(), Value::from("complete"));
        Value::Object(m)
    }

    fn has_handler(&self, method: &str) -> bool {
        match method {
            "ping" | "server/discover" | "tools/list" | "tools/call" => true,
            "subscriptions/listen" => self.notifier.is_some(),
            _ => false,
        }
    }

    /// `_serialize`: the per-version sieve, `resultType`, the serverInfo stamp.
    fn serialize(&self, method: &str, version: &str, result: Value) -> Result<Value, McpError> {
        let mut dumped = if SPEC_CLIENT_METHODS.contains(&method) {
            schema::serialize_server_result(method, version, &result).map_err(|()| {
                tracing::error!("handler for {method:?} returned an invalid result");
                McpError::rpc(INTERNAL_ERROR, "Handler returned an invalid result")
            })?
        } else {
            result
        };
        if is_modern_version(version) {
            if let Value::Object(m) = &mut dumped {
                if m.get("resultType").is_none_or(Value::is_null) {
                    m.insert("resultType".into(), Value::from("complete"));
                }
                let stamp = self.info().implementation();
                match m.get_mut("_meta") {
                    None | Some(Value::Null) => {
                        let mut meta = Map::new();
                        meta.insert(SERVER_INFO_META_KEY.into(), stamp);
                        m.insert("_meta".into(), Value::Object(meta));
                    }
                    Some(Value::Object(meta)) => {
                        if meta.get(SERVER_INFO_META_KEY).is_none_or(Value::is_null) {
                            meta.insert(SERVER_INFO_META_KEY.into(), stamp);
                        }
                    }
                    Some(_) => {}
                }
            }
        }
        Ok(dumped)
    }

    /// Serve one request. `ctx.method` / `ctx.request_id` name it.
    pub(crate) async fn on_request(
        &self,
        conn: &Conn,
        ctx: &RequestContext,
        params: Option<&Map<String, Value>>,
        sink: &Sink,
    ) -> Result<Value, McpError> {
        let method = ctx.method.as_str();
        let version = conn.version();
        if SPEC_CLIENT_METHODS.contains(&method) {
            match schema::validate_client_request(method, &version, params) {
                Ok(()) => {}
                Err(SurfaceError::NotOnSurface) => return Err(McpError::Rpc(ErrorData::method_not_found(method))),
                Err(SurfaceError::Invalid) => return Err(McpError::Rpc(ErrorData::invalid_params())),
            }
        }
        if method == "initialize" {
            let negotiated = negotiate(params);
            let result = self.serialize(method, &version, self.initialize_result(&negotiated))?;
            // Commit only on success.
            *conn.client_params.lock() = Some(params.map(|p| Value::Object(p.clone())).unwrap_or(Value::Null));
            *conn.version.lock() = negotiated;
            return Ok(result);
        }
        if !self.has_handler(method) {
            return Err(McpError::Rpc(ErrorData::method_not_found(method)));
        }
        if !conn.initialize_accepted() && method != "ping" {
            return Err(McpError::Rpc(ErrorData::invalid_params()));
        }
        let result = match method {
            "ping" => Value::Object(Map::new()),
            "server/discover" => self.discover_result(),
            "tools/list" => self.handler.list_tools(ctx).await?.dump(),
            "tools/call" => {
                let p = params.cloned().unwrap_or_default();
                let name = p.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
                let args = p.get("arguments").and_then(Value::as_object).cloned().unwrap_or_default();
                self.handler.call_tool(ctx, &name, args).await?.dump()
            }
            "subscriptions/listen" => {
                let notifier = self.notifier.as_ref().expect("has_handler checked");
                let filter = schema::subscription_filter(params);
                notifier.listen(ctx.request_id.as_ref(), &filter, sink).await?
            }
            _ => unreachable!("has_handler checked"),
        };
        self.serialize(method, &version, result)
    }

    /// Handle one notification. Never fails: a bad one is dropped.
    pub(crate) async fn on_notify(&self, conn: &Conn, ctx: &RequestContext, params: Option<&Map<String, Value>>) {
        let method = ctx.method.as_str();
        let version = conn.version();
        if SPEC_CLIENT_NOTIFICATION_METHODS.contains(&method) {
            match schema::validate_client_notification(method, &version, params) {
                Ok(()) => {}
                Err(SurfaceError::NotOnSurface) => {
                    tracing::debug!("dropped {method:?}: not defined at {version}");
                    return;
                }
                Err(SurfaceError::Invalid) => {
                    tracing::warn!("dropped {method:?}: malformed params");
                    return;
                }
            }
        }
        if method == "notifications/initialized" {
            conn.initialized.store(true, Ordering::SeqCst);
        } else if !conn.initialize_accepted() {
            tracing::debug!("dropped {method}: received before initialization");
            return;
        }
        if method == "notifications/initialized" {
            self.handler.on_initialized(ctx).await;
        } else {
            tracing::debug!("no handler for notification {method}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::handler::{CallToolResult, ListToolsResult};
    use async_trait::async_trait;
    use serde_json::json;

    struct Echo;

    #[async_trait]
    impl McpHandler for Echo {
        fn server_info(&self) -> ServerInfo {
            ServerInfo::new("echo", "1.0").with_instructions("hi")
        }
        async fn list_tools(&self, _ctx: &RequestContext) -> Result<ListToolsResult, McpError> {
            Ok(ListToolsResult::new(vec![json!({"name": "a", "inputSchema": {"type": "object"}, "execution": {"taskSupport": "forbidden"}})]))
        }
        async fn call_tool(&self, _ctx: &RequestContext, name: &str, _a: Map<String, Value>) -> Result<CallToolResult, McpError> {
            match name {
                "bad" => Ok(CallToolResult { content: vec![json!({"type": "text"})], ..Default::default() }),
                "boom" => Err(McpError::internal("boom")),
                _ => Ok(CallToolResult::text(name, false)),
            }
        }
    }

    fn kernel(notifier: bool) -> Kernel {
        Kernel { handler: Arc::new(Echo), notifier: notifier.then(CatalogNotifier::new) }
    }

    async fn req(k: &Kernel, conn: &Conn, method: &str, params: Value) -> Result<Value, McpError> {
        let mut ctx = RequestContext::detached(method, conn.version());
        ctx.request_id = Some(json!(1));
        let p = params.as_object().cloned();
        k.on_request(conn, &ctx, p.as_ref(), &None).await
    }

    #[tokio::test]
    async fn initialize_negotiates_and_opens_the_gate() {
        let k = kernel(true);
        let conn = Conn::for_loop();
        assert_eq!(req(&k, &conn, "tools/list", json!({})).await.unwrap_err(), McpError::Rpc(ErrorData::invalid_params()));
        assert_eq!(req(&k, &conn, "ping", Value::Null).await.unwrap(), json!({}));
        let init = req(&k, &conn, "initialize", json!({"protocolVersion": "1999-01-01", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}}))
            .await
            .unwrap();
        assert_eq!(
            init,
            json!({"capabilities": {"experimental": {}, "tools": {"listChanged": true}}, "instructions": "hi",
                   "protocolVersion": "2025-11-25", "serverInfo": {"name": "echo", "version": "1.0"}})
        );
        assert_eq!(conn.version(), "2025-11-25");
        let tools = req(&k, &conn, "tools/list", json!({})).await.unwrap();
        assert_eq!(tools, json!({"tools": [{"execution": {"taskSupport": "forbidden"}, "inputSchema": {"type": "object"}, "name": "a"}]}));
    }

    #[tokio::test]
    async fn modern_results_are_stamped_and_typed() {
        let k = kernel(false);
        let conn = Conn::born_ready("2026-07-28");
        let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}});
        let d = req(&k, &conn, "server/discover", json!({"_meta": meta})).await.unwrap();
        assert_eq!(
            d,
            json!({"_meta": {"io.modelcontextprotocol/serverInfo": {"name": "echo", "version": "1.0"}}, "cacheScope": "private",
                   "capabilities": {"tools": {"listChanged": false}}, "instructions": "hi", "resultType": "complete",
                   "supportedVersions": ["2026-07-28"], "ttlMs": 0})
        );
        let c = req(&k, &conn, "tools/call", json!({"_meta": meta, "name": "x"})).await.unwrap();
        assert_eq!(c["resultType"], "complete");
        assert_eq!(c["isError"], false);
        assert_eq!(req(&k, &conn, "ping", json!({"_meta": meta})).await.unwrap_err(), McpError::Rpc(ErrorData::method_not_found("ping")));
        assert_eq!(
            req(&k, &conn, "subscriptions/listen", json!({"_meta": meta, "notifications": {}})).await.unwrap_err(),
            McpError::Rpc(ErrorData::method_not_found("subscriptions/listen"))
        );
        assert_eq!(
            req(&k, &conn, "tools/call", json!({"_meta": meta, "name": "bad"})).await.unwrap_err(),
            McpError::rpc(INTERNAL_ERROR, "Handler returned an invalid result")
        );
        assert_eq!(req(&k, &conn, "tools/call", json!({"_meta": meta, "name": "boom"})).await.unwrap_err(), McpError::internal("boom"));
    }

    #[tokio::test]
    async fn notifications_open_the_gate() {
        let k = kernel(false);
        let conn = Conn::for_loop();
        let ctx = RequestContext::detached("notifications/initialized", conn.version());
        k.on_notify(&conn, &ctx, None).await;
        assert!(req(&k, &conn, "tools/list", json!({})).await.is_ok());
    }
}
