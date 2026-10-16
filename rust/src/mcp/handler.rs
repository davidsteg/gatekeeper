//! What an application implements to be served: [`McpHandler`], the
//! per-request [`RequestContext`] and the result types.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use http::{Extensions, HeaderMap};
use serde_json::{Map, Value};

use super::types::McpError;

/// Server identity (`Implementation` plus the `instructions` string).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub website_url: Option<String>,
    /// `Icon` objects as JSON.
    pub icons: Option<Vec<Value>>,
    pub instructions: Option<String>,
}

impl ServerInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        ServerInfo { name: name.into(), version: version.into(), ..Default::default() }
    }

    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// The `Implementation` dump (`serverInfo`, and the 2026-era
    /// `io.modelcontextprotocol/serverInfo` result stamp).
    pub fn implementation(&self) -> Value {
        // `Implementation`'s field order.
        let mut m = Map::new();
        if let Some(d) = &self.description {
            m.insert("description".into(), Value::from(d.clone()));
        }
        if let Some(i) = &self.icons {
            m.insert("icons".into(), Value::Array(i.clone()));
        }
        m.insert("name".into(), Value::from(self.name.clone()));
        if let Some(t) = &self.title {
            m.insert("title".into(), Value::from(t.clone()));
        }
        m.insert("version".into(), Value::from(self.version.clone()));
        if let Some(w) = &self.website_url {
            m.insert("websiteUrl".into(), Value::from(w.clone()));
        }
        Value::Object(m)
    }
}

/// `ListToolsResult`. `tools` are `Tool` objects as JSON; the per-version
/// sieve drops whatever the negotiated schema does not define.
#[derive(Debug, Clone, PartialEq)]
pub struct ListToolsResult {
    pub tools: Vec<Value>,
    pub next_cursor: Option<String>,
    /// `"private"` (the SDK default) or `"public"`; 2026-07-28 only.
    pub cache_scope: String,
    pub ttl_ms: i64,
    pub meta: Option<Map<String, Value>>,
}

impl ListToolsResult {
    pub fn new(tools: Vec<Value>) -> Self {
        ListToolsResult { tools, next_cursor: None, cache_scope: "private".into(), ttl_ms: 0, meta: None }
    }

    pub(crate) fn dump(&self) -> Value {
        let mut m = Map::new();
        if let Some(meta) = &self.meta {
            m.insert("_meta".into(), Value::Object(meta.clone()));
        }
        m.insert("ttlMs".into(), Value::from(self.ttl_ms));
        m.insert("cacheScope".into(), Value::from(self.cache_scope.clone()));
        if let Some(c) = &self.next_cursor {
            m.insert("nextCursor".into(), Value::from(c.clone()));
        }
        m.insert("tools".into(), Value::Array(self.tools.clone()));
        m.insert("resultType".into(), Value::from("complete"));
        Value::Object(m)
    }
}

/// `CallToolResult`. `content` blocks are JSON (`{"type": "text", ...}`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CallToolResult {
    pub content: Vec<Value>,
    pub is_error: bool,
    pub structured_content: Option<Value>,
    pub meta: Option<Map<String, Value>>,
}

impl CallToolResult {
    /// One text block.
    pub fn text(text: impl Into<String>, is_error: bool) -> Self {
        let mut block = Map::new();
        block.insert("type".into(), Value::from("text"));
        block.insert("text".into(), Value::from(text.into()));
        CallToolResult { content: vec![Value::Object(block)], is_error, ..Default::default() }
    }

    pub(crate) fn dump(&self) -> Value {
        let mut m = Map::new();
        if let Some(meta) = &self.meta {
            m.insert("_meta".into(), Value::Object(meta.clone()));
        }
        m.insert("content".into(), Value::Array(self.content.clone()));
        if let Some(s) = &self.structured_content {
            if !s.is_null() {
                m.insert("structuredContent".into(), s.clone());
            }
        }
        m.insert("isError".into(), Value::Bool(self.is_error));
        m.insert("resultType".into(), Value::from("complete"));
        Value::Object(m)
    }
}

/// Where a server-to-client message for one session goes: the standalone
/// SSE stream a handshake-era client opened with `GET`.
pub trait SessionChannel: Send + Sync {
    /// Queue `notifications/tools/list_changed`. A session without an open
    /// stream drops it silently (`Ok`); `Err` means the session is gone
    /// for good (terminated) and is not worth notifying again.
    fn send_tool_list_changed(&self) -> Result<(), ()>;
}

/// Everything a handler may want to know about the request it serves.
#[derive(Clone)]
pub struct RequestContext {
    /// The HTTP request's extensions: authentication middleware puts the
    /// caller's identity here.
    pub extensions: Extensions,
    pub headers: HeaderMap,
    /// The TCP peer (from axum's `ConnectInfo`), when the server was
    /// started with connect info.
    pub peer: Option<SocketAddr>,
    /// The transport's session id (stateful mount, handshake era only).
    pub session_id: Option<String>,
    /// The JSON-RPC request id; `None` for a notification.
    pub request_id: Option<Value>,
    pub method: String,
    /// The connection's protocol version.
    pub protocol_version: String,
    pub(crate) channel: Option<Arc<dyn SessionChannel>>,
}

impl RequestContext {
    /// A context not attached to any transport (tests, direct calls).
    pub fn detached(method: impl Into<String>, protocol_version: impl Into<String>) -> Self {
        RequestContext {
            extensions: Extensions::new(),
            headers: HeaderMap::new(),
            peer: None,
            session_id: None,
            request_id: None,
            method: method.into(),
            protocol_version: protocol_version.into(),
            channel: None,
        }
    }

    /// Attach a session channel (what [`super::CatalogNotifier::track`]
    /// remembers). Mostly for tests; the transport sets it itself.
    pub fn with_channel(mut self, channel: Arc<dyn SessionChannel>) -> Self {
        self.channel = Some(channel);
        self
    }

    /// The `Mcp-Session-Id` header the client sent, if any.
    pub fn session_header(&self) -> Option<&str> {
        self.headers.get(super::types::MCP_SESSION_ID_HEADER).and_then(|v| v.to_str().ok()).filter(|s| !s.is_empty())
    }
}

/// The application side of an MCP mount.
#[async_trait]
pub trait McpHandler: Send + Sync + 'static {
    fn server_info(&self) -> ServerInfo;

    async fn list_tools(&self, ctx: &RequestContext) -> Result<ListToolsResult, McpError>;

    async fn call_tool(
        &self,
        ctx: &RequestContext,
        name: &str,
        args: Map<String, Value>,
    ) -> Result<CallToolResult, McpError>;

    /// `notifications/initialized` arrived (handshake era).
    async fn on_initialized(&self, _ctx: &RequestContext) {}
}
