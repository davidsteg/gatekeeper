//! A generic MCP server over Streamable HTTP (axum + tokio), standing in
//! for the Python SDK's `StreamableHTTPSessionManager` stack plus
//! gatekeeper's `notifications.py`.
//!
//! Both protocol eras are served on one path:
//!
//! * **Handshake era** (2024-11-05 .. 2025-11-25): `initialize`,
//!   `Mcp-Session-Id`, a standalone `GET` SSE stream, `DELETE`. On a
//!   stateful mount sessions are retained (idle timeout
//!   [`SESSION_IDLE_TIMEOUT_SECONDS`]); a stateless mount serves every
//!   request on a fresh, born-ready connection.
//! * **2026-07-28**: a request whose `MCP-Protocol-Version` header is not a
//!   handshake version is one self-contained POST (no session), with
//!   `server/discover` and `subscriptions/listen`.
//!
//! The application implements [`McpHandler`]; [`router`] returns the axum
//! `Router` for one mount. Nothing here knows about gatekeeper.

mod handler;
mod inbound;
mod jsonrpc;
mod kernel;
mod modern;
mod notifier;
mod schema;
mod sse;
mod transport;
mod types;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;

pub use handler::{CallToolResult, ListToolsResult, McpHandler, RequestContext, ServerInfo, SessionChannel};
pub use inbound::{
    classify_inbound_request, decode_header_value, encode_header_value, error_code_http_status,
    find_duplicated_routing_header, find_invalid_x_mcp_header, mcp_param_headers, unsupported_protocol_version_rejection,
    validate_mcp_param_headers,
    x_mcp_header_map, ModernRoute,
};
pub use jsonrpc::{parse_message, Message};
pub use notifier::{
    CatalogNotifier, ServerEvent, MAX_BUFFERED_EVENTS, MAX_SUBSCRIPTIONS, MAX_TRACKED_SESSIONS, SESSION_ID_HEADER,
};
pub use types::*;

/// How long a handshake-era session may sit idle before it is reaped
/// (`gatekeeper.server.SESSION_IDLE_TIMEOUT_SECONDS`).
pub const SESSION_IDLE_TIMEOUT_SECONDS: u64 = 3600;
/// The SDK's default request body cap (`DEFAULT_MAX_REQUEST_BODY_SIZE`).
pub const DEFAULT_MAX_REQUEST_BODY_SIZE: usize = 4 * 1024 * 1024;
/// The SDK's default cap on concurrent stateful sessions per mount
/// (`DEFAULT_MAX_SESSIONS`); gatekeeper keeps it.
pub const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// DNS-rebinding protection (`TransportSecuritySettings`). The POST
/// content-type check runs regardless.
#[derive(Debug, Clone, Default)]
pub struct TransportSecurity {
    pub enable_dns_rebinding_protection: bool,
    /// Exact `Host` values, or `host:*` for any port.
    pub allowed_hosts: Vec<String>,
    /// Exact `Origin` values, or `scheme://host:*` for any port.
    pub allowed_origins: Vec<String>,
}

/// One MCP mount.
#[derive(Clone)]
pub struct McpConfig {
    /// The route path, e.g. `/mcp`.
    pub path: String,
    /// `stateless_http`: no session retention, no standalone stream.
    pub stateless: bool,
    /// Stateful mounts only.
    pub session_idle_timeout: Option<Duration>,
    pub max_request_body_size: usize,
    /// Stateful mounts only: while this many sessions are open, a request
    /// that would open another is answered 503. `None` removes the limit.
    pub max_sessions: Option<usize>,
    /// Serves `subscriptions/listen`, announces `tools.listChanged` in both
    /// eras and is told about `DELETE`d sessions.
    pub notifier: Option<CatalogNotifier>,
    pub security: TransportSecurity,
}

impl McpConfig {
    /// A stateful mount with gatekeeper's idle timeout.
    pub fn stateful(path: impl Into<String>) -> Self {
        McpConfig {
            path: path.into(),
            stateless: false,
            session_idle_timeout: Some(Duration::from_secs(SESSION_IDLE_TIMEOUT_SECONDS)),
            max_request_body_size: DEFAULT_MAX_REQUEST_BODY_SIZE,
            max_sessions: Some(DEFAULT_MAX_SESSIONS),
            notifier: None,
            security: TransportSecurity::default(),
        }
    }

    pub fn stateless(path: impl Into<String>) -> Self {
        McpConfig { stateless: true, session_idle_timeout: None, ..McpConfig::stateful(path) }
    }

    pub fn with_notifier(mut self, notifier: CatalogNotifier) -> Self {
        self.notifier = Some(notifier);
        self
    }
}

pub(crate) struct Mount {
    pub(crate) kernel: Arc<kernel::Kernel>,
    pub(crate) config: McpConfig,
    pub(crate) sessions: Arc<transport::SessionMap>,
}

/// The parts of one HTTP request the transports read.
pub(crate) struct Inbound {
    pub(crate) method: Method,
    pub(crate) headers: HeaderMap,
    pub(crate) extensions: http::Extensions,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) body: Bytes,
}

impl Inbound {
    /// First value of a header, latin-1 decoded (Starlette's `headers.get`).
    pub(crate) fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).map(latin1)
    }

    /// Every raw `(lowercase name, value)` pair, duplicates included.
    pub(crate) fn header_pairs(&self) -> Vec<(String, String)> {
        self.headers.iter().map(|(k, v)| (k.as_str().to_string(), latin1(v))).collect()
    }
}

pub(crate) fn latin1(v: &HeaderValue) -> String {
    v.as_bytes().iter().map(|&b| b as char).collect()
}

/// The router for one mount. Call inside the tokio runtime that will
/// serve it so the notifier binds to it; serve with
/// `into_make_service_with_connect_info::<SocketAddr>()` to fill
/// [`RequestContext::peer`].
pub fn router(handler: Arc<dyn McpHandler>, config: McpConfig) -> Router {
    if let Some(n) = &config.notifier {
        n.bind_current();
    }
    let mount = Arc::new(Mount {
        kernel: Arc::new(kernel::Kernel { handler, notifier: config.notifier.clone() }),
        sessions: Arc::new(transport::SessionMap::default()),
        config: config.clone(),
    });
    Router::new().route(&config.path, any(handle)).with_state(mount)
}

pub(crate) fn plain(status: u16, text: &'static str) -> Response {
    let mut r = Response::new(axum::body::Body::from(text));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r
}

async fn handle(State(mount): State<Arc<Mount>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    // `SessionReaper` (outside the SDK app, so before the body cap and the
    // era routing): a DELETE with a session id is the client saying it is
    // done; forget it before the transport sees the request.
    if parts.method == Method::DELETE {
        if let Some(n) = &mount.config.notifier {
            if let Some(id) = parts.headers.get(MCP_SESSION_ID_HEADER).map(latin1).filter(|s| !s.is_empty()) {
                n.forget(&id);
            }
        }
    }
    let limit = mount.config.max_request_body_size;
    // `RequestBodyLimitMiddleware` caps every HTTP method's body, not just
    // POST's.
    let declared = parts.headers.get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
    let body = match read_body(body, limit, declared.is_some_and(|n| n > limit as u64)).await {
        Some(bytes) => bytes,
        None => return plain(413, "Request body too large"),
    };
    let inbound = Inbound { method: parts.method, headers: parts.headers, extensions: parts.extensions, peer, body };

    // Era routing on the header alone: anything but a handshake version
    // (unknown values included) goes to the 2026-07-28 entry.
    if let Some(pv) = inbound.header(MCP_PROTOCOL_VERSION_HEADER) {
        if !is_handshake_version(&pv) {
            return modern::handle(&mount, inbound).await;
        }
    }
    if mount.config.stateless {
        transport::handle_stateless(&mount, inbound).await
    } else {
        transport::handle_stateful(&mount, inbound).await
    }
}

/// How much of an oversized body is read and discarded before the 413.
const DRAIN_CAP: usize = 64 * 1024 * 1024;

/// `RequestBodyLimitMiddleware`: the body, or `None` when it exceeds
/// `limit` (or its declared length already does).
///
/// PORT NOTE: the SDK answers 413 without reading the rest of the body;
/// here the remainder (up to [`DRAIN_CAP`]) is drained first, because
/// hyper closes a connection with unread request data and the client,
/// still writing, would see a reset instead of the 413.
async fn read_body(mut body: axum::body::Body, limit: usize, declared_too_large: bool) -> Option<Bytes> {
    let mut buf = bytes::BytesMut::new();
    let mut too_large = declared_too_large;
    let mut drained = 0usize;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        let Some(data) = frame.data_ref() else { continue };
        if !too_large && buf.len() + data.len() > limit {
            too_large = true;
            buf.clear();
        }
        if too_large {
            drained += data.len();
            if drained > DRAIN_CAP {
                break;
            }
        } else {
            buf.extend_from_slice(data);
        }
    }
    (!too_large).then(|| buf.freeze())
}

/// `TransportSecurityMiddleware.validate_request`.
pub(crate) fn security_check(security: &TransportSecurity, inbound: &Inbound) -> Option<Response> {
    if inbound.method == Method::POST {
        let ok = inbound.header("content-type").is_some_and(|ct| ct.to_lowercase().starts_with("application/json"));
        if !ok {
            return Some(plain(400, "Invalid Content-Type header"));
        }
    }
    if !security.enable_dns_rebinding_protection {
        return None;
    }
    let matches = |value: &str, allowed: &[String]| {
        allowed.iter().any(|a| a == value || a.strip_suffix(":*").is_some_and(|base| value.starts_with(&format!("{base}:"))))
    };
    let host = inbound.header("host").unwrap_or_default();
    if host.is_empty() || !matches(&host, &security.allowed_hosts) {
        tracing::warn!("Invalid Host header: {host}");
        return Some(plain(421, "Invalid Host header"));
    }
    if let Some(origin) = inbound.header("origin").filter(|o| !o.is_empty()) {
        if !matches(&origin, &security.allowed_origins) {
            tracing::warn!("Invalid Origin header: {origin}");
            return Some(plain(403, "Invalid Origin header"));
        }
    }
    None
}

/// `check_accept_headers`: `(has_json, has_sse)` with RFC 7231 wildcards.
pub(crate) fn check_accept(inbound: &Inbound) -> (bool, bool) {
    let accept = inbound.header("accept").unwrap_or_default();
    let types: Vec<String> =
        accept.split(',').map(|t| t.trim().split(';').next().unwrap_or("").trim().to_lowercase()).collect();
    let wildcard = types.iter().any(|t| t == "*/*");
    let json = wildcard || types.iter().any(|t| t == "application/json" || t == "application/*");
    let sse = wildcard || types.iter().any(|t| t == "text/event-stream" || t == "text/*");
    (json, sse)
}
