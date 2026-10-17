//! MCP protocol and HTTP layer (port of `server.py`, REQUIREMENTS.md §3).
//!
//! Authentication sits in front of everything as middleware; the routes it
//! guards are the agent MCP mount (`/mcp`), the admin MCP mount
//! (`/admin/mcp`, only with a writable store), health, metrics, release
//! notes, artifact downloads and -- with the UI enabled -- the console's
//! own router ([`crate::api::console_router`]).
//!
//! Request-scoped values the middleware hands on, as request extensions:
//!
//! * [`AuthIdentity`] -- the authenticated identity (Python's
//!   `scope["gatekeeper.identity"]`), set by the bearer middleware.
//! * [`ClientAddr`] -- the caller's address after reverse-proxy handling
//!   (Python's rewritten `scope["client"]`). Set by the proxy middlewares
//!   ([`uvicorn_proxy_headers`], [`real_ip`]); without them, read
//!   [`client_addr`], which falls back to the TCP peer.
//! * [`RequestScheme`] -- `http`/`https` after `X-Forwarded-Proto` from a
//!   trusted proxy (Python's `scope["scheme"]`), set by
//!   [`uvicorn_proxy_headers`].

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, RawQuery, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{json, Map, Value};

use crate::admin_server::AdminMcp;
use crate::admin_service::AdminService;
use crate::api::{console_router, ConsoleDeps};
use crate::artifacts::{artifact_download as decide_download, DownloadResponse, StreamError};
use crate::audit::AuditLog;
use crate::credentials::CredentialStore;
use crate::errors::{DenialReason, Denied};
use crate::execute::{ExecResult, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::identity::{hash_token_lookup, summarize, Identity, ADMIN_ROLE};
use crate::mcp::{
    self, CallToolResult, CatalogNotifier, ListToolsResult, McpConfig, McpError, McpHandler, RequestContext,
    ServerInfo, TransportSecurity, SESSION_ID_HEADER,
};
use crate::pending::PendingStore;
use crate::pyfmt::repr_str;
use crate::realip::TrustedProxies;
use crate::release_notes::{self, json_body};
use crate::service::{CallError, Service, SharedIdentities};
use crate::store::ConfigStore;
use crate::toolkit_proposals::ToolkitProposalStore;
use crate::ui::{APP_PREFIX, UI_COMPANION_PATHS, UI_PREFIX};

/// Only these paths are reachable without a token (NFR-3). They disclose
/// nothing about catalog or identities.
pub const PUBLIC_PATHS: [&str; 3] = ["/health/live", "/health/ready", "/health/startup"];

/// The agent-facing and admin MCP mount points. Isolation between them
/// (FR-2.8/2.9) is structural: two separate handlers sharing no tool
/// registry, mounted at these two fixed paths, with the auth middleware
/// role-gating each one so a token for one endpoint is simply rejected on
/// the other -- not filtered, rejected outright.
pub const MCP_PATH: &str = "/mcp";
pub const ADMIN_MCP_PATH: &str = "/admin/mcp";

/// The console JSON API's mount point (`api.API_PREFIX`).
pub const API_PREFIX: &str = crate::api::API_PREFIX;

/// How long a retained `/mcp` session may go without a request before the
/// transport is terminated and forgotten. Only handshake-era (2025-11-25
/// and earlier) clients hold sessions at all; see [`build_app`].
pub const SESSION_IDLE_TIMEOUT_SECONDS: u64 = mcp::SESSION_IDLE_TIMEOUT_SECONDS;

/// The agent-facing server's `instructions`.
pub const INSTRUCTIONS: &str = "Controlled access to host operations. Every tool performs one \
fixed action; there are no free-form commands. A timeout on a \
non-idempotent tool means 'outcome unknown' -- check the state \
instead of retrying.";

// -- Request extensions ---------------------------------------------------------

/// The identity the bearer middleware authenticated
/// (`_authctx.SCOPE_IDENTITY`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthIdentity(pub Identity);

/// The caller's address as gatekeeper attributes the request: the TCP peer,
/// or the forwarded address behind a trusted proxy. `host` is a string
/// because uvicorn copies whatever `X-Forwarded-For` names, address or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAddr {
    pub host: String,
    pub port: i64,
}

/// The request's scheme after `X-Forwarded-Proto` (`scope["scheme"]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestScheme(pub String);

/// The caller's address: [`ClientAddr`] when a proxy middleware set it,
/// otherwise the TCP peer (`ConnectInfo`).
pub fn client_addr(extensions: &http::Extensions) -> Option<ClientAddr> {
    if let Some(addr) = extensions.get::<ClientAddr>() {
        return Some(addr.clone());
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| ClientAddr { host: c.0.ip().to_string(), port: i64::from(c.0.port()) })
}

/// `_authctx.identity_from`: the authenticated identity of an MCP request.
pub fn identity_from(ctx: &RequestContext) -> Result<Identity, Denied> {
    match ctx.extensions.get::<AuthIdentity>() {
        Some(identity) => Ok(identity.0.clone()),
        // Can only occur if the middleware was bypassed. Then the safe
        // outcome is to show nothing at all.
        None => Err(Denied::new(DenialReason::UnknownToken, "No identity in the request scope")),
    }
}

/// `_client_of`: the caller's address from an MCP request context.
fn client_of(ctx: &RequestContext) -> Option<String> {
    if let Some(addr) = ctx.extensions.get::<ClientAddr>() {
        return Some(addr.host.clone());
    }
    ctx.peer.map(|p| p.ip().to_string())
}

/// Python's `str.isspace()` for one character.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// `_render`: what the agent reads of a result.
///
/// `external_untrusted` is deliberately not consulted: Python's `_render`
/// does not either -- the executors that set it frame their own output.
pub fn render(result: &ExecResult) -> String {
    let mut parts: Vec<String> = Vec::new();
    if result.outcome == OUTCOME_UNKNOWN {
        parts.push("OUTCOME UNKNOWN".into());
    }
    if let Some(code) = result.exit_code {
        parts.push(format!("exit={code}"));
    }
    if result.truncated {
        parts.push("[output truncated]".into());
    }
    let header = parts.join(" ");
    let body = [result.stdout.trim_end_matches(py_space), result.stderr.trim_end_matches(py_space)]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    if !header.is_empty() {
        format!("{header}\n{body}").trim_matches(py_space).to_string()
    } else if body.is_empty() {
        "(no output)".to_string()
    } else {
        body
    }
}

// -- The agent-facing MCP server -------------------------------------------------

/// `build_mcp_server`: the agent-facing MCP server.
///
/// `notifier` is the one thing that makes a catalog change visible to an
/// already-connected agent: the transport serves `subscriptions/listen`
/// from it and advertises `listChanged` in both eras; this handler tells it
/// which sessions to push to.
pub struct AgentMcp {
    pub service: Arc<Service>,
    pub notifier: CatalogNotifier,
}

impl AgentMcp {
    pub fn new(service: Arc<Service>, notifier: CatalogNotifier) -> Self {
        AgentMcp { service, notifier }
    }
}

/// One `Tool` as the SDK dumps it (field order of `mcp.types.Tool`).
fn tool_value(view: &crate::service::ToolView) -> Value {
    let mut annotations = Map::new();
    annotations.insert("readOnlyHint".into(), Value::Bool(view.read_only));
    annotations.insert("destructiveHint".into(), Value::Bool(!view.read_only && !view.idempotent));
    annotations.insert("idempotentHint".into(), Value::Bool(view.idempotent));
    let mut tool = Map::new();
    tool.insert("name".into(), Value::String(view.name.clone()));
    tool.insert("title".into(), Value::String(view.title.clone()));
    tool.insert("description".into(), Value::String(view.description.clone()));
    tool.insert("inputSchema".into(), view.input_schema.clone());
    tool.insert("annotations".into(), Value::Object(annotations));
    Value::Object(tool)
}

#[async_trait]
impl McpHandler for AgentMcp {
    fn server_info(&self) -> ServerInfo {
        ServerInfo::new("gatekeeper", crate::VERSION).with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(&self, ctx: &RequestContext) -> Result<ListToolsResult, McpError> {
        let identity = identity_from(ctx).map_err(|d| McpError::internal(d.to_string()))?;
        // The moment a client acquires a list it may cache is the moment it
        // becomes worth notifying.
        self.notifier.track(ctx);
        let tools = self.service.visible_tools(&identity).iter().map(tool_value).collect();
        // cacheScope private: the list differs per identity and must not be
        // shared between agents (the `ListToolsResult::new` default).
        Ok(ListToolsResult::new(tools))
    }

    async fn call_tool(
        &self,
        ctx: &RequestContext,
        name: &str,
        args: Map<String, Value>,
    ) -> Result<CallToolResult, McpError> {
        let identity = identity_from(ctx).map_err(|d| McpError::internal(d.to_string()))?;
        let client = client_of(ctx);
        match self.service.call(&identity, name, &args, client.as_deref()).await {
            Ok(result) => Ok(CallToolResult::text(render(&result), result.outcome != OUTCOME_OK)),
            Err(CallError::Denied(denial)) => Ok(CallToolResult::text(denial.agent_message(), true)),
            // What escaped Python's `on_call_tool` as an exception.
            Err(other) => Err(McpError::internal(other.to_string())),
        }
    }

    /// Register a handshake-era session as soon as it is usable:
    /// `notifications/initialized` is the first message that carries the
    /// session id, earlier than the client's first `tools/list`.
    async fn on_initialized(&self, ctx: &RequestContext) {
        self.notifier.track(ctx);
    }
}

// -- Middleware -------------------------------------------------------------------

fn header_latin1(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).map(|v| v.as_bytes().iter().map(|&b| b as char).collect())
}

/// How much of a refused POST body to `/mcp` or `/admin/mcp` is read, and
/// for how long, to name the MCP client in the audit record. A larger body, a missing Content-Length
/// or a slow sender is simply not read: the 401 never waits on it for long.
pub const HINT_BODY_MAX: usize = 8192;
pub const HINT_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// `gatekeeper` for the shape `gatekeeper token` generates (`gk_` and 43
/// URL-safe characters), `gk_malformed` for a token that has `gk_` in it but
/// not that shape (truncated, quoted, joined), `foreign` for anything else.
pub fn token_format(token: &str) -> &'static str {
    let shaped = token.strip_prefix("gk_").is_some_and(|rest| {
        rest.len() == 43 && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    });
    if shaped {
        "gatekeeper"
    } else if token.contains("gk_") {
        "gk_malformed"
    } else {
        "foreign"
    }
}

/// What a refused MCP request was: its JSON-RPC method and, on an
/// `initialize`, the client's own `clientInfo` name and version. Both are
/// the caller's claims, capped; anything not JSON-RPC yields nothing.
pub fn mcp_hint(body: &[u8]) -> Map<String, Value> {
    let mut hint = Map::new();
    let Ok(mut message) = serde_json::from_slice::<Value>(body) else {
        return hint;
    };
    if let Value::Array(items) = message {
        message = items.into_iter().next().unwrap_or(Value::Null);
    }
    let Value::Object(message) = message else {
        return hint;
    };
    if let Some(method) = message.get("method").and_then(Value::as_str).filter(|m| !m.is_empty()) {
        hint.insert("mcp_method".into(), Value::String(method.chars().take(80).collect()));
    }
    if let Some(info) = message.get("params").and_then(|p| p.get("clientInfo")).and_then(Value::as_object) {
        let parts: Vec<&str> = ["name", "version"]
            .iter()
            .filter_map(|k| info.get(*k).and_then(Value::as_str).filter(|v| !v.is_empty()))
            .collect();
        if !parts.is_empty() {
            hint.insert("mcp_client".into(), Value::String(parts.join(" ").chars().take(120).collect()));
        }
    }
    hint
}

/// The body of a refused POST, for [`mcp_hint`]: only with a Content-Length
/// of at most [`HINT_BODY_MAX`], and only what arrives within
/// [`HINT_BODY_TIMEOUT`]; otherwise empty.
async fn hint_body(request: Request) -> Vec<u8> {
    let path = decoded_path(&request);
    if (path != MCP_PATH && path != ADMIN_MCP_PATH) || request.method() != Method::POST {
        return Vec::new();
    }
    let length = header_latin1(request.headers(), "content-length").unwrap_or_default();
    if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
        return Vec::new();
    }
    if length.parse::<u128>().map_or(true, |n| n > HINT_BODY_MAX as u128) {
        return Vec::new();
    }
    match tokio::time::timeout(HINT_BODY_TIMEOUT, axum::body::to_bytes(request.into_body(), HINT_BODY_MAX)).await {
        Ok(Ok(bytes)) => bytes.to_vec(),
        _ => Vec::new(),
    }
}

/// `_bearer_token`: the first `Authorization` header that is a non-empty
/// `Bearer` credential.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all("authorization") {
        let raw: String = value.as_bytes().iter().map(|&b| b as char).collect();
        let (prefix, token) = match raw.split_once(' ') {
            Some((p, t)) => (p, t),
            None => (raw.as_str(), ""),
        };
        if prefix.to_lowercase() == "bearer" && !token.is_empty() {
            return Some(token.trim_matches(py_space).to_string());
        }
    }
    None
}

/// Starlette's `scope["path"]`: the percent-decoded request path.
fn decoded_path(request: &Request) -> String {
    percent_encoding::percent_decode_str(request.uri().path()).decode_utf8_lossy().into_owned()
}

/// `AuthMiddleware._is_ui_path`.
fn is_ui_path(path: &str) -> bool {
    let under = |prefix: &str| path == prefix || path.starts_with(&format!("{prefix}/"));
    // Exact prefix comparison: '/uixyz' must not be included. The console's
    // JSON API authenticates by session as well -- and refuses a bearer
    // token outright -- and `/app` is the static build: public bytes.
    if under(UI_PREFIX) || under(API_PREFIX) || under(APP_PREFIX) {
        return true;
    }
    // '/' and '/favicon.ico' are requested by the browser on its own.
    UI_COMPANION_PATHS.contains(&path)
}

fn json_response(status: u16, value: &Value) -> Response {
    let mut r = Response::new(Body::from(json_body(value)));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
    r
}

fn unauthorized() -> Response {
    let mut r = json_response(401, &json!({"error": "unauthorized"}));
    r.headers_mut().insert("www-authenticate", HeaderValue::from_static("Bearer"));
    r
}

/// Starlette's `ServerErrorMiddleware` answer to an exception escaping a
/// middleware (here: an audit log that cannot be written).
fn internal_error() -> Response {
    plain_text(500, "Internal Server Error", "text/plain; charset=utf-8")
}

fn plain_text(status: u16, body: impl Into<String>, content_type: &str) -> Response {
    let mut r = Response::new(Body::from(body.into()));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Ok(v) = HeaderValue::from_str(content_type) {
        r.headers_mut().insert("content-type", v);
    }
    r
}

/// Starlette's content type for a `media_type`: `text/*` gets a charset.
fn with_charset(media_type: &str) -> String {
    if media_type.starts_with("text/") && !media_type.contains("charset=") {
        format!("{media_type}; charset=utf-8")
    } else {
        media_type.to_string()
    }
}

/// What [`auth_middleware`] needs.
#[derive(Clone)]
pub struct AuthState {
    pub identities: SharedIdentities,
    pub audit: Arc<AuditLog>,
    pub ui_enabled: bool,
}

/// `AuthMiddleware`: check the bearer token, otherwise 401 (FR-2.3).
///
/// Reads exclusively the `Authorization` header and never a cookie. That is
/// why `/mcp` is immune to CSRF: a browser does not attach such a header on
/// its own. The console's session is deliberately a separate mechanism.
///
/// PORT NOTE: Python passed non-`http` ASGI scopes (websockets) through
/// unchecked; here every request is checked -- gatekeeper serves no
/// websocket outside the console paths, which pass anyway.
pub async fn auth_middleware(State(state): State<AuthState>, mut request: Request, next: Next) -> Response {
    let path = decoded_path(&request);
    if PUBLIC_PATHS.contains(&path.as_str()) {
        return next.run(request).await;
    }
    // The UI routes bring their own check (session instead of token). If
    // the UI is disabled, the token requirement still applies here.
    if state.ui_enabled && is_ui_path(&path) {
        return next.run(request).await;
    }

    let token = bearer_token(request.headers());
    let identity: Option<Identity> = match token.clone().filter(|t| !t.is_empty()) {
        Some(token) => {
            // scrypt: off the event loop.
            let identities = state.identities.clone();
            tokio::task::spawn_blocking(move || identities.read().authenticate(&token).cloned())
                .await
                .unwrap_or(None)
        }
        None => None,
    };
    // Who knocked, so a stale token in some client's config can be traced
    // to a machine: the peer, or the forwarded one behind a trusted proxy.
    let method = request.method().as_str().to_string();
    let client = client_addr(request.extensions()).map(|c| c.host).unwrap_or_else(|| "unknown".into());
    let mut caller = Map::new();
    caller.insert("client".into(), Value::String(client.clone()));
    caller.insert("method".into(), Value::String(method.clone()));
    caller.insert("path".into(), Value::String(path.clone()));
    if let Some(agent) = header_latin1(request.headers(), "user-agent").filter(|a| !a.is_empty()) {
        // Names the client program; capped so a hostile header cannot bloat
        // the log.
        caller.insert("user_agent".into(), Value::String(agent.chars().take(160).collect()));
    }

    // Behind a NAT or a Docker port mapping the peer is a gateway; an
    // untrusted proxy's header still names the machine behind it. As sent,
    // unverified, capped.
    let forwarded = header_latin1(request.headers(), "x-forwarded-for")
        .filter(|v| !v.is_empty())
        .or_else(|| header_latin1(request.headers(), "x-real-ip").filter(|v| !v.is_empty()));
    if let Some(forwarded) = forwarded {
        caller.insert("forwarded_for".into(), Value::String(forwarded.chars().take(160).collect()));
    }
    // A session ID from before a restart: the client was connected and is
    // still going. Its value is never logged.
    if header_latin1(request.headers(), SESSION_ID_HEADER).is_some_and(|v| !v.is_empty()) {
        caller.insert("mcp_session".into(), Value::Bool(true));
    }

    let Some(identity) = identity else {
        if let Some(token) = token.as_deref().filter(|t| !t.is_empty()) {
            // The presented token's lookup index, shortened: matchable
            // against an older identities.yaml, never a secret.
            caller.insert("fingerprint".into(), Value::String(hash_token_lookup(token)[..12].to_string()));
            // Its shape, not its content: a gatekeeper token, a mangled one,
            // or some other service's credential.
            caller.insert("presented_format".into(), Value::String(token_format(token).into()));
            caller.insert("presented_length".into(), json!(token.chars().count()));
            let matches = state.identities.read().lookup_matches(token);
            if !matches.is_empty() {
                caller.insert("lookup_identity".into(), Value::String(matches.join(", ")));
            }
        }
        caller.extend(mcp_hint(&hint_body(request).await));
        let detail = format!("{method} {path} from {client}");
        if state.audit.auth_failure(DenialReason::UnknownToken.as_str(), &detail, caller).is_err() {
            return internal_error();
        }
        return unauthorized();
    };

    // FR-2.8/2.9: an `admin` token on `/mcp` and any non-admin token on
    // `/admin/mcp` are both rejected outright -- the same response an
    // unknown token gets.
    let role_mismatch = (path == ADMIN_MCP_PATH && identity.role != ADMIN_ROLE)
        || (path == MCP_PATH && identity.role == ADMIN_ROLE);
    if role_mismatch {
        let detail = format!(
            "role {} on {path} ({}) from {client}",
            repr_str(&identity.role),
            repr_str(&identity.id)
        );
        // The token was valid, just on the wrong endpoint: say whose.
        let mut extra = Map::new();
        extra.insert("identity".into(), Value::String(identity.id.clone()));
        extra.extend(caller);
        if state.audit.auth_failure(DenialReason::UnknownToken.as_str(), &detail, extra).is_err() {
            return internal_error();
        }
        return unauthorized();
    }

    request.extensions_mut().insert(AuthIdentity(identity));
    next.run(request).await
}

/// `SessionReaper`: drops a tracked MCP session when its client terminates
/// it (`DELETE /mcp` with an `Mcp-Session-Id`). Sits inside the auth
/// middleware, so an unauthenticated DELETE never reaches it.
pub async fn session_reaper(State(notifier): State<CatalogNotifier>, request: Request, next: Next) -> Response {
    if request.method() == Method::DELETE && decoded_path(&request) == MCP_PATH {
        if let Some(session_id) = header_latin1(request.headers(), SESSION_ID_HEADER).filter(|s| !s.is_empty()) {
            notifier.forget(&session_id);
        }
    }
    next.run(request).await
}

// -- Reverse-proxy headers ---------------------------------------------------------

/// uvicorn's `_TrustedHosts` (`forwarded_allow_ips`): addresses, strict
/// networks, and literals for anything else; `"*"` alone trusts everyone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvicornTrustedHosts {
    always_trust: bool,
    literals: BTreeSet<String>,
    hosts: BTreeSet<IpAddr>,
    networks: Vec<ipnet::IpNet>,
}

impl UvicornTrustedHosts {
    /// `forwarded_allow_ips`: `None` means uvicorn's own default, the
    /// `FORWARDED_ALLOW_IPS` environment variable or else `127.0.0.1`.
    pub fn new(trusted: Option<&[String]>) -> Self {
        let entries: Vec<String> = match trusted {
            Some(list) => {
                if list.len() == 1 && list[0] == "*" {
                    return Self::trust_all();
                }
                list.to_vec()
            }
            None => {
                let raw = std::env::var("FORWARDED_ALLOW_IPS").unwrap_or_else(|_| "127.0.0.1".into());
                if raw == "*" {
                    return Self::trust_all();
                }
                raw.split(',').map(|s| s.trim().to_string()).collect()
            }
        };
        let mut out = UvicornTrustedHosts {
            always_trust: false,
            literals: BTreeSet::new(),
            hosts: BTreeSet::new(),
            networks: Vec::new(),
        };
        for host in entries {
            if host.contains('/') {
                match strict_network(&host) {
                    Some(net) => out.networks.push(net),
                    None => {
                        out.literals.insert(host);
                    }
                }
            } else {
                match crate::realip::ip_address(&host) {
                    Some(ip) => {
                        out.hosts.insert(ip);
                    }
                    None => {
                        out.literals.insert(host);
                    }
                }
            }
        }
        out
    }

    fn trust_all() -> Self {
        UvicornTrustedHosts {
            always_trust: true,
            literals: BTreeSet::new(),
            hosts: BTreeSet::new(),
            networks: Vec::new(),
        }
    }

    /// `host in trusted_hosts`.
    pub fn contains(&self, host: Option<&str>) -> bool {
        if self.always_trust {
            return true;
        }
        let Some(host) = host.filter(|h| !h.is_empty()) else { return false };
        match crate::realip::ip_address(host) {
            Some(ip) => self.hosts.contains(&ip) || self.networks.iter().any(|n| n.contains(&ip)),
            None => self.literals.contains(host),
        }
    }

    /// `get_trusted_client_address`: the first untrusted host from the
    /// right of `X-Forwarded-For`.
    pub fn trusted_client_address(&self, x_forwarded_for: &str) -> (String, i64) {
        let hosts: Vec<&str> = x_forwarded_for.split(',').map(|s| s.trim()).collect();
        if self.always_trust {
            return parse_host_port(hosts[0]);
        }
        for host_port in hosts.iter().rev() {
            let (host, port) = parse_host_port(host_port);
            if !self.contains(Some(&host)) {
                return (host, port);
            }
        }
        parse_host_port(hosts[0])
    }
}

/// `ipaddress.ip_network(entry)` with `strict=True`: host bits must be
/// clear.
fn strict_network(entry: &str) -> Option<ipnet::IpNet> {
    let net = crate::realip::ip_network(entry)?;
    let addr = crate::realip::ip_address(entry.split('/').next()?)?;
    (net.network() == addr).then_some(net)
}

/// Python's `int(text)` for a port.
fn py_port(text: &str) -> Option<i64> {
    crate::release_notes::py_int(text)
}

/// uvicorn's `_parse_host_port`.
fn parse_host_port(value: &str) -> (String, i64) {
    if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else { return (value.to_string(), 0) };
        let host = &rest[..end];
        let remainder = &rest[end + 1..];
        if remainder.is_empty() {
            return (host.to_string(), 0);
        }
        let Some(port) = remainder.strip_prefix(':') else { return (value.to_string(), 0) };
        return (host.to_string(), py_port(port).unwrap_or(0));
    }
    if value.matches(':').count() == 1 {
        let (host, port) = value.rsplit_once(':').unwrap_or((value, ""));
        return match py_port(port) {
            Some(p) => (host.to_string(), p),
            None => (value.to_string(), 0),
        };
    }
    (value.to_string(), 0)
}

/// Records the caller's address in both places a handler may read it:
/// [`ClientAddr`], and -- when it is an IP address -- axum's `ConnectInfo`.
fn set_client(extensions: &mut http::Extensions, host: String, port: i64) {
    if let Some(ip) = crate::realip::ip_address(&host) {
        let port = u16::try_from(port).unwrap_or(0);
        extensions.insert(ConnectInfo(SocketAddr::new(ip, port)));
    }
    extensions.insert(ClientAddr { host, port });
}

/// uvicorn's `ProxyHeadersMiddleware`, applied to one request: for a
/// trusted peer, `X-Forwarded-Proto` sets the scheme and `X-Forwarded-For`
/// the client.
pub fn apply_proxy_headers(trusted: &UvicornTrustedHosts, request: &mut Request) {
    let peer = client_addr(request.extensions());
    let mut scheme = request.extensions().get::<RequestScheme>().map(|s| s.0.clone()).unwrap_or_else(|| "http".into());
    if trusted.contains(peer.as_ref().map(|p| p.host.as_str())) {
        let mut proto: Option<String> = None;
        let mut forwarded: Vec<String> = Vec::new();
        for (name, value) in request.headers() {
            let text: String = value.as_bytes().iter().map(|&b| b as char).collect();
            if name == "x-forwarded-proto" {
                proto = Some(text);
            } else if name == "x-forwarded-for" {
                forwarded.push(text);
            }
        }
        if let Some(proto) = proto {
            let proto = proto.trim_matches(py_space).to_string();
            if matches!(proto.as_str(), "http" | "https" | "ws" | "wss") {
                scheme = proto;
            }
        }
        if !forwarded.is_empty() {
            let (host, port) = trusted.trusted_client_address(&forwarded.join(", "));
            // An empty X-Forwarded-For yields an empty host: keep the peer.
            if !host.is_empty() {
                set_client(request.extensions_mut(), host, port);
            }
        }
    }
    let host = client_addr(request.extensions()).map(|c| c.host);
    request
        .extensions_mut()
        .insert(crate::api::RequestClient { host, scheme: Some(scheme.clone()) });
    request.extensions_mut().insert(RequestScheme(scheme));
}

/// Wraps `router` in uvicorn's proxy-header handling (`forwarded_allow_ips`
/// = `trusted`).
pub fn uvicorn_proxy_headers(router: Router, trusted: Option<Vec<String>>) -> Router {
    let trusted = Arc::new(UvicornTrustedHosts::new(trusted.as_deref()));
    router.layer(middleware::from_fn(move |mut request: Request, next: Next| {
        let trusted = trusted.clone();
        async move {
            apply_proxy_headers(&trusted, &mut request);
            next.run(request).await
        }
    }))
}

/// `RealIpMiddleware`, applied to one request: `X-Real-IP` from a trusted
/// proxy when no `X-Forwarded-For` came along.
pub fn apply_real_ip(trusted: &TrustedProxies, request: &mut Request) {
    let peer = client_addr(request.extensions());
    let Some(peer) = peer else { return };
    if let Some(real) = crate::realip::real_ip(trusted, Some(&peer.host), request.headers()) {
        set_client(request.extensions_mut(), real, 0);
    }
}

/// Wraps `router` in `RealIpMiddleware` with the same trust list.
pub fn real_ip(router: Router, trusted: Option<Vec<String>>) -> Router {
    let trusted = Arc::new(TrustedProxies::parse(trusted.as_deref()));
    router.layer(middleware::from_fn(move |mut request: Request, next: Next| {
        let trusted = trusted.clone();
        async move {
            apply_real_ip(&trusted, &mut request);
            next.run(request).await
        }
    }))
}

/// Both proxy layers, in `serve`'s order: uvicorn's `X-Forwarded-*`
/// handling first, then `X-Real-IP`.
pub fn with_proxy_headers(router: Router, trusted: Option<Vec<String>>) -> Router {
    uvicorn_proxy_headers(real_ip(router, trusted.clone()), trusted)
}

// -- The application -------------------------------------------------------------

/// `build_app`'s arguments. `store: None` means read only; `pending` and
/// `toolkit_proposals` must be supplied whenever `store` is.
#[derive(Clone)]
pub struct AppOptions {
    pub service: Arc<Service>,
    pub identities: SharedIdentities,
    pub audit: Arc<AuditLog>,
    /// The bind address; a loopback host turns on DNS-rebinding protection
    /// on both MCP mounts, as the SDK does.
    pub host: String,
    pub ui: bool,
    pub store: Option<Arc<ConfigStore>>,
    pub credentials: Option<Arc<CredentialStore>>,
    pub pending: Option<Arc<PendingStore>>,
    pub toolkit_proposals: Option<Arc<ToolkitProposalStore>>,
}

impl AppOptions {
    /// The defaults of Python's keyword arguments: host `0.0.0.0`, no UI,
    /// read only.
    pub fn new(service: Arc<Service>, identities: SharedIdentities, audit: Arc<AuditLog>) -> Self {
        AppOptions {
            service,
            identities,
            audit,
            host: "0.0.0.0".into(),
            ui: false,
            store: None,
            credentials: None,
            pending: None,
            toolkit_proposals: None,
        }
    }
}

/// `streamable_http_app(host=...)`: DNS-rebinding protection is switched on
/// for a loopback bind address.
pub fn transport_security(host: &str) -> TransportSecurity {
    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
        TransportSecurity {
            enable_dns_rebinding_protection: true,
            allowed_hosts: vec!["127.0.0.1:*".into(), "localhost:*".into(), "[::1]:*".into()],
            allowed_origins: vec![
                "http://127.0.0.1:*".into(),
                "http://localhost:*".into(),
                "http://[::1]:*".into(),
            ],
        }
    } else {
        TransportSecurity::default()
    }
}

/// 503, not 404, when the build shipped without RELEASE.md -- shared with
/// `release_notes::release_response`.
fn release_route(query: Option<String>) -> Response {
    let params: Vec<(String, String)> = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let r = release_notes::release_response(&params);
    plain_text(r.status, r.body, &r.content_type)
}

/// The authenticated download of a release-bound artifact (`artifacts.py`):
/// the same gate as the `artifact` tools; everything else is one
/// indistinguishable 404 (FR-7.7).
async fn artifact_route(
    service: Arc<Service>,
    audit: Arc<AuditLog>,
    identity: Option<Identity>,
    artifact_id: String,
    version: Option<String>,
) -> Response {
    let tier1 = service.tier1();
    let enabled: BTreeSet<&String> = tier1
        .toolkits
        .values()
        .filter(|t| t.executor == "artifact")
        .flat_map(|t| t.allowed_artifacts.iter())
        .collect();
    let allowed = identity
        .as_ref()
        .is_some_and(|i| enabled.contains(&artifact_id) && i.covers_scope(&format!("artifact:{artifact_id}")));
    let store = service.artifact_store();
    let download =
        decide_download(&store, identity.as_ref().map(|i| i.id.as_str()), allowed, &artifact_id, version.as_deref());
    if audit.write(download.audit).is_err() {
        return internal_error();
    }
    match download.response {
        DownloadResponse::NotFound { status, content_type, body } => plain_text(status, body, content_type),
        DownloadResponse::Stream { artifact, media_type, headers } => {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(4);
            let store = store.clone();
            tokio::task::spawn_blocking(move || {
                for chunk in store.stream(&artifact) {
                    match chunk {
                        Ok(bytes) => {
                            if tx.blocking_send(Ok(bytes::Bytes::from(bytes))).is_err() {
                                return;
                            }
                        }
                        Err(error) => {
                            if matches!(error, StreamError::Integrity(_)) {
                                tracing::error!("Artifact {} changed on disk; download aborted", artifact.id);
                            }
                            let _ = tx.blocking_send(Err(std::io::Error::other(error.to_string())));
                            return;
                        }
                    }
                }
            });
            let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
            let mut r = Response::new(Body::from_stream(stream));
            if let Ok(v) = HeaderValue::from_str(&with_charset(&media_type)) {
                r.headers_mut().insert("content-type", v);
            }
            for (name, value) in headers {
                if let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(&value)) {
                    r.headers_mut().insert(n, v);
                }
            }
            r
        }
    }
}

/// The agent-facing routes with no MCP in them: health, metrics, release
/// notes, artifact downloads.
fn plain_routes(service: &Arc<Service>, audit: &Arc<AuditLog>) -> Router {
    let ready_service = service.clone();
    let startup_service = service.clone();
    let metrics_service = service.clone();
    let (art1, aud1) = (service.clone(), audit.clone());
    let (art2, aud2) = (service.clone(), audit.clone());
    Router::new()
        .route("/health/live", get(|| async { json_response(200, &json!({"status": "live"})) }))
        .route(
            "/health/ready",
            get(move || {
                let service = ready_service.clone();
                async move {
                    let ready = service.probe_executors().await;
                    // Without toolkits there is nothing to check: the state
                    // after `init`, not a deficiency.
                    let ok = if ready.is_empty() {
                        service.tier1().toolkits.is_empty()
                    } else {
                        ready.values().all(|v| *v)
                    };
                    let executors: Map<String, Value> = ready.into_iter().map(|(k, v)| (k, Value::Bool(v))).collect();
                    json_response(
                        if ok { 200 } else { 503 },
                        &json!({"status": if ok { "ready" } else { "degraded" }, "executors": executors}),
                    )
                }
            }),
        )
        .route(
            "/health/startup",
            get(move || {
                let catalog = startup_service.catalog();
                async move {
                    json_response(
                        200,
                        &json!({
                            "status": "started",
                            "tools": catalog.tools.len(),
                            "disabled_by_tier1": catalog.disabled_by_tier1.len(),
                        }),
                    )
                }
            }),
        )
        .route(
            "/metrics",
            get(move || {
                let text = metrics_service.render_metrics();
                async move { plain_text(200, text, "text/plain; version=0.0.4; charset=utf-8") }
            }),
        )
        // Deliberately not public: the notes are a version inventory of the
        // very build answering the request.
        .route("/release", get(|RawQuery(query): RawQuery| async move { release_route(query) }))
        .route(
            "/artifacts/{artifact_id}",
            get(move |Path(artifact_id): Path<String>, request: Request| {
                let identity = request.extensions().get::<AuthIdentity>().map(|i| i.0.clone());
                artifact_route(art1.clone(), aud1.clone(), identity, artifact_id, None)
            }),
        )
        .route(
            "/artifacts/{artifact_id}/{version}",
            get(move |Path((artifact_id, version)): Path<(String, String)>, request: Request| {
                let identity = request.extensions().get::<AuthIdentity>().map(|i| i.0.clone());
                artifact_route(art2.clone(), aud2.clone(), identity, artifact_id, Some(version))
            }),
        )
}

/// Starlette's answer for a path no route matches.
async fn not_found() -> Response {
    plain_text(404, "Not Found", "text/plain; charset=utf-8")
}

/// `build_app`: the complete application. Call inside the tokio runtime
/// that will serve it -- the catalog notifier binds to that runtime.
///
/// `ui: false` is intentional: the console is the only browser-facing
/// surface and does not silently grow on an existing deployment.
/// `/admin/mcp` (FR-2.8) is mounted under exactly the same condition as
/// the console's write functions: a writable `ConfigStore`. Passing a
/// `store` without `pending` and `toolkit_proposals` is a programming
/// error (`Err`, Python's `ValueError`).
///
/// Serve it with `into_make_service_with_connect_info::<SocketAddr>()`.
pub fn build_app(opts: AppOptions) -> Result<Router, String> {
    let AppOptions { service, identities, audit, host, ui, store, credentials, pending, toolkit_proposals } = opts;
    let notifier = service.catalog_notifier.clone();
    // The MCP transports live on this runtime, and catalog writes arrive
    // from synchronous code on any thread.
    notifier.bind_current();

    let mut app = plain_routes(&service, &audit);

    // `/mcp` retains sessions: a handshake-era client's standalone SSE
    // stream (where `tools/list_changed` goes) only exists on a retained
    // session. Retained sessions are reaped after an hour of silence.
    let mut agent_config = McpConfig::stateful(MCP_PATH).with_notifier(notifier.clone());
    agent_config.session_idle_timeout = Some(std::time::Duration::from_secs(SESSION_IDLE_TIMEOUT_SECONDS));
    agent_config.security = transport_security(&host);
    app = app.merge(mcp::router(Arc::new(AgentMcp::new(service.clone(), notifier.clone())), agent_config));

    if let Some(store) = &store {
        let Some(pending) = pending.clone() else {
            return Err("build_app(store=...) requires pending=... as well -- \
                        __main__.py constructs a PendingStore alongside the \
                        ConfigStore for exactly this."
                .into());
        };
        let Some(toolkit_proposals) = toolkit_proposals.clone() else {
            return Err("build_app(store=...) requires toolkit_proposals=... as \
                        well -- __main__.py constructs a ToolkitProposalStore \
                        alongside the ConfigStore/PendingStore for exactly this."
                .into());
        };
        let admin_service = AdminService::new(store.clone(), pending, toolkit_proposals, credentials.clone());
        // Stateless: its tool list is a fixed constant, nothing to announce.
        let mut admin_config = McpConfig::stateless(ADMIN_MCP_PATH);
        admin_config.security = transport_security(&host);
        app = app.merge(mcp::router(Arc::new(AdminMcp::new(admin_service)), admin_config));
    }

    // Set before the console is merged: a console router with a fallback
    // of its own would make `merge` panic -- loudly, at startup.
    app = app.fallback(not_found);

    if ui {
        app = app.merge(console_router(ConsoleDeps {
            service: service.clone(),
            identities: identities.clone(),
            audit: audit.clone(),
            store,
            credentials,
            pending,
            toolkit_proposals,
        }));
    }

    let app = app
        .layer(middleware::from_fn_with_state(notifier, session_reaper))
        .layer(middleware::from_fn_with_state(AuthState { identities, audit, ui_enabled: ui }, auth_middleware));
    Ok(app)
}

/// NFR-7: record at startup what actually applies.
pub fn log_startup(service: &Service, identities: &SharedIdentities) -> Value {
    let tier1 = service.tier1();
    let catalog = service.catalog();
    let mut toolkits = Map::new();
    for (name, tk) in &tier1.toolkits {
        toolkits.insert(
            name.clone(),
            json!({
                "executor": tk.executor,
                "binaries": tk.binaries,
                "denied_args": tk.denied_args,
                "path_roots": tk.path_roots,
                "protected_resources": tk.protected_resources,
            }),
        );
    }
    let mut active: Vec<&String> = catalog.tools.keys().collect();
    active.sort();
    let payload = json!({
        "toolkits": toolkits,
        "tools_active": active,
        "tools_disabled_by_tier1": catalog.disabled_by_tier1,
        "identities": summarize(&identities.read()),
    });
    if let Err(e) = service.audit.startup(payload.clone()) {
        tracing::error!("The audit log could not be written: {e}");
    }
    tracing::info!(
        "gatekeeper ready: {}",
        crate::pyjson::dumps_with(&payload, &crate::pyjson::Opts::unicode())
    );
    for violation in &catalog.disabled_by_tier1 {
        tracing::warn!("Definition disabled by Tier 1 violation: {}", violation);
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(outcome: &str, exit: Option<i64>, out: &str, err: &str, truncated: bool) -> ExecResult {
        ExecResult::new(outcome, exit, out, err, truncated, 1)
    }

    #[test]
    fn render_matches_python() {
        assert_eq!(render(&result("ok", None, "", "", false)), "(no output)");
        assert_eq!(render(&result("ok", None, "a\n", "", false)), "a");
        assert_eq!(render(&result("ok", Some(0), "a\n", "b \n", false)), "exit=0\na\nb");
        assert_eq!(render(&result("unknown", None, "", "", true)), "OUTCOME UNKNOWN [output truncated]");
        assert_eq!(render(&result("failed", Some(2), "", "  err\n", false)), "exit=2\n  err");
        assert_eq!(render(&result("ok", None, "  x", "", false)), "  x");
        assert_eq!(render(&result("ok", Some(1), "  x", "", false)), "exit=1\n  x");
    }

    #[test]
    fn bearer_parsing_matches_python() {
        let headers = |pairs: &[&str]| {
            let mut h = HeaderMap::new();
            for v in pairs {
                h.append("authorization", HeaderValue::from_str(v).unwrap());
            }
            h
        };
        assert_eq!(bearer_token(&headers(&["Bearer abc"])), Some("abc".into()));
        assert_eq!(bearer_token(&headers(&["bEaReR  abc "])), Some("abc".into()));
        assert_eq!(bearer_token(&headers(&["Basic xyz", "Bearer second"])), Some("second".into()));
        assert_eq!(bearer_token(&headers(&["Bearer"])), None);
        assert_eq!(bearer_token(&headers(&["Bearer "])), None);
        // A whitespace-only token survives as "" -- falsy, so no lookup.
        assert_eq!(bearer_token(&headers(&["Bearer   "])), Some(String::new()));
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn ui_paths_are_exact_prefixes() {
        for p in ["/ui", "/ui/x", "/api/v1", "/api/v1/session", "/app", "/app/x", "/", "/favicon.ico"] {
            assert!(is_ui_path(p), "{p}");
        }
        for p in ["/uixyz", "/api/v1xyz", "/apixyz", "/appxyz", "/mcp", "/metrics"] {
            assert!(!is_ui_path(p), "{p}");
        }
    }

    #[test]
    fn uvicorn_host_port_parsing() {
        assert_eq!(parse_host_port("1.2.3.4"), ("1.2.3.4".into(), 0));
        assert_eq!(parse_host_port("1.2.3.4:80"), ("1.2.3.4".into(), 80));
        assert_eq!(parse_host_port("1.2.3.4:x"), ("1.2.3.4:x".into(), 0));
        assert_eq!(parse_host_port("[::1]:443"), ("::1".into(), 443));
        assert_eq!(parse_host_port("[::1]"), ("::1".into(), 0));
        assert_eq!(parse_host_port("[::1"), ("[::1".into(), 0));
        assert_eq!(parse_host_port("::1"), ("::1".into(), 0));
    }

    #[test]
    fn uvicorn_trust_list() {
        let t = UvicornTrustedHosts::new(Some(&["10.0.0.0/8".into(), "1.2.3.4".into(), "10.1.0.0/8".into(), "sock".into()]));
        assert!(t.contains(Some("10.9.9.9")));
        assert!(t.contains(Some("1.2.3.4")));
        assert!(t.contains(Some("sock")));
        assert!(!t.contains(Some("11.0.0.1")));
        assert!(!t.contains(None));
        // A non-strict network is a literal, not a network.
        assert!(t.literals.contains("10.1.0.0/8"));
        let all = UvicornTrustedHosts::new(Some(&["*".into()]));
        assert!(all.contains(None));
        assert_eq!(all.trusted_client_address("9.9.9.9, 10.0.0.1"), ("9.9.9.9".into(), 0));
        assert_eq!(t.trusted_client_address("9.9.9.9, 8.8.8.8, 10.0.0.1"), ("8.8.8.8".into(), 0));
        assert_eq!(t.trusted_client_address("10.0.0.2, 10.0.0.1"), ("10.0.0.2".into(), 0));
    }

    #[test]
    fn loopback_hosts_get_dns_rebinding_protection() {
        assert!(transport_security("127.0.0.1").enable_dns_rebinding_protection);
        assert!(transport_security("::1").enable_dns_rebinding_protection);
        assert!(!transport_security("0.0.0.0").enable_dns_rebinding_protection);
    }
}
