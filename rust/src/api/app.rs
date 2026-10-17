//! The `/api/v1` application (port of `api/app.py`, `api/writes.py` and
//! `api/extras.py`), plus the browser surface around it: `/app`
//! (`web.rs`), the `/ui` redirects and the OAuth callbacks.
//!
//! Routing follows Starlette's rules exactly, because they are visible on
//! the wire: routes are tried in registration order; a path that matches a
//! route with another method is a 405 whose `Allow` names the *first* such
//! route's method; a GET route does not answer HEAD (FastAPI); an unmatched
//! path that would match with or without a trailing slash is a 307 to that
//! spelling; anything else is a 404. Every error body is
//! `{"error": "<sentence>"}`.
//!
//! Per request, in FastAPI's order: the body is read (a JSON decode error
//! is a 422 before anything else), then the session dependencies run
//! (401/403), then query parameters and the body are validated (422), then
//! the handler. Store calls and password hashing run on the blocking pool.
//!
//! Invariants this module keeps: no route writes a toolkit (FR-4.11); no
//! response carries a credential value, token hash or password hash; an MCP
//! bearer token opens nothing here; the OpenAPI schema is admin-only and
//! there are no interactive docs pages.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Body as AxumBody;
use axum::extract::{ConnectInfo, Request, State};
use axum::response::Response;
use futures::{Stream, StreamExt};
use http::{HeaderName, HeaderValue, StatusCode};
use serde_json::{json, Map, Value};

use crate::errors::ConfigError;
use crate::identity::ADMIN_ROLE;
use crate::oauth::{CallbackContext, CallbackQuery, StartContext, StartError, TokenEndpoints};
use crate::pyfmt::repr_str;
use crate::ui::{self, UiResponse, UiRoute};

use super::deps::{
    api, etag, if_match, py_strip, require_admin, require_admin_read, require_csrf, require_session_write,
    require_viewer, ApiContext, ApiError, ApiRequest, ApiResult, Fail, EMPTY_REVISION,
};
use super::events::{EventHub, StreamTimings};
use super::models::{self, read_body, validate, validate_query, Body, BodyError, Model, QKind, QValue};
use super::service as rm;
use super::session::{Session, SESSION_COOKIE};
use super::web::{self, WebDir};
use super::{RequestClient, API_PREFIX};

/// API responses are data, never a document.
pub const SECURITY_HEADERS: [(&str, &str); 5] = [
    ("content-security-policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
    ("cross-origin-resource-policy", "same-origin"),
];

/// The committed OpenAPI document (`frontend/openapi.json`).
pub const OPENAPI_JSON: &str = include_str!("../../../frontend/openapi.json");

// -- Routes ------------------------------------------------------------------

/// Which session dependency a route runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    None,
    Viewer,
    Csrf,
    Admin,
    SessionWrite,
    AdminRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    SessionGet,
    SessionCreate,
    SessionDelete,
    Account,
    Overview,
    Tools,
    Tool,
    Identities,
    Credentials,
    Toolkits,
    ToolkitReference,
    RequestsPending,
    RequestsDecided,
    RequestsToolkits,
    Audit,
    ReleaseNotes,
    ToolScaffold,
    ToolCreate,
    ToolUpdate,
    ToolEnable,
    ToolDelete,
    IdentityCreate,
    IdentityUpdate,
    IdentityRotate,
    IdentityDelete,
    CredentialCreate,
    CredentialRotate,
    CredentialDelete,
    AccountPassword,
    PendingApprove,
    PendingCredential,
    PendingReject,
    PendingApproveAll,
    PendingRejectAll,
    ToolkitDeploy,
    ToolkitReject,
    Stats,
    Documents,
    Document,
    OAuthProviders,
    OAuthAuthorize,
    Events,
    OpenApi,
}

/// One `/api/v1` route.
#[derive(Debug, Clone, Copy)]
pub struct RouteDef {
    pub method: &'static str,
    /// Relative to `/api/v1`, Starlette syntax (`{name}` is one segment).
    pub path: &'static str,
    pub op: Op,
    pub gate: Gate,
    pub query: &'static [(&'static str, QKind)],
    pub body: Option<Model>,
    /// `include_in_schema`.
    pub in_schema: bool,
}

const fn r(method: &'static str, path: &'static str, op: Op, gate: Gate) -> RouteDef {
    RouteDef { method, path, op, gate, query: &[], body: None, in_schema: true }
}

const fn rb(method: &'static str, path: &'static str, op: Op, gate: Gate, body: Model) -> RouteDef {
    RouteDef { method, path, op, gate, query: &[], body: Some(body), in_schema: true }
}

const fn rq(method: &'static str, path: &'static str, op: Op, query: &'static [(&'static str, QKind)]) -> RouteDef {
    RouteDef { method, path, op, gate: Gate::Viewer, query, body: None, in_schema: true }
}

const STATUS_QUERY: &[(&str, QKind)] = &[("status", QKind::OptStr { max: 32 })];
const DECIDED_QUERY: &[(&str, QKind)] =
    &[("limit", QKind::Int { default: 25, ge: 1, le: 200 }), ("cursor", QKind::OptStr { max: 256 })];
const AUDIT_QUERY: &[(&str, QKind)] = &[
    ("identity", QKind::Str { default: "", max: Some(256), pattern: None }),
    ("tool", QKind::Str { default: "", max: Some(256), pattern: None }),
    ("outcome", QKind::Str { default: "", max: None, pattern: Some("^(|ok|denied|failed|unknown)$") }),
    ("limit", QKind::Int { default: 100, ge: 1, le: 500 }),
    ("cursor", QKind::OptStr { max: 128 }),
];
const NOTES_QUERY: &[(&str, QKind)] = &[
    ("version", QKind::OptStr { max: 64 }),
    ("search", QKind::OptStr { max: 256 }),
    ("limit", QKind::OptInt { ge: 1, le: 1000 }),
];
const STATS_QUERY: &[(&str, QKind)] =
    &[("window", QKind::Str { default: "24h", max: None, pattern: Some("^(24h|7d|30d)$") })];

/// Every route, in the order `build_api_app` registers them.
pub const ROUTES: &[RouteDef] = &[
    // app.py
    r("GET", "/session", Op::SessionGet, Gate::Viewer),
    rb("POST", "/session", Op::SessionCreate, Gate::None, models::LOGIN_REQUEST),
    r("DELETE", "/session", Op::SessionDelete, Gate::Csrf),
    r("GET", "/account", Op::Account, Gate::Viewer),
    r("GET", "/overview", Op::Overview, Gate::Viewer),
    r("GET", "/tools", Op::Tools, Gate::Viewer),
    r("GET", "/tools/{tool_id}", Op::Tool, Gate::Viewer),
    r("GET", "/identities", Op::Identities, Gate::Viewer),
    r("GET", "/credentials", Op::Credentials, Gate::Viewer),
    r("GET", "/toolkits", Op::Toolkits, Gate::Viewer),
    r("GET", "/toolkits/reference", Op::ToolkitReference, Gate::Viewer),
    rq("GET", "/requests/pending", Op::RequestsPending, STATUS_QUERY),
    rq("GET", "/requests/decided", Op::RequestsDecided, DECIDED_QUERY),
    rq("GET", "/requests/toolkits", Op::RequestsToolkits, STATUS_QUERY),
    rq("GET", "/audit", Op::Audit, AUDIT_QUERY),
    rq("GET", "/release-notes", Op::ReleaseNotes, NOTES_QUERY),
    // writes.py: register_write_routes
    r("GET", "/tool-scaffold", Op::ToolScaffold, Gate::Viewer),
    rb("POST", "/tools", Op::ToolCreate, Gate::Admin, models::TOOL_WRITE),
    rb("PUT", "/tools/{tool_id}", Op::ToolUpdate, Gate::Admin, models::TOOL_WRITE),
    rb("PUT", "/tools/{tool_id}/enabled", Op::ToolEnable, Gate::Admin, models::TOOL_ENABLED),
    r("DELETE", "/tools/{tool_id}", Op::ToolDelete, Gate::Admin),
    rb("POST", "/identities", Op::IdentityCreate, Gate::Admin, models::IDENTITY_WRITE),
    rb("PUT", "/identities/{identity_id}", Op::IdentityUpdate, Gate::Admin, models::IDENTITY_WRITE),
    r("POST", "/identities/{identity_id}/token", Op::IdentityRotate, Gate::Admin),
    r("DELETE", "/identities/{identity_id}", Op::IdentityDelete, Gate::Admin),
    rb("POST", "/credentials", Op::CredentialCreate, Gate::Admin, models::CREDENTIAL_CREATE),
    rb("POST", "/credentials/{name}/rotate", Op::CredentialRotate, Gate::Admin, models::CREDENTIAL_ROTATE),
    r("DELETE", "/credentials/{name}", Op::CredentialDelete, Gate::Admin),
    rb("PUT", "/account/password", Op::AccountPassword, Gate::SessionWrite, models::PASSWORD_CHANGE),
    // writes.py: register_request_routes
    r("POST", "/requests/pending/{item_id}/approve", Op::PendingApprove, Gate::Admin),
    rb("POST", "/requests/pending/{item_id}/credential", Op::PendingCredential, Gate::Admin, models::CREDENTIAL_FILL),
    rb("POST", "/requests/pending/{item_id}/reject", Op::PendingReject, Gate::Admin, models::REJECT_BODY),
    rb("POST", "/requests/pending/approve-all", Op::PendingApproveAll, Gate::Admin, models::APPROVE_ALL),
    rb("POST", "/requests/pending/reject-all", Op::PendingRejectAll, Gate::Admin, models::REJECT_ALL),
    rb("POST", "/requests/toolkits/{proposal_id}/deploy", Op::ToolkitDeploy, Gate::Admin, models::DEPLOY_BODY),
    rb("POST", "/requests/toolkits/{proposal_id}/reject", Op::ToolkitReject, Gate::Admin, models::REJECT_BODY),
    // extras.py
    rq("GET", "/stats", Op::Stats, STATS_QUERY),
    r("GET", "/documents", Op::Documents, Gate::Viewer),
    r("GET", "/documents/{slug}", Op::Document, Gate::Viewer),
    r("GET", "/oauth/providers", Op::OAuthProviders, Gate::Viewer),
    rb("POST", "/oauth/{provider}/authorize", Op::OAuthAuthorize, Gate::Admin, models::OAUTH_START_BODY),
    // events.py
    r("GET", "/events", Op::Events, Gate::Viewer),
    // The schema (include_in_schema=False).
    RouteDef {
        method: "GET",
        path: "/openapi.json",
        op: Op::OpenApi,
        gate: Gate::AdminRead,
        query: &[],
        body: None,
        in_schema: false,
    },
];

/// Starlette path matching: `{name}` is one non-empty segment.
pub fn match_path(pattern: &str, path: &str) -> Option<HashMap<&'static str, String>>
where
{
    let pat: Vec<&str> = pattern.split('/').collect();
    let got: Vec<&str> = path.split('/').collect();
    if pat.len() != got.len() {
        return None;
    }
    let mut params = HashMap::new();
    for (p, g) in pat.iter().zip(got.iter()) {
        if let Some(name) = p.strip_prefix('{').and_then(|n| n.strip_suffix('}')) {
            if g.is_empty() {
                return None;
            }
            params.insert(leak_name(name), (*g).to_string());
        } else if p != g {
            return None;
        }
    }
    Some(params)
}

/// The parameter names are the routes' own `&'static str` slices.
fn leak_name(name: &str) -> &'static str {
    for route in ROUTES {
        if let Some(pos) = route.path.find(&format!("{{{name}}}")) {
            return &route.path[pos + 1..pos + 1 + name.len()];
        }
    }
    "param"
}

// -- The console --------------------------------------------------------------

/// Knobs that are not deployment configuration (tests set them).
#[derive(Debug, Clone)]
pub struct ConsoleOptions {
    /// Where OAuth codes are exchanged.
    pub token_endpoints: TokenEndpoints,
    /// Where the `/app` build is found.
    pub web_dir: WebDir,
    /// Live-update stream timings.
    pub stream: StreamTimings,
    pub max_subscribers: usize,
    pub queue_limit: usize,
}

impl Default for ConsoleOptions {
    fn default() -> Self {
        ConsoleOptions {
            token_endpoints: TokenEndpoints::default(),
            web_dir: WebDir::Auto,
            stream: StreamTimings::default(),
            max_subscribers: super::events::MAX_SUBSCRIBERS,
            queue_limit: super::events::QUEUE_LIMIT,
        }
    }
}

/// Everything the routes share.
pub struct Console {
    pub ctx: ApiContext,
    pub hub: Arc<EventHub>,
    pub options: ConsoleOptions,
}

/// A response before it becomes an HTTP response.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: ReplyBody,
}

pub enum ReplyBody {
    Json(Value),
    Empty,
    /// `text/plain` 500 from an unhandled error: no security headers, as
    /// Starlette's `ServerErrorMiddleware` sits outside them.
    InternalError,
    Stream(Pin<Box<dyn Stream<Item = String> + Send>>),
}

impl Reply {
    fn json(status: u16, value: Value) -> Reply {
        Reply { status, headers: Vec::new(), body: ReplyBody::Json(value) }
    }

    fn ok(value: Value) -> Reply {
        Reply::json(200, value)
    }

    fn with_etag(mut self, revision: &str) -> Reply {
        self.headers.push(("etag".into(), etag(revision)));
        self
    }
}

fn fail_reply(fail: Fail) -> Reply {
    match fail {
        Fail::Api(ApiError { status, message, headers }) => {
            Reply { status, headers, body: ReplyBody::Json(json!({ "error": message })) }
        }
        Fail::Validation(message) => Reply::json(422, json!({ "error": message })),
        Fail::Internal(detail) => {
            tracing::error!("console API request failed: {detail}");
            Reply { status: 500, headers: Vec::new(), body: ReplyBody::InternalError }
        }
    }
}

fn internal(e: impl std::fmt::Display) -> Fail {
    Fail::Internal(e.to_string())
}

/// `_refused`: a store refusal is a 400 with its own sentence, a "changed
/// since" refusal a 412.
fn refused(e: ConfigError) -> Fail {
    if e.message.contains("changed since") {
        return api(412, "The resource changed since you loaded it. Reload and apply your edit again.");
    }
    api(400, e.message)
}

/// Python's `str(exc)`.
fn exc_text(e: &ConfigError) -> String {
    e.message.clone()
}

fn written(revision: &str) -> (String, Value) {
    let rev = if revision.is_empty() { EMPTY_REVISION.to_string() } else { revision.to_string() };
    (revision.to_string(), Value::String(rev))
}

fn to_http(reply: Reply, security: bool) -> Response {
    let (body, content_type, add_security) = match reply.body {
        ReplyBody::Json(v) => (
            AxumBody::from(crate::pyjson::dumps_with(&v, &crate::pyjson::Opts::compact().ascii(false))),
            Some("application/json"),
            security,
        ),
        ReplyBody::Empty => (AxumBody::empty(), None, security),
        ReplyBody::InternalError => (AxumBody::from("Internal Server Error"), Some("text/plain; charset=utf-8"), false),
        ReplyBody::Stream(s) => (
            AxumBody::from_stream(s.map(|chunk| Ok::<_, std::convert::Infallible>(bytes::Bytes::from(chunk)))),
            Some("text/event-stream; charset=utf-8"),
            security,
        ),
    };
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    if let Some(ct) = content_type {
        headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static(ct));
    }
    for (k, v) in reply.headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
            headers.append(name, value);
        }
    }
    if add_security {
        for (k, v) in SECURITY_HEADERS {
            if !headers.contains_key(k) {
                headers.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
            }
        }
    }
    response
}

/// Percent-decodes a request path the way the ASGI server does.
fn decode_path(raw: &str) -> String {
    percent_encoding::percent_decode_str(raw).decode_utf8_lossy().into_owned()
}

async fn into_api_request(request: Request) -> ApiRequest {
    let (parts, body) = request.into_parts();
    let client_info = parts.extensions.get::<RequestClient>().cloned();
    let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string());
    let client = client_info.as_ref().and_then(|c| c.host.clone()).or(peer);
    let scheme = client_info
        .as_ref()
        .and_then(|c| c.scheme.clone())
        .or_else(|| parts.uri.scheme_str().map(str::to_string))
        .unwrap_or_else(|| "http".to_string());
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.authority().map(|a| a.to_string()))
        .unwrap_or_else(|| "localhost".to_string());
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap_or_default();
    ApiRequest {
        method: parts.method.as_str().to_string(),
        path: decode_path(parts.uri.path()),
        query: parts.uri.query().unwrap_or("").to_string(),
        headers: parts.headers,
        body,
        client,
        scheme,
        host,
    }
}

fn redirect_307(request: &ApiRequest, path: &str) -> Reply {
    let mut location = format!("{}://{}{}", request.scheme, request.host, ui::quote_location(path));
    if !request.query.is_empty() {
        location.push('?');
        location.push_str(&request.query);
    }
    Reply { status: 307, headers: vec![("location".into(), location)], body: ReplyBody::Empty }
}

/// `/api/v1` and below.
pub async fn api_entry(State(console): State<Arc<Console>>, request: Request) -> Response {
    let request = into_api_request(request).await;
    let sub = request.path.strip_prefix(API_PREFIX).unwrap_or("").to_string();
    if sub.is_empty() {
        // The outer router's redirect_slashes: `/api/v1` -> `/api/v1/`.
        return to_http(redirect_307(&request, &format!("{API_PREFIX}/")), false);
    }
    let reply = dispatch(console, request, &sub).await;
    to_http(reply, true)
}

async fn dispatch(console: Arc<Console>, request: ApiRequest, sub: &str) -> Reply {
    let mut partial: Option<&RouteDef> = None;
    for route in ROUTES {
        if let Some(params) = match_path(route.path, sub) {
            if route.method == request.method {
                return run(console, *route, params, request).await;
            }
            if partial.is_none() {
                partial = Some(route);
            }
        }
    }
    if let Some(route) = partial {
        let mut e = ApiError::new(405, "Method Not Allowed");
        e.headers.push(("allow".into(), route.method.into()));
        return fail_reply(Fail::Api(e));
    }
    if sub != "/" {
        let alt = if sub.ends_with('/') { sub.trim_end_matches('/').to_string() } else { format!("{sub}/") };
        if ROUTES.iter().any(|route| match_path(route.path, &alt).is_some()) {
            return redirect_307(&request, &format!("{API_PREFIX}{alt}"));
        }
    }
    fail_reply(api(404, "Not Found"))
}

/// What a handler receives after the gates and validation.
pub struct Call {
    pub request: ApiRequest,
    pub session: Option<Session>,
    pub params: HashMap<&'static str, String>,
    pub query: Vec<QValue>,
    pub body: Map<String, Value>,
}

impl Call {
    fn param(&self, name: &str) -> &str {
        self.params.get(name).map(String::as_str).unwrap_or("")
    }
    fn session(&self) -> &Session {
        self.session.as_ref().expect("gated route")
    }
    fn actor(&self) -> &str {
        &self.session().identity
    }
    fn s(&self, field: &str) -> &str {
        self.body.get(field).and_then(Value::as_str).unwrap_or("")
    }
    fn opt_s(&self, field: &str) -> Option<&str> {
        self.body.get(field).and_then(Value::as_str)
    }
    fn list(&self, field: &str) -> Vec<String> {
        self.body
            .get(field)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    }
    fn sid(&self) -> Option<String> {
        self.request.cookie(SESSION_COOKIE)
    }
}

async fn run(console: Arc<Console>, route: RouteDef, params: HashMap<&'static str, String>, request: ApiRequest) -> Reply {
    let worker = console.clone();
    let joined = tokio::task::spawn_blocking(move || gate_and_handle(&worker, route, params, request)).await;
    match joined {
        Ok(Ok(reply)) => reply,
        Ok(Err(fail)) => fail_reply(fail),
        Err(e) => fail_reply(internal(e)),
    }
}

fn gate_and_handle(
    console: &Console,
    route: RouteDef,
    params: HashMap<&'static str, String>,
    request: ApiRequest,
) -> ApiResult<Reply> {
    let ctx = &console.ctx;
    // 1. The body is read before any dependency runs.
    let body = match route.body {
        None => Body::Missing,
        Some(_) => match read_body(request.header("content-type").as_deref(), &request.body) {
            Ok(body) => body,
            Err(BodyError::Decode(pos)) => return Err(Fail::Validation(format!("{pos}: JSON decode error"))),
            Err(BodyError::Unreadable) => return Err(api(400, "There was an error parsing the body")),
        },
    };
    // 2. The session dependencies.
    let session = match route.gate {
        Gate::None => None,
        Gate::Viewer => Some(require_viewer(ctx, &request)?),
        Gate::Csrf => Some(require_csrf(ctx, &request)?),
        Gate::Admin => Some(require_admin(ctx, &request)?),
        Gate::SessionWrite => Some(require_session_write(ctx, &request)?),
        Gate::AdminRead => Some(require_admin_read(ctx, &request)?),
    };
    // 3. Query parameters, then the body.
    let query = validate_query(&request.query, route.query).map_err(Fail::Validation)?;
    let body = match route.body {
        None => Map::new(),
        Some(model) => validate(model, &body).map_err(Fail::Validation)?,
    };
    let call = Call { request, session, params, query, body };
    handle(console, route.op, &call)
}

fn handle(console: &Console, op: Op, call: &Call) -> ApiResult<Reply> {
    let ctx = &console.ctx;
    match op {
        Op::SessionGet => Ok(Reply::ok(session_info(ctx, call.session()))),
        Op::SessionCreate => session_create(ctx, call),
        Op::SessionDelete => {
            ctx.sessions.destroy(call.sid().as_deref());
            let expires = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
            Ok(Reply {
                status: 204,
                headers: vec![(
                    "set-cookie".into(),
                    format!("{SESSION_COOKIE}=\"\"; expires={expires}; Max-Age=0; Path={API_PREFIX}; SameSite=lax"),
                )],
                body: ReplyBody::Empty,
            })
        }
        Op::Account => {
            let session = call.session();
            let reply = Reply::ok(json!({
                "identity": session.identity, "role": session.role,
                "can_change_password": !ctx.read_only(),
            }));
            Ok(match &ctx.store {
                // The `If-Match` for `PUT /account/password`.
                Some(store) => reply.with_etag(&store.identities_revision()),
                None => reply,
            })
        }
        Op::Overview => {
            let identities = ctx.identities.read();
            let view = rm::overview_view(
                &ctx.service,
                &identities,
                ctx.store.as_deref(),
                ctx.pending.as_deref(),
                ctx.toolkit_proposals.as_deref(),
                None,
            )
            .map_err(internal)?;
            Ok(Reply::ok(view))
        }
        Op::Tools => {
            let view = rm::tools_view(&ctx.service, &ctx.identities.read());
            Ok(etag_if_store(ctx, Reply::ok(view), |s| s.tools_revision()))
        }
        Op::Tool => {
            let tool_id = call.param("tool_id");
            let Some(detail) = rm::tool_detail(&ctx.service, &ctx.identities.read(), tool_id) else {
                return Err(api(404, format!("No tool definition with ID {}.", repr_str(tool_id))));
            };
            Ok(etag_if_store(ctx, Reply::ok(detail), |s| s.tools_revision()))
        }
        Op::Identities => {
            let view = rm::identities_view(&ctx.service, &ctx.identities.read());
            Ok(etag_if_store(ctx, Reply::ok(Value::Array(view)), |s| s.identities_revision()))
        }
        Op::Credentials => credentials_list(ctx),
        Op::Toolkits => {
            let tier1 = ctx.service.tier1();
            let mut destinations: Vec<&String> = tier1.destinations.keys().collect();
            destinations.sort();
            Ok(Reply::ok(json!({"toolkits": rm::toolkit_summaries(&tier1), "destinations": destinations})))
        }
        Op::ToolkitReference => Ok(Reply::ok(Value::Array(rm::toolkit_reference_view()))),
        Op::RequestsPending => {
            let items = rm::pending_view(
                ctx.store.as_deref(),
                ctx.pending.as_deref(),
                call.query[0].str(),
                ctx.credentials.as_deref(),
            )
            .map_err(internal)?;
            let reply = Reply::ok(Value::Array(items));
            Ok(match &ctx.pending {
                Some(pending) => reply.with_etag(&pending.revision()),
                None => reply,
            })
        }
        Op::RequestsDecided => {
            let limit = call.query[0].int().unwrap_or(25) as usize;
            match rm::decided_pending_page(
                ctx.store.as_deref(),
                ctx.pending.as_deref(),
                limit,
                call.query[1].str(),
                ctx.credentials.as_deref(),
            ) {
                Ok(page) => Ok(Reply::ok(page)),
                Err(None) => Err(api(400, "Invalid cursor.")),
                Err(Some(e)) => Err(internal(e)),
            }
        }
        Op::RequestsToolkits => {
            let reply_etag = ctx.toolkit_proposals.as_ref().map(|p| p.revision());
            let view = rm::toolkit_proposals_view(&ctx.service, ctx.toolkit_proposals.as_deref(), call.query[0].str())
                .map_err(internal)?;
            let reply = Reply::ok(Value::Array(view));
            Ok(match reply_etag {
                Some(rev) => reply.with_etag(&rev),
                None => reply,
            })
        }
        Op::Audit => {
            let filter = rm::AuditFilter {
                identity: call.query[0].str().unwrap_or("").to_string(),
                tool: call.query[1].str().unwrap_or("").to_string(),
                outcome: call.query[2].str().unwrap_or("").to_string(),
                since: None,
            };
            let limit = call.query[3].int().unwrap_or(100) as usize;
            match rm::audit_page(&ctx.service, limit, call.query[4].str(), &filter) {
                Some(page) => Ok(Reply::ok(page)),
                None => Err(api(400, "Invalid cursor.")),
            }
        }
        Op::ReleaseNotes => {
            let (releases, total) =
                crate::release_notes::query(call.query[0].str(), call.query[1].str(), call.query[2].int());
            let releases: Vec<Value> = releases.iter().map(|r| rm::project(r, &["version", "notes"])).collect();
            Ok(Reply::ok(json!({"version": crate::VERSION, "releases": releases, "total": total})))
        }
        Op::ToolScaffold => {
            if ctx.service.tier1().toolkits.is_empty() {
                return Err(api(409, "No toolkit is configured, so there is nothing a tool could build on."));
            }
            Ok(Reply::ok(json!({"yaml": rm::tool_scaffold(&ctx.service)})))
        }
        Op::ToolCreate | Op::ToolUpdate => tool_save(ctx, op, call),
        Op::ToolEnable => {
            let store = writable_store(ctx)?;
            let rev = if_match(&call.request, &store.tools_revision())?;
            let enabled = call.body.get("enabled").and_then(Value::as_bool).unwrap_or(false);
            store
                .set_tool_enabled(&definition_id(ctx, call.param("tool_id")), enabled, call.actor(), &rev)
                .map_err(refused)?;
            Ok(written_reply(200, &store.tools_revision(), Map::new()))
        }
        Op::ToolDelete => {
            let store = writable_store(ctx)?;
            let rev = if_match(&call.request, &store.tools_revision())?;
            store.delete_tool(&definition_id(ctx, call.param("tool_id")), call.actor(), &rev).map_err(refused)?;
            Ok(written_reply(200, &store.tools_revision(), Map::new()))
        }
        Op::IdentityCreate => {
            let store = writable_store(ctx)?;
            let rev = if_match(&call.request, &store.identities_revision())?;
            let (id, role, tools, scopes) = clean_identity(call);
            let token = store
                .create_identity(&id, &role, &tools, &scopes, call.actor(), &rev, call.s("password"))
                .map_err(refused)?;
            let mut extra = Map::new();
            extra.insert("identity".into(), Value::String(id));
            extra.insert("token".into(), Value::String(token));
            Ok(written_reply(201, &store.identities_revision(), extra))
        }
        Op::IdentityUpdate => {
            let store = writable_store(ctx)?;
            let rev = if_match(&call.request, &store.identities_revision())?;
            let replaces = call.param("identity_id");
            let (id, role, tools, scopes) = clean_identity(call);
            let password = call.s("password");
            store
                .save_identity(&id, &role, &tools, &scopes, call.actor(), &rev, Some(replaces), password)
                .map_err(refused)?;
            rm::drop_sessions_after_identity_update(
                &ctx.sessions,
                replaces,
                &id,
                &role,
                !password.is_empty(),
                call.actor(),
                call.sid().as_deref(),
            );
            Ok(written_reply(200, &store.identities_revision(), Map::new()))
        }
        Op::IdentityRotate => {
            let store = writable_store(ctx)?;
            let rev = if_match(&call.request, &store.identities_revision())?;
            let identity_id = call.param("identity_id");
            let token = store.rotate_token(identity_id, call.actor(), &rev).map_err(refused)?;
            if identity_id != call.actor() {
                ctx.sessions.drop_identity(identity_id, None);
            }
            let mut extra = Map::new();
            extra.insert("identity".into(), Value::String(identity_id.to_string()));
            extra.insert("token".into(), Value::String(token));
            Ok(written_reply(200, &store.identities_revision(), extra))
        }
        Op::IdentityDelete => {
            let store = writable_store(ctx)?;
            let rev = if_match(&call.request, &store.identities_revision())?;
            let identity_id = call.param("identity_id");
            store.delete_identity(identity_id, call.actor(), &rev).map_err(refused)?;
            ctx.sessions.drop_identity(identity_id, None);
            Ok(written_reply(200, &store.identities_revision(), Map::new()))
        }
        Op::CredentialCreate => {
            let store = credential_store(ctx)?;
            let rev = if_match(&call.request, &store.revision())?;
            let name = py_strip(call.s("name")).to_string();
            let probe_url = non_blank(call.opt_s("probe_url"));
            store
                .create(
                    &name,
                    call.s("kind"),
                    call.s("value"),
                    non_blank(call.opt_s("header")).as_deref(),
                    probe_url.as_deref(),
                    non_blank(call.opt_s("header_format")).as_deref(),
                    call.actor(),
                    &rev,
                )
                .map_err(refused)?;
            if probe_url.is_some() {
                rm::schedule_credential_probe(store.clone(), name);
            }
            Ok(written_reply(201, &store.revision(), Map::new()))
        }
        Op::CredentialRotate => {
            let store = credential_store(ctx)?;
            let rev = if_match(&call.request, &store.revision())?;
            let name = call.param("name");
            let overlap = call.body.get("overlap_seconds").and_then(Value::as_i64).unwrap_or(0);
            store.rotate(name, call.s("value"), overlap, call.actor(), &rev).map_err(refused)?;
            let probed = store
                .names(None)
                .map_err(internal)?
                .iter()
                .any(|m| m.name == name && m.probe_url.as_deref().is_some_and(|u| !u.is_empty()));
            if probed {
                rm::schedule_credential_probe(store.clone(), name.to_string());
            }
            Ok(written_reply(200, &store.revision(), Map::new()))
        }
        Op::CredentialDelete => {
            let store = credential_store(ctx)?;
            let rev = if_match(&call.request, &store.revision())?;
            store.delete(call.param("name"), call.actor(), &rev).map_err(refused)?;
            Ok(written_reply(200, &store.revision(), Map::new()))
        }
        Op::AccountPassword => {
            let store = writable_store(ctx)?;
            let rev = if_match(&call.request, &store.identities_revision())?;
            let me = call.actor();
            if let Err(exc) = store.set_password(me, call.s("password"), me, &rev, call.s("current"), true) {
                // A wrong current password is a failed attempt and belongs
                // in the log.
                ctx.audit.auth_failure(
                    "ui_password_change_failed",
                    &format!("identity={}: {}", repr_str(me), exc_text(&exc)),
                    Map::new(),
                )?;
                return Err(refused(exc));
            }
            ctx.sessions.drop_identity(me, call.sid().as_deref());
            Ok(written_reply(200, &store.identities_revision(), Map::new()))
        }
        Op::PendingApprove => pending_approve(ctx, call),
        Op::PendingCredential => pending_credential(ctx, call),
        Op::PendingReject => {
            let queue = pending_queue(ctx)?;
            let item_id = call.param("item_id");
            pending_item(queue, item_id)?;
            queue.reject(item_id, call.actor(), call.s("reason")).map_err(refused)?;
            decided(item_id, &pending_item(queue, item_id)?.status)
        }
        Op::PendingApproveAll => {
            let queue = pending_queue(ctx)?;
            let wanted: HashSet<String> = call.list("ids").into_iter().collect();
            let batch: Vec<_> = queue
                .list(None)
                .map_err(internal)?
                .into_iter()
                .filter(|i| wanted.contains(&i.id) && i.status == "pending" && i.action != "cred_propose")
                .collect();
            let store = writable_store(ctx)?;
            let (mut applied, mut refusals) = (0, Vec::new());
            for item in batch {
                match crate::admin_service::apply_pending(store, queue, &item.id, call.actor(), ctx.credentials.as_deref())
                {
                    Ok(_) => applied += 1,
                    Err(exc) => refusals.push(json!({"id": item.id, "action": item.action, "reason": exc_text(&exc)})),
                }
            }
            Ok(Reply::ok(json!({"applied": applied, "refused": refusals})))
        }
        Op::PendingRejectAll => {
            let queue = pending_queue(ctx)?;
            let wanted: HashSet<String> = call.list("ids").into_iter().collect();
            let batch: Vec<_> = queue
                .list(None)
                .map_err(internal)?
                .into_iter()
                .filter(|i| wanted.contains(&i.id) && i.status == "pending")
                .collect();
            let (mut rejected, mut refusals) = (0, Vec::new());
            for item in batch {
                match queue.reject(&item.id, call.actor(), call.s("reason")) {
                    Ok(_) => rejected += 1,
                    Err(exc) => refusals.push(json!({"id": item.id, "action": item.action, "reason": exc_text(&exc)})),
                }
            }
            Ok(Reply::ok(json!({"rejected": rejected, "refused": refusals})))
        }
        Op::ToolkitDeploy | Op::ToolkitReject => {
            let Some(queue) = ctx.toolkit_proposals.as_deref() else {
                return Err(api(409, "No toolkit-proposal queue is configured on this deployment."));
            };
            let proposal_id = call.param("proposal_id");
            let exists = |queue: &crate::toolkit_proposals::ToolkitProposalStore| -> ApiResult<String> {
                match queue.get(proposal_id).map_err(internal)? {
                    Some(item) => Ok(item.status),
                    None => Err(api(404, format!("No proposal {}.", repr_str(proposal_id)))),
                }
            };
            exists(queue)?;
            if op == Op::ToolkitDeploy {
                queue.deploy(proposal_id, call.actor()).map_err(refused)?;
            } else {
                queue.reject(proposal_id, call.actor(), call.s("reason")).map_err(refused)?;
            }
            decided(proposal_id, &exists(queue)?)
        }
        Op::Stats => Ok(Reply::ok(rm::stats_view(&ctx.service, call.query[0].str().unwrap_or("24h")))),
        Op::Documents => Ok(Reply::ok(Value::Array(rm::docs_index()))),
        Op::Document => {
            let slug = call.param("slug");
            match rm::doc_text(slug) {
                Some(doc) => Ok(Reply::ok(doc)),
                None => Err(api(404, format!("No document {}.", repr_str(slug)))),
            }
        }
        Op::OAuthProviders => {
            let views = crate::oauth::providers_view(&ctx.service.tier1());
            Ok(Reply::ok(serde_json::to_value(views).map_err(internal)?))
        }
        Op::OAuthAuthorize => {
            let tier1 = ctx.service.tier1();
            let start = StartContext {
                tier1: &tier1,
                audit: &ctx.audit,
                credentials: ctx.credentials.as_deref(),
                states: ctx.oauth_states.as_deref(),
            };
            match crate::oauth::start_authorize(
                &start,
                call.param("provider"),
                call.s("credential"),
                call.actor(),
                &call.request.base_url(),
            ) {
                Ok(started) => Ok(Reply::ok(serde_json::to_value(started).map_err(internal)?)),
                Err(StartError::Api { status, message }) => Err(api(status, message)),
                Err(StartError::Store(e)) => Err(internal(e)),
                Err(StartError::Audit(e)) => Err(internal(e)),
            }
        }
        Op::Events => events(console, call),
        Op::OpenApi => {
            let schema: Value = serde_json::from_str(OPENAPI_JSON).map_err(internal)?;
            Ok(Reply::ok(schema))
        }
    }
}

fn etag_if_store(ctx: &ApiContext, reply: Reply, rev: impl Fn(&crate::store::ConfigStore) -> String) -> Reply {
    match &ctx.store {
        Some(store) => reply.with_etag(&rev(store)),
        None => reply,
    }
}

fn session_info(ctx: &ApiContext, session: &Session) -> Value {
    json!({
        "identity": session.identity,
        "role": session.role,
        "can_write": ctx.can_write(session),
        "read_only": ctx.read_only(),
        "csrf": session.csrf,
        "version": crate::VERSION,
    })
}

/// `POST /session`: sign in with the console password (FR-11.5), never the
/// API token. JSON only; the failure message never says which half was
/// wrong -- the audit log has it in full.
fn session_create(ctx: &ApiContext, call: &Call) -> ApiResult<Reply> {
    let request = &call.request;
    if request.headers.contains_key("authorization") {
        ctx.audit.auth_failure("api_bearer_rejected", &format!("POST {}", request.path), Map::new())?;
        return Err(api(401, "Bearer tokens are not accepted here; sign in to the console."));
    }
    if !request.header("content-type").unwrap_or_default().starts_with("application/json") {
        return Err(api(415, "Send the credentials as application/json."));
    }
    let client = request.client_or_unknown();
    if ctx.throttle.blocked(&client) {
        ctx.audit.auth_failure("ui_login_throttled", &client, Map::new())?;
        return Err(api(429, "Too many failed attempts. Try again later."));
    }
    let supplied: String = py_strip(call.s("identity")).chars().take(64).collect();
    let password = call.s("password");
    let identity = if !supplied.is_empty() && !password.is_empty() {
        ctx.identities.read().authenticate_console(&supplied, password).map(|i| (i.id.clone(), i.role.clone()))
    } else {
        None
    };
    let Some((identity_id, role)) = identity else {
        ctx.throttle.record_failure(&client);
        ctx.audit.auth_failure("ui_login_failed", &format!("identity={} from {client}", repr_str(&supplied)), Map::new())?;
        return Err(api(401, "Sign-in failed."));
    };
    ctx.throttle.reset(&client);
    let sid = ctx.sessions.create(&identity_id, &role);
    ctx.audit.write(json!({
        "kind": "ui_login", "identity": identity_id, "role": role, "client": client, "surface": "api",
    }))?;
    let secure = if request.scheme == "https" { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE}={sid}; HttpOnly; Max-Age={}; Path={API_PREFIX}; SameSite=strict{secure}",
        ctx.sessions.ttl()
    );
    let session = ctx.sessions.resolve(Some(&sid)).ok_or_else(|| internal("session vanished"))?;
    let mut reply = Reply::ok(session_info(ctx, &session));
    reply.headers.push(("set-cookie".into(), cookie));
    Ok(reply)
}

fn credentials_list(ctx: &ApiContext) -> ApiResult<Reply> {
    let tier1 = ctx.service.tier1();
    let refs = tier1.credential_references();
    let mut names: Vec<&String> = refs.keys().collect();
    names.sort();
    let Some(credentials) = &ctx.credentials else {
        return Ok(Reply::ok(json!({"configured": false, "credentials": [], "dangling": names})));
    };
    let metas = rm::credential_summaries(credentials, &tier1).map_err(internal)?;
    let held: HashSet<&str> = metas.iter().filter_map(|m| m["name"].as_str()).collect();
    let dangling: Vec<&&String> = names.iter().filter(|n| !held.contains(n.as_str())).collect();
    Ok(Reply::ok(json!({"configured": true, "credentials": metas, "dangling": dangling})).with_etag(&credentials.revision()))
}

fn writable_store(ctx: &ApiContext) -> ApiResult<&Arc<crate::store::ConfigStore>> {
    // `require_admin`/`require_session_write` already refused read-only.
    ctx.store.as_ref().ok_or_else(|| api(403, "The console is read-only."))
}

fn credential_store(ctx: &ApiContext) -> ApiResult<&Arc<crate::credentials::CredentialStore>> {
    ctx.credentials
        .as_ref()
        .ok_or_else(|| api(409, "No credential store is configured (GATEKEEPER_CREDENTIAL_KEY is not set)."))
}

/// `(x or "").strip() or None`.
fn non_blank(value: Option<&str>) -> Option<String> {
    let v = py_strip(value.unwrap_or(""));
    (!v.is_empty()).then(|| v.to_string())
}

/// `Written` (and its subclasses): `revision` first, then the subclass's
/// fields; the revision is also the `ETag`.
fn written_reply(status: u16, revision: &str, extra: Map<String, Value>) -> Reply {
    let (raw, value) = written(revision);
    let mut body = Map::new();
    body.insert("revision".into(), value);
    body.extend(extra);
    Reply { status, headers: vec![("etag".into(), etag(&raw))], body: ReplyBody::Json(Value::Object(body)) }
}

/// The ID a write targets: `<id>@<destination>` edits the bare entry.
fn definition_id(ctx: &ApiContext, tool_id: &str) -> String {
    let catalog = ctx.service.catalog();
    match catalog.tools.get(tool_id).and_then(|t| t.destination.as_ref()) {
        Some(destination) if tool_id.len() > destination.len() => tool_id[..tool_id.len() - destination.len() - 1].to_string(),
        _ => tool_id.to_string(),
    }
}

fn tool_save(ctx: &ApiContext, op: Op, call: &Call) -> ApiResult<Reply> {
    let store = writable_store(ctx)?;
    let rev = if_match(&call.request, &store.tools_revision())?;
    let spec = crate::store::load_tool_yaml(call.s("yaml")).map_err(refused)?;
    let replaces = (op == Op::ToolUpdate).then(|| definition_id(ctx, call.param("tool_id")));
    let tool_id = store.save_tool(&spec, call.actor(), &rev, replaces.as_deref()).map_err(refused)?;
    let mut extra = Map::new();
    extra.insert("id".into(), Value::String(tool_id));
    Ok(written_reply(if op == Op::ToolCreate { 201 } else { 200 }, &store.tools_revision(), extra))
}

/// `_clean`: the ID stripped, blank scopes dropped.
fn clean_identity(call: &Call) -> (String, String, Vec<String>, Vec<String>) {
    let scopes: Vec<String> =
        call.list("scopes").iter().map(|s| py_strip(s).to_string()).filter(|s| !s.is_empty()).collect();
    (py_strip(call.s("id")).to_string(), call.s("role").to_string(), call.list("tools"), scopes)
}

fn pending_queue(ctx: &ApiContext) -> ApiResult<&crate::pending::PendingStore> {
    ctx.pending.as_deref().ok_or_else(|| api(409, "No pending queue is configured on this deployment."))
}

fn pending_item(queue: &crate::pending::PendingStore, item_id: &str) -> ApiResult<crate::pending::PendingAction> {
    match queue.get(item_id).map_err(internal)? {
        Some(item) => Ok(item),
        None => Err(api(404, format!("No proposal {}.", repr_str(item_id)))),
    }
}

fn decided(id: &str, status: &str) -> ApiResult<Reply> {
    Ok(Reply::ok(json!({"id": id, "status": status})))
}

/// Applies one proposal through `apply_pending`, which refuses a stale one.
/// A credential proposal needs its value: `/credential` instead.
fn pending_approve(ctx: &ApiContext, call: &Call) -> ApiResult<Reply> {
    let queue = pending_queue(ctx)?;
    let item_id = call.param("item_id");
    let item = pending_item(queue, item_id)?;
    if item.action == "cred_propose" {
        return Err(api(400, "A credential proposal needs a value; approve it with POST .../credential."));
    }
    let store = writable_store(ctx)?;
    crate::admin_service::apply_pending(store, queue, item_id, call.actor(), ctx.credentials.as_deref())
        .map_err(refused)?;
    if item.action == "cred_update" && rm::truthy(item.payload.get("probe_url")) {
        if let Some(credentials) = &ctx.credentials {
            let name = item.payload.get("new_name").filter(|v| rm::truthy(Some(v))).or_else(|| item.payload.get("name"));
            let name = match name {
                Some(v) if rm::truthy(Some(v)) => crate::pyfmt::str_value(v),
                _ => String::new(),
            };
            rm::schedule_credential_probe(credentials.clone(), name);
        }
    }
    decided(item_id, &pending_item(queue, item_id)?.status)
}

/// Approves a `cred_propose` with the value a human types now. The agent
/// never sees or supplies the value (FR-10.2).
fn pending_credential(ctx: &ApiContext, call: &Call) -> ApiResult<Reply> {
    let queue = pending_queue(ctx)?;
    let Some(credentials) = ctx.credentials.as_ref() else {
        return Err(api(409, "No credential store is configured (GATEKEEPER_CREDENTIAL_KEY is not set)."));
    };
    let item_id = call.param("item_id");
    let item = pending_item(queue, item_id)?;
    if item.action != "cred_propose" {
        return Err(api(400, "Only a credential proposal takes a value."));
    }
    let name = match item.payload.get("name") {
        Some(v) if rm::truthy(Some(v)) => crate::pyfmt::str_value(v),
        _ => String::new(),
    };
    let taken = credentials.names(None).map_err(internal)?.iter().any(|m| m.name == name);
    if item.status == "pending" && taken {
        // Taken since it was proposed: close it now instead of leaving it
        // pending.
        queue.close_taken_credentials(&HashSet::from([name.clone()]), call.actor()).map_err(internal)?;
        return Err(api(409, format!("A credential named {} exists now; this proposal was marked stale.", repr_str(&name))));
    }
    let value = call.s("value").to_string();
    let actor = call.actor().to_string();
    queue
        .approve(
            item_id,
            &actor,
            |_item| credentials.revision(),
            |i| -> Result<(), ConfigError> {
                let field = |k: &str| i.payload.get(k).and_then(Value::as_str).map(str::to_string);
                let (Some(p_name), Some(kind)) = (field("name"), field("kind")) else {
                    // PORT NOTE: Python raised KeyError here (HTTP 500).
                    return Err(ConfigError::refused("The proposal's payload is malformed: missing name or kind."));
                };
                credentials.create(
                    &p_name,
                    &kind,
                    &value,
                    field("header").as_deref(),
                    field("probe_url").as_deref(),
                    field("header_format").as_deref(),
                    &actor,
                    &credentials.revision(),
                )
            },
        )
        .map_err(refused)?;
    if rm::truthy(item.payload.get("probe_url")) {
        rm::schedule_credential_probe(credentials.clone(), name);
    }
    decided(item_id, &pending_item(queue, item_id)?.status)
}

/// `GET /events`: Server-Sent Events naming stale topics, never data.
fn events(console: &Console, call: &Call) -> ApiResult<Reply> {
    let Some(sub) = console.hub.subscribe() else {
        return Err(api(503, "Too many live-update streams are open; the console falls back to polling."));
    };
    let sessions = console.ctx.sessions.clone();
    let sid = call.sid();
    let session = call.session().clone();
    let still_signed_in = move || sessions.resolve(sid.as_deref()).as_ref() == Some(&session);
    let body = super::events::stream(console.hub.clone(), sub, still_signed_in, console.options.stream);
    Ok(Reply {
        status: 200,
        // nginx and friends buffer a response unless told not to.
        headers: vec![("x-accel-buffering".into(), "no".into())],
        body: ReplyBody::Stream(Box::pin(body)),
    })
}

// -- /app ------------------------------------------------------------------------

pub async fn web_entry(State(console): State<Arc<Console>>, request: Request) -> Response {
    let method = request.method().as_str().to_string();
    let path = decode_path(request.uri().path());
    let accept = request
        .headers()
        .get(http::header::ACCEPT_ENCODING)
        .map(|v| v.as_bytes().iter().map(|&b| b as char).collect::<String>())
        .unwrap_or_default();
    let dir = console.options.web_dir.clone();
    tokio::task::spawn_blocking(move || web::handle(&method, &path, &accept, &dir))
        .await
        .unwrap_or_else(|_| to_http(Reply { status: 500, headers: Vec::new(), body: ReplyBody::InternalError }, false))
}

// -- /ui, /, /favicon.ico and the OAuth callbacks ---------------------------------

fn plain(status: u16, body: &'static str, headers: Vec<(String, String)>) -> Response {
    let mut response = Response::new(AxumBody::from(body));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    for (k, v) in headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

fn redirect(status: u16, location: &str) -> Response {
    let mut response = Response::new(AxumBody::empty());
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::SEE_OTHER);
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(http::header::LOCATION, value);
    }
    response
}

pub async fn ui_entry(State(console): State<Arc<Console>>, request: Request) -> Response {
    let method = request.method().as_str().to_string();
    let path = decode_path(request.uri().path());
    let query = request.uri().query().unwrap_or("").to_string();
    match ui::route(&method, &path, &query) {
        UiRoute::OAuthCallback(spec) => {
            let ctx = &console.ctx;
            let identities = ctx.identities.clone();
            let is_admin = move |actor: &str| {
                identities.read().identities.get(actor).is_some_and(|i| i.role == ADMIN_ROLE)
            };
            let fallback_states;
            let states = match &ctx.oauth_states {
                Some(states) => states.as_ref(),
                None => {
                    fallback_states = crate::oauth::OAuthStateStore::new();
                    &fallback_states
                }
            };
            let callback_ctx = CallbackContext {
                audit: &ctx.audit,
                credentials: ctx.credentials.as_deref(),
                has_config_store: ctx.store.is_some(),
                is_admin: &is_admin,
                states,
                endpoints: &console.options.token_endpoints,
            };
            match crate::oauth::callback(&callback_ctx, spec, &CallbackQuery::parse(&query)).await {
                Ok(done) => redirect(done.status, &ui::quote_location(&done.location)),
                Err(e) => {
                    tracing::error!("OAuth callback failed: {e}");
                    plain(500, "Internal Server Error", Vec::new())
                }
            }
        }
        UiRoute::Respond(UiResponse::Redirect { status, location }) => redirect(status, &location),
        UiRoute::Respond(UiResponse::Gone { status, body }) => plain(status, body, Vec::new()),
        UiRoute::MethodNotAllowed => {
            let allow = if path == "/" || path == "/favicon.ico" { "GET, HEAD" } else { "GET, HEAD, POST, PUT, PATCH, DELETE" };
            plain(405, "Method Not Allowed", vec![("allow".into(), allow.into())])
        }
        UiRoute::NotMatched => plain(404, "Not Found", Vec::new()),
    }
}
