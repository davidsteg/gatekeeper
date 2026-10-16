//! The handshake-era Streamable HTTP transport
//! (`StreamableHTTPServerTransport`) and the session manager around it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use axum::body::{Body, HttpBody};
use axum::response::Response;
use http::{HeaderValue, Method, StatusCode};
use parking_lot::Mutex;
use serde_json::{Map, Value};
use futures::StreamExt;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::handler::{RequestContext, SessionChannel};
use super::jsonrpc::{self, Message};
use super::kernel::Conn;
use super::types::{
    ErrorData, RidKey, DEFAULT_NEGOTIATED_VERSION, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST,
    LAST_EVENT_ID_HEADER, MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID_HEADER, PARSE_ERROR, REQUEST_CANCELLED,
};
use super::{check_accept, security_check, sse, Inbound, Mount};

/// `REQUEST_STREAM_BUFFER_SIZE`.
const STREAM_BUFFER: usize = 16;

#[derive(Default)]
pub(crate) struct SessionMap {
    map: Mutex<HashMap<String, Arc<Session>>>,
}

impl SessionMap {
    fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.map.lock().get(id).cloned()
    }

    /// `_discard_session`: stop tracking the session (its id answers 404
    /// from now on) and make sure its transport refuses anything that still
    /// reaches it.
    fn discard(&self, session: &Arc<Session>) {
        if let Some(id) = &session.id {
            self.map.lock().remove(id);
        }
        if !session.is_terminated() {
            session.terminate();
        }
    }
}

/// The idle countdown of a stateful session (`idle_scope` plus
/// `_requests_in_flight`): suspended while any request is being served
/// (an open GET stream included), restarted when the last one completes.
struct IdleState {
    in_flight: usize,
    /// `None` while suspended (the scope's `math.inf`).
    deadline: Option<Instant>,
    /// The countdown ran out (`idle_scope.cancel_called`).
    expired: bool,
}

struct Idle {
    timeout: Duration,
    state: Mutex<IdleState>,
    changed: Notify,
}

/// Holds one request in flight; dropping it (when the response, streamed
/// or not, is done) restarts the countdown if it was the last one.
struct InFlight(Arc<Session>);

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(idle) = &self.0.idle {
            let mut st = idle.state.lock();
            st.in_flight = st.in_flight.saturating_sub(1);
            if st.in_flight == 0 {
                st.deadline = Some(Instant::now() + idle.timeout);
            }
            drop(st);
            idle.changed.notify_one();
        }
    }
}

/// One handshake-era connection. On the stateful mount it lives in the
/// session map until it is discarded (DELETE, idle timeout, a refused
/// opening request); on the stateless mount it lives for one request.
pub(crate) struct Session {
    id: Option<String>,
    conn: Conn,
    terminated: AtomicBool,
    /// Cancelled on termination: every open stream of the session ends.
    closed: CancellationToken,
    standalone: Mutex<Option<(u64, mpsc::Sender<Value>)>>,
    standalone_gen: AtomicU64,
    inflight: Mutex<HashMap<RidKey, CancellationToken>>,
    /// Stateful sessions with an idle timeout only.
    idle: Option<Idle>,
    /// Whether this connection has a standalone channel at all (not on the
    /// stateless mount).
    has_channel: bool,
}

impl SessionChannel for Session {
    fn send_tool_list_changed(&self) -> Result<(), ()> {
        if self.terminated.load(Ordering::SeqCst) {
            return Err(());
        }
        if let Some((_, tx)) = &*self.standalone.lock() {
            if tx.try_send(jsonrpc::notification("notifications/tools/list_changed", None)).is_err() {
                tracing::debug!("dropped tools/list_changed: standalone stream full or closed");
            }
        }
        Ok(())
    }
}

impl Session {
    fn new(id: Option<String>, conn: Conn, has_channel: bool, idle_timeout: Option<Duration>) -> Self {
        Session {
            id,
            conn,
            terminated: AtomicBool::new(false),
            closed: CancellationToken::new(),
            standalone: Mutex::new(None),
            standalone_gen: AtomicU64::new(0),
            inflight: Mutex::new(HashMap::new()),
            idle: idle_timeout.map(|timeout| Idle {
                timeout,
                state: Mutex::new(IdleState { in_flight: 0, deadline: None, expired: false }),
                changed: Notify::new(),
            }),
            has_channel,
        }
    }

    pub(crate) fn is_terminated(&self) -> bool {
        self.terminated.load(Ordering::SeqCst)
    }

    fn terminate(&self) {
        self.terminated.store(true, Ordering::SeqCst);
        tracing::info!("Terminating session: {:?}", self.id);
        self.closed.cancel();
        *self.standalone.lock() = None;
        for (_, token) in self.inflight.lock().drain() {
            token.cancel();
        }
    }

    fn error_response(&self, message: &str, status: StatusCode, code: i64, extra: &[(&'static str, &'static str)]) -> Response {
        let body = jsonrpc::legacy_text(&jsonrpc::error(None, &ErrorData::new(code, message)));
        let mut r = Response::new(Body::from(body));
        *r.status_mut() = status;
        let h = r.headers_mut();
        h.insert("content-type", HeaderValue::from_static("application/json"));
        for (k, v) in extra {
            h.insert(*k, HeaderValue::from_static(v));
        }
        self.add_session_header(&mut r);
        r
    }

    fn empty_json(&self, status: StatusCode) -> Response {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = status;
        r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
        self.add_session_header(&mut r);
        r
    }

    fn add_session_header(&self, r: &mut Response) {
        if let Some(id) = &self.id {
            if let Ok(v) = HeaderValue::from_str(id) {
                r.headers_mut().insert(MCP_SESSION_ID_HEADER, v);
            }
        }
    }

    fn context(self: &Arc<Self>, inbound: &Inbound, method: &str, request_id: Option<Value>) -> RequestContext {
        RequestContext {
            extensions: inbound.extensions.clone(),
            headers: inbound.headers.clone(),
            peer: inbound.peer,
            session_id: self.id.clone(),
            request_id,
            method: method.to_string(),
            protocol_version: self.conn.version(),
            channel: if self.has_channel { Some(self.clone() as Arc<dyn SessionChannel>) } else { None },
        }
    }

    /// `_validate_session`: `Err` is the response to send.
    fn validate_session(&self, inbound: &Inbound) -> Result<(), Response> {
        let Some(id) = &self.id else { return Ok(()) };
        match inbound.header(MCP_SESSION_ID_HEADER).filter(|s| !s.is_empty()) {
            None => Err(self.error_response("Bad Request: Missing session ID", StatusCode::BAD_REQUEST, INVALID_REQUEST, &[])),
            Some(h) if h != *id => Err(self.error_response(
                "Not Found: Invalid or expired session ID",
                StatusCode::NOT_FOUND,
                INVALID_REQUEST,
                &[],
            )),
            Some(_) => Ok(()),
        }
    }

    /// `handle_request`: with an idle timeout, the request holds the
    /// session open until its response (a whole SSE stream included) is
    /// done.
    pub(crate) async fn handle(self: &Arc<Self>, mount: &Mount, inbound: Inbound) -> Response {
        let Some(idle) = &self.idle else { return self.handle_inner(mount, inbound).await };
        let expired = {
            let mut st = idle.state.lock();
            if !st.expired {
                st.in_flight += 1;
                st.deadline = None;
            }
            st.expired
        };
        if expired {
            // The idle period already ran out and the session is ending:
            // answer as terminated.
            if !self.is_terminated() {
                self.terminate();
            }
            return self.handle_inner(mount, inbound).await;
        }
        let guard = InFlight(self.clone());
        let response = self.handle_inner(mount, inbound).await;
        if response.body().size_hint().exact().is_some() {
            drop(guard);
            return response;
        }
        let (parts, body) = response.into_parts();
        let mut data = body.into_data_stream();
        let stream = async_stream::stream! {
            let _guard = guard;
            while let Some(chunk) = data.next().await {
                yield chunk;
            }
        };
        Response::from_parts(parts, Body::from_stream(stream))
    }

    async fn handle_inner(self: &Arc<Self>, mount: &Mount, inbound: Inbound) -> Response {
        if let Some(r) = security_check(&mount.config.security, &inbound) {
            return r;
        }
        if self.is_terminated() {
            return self.error_response("Not Found: Session has been terminated", StatusCode::NOT_FOUND, INVALID_REQUEST, &[]);
        }
        match inbound.method {
            Method::POST => self.post(mount, inbound).await,
            Method::GET => self.get(inbound),
            Method::DELETE => self.delete(inbound),
            _ => self.error_response(
                "Method Not Allowed",
                StatusCode::METHOD_NOT_ALLOWED,
                INVALID_REQUEST,
                &[("allow", "GET, POST, DELETE")],
            ),
        }
    }

    async fn post(self: &Arc<Self>, mount: &Mount, inbound: Inbound) -> Response {
        let (has_json, has_sse) = check_accept(&inbound);
        if !(has_json && has_sse) {
            return self.error_response(
                "Not Acceptable: Client must accept both application/json and text/event-stream",
                StatusCode::NOT_ACCEPTABLE,
                INVALID_REQUEST,
                &[],
            );
        }
        let content_type = inbound.header("content-type").unwrap_or_default();
        let first = content_type.split(';').next().unwrap_or("");
        if !first.split(',').any(|part| part.trim() == "application/json") {
            return self.error_response(
                "Unsupported Media Type: Content-Type must be application/json",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                INVALID_REQUEST,
                &[],
            );
        }
        let raw = match jsonrpc::parse_json(&inbound.body) {
            Ok(v) => v,
            Err(e) => return self.error_response(&format!("Parse error: {e}"), StatusCode::BAD_REQUEST, PARSE_ERROR, &[]),
        };
        let message = match jsonrpc::parse_message(&raw) {
            Ok(m) => m,
            Err(e) => {
                return self.error_response(&format!("Validation error: {e}"), StatusCode::BAD_REQUEST, INVALID_PARAMS, &[])
            }
        };
        let is_init = matches!(&message, Message::Request { method, .. } if method == "initialize");
        if is_init {
            if let Some(id) = &self.id {
                if inbound.header(MCP_SESSION_ID_HEADER).is_some_and(|h| !h.is_empty() && h != *id) {
                    return self.error_response(
                        "Not Found: Invalid or expired session ID",
                        StatusCode::NOT_FOUND,
                        INVALID_REQUEST,
                        &[],
                    );
                }
            }
        } else if let Err(r) = self.validate_session(&inbound) {
            return r;
        }
        match message {
            Message::Request { id, method, params } => self.request(mount, &inbound, id, method, params, is_init).await,
            Message::Notification { method, params } => {
                self.notification(mount, &inbound, &method, params.as_ref()).await;
                self.empty_json(StatusCode::ACCEPTED)
            }
            // We never send server-to-client requests, so a client response
            // correlates with nothing.
            Message::Response { .. } | Message::Error { .. } => {
                tracing::debug!("dropping response for unknown/late request id");
                self.empty_json(StatusCode::ACCEPTED)
            }
        }
    }

    async fn notification(self: &Arc<Self>, mount: &Mount, inbound: &Inbound, method: &str, params: Option<&Map<String, Value>>) {
        if method == "notifications/cancelled" {
            if let Some(key) = params.and_then(|p| p.get("requestId")).and_then(RidKey::of) {
                if let Some(token) = self.inflight.lock().get(&key) {
                    token.cancel();
                }
            }
        }
        let ctx = self.context(inbound, method, None);
        mount.kernel.on_notify(&self.conn, &ctx, params).await;
    }

    async fn request(
        self: &Arc<Self>,
        mount: &Mount,
        inbound: &Inbound,
        id: Value,
        method: String,
        params: Option<Map<String, Value>>,
        is_init: bool,
    ) -> Response {
        let ctx = self.context(inbound, &method, Some(id.clone()));
        let (tx, rx) = oneshot::channel::<Value>();
        if is_init {
            // `initialize` runs inline so a pipelined next request sees the
            // committed state.
            let outcome = mount.kernel.on_request(&self.conn, &ctx, params.as_ref(), &None).await;
            let _ = tx.send(reply(&id, outcome));
        } else {
            let key = RidKey::of(&id);
            let token = CancellationToken::new();
            if let Some(k) = &key {
                self.inflight.lock().insert(k.clone(), token.clone());
            }
            let session = self.clone();
            let kernel = mount.kernel.clone();
            tokio::spawn(async move {
                let outcome = tokio::select! {
                    _ = token.cancelled() => None,
                    r = kernel.on_request(&session.conn, &ctx, params.as_ref(), &None) => Some(r),
                };
                if let Some(k) = &key {
                    session.inflight.lock().remove(k);
                }
                let message = match outcome {
                    Some(r) => reply(&id, r),
                    None => jsonrpc::error(Some(&id), &ErrorData::new(REQUEST_CANCELLED, "Request cancelled")),
                };
                let _ = tx.send(message);
            });
        }
        let closed = self.closed.clone();
        let stream = async_stream::stream! {
            let mut rx = rx;
            let mut ticker = tokio::time::interval_at(Instant::now() + sse::PING_INTERVAL, sse::PING_INTERVAL);
            loop {
                tokio::select! {
                    biased;
                    _ = closed.cancelled() => break,
                    message = &mut rx => {
                        if let Ok(m) = message {
                            yield Ok::<_, std::convert::Infallible>(sse::legacy_frame(&m));
                        }
                        break;
                    }
                    _ = ticker.tick() => yield Ok(sse::legacy_ping()),
                }
            }
        };
        sse::legacy_response(self.id.as_deref(), Body::from_stream(stream))
    }

    fn get(self: &Arc<Self>, inbound: Inbound) -> Response {
        let (_, has_sse) = check_accept(&inbound);
        if !has_sse {
            return self.error_response(
                "Not Acceptable: Client must accept text/event-stream",
                StatusCode::NOT_ACCEPTABLE,
                INVALID_REQUEST,
                &[],
            );
        }
        if let Err(r) = self.validate_session(&inbound) {
            return r;
        }
        if inbound.header(LAST_EVENT_ID_HEADER).is_some_and(|v| !v.is_empty()) {
            // PORT NOTE: with no event store the SDK returns without sending a
            // response, which uvicorn turns into this 500.
            let mut r = super::plain(500, "Internal Server Error");
            r.headers_mut().insert("content-type", HeaderValue::from_static("text/plain; charset=utf-8"));
            return r;
        }
        let (tx, mut rx) = mpsc::channel::<Value>(STREAM_BUFFER);
        let generation = {
            let mut slot = self.standalone.lock();
            if slot.is_some() {
                drop(slot);
                return self.error_response(
                    "Conflict: Only one SSE stream is allowed per session",
                    StatusCode::CONFLICT,
                    INVALID_REQUEST,
                    &[],
                );
            }
            let generation = self.standalone_gen.fetch_add(1, Ordering::SeqCst) + 1;
            *slot = Some((generation, tx));
            generation
        };
        let guard = StandaloneGuard { session: Arc::downgrade(self), generation };
        let closed = self.closed.clone();
        let stream = async_stream::stream! {
            let _guard = guard;
            let mut ticker = tokio::time::interval_at(Instant::now() + sse::PING_INTERVAL, sse::PING_INTERVAL);
            loop {
                tokio::select! {
                    biased;
                    _ = closed.cancelled() => break,
                    message = rx.recv() => match message {
                        Some(m) => yield Ok::<_, std::convert::Infallible>(sse::legacy_frame(&m)),
                        None => break,
                    },
                    _ = ticker.tick() => yield Ok(sse::legacy_ping()),
                }
            }
        };
        sse::legacy_response(self.id.as_deref(), Body::from_stream(stream))
    }

    fn delete(self: &Arc<Self>, inbound: Inbound) -> Response {
        if self.id.is_none() {
            return self.error_response(
                "Method Not Allowed: Session termination not supported",
                StatusCode::METHOD_NOT_ALLOWED,
                INVALID_REQUEST,
                &[],
            );
        }
        if let Err(r) = self.validate_session(&inbound) {
            return r;
        }
        self.terminate();
        self.empty_json(StatusCode::OK)
    }
}

/// Frees the standalone slot when its stream ends (client disconnect).
struct StandaloneGuard {
    session: Weak<Session>,
    generation: u64,
}

impl Drop for StandaloneGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.upgrade() {
            let mut slot = session.standalone.lock();
            if slot.as_ref().is_some_and(|(g, _)| *g == self.generation) {
                *slot = None;
            }
        }
    }
}

fn reply(id: &Value, outcome: Result<Value, super::McpError>) -> Value {
    match outcome {
        Ok(result) => jsonrpc::response(id, result),
        Err(e) => jsonrpc::error(Some(id), &e.legacy_error()),
    }
}

pub(crate) async fn handle_stateless(mount: &Mount, inbound: Inbound) -> Response {
    // Born-ready, no standalone channel: the header (or the spec's
    // default-absent value) seeds the connection's version.
    let version = inbound.header(MCP_PROTOCOL_VERSION_HEADER).unwrap_or_else(|| DEFAULT_NEGOTIATED_VERSION.to_string());
    let session = Arc::new(Session::new(None, Conn::born_ready(&version), false, None));
    session.handle(mount, inbound).await
}

/// `_error_response`: a JSON-RPC error body (no request id), no session header.
fn manager_error(message: &str, status: StatusCode, code: i64) -> Response {
    let body = jsonrpc::legacy_text(&jsonrpc::error(None, &ErrorData::new(code, message)));
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
    r
}

pub(crate) async fn handle_stateful(mount: &Mount, inbound: Inbound) -> Response {
    let header = inbound.header(MCP_SESSION_ID_HEADER);
    // `SessionReaper`: a DELETE with a session id is the client saying it
    // is done; forget it before the transport sees the request.
    if inbound.method == Method::DELETE {
        if let (Some(n), Some(id)) = (&mount.config.notifier, header.as_deref().filter(|s| !s.is_empty())) {
            n.forget(id);
        }
    }
    // The SDK binds a session to the credential that created it
    // (`scope["user"]`, which only its own `AuthenticationMiddleware`
    // sets) and answers anyone else 404 `Session not found`. gatekeeper
    // authenticates in its own middleware and never sets `scope["user"]`,
    // so every requestor is `None`, matches the `None` owner, and the
    // binding never refuses anything: there is nothing to port.
    match header {
        Some(id) => match mount.sessions.get(&id) {
            Some(session) => {
                let response = session.handle(mount, inbound).await;
                if session.is_terminated() {
                    // The client ended the session (DELETE): forget it now.
                    mount.sessions.discard(&session);
                }
                response
            }
            None => {
                tracing::info!("Rejected request with unknown or expired session ID: {}", id.chars().take(64).collect::<String>());
                manager_error("Session not found", StatusCode::NOT_FOUND, INVALID_REQUEST)
            }
        },
        None => {
            // `_admit_session`: the session limit and registration, under
            // one lock.
            let session = {
                let mut map = mount.sessions.map.lock();
                if mount.config.max_sessions.is_some_and(|max| map.len() >= max) {
                    None
                } else {
                    let id = uuid::Uuid::new_v4().simple().to_string();
                    let session =
                        Arc::new(Session::new(Some(id.clone()), Conn::for_loop(), true, mount.config.session_idle_timeout));
                    map.insert(id.clone(), session.clone());
                    tracing::info!("Created new transport with session ID: {id}");
                    Some(session)
                }
            };
            let Some(session) = session else {
                tracing::warn!(
                    "Refusing to open a new session: {} sessions are already open",
                    mount.config.max_sessions.unwrap_or_default()
                );
                return manager_error("Too many open sessions", StatusCode::SERVICE_UNAVAILABLE, INTERNAL_ERROR);
            };
            if session.idle.is_some() {
                spawn_idle_reaper(Arc::downgrade(&mount.sessions), session.clone());
            }
            // `_serve_opening_request`: without a session id only an
            // initialize can succeed; if this request is refused nothing
            // was established and the session is discarded again.
            let response = session.handle(mount, inbound).await;
            if response.status().as_u16() >= 400 {
                mount.sessions.discard(&session);
            }
            response
        }
    }
}

fn spawn_idle_reaper(sessions: Weak<SessionMap>, session: Arc<Session>) {
    tokio::spawn(async move {
        let Some(idle) = &session.idle else { return };
        loop {
            let deadline = {
                let st = idle.state.lock();
                if st.expired {
                    return;
                }
                st.deadline
            };
            let sleep = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = session.closed.cancelled() => return,
                _ = idle.changed.notified() => continue,
                _ = sleep => {}
            }
            {
                let mut st = idle.state.lock();
                if st.in_flight > 0 || st.deadline.is_none_or(|d| d > Instant::now()) {
                    continue;
                }
                st.expired = true;
            }
            tracing::info!("Session {} idle timeout", session.id.as_deref().unwrap_or_default());
            match sessions.upgrade() {
                Some(map) => map.discard(&session),
                None => session.terminate(),
            }
            return;
        }
    });
}
