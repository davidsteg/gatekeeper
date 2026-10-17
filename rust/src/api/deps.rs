//! Authentication, roles, CSRF and optimistic concurrency for `/api/v1`
//! (port of `api/deps.py`).
//!
//! The rules, one for one:
//!
//! * **Session, not token.** A request is authenticated by the console
//!   session cookie only. An `Authorization` header is refused outright --
//!   an MCP bearer token must never reach console capabilities (FR-11.5).
//! * **Two roles.** `viewer` reads, `admin` writes; read-only mode (no
//!   `ConfigStore`) turns every write into a 403 for everyone.
//! * **CSRF.** Every mutating request carries `X-CSRF-Token` equal to the
//!   session's token, compared in constant time.
//! * **If-Match.** Reads return `ETag: "<store revision>"`; writes must send
//!   it back. A stale revision is a 412.
//!
//! Denials are audited as an `admin_denied` record ([`deny`]).

use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;
use serde_json::{json, Value};

use crate::audit::AuditLog;
use crate::credentials::CredentialStore;
use crate::oauth::OAuthStateStore;
use crate::pending::PendingStore;
use crate::service::{Service, SharedIdentities};
use crate::store::ConfigStore;
use crate::toolkit_proposals::ToolkitProposalStore;

use super::session::{LoginThrottle, Session, SessionStore, SESSION_COOKIE};

pub const CSRF_HEADER: &str = "X-CSRF-Token";
pub const MUTATING_METHODS: [&str; 4] = ["POST", "PUT", "PATCH", "DELETE"];

/// The ETag of a store whose file does not exist yet. Sent back, it
/// matches only while the file is still missing.
pub const EMPTY_REVISION: &str = "0";

/// The stores the API shares with the MCP mounts.
#[derive(Clone)]
pub struct ApiContext {
    pub service: Arc<Service>,
    pub identities: SharedIdentities,
    pub audit: Arc<AuditLog>,
    pub sessions: Arc<SessionStore>,
    pub throttle: Arc<LoginThrottle>,
    /// `None` means read-only mode.
    pub store: Option<Arc<ConfigStore>>,
    pub credentials: Option<Arc<CredentialStore>>,
    pub pending: Option<Arc<PendingStore>>,
    pub toolkit_proposals: Option<Arc<ToolkitProposalStore>>,
    /// Shared with the callback route.
    pub oauth_states: Option<Arc<OAuthStateStore>>,
}

impl ApiContext {
    pub fn read_only(&self) -> bool {
        self.store.is_none()
    }

    pub fn can_write(&self, session: &Session) -> bool {
        session.can_write() && !self.read_only()
    }
}

/// An error answered as `{"error": "<sentence>"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
    pub headers: Vec<(String, String)>,
}

impl ApiError {
    pub fn new(status: u16, message: impl Into<String>) -> ApiError {
        ApiError { status, message: message.into(), headers: Vec::new() }
    }
}

/// Why a handler did not answer normally.
#[derive(Debug)]
pub enum Fail {
    /// `ApiError` / `HTTPException`: status and `{"error": ...}`.
    Api(ApiError),
    /// A `RequestValidationError`, already formatted the way `app.py`'s
    /// handler does (`"<where>: <msg>"`): 422.
    Validation(String),
    /// An exception Python would have let escape: 500.
    Internal(String),
}

impl From<ApiError> for Fail {
    fn from(e: ApiError) -> Fail {
        Fail::Api(e)
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Fail {
        Fail::Internal(e.to_string())
    }
}

pub type ApiResult<T> = Result<T, Fail>;

pub fn api(status: u16, message: impl Into<String>) -> Fail {
    Fail::Api(ApiError::new(status, message))
}

/// One request as the handlers see it.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    pub method: String,
    /// The full, percent-decoded path (`/api/v1/tools`) -- what
    /// `request.url.path` printed in audit records.
    pub path: String,
    /// The raw query string.
    pub query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    /// `request.client.host`; `None` when unknown.
    pub client: Option<String>,
    /// `request.url.scheme`.
    pub scheme: String,
    /// The `Host` header (or the URI authority).
    pub host: String,
}

impl ApiRequest {
    /// The first value of a header, latin-1 decoded (Starlette `Headers.get`).
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).map(|v| v.as_bytes().iter().map(|&b| b as char).collect())
    }

    /// One cookie, parsed the way Starlette's `cookie_parser` does.
    pub fn cookie(&self, name: &str) -> Option<String> {
        let raw = self.header("cookie")?;
        let mut found = None;
        for chunk in raw.split(';') {
            let (key, val) = match chunk.split_once('=') {
                Some((k, v)) => (k, v),
                None => ("", chunk),
            };
            let (key, val) = (key.trim(), val.trim());
            if (!key.is_empty() || !val.is_empty()) && key == name {
                found = Some(unquote_cookie(val));
            }
        }
        found
    }

    /// `request.base_url` of the application: `scheme://host/`.
    pub fn base_url(&self) -> String {
        format!("{}://{}/", self.scheme, self.host)
    }

    pub fn client_or_unknown(&self) -> String {
        self.client.clone().unwrap_or_else(|| "unknown".to_string())
    }
}

/// `http.cookies._unquote`: strips one pair of double quotes and resolves
/// the backslash escapes inside.
fn unquote_cookie(val: &str) -> String {
    if val.len() < 2 || !val.starts_with('"') || !val.ends_with('"') {
        return val.to_string();
    }
    let inner = &val[1..val.len() - 1];
    let bytes = inner.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let octal = &bytes[i + 1..(i + 4).min(bytes.len())];
            if octal.len() == 3 && octal.iter().all(|b| (b'0'..=b'7').contains(b)) {
                out.push(((octal[0] - b'0') << 6) | ((octal[1] - b'0') << 3) | (octal[2] - b'0'));
                i += 4;
                continue;
            }
            out.push(bytes[i + 1]);
            i += 2;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn write_audit(context: &ApiContext, record: Value) -> ApiResult<()> {
    context.audit.write(record)?;
    Ok(())
}

/// `current_session`: the cookie's session, never a bearer token.
pub fn current_session(context: &ApiContext, request: &ApiRequest) -> ApiResult<Session> {
    if request.headers.contains_key("authorization") {
        // Not a fallback, not a second way in: an agent's bearer token is
        // refused on every API route, with or without a cookie next to it.
        context.audit.auth_failure(
            "api_bearer_rejected",
            &format!("{} {}", request.method, request.path),
            serde_json::Map::new(),
        )?;
        return Err(api(401, "Bearer tokens are not accepted here; sign in to the console."));
    }
    match context.sessions.resolve(request.cookie(SESSION_COOKIE).as_deref()) {
        Some(session) => Ok(session),
        None => Err(api(401, "Not signed in.")),
    }
}

/// An `admin_denied` audit record: the denied path and the reason.
pub fn deny(context: &ApiContext, request: &ApiRequest, session: &Session, reason: &str) -> ApiResult<()> {
    write_audit(
        context,
        json!({
            "kind": "admin_denied",
            "actor": session.identity,
            "role": session.role,
            "path": request.path,
            "reason": reason,
        }),
    )
}

/// Any console session. Viewers and admins read the same data.
pub fn require_viewer(context: &ApiContext, request: &ApiRequest) -> ApiResult<Session> {
    current_session(context, request)
}

/// `hmac.compare_digest` on the UTF-8 bytes.
pub fn compare_digest(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8 | u8::from(a.len() != b.len());
    for (i, x) in a.iter().enumerate() {
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

fn check_csrf(context: &ApiContext, request: &ApiRequest, session: Session) -> ApiResult<Session> {
    if MUTATING_METHODS.contains(&request.method.as_str()) {
        let supplied = request.header(CSRF_HEADER).unwrap_or_default();
        if !compare_digest(&supplied, &session.csrf) {
            deny(context, request, &session, "csrf_mismatch")?;
            return Err(api(403, "Missing or stale CSRF token."));
        }
    }
    Ok(session)
}

pub fn require_csrf(context: &ApiContext, request: &ApiRequest) -> ApiResult<Session> {
    let session = current_session(context, request)?;
    check_csrf(context, request, session)
}

/// A write that needs a session and CSRF, but not `admin` -- one's own
/// console password.
pub fn require_session_write(context: &ApiContext, request: &ApiRequest) -> ApiResult<Session> {
    let session = require_csrf(context, request)?;
    if context.read_only() {
        deny(context, request, &session, "read_only")?;
        return Err(api(403, "The console is read-only."));
    }
    Ok(session)
}

/// Role first, then CSRF, so a viewer is told "not permitted" rather than
/// "stale token".
pub fn require_admin(context: &ApiContext, request: &ApiRequest) -> ApiResult<Session> {
    let session = current_session(context, request)?;
    if context.read_only() || !session.can_write() {
        let reason = if context.read_only() { "read_only" } else { "role_required" };
        deny(context, request, &session, reason)?;
        return Err(api(403, "Writing requires role admin and a writable configuration."));
    }
    check_csrf(context, request, session)
}

/// Admin role for a read (the OpenAPI schema). Read-only mode does not
/// matter for a read.
pub fn require_admin_read(context: &ApiContext, request: &ApiRequest) -> ApiResult<Session> {
    let session = require_viewer(context, request)?;
    if session.role != crate::identity::ADMIN_ROLE {
        deny(context, request, &session, "role_required")?;
        return Err(api(403, "The API schema is available to role admin only."));
    }
    Ok(session)
}

/// The `ETag` header value for a revision.
pub fn etag(revision: &str) -> String {
    let revision = if revision.is_empty() { EMPTY_REVISION } else { revision };
    format!("\"{revision}\"")
}

/// The revision a write is based on, checked against `current`. Returns
/// the supplied revision so the caller can hand it to the store, whose own
/// check at write time is the real guarantee.
pub fn if_match(request: &ApiRequest, current: &str) -> ApiResult<String> {
    let Some(raw) = request.header("if-match") else {
        return Err(api(428, "If-Match is required; send the ETag of the resource you edited."));
    };
    let mut supplied = py_strip(&raw);
    if let Some(rest) = supplied.strip_prefix("W/") {
        supplied = rest;
    }
    let supplied = supplied.trim_matches('"');
    let current = if current.is_empty() { EMPTY_REVISION } else { current };
    if supplied != current {
        return Err(api(412, "The resource changed since you loaded it. Reload and apply your edit again."));
    }
    Ok(supplied.to_string())
}

/// Python's `str.strip()` (Unicode whitespace).
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(headers: &[(&str, &str)]) -> ApiRequest {
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        ApiRequest {
            method: "POST".into(),
            path: "/api/v1/x".into(),
            query: String::new(),
            headers: map,
            body: Bytes::new(),
            client: None,
            scheme: "http".into(),
            host: "gatekeeper.test".into(),
        }
    }

    #[test]
    fn if_match_accepts_strong_weak_and_bare_tags() {
        for tag in ["\"abc\"", "W/\"abc\"", "abc", " \"abc\" "] {
            assert_eq!(if_match(&request(&[("if-match", tag)]), "abc").unwrap(), "abc", "{tag}");
        }
        match if_match(&request(&[]), "abc") {
            Err(Fail::Api(e)) => assert_eq!(e.status, 428),
            other => panic!("{other:?}"),
        }
        match if_match(&request(&[("if-match", "\"0123\"")]), "abc") {
            Err(Fail::Api(e)) => {
                assert_eq!(e.status, 412);
                assert!(e.message.contains("changed"));
            }
            other => panic!("{other:?}"),
        }
        // A missing file's revision is "0".
        assert_eq!(if_match(&request(&[("if-match", "\"0\"")]), "").unwrap(), "0");
        assert_eq!(etag(""), "\"0\"");
    }

    #[test]
    fn cookies_parse_like_starlette() {
        let r = request(&[("cookie", "a=1; gatekeeper_ui=abc; b=\"q\\\"x\"")]);
        assert_eq!(r.cookie("gatekeeper_ui").as_deref(), Some("abc"));
        assert_eq!(r.cookie("b").as_deref(), Some("q\"x"));
        assert_eq!(r.cookie("nope"), None);
    }

    #[test]
    fn compare_digest_is_exact() {
        assert!(compare_digest("abc", "abc"));
        assert!(!compare_digest("abc", "abd"));
        assert!(!compare_digest("abc", "abcd"));
        assert!(!compare_digest("", "a"));
        assert!(compare_digest("", ""));
    }
}
