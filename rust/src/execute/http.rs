//! The `http` executor (port of `execute_http.py`; REQUIREMENTS.md §8,
//! FR-8.5 to FR-8.15).
//!
//! What the argv template is to the local executor, the URL template is
//! here. The one property everything below serves: the agent can never
//! determine the actual network target. Scheme and host come exclusively
//! from the toolkit (FR-8.5); a parameter fills exactly one path segment,
//! query value, or body field (FR-8.7); the resolved IP is checked against
//! the toolkit's CIDR allowlist immediately before connecting, closing the
//! DNS-rebinding gap a one-time hostname check would leave open (FR-8.9);
//! redirects are reported, never followed (FR-8.8); the credential is
//! injected as a header by this module directly, never through a tool's
//! own query/body template (FR-8.14).
//!
//! A tool may declare `body: {raw_param: <name>}` to hand one parameter's
//! own JSON document to the target as the request body byte for byte
//! ([`raw_json_body`]) -- the body's *shape* is the only thing that
//! changes; target, method, path and headers stay where every other rule
//! above puts them.
//!
//! PORT NOTE: Python sent the request through `httpx`. The port speaks
//! HTTP/1.1 through `hyper`'s connection-level client over a TCP (and,
//! for `https`, rustls) stream that this module opens itself to the
//! *checked* IP: that is the only way to keep the request-target byte for
//! byte what httpx produced (httpx's own path quoting is reproduced in
//! [`request_path`]; `url::Url` would rewrite `\` and re-quote) while
//! connecting to the address that passed the CIDR check, with TLS still
//! verified against the real hostname (httpx's `sni_hostname`). What that
//! keeps from httpx: the same request headers (`Accept: */*`,
//! `Accept-Encoding: gzip, deflate`, `Connection: keep-alive`, the
//! `Content-Length: 0` httpx adds to a body-less POST/PUT/PATCH), gzip and
//! deflate response decoding, and httpx's default 5 s connect/read
//! timeouts, which bound a single read independently of the tool's own
//! `timeout_seconds`. What differs, deliberately: the `User-Agent` names
//! gatekeeper instead of `python-httpx`; header names go out title-cased
//! (`X-Api-Key`) because hyper cannot replay arbitrary casing; and the
//! process proxy environment (`HTTPS_PROXY`, which httpx honoured by
//! default) is ignored, because a proxy would turn "connect to the checked
//! IP" into "connect wherever the proxy decides" -- the FR-8.9 gap this
//! module exists to close.

use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper_util::rt::TokioIo;
use indexmap::IndexMap;
use once_cell::sync::Lazy;
use serde_json::{Map, Value};

use super::{elapsed_ms, ExecResult, Redact, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::credentials::{format_header_value, CredentialStore, ResolvedCredential};
use crate::errors::{ConfigError, DenialReason, Denied};
use crate::pyfmt::repr_str;
use crate::pyjson;
use crate::tier1::{py_truthy, urlsplit, Toolkit};

/// FR-8.12: responses are capped not just in bytes but in list length --
/// a single "list all series" call must not smuggle thousands of fields
/// worth of untrusted text into the agent's context.
pub const MAX_JSON_ITEMS: i64 = 500;

/// httpx's default per-operation timeout (connect, read), which Python's
/// `httpx.AsyncClient(verify=True)` applied under the tool's own
/// `asyncio.wait_for`.
const HTTPX_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The request headers httpx adds to every request.
const USER_AGENT: &str = concat!("gatekeeper/", env!("CARGO_PKG_VERSION"));

// -- Shared network helpers (also used by the truenas and ssh executors) --

/// `f"{timeout_seconds}s"` for a value Python held as `int` (service) or
/// `float` (tests): `5` -> `5`, `0.2` -> `0.2`.
pub(crate) fn fmt_seconds(seconds: f64) -> String {
    if seconds.fract() == 0.0 && seconds.abs() < 1e15 {
        format!("{}", seconds as i64)
    } else {
        crate::pyfmt::float_str(seconds)
    }
}

/// A `Duration` for a timeout in seconds; negative/NaN means "already
/// expired", as `asyncio.wait_for` treats a non-positive timeout.
pub(crate) fn seconds(timeout_seconds: f64) -> Duration {
    if timeout_seconds.is_finite() && timeout_seconds > 0.0 {
        Duration::from_secs_f64(timeout_seconds.min(1e9))
    } else {
        Duration::ZERO
    }
}

/// Python's `str(OSError(errno, strerror))`.
pub(crate) fn errno_str(code: i32) -> String {
    let msg = unsafe { CStr::from_ptr(libc::strerror(code)) }.to_string_lossy().into_owned();
    format!("[Errno {code}] {msg}")
}

/// One resolved address: the socket address to connect to and the text
/// Python's `getaddrinfo` returned as `info[4][0]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub addr: SocketAddr,
    pub raw: String,
}

/// `loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)` through the
/// system resolver, so the address list (and its order) is the one Python
/// saw. The error is `str(socket.gaierror)`, e.g. `[Errno -2] Name or
/// service not known`.
pub(crate) async fn getaddrinfo(host: &str, port: u16) -> Result<Vec<Resolved>, String> {
    // Python encodes the host with the `idna` codec before the lookup.
    let host = if host.is_ascii() {
        host.to_string()
    } else {
        match url::Host::parse(host) {
            Ok(url::Host::Domain(d)) => d,
            Ok(other) => other.to_string(),
            Err(e) => return Err(format!("encoding with 'idna' codec failed ({e})")),
        }
    };
    tokio::task::spawn_blocking(move || getaddrinfo_blocking(&host, port))
        .await
        .unwrap_or_else(|e| Err(e.to_string()))
}

fn getaddrinfo_blocking(host: &str, port: u16) -> Result<Vec<Resolved>, String> {
    let c_host = CString::new(host).map_err(|_| "embedded null character".to_string())?;
    let c_port = CString::new(port.to_string()).expect("digits");
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = unsafe { libc::getaddrinfo(c_host.as_ptr(), c_port.as_ptr(), &hints, &mut res) };
    if rc != 0 {
        if rc == libc::EAI_SYSTEM {
            return Err(errno_str(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
        }
        let msg = unsafe { CStr::from_ptr(libc::gai_strerror(rc)) }.to_string_lossy().into_owned();
        return Err(format!("[Errno {rc}] {msg}"));
    }
    let mut out = Vec::new();
    let mut cur = res;
    while !cur.is_null() {
        let info = unsafe { &*cur };
        if !info.ai_addr.is_null() {
            match info.ai_family {
                libc::AF_INET => {
                    let sa = unsafe { &*(info.ai_addr as *const libc::sockaddr_in) };
                    let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                    let addr = SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(sa.sin_port)));
                    out.push(Resolved { addr, raw: ip.to_string() });
                }
                libc::AF_INET6 => {
                    let sa = unsafe { &*(info.ai_addr as *const libc::sockaddr_in6) };
                    let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
                    let scope = sa.sin6_scope_id;
                    let mut raw = ip.to_string();
                    if scope != 0 {
                        // Python reports a scoped address as `fe80::1%eth0`.
                        let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
                        let name = unsafe { libc::if_indextoname(scope, buf.as_mut_ptr()) };
                        if name.is_null() {
                            raw.push_str(&format!("%{scope}"));
                        } else {
                            let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
                            raw.push_str(&format!("%{name}"));
                        }
                    }
                    let addr = SocketAddr::V6(SocketAddrV6::new(
                        ip,
                        u16::from_be(sa.sin6_port),
                        sa.sin6_flowinfo,
                        scope,
                    ));
                    out.push(Resolved { addr, raw });
                }
                _ => {}
            }
        }
        cur = info.ai_next;
    }
    unsafe { libc::freeaddrinfo(res) };
    Ok(out)
}

/// Python's repr of a socket address tuple: `('127.0.0.1', 1)` /
/// `('::1', 1, 0, 0)`.
fn sockaddr_repr(r: &Resolved) -> String {
    match r.addr {
        SocketAddr::V4(a) => format!("({}, {})", repr_str(&r.raw), a.port()),
        SocketAddr::V6(a) => format!(
            "({}, {}, {}, {})",
            repr_str(&r.raw),
            a.port(),
            a.flowinfo(),
            a.scope_id()
        ),
    }
}

/// `asyncio`'s `loop.create_connection(host, port)` -- the connect step
/// websockets and asyncssh use -- including its error text: a single
/// failure is `[Errno 111] Connect call failed ('127.0.0.1', 1)`, several
/// different ones `Multiple exceptions: ..., ...`.
pub(crate) async fn asyncio_connect(host: &str, port: u16) -> Result<tokio::net::TcpStream, String> {
    let infos = getaddrinfo(host, port).await?;
    if infos.is_empty() {
        return Err("getaddrinfo() returned empty list".to_string());
    }
    let mut errors: Vec<String> = Vec::new();
    for info in &infos {
        match tokio::net::TcpStream::connect(info.addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                errors.push(format!("[Errno {code}] Connect call failed {}", sockaddr_repr(info)));
            }
        }
    }
    if errors.len() == 1 || errors.iter().all(|e| e == &errors[0]) {
        return Err(errors.swap_remove(0));
    }
    Err(format!("Multiple exceptions: {}", errors.join(", ")))
}

/// The parts of `urllib.parse.SplitResult.hostname` / `.port`.
pub(crate) struct HostInfo {
    /// `hostname` (lower-cased, brackets stripped), `""` for `None`.
    pub hostname: String,
    /// The raw port text, `None` when absent/empty.
    pub port: Option<String>,
}

pub(crate) fn host_info(netloc: &str) -> HostInfo {
    let hostinfo = netloc.rsplit_once('@').map(|(_, h)| h).unwrap_or(netloc);
    let (hostname, port) = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let (hostname, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            let port = rest.split_once(':').map(|(_, p)| p).unwrap_or("");
            (hostname, port)
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    let hostname = match hostname.split_once('%') {
        Some((h, zone)) => format!("{}%{zone}", h.to_lowercase()),
        None => hostname.to_lowercase(),
    };
    HostInfo { hostname, port: if port.is_empty() { None } else { Some(port.to_string()) } }
}

/// `SplitResult.port`: `Ok(None)` when absent, the Python `ValueError`
/// text when invalid.
pub(crate) fn parse_port(port: &Option<String>) -> Result<Option<u16>, String> {
    let Some(p) = port else { return Ok(None) };
    if !p.chars().all(|c| c.is_ascii_digit()) || p.is_empty() {
        return Err(format!("Port could not be cast to integer value as {}", repr_str(p)));
    }
    match p.trim_start_matches('0').parse::<u32>() {
        Ok(n) if n <= 65535 => Ok(Some(n as u16)),
        _ if p.trim_start_matches('0').is_empty() => Ok(Some(0)),
        _ => Err("Port out of range 0-65535".to_string()),
    }
}

// -- The executor proper ----------------------------------------------------

/// TCP-connect only, for /health/ready -- no HTTP request is issued.
///
/// A base_url containing an unresolved `{credential}` placeholder (the
/// Telegram case) is skipped as "not checkable this way" rather than
/// reported unreachable -- opening a probe connection would otherwise need
/// a real credential just to answer a liveness question.
pub async fn probe(toolkit: &Toolkit) -> bool {
    let base_url = toolkit.base_url.as_deref().expect("http toolkit without base_url");
    if base_url.contains("{credential}") {
        return true;
    }
    let parsed = urlsplit(base_url);
    let info = host_info(&parsed.netloc);
    // PORT NOTE: an unparseable port raised ValueError out of Python's
    // probe; here it is simply "not ready".
    let Ok(port) = parse_port(&info.port) else { return false };
    let port = default_port(port, &parsed.scheme);
    let Ok(resolved) = resolve_and_check(&info.hostname, port, toolkit).await else {
        return false;
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(resolved.addr)).await,
        Ok(Ok(_))
    )
}

/// `parsed.port or (443 if scheme == "https" else 80)` -- a literal `:0`
/// is falsy and gets the default too.
fn default_port(port: Option<u16>, scheme: &str) -> u16 {
    match port {
        Some(p) if p != 0 => p,
        _ => {
            if scheme == "https" {
                443
            } else {
                80
            }
        }
    }
}

/// Resolves a `{credential}` placeholder in `base_url` server-side only.
///
/// The one contained exception to "credentials are always a header"
/// (FR-8.10): a handful of services (Telegram's bot API) put the secret in
/// the URL path itself. The placeholder never appears in a tool definition
/// or a response -- only here, immediately before use.
pub fn substitute_base_url(base_url: &str, credential: Option<&ResolvedCredential>) -> Result<String, Denied> {
    if !base_url.contains("{credential}") {
        return Ok(base_url.to_string());
    }
    let Some(credential) = credential else {
        return Err(Denied::new(
            DenialReason::CredentialUnavailable,
            "This toolkit's base_url needs a credential that is not configured.",
        ));
    };
    if credential.kind != "url_path" {
        // FR-8.14's preference for a header over a URL exists precisely
        // because a URL ends up in the target's own access logs.
        return Err(Denied::new(
            DenialReason::CredentialUnavailable,
            format!(
                "This toolkit's base_url substitutes a credential into the URL path, but {} is kind {}, not 'url_path'. Only a 'url_path' credential may fill this placeholder.",
                repr_str(&credential.name),
                repr_str(&credential.kind)
            ),
        ));
    }
    Ok(base_url.replace("{credential}", &credential.value))
}

/// Resolves `host` and checks every returned address against the toolkit's
/// `allowed_cidrs` (FR-8.9). Fail-closed: if *any* resolved address falls
/// outside the allowlist, the call is denied -- a multi-homed or
/// round-robin DNS answer does not get to pick the permissive address.
///
/// PORT NOTE: Python collected the addresses in a `set` and checked and
/// returned them in set iteration order; the port keeps resolver order
/// (deduplicated), which only decides *which* address an error names or
/// the connection uses when several all pass.
pub(crate) async fn resolve_and_check(host: &str, port: u16, toolkit: &Toolkit) -> Result<Resolved, Denied> {
    let infos = getaddrinfo(host, port).await.map_err(|exc| {
        Denied::new(DenialReason::ExecutorUnavailable, format!("Could not resolve {}: {exc}", repr_str(host)))
    })?;
    if infos.is_empty() {
        return Err(Denied::new(
            DenialReason::ExecutorUnavailable,
            format!("Could not resolve {}", repr_str(host)),
        ));
    }
    let mut addresses: Vec<Resolved> = Vec::new();
    for info in infos {
        if !addresses.iter().any(|a| a.raw == info.raw) {
            addresses.push(info);
        }
    }
    for address in &addresses {
        let ip: IpAddr = address.addr.ip();
        if !toolkit.in_allowed_cidrs(ip) {
            return Err(Denied::new(
                DenialReason::SsrfBlocked,
                format!(
                    "{} resolves to {}, which is outside this toolkit's allowed_cidrs.",
                    repr_str(host),
                    address.raw
                ),
            ));
        }
    }
    // Any one of the checked addresses is equally allowed.
    Ok(addresses.swap_remove(0))
}

/// Truncates list/dict field counts recursively (FR-8.12).
pub fn cap_json(value: &Value, budget: &mut i64) -> Value {
    if *budget <= 0 {
        return if value.is_array() || value.is_object() {
            Value::String("...(truncated)...".into())
        } else {
            value.clone()
        };
    }
    match value {
        Value::Array(items) => {
            let mut kept = Vec::new();
            for item in items {
                if *budget <= 0 {
                    break;
                }
                kept.push(cap_json(item, budget));
                *budget -= 1;
            }
            Value::Array(kept)
        }
        Value::Object(map) => {
            let mut kept = Map::new();
            for (key, item) in map {
                if *budget <= 0 {
                    break;
                }
                let capped = cap_json(item, budget);
                kept.insert(key.clone(), capped);
                *budget -= 1;
            }
            Value::Object(kept)
        }
        other => other.clone(),
    }
}

/// The headers a credential contributes (`_credential_headers`).
pub fn credential_headers(credential: Option<&ResolvedCredential>) -> Vec<(String, String)> {
    let Some(credential) = credential else { return Vec::new() };
    match credential.kind.as_str() {
        "api_key_header" => match credential.header.as_deref() {
            Some(header) if !header.is_empty() => vec![(
                header.to_string(),
                format_header_value(credential.header_format.as_deref(), &credential.value),
            )],
            _ => Vec::new(),
        },
        "bearer" => vec![("Authorization".into(), format!("Bearer {}", credential.value))],
        "basic" => {
            // `value` is expected as "user:pass".
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(credential.value.as_bytes());
            vec![("Authorization".into(), format!("Basic {encoded}"))]
        }
        _ => Vec::new(),
    }
}

/// FR-8.14's narrow, documented exception: a `url_query` credential is
/// injected as a query parameter by this module, exactly like a header
/// would be -- never through a tool's own `query_template`.
pub fn credential_query(credential: Option<&ResolvedCredential>) -> Vec<(String, String)> {
    match credential {
        Some(c) if c.kind == "url_query" => match c.header.as_deref() {
            Some(header) if !header.is_empty() => vec![(header.to_string(), c.value.clone())],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Resolves a tool's `body: {raw_param: <name>}` into a verbatim body.
///
/// Returns `(content, fallback_body)`: `content` is the bytes to send as
/// the request body, `fallback_body` what to send as a normal JSON object
/// instead when raw mode does not apply -- the referenced parameter being
/// absent falls back to the wrapper. The raw value *is* the body: it never
/// also appears as a field of a wrapper object. A string value must parse
/// as JSON (validation only -- the original bytes are sent); any other
/// value is serialized.
pub fn raw_json_body(raw_param: &str, body: Option<Value>) -> Result<(Option<Vec<u8>>, Option<Value>), Denied> {
    let value = match &body {
        Some(Value::Object(map)) if map.contains_key(raw_param) => map[raw_param].clone(),
        _ => return Ok((None, body)),
    };
    if let Value::String(text) = &value {
        if let Err(exc) = py_json_check(text) {
            return Err(Denied::new(
                DenialReason::ParamInvalid,
                format!(
                    "Parameter {} must contain valid JSON (it is sent as the request body verbatim), but parsing it failed: {exc}. Nothing was sent.",
                    repr_str(raw_param)
                ),
            ));
        }
        return Ok((Some(text.as_bytes().to_vec()), None));
    }
    Ok((Some(pyjson::dumps_with(&value, &pyjson::Opts::unicode()).into_bytes()), None))
}

/// One `http` call. `credentials`/`toolkit.credential` rather than a
/// pre-resolved value: this module is one of the few places allowed to call
/// [`CredentialStore::resolve`].
///
/// `Err` only for what escaped Python's `run()` as an exception: a
/// credential store that cannot be read or decrypted, or a failed
/// `mark_suspect` write. Every denial and network failure is an `Ok`
/// result, so it stays inside the normal audit bookkeeping.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    method: &str,
    path: &str,
    query: &IndexMap<String, String>,
    body: Option<&Value>,
    raw_param: Option<&str>,
    toolkit: &Toolkit,
    credentials: Option<&CredentialStore>,
    timeout_seconds: f64,
    max_output_bytes: i64,
    idempotent: bool,
    redact: Option<&Redact>,
) -> Result<ExecResult, ConfigError> {
    let base_url = toolkit.base_url.as_deref().expect("http toolkit without base_url");
    let started = Instant::now();

    // A rejection here (missing credential, SSRF block) is still a denial,
    // not a network failure -- reported as a result so it stays inside the
    // normal audit.call()/outcome bookkeeping.
    let denied = |denial: Denied| -> ExecResult {
        ExecResult::new(OUTCOME_FAILED, None, "", denial.agent_message(), false, elapsed_ms(started))
    };

    let mut credential: Option<ResolvedCredential> = None;
    if let Some(name) = toolkit.credential.as_deref().filter(|n| !n.is_empty()) {
        let Some(store) = credentials else {
            return Ok(denied(Denied::new(
                DenialReason::CredentialUnavailable,
                "No credential store is configured, but this toolkit needs one.",
            )));
        };
        credential = store.resolve(name)?;
        if credential.is_none() {
            return Ok(denied(Denied::new(
                DenialReason::CredentialUnavailable,
                format!("Credential {} is not configured yet.", repr_str(name)),
            )));
        }
    }

    let base_url = match substitute_base_url(base_url, credential.as_ref()) {
        Ok(u) => u,
        Err(denial) => return Ok(denied(denial)),
    };
    let parsed = urlsplit(&base_url);
    let scheme = parsed.scheme.clone();
    let info = host_info(&parsed.netloc);
    let host = info.hostname.clone();
    let port = match parse_port(&info.port) {
        Ok(p) => default_port(p, &scheme),
        // PORT NOTE: Python's `parsed.port` raised ValueError out of run()
        // (an unaudited error); the port reports it as a failed call.
        Err(exc) => {
            return Ok(ExecResult::new(OUTCOME_FAILED, None, "", exc, false, elapsed_ms(started)))
        }
    };

    let resolved = match resolve_and_check(&host, port, toolkit).await {
        Ok(r) => r,
        Err(denial) => return Ok(denied(denial)),
    };

    let mut headers: Vec<(String, String)> =
        vec![("Host".into(), if port == 80 || port == 443 { host.clone() } else { format!("{host}:{port}") })];
    for (k, v) in credential_headers(credential.as_ref()) {
        set_header(&mut headers, k, v);
    }
    let mut query: IndexMap<String, String> = query.clone();
    for (k, v) in credential_query(credential.as_ref()) {
        query.insert(k, v);
    }

    // Connect to the *checked* IP directly rather than resolving a second
    // time -- that second lookup is exactly the rebinding window FR-8.9
    // closes. TLS stays bound to the real hostname.
    let target_path = match request_path(&format!("{}{path}", parsed.path)) {
        Ok(p) => p,
        Err(exc) => {
            return Ok(denied(Denied::new(
                DenialReason::ParamInvalid,
                format!("Resolved request path is not a valid URL component: {exc}"),
            )))
        }
    };

    // Raw JSON body mode. Resolved before any connection exists, so an
    // unparseable document is refused without one ever being opened.
    let mut body: Option<Value> = body.cloned();
    let mut raw_content: Option<Vec<u8>> = None;
    if let Some(raw_param) = raw_param {
        match raw_json_body(raw_param, body.take()) {
            Ok((content, fallback)) => {
                raw_content = content;
                body = fallback;
            }
            Err(denial) => return Ok(denied(denial)),
        }
    }
    if raw_content.is_some() {
        set_header(&mut headers, "Content-Type".into(), "application/json".into());
    }

    let method = method.to_uppercase();
    let mut content: Option<Vec<u8>> = None;
    if let Some(raw) = raw_content {
        set_header(&mut headers, "Content-Length".into(), raw.len().to_string());
        content = Some(raw);
    } else if let Some(b) = body.as_ref().filter(|b| py_truthy(b)) {
        // httpx's `json=` encoding: compact separators, non-ASCII as is.
        let opts = pyjson::Opts { ensure_ascii: false, ..pyjson::Opts::compact() };
        let encoded = pyjson::dumps_with(b, &opts).into_bytes();
        set_header(&mut headers, "Content-Length".into(), encoded.len().to_string());
        set_header(&mut headers, "Content-Type".into(), "application/json".into());
        content = Some(encoded);
    }
    if content.is_none() && matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        headers.insert(0, ("Content-Length".into(), "0".into()));
    }
    for (k, v) in [
        ("Accept", "*/*"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Connection", "keep-alive"),
        ("User-Agent", USER_AGENT),
    ] {
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case(k)) {
            headers.push((k.into(), v.into()));
        }
    }
    let target = if query.is_empty() { target_path } else { format!("{target_path}?{}", urlencode(&query)) };

    let timeout_msg = |idempotent: bool| -> String {
        if idempotent {
            format!("Timeout of {}s exceeded.", fmt_seconds(timeout_seconds))
        } else {
            format!(
                "Timeout of {}s exceeded. The outcome is UNKNOWN: the request may have reached the target. Do not retry without checking the state first.",
                fmt_seconds(timeout_seconds)
            )
        }
    };
    let timeout_result = |started: Instant| -> ExecResult {
        ExecResult::new(
            if idempotent { OUTCOME_FAILED } else { OUTCOME_UNKNOWN },
            None,
            "",
            timeout_msg(idempotent),
            false,
            elapsed_ms(started),
        )
        .untrusted(true)
    };
    let failed_result = |exc: String, started: Instant| -> ExecResult {
        ExecResult::new(OUTCOME_FAILED, None, "", format!("Request failed: {exc}"), false, elapsed_ms(started))
            .untrusted(true)
    };

    let request = Prepared { scheme: scheme.clone(), host: host.clone(), addr: resolved.addr, method, target, headers, content };
    let sent = tokio::time::timeout(seconds(timeout_seconds), send(&request)).await;
    let (status, response_headers, response_body) = match sent {
        Err(_) | Ok(Err(Failure::Timeout)) => return Ok(timeout_result(started)),
        Ok(Err(Failure::Http(exc))) => return Ok(failed_result(exc, started)),
        Ok(Ok(parts)) => parts,
    };

    let max = max_output_bytes.max(0) as usize;
    let (raw, truncated) = match read_capped(response_body, &response_headers, max).await {
        Ok(r) => r,
        Err(Failure::Timeout) => return Ok(timeout_result(started)),
        Err(Failure::Http(exc)) => return Ok(failed_result(exc, started)),
    };

    let content_type = header_text(&response_headers, "content-type");
    let mut stdout = String::from_utf8_lossy(&raw).into_owned();
    if content_type.contains("json") && !truncated {
        // PORT NOTE: parsed with serde_json, so the few documents Python's
        // `json.loads` accepts and serde_json does not (NaN/Infinity
        // literals, lone surrogate escapes) fall back to the raw text, and
        // an integer beyond 64 bits is re-serialized as a float.
        if let Ok(parsed_json) = serde_json::from_str::<Value>(&stdout) {
            let mut budget = MAX_JSON_ITEMS;
            let capped = cap_json(&parsed_json, &mut budget);
            stdout = pyjson::dumps_with(&capped, &pyjson::Opts::unicode());
        }
    }

    if let (Some(credential), Some(store)) = (credential.as_ref(), credentials) {
        if status == 401 || status == 403 {
            store.mark_suspect(&credential.name, "auth_failed")?;
        }
    }

    let mut stderr = String::new();
    let outcome = if (300..400).contains(&status) {
        // FR-8.8: reported as data, never chased. The Location header is
        // itself untrusted external data and is included as such.
        let location = header_text(&response_headers, "location");
        stderr = format!("Redirect ({status}) to {}, not followed.", repr_str(&location));
        OUTCOME_FAILED
    } else if (200..300).contains(&status) {
        OUTCOME_OK
    } else {
        OUTCOME_FAILED
    };

    if let Some(redact) = redact {
        stdout = redact(&stdout);
        stderr = redact(&stderr);
    }
    Ok(ExecResult::new(outcome, Some(status as i64), stdout, stderr, truncated, elapsed_ms(started)).untrusted(true))
}

/// `headers[name] = value` on an ordered, case-insensitive header list.
fn set_header(headers: &mut Vec<(String, String)>, name: String, value: String) {
    if let Some(slot) = headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&name)) {
        slot.1 = value;
    } else {
        headers.push((name, value));
    }
}

/// httpx's `Headers.get`: several values joined with `", "`, decoded as
/// UTF-8 or else Latin-1.
fn header_text(headers: &HeaderMap, name: &str) -> String {
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .map(|v| match std::str::from_utf8(v.as_bytes()) {
            Ok(s) => s.to_string(),
            Err(_) => v.as_bytes().iter().map(|&b| b as char).collect(),
        })
        .collect();
    values.join(", ")
}

// -- httpx's URL handling ---------------------------------------------------

const MAX_URL_LENGTH: usize = 65536;

/// httpx's `PATH_SAFE` plus the unreserved characters: everything in
/// 0x20..0x7F except space, `"`, `#`, `<`, `>`, `?`, `` ` ``, `{`, `}`.
fn path_safe(c: char) -> bool {
    (0x20..0x7f).contains(&(c as u32)) && !matches!(c, ' ' | '"' | '#' | '<' | '>' | '?' | '`' | '{' | '}')
}

/// The request-target httpx builds from `httpx.URL(path=...)`: the same
/// checks with the same messages (`httpx.InvalidURL`), RFC 3986 dot-segment
/// removal, and percent-encoding of everything outside `PATH_SAFE` while
/// keeping existing `%XX` escapes. An empty path becomes `/`.
pub fn request_path(path: &str) -> Result<String, String> {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() > MAX_URL_LENGTH {
        return Err("URL component 'path' too long".into());
    }
    if let Some(idx) = chars.iter().position(|&c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(format!(
            "Invalid non-printable ASCII character in URL path component, {} at position {idx}.",
            repr_str(&chars[idx].to_string())
        ));
    }
    if chars.iter().any(|&c| c == '?' || c == '#') {
        return Err("Invalid URL component 'path'".into());
    }
    if !path.is_empty() && !path.starts_with('/') {
        return Err("For absolute URLs, path must be empty or begin with '/'".into());
    }
    let normalized = normalize_path(path);
    let quoted = quote_keep_escapes(&normalized, path_safe);
    Ok(if quoted.is_empty() { "/".into() } else { quoted })
}

/// httpx's `normalize_path` (RFC 3986 §5.2.4).
fn normalize_path(path: &str) -> String {
    if !path.contains('.') {
        return path.to_string();
    }
    let components: Vec<&str> = path.split('/').collect();
    if !components.iter().any(|c| *c == "." || *c == "..") {
        return path.to_string();
    }
    let mut output: Vec<&str> = Vec::new();
    for component in components {
        if component == "." {
        } else if component == ".." {
            if !output.is_empty() && output != [""] {
                output.pop();
            }
        } else {
            output.push(component);
        }
    }
    output.join("/")
}

fn percent(c: char, out: &mut String) {
    let mut buf = [0u8; 4];
    for b in c.encode_utf8(&mut buf).bytes() {
        out.push_str(&format!("%{b:02X}"));
    }
}

/// httpx's `quote`: percent-encode, but leave valid `%XX` sequences alone.
fn quote_keep_escapes(s: &str, safe: fn(char) -> bool) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '%'
            && chars.get(i + 1).is_some_and(|h| h.is_ascii_hexdigit())
            && chars.get(i + 2).is_some_and(|h| h.is_ascii_hexdigit())
        {
            out.push(c);
            out.push(chars[i + 1]);
            out.push(chars[i + 2]);
            i += 3;
            continue;
        }
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') || safe(c) {
            out.push(c);
        } else {
            percent(c, &mut out);
        }
        i += 1;
    }
    out
}

/// `urllib.parse.urlencode(items)` -- `quote_plus` on keys and values,
/// which is what httpx's `params=` produces.
pub fn urlencode(items: &IndexMap<String, String>) -> String {
    items
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn quote_plus(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            out.push(c);
        } else if c == ' ' {
            out.push('+');
        } else {
            percent(c, &mut out);
        }
    }
    out
}

// -- Sending ------------------------------------------------------------

struct Prepared {
    scheme: String,
    host: String,
    addr: SocketAddr,
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    content: Option<Vec<u8>>,
}

enum Failure {
    Timeout,
    Http(String),
}

static TLS: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
});

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

/// Connects (5 s, like httpx's connect timeout, TLS handshake included),
/// sends the request and waits for the response head (5 s read timeout).
async fn send(req: &Prepared) -> Result<(u16, HeaderMap, Incoming), Failure> {
    let connect = async {
        let tcp = tokio::net::TcpStream::connect(req.addr)
            .await
            .map_err(|_| Failure::Http("All connection attempts failed".into()))?;
        let stream: Box<dyn Io> = if req.scheme == "https" {
            let server_name = rustls::pki_types::ServerName::try_from(req.host.clone())
                .map_err(|e| Failure::Http(e.to_string()))?;
            let connector = tokio_rustls::TlsConnector::from(TLS.clone());
            let tls = connector.connect(server_name, tcp).await.map_err(|e| Failure::Http(e.to_string()))?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };
        Ok::<_, Failure>(stream)
    };
    let stream = match tokio::time::timeout(HTTPX_DEFAULT_TIMEOUT, connect).await {
        Err(_) => return Err(Failure::Timeout),
        Ok(r) => r?,
    };

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .title_case_headers(true)
        .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(|e| Failure::Http(hyper_error(&e)))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder().method(req.method.as_str()).uri(req.target.as_str());
    for (name, value) in &req.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Failure::Http(format!("Illegal header name {}", py_bytes_repr(name.as_bytes()))))?;
        let value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| Failure::Http(format!("Illegal header value {}", py_bytes_repr(value.as_bytes()))))?;
        builder = builder.header(name, value);
    }
    let body = Full::new(Bytes::from(req.content.clone().unwrap_or_default()));
    let request = builder.body(body).map_err(|e| Failure::Http(e.to_string()))?;
    let response = match tokio::time::timeout(HTTPX_DEFAULT_TIMEOUT, sender.send_request(request)).await {
        Err(_) => return Err(Failure::Timeout),
        Ok(Err(e)) => return Err(Failure::Http(hyper_error(&e))),
        Ok(Ok(r)) => r,
    };
    let (parts, body) = response.into_parts();
    Ok((parts.status.as_u16(), parts.headers, body))
}

/// The text httpx gave the common transport failures.
fn hyper_error(e: &hyper::Error) -> String {
    if e.is_incomplete_message() {
        "Server disconnected without sending a response.".into()
    } else {
        e.to_string()
    }
}

/// Python's `repr(bytes)` (what h11 puts in its header errors).
fn py_bytes_repr(b: &[u8]) -> String {
    let mut out = String::from("b'");
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(c as char),
            _ => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push('\'');
    out
}

/// One content decoder (httpx's `GZipDecoder`/`DeflateDecoder`).
enum Decoder {
    Gzip(flate2::Decompress),
    Deflate { inner: flate2::Decompress, first_attempt: bool },
}

impl Decoder {
    fn decode(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Decoder::Gzip(d) => inflate(d, data),
            Decoder::Deflate { inner, first_attempt } => {
                let was_first = *first_attempt;
                *first_attempt = false;
                match inflate(inner, data) {
                    Ok(out) => Ok(out),
                    Err(_) if was_first => {
                        // httpx: retry as raw deflate (no zlib header).
                        *inner = flate2::Decompress::new(false);
                        inflate(inner, data)
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }
}

fn inflate(d: &mut flate2::Decompress, mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 2 + 64);
    loop {
        if out.capacity() - out.len() < 4096 {
            out.reserve(out.capacity().max(4096));
        }
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress_vec(data, &mut out, flate2::FlushDecompress::None)
            .map_err(|e| format!("Error -3 while decompressing data: {}", e.message().unwrap_or("invalid data")))?;
        let consumed = (d.total_in() - before_in) as usize;
        data = &data[consumed..];
        let produced = d.total_out() - before_out;
        if status == flate2::Status::StreamEnd {
            return Ok(out);
        }
        if data.is_empty() && out.len() < out.capacity() {
            return Ok(out);
        }
        if consumed == 0 && produced == 0 && out.len() < out.capacity() {
            return Ok(out);
        }
    }
}

/// httpx's `_get_content_decoder`: one decoder per supported
/// `Content-Encoding` value (unknown ones are skipped), applied in reverse.
fn decoders_for(headers: &HeaderMap) -> Vec<Decoder> {
    let mut decoders = Vec::new();
    for value in headers.get_all("content-encoding") {
        let text = String::from_utf8_lossy(value.as_bytes()).into_owned();
        for part in text.split(',') {
            match part.trim().to_lowercase().as_str() {
                "gzip" => decoders.push(Decoder::Gzip(flate2::Decompress::new_gzip(15))),
                "deflate" => decoders.push(Decoder::Deflate { inner: flate2::Decompress::new(true), first_attempt: true }),
                _ => {}
            }
        }
    }
    decoders.reverse();
    decoders
}

/// Streams the (decoded) body, stopping at `max` bytes the way Python's
/// chunk loop did: the chunk that would cross the cap is cut and marks the
/// result truncated. Each read waits at most httpx's 5 s read timeout.
async fn read_capped(mut body: Incoming, headers: &HeaderMap, max: usize) -> Result<(Vec<u8>, bool), Failure> {
    let mut decoders = decoders_for(headers);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let frame = match tokio::time::timeout(HTTPX_DEFAULT_TIMEOUT, body.frame()).await {
            Err(_) => return Err(Failure::Timeout),
            Ok(None) => break,
            Ok(Some(Err(e))) => return Err(Failure::Http(hyper_error(&e))),
            Ok(Some(Ok(frame))) => frame,
        };
        let Ok(data) = frame.into_data() else { continue };
        let mut chunk = data.to_vec();
        for decoder in decoders.iter_mut() {
            chunk = decoder.decode(&chunk).map_err(Failure::Http)?;
        }
        if chunk.is_empty() {
            continue;
        }
        if out.len() + chunk.len() > max {
            let room = max - out.len();
            out.extend_from_slice(&chunk[..room]);
            return Ok((out, true));
        }
        out.extend_from_slice(&chunk);
    }
    Ok((out, false))
}

// -- Python's json.loads error messages -------------------------------------

/// What Python's `json.loads(text)` would say about `text`: `Ok(())` when it
/// parses, else the `JSONDecodeError` text (`Expecting value: line 1
/// column 1 (char 0)`). Mirrors CPython's C scanner, including what it
/// accepts beyond RFC 8259 (`NaN`, `Infinity`, lone surrogate escapes).
pub fn py_json_check(text: &str) -> Result<(), String> {
    let s: Vec<char> = text.chars().collect();
    let fail = |msg: &str, pos: usize| -> String {
        let before = &s[..pos.min(s.len())];
        let lineno = before.iter().filter(|&&c| c == '\n').count() + 1;
        let colno = match before.iter().rposition(|&c| c == '\n') {
            Some(nl) => pos - nl,
            None => pos + 1,
        };
        format!("{msg}: line {lineno} column {colno} (char {pos})")
    };
    if s.first() == Some(&'\u{feff}') {
        return Err(fail("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0));
    }
    let start = skip_ws(&s, 0);
    let mut scanner = Scanner { s: &s, depth: 0 };
    match scanner.scan_once(start) {
        Ok(end) => {
            let end = skip_ws(&s, end);
            if end != s.len() {
                return Err(fail("Extra data", end));
            }
            Ok(())
        }
        Err(ScanError::Stop(idx)) => Err(fail("Expecting value", idx)),
        Err(ScanError::Msg(msg, idx)) => Err(fail(msg, idx)),
        // PORT NOTE: Python raised RecursionError (not a ValueError) for a
        // document nested this deep; here it is refused as invalid JSON.
        Err(ScanError::Recursion) => Err("maximum recursion depth exceeded while decoding a JSON document".into()),
    }
}

fn skip_ws(s: &[char], mut idx: usize) -> usize {
    while idx < s.len() && matches!(s[idx], ' ' | '\t' | '\n' | '\r') {
        idx += 1;
    }
    idx
}

enum ScanError {
    Stop(usize),
    Msg(&'static str, usize),
    Recursion,
}

struct Scanner<'a> {
    s: &'a [char],
    depth: usize,
}

impl Scanner<'_> {
    fn at(&self, idx: usize) -> Option<char> {
        self.s.get(idx).copied()
    }

    fn starts(&self, idx: usize, word: &str) -> bool {
        let w: Vec<char> = word.chars().collect();
        self.s.len() >= idx + w.len() && self.s[idx..idx + w.len()] == w[..]
    }

    fn scan_once(&mut self, idx: usize) -> Result<usize, ScanError> {
        let Some(c) = self.at(idx) else { return Err(ScanError::Stop(idx)) };
        match c {
            '"' => self.scan_string(idx + 1),
            '{' => self.nested(|me| me.parse_object(idx + 1)),
            '[' => self.nested(|me| me.parse_array(idx + 1)),
            'n' if self.starts(idx, "null") => Ok(idx + 4),
            't' if self.starts(idx, "true") => Ok(idx + 4),
            'f' if self.starts(idx, "false") => Ok(idx + 5),
            'N' if self.starts(idx, "NaN") => Ok(idx + 3),
            'I' if self.starts(idx, "Infinity") => Ok(idx + 8),
            '-' if self.starts(idx, "-Infinity") => Ok(idx + 9),
            _ => self.match_number(idx),
        }
    }

    fn nested(&mut self, f: impl FnOnce(&mut Self) -> Result<usize, ScanError>) -> Result<usize, ScanError> {
        if self.depth >= 990 {
            return Err(ScanError::Recursion);
        }
        self.depth += 1;
        let r = f(self);
        self.depth -= 1;
        r
    }

    fn match_number(&self, start: usize) -> Result<usize, ScanError> {
        let digit = |i: usize| self.at(i).is_some_and(|c| c.is_ascii_digit());
        let mut idx = start;
        if self.at(idx) == Some('-') {
            idx += 1;
        }
        match self.at(idx) {
            Some('1'..='9') => {
                idx += 1;
                while digit(idx) {
                    idx += 1;
                }
            }
            Some('0') => idx += 1,
            _ => return Err(ScanError::Stop(start)),
        }
        if self.at(idx) == Some('.') && digit(idx + 1) {
            idx += 2;
            while digit(idx) {
                idx += 1;
            }
        }
        if matches!(self.at(idx), Some('e') | Some('E')) {
            let mut j = idx + 1;
            if matches!(self.at(j), Some('-') | Some('+')) {
                j += 1;
            }
            if digit(j) {
                while digit(j) {
                    j += 1;
                }
                idx = j;
            }
        }
        Ok(idx)
    }

    /// `scanstring`, starting just after the opening quote.
    fn scan_string(&self, mut end: usize) -> Result<usize, ScanError> {
        let begin = end - 1;
        let len = self.s.len();
        loop {
            let mut next = end;
            while next < len {
                let c = self.s[next];
                if c == '"' || c == '\\' {
                    break;
                }
                if (c as u32) <= 0x1f {
                    return Err(ScanError::Msg("Invalid control character at", next));
                }
                next += 1;
            }
            if next >= len {
                return Err(ScanError::Msg("Unterminated string starting at", begin));
            }
            if self.s[next] == '"' {
                return Ok(next + 1);
            }
            next += 1; // past the backslash
            if next == len {
                return Err(ScanError::Msg("Unterminated string starting at", begin));
            }
            let c = self.s[next];
            if c != 'u' {
                if !matches!(c, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') {
                    return Err(ScanError::Msg("Invalid \\escape", next - 1));
                }
                end = next + 1;
                continue;
            }
            let u = next;
            let Some(code) = self.hex4(u + 1) else {
                return Err(ScanError::Msg("Invalid \\uXXXX escape", u));
            };
            end = u + 5;
            if (0xd800..=0xdbff).contains(&code) && self.at(end) == Some('\\') && self.at(end + 1) == Some('u') {
                let Some(low) = self.hex4(end + 2) else {
                    return Err(ScanError::Msg("Invalid \\uXXXX escape", end + 1));
                };
                if (0xdc00..=0xdfff).contains(&low) {
                    end += 6;
                }
            }
        }
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        if at + 4 > self.s.len() {
            return None;
        }
        let text: String = self.s[at..at + 4].iter().collect();
        if !text.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(&text, 16).ok()
    }

    fn parse_object(&mut self, start: usize) -> Result<usize, ScanError> {
        let len = self.s.len();
        let mut idx = skip_ws(self.s, start);
        if idx >= len || self.s[idx] != '}' {
            while idx < len {
                if self.s[idx] != '"' {
                    return Err(ScanError::Msg("Expecting property name enclosed in double quotes", idx));
                }
                idx = self.scan_string(idx + 1)?;
                idx = skip_ws(self.s, idx);
                if idx >= len || self.s[idx] != ':' {
                    return Err(ScanError::Msg("Expecting ':' delimiter", idx));
                }
                idx = skip_ws(self.s, idx + 1);
                idx = self.scan_once(idx)?;
                idx = skip_ws(self.s, idx);
                if idx < len && self.s[idx] == '}' {
                    break;
                }
                if idx >= len || self.s[idx] != ',' {
                    return Err(ScanError::Msg("Expecting ',' delimiter", idx));
                }
                let comma = idx;
                idx = skip_ws(self.s, idx + 1);
                if idx < len && self.s[idx] == '}' {
                    return Err(ScanError::Msg("Illegal trailing comma before end of object", comma));
                }
            }
            if idx >= len || self.s[idx] != '}' {
                return Err(ScanError::Msg("Expecting property name enclosed in double quotes", idx));
            }
        }
        Ok(idx + 1)
    }

    fn parse_array(&mut self, start: usize) -> Result<usize, ScanError> {
        let len = self.s.len();
        let mut idx = skip_ws(self.s, start);
        if idx >= len || self.s[idx] != ']' {
            while idx < len {
                idx = self.scan_once(idx)?;
                idx = skip_ws(self.s, idx);
                if idx < len && self.s[idx] == ']' {
                    break;
                }
                if idx >= len || self.s[idx] != ',' {
                    return Err(ScanError::Msg("Expecting ',' delimiter", idx));
                }
                let comma = idx;
                idx = skip_ws(self.s, idx + 1);
                if idx < len && self.s[idx] == ']' {
                    return Err(ScanError::Msg("Illegal trailing comma before end of array", comma));
                }
            }
            if idx >= len || self.s[idx] != ']' {
                return Err(ScanError::Msg("Expecting value", idx));
            }
        }
        Ok(idx + 1)
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
pub(crate) mod tests;
