//! The `kuma` executor: Uptime Kuma monitors over Socket.IO (port of
//! `execute_kuma.py`).
//!
//! Uptime Kuma has no REST API for monitors. Its own web UI creates, pauses
//! and lists them over a Socket.IO connection, so the `http` executor
//! cannot reach any of it -- and the alternatives (an INSERT into Kuma's
//! database plus a restart, or a host script holding the Kuma login
//! outside the credential store) are exactly what gatekeeper exists to
//! replace.
//!
//! So this executor has the `opencode`/`truenas` shape: the whitelist acts
//! on **operation names** (`tier1::KUMA_OPERATIONS`), and one operation is
//! one fixed exchange with Kuma, written out here and nowhere else:
//!
//! * `monitor_list` -- the monitor list Kuma pushes after login, projected
//!   to a handful of fields. Kuma's own monitor objects carry basic-auth
//!   passwords, request headers and bodies; none of those fields is copied.
//! * `monitor_add_http` -- one `add` with type fixed to `http`, method GET.
//!   The caller supplies name, URL, interval, the accepted status range and
//!   the retry settings, nothing else of the monitor object.
//! * `monitor_add_port` (1.29.0) -- one `add` with type fixed to `port`: a
//!   TCP connect to a hostname or IPv4 address and a port. The target must
//!   be in the toolkit's `allowed_monitor_targets`, checked before anything
//!   is sent.
//! * Both add operations attach exactly the toolkit's
//!   `kuma_notification_ids` (1.29.0), after checking against the
//!   `notificationList` Kuma pushes on login that every one of them exists;
//!   an unknown ID aborts before the `add`. The caller cannot name any.
//! * `monitor_pause` / `monitor_resume` -- only for a monitor this executor
//!   created. Ownership is the `description` it writes on `add`
//!   ([`MANAGED_MARKER`]); a monitor somebody set up by hand is refused
//!   before anything is sent for it.
//!
//! There is no delete, no edit, and nothing that changes notifications or
//! settings: those events are simply never emitted by this module. The
//! notification list is only read, and only its IDs are looked at.
//!
//! What it keeps from the `http` executor, by reusing that module's
//! helpers: the target lives only on the toolkit (`base_url`), the resolved
//! address is checked against `allowed_hosts`/`allowed_cidrs` immediately
//! before the connect and the socket is opened to that address literally
//! (FR-8.9), and every answer is external, untrusted data with the FR-8.12
//! field cap.
//!
//! The Socket.IO client is the minimum Kuma needs: Engine.IO v4 over a
//! WebSocket transport, the default namespace, events with
//! acknowledgements, and answering the server's pings. Each call opens one
//! connection, logs in, does its one thing, and closes -- the same
//! reasoning as the `truenas` executor.
//!
//! Login is Kuma's socket `login` event (Uptime Kuma 1.23 and 2.0) with a
//! `basic` credential (`user:password`). The password goes to Kuma and
//! nowhere else -- not into a response, an error text or the audit log. A
//! Kuma account with 2FA cannot be used: there is nobody to type the code.
//!
//! PORT NOTE: Python used the `websockets` library, connecting with
//! `host=<checked address>, proxy=None`. The port opens the TCP stream to
//! the checked address itself (asyncio's `Connect call failed` text on
//! failure) and runs the WebSocket handshake over it with tokio-tungstenite,
//! so the URL's hostname stays in the Host header and the TLS server name
//! while the socket goes to the address that passed the check; no proxy is
//! ever consulted. Kept from websockets: `max_size`, the handshake refusal
//! text (`server rejected WebSocket connection: HTTP 404`), the
//! `ConnectionClosed` texts and the bounded close handshake.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::SinkExt;
use serde_json::{json, Map, Value};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};

use super::http::{
    cap_json, default_port, fmt_seconds, host_info, parse_port, resolve_and_check, seconds, sockaddr_repr,
    MAX_JSON_ITEMS,
};
use super::truenas::{close, recv, ws_error, Ws, WsError};
use super::{elapsed_ms, ExecResult, Redact, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::credentials::{CredentialStore, ResolvedCredential};
use crate::errors::{ConfigError, DenialReason, Denied};
use crate::pyfmt::{repr_list, repr_str, str_value};
use crate::pyjson;
use crate::tier1::{
    ip_network, is_monitor_hostname, py_truthy, urlsplit, Toolkit, KUMA_INTERVAL_MAX, KUMA_INTERVAL_MIN,
    KUMA_MAXRETRIES_MAX, KUMA_MAXRETRIES_MIN, KUMA_PORT_MAX, KUMA_PORT_MIN, KUMA_RETRY_INTERVAL_MAX,
    KUMA_RETRY_INTERVAL_MIN, KUMA_STATUS_CODES,
};

/// What `monitor_add_http` writes into a monitor's description, and what
/// `monitor_pause`/`monitor_resume` require to find there. A prefix rather
/// than an exact string so the toolkit name after it is information for
/// the human reading Kuma's UI, not a second key that a toolkit rename
/// would silently orphan.
pub const MANAGED_MARKER: &str = "Managed by gatekeeper";

/// How long `monitor_add_http` waits for Kuma's `info` event (which names
/// its version) before assuming a 1.x server. Kuma sends it right after
/// login; this only bounds a server that never does.
const INFO_WAIT_SECONDS: f64 = 3.0;

/// How long an add operation waits for Kuma's `notificationList` event
/// (pushed right after login) when the toolkit names notification IDs.
/// Without it the IDs cannot be checked, so nothing is added.
const NOTIFICATION_WAIT_SECONDS: f64 = 5.0;

/// The longest name `monitor_add_port` accepts (1.29.0).
const PORT_NAME_MAX: usize = 60;

/// The events that change something in Kuma. Once one is on the wire, a
/// timeout no longer means "nothing happened" (FR-6.9).
const WRITE_EVENTS: &[&str] = &["add", "pauseMonitor", "resumeMonitor"];

/// The operations this module has code for (Python's `_OPERATIONS`).
const OPERATIONS: &[&str] = &["monitor_list", "monitor_add_http", "monitor_add_port", "monitor_pause", "monitor_resume"];

/// How one exchange can end besides success -- Python's exception types.
#[derive(Debug)]
enum Fail {
    Denied(Denied),
    /// `_KumaError`: Kuma answered, and the answer was a refusal or not
    /// understood.
    Kuma(String),
    /// `TimeoutError`.
    Timeout,
    /// `websockets.exceptions.WebSocketException`, as its `str()`.
    Ws(String),
}

impl From<WsError> for Fail {
    fn from(e: WsError) -> Self {
        Fail::Ws(e.0)
    }
}

fn kuma_error(message: impl Into<String>) -> Fail {
    Fail::Kuma(message.into())
}

/// Engine.IO v4 + Socket.IO v4, default namespace, WebSocket only.
///
/// Packets are text frames: Engine.IO type digit first (`0` open, `2`
/// ping, `3` pong, `4` message), and inside a message the Socket.IO type
/// (`0` connect, `2` event, `3` ack, `4` connect error), an optional ack
/// id, then a JSON array. Events Kuma pushes on its own (`monitorList`,
/// `info`, ...) are kept by name, last one wins, so an operation can wait
/// for one that arrived while it was waiting for something else.
struct SocketIo {
    ws: Ws,
    deadline: Instant,
    events: HashMap<String, Vec<Value>>,
    acks: HashMap<u128, Vec<Value>>,
    next_id: u64,
    /// True once a [`WRITE_EVENTS`] event has been sent.
    sent_write: bool,
}

/// The number of leading ASCII digits (`len(s) - len(s.lstrip("0123456789"))`).
fn leading_digits(s: &str) -> usize {
    s.len() - s.trim_start_matches(|c: char| c.is_ascii_digit()).len()
}

/// `_json_array`: the body as a JSON array, `[]` for anything else.
///
/// PORT NOTE: Python's `json.loads` also accepted `NaN`/`Infinity` and kept
/// integers beyond 64 bits exact; serde_json rejects the former (the frame
/// then reads as `[]`) and reads the latter as a float.
fn json_array(body: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Array(items)) => items,
        _ => Vec::new(),
    }
}

impl SocketIo {
    fn new(ws: Ws, deadline: Instant) -> Self {
        SocketIo { ws, deadline, events: HashMap::new(), acks: HashMap::new(), next_id: 0, sent_write: false }
    }

    fn remaining(&self) -> Result<Duration, Fail> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(Fail::Timeout);
        }
        Ok(self.deadline - now)
    }

    async fn send(&mut self, text: String) -> Result<(), Fail> {
        self.ws.send(Message::text(text)).await.map_err(|e| Fail::from(ws_error(e)))
    }

    async fn recv(&mut self, until: Option<Instant>) -> Result<String, Fail> {
        let mut budget = self.remaining()?;
        if let Some(until) = until {
            let now = Instant::now();
            if until <= now {
                return Err(Fail::Timeout);
            }
            budget = budget.min(until - now);
        }
        match tokio::time::timeout(budget, recv(&mut self.ws)).await {
            Err(_) => Err(Fail::Timeout),
            Ok(r) => Ok(r?),
        }
    }

    /// Reads one frame and files it. Returns the Socket.IO packet (without
    /// the Engine.IO `4`) for the caller to inspect, or `None` for
    /// transport-level frames.
    async fn pump(&mut self, until: Option<Instant>) -> Result<Option<String>, Fail> {
        let frame = self.recv(until).await?;
        if frame == "2" {
            self.send("3".to_string()).await?;
            return Ok(None);
        }
        if frame.starts_with('1') {
            return Err(kuma_error("Uptime Kuma closed the connection."));
        }
        let Some(packet) = frame.strip_prefix('4') else { return Ok(None) };
        if let Some(rest) = packet.strip_prefix('2') {
            let mut args = json_array(&rest[leading_digits(rest)..]);
            if let Some(Value::String(name)) = args.first() {
                let name = name.clone();
                args.remove(0);
                self.events.insert(name, args);
            }
        } else if let Some(body) = packet.strip_prefix('3') {
            let digits = leading_digits(body);
            if digits > 0 {
                // PORT NOTE: an ack id beyond 128 bits (Python: any int)
                // cannot be one this client sent; it is dropped.
                if let Ok(id) = body[..digits].parse::<u128>() {
                    self.acks.insert(id, json_array(&body[digits..]));
                }
            }
        }
        Ok(Some(packet.to_string()))
    }

    /// The Engine.IO handshake, then a connect to the default namespace.
    async fn open(&mut self) -> Result<(), Fail> {
        let frame = self.recv(None).await?;
        if !frame.starts_with('0') {
            return Err(kuma_error(
                "The server did not open a Socket.IO session -- is base_url an Uptime Kuma?",
            ));
        }
        self.send("40".to_string()).await?;
        loop {
            let Some(packet) = self.pump(None).await? else { continue };
            if packet.starts_with('0') {
                return Ok(());
            }
            if packet.starts_with('4') {
                return Err(kuma_error("Uptime Kuma refused the Socket.IO connection."));
            }
        }
    }

    /// Emits `event` with an ack id and returns the ack's first value.
    async fn call(&mut self, event: &str, args: Vec<Value>) -> Result<Value, Fail> {
        let ack_id = self.next_id;
        self.next_id += 1;
        if WRITE_EVENTS.contains(&event) {
            self.sent_write = true;
        }
        let mut payload = vec![Value::String(event.to_string())];
        payload.extend(args);
        let text = pyjson::dumps_with(&Value::Array(payload), &pyjson::Opts::unicode());
        self.send(format!("42{ack_id}{text}")).await?;
        let key = u128::from(ack_id);
        while !self.acks.contains_key(&key) {
            self.pump(None).await?;
        }
        let values = self.acks.remove(&key).unwrap_or_default();
        Ok(values.into_iter().next().unwrap_or(Value::Null))
    }

    /// The args of the last `name` event, waiting for it if needed.
    ///
    /// `accept`, if given, is a predicate over those args: an event it
    /// rejects counts as not yet arrived. With `wait_seconds`, gives up
    /// after that long and returns `None`; without, waits for the
    /// operation's whole remaining budget.
    async fn event(
        &mut self,
        name: &str,
        wait_seconds: Option<f64>,
        accept: Option<fn(&[Value]) -> bool>,
    ) -> Result<Option<Vec<Value>>, Fail> {
        let until = wait_seconds.map(|w| Instant::now() + seconds(w));
        loop {
            if let Some(args) = self.events.get(name) {
                if accept.is_none_or(|f| f(args)) {
                    return Ok(Some(args.clone()));
                }
            }
            match self.pump(until).await {
                Ok(_) => {}
                Err(Fail::Timeout) if until.is_some() && Instant::now() < self.deadline => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
}

/// `str.isspace()` for one character: Unicode White_Space plus the four
/// information separators U+001C..U+001F Python also counts.
pub(crate) fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Characters whose NFKC form contains one of `/?#@:` (generated from
/// Python's `unicodedata`, Unicode 15.1) -- what `urllib.parse._checknetloc`
/// refuses in a non-ASCII netloc.
const NFKC_NETLOC_HAZARDS: &[char] = &[
    '\u{2047}', '\u{2048}', '\u{2049}', '\u{2100}', '\u{2101}', '\u{2105}', '\u{2106}', '\u{2a74}', '\u{fe13}',
    '\u{fe16}', '\u{fe55}', '\u{fe56}', '\u{fe5f}', '\u{fe6b}', '\u{ff03}', '\u{ff0f}', '\u{ff1a}', '\u{ff1f}',
    '\u{ff20}',
];

/// `ipaddress.ip_address(s)`: `Some(true)` for IPv4, `Some(false)` for
/// IPv6 (an optional `%zone` included), `None` when it is neither.
fn ip_kind(s: &str) -> Option<bool> {
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(true);
    }
    let addr = match s.split_once('%') {
        Some((addr, zone)) if !zone.is_empty() && !zone.contains('%') => addr,
        Some(_) => return None,
        None => s,
    };
    addr.parse::<std::net::Ipv6Addr>().ok().map(|_| false)
}

/// The `ValueError`s Python's `urlsplit()` raises for a netloc: unbalanced
/// brackets, a bracketed host that is not an IPv6/IPvFuture address, and
/// characters that turn into URL delimiters under NFKC.
pub(crate) fn netloc_is_valid(netloc: &str) -> bool {
    let open = netloc.contains('[');
    let close = netloc.contains(']');
    if open != close {
        return false;
    }
    if open {
        let host_and_port = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
        let hostname = match host_and_port.split_once('[') {
            Some((before, bracketed)) => {
                if !before.is_empty() {
                    return false;
                }
                let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                if !port.is_empty() && !port.starts_with(':') {
                    return false;
                }
                hostname
            }
            None => host_and_port.split_once(':').map_or(host_and_port, |(h, _)| h),
        };
        if hostname.starts_with(['v', 'V']) {
            // \A[vV][a-fA-F0-9]+\..+\Z
            let rest = &hostname[1..];
            let hex = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_hexdigit()).len();
            let after = &rest[hex..];
            if hex == 0 || !after.starts_with('.') || after.len() < 2 || after[1..].contains('\n') {
                return false;
            }
        } else if ip_kind(hostname) != Some(false) {
            return false;
        }
    }
    if !netloc.is_ascii() {
        let stripped = netloc.chars().filter(|c| !matches!(c, '@' | ':' | '#' | '?'));
        if stripped.into_iter().any(|c| NFKC_NETLOC_HAZARDS.contains(&c)) {
            return false;
        }
    }
    true
}

/// What `urlsplit(url)` plus `.hostname`/`.port` yield, or `None` where
/// Python raised `ValueError`.
struct UrlParts {
    scheme: String,
    netloc: String,
    path: String,
    /// `.hostname`, `None` when empty.
    hostname: Option<String>,
    port: Option<u16>,
}

fn split_url(url: &str) -> Option<UrlParts> {
    let parsed = urlsplit(url);
    if !netloc_is_valid(&parsed.netloc) {
        return None;
    }
    let info = host_info(&parsed.netloc);
    let port = parse_port(&info.port).ok()?;
    Some(UrlParts {
        scheme: parsed.scheme,
        netloc: parsed.netloc,
        path: parsed.path,
        hostname: (!info.hostname.is_empty()).then_some(info.hostname),
        port,
    })
}

/// `_socket_url`: the Socket.IO endpoint under `base_url`, and the
/// host/port to check.
///
/// PORT NOTE: a `base_url` whose port does not parse raised ValueError out
/// of Python's `run()`; `load_tier1` refuses one, and here it is the error
/// text of a failed connect.
fn socket_url(base_url: &str) -> Result<(String, String, u16), String> {
    let parsed = urlsplit(base_url);
    let scheme = if parsed.scheme == "https" { "wss" } else { "ws" };
    let info = host_info(&parsed.netloc);
    let port = default_port(parse_port(&info.port)?, &parsed.scheme);
    let path = format!("{}/socket.io/", parsed.path.trim_end_matches('/'));
    Ok((format!("{scheme}://{}{path}?EIO=4&transport=websocket", parsed.netloc), info.hostname, port))
}

fn split_basic(credential: &ResolvedCredential) -> Result<(String, String), Denied> {
    match credential.value.split_once(':') {
        Some((username, password)) if credential.kind == "basic" => {
            Ok((username.to_string(), password.to_string()))
        }
        _ => Err(Denied::new(
            DenialReason::CredentialUnavailable,
            format!(
                "Credential {} must be kind 'basic' with the value 'username:password' of the Kuma login.",
                repr_str(&credential.name)
            ),
        )),
    }
}

async fn login(sio: &mut SocketIo, credential: &ResolvedCredential) -> Result<(), Fail> {
    let (username, password) = split_basic(credential).map_err(Fail::Denied)?;
    let answer = sio.call("login", vec![json!({"username": username, "password": password, "token": ""})]).await?;
    let Value::Object(answer) = answer else {
        return Err(Fail::Denied(Denied::new(
            DenialReason::CredentialUnavailable,
            "Uptime Kuma did not answer the login.",
        )));
    };
    if answer.get("tokenRequired").is_some_and(py_truthy) {
        return Err(Fail::Denied(Denied::new(
            DenialReason::CredentialUnavailable,
            "The Kuma account has 2FA enabled. Gatekeeper cannot supply a TOTP \
             code; use an account without 2FA for this toolkit.",
        )));
    }
    if answer.get("ok") != Some(&Value::Bool(true)) {
        // Kuma's own texts here are fixed strings ("Incorrect username or
        // password.", a rate-limit notice) and never echo the password.
        let reason = match answer.get("msg") {
            Some(Value::String(m)) => m.clone(),
            _ => "refused".to_string(),
        };
        return Err(Fail::Denied(Denied::new(
            DenialReason::CredentialUnavailable,
            format!("Uptime Kuma login failed: {reason}"),
        )));
    }
    Ok(())
}

fn is_managed(monitor: &Value) -> bool {
    matches!(monitor.get("description"), Some(Value::String(d)) if d.starts_with(MANAGED_MARKER))
}

/// `_public_url`: a monitor URL without userinfo, query or fragment.
///
/// A hand-made monitor may well carry a token in its URL; the list is for
/// telling monitors apart, which scheme, host and path already do.
fn public_url(raw: Option<&Value>) -> Value {
    let Some(Value::String(raw)) = raw else { return Value::Null };
    if raw.is_empty() {
        return Value::Null;
    }
    let Some(parsed) = split_url(raw) else { return Value::Null };
    let Some(host) = parsed.hostname.filter(|_| !parsed.scheme.is_empty()) else { return Value::Null };
    let mut netloc = if host.contains(':') { format!("[{host}]") } else { host };
    if let Some(port) = parsed.port {
        netloc.push_str(&format!(":{port}"));
    }
    // urlunsplit((scheme, netloc, path, "", "")): with a netloc, a path
    // that does not start with '/' gets one.
    let path = if !parsed.path.is_empty() && !parsed.path.starts_with('/') {
        format!("/{}", parsed.path)
    } else {
        parsed.path
    };
    Value::String(format!("{}://{netloc}{path}", parsed.scheme))
}

fn summary(monitor_id: &str, monitor: &Map<String, Value>) -> Value {
    let get = |k: &str| monitor.get(k).cloned().unwrap_or(Value::Null);
    let monitor_value = Value::Object(monitor.clone());
    let typ = monitor.get("type");
    let url = match typ {
        Some(Value::String(t)) if matches!(t.as_str(), "http" | "keyword" | "json-query") => {
            public_url(monitor.get("url"))
        }
        _ => Value::Null,
    };
    json!({
        "id": monitor.get("id").cloned().unwrap_or_else(|| Value::String(monitor_id.to_string())),
        "name": get("name"),
        "type": get("type"),
        "url": url,
        "active": monitor.get("active").is_some_and(py_truthy),
        "interval": get("interval"),
        "managed": is_managed(&monitor_value),
    })
}

fn version_of(info: &[Value]) -> Option<String> {
    match info.first().and_then(|p| p.get("version")) {
        Some(Value::String(v)) if !v.is_empty() => Some(v.clone()),
        _ => None,
    }
}

/// Kuma's major version from its `info` event, 1 when it names none.
///
/// Kuma sends `info` twice: on connect with the version hidden, and again
/// after login with it -- so the caller waits for one that has it.
///
/// PORT NOTE: Python's `str.isdigit()` also accepted non-ASCII digits;
/// only ASCII digits count here (Kuma's versions are ASCII).
fn major_version(info: Option<&[Value]>) -> u64 {
    if let Some(version) = info.and_then(version_of) {
        let head = version.trim_start_matches('v').split('.').next().unwrap_or("");
        if !head.is_empty() && head.chars().all(|c| c.is_ascii_digit()) {
            return head.parse::<u64>().unwrap_or(u64::MAX);
        }
    }
    1
}

/// What both add operations share (1.29.0): the check cadence, the retry
/// settings and the notifications, all already bounded.
#[derive(Debug, Clone, PartialEq)]
pub struct MonitorSettings {
    pub interval: i64,
    pub maxretries: i64,
    pub retry_interval: i64,
    /// Exactly the toolkit's `kuma_notification_ids`.
    pub notification_ids: Vec<u64>,
}

/// Kuma's `notificationIDList`: `{"<id>": true, ...}`, the shape its own UI
/// sends and its `add` handler reads (it inserts one monitor_notification
/// row per key whose value is true).
fn notification_id_list(ids: &[u64]) -> Value {
    Value::Object(ids.iter().map(|id| (id.to_string(), Value::Bool(true))).collect())
}

/// The fields every gatekeeper-made monitor carries, whatever its type:
/// Kuma's own UI defaults, with the cadence, retries and notifications from
/// `settings`. Everything that could carry a secret or reach somewhere else
/// (headers, body, auth, proxy) is left out.
///
/// Kuma's `add` handler JSON-encodes the Kafka fields on 1.23 and 2.0
/// alike and additionally `conditions`/`rabbitmqNodes` on 2.0, whose
/// database rejects them missing -- so those two are sent to a 2.x server
/// only, where the column exists.
fn base_monitor(typ: &str, name: &str, settings: &MonitorSettings, toolkit: &str, major: u64) -> Value {
    let interval = settings.interval;
    let mut monitor = json!({
        "type": typ,
        "name": name,
        "interval": interval,
        "retryInterval": settings.retry_interval,
        "resendInterval": 0,
        "maxretries": settings.maxretries,
        "timeout": 48.min((interval as f64 * 0.8) as i64),
        "notificationIDList": notification_id_list(&settings.notification_ids),
        "upsideDown": false,
        "expiryNotification": false,
        "description": format!("{MANAGED_MARKER} (toolkit {toolkit})"),
        "kafkaProducerBrokers": [],
        "kafkaProducerSaslOptions": {"mechanism": "None"},
    });
    if major >= 2 {
        monitor["conditions"] = json!([]);
        monitor["rabbitmqNodes"] = json!([]);
    }
    monitor
}

/// The `add` payload for an HTTP(s) GET monitor: only name, url, the
/// accepted status range and `settings` come from the call.
pub fn http_monitor(
    name: &str,
    url: &str,
    expected_status: &str,
    settings: &MonitorSettings,
    toolkit: &str,
    major: u64,
) -> Value {
    let mut monitor = base_monitor("http", name, settings, toolkit, major);
    monitor["url"] = json!(url);
    monitor["method"] = json!("GET");
    monitor["accepted_statuscodes"] = json!([expected_status]);
    monitor["ignoreTls"] = json!(false);
    monitor["maxredirects"] = json!(10);
    monitor
}

/// The `add` payload for a TCP port monitor (1.29.0): hostname and port
/// from the call. `url` and `accepted_statuscodes` carry the values Kuma's
/// UI sends for every monitor type (a port check reads neither), because
/// the `add` handler encodes `accepted_statuscodes` unconditionally.
pub fn port_monitor(
    name: &str,
    hostname: &str,
    port: u16,
    settings: &MonitorSettings,
    toolkit: &str,
    major: u64,
) -> Value {
    let mut monitor = base_monitor("port", name, settings, toolkit, major);
    monitor["hostname"] = json!(hostname);
    monitor["port"] = json!(port);
    monitor["url"] = json!("https://");
    monitor["accepted_statuscodes"] = json!(["200-299"]);
    monitor
}

fn ack_ok(answer: Value, what: &str) -> Result<Map<String, Value>, Fail> {
    let Value::Object(answer) = answer else {
        return Err(kuma_error(format!("Uptime Kuma sent no usable answer to {what}.")));
    };
    if answer.get("ok") != Some(&Value::Bool(true)) {
        let msg = match answer.get("msg") {
            Some(Value::String(m)) => m.clone(),
            _ => "no reason given".to_string(),
        };
        return Err(kuma_error(format!("Uptime Kuma refused {what}: {msg}")));
    }
    Ok(answer)
}

async fn op_list(sio: &mut SocketIo) -> Result<Value, Fail> {
    let args = sio.event("monitorList", None, None).await?.unwrap_or_default();
    let mut items: Vec<Value> = match args.first() {
        Some(Value::Object(monitors)) => monitors
            .iter()
            .filter_map(|(mid, m)| m.as_object().map(|m| summary(mid, m)))
            .collect(),
        _ => Vec::new(),
    };
    let key = |m: &Value| {
        let name = m.get("name").filter(|n| py_truthy(n)).map(str_value).unwrap_or_default();
        (name, str_value(m.get("id").unwrap_or(&Value::Null)))
    };
    items.sort_by_key(key);
    let count = items.len();
    Ok(json!({"monitors": items, "count": count}))
}

fn get<'a>(values: &'a crate::validate::Values, key: &str) -> Option<&'a str> {
    values.get(key).map(String::as_str)
}

/// `values.get(key) or default`.
fn get_or<'a>(values: &'a crate::validate::Values, key: &str, default: &'a str) -> &'a str {
    get(values, key).filter(|v| !v.is_empty()).unwrap_or(default)
}

/// The IDs in Kuma's `notificationList` event (an array of notification
/// objects). Only `id` is read; a notification's `config` holds webhook
/// URLs and tokens and is never copied anywhere.
fn notification_ids_of(args: &[Value]) -> Vec<u64> {
    match args.first() {
        Some(Value::Array(items)) => items.iter().filter_map(|n| n.get("id").and_then(Value::as_u64)).collect(),
        _ => Vec::new(),
    }
}

/// Before an `add`: every ID in the toolkit's `kuma_notification_ids` must
/// exist in this Kuma. A missing one (or a Kuma that sends no list) aborts
/// the call before anything is written -- a monitor that silently alerts
/// nobody is worse than no monitor.
async fn check_notifications(sio: &mut SocketIo, toolkit: &Toolkit) -> Result<(), Fail> {
    if toolkit.kuma_notification_ids.is_empty() {
        return Ok(());
    }
    let Some(args) = sio.event("notificationList", Some(NOTIFICATION_WAIT_SECONDS), None).await? else {
        return Err(kuma_error(
            "Uptime Kuma sent no notification list, so the toolkit's kuma_notification_ids cannot be \
             checked. Nothing was added.",
        ));
    };
    let known = notification_ids_of(&args);
    let missing: Vec<String> = toolkit
        .kuma_notification_ids
        .iter()
        .filter(|id| !known.contains(id))
        .map(|id| id.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(Fail::Denied(Denied::new(
            DenialReason::Tier1Violation,
            format!(
                "Notification ID(s) {} of this toolkit's kuma_notification_ids do not exist in Uptime Kuma. \
                 Nothing was added.",
                missing.join(", ")
            ),
        )));
    }
    Ok(())
}

/// The bounded settings of one add call: the values (the tool's `fixed:`
/// ones are already merged in), the defaults Kuma's UI uses, and the
/// toolkit's notification IDs.
fn settings_of(values: &crate::validate::Values, toolkit: &Toolkit) -> MonitorSettings {
    let interval: i64 = get_or(values, "interval", "60").parse().unwrap_or(60);
    let maxretries: i64 = get_or(values, "maxretries", "0").parse().unwrap_or(0);
    let retry_interval: i64 = match get(values, "retry_interval").filter(|v| !v.is_empty()) {
        Some(v) => v.parse().unwrap_or(interval),
        None => interval,
    };
    MonitorSettings { interval, maxretries, retry_interval, notification_ids: toolkit.kuma_notification_ids.clone() }
}

/// Sends the `add`, then reads the new monitor back for its `active` flag.
/// The read-back is a plain `getMonitor`; if it fails the monitor exists
/// anyway, so the call still succeeds with `active: null`.
async fn add_monitor(sio: &mut SocketIo, monitor: &Value) -> Result<(Value, Value), Fail> {
    let answer = ack_ok(sio.call("add", vec![monitor.clone()]).await?, "the new monitor")?;
    let monitor_id = answer.get("monitorID").cloned().unwrap_or(Value::Null);
    let mut active = Value::Null;
    if let Some(id) = monitor_id.as_u64() {
        if let Ok(Value::Object(read)) = sio.call("getMonitor", vec![json!(id)]).await {
            if read.get("ok").is_some_and(py_truthy) {
                if let Some(flag) = read.get("monitor").and_then(|m| m.get("active")) {
                    active = Value::Bool(py_truthy(flag));
                }
            }
        }
    }
    Ok((monitor_id, active))
}

async fn kuma_major(sio: &mut SocketIo) -> Result<u64, Fail> {
    let accept: fn(&[Value]) -> bool = |args| version_of(args).is_some();
    let info = sio.event("info", Some(INFO_WAIT_SECONDS), Some(accept)).await?;
    Ok(major_version(info.as_deref()))
}

async fn op_add_http(sio: &mut SocketIo, values: &crate::validate::Values, toolkit: &Toolkit) -> Result<Value, Fail> {
    let major = kuma_major(sio).await?;
    check_notifications(sio, toolkit).await?;
    let settings = settings_of(values, toolkit);
    let monitor = http_monitor(
        get(values, "name").unwrap_or(""),
        get(values, "url").unwrap_or(""),
        get_or(values, "expected_status", "200-299"),
        &settings,
        &toolkit.name,
        major,
    );
    let (monitor_id, active) = add_monitor(sio, &monitor).await?;
    Ok(json!({
        "monitor_id": monitor_id,
        "active": active,
        "name": monitor["name"],
        "url": monitor["url"],
        "interval": monitor["interval"],
        "maxretries": monitor["maxretries"],
        "retry_interval": monitor["retryInterval"],
        "notification_ids": settings.notification_ids,
        "accepted_statuscodes": monitor["accepted_statuscodes"],
    }))
}

async fn op_add_port(sio: &mut SocketIo, values: &crate::validate::Values, toolkit: &Toolkit) -> Result<Value, Fail> {
    let major = kuma_major(sio).await?;
    check_notifications(sio, toolkit).await?;
    let settings = settings_of(values, toolkit);
    let port: u16 = get(values, "port").unwrap_or("").parse().unwrap_or(0);
    let monitor = port_monitor(
        get(values, "name").unwrap_or(""),
        &get(values, "hostname").unwrap_or("").to_ascii_lowercase(),
        port,
        &settings,
        &toolkit.name,
        major,
    );
    let (monitor_id, active) = add_monitor(sio, &monitor).await?;
    Ok(json!({
        "monitor_id": monitor_id,
        "active": active,
        "name": monitor["name"],
        "hostname": monitor["hostname"],
        "port": monitor["port"],
        "interval": monitor["interval"],
        "maxretries": monitor["maxretries"],
        "retry_interval": monitor["retryInterval"],
        "notification_ids": settings.notification_ids,
    }))
}

async fn owned_monitor(sio: &mut SocketIo, monitor_id: u64) -> Result<Map<String, Value>, Fail> {
    let answer = sio.call("getMonitor", vec![json!(monitor_id)]).await?;
    let monitor = match &answer {
        Value::Object(a) if a.get("ok").is_some_and(py_truthy) => a.get("monitor").cloned(),
        _ => None,
    };
    let Some(Value::Object(monitor)) = monitor else {
        return Err(kuma_error(format!("Monitor {monitor_id} does not exist.")));
    };
    if !is_managed(&Value::Object(monitor.clone())) {
        return Err(Fail::Denied(Denied::new(
            DenialReason::Tier1Violation,
            format!(
                "Monitor {monitor_id} was not created through gatekeeper; this toolkit \
                 only pauses and resumes its own monitors."
            ),
        )));
    }
    Ok(monitor)
}

async fn op_pause_resume(sio: &mut SocketIo, values: &crate::validate::Values, pause: bool) -> Result<Value, Fail> {
    let monitor_id: u64 = get(values, "monitor_id").unwrap_or("").parse().unwrap_or(0);
    let monitor = owned_monitor(sio, monitor_id).await?;
    let (event, what) = if pause {
        ("pauseMonitor", format!("pausing monitor {monitor_id}"))
    } else {
        ("resumeMonitor", format!("resuming monitor {monitor_id}"))
    };
    ack_ok(sio.call(event, vec![json!(monitor_id)]).await?, &what)?;
    Ok(json!({
        "monitor_id": monitor_id,
        "name": monitor.get("name").cloned().unwrap_or(Value::Null),
        "active": !pause,
    }))
}

/// `^\d+$` the way the executor reads it, as an integer.
///
/// PORT NOTE: Python's `str.isdigit()`/`int()` also accepted non-ASCII
/// decimal digits (and crashed on superscripts); `validate_scalar` only
/// ever produces ASCII decimals, so only those are accepted here, and a
/// value beyond 64 bits counts as invalid.
fn ascii_uint(s: &str) -> Option<u64> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// The executor's own floor under whatever the tool definition says.
///
/// A tool definition may narrow these (a stricter URL pattern, a shorter
/// enum); it can never widen them, because they are checked here again
/// regardless of what it declares.
pub fn check_values(operation: &str, values: &crate::validate::Values) -> Result<(), Denied> {
    let invalid = |msg: String| Err(Denied::new(DenialReason::ParamInvalid, msg));
    if matches!(operation, "monitor_add_http" | "monitor_add_port") {
        for (param, min, max, unit) in [
            ("interval", KUMA_INTERVAL_MIN, KUMA_INTERVAL_MAX, " seconds"),
            ("maxretries", KUMA_MAXRETRIES_MIN, KUMA_MAXRETRIES_MAX, ""),
            ("retry_interval", KUMA_RETRY_INTERVAL_MIN, KUMA_RETRY_INTERVAL_MAX, " seconds"),
        ] {
            if let Some(v) = get(values, param) {
                if !ascii_uint(v).is_some_and(|n| (min as u64..=max as u64).contains(&n)) {
                    return invalid(format!("Parameter {} must be {min}-{max}{unit}.", repr_str(param)));
                }
            }
        }
    }
    if operation == "monitor_add_port" {
        let name = get(values, "name").unwrap_or("");
        if name.trim_matches(py_isspace).is_empty() || name.chars().count() > PORT_NAME_MAX {
            return invalid(format!("Parameter 'name' must be 1-{PORT_NAME_MAX} characters."));
        }
        let hostname = get(values, "hostname").unwrap_or("");
        if !is_monitor_hostname(hostname) {
            return invalid(
                "Parameter 'hostname' must be a hostname or an IPv4 address -- no scheme, port, path or user."
                    .into(),
            );
        }
        let port = get(values, "port").unwrap_or("");
        if !ascii_uint(port).is_some_and(|n| (KUMA_PORT_MIN as u64..=KUMA_PORT_MAX as u64).contains(&n)) {
            return invalid(format!("Parameter 'port' must be {KUMA_PORT_MIN}-{KUMA_PORT_MAX}."));
        }
    } else if operation == "monitor_add_http" {
        let name = get(values, "name").unwrap_or("");
        if name.trim_matches(py_isspace).is_empty() || name.chars().count() > 150 {
            return invalid("Parameter 'name' must be 1-150 characters.".into());
        }
        let url = get(values, "url").unwrap_or("");
        let Some(parsed) = split_url(url) else {
            return invalid("Parameter 'url' is not a valid URL.".into());
        };
        if !matches!(parsed.scheme.as_str(), "http" | "https") || parsed.hostname.is_none() {
            return invalid("Parameter 'url' must be an absolute http(s) URL.".into());
        }
        // `.username`/`.password` are not None exactly when the netloc
        // has a userinfo part.
        if parsed.netloc.contains('@') {
            return invalid("Parameter 'url' must not carry a user or password.".into());
        }
        if url.chars().any(py_isspace) {
            return invalid("Parameter 'url' must not contain whitespace.".into());
        }
        if let Some(status) = get(values, "expected_status") {
            if !KUMA_STATUS_CODES.contains(&status) {
                return invalid(format!(
                    "Parameter 'expected_status' must be one of {}.",
                    repr_list(KUMA_STATUS_CODES)
                ));
            }
        }
    } else if matches!(operation, "monitor_pause" | "monitor_resume") {
        let monitor_id = get(values, "monitor_id").unwrap_or("");
        if ascii_uint(monitor_id).is_none_or(|n| n < 1) {
            return invalid("Parameter 'monitor_id' must be a positive integer.".into());
        }
    }
    Ok(())
}

/// `monitor_add_port`'s target against the toolkit's
/// `allowed_monitor_targets` (1.29.0), before anything is sent. An IPv4
/// address must lie in one of its networks; a hostname must be one of its
/// hostnames exactly (case-insensitive). A hostname is never resolved here:
/// the monitor is Kuma's, and it resolves the name itself on every check,
/// so a lookup now would prove nothing about the address Kuma will use.
pub fn check_monitor_target(toolkit: &Toolkit, hostname: &str) -> Result<(), Denied> {
    let refuse = || {
        Err(Denied::new(
            DenialReason::Tier1Violation,
            format!(
                "Monitor target {} is not in this toolkit's allowed_monitor_targets. Nothing was sent.",
                repr_str(hostname)
            ),
        ))
    };
    if let Ok(v4) = hostname.parse::<std::net::Ipv4Addr>() {
        let ip = std::net::IpAddr::V4(v4);
        let inside = toolkit.allowed_monitor_targets.iter().any(|t| ip_network(t).is_ok_and(|net| net.contains(&ip)));
        return if inside { Ok(()) } else { refuse() };
    }
    let name = hostname.to_ascii_lowercase();
    let listed = toolkit.allowed_monitor_targets.iter().any(|t| ip_network(t).is_err() && *t == name);
    if listed {
        Ok(())
    } else {
        refuse()
    }
}

/// The handshake failure, as websockets' exception text.
fn handshake_error(err: tungstenite::Error) -> String {
    match err {
        tungstenite::Error::Http(response) => {
            format!("server rejected WebSocket connection: HTTP {}", response.status().as_u16())
        }
        tungstenite::Error::ConnectionClosed
        | tungstenite::Error::AlreadyClosed
        | tungstenite::Error::Io(_)
        | tungstenite::Error::Protocol(_)
        | tungstenite::Error::HttpFormat(_) => "did not receive a valid HTTP response".to_string(),
        other => other.to_string(),
    }
}

/// `websockets.connect(url, host=<checked address>, port=port, proxy=None)`:
/// TCP to the checked address (asyncio's error text), then the opening
/// handshake for `url` over it.
async fn connect(url: &str, addr: &super::http::Resolved, max_size: usize) -> Result<Ws, String> {
    let stream = tokio::net::TcpStream::connect(addr.addr).await.map_err(|e| {
        format!("[Errno {}] Connect call failed {}", e.raw_os_error().unwrap_or(0), sockaddr_repr(addr))
    })?;
    let config = WebSocketConfig::default().max_message_size(Some(max_size));
    let (ws, _) = tokio_tungstenite::client_async_tls_with_config(url, stream, Some(config), None)
        .await
        .map_err(handshake_error)?;
    Ok(ws)
}

/// One operation against Uptime Kuma.
///
/// `Err` only for a credential store that cannot be read or decrypted --
/// what escaped Python's `run()` as an exception.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    operation: &str,
    values: &crate::validate::Values,
    toolkit: &Toolkit,
    credentials: Option<&CredentialStore>,
    timeout_seconds: f64,
    max_output_bytes: i64,
    idempotent: bool,
    redact: Option<&Redact>,
) -> Result<ExecResult, ConfigError> {
    let base_url = toolkit.base_url.as_deref().expect("kuma toolkit without base_url");
    let started = Instant::now();
    let deadline = started + seconds(timeout_seconds);
    let clean = |text: &str| -> String {
        match redact {
            Some(r) => r(text),
            None => text.to_string(),
        }
    };
    let denied = |denial: Denied, duration_ms: i64| -> ExecResult {
        let mut result = ExecResult::new(OUTCOME_FAILED, None, "", clean(&denial.agent_message()), false, duration_ms);
        result.denial_reason = Some(denial.reason.as_str().to_string());
        result.denial_detail = Some(denial.detail);
        result
    };
    let failed = |message: &str, exit_code: Option<i64>, duration_ms: i64| -> ExecResult {
        ExecResult::new(OUTCOME_FAILED, exit_code, "", clean(message), false, duration_ms).untrusted(true)
    };

    // Defensive re-checks: `operation` is fixed per tool and the values
    // were validated by `validate::build_kuma_call` -- kept for the same
    // reason `build_argv` re-checks `check_binary`.
    if !toolkit.allows_kuma_operation(operation) || !OPERATIONS.contains(&operation) {
        return Ok(denied(
            Denied::new(
                DenialReason::Tier1Violation,
                format!("Kuma operation {} is not allowed for this toolkit.", repr_str(operation)),
            ),
            elapsed_ms(started),
        ));
    }
    if let Err(denial) = check_values(operation, values) {
        return Ok(denied(denial, elapsed_ms(started)));
    }
    if operation == "monitor_add_port" {
        if let Err(denial) = check_monitor_target(toolkit, get(values, "hostname").unwrap_or("")) {
            return Ok(denied(denial, elapsed_ms(started)));
        }
    }

    let name = toolkit.credential.as_deref().unwrap_or("");
    let (Some(store), false) = (credentials, name.is_empty()) else {
        return Ok(denied(
            Denied::new(DenialReason::CredentialUnavailable, "This toolkit needs the Kuma login in the credential store."),
            elapsed_ms(started),
        ));
    };
    let Some(credential) = store.resolve(name)? else {
        return Ok(denied(
            Denied::new(
                DenialReason::CredentialUnavailable,
                format!("Credential {} is not configured yet.", repr_str(name)),
            ),
            elapsed_ms(started),
        ));
    };

    let (url, host, port) = match socket_url(base_url) {
        Ok(parts) => parts,
        Err(exc) => {
            return Ok(failed(
                &format!("Could not connect to Uptime Kuma at {base_url}: {exc}"),
                None,
                elapsed_ms(started),
            ))
        }
    };
    // FR-8.9: resolved and checked now, and the socket goes to that literal
    // address -- the URL's hostname stays in the Host header and TLS SNI.
    // No proxy: a proxy would make its own lookup this check never saw.
    let resolved = match resolve_and_check(&host, port, toolkit).await {
        Ok(r) => r,
        Err(denial) => return Ok(denied(denial, elapsed_ms(started))),
    };

    let max_size = (1usize << 20).max(max_output_bytes.max(0) as usize * 4);
    let connect_budget = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(100));
    let ws = match tokio::time::timeout(connect_budget, connect(&url, &resolved, max_size)).await {
        Ok(Ok(ws)) => ws,
        Ok(Err(exc)) => {
            return Ok(failed(
                &format!("Could not connect to Uptime Kuma at {base_url}: {exc}"),
                None,
                elapsed_ms(started),
            ))
        }
        Err(_) => {
            return Ok(failed(&format!("Could not connect to Uptime Kuma at {base_url}: "), None, elapsed_ms(started)))
        }
    };

    let mut sio = SocketIo::new(ws, deadline);
    let outcome = async {
        sio.open().await?;
        login(&mut sio, &credential).await?;
        match operation {
            "monitor_list" => op_list(&mut sio).await,
            "monitor_add_http" => op_add_http(&mut sio, values, toolkit).await,
            "monitor_add_port" => op_add_port(&mut sio, values, toolkit).await,
            "monitor_pause" => op_pause_resume(&mut sio, values, true).await,
            _ => op_pause_resume(&mut sio, values, false).await,
        }
    }
    .await;
    // The result's duration is taken before the close, like Python's
    // `return` inside `try` before its `finally`.
    let duration = elapsed_ms(started);
    let sent_write = sio.sent_write;
    close(sio.ws).await;

    let summary = match outcome {
        Ok(summary) => summary,
        Err(Fail::Denied(denial)) => return Ok(denied(denial, duration)),
        Err(Fail::Kuma(message)) => return Ok(failed(&message, Some(1), duration)),
        Err(Fail::Timeout) => {
            let unknown = sent_write && !idempotent;
            let t = fmt_seconds(timeout_seconds);
            let stderr = if unknown {
                format!(
                    "Timeout of {t}s exceeded. The outcome is UNKNOWN: the request may have reached \
                     Uptime Kuma. List the monitors before trying again."
                )
            } else {
                format!("Timeout of {t}s exceeded.")
            };
            return Ok(ExecResult::new(
                if unknown { OUTCOME_UNKNOWN } else { OUTCOME_FAILED },
                None,
                "",
                stderr,
                false,
                duration,
            )
            .untrusted(true));
        }
        Err(Fail::Ws(exc)) => return Ok(failed(&format!("Connection error: {exc}"), None, duration)),
    };

    let mut budget = MAX_JSON_ITEMS;
    let mut stdout = pyjson::dumps_with(&cap_json(&summary, &mut budget), &pyjson::Opts::unicode());
    let max = max_output_bytes.max(0) as usize;
    let truncated = stdout.len() > max;
    if truncated {
        stdout = String::from_utf8_lossy(&stdout.as_bytes()[..max]).into_owned();
    }
    Ok(ExecResult::new(OUTCOME_OK, Some(0), clean(&stdout), "", truncated, elapsed_ms(started)).untrusted(true))
}

/// TCP-connect only, for /health/ready -- the `http` probe verbatim: same
/// `base_url`, same address checks. No login: that would put a credential
/// on the wire for a liveness question.
pub async fn probe(toolkit: &Toolkit) -> bool {
    super::http::probe(toolkit).await
}

#[cfg(test)]
#[path = "kuma_tests.rs"]
mod tests;
