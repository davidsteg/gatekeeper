//! The `opencode` executor (port of `execute_opencode.py`; FR-8.5/8.7/8.9/
//! 8.12 applied to a multi-request workflow).
//!
//! opencode runs as a headless server on the LAN with an HTTP API. The
//! useful units of work are not single requests ("ask" is create-session +
//! message; "run" is a session, an async dispatch and a poll loop), so the
//! whitelist acts on **operation names** and one operation is one fixed
//! workflow. Kept from the `http` executor:
//!
//! * the target lives exclusively on the toolkit (`base_url`, FR-8.5);
//! * every request resolves the host and re-checks it and the resolved IP
//!   against `allowed_hosts`/`allowed_cidrs` immediately before connecting
//!   (FR-8.9), per request;
//! * redirects are reported, never followed (FR-8.8);
//! * the credential is injected as a header by this module (FR-8.14);
//! * responses are external, untrusted data (`external_untrusted`, and the
//!   JSON field-count cap of FR-8.12).
//!
//! The request paths are fixed in [`EP`] and nowhere else.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::credentials::{format_header_value, CredentialStore, ResolvedCredential};
use crate::errors::{DenialReason, Denied};
use crate::execute::google::{cap_json_items, truthy, MAX_JSON_ITEMS};
use crate::execute::{elapsed_ms, ExecResult, Redact, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::pyfmt::{repr_str, str_value};
use crate::pyjson::{self, Opts};
use crate::tier1::Toolkit;
use crate::validate::Values;

pub use crate::validate::{check_directory, check_session_id};

/// One endpoint: `(name, (method, path template))`.
pub type Endpoint = (&'static str, (&'static str, &'static str));

/// The opencode HTTP API endpoints this executor uses. `{id}` is filled
/// with a session id that has passed [`check_session_id`].
pub const EP: &[Endpoint] = &[
    ("session_create", ("POST", "/session")),
    ("session_message", ("POST", "/session/{id}/message")),
    ("session_prompt_async", ("POST", "/session/{id}/prompt_async")),
    ("session_get", ("GET", "/session/{id}")),
    ("session_todo", ("GET", "/session/{id}/todo")),
    ("session_diff", ("GET", "/session/{id}/diff")),
    ("session_abort", ("POST", "/session/{id}/abort")),
    ("providers", ("GET", "/config/providers")),
    ("health", ("GET", "/global/health")),
];

/// The header opencode reads to decide which project root a session works in.
pub const DIRECTORY_HEADER: &str = "x-opencode-directory";

/// How often `run` asks the session whether it is finished.
pub const POLL_INTERVAL_SECONDS: f64 = 5.0;

/// Ceiling for any single HTTP request inside a workflow.
pub const PER_REQUEST_TIMEOUT_SECONDS: f64 = 60.0;

/// Field-count cap for the compact summaries.
pub const SUMMARY_ITEMS: i64 = 200;

/// Session states that mean "opencode is no longer working on this".
const TERMINAL_STATES: &[&str] =
    &["idle", "completed", "complete", "done", "finished", "error", "aborted", "cancelled"];

/// What can end a workflow early.
#[derive(Debug)]
enum Failure {
    Denied(Denied),
    /// The operation's overall budget is spent.
    Timeout,
    /// `_OpencodeError`: an HTTP-level failure, with its status.
    Opencode { message: String, status: Option<i64> },
}

impl From<Denied> for Failure {
    fn from(d: Denied) -> Self {
        Failure::Denied(d)
    }
}

fn oc_err(message: impl Into<String>, status: Option<i64>) -> Failure {
    Failure::Opencode { message: message.into(), status }
}

// -- Stand-ins for execute_http helpers -----------------------------------

/// `execute_http._resolve_and_check`: the host against `allowed_hosts`,
/// then every resolved address against the public-address floor and
/// `allowed_cidrs` (fail-closed); the checked address is what the request
/// connects to.
async fn resolve_and_check(host: &str, port: u16, toolkit: &Toolkit) -> Result<IpAddr, Denied> {
    crate::execute::http::resolve_and_check(host, port, toolkit).await.map(|resolved| resolved.addr.ip())
}

/// `execute_http._credential_headers`.
// PORT NOTE: stand-in until execute::http lands.
fn credential_headers(credential: Option<&ResolvedCredential>) -> Vec<(String, String)> {
    let Some(credential) = credential else {
        return Vec::new();
    };
    match credential.kind.as_str() {
        "api_key_header" => match credential.header.as_deref().filter(|h| !h.is_empty()) {
            Some(header) => vec![(
                header.to_string(),
                format_header_value(credential.header_format.as_deref(), &credential.value),
            )],
            None => Vec::new(),
        },
        "bearer" => vec![("Authorization".into(), format!("Bearer {}", credential.value))],
        "basic" => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(credential.value.as_bytes());
            vec![("Authorization".into(), format!("Basic {encoded}"))]
        }
        _ => Vec::new(),
    }
}

/// `urlsplit(base_url)`: scheme, hostname (lowercase, no brackets), port
/// (default by scheme), path without a trailing `/`.
fn split_base_url(base_url: &str) -> (String, String, u16, String) {
    match url::Url::parse(base_url) {
        Ok(parsed) => {
            let scheme = parsed.scheme().to_string();
            let host = match parsed.host() {
                Some(url::Host::Ipv6(addr)) => addr.to_string(),
                Some(url::Host::Ipv4(addr)) => addr.to_string(),
                Some(url::Host::Domain(d)) => d.to_lowercase(),
                None => String::new(),
            };
            let port = parsed.port().unwrap_or(if scheme == "https" { 443 } else { 80 });
            let path = parsed.path().trim_end_matches('/').to_string();
            (scheme, host, port, path)
        }
        Err(_) => (String::new(), String::new(), 80, String::new()),
    }
}

/// `execute_http.probe`: TCP-connect only, no HTTP request.
// PORT NOTE: stand-in until execute::http lands (`opencode.probe` is
// `execute_http.probe` verbatim in Python).
async fn http_probe(toolkit: &Toolkit) -> bool {
    let base_url = toolkit.base_url.clone().unwrap_or_default();
    if base_url.contains("{credential}") {
        return true;
    }
    let (_, host, port, _) = split_base_url(&base_url);
    let Ok(ip) = resolve_and_check(&host, port, toolkit).await else {
        return false;
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect((ip, port))).await,
        Ok(Ok(_))
    )
}

// -- One HTTP request, SSRF-checked ----------------------------------------

/// Issues the requests of one workflow against one checked target,
/// re-resolving and re-checking the host per request (FR-8.9).
struct Client<'a> {
    toolkit: &'a Toolkit,
    endpoints: &'a [Endpoint],
    deadline: Instant,
    scheme: String,
    host: String,
    port: u16,
    base_path: String,
    headers: Vec<(String, String)>,
    /// The status of the most recent response (the Result's exit_code).
    last_status: Option<i64>,
    /// The session this workflow is working on, once known -- kept for the
    /// timeout message, the one path that never reaches a summary.
    session_id: Option<String>,
}

fn remaining(deadline: Instant) -> f64 {
    deadline.saturating_duration_since(Instant::now()).as_secs_f64()
}

impl<'a> Client<'a> {
    fn new(
        toolkit: &'a Toolkit,
        endpoints: &'a [Endpoint],
        credential: Option<&ResolvedCredential>,
        directory: Option<&str>,
        deadline: Instant,
    ) -> Self {
        let (scheme, host, port, base_path) = split_base_url(toolkit.base_url.as_deref().unwrap_or(""));
        let host_header = if port == 80 || port == 443 {
            host.clone()
        } else if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut headers = vec![("Host".to_string(), host_header), ("Accept".to_string(), "application/json".to_string())];
        headers.extend(credential_headers(credential));
        if let Some(directory) = directory.filter(|d| !d.is_empty()) {
            headers.push((DIRECTORY_HEADER.to_string(), directory.to_string()));
        }
        Client {
            toolkit,
            endpoints,
            deadline,
            scheme,
            host,
            port,
            base_path,
            headers,
            last_status: None,
            session_id: None,
        }
    }

    /// Issues one request and returns its parsed JSON body (`Null` for an
    /// empty one).
    async fn request(
        &mut self,
        endpoint: &str,
        session_id: Option<&str>,
        body: Option<&Value>,
        max_output_bytes: i64,
    ) -> Result<Value, Failure> {
        let (method, template) =
            self.endpoints.iter().find(|(name, _)| *name == endpoint).map(|(_, ep)| *ep).expect("known endpoint");
        let mut path = template.to_string();
        if let Some(session_id) = session_id {
            path = template.replace("{id}", &check_session_id(session_id)?);
        }

        let left = remaining(self.deadline);
        if left <= 0.0 {
            return Err(Failure::Timeout);
        }
        let timeout = left.min(PER_REQUEST_TIMEOUT_SECONDS);

        // The resolved IP, re-checked now, is what we connect to: the client
        // is pinned to it, so no second lookup can happen (FR-8.9).
        let resolved_ip = resolve_and_check(&self.host, self.port, self.toolkit).await?;
        let url_host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let url = format!("{}://{}:{}{}{}", self.scheme, url_host, self.port, self.base_path, path);

        let limit = max_output_bytes.max(0) as usize;
        let send = async {
            // PORT NOTE: no proxy -- a proxy would connect to the target on
            // our behalf and void the resolved-IP check above.
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .resolve(&self.host, SocketAddr::new(resolved_ip, self.port))
                .build()?;
            let mut req = client.request(reqwest::Method::from_bytes(method.as_bytes()).expect("method"), &url);
            for (name, value) in &self.headers {
                req = req.header(name.as_str(), value.as_str());
            }
            if let Some(body) = body {
                req = req.header("Content-Type", "application/json").body(serde_json::to_vec(body).expect("json"));
            }
            let mut response = req.send().await?;
            let status = response.status().as_u16() as i64;
            let location = response
                .headers()
                .get("location")
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .unwrap_or_default();
            let mut raw: Vec<u8> = Vec::new();
            let mut over_cap = false;
            while let Some(chunk) = response.chunk().await? {
                if raw.len() + chunk.len() > limit {
                    over_cap = true;
                    break;
                }
                raw.extend_from_slice(&chunk);
            }
            Ok::<_, reqwest::Error>((status, location, raw, over_cap))
        };
        // PORT NOTE: Python capped only the header phase with wait_for and
        // otherwise relied on httpx's default 5 s read timeout; the whole
        // request is capped at min(remaining, 60 s) here, as documented.
        let (status, location, raw, over_cap) = match tokio::time::timeout(Duration::from_secs_f64(timeout), send).await {
            Err(_) => {
                if remaining(self.deadline) <= 0.0 {
                    return Err(Failure::Timeout);
                }
                return Err(oc_err(format!("{method} {path} did not answer within {}s.", timeout as i64), None));
            }
            Ok(Err(exc)) if exc.is_timeout() => {
                if remaining(self.deadline) <= 0.0 {
                    return Err(Failure::Timeout);
                }
                return Err(oc_err(format!("{method} {path} did not answer within {}s.", timeout as i64), None));
            }
            // PORT NOTE: the error text is reqwest's, not httpx's.
            Ok(Err(exc)) => return Err(oc_err(format!("{method} {path} failed: {exc}"), None)),
            Ok(Ok(found)) => found,
        };

        self.last_status = Some(status);

        if (300..400).contains(&status) {
            return Err(oc_err(
                format!(
                    "{method} {path} redirected ({status}) to {}; redirects are not followed.",
                    repr_str(&location)
                ),
                Some(status),
            ));
        }
        if !(200..300).contains(&status) {
            let decoded = String::from_utf8_lossy(&raw);
            let detail: String = decoded.trim().chars().take(500).collect();
            let detail = if detail.is_empty() { "(empty body)".to_string() } else { detail };
            return Err(oc_err(format!("{method} {path} returned {status}: {detail}"), Some(status)));
        }
        if over_cap {
            return Err(oc_err(
                format!(
                    "{method} {path} returned more than the tool's max_output_bytes ({max_output_bytes}); no \
                     summary could be built. Narrow the request or raise the ceiling."
                ),
                Some(status),
            ));
        }
        if raw.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&String::from_utf8_lossy(&raw))
            .map_err(|_| oc_err(format!("{method} {path} returned a non-JSON body."), Some(status)))
    }
}

// -- Reading opencode's responses (tolerantly) ------------------------------

fn is_empty_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// The first present, non-empty value among `keys`, at the top level or one
/// level down under `info`/`session`/`data`/`result`.
pub fn first(payload: &Value, keys: &[&str]) -> Option<Value> {
    let Value::Object(top) = payload else {
        return None;
    };
    let mut scopes: Vec<&Map<String, Value>> = vec![top];
    for wrapper in ["info", "session", "data", "result"] {
        if let Some(Value::Object(nested)) = top.get(wrapper) {
            scopes.push(nested);
        }
    }
    for scope in scopes {
        for key in keys {
            if let Some(value) = scope.get(*key) {
                if !is_empty_value(value) {
                    return Some(value.clone());
                }
            }
        }
    }
    None
}

fn session_id_of(payload: &Value) -> Option<String> {
    match first(payload, &["id", "sessionId", "session_id", "sessionID"])? {
        Value::String(s) => Some(s),
        // isinstance(value, int) -- a bool is an int in Python.
        Value::Number(n) if n.is_i64() || n.is_u64() => Some(n.to_string()),
        Value::Bool(b) => Some(if b { "True" } else { "False" }.into()),
        _ => None,
    }
}

/// Whether a session has stopped working, read tolerantly. A response with
/// none of the known signals means "still running".
pub fn session_is_done(payload: &Value) -> bool {
    if let Some(Value::String(state)) = first(payload, &["status", "state"]) {
        if TERMINAL_STATES.contains(&state.trim().to_lowercase().as_str()) {
            return true;
        }
    }
    if first(payload, &["error"]).is_some() {
        return true;
    }
    if first(payload, &["idle"]) == Some(Value::Bool(true)) {
        return true;
    }
    if let Value::Object(map) = payload {
        for key in ["busy", "running", "working"] {
            if map.get(key) == Some(&Value::Bool(false)) {
                return true;
            }
        }
    }
    if let Some(Value::Object(time)) = first(payload, &["time"]) {
        if time.get("completed").is_some_and(truthy) {
            return true;
        }
    }
    false
}

fn session_status(payload: &Value) -> String {
    if let Some(Value::String(state)) = first(payload, &["status", "state"]) {
        if !state.trim().is_empty() {
            return state.trim().to_string();
        }
    }
    if first(payload, &["error"]).is_some() {
        return "error".into();
    }
    if session_is_done(payload) { "idle" } else { "running" }.into()
}

/// The assistant's answer: a bare string, `{"text": ...}`, or a
/// `parts`/`content` list of typed blocks.
pub fn message_text(payload: &Value) -> String {
    if let Value::String(s) = payload {
        return s.clone();
    }
    let direct = first(payload, &["text", "content", "answer", "message", "output"]);
    if let Some(Value::String(s)) = &direct {
        return s.clone();
    }
    let blocks = match direct {
        Some(Value::Array(a)) => Some(Value::Array(a)),
        _ => first(payload, &["parts"]),
    };
    if let Some(Value::Array(blocks)) = blocks {
        let mut chunks: Vec<String> = Vec::new();
        for block in &blocks {
            match block {
                Value::String(s) => chunks.push(s.clone()),
                Value::Object(b) => {
                    let text = b.get("text").filter(|v| truthy(v)).or_else(|| b.get("content"));
                    if let Some(Value::String(s)) = text {
                        chunks.push(s.clone());
                    }
                }
                _ => {}
            }
        }
        if !chunks.is_empty() {
            return chunks.join("\n");
        }
    }
    String::new()
}

/// `str.splitlines()`.
fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let is_break = matches!(
            c,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        );
        if is_break {
            lines.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = chars.peek() {
                    chars.next();
                    end = j + 1;
                }
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

fn count_patch_lines(patch: &str) -> (i64, i64) {
    let (mut added, mut removed) = (0, 0);
    for line in splitlines(patch) {
        if line.starts_with('+') && !line.starts_with("+++") {
            added += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            removed += 1;
        }
    }
    (added, removed)
}

fn is_int(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Number(n)) if n.is_i64() || n.is_u64())
}

/// Per-file add/remove counts out of a diff response.
pub fn files_changed(diff_payload: &Value) -> Vec<Map<String, Value>> {
    let mut entries = diff_payload.clone();
    if diff_payload.is_object() {
        if let Some(wrapped) = first(diff_payload, &["files", "diffs", "changes"]) {
            entries = wrapped;
        }
    }
    let mut files = Vec::new();
    match &entries {
        Value::Array(list) => {
            for entry in list {
                match entry {
                    Value::String(s) => {
                        let mut record = Map::new();
                        record.insert("path".into(), Value::String(s.clone()));
                        files.push(record);
                    }
                    Value::Object(e) => {
                        let path = ["path", "file", "filename"]
                            .iter()
                            .filter_map(|k| e.get(*k))
                            .find(|v| truthy(v))
                            .map(str_value)
                            .unwrap_or_else(|| "(unnamed)".into());
                        let mut record = Map::new();
                        record.insert("path".into(), Value::String(path));
                        for (key, out) in [
                            ("additions", "added"),
                            ("added", "added"),
                            ("insertions", "added"),
                            ("deletions", "removed"),
                            ("removed", "removed"),
                        ] {
                            if is_int(e.get(key)) && !record.contains_key(out) {
                                record.insert(out.into(), e[key].clone());
                            }
                        }
                        if !record.contains_key("added") {
                            if let Some(Value::String(patch)) = e.get("patch") {
                                let (a, r) = count_patch_lines(patch);
                                record.insert("added".into(), json!(a));
                                record.insert("removed".into(), json!(r));
                            }
                        }
                        if let Some(status) = e.get("status").filter(|v| truthy(v)) {
                            record.insert("status".into(), Value::String(str_value(status)));
                        }
                        files.push(record);
                    }
                    _ => {}
                }
            }
        }
        Value::Object(map) => {
            for (path, patch) in map {
                let mut record = Map::new();
                record.insert("path".into(), Value::String(path.clone()));
                if let Value::String(patch) = patch {
                    let (a, r) = count_patch_lines(patch);
                    record.insert("added".into(), json!(a));
                    record.insert("removed".into(), json!(r));
                }
                files.push(record);
            }
        }
        _ => {}
    }
    files
}

/// `x.get(a) or x.get(b) or ...` -- the first truthy value.
fn first_truthy<'v>(map: &'v Map<String, Value>, keys: &[&str]) -> Option<&'v Value> {
    keys.iter().filter_map(|k| map.get(*k)).find(|v| truthy(v))
}

fn todos(payload: &Value) -> Vec<Value> {
    let entries = if payload.is_object() {
        first(payload, &["todos", "items", "todo"]).unwrap_or(Value::Array(Vec::new()))
    } else {
        payload.clone()
    };
    let Value::Array(entries) = entries else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in &entries {
        match entry {
            Value::String(s) => out.push(json!({"task": s})),
            Value::Object(e) => {
                let task = first_truthy(e, &["content", "text", "task"]).map(str_value).unwrap_or_else(|| "(unnamed)".into());
                let status =
                    first_truthy(e, &["status", "state"]).map(str_value).unwrap_or_else(|| "unknown".into());
                out.push(json!({"task": task, "status": status}));
            }
            _ => {}
        }
    }
    out
}

fn providers(payload: &Value) -> Vec<Value> {
    let mut defaults = Map::new();
    let entries = if let Value::Object(map) = payload {
        if let Some(Value::Object(d)) = first_truthy(map, &["default", "defaults"]) {
            defaults = d.clone();
        }
        first(payload, &["providers", "items"]).unwrap_or(Value::Array(Vec::new()))
    } else {
        payload.clone()
    };
    let Value::Array(entries) = entries else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in &entries {
        let Value::Object(e) = entry else { continue };
        let provider_id = first_truthy(e, &["id", "name"]).map(str_value).unwrap_or_else(|| "(unnamed)".into());
        let model_ids: Vec<String> = match e.get("models") {
            Some(Value::Object(models)) => models.keys().cloned().collect(),
            Some(Value::Array(models)) => models
                .iter()
                .map(|m| match m {
                    Value::Object(mm) => str_value(first_truthy(mm, &["id"]).or_else(|| mm.get("name")).unwrap_or(&Value::Null)),
                    other => str_value(other),
                })
                .collect(),
            _ => Vec::new(),
        };
        let mut record = Map::new();
        record.insert("id".into(), Value::String(provider_id.clone()));
        if let Some(name) = e.get("name").filter(|v| truthy(v)) {
            record.insert("name".into(), Value::String(str_value(name)));
        }
        if let Some(default) = defaults.get(&provider_id) {
            record.insert("default_model".into(), Value::String(str_value(default)));
        }
        if !model_ids.is_empty() {
            record.insert("models".into(), json!(model_ids));
        }
        out.push(Value::Object(record));
    }
    out
}

/// Attaches the capped raw payload when every extracted field is empty.
pub fn summarise(mut summary: Map<String, Value>, payload: &Value, keys: &[&str]) -> Map<String, Value> {
    if payload.is_null() {
        return summary;
    }
    if keys.iter().any(|k| summary.get(*k).is_some_and(|v| !is_empty_value(v))) {
        return summary;
    }
    summary.insert("raw".into(), cap_json_items(payload, SUMMARY_ITEMS));
    summary
}

// -- The workflows -----------------------------------------------------------

fn get<'v>(values: &'v Values, key: &str) -> &'v str {
    values.get(key).map(String::as_str).unwrap_or("")
}

/// The message body every prompt-carrying operation sends.
pub fn prompt_body(values: &Values) -> Result<Value, Denied> {
    let mut body = Map::new();
    body.insert("parts".into(), json!([{"type": "text", "text": get(values, "prompt")}]));
    let model = get(values, "model");
    if !model.is_empty() {
        let (provider, model_id) = model.split_once('/').unwrap_or(("", ""));
        if provider.is_empty() || model_id.is_empty() {
            return Err(Denied::new(
                DenialReason::ParamInvalid,
                format!("model {} must be 'provider/model', e.g. 'anthropic/claude-opus-5'.", repr_str(model)),
            ));
        }
        body.insert("providerID".into(), json!(provider));
        body.insert("modelID".into(), json!(model_id));
    }
    let agent = get(values, "agent");
    if !agent.is_empty() {
        body.insert("agent".into(), json!(agent));
    }
    Ok(Value::Object(body))
}

async fn create_session(client: &mut Client<'_>, values: &Values, max: i64) -> Result<String, Failure> {
    let title = match get(values, "title") {
        "" => "gatekeeper",
        t => t,
    };
    let payload = client.request("session_create", None, Some(&json!({"title": title})), max).await?;
    let Some(session_id) = session_id_of(&payload).filter(|s| !s.is_empty()) else {
        return Err(oc_err("opencode created a session but returned no usable session id.", None));
    };
    let checked = check_session_id(&session_id)?;
    client.session_id = Some(checked.clone());
    Ok(checked)
}

async fn session_or_new(client: &mut Client<'_>, values: &Values, max: i64) -> Result<String, Failure> {
    let given = get(values, "session_id");
    let session_id = if given.is_empty() { create_session(client, values, max).await? } else { given.to_string() };
    client.session_id = Some(session_id.clone());
    Ok(session_id)
}

async fn op_ask(client: &mut Client<'_>, values: &Values, max: i64) -> Result<Map<String, Value>, Failure> {
    let session_id = session_or_new(client, values, max).await?;
    let body = prompt_body(values)?;
    let payload = client.request("session_message", Some(&session_id), Some(&body), max).await?;
    let mut summary = Map::new();
    summary.insert("operation".into(), json!("ask"));
    summary.insert("session_id".into(), json!(session_id));
    summary.insert("answer".into(), json!(message_text(&payload)));
    Ok(summarise(summary, &payload, &["answer"]))
}

async fn op_fire(client: &mut Client<'_>, values: &Values, max: i64) -> Result<Map<String, Value>, Failure> {
    let session_id = session_or_new(client, values, max).await?;
    let body = prompt_body(values)?;
    client.request("session_prompt_async", Some(&session_id), Some(&body), max).await?;
    let mut summary = Map::new();
    summary.insert("operation".into(), json!("fire"));
    summary.insert("session_id".into(), json!(session_id));
    summary.insert("status".into(), json!("dispatched"));
    summary.insert(
        "next".into(),
        json!(format!(
            "The task runs in the background. Call the check operation with session_id={} for progress.",
            repr_str(&session_id)
        )),
    );
    Ok(summary)
}

/// fire, then poll until the session stops working. A timeout propagates
/// (the session keeps running on the other side).
async fn op_run(client: &mut Client<'_>, values: &Values, max: i64) -> Result<Map<String, Value>, Failure> {
    let session_id = session_or_new(client, values, max).await?;
    let body = prompt_body(values)?;
    client.request("session_prompt_async", Some(&session_id), Some(&body), max).await?;
    let session = loop {
        let session = client.request("session_get", Some(&session_id), None, max).await?;
        if session_is_done(&session) {
            break session;
        }
        let left = remaining(client.deadline);
        if left <= 0.0 {
            return Err(Failure::Timeout);
        }
        tokio::time::sleep(Duration::from_secs_f64(POLL_INTERVAL_SECONDS.min(left))).await;
    };
    let mut summary = report(client, &session_id, &session, max).await?;
    summary.insert("operation".into(), json!("run"));
    Ok(summary)
}

async fn op_check(client: &mut Client<'_>, values: &Values, max: i64) -> Result<Map<String, Value>, Failure> {
    let session_id = check_session_id(get(values, "session_id"))?;
    client.session_id = Some(session_id.clone());
    let session = client.request("session_get", Some(&session_id), None, max).await?;
    let mut summary = report(client, &session_id, &session, max).await?;
    summary.insert("operation".into(), json!("check"));
    Ok(summary)
}

/// The shared progress report behind `run` and `check`. The todo and diff
/// requests are best-effort.
async fn report(client: &mut Client<'_>, session_id: &str, session: &Value, max: i64) -> Result<Map<String, Value>, Failure> {
    let mut summary = Map::new();
    summary.insert("session_id".into(), json!(session_id));
    summary.insert("status".into(), json!(session_status(session)));
    summary.insert("done".into(), json!(session_is_done(session)));
    if let Some(error) = first(session, &["error"]) {
        summary.insert("error".into(), cap_json_items(&error, 50));
    }

    match client.request("session_todo", Some(session_id), None, max).await {
        Ok(payload) => {
            let todos = todos(&payload);
            if !todos.is_empty() {
                summary.insert("todos".into(), Value::Array(todos.into_iter().take(SUMMARY_ITEMS as usize).collect()));
            }
        }
        Err(Failure::Denied(d)) => return Err(Failure::Denied(d)),
        Err(_) => {}
    }

    match client.request("session_diff", Some(session_id), None, max).await {
        Ok(payload) => {
            let paths: Vec<Value> =
                files_changed(&payload).into_iter().map(|f| f["path"].clone()).take(SUMMARY_ITEMS as usize).collect();
            summary.insert("files_changed".into(), Value::Array(paths));
        }
        Err(Failure::Denied(d)) => return Err(Failure::Denied(d)),
        Err(_) => {}
    }

    let text = message_text(session);
    if !text.is_empty() {
        summary.insert("last_message".into(), json!(text));
    }
    Ok(summary)
}

async fn op_review_changes(client: &mut Client<'_>, values: &Values, max: i64) -> Result<Map<String, Value>, Failure> {
    let session_id = check_session_id(get(values, "session_id"))?;
    client.session_id = Some(session_id.clone());
    let payload = client.request("session_diff", Some(&session_id), None, max).await?;
    let files = files_changed(&payload);
    let sum = |key: &str| -> i64 { files.iter().map(|f| f.get(key).and_then(Value::as_i64).unwrap_or(0)).sum() };
    let totals = json!({"files": files.len(), "added": sum("added"), "removed": sum("removed")});
    let mut summary = Map::new();
    summary.insert("operation".into(), json!("review_changes"));
    summary.insert("session_id".into(), json!(session_id));
    summary.insert(
        "files".into(),
        Value::Array(files.iter().take(SUMMARY_ITEMS as usize).cloned().map(Value::Object).collect()),
    );
    summary.insert("totals".into(), totals);
    Ok(summarise(summary, &payload, &["files"]))
}

async fn op_abort(client: &mut Client<'_>, values: &Values, max: i64) -> Result<Map<String, Value>, Failure> {
    let session_id = check_session_id(get(values, "session_id"))?;
    client.session_id = Some(session_id.clone());
    let payload = client.request("session_abort", Some(&session_id), None, max).await?;
    let mut summary = Map::new();
    summary.insert("operation".into(), json!("abort"));
    summary.insert("session_id".into(), json!(session_id));
    summary.insert("aborted".into(), json!(true));
    summary.insert("response".into(), if truthy(&payload) { cap_json_items(&payload, 50) } else { Value::Null });
    Ok(summary)
}

async fn op_providers(client: &mut Client<'_>, max: i64) -> Result<Map<String, Value>, Failure> {
    let payload = client.request("providers", None, None, max).await?;
    let mut summary = Map::new();
    summary.insert("operation".into(), json!("providers"));
    summary.insert(
        "providers".into(),
        Value::Array(providers(&payload).into_iter().take(SUMMARY_ITEMS as usize).collect()),
    );
    Ok(summarise(summary, &payload, &["providers"]))
}

async fn op_health(client: &mut Client<'_>, max: i64) -> Result<Map<String, Value>, Failure> {
    let payload = client.request("health", None, None, max).await?;
    let mut summary = Map::new();
    summary.insert("operation".into(), json!("health"));
    summary.insert("healthy".into(), json!(true));
    if let Some(version) = first(&payload, &["version", "app_version", "appVersion"]) {
        summary.insert("version".into(), json!(str_value(&version)));
    }
    Ok(summary)
}

// -- Entry point -------------------------------------------------------------

/// Runs one opencode operation and returns its compact summary as JSON.
/// `values` are the already-validated parameter values.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    operation: &str,
    values: &Values,
    toolkit: &Toolkit,
    credentials: Option<&CredentialStore>,
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    redact: Option<&Redact>,
) -> ExecResult {
    run_with(operation, values, toolkit, credentials, timeout_seconds, max_output_bytes, idempotent, redact, EP).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with(
    operation: &str,
    values: &Values,
    toolkit: &Toolkit,
    credentials: Option<&CredentialStore>,
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    redact: Option<&Redact>,
    endpoints: &[Endpoint],
) -> ExecResult {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(timeout_seconds.max(0) as u64);
    let denied = |denial: Denied| ExecResult::denied(&denial, elapsed_ms(started));

    if !toolkit.allows_opencode_operation(operation) {
        return denied(Denied::new(
            DenialReason::Tier1Violation,
            format!("Opencode operation {} is not allowed for this toolkit.", repr_str(operation)),
        ));
    }

    let mut credential: Option<ResolvedCredential> = None;
    if let Some(name) = toolkit.credential.as_deref().filter(|c| !c.is_empty()) {
        let Some(store) = credentials else {
            return denied(Denied::new(
                DenialReason::CredentialUnavailable,
                "No credential store is configured, but this toolkit needs one.",
            ));
        };
        match store.resolve(name) {
            Ok(Some(found)) => credential = Some(found),
            Ok(None) => {
                return denied(Denied::new(
                    DenialReason::CredentialUnavailable,
                    format!("Credential {} is not configured yet.", repr_str(name)),
                ))
            }
            // PORT NOTE: a store/decrypt error raised out of `run()` in
            // Python; it is reported as an unavailable credential here.
            Err(err) => return denied(Denied::new(DenialReason::CredentialUnavailable, err.to_string())),
        }
    }

    let directory = Some(get(values, "directory")).filter(|d| !d.is_empty());
    if let Some(directory) = directory {
        if let Err(denial) = check_directory(directory, toolkit) {
            return denied(denial);
        }
    }

    let mut client = Client::new(toolkit, endpoints, credential.as_ref(), directory, deadline);
    let max = max_output_bytes;
    let outcome = match operation {
        "ask" => op_ask(&mut client, values, max).await,
        "run" => op_run(&mut client, values, max).await,
        "fire" => op_fire(&mut client, values, max).await,
        "check" => op_check(&mut client, values, max).await,
        "review_changes" => op_review_changes(&mut client, values, max).await,
        "abort" => op_abort(&mut client, values, max).await,
        "providers" => op_providers(&mut client, max).await,
        "health" => op_health(&mut client, max).await,
        // Unreachable: Tier 1 only admits OPENCODE_OPERATIONS.
        other => Err(Failure::Denied(Denied::new(
            DenialReason::Tier1Violation,
            format!("Opencode operation {} is not allowed for this toolkit.", repr_str(other)),
        ))),
    };

    let summary = match outcome {
        Ok(summary) => summary,
        Err(Failure::Denied(denial)) => return denied(denial),
        Err(Failure::Timeout) => {
            let session_id = client.session_id.clone().unwrap_or_else(|| get(values, "session_id").to_string());
            return ExecResult::new(
                if idempotent { OUTCOME_FAILED } else { OUTCOME_UNKNOWN },
                None,
                "",
                timeout_message(operation, timeout_seconds, &session_id, idempotent),
                false,
                elapsed_ms(started),
            )
            .untrusted(true);
        }
        Err(Failure::Opencode { message, status }) => {
            let stderr = match redact {
                Some(redact) => redact(&message),
                None => message,
            };
            return ExecResult::new(OUTCOME_FAILED, status, "", stderr, false, elapsed_ms(started)).untrusted(true);
        }
    };

    let mut stdout =
        pyjson::dumps_with(&cap_json_items(&Value::Object(summary), MAX_JSON_ITEMS), &Opts::unicode());
    let budget = max_output_bytes.max(0) as usize;
    let truncated = stdout.len() > budget;
    if truncated {
        stdout = String::from_utf8_lossy(&stdout.as_bytes()[..budget]).into_owned();
    }
    if let Some(redact) = redact {
        stdout = redact(&stdout);
    }
    ExecResult::new(OUTCOME_OK, client.last_status, stdout, "", truncated, elapsed_ms(started)).untrusted(true)
}

fn timeout_message(operation: &str, timeout_seconds: i64, session_id: &str, idempotent: bool) -> String {
    let base = format!("Timeout of {timeout_seconds}s exceeded.");
    if idempotent {
        return base;
    }
    let hint = if session_id.is_empty() {
        " Use the check operation on the session instead.".to_string()
    } else {
        format!(" Call the check operation with session_id={} instead.", repr_str(session_id))
    };
    format!(
        "{base} The outcome is UNKNOWN: opencode has the prompt and the session may still be working. Do \
         not retry the {operation} operation -- that would start the work a second time.{hint}"
    )
}

/// TCP-connect only, for `/health/ready` -- the `http` probe verbatim.
pub async fn probe(toolkit: &Toolkit) -> bool {
    http_probe(toolkit).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Bytes;
    use axum::extract::{Path as UrlPath, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get as get_route, post};
    use axum::{Json, Router};
    use parking_lot::Mutex;

    const BUSY_POLLS: i64 = 2;

    #[derive(Default)]
    struct FakeState {
        sessions: Vec<String>,
        counter: i64,
        requests: Vec<(String, String, HashMap<String, String>, Option<Value>)>,
        polls: HashMap<String, i64>,
        never_finish: bool,
    }

    type Shared = Arc<Mutex<FakeState>>;

    fn record(s: &Shared, method: &str, path: &str, headers: &HeaderMap, body: Option<Value>) {
        let h = headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        s.lock().requests.push((method.into(), path.into(), h, body));
    }

    fn not_found(msg: &str) -> Response {
        (StatusCode::NOT_FOUND, Json(json!({"error": msg}))).into_response()
    }

    async fn serve() -> (u16, Shared) {
        let state: Shared = Arc::default();
        let app = Router::new()
            .route(
                "/global/health",
                get_route(|State(s): State<Shared>, h: HeaderMap| async move {
                    record(&s, "GET", "/global/health", &h, None);
                    Json(json!({"status": "ok", "version": "1.1.48"}))
                }),
            )
            .route(
                "/config/providers",
                get_route(|State(s): State<Shared>, h: HeaderMap| async move {
                    record(&s, "GET", "/config/providers", &h, None);
                    Json(json!({
                        "providers": [{"id": "anthropic", "name": "Anthropic",
                                       "models": {"claude-opus-5": {}, "claude-sonnet-5": {}}}],
                        "default": {"anthropic": "claude-opus-5"},
                    }))
                }),
            )
            .route(
                "/api/redirect",
                get_route(|State(s): State<Shared>, h: HeaderMap| async move {
                    record(&s, "GET", "/api/redirect", &h, None);
                    (StatusCode::FOUND, [("Location", "http://evil.example/steal")]).into_response()
                }),
            )
            .route(
                "/session",
                post(|State(s): State<Shared>, h: HeaderMap, body: Bytes| async move {
                    let body: Option<Value> = serde_json::from_slice(&body).ok();
                    record(&s, "POST", "/session", &h, body.clone());
                    let mut st = s.lock();
                    st.counter += 1;
                    let id = format!("ses_{:04}", st.counter);
                    st.sessions.push(id.clone());
                    Json(json!({"id": id, "title": body.and_then(|b| b.get("title").cloned())}))
                }),
            )
            .route(
                "/session/{id}",
                get_route(|State(s): State<Shared>, UrlPath(id): UrlPath<String>, h: HeaderMap| async move {
                    record(&s, "GET", &format!("/session/{id}"), &h, None);
                    let mut st = s.lock();
                    if !st.sessions.contains(&id) {
                        return not_found("no such session");
                    }
                    let polls = st.polls.entry(id.clone()).or_insert(0);
                    *polls += 1;
                    let busy = st.never_finish || st.polls[&id] <= BUSY_POLLS;
                    Json(json!({"id": id, "status": if busy {"running"} else {"idle"},
                                "parts": [{"type": "text", "text": "task finished"}]}))
                    .into_response()
                }),
            )
            .route(
                "/session/{id}/{action}",
                get_route(
                    |State(s): State<Shared>, UrlPath((id, action)): UrlPath<(String, String)>, h: HeaderMap| async move {
                        record(&s, "GET", &format!("/session/{id}/{action}"), &h, None);
                        if !s.lock().sessions.contains(&id) {
                            return not_found("no such session");
                        }
                        match action.as_str() {
                            "todo" => Json(json!({"todos": [
                                {"content": "read the file", "status": "completed"},
                                {"content": "write the patch", "status": "in_progress"}]}))
                            .into_response(),
                            "diff" => Json(json!({"files": [
                                {"path": "src/a.py", "additions": 12, "deletions": 3},
                                {"path": "src/b.py", "patch": "+one\n+two\n-three\n"}]}))
                            .into_response(),
                            _ => not_found("not found"),
                        }
                    },
                )
                .post(
                    |State(s): State<Shared>, UrlPath((id, action)): UrlPath<(String, String)>, h: HeaderMap, body: Bytes| async move {
                        record(&s, "POST", &format!("/session/{id}/{action}"), &h, serde_json::from_slice(&body).ok());
                        let mut st = s.lock();
                        if !st.sessions.contains(&id) {
                            return not_found("no such session");
                        }
                        match action.as_str() {
                            "message" => Json(json!({"parts": [{"type": "text", "text": "The answer is 4."}]})).into_response(),
                            "prompt_async" => {
                                st.polls.insert(id, 0);
                                Json(json!({"accepted": true})).into_response()
                            }
                            "abort" => Json(json!({"aborted": true})).into_response(),
                            _ => not_found("not found"),
                        }
                    },
                ),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, state)
    }

    struct Env {
        dir: tempfile::TempDir,
        projects: String,
        port: u16,
        state: Shared,
    }

    async fn setup() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let projects = dir.path().join("projects");
        std::fs::create_dir_all(projects.join("demo")).unwrap();
        let (port, state) = serve().await;
        Env { projects: projects.to_string_lossy().into_owned(), dir, port, state }
    }

    fn toolkit(env: &Env, cidrs: &[&str], ops: &[&str], roots: Option<Vec<String>>, credential: Option<&str>) -> Toolkit {
        Toolkit {
            name: "opencode".into(),
            executor: "opencode".into(),
            base_url: Some(format!("http://127.0.0.1:{}", env.port)),
            allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
            allowed_opencode_operations: ops.iter().map(|s| s.to_string()).collect(),
            path_roots: roots.unwrap_or_else(|| vec![env.projects.clone()]),
            credential: credential.map(str::to_string),
            ..Toolkit::default()
        }
    }

    const ALL: &[&str] = &["ask", "run", "fire", "check", "review_changes", "abort", "providers", "health"];

    fn default_tk(env: &Env) -> Toolkit {
        toolkit(env, &["127.0.0.1/32"], ALL, None, None)
    }

    fn vals(pairs: &[(&str, &str)]) -> Values {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    async fn call(tk: &Toolkit, op: &str, pairs: &[(&str, &str)], timeout: i64, idempotent: bool) -> ExecResult {
        run(op, &vals(pairs), tk, None, timeout, 65536, idempotent, None).await
    }

    fn parse(r: &ExecResult) -> Value {
        serde_json::from_str(&r.stdout).unwrap_or_else(|_| panic!("{r:?}"))
    }

    #[tokio::test]
    async fn health_reports_healthy_and_version() {
        let env = setup().await;
        let r = call(&default_tk(&env), "health", &[], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_OK, "{r:?}");
        assert_eq!(parse(&r), json!({"operation": "health", "healthy": true, "version": "1.1.48"}));
        assert!(r.external_untrusted);
        assert_eq!(r.exit_code, Some(200));
    }

    #[tokio::test]
    async fn ask_creates_a_session_and_returns_the_answer() {
        let env = setup().await;
        let r = call(&default_tk(&env), "ask", &[("prompt", "what is 2+2?")], 30, true).await;
        let p = parse(&r);
        assert_eq!(p["operation"], "ask");
        assert_eq!(p["answer"], "The answer is 4.");
        let st = env.state.lock();
        assert!(st.sessions.contains(&p["session_id"].as_str().unwrap().to_string()));
        assert_eq!(st.requests.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(), ["POST", "POST"]);
        assert_eq!(st.requests[0].3, Some(json!({"title": "gatekeeper"})));
        assert_eq!(st.requests[1].3, Some(json!({"parts": [{"type": "text", "text": "what is 2+2?"}]})));
    }

    #[tokio::test]
    async fn fire_returns_the_session_id_without_waiting() {
        let env = setup().await;
        let p = parse(&call(&default_tk(&env), "fire", &[("prompt", "refactor it")], 30, true).await);
        assert_eq!(p["status"], "dispatched");
        assert_eq!(
            p["next"],
            "The task runs in the background. Call the check operation with session_id='ses_0001' for progress."
        );
        assert!(!env.state.lock().requests.iter().any(|r| r.0 == "GET"));
    }

    #[tokio::test]
    async fn run_polls_until_the_session_finishes() {
        let env = setup().await;
        let r = call(&default_tk(&env), "run", &[("prompt", "do the thing")], 30, false).await;
        let p = parse(&r);
        assert_eq!(p["operation"], "run");
        assert_eq!(p["done"], true);
        assert_eq!(p["status"], "idle");
        assert_eq!(p["files_changed"], json!(["src/a.py", "src/b.py"]));
        assert_eq!(p["last_message"], "task finished");
        let sid = p["session_id"].as_str().unwrap().to_string();
        assert_eq!(env.state.lock().polls[&sid], BUSY_POLLS + 1);
        // Key order follows Python's summary dict.
        let keys: Vec<&String> = p.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["session_id", "status", "done", "todos", "files_changed", "last_message", "operation"]);
    }

    #[tokio::test]
    async fn check_review_abort() {
        let env = setup().await;
        let tk = default_tk(&env);
        let fired = parse(&call(&tk, "fire", &[("prompt", "go")], 30, true).await);
        let sid = fired["session_id"].as_str().unwrap();

        let p = parse(&call(&tk, "check", &[("session_id", sid)], 30, true).await);
        assert_eq!(p["operation"], "check");
        assert_eq!(p["status"], "running");
        assert_eq!(p["done"], false);
        assert_eq!(p["todos"], json!([{"task": "read the file", "status": "completed"},
                                      {"task": "write the patch", "status": "in_progress"}]));
        assert_eq!(p["files_changed"], json!(["src/a.py", "src/b.py"]));

        let p = parse(&call(&tk, "review_changes", &[("session_id", sid)], 30, true).await);
        assert_eq!(p["files"][0], json!({"path": "src/a.py", "added": 12, "removed": 3}));
        assert_eq!(p["files"][1], json!({"path": "src/b.py", "added": 2, "removed": 1}));
        assert_eq!(p["totals"], json!({"files": 2, "added": 14, "removed": 4}));

        let p = parse(&call(&tk, "abort", &[("session_id", sid)], 30, true).await);
        assert_eq!(p["operation"], "abort");
        assert_eq!(p["aborted"], true);
        assert_eq!(p["response"], json!({"aborted": true}));
    }

    #[tokio::test]
    async fn providers_lists_models_and_defaults() {
        let env = setup().await;
        let p = parse(&call(&default_tk(&env), "providers", &[], 30, true).await);
        assert_eq!(
            p["providers"],
            json!([{"id": "anthropic", "name": "Anthropic", "default_model": "claude-opus-5",
                    "models": ["claude-opus-5", "claude-sonnet-5"]}])
        );
    }

    #[tokio::test]
    async fn directory_header_and_checks() {
        let env = setup().await;
        let tk = default_tk(&env);
        let directory = format!("{}/demo", env.projects);
        let r = call(&tk, "ask", &[("prompt", "hi"), ("directory", &directory)], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_OK);
        for (_, _, headers, _) in &env.state.lock().requests {
            assert_eq!(headers.get(DIRECTORY_HEADER), Some(&directory));
        }
        let r = call(&tk, "ask", &[("prompt", "hi"), ("directory", &format!("{}/typo", env.projects))], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(r.stderr.contains("does not exist"));
        let r = call(&tk, "ask", &[("prompt", "hi"), ("directory", "/etc")], 30, true).await;
        assert!(r.stderr.contains("path_roots"));

        let unmounted = toolkit(&env, &["127.0.0.1/32"], ALL, Some(vec!["/srv/not-mounted-here".into()]), None);
        let r = call(&unmounted, "ask", &[("prompt", "hi"), ("directory", "/srv/not-mounted-here/repo")], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_OK);
    }

    #[tokio::test]
    async fn session_id_is_rechecked_in_the_executor() {
        let env = setup().await;
        let r = call(&default_tk(&env), "check", &[("session_id", "../../global/health")], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(r.stderr.contains("session_id"));
        assert!(env.state.lock().requests.is_empty());
    }

    #[tokio::test]
    async fn tier1_boundaries() {
        let env = setup().await;
        let r = call(&toolkit(&env, &["127.0.0.1/32"], &["health"], None, None), "run", &[("prompt", "go")], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.stderr, "Opencode operation 'run' is not allowed for this toolkit.");

        let blocked = toolkit(&env, &["10.9.9.0/24"], ALL, None, None);
        let r = call(&blocked, "health", &[], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.stderr, "'127.0.0.1' resolves to 127.0.0.1, which is outside this toolkit's allowed_cidrs.");
        assert!(env.state.lock().requests.is_empty());
        assert!(!probe(&blocked).await);
        assert!(probe(&default_tk(&env)).await);
    }

    #[tokio::test]
    async fn run_timeout_is_unknown_not_failed() {
        let env = setup().await;
        env.state.lock().never_finish = true;
        let tk = default_tk(&env);
        let r = call(&tk, "run", &[("prompt", "endless")], 1, false).await;
        assert_eq!(r.outcome, OUTCOME_UNKNOWN);
        assert!(r.stderr.contains("UNKNOWN") && r.stderr.contains("check operation"));
        assert!(r.stderr.contains("session_id='ses_0001'"), "{}", r.stderr);
        let r = call(&tk, "run", &[("prompt", "endless")], 1, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.stderr, "Timeout of 1s exceeded.");
    }

    #[tokio::test]
    async fn credentials_are_sent_and_required() {
        let env = setup().await;
        let tk = toolkit(&env, &["127.0.0.1/32"], ALL, None, Some("opencode"));
        let r = call(&tk, "health", &[], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(r.stderr.contains("credential store"));

        let cred = ResolvedCredential {
            name: "opencode".into(),
            kind: "basic".into(),
            header: None,
            value: "opencode:s3cret".into(),
            previous_value: None,
            header_format: None,
        };
        assert_eq!(
            credential_headers(Some(&cred)),
            [("Authorization".to_string(), "Basic b3BlbmNvZGU6czNjcmV0".to_string())]
        );
        let mut client = Client::new(&tk, EP, Some(&cred), None, Instant::now() + Duration::from_secs(10));
        client.request("health", None, None, 65536).await.unwrap();
        let st = env.state.lock();
        assert_eq!(st.requests[0].2.get("authorization").map(String::as_str), Some("Basic b3BlbmNvZGU6czNjcmV0"));
        assert_eq!(st.requests[0].2.get("host").map(String::as_str), Some(format!("127.0.0.1:{}", env.port).as_str()));
    }

    #[tokio::test]
    async fn redirect_is_reported_not_followed() {
        let env = setup().await;
        let endpoints: Vec<Endpoint> = EP
            .iter()
            .map(|e| if e.0 == "health" { ("health", ("GET", "/api/redirect")) } else { *e })
            .collect();
        let r = run_with("health", &vals(&[]), &default_tk(&env), None, 30, 65536, true, None, &endpoints).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(
            r.stderr,
            "GET /api/redirect redirected (302) to 'http://evil.example/steal'; redirects are not followed."
        );
        assert_eq!(r.exit_code, Some(302));
    }

    #[tokio::test]
    async fn model_and_ceiling() {
        let env = setup().await;
        let tk = default_tk(&env);
        let r = call(&tk, "ask", &[("prompt", "hi"), ("model", "claude-opus-5")], 30, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(r.stderr.contains("provider/model"));
        let r = run("health", &vals(&[]), &tk, None, 10, 8, true, None).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(
            r.stderr,
            "GET /global/health returned more than the tool's max_output_bytes (8); no summary could be built. \
             Narrow the request or raise the ceiling."
        );
        // An unknown session is a 404 with opencode's own body.
        let r = call(&tk, "check", &[("session_id", "ses_9999")], 30, true).await;
        assert_eq!(r.stderr, r#"GET /session/ses_9999 returned 404: {"error":"no such session"}"#);
        assert_eq!(r.exit_code, Some(404));
        let _ = &env.dir;
    }

    #[test]
    fn readers() {
        let done = session_is_done;
        assert!(done(&json!({"status": "idle"})));
        assert!(done(&json!({"state": "completed"})));
        assert!(done(&json!({"idle": true})));
        assert!(done(&json!({"busy": false})));
        assert!(done(&json!({"time": {"completed": 1735689600}})));
        assert!(done(&json!({"error": {"message": "boom"}})));
        assert!(!done(&json!({"status": "running"})));
        assert!(!done(&json!({"unrelated": "shape"})));
        assert!(!done(&json!({})));

        let s = summarise(
            json!({"operation": "providers", "providers": []}).as_object().unwrap().clone(),
            &json!({"totally": {"different": "shape"}}),
            &["providers"],
        );
        assert_eq!(s["raw"], json!({"totally": {"different": "shape"}}));
        let s = summarise(json!({"operation": "ask", "answer": "hi"}).as_object().unwrap().clone(), &json!({"parts": []}), &["answer"]);
        assert!(!s.contains_key("raw"));

        assert_eq!(message_text(&json!("plain")), "plain");
        assert_eq!(message_text(&json!({"text": "wrapped"})), "wrapped");
        assert_eq!(message_text(&json!({"parts": [{"text": "a"}, {"text": "b"}]})), "a\nb");

        assert_eq!(
            prompt_body(&vals(&[("prompt", "fix it"), ("model", "anthropic/claude-opus-5"), ("agent", "build")])).unwrap(),
            json!({"parts": [{"type": "text", "text": "fix it"}], "providerID": "anthropic",
                   "modelID": "claude-opus-5", "agent": "build"})
        );
        assert_eq!(prompt_body(&vals(&[("prompt", "hi")])).unwrap(), json!({"parts": [{"type": "text", "text": "hi"}]}));

        assert_eq!(splitlines("a\r\nb\rc\n\nd"), ["a", "b", "c", "", "d"]);
        assert_eq!(
            files_changed(&json!({"x.py": "+a\n-b\n+++ h\n"})),
            vec![json!({"path": "x.py", "added": 1, "removed": 1}).as_object().unwrap().clone()]
        );
    }
}
