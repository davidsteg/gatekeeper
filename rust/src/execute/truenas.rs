//! The `truenas` executor (port of `execute_truenas.py`; REQUIREMENTS.md
//! §8, FR-8.3a-f).
//!
//! TrueNAS's REST API v2.0 is deprecated as of 25.04 and removed in TrueNAS
//! 26; the authoritative interface is JSON-RPC 2.0 over WebSocket. This is
//! why `truenas` is its own executor rather than an `http` toolkit: the
//! whitelist here acts on *method names* (`pool.dataset.create`,
//! `pool.query`) instead of binaries or path prefixes, and parameters
//! travel as JSON-RPC params, not as a string that could be concatenated
//! (FR-8.3d).
//!
//! Each call opens its own connection, authenticates, sends one request,
//! and closes. Like Python, this executor does no CIDR/SSRF check of its
//! own: `ws_url` is a Tier 1 value, never agent-supplied.
//!
//! PORT NOTE: Python used the `websockets` library. Kept from it: the
//! connect step's error text (asyncio's `Connect call failed ...`), the
//! 1 MiB incoming message limit (`max_size`), the `ConnectionClosed` texts
//! (`received 1000 (OK); then sent 1000 (OK)`) and the 10 s close
//! handshake. Not kept: websockets' proxy support from the environment.

use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use indexmap::IndexMap;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::http::{asyncio_connect, fmt_seconds, host_info, parse_port, seconds};
use super::{elapsed_ms, ExecResult, Redact, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::credentials::{CredentialStore, ResolvedCredential};
use crate::errors::{ConfigError, DenialReason, Denied};
use crate::pyfmt::repr_str;
use crate::pyjson;
use crate::tier1::{py_truthy, urlsplit, Toolkit};

/// TrueNAS's JSON-RPC auth method for a static API key (FR-8.3e).
const AUTH_METHOD: &str = "auth.login_with_api_key";

/// What a `job: true` tool polls; its toolkit must allow it.
pub const JOB_METHOD: &str = "core.get_jobs";

/// websockets' default `max_size` for one incoming message.
const MAX_MESSAGE_SIZE: usize = 1 << 20;

/// websockets' default `close_timeout`.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Wraps a JSON-RPC call in TrueNAS middleware framing.
pub fn method_frame(method: &str, params: Vec<Value>, request_id: &str) -> Value {
    json!({"msg": "method", "method": method, "params": params, "id": request_id})
}

/// A `websockets.exceptions.WebSocketException`, as its `str()`.
#[derive(Debug)]
pub(super) struct WsError(pub(super) String);

/// The explanation websockets prints next to a close code.
fn close_code_explanation(code: u16) -> &'static str {
    match code {
        1000 => "OK",
        1001 => "going away",
        1002 => "protocol error",
        1003 => "unsupported data",
        1005 => "no status received [internal]",
        1006 => "connection closed abnormally [internal]",
        1007 => "invalid frame payload data",
        1008 => "policy violation",
        1009 => "message too big",
        1010 => "mandatory extension",
        1011 => "internal error",
        1012 => "service restart",
        1013 => "try again later",
        1014 => "bad gateway",
        1015 => "TLS handshake failure [internal]",
        3000..=3999 => "registered",
        4000..=4999 => "private use",
        _ => "unknown",
    }
}

/// websockets' `str(Close)`: `1000 (OK)` or `1000 (OK) reason`.
fn close_str(frame: Option<&CloseFrame>) -> String {
    let (code, reason) = match frame {
        Some(f) => (u16::from(f.code), f.reason.as_str().to_string()),
        None => (1005, String::new()),
    };
    let base = format!("{code} ({})", close_code_explanation(code));
    if reason.is_empty() {
        base
    } else {
        format!("{base} {reason}")
    }
}

/// Map a tungstenite failure to websockets' `ConnectionClosed` text.
pub(super) fn ws_error(err: tungstenite::Error) -> WsError {
    match err {
        tungstenite::Error::Capacity(e) => WsError(format!(
            "sent 1009 (message too big) {e}; no close frame received"
        )),
        _ => WsError("no close frame received or sent".into()),
    }
}

/// The next data message (text or binary); a close frame from the server
/// ends the connection the way websockets reports it.
pub(super) async fn recv(ws: &mut Ws) -> Result<String, WsError> {
    loop {
        match ws.next().await {
            None => return Err(WsError("no close frame received or sent".into())),
            Some(Err(e)) => return Err(ws_error(e)),
            Some(Ok(Message::Text(t))) => return Ok(t.as_str().to_string()),
            Some(Ok(Message::Binary(b))) => return Ok(String::from_utf8_lossy(&b).into_owned()),
            Some(Ok(Message::Close(frame))) => {
                let c = close_str(frame.as_ref());
                return Err(WsError(format!("received {c}; then sent {c}")));
            }
            Some(Ok(_)) => continue,
        }
    }
}

async fn send_method(ws: &mut Ws, method: &str, params: Vec<Value>, request_id: &str) -> Result<(), WsError> {
    let text = pyjson::dumps(&method_frame(method, params, request_id));
    ws.send(Message::text(text)).await.map_err(ws_error)
}

/// Waits for the `result` frame answering `request_id`; `Ok(None)` on
/// timeout.
async fn recv_result(ws: &mut Ws, request_id: &str, timeout_seconds: f64) -> Result<Option<String>, WsError> {
    let deadline = Instant::now() + seconds(timeout_seconds);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let raw = match tokio::time::timeout(deadline - now, recv(ws)).await {
            Err(_) => return Ok(None),
            Ok(r) => r?,
        };
        let Ok(frame) = serde_json::from_str::<Value>(&raw) else { continue };
        if frame.get("msg").and_then(Value::as_str) == Some("result")
            && frame.get("id").and_then(Value::as_str) == Some(request_id)
        {
            return Ok(Some(raw));
        }
    }
}

/// TrueNAS 26 middleware framing: a connect handshake must precede the
/// first method frame. Waits at most 1 s for `connected`.
async fn middleware_handshake(ws: &mut Ws, timeout_seconds: f64) -> Result<(), WsError> {
    let text = pyjson::dumps(&json!({"msg": "connect", "version": "1", "support": ["1"]}));
    ws.send(Message::text(text)).await.map_err(ws_error)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now).min(seconds(timeout_seconds));
        if remaining.is_zero() {
            return Ok(());
        }
        let raw = match tokio::time::timeout(remaining, recv(ws)).await {
            Err(_) => return Ok(()),
            Ok(r) => r?,
        };
        let Ok(frame) = serde_json::from_str::<Value>(&raw) else { continue };
        if frame.get("msg").and_then(Value::as_str) == Some("connected") {
            return Ok(());
        }
    }
}

/// What `_authenticate` can end in besides success.
enum AuthFailure {
    Denied(Denied),
    Ws(WsError),
    /// PORT NOTE: Python's `asyncio.wait_for(ws.recv())` here raised
    /// TimeoutError straight out of `run()`; the port reports it as a
    /// failed call (the method itself was never sent).
    Timeout,
}

async fn authenticate(
    ws: &mut Ws,
    credential: Option<&ResolvedCredential>,
    timeout_seconds: f64,
) -> Result<(), AuthFailure> {
    let Some(credential) = credential else { return Ok(()) };
    let request_id = uuid::Uuid::new_v4().to_string();
    send_method(ws, AUTH_METHOD, vec![Value::String(credential.value.clone())], &request_id)
        .await
        .map_err(AuthFailure::Ws)?;
    let raw = match tokio::time::timeout(seconds(timeout_seconds), recv(ws)).await {
        Err(_) => return Err(AuthFailure::Timeout),
        Ok(r) => r.map_err(AuthFailure::Ws)?,
    };
    // PORT NOTE: a reply that is not a JSON object raised out of Python's
    // `run()` (ValueError/AttributeError); here it is an authentication
    // failure.
    let ok = match serde_json::from_str::<Value>(&raw) {
        Ok(Value::Object(response)) => {
            !response.get("error").is_some_and(py_truthy) && response.get("result").is_some_and(py_truthy)
        }
        _ => false,
    };
    if !ok {
        return Err(AuthFailure::Denied(Denied::new(
            DenialReason::CredentialUnavailable,
            "TrueNAS authentication failed.",
        )));
    }
    Ok(())
}

/// Accepts exactly the server certificates whose SHA-256 (of the DER) is
/// pinned in Tier 1 (`tls_pin_sha256`, 1.24.0), instead of a CA chain and
/// a host name: a NAS's own self-signed certificate, reached by IP. The
/// handshake signature is still verified with the certificate's key.
#[derive(Debug)]
struct PinnedCert {
    pins: Vec<String>,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let seen = hex::encode(Sha256::digest(end_entity.as_ref()));
        if self.pins.iter().any(|pin| *pin == seen) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!("certificate sha256 {seen} is not pinned")))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The TLS connector for a toolkit with pinned certificates; `None` keeps
/// tungstenite's default (the system roots).
fn pinned_connector(pins: &[String]) -> Option<tokio_tungstenite::Connector> {
    if pins.is_empty() {
        return None;
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(PinnedCert { pins: pins.to_vec(), provider }))
        .with_no_client_auth();
    Some(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(config)))
}

/// `websockets.connect(url)`: TCP connect (asyncio's error text), then the
/// opening handshake, with the toolkit's certificate pins if it has any.
async fn connect_pinned(ws_url: &str, pins: &[String]) -> Result<Ws, String> {
    let parsed = urlsplit(ws_url);
    let info = host_info(&parsed.netloc);
    let port = match parse_port(&info.port)? {
        Some(p) if p != 0 => p,
        _ => {
            if parsed.scheme == "wss" {
                443
            } else {
                80
            }
        }
    };
    let stream = asyncio_connect(&info.hostname, port).await?;
    let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE_SIZE));
    let (ws, _) = tokio_tungstenite::client_async_tls_with_config(ws_url, stream, Some(config), pinned_connector(pins))
        .await
        .map_err(|e| e.to_string())?;
    Ok(ws)
}

/// Best-effort close, bounded like websockets' close handshake.
pub(super) async fn close(mut ws: Ws) {
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
        let _ = ws.close(None).await;
        while let Some(Ok(_)) = ws.next().await {}
    })
    .await;
}

/// How often a job's state is asked for while waiting on it.
const JOB_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The job states TrueNAS reports once a job has ended.
const JOB_FINAL_STATES: [&str; 3] = ["SUCCESS", "FAILED", "ABORTED"];

/// One JSON-RPC call. `params` is sent positionally, in declaration order.
///
/// `Err` only for a credential store that cannot be read or decrypted --
/// what escaped Python's `run()` as an exception.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    method: &str,
    params: &IndexMap<String, Value>,
    toolkit: &Toolkit,
    credentials: Option<&CredentialStore>,
    timeout_seconds: f64,
    max_output_bytes: i64,
    idempotent: bool,
    redact: Option<&Redact>,
) -> Result<ExecResult, ConfigError> {
    run_call(method, params, toolkit, credentials, timeout_seconds, max_output_bytes, idempotent, false, redact).await
}

/// Polls `core.get_jobs` for job `id` on the open connection until it has
/// ended, and returns a `result` frame of its own: the job's `result` on
/// SUCCESS, an `error` with the state and the job's error otherwise. Only
/// the job's `state`, `result` and `error` are read, never its
/// `arguments`. `Ok(None)` when the deadline passes first.
async fn wait_for_job(ws: &mut Ws, id: &Value, deadline: Instant) -> Result<Option<String>, WsError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        send_method(ws, JOB_METHOD, vec![json!([["id", "=", id]])], &request_id).await?;
        let Some(raw) = recv_result(ws, &request_id, remaining.as_secs_f64()).await? else { return Ok(None) };
        let frame: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
        if frame.get("error").is_some_and(py_truthy) {
            return Ok(Some(raw));
        }
        let job = frame.get("result").and_then(|r| r.get(0)).cloned().unwrap_or(Value::Null);
        let state = job.get("state").and_then(Value::as_str).unwrap_or_default().to_string();
        if JOB_FINAL_STATES.contains(&state.as_str()) {
            let reply = if state == "SUCCESS" {
                json!({"msg": "result", "result": job.get("result").cloned().unwrap_or(Value::Null)})
            } else {
                json!({"msg": "result", "error": {"job_state": state, "error": job.get("error").cloned().unwrap_or(Value::Null)}})
            };
            return Ok(Some(reply.to_string()));
        }
        if job.is_null() {
            return Ok(Some(json!({"msg": "result", "error": {"error": format!("job {id} not found")}}).to_string()));
        }
        tokio::time::sleep(JOB_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))).await;
    }
}

/// [`run`] for a tool that may be a middleware job (`job: true`, 1.24.0):
/// the method answers with a job id, and the call's result is the job's,
/// waited for within the same timeout.
#[allow(clippy::too_many_arguments)]
pub async fn run_call(
    method: &str,
    params: &IndexMap<String, Value>,
    toolkit: &Toolkit,
    credentials: Option<&CredentialStore>,
    timeout_seconds: f64,
    max_output_bytes: i64,
    idempotent: bool,
    job: bool,
    redact: Option<&Redact>,
) -> Result<ExecResult, ConfigError> {
    let ws_url = toolkit.ws_url.as_deref().expect("truenas toolkit without ws_url");
    let started = Instant::now();
    let denied = |denial: Denied| -> ExecResult {
        ExecResult::new(OUTCOME_FAILED, None, "", denial.agent_message(), false, elapsed_ms(started))
    };

    // Defensive re-check (FR-8.3c): `method` is fixed per tool, not
    // agent-suppliable, so this can only fail on a programming error.
    if !toolkit.allows_rpc_method(method) {
        return Ok(denied(Denied::new(
            DenialReason::RpcMethodDenied,
            format!("RPC method {} is not allowed for this toolkit.", repr_str(method)),
        )));
    }

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

    // PORT NOTE: Python caught only OSError/TimeoutError here; a failed
    // opening handshake (e.g. an HTTP 404 instead of an upgrade) escaped
    // `run()`. The port reports every connect failure the same way.
    let deadline = started + seconds(timeout_seconds);
    let mut ws = match tokio::time::timeout(seconds(timeout_seconds), connect_pinned(ws_url, &toolkit.tls_pin_sha256)).await {
        Ok(Ok(ws)) => ws,
        Ok(Err(exc)) => {
            return Ok(ExecResult::new(
                OUTCOME_FAILED,
                None,
                "",
                format!("Could not connect to {ws_url}: {exc}"),
                false,
                elapsed_ms(started),
            )
            .untrusted(true))
        }
        Err(_) => {
            return Ok(ExecResult::new(
                OUTCOME_FAILED,
                None,
                "",
                format!("Could not connect to {ws_url}: "),
                false,
                elapsed_ms(started),
            )
            .untrusted(true))
        }
    };

    let exchange = async {
        if let Err(e) = middleware_handshake(&mut ws, timeout_seconds).await {
            return Err(AuthFailure::Ws(e));
        }
        authenticate(&mut ws, credential.as_ref(), timeout_seconds).await?;
        let request_id = uuid::Uuid::new_v4().to_string();
        // FR-8.3d: params are JSON-RPC params, never string-concatenated,
        // sent positionally in declaration order.
        let values: Vec<Value> = params.values().cloned().collect();
        send_method(&mut ws, method, values, &request_id).await.map_err(AuthFailure::Ws)?;
        let raw = recv_result(&mut ws, &request_id, timeout_seconds).await.map_err(AuthFailure::Ws)?;
        if !job {
            return Ok(raw);
        }
        let Some(raw) = raw else { return Ok(None) };
        let frame: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
        match frame.get("result") {
            Some(id @ Value::Number(_)) if !frame.get("error").is_some_and(py_truthy) => {
                wait_for_job(&mut ws, id, deadline).await.map_err(AuthFailure::Ws)
            }
            _ => Ok(Some(raw)),
        }
    };
    let outcome = exchange.await;
    // The timeout result's duration is taken before the close, like
    // Python's `return` inside `try` before its `finally`.
    let early_duration = elapsed_ms(started);
    close(ws).await;

    let raw = match outcome {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            return Ok(ExecResult::new(
                if idempotent { OUTCOME_FAILED } else { OUTCOME_UNKNOWN },
                None,
                "",
                if idempotent {
                    format!("Timeout of {}s exceeded.", fmt_seconds(timeout_seconds))
                } else {
                    format!(
                        "Timeout of {}s exceeded. The outcome is UNKNOWN: the call may have reached TrueNAS. Do not retry without checking the state first.",
                        fmt_seconds(timeout_seconds)
                    )
                },
                false,
                early_duration,
            )
            .untrusted(true))
        }
        Err(AuthFailure::Denied(denial)) => {
            return Ok(ExecResult::new(OUTCOME_FAILED, None, "", denial.agent_message(), false, early_duration))
        }
        Err(AuthFailure::Timeout) => {
            return Ok(ExecResult::new(
                OUTCOME_FAILED,
                None,
                "",
                format!("Timeout of {}s exceeded.", fmt_seconds(timeout_seconds)),
                false,
                early_duration,
            )
            .untrusted(true))
        }
        Err(AuthFailure::Ws(WsError(exc))) => {
            return Ok(ExecResult::new(
                OUTCOME_FAILED,
                None,
                "",
                format!("Connection error: {exc}"),
                false,
                early_duration,
            )
            .untrusted(true))
        }
    };

    let mut text = raw;
    let max = max_output_bytes.max(0) as usize;
    let truncated = text.len() > max;
    if truncated {
        text = String::from_utf8_lossy(&text.as_bytes()[..max]).into_owned();
    }

    let response: Option<Value> = serde_json::from_str(&text).ok();
    let unicode = pyjson::Opts::unicode();
    let (outcome, exit_code, mut stdout, mut stderr) = match &response {
        Some(Value::Object(map)) if map.get("error").is_some_and(py_truthy) => {
            (OUTCOME_FAILED, Some(1), String::new(), pyjson::dumps_with(&map["error"], &unicode))
        }
        Some(Value::Object(map)) => (
            OUTCOME_OK,
            Some(0),
            pyjson::dumps_with(map.get("result").unwrap_or(&Value::Null), &unicode),
            String::new(),
        ),
        _ => (OUTCOME_FAILED, None, text.clone(), "Response was not a JSON-RPC object.".to_string()),
    };

    if let Some(redact) = redact {
        stdout = redact(&stdout);
        stderr = redact(&stderr);
    }
    Ok(ExecResult::new(outcome, exit_code, stdout, stderr, truncated, elapsed_ms(started)).untrusted(true))
}

#[cfg(test)]
#[path = "truenas_tests.rs"]
mod tests;

/// TCP/WebSocket-handshake reachability only, for /health/ready.
pub async fn probe(toolkit: &Toolkit) -> bool {
    let ws_url = toolkit.ws_url.as_deref().expect("truenas toolkit without ws_url");
    match tokio::time::timeout(Duration::from_secs(5), connect_pinned(ws_url, &toolkit.tls_pin_sha256)).await {
        Ok(Ok(ws)) => {
            close(ws).await;
            true
        }
        _ => false,
    }
}
