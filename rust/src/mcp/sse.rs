//! Server-sent-event framing for both eras.

use std::time::Duration;

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use serde_json::Value;

use super::jsonrpc;

/// Keepalive interval on every stream (sse-starlette's default, and the
/// 2026-07-28 deferral window).
pub(crate) const PING_INTERVAL: Duration = Duration::from_secs(15);

/// `event: message` frame, handshake-era JSON (`model_dump_json`).
pub(crate) fn legacy_frame(message: &Value) -> Bytes {
    Bytes::from(format!("event: message\r\ndata: {}\r\n\r\n", jsonrpc::legacy_text(message)))
}

/// `event: message` frame, 2026-07-28 JSON (`json.dumps`, compact).
pub(crate) fn modern_frame(message: &Value) -> Bytes {
    Bytes::from(format!("event: message\r\ndata: {}\r\n\r\n", jsonrpc::modern_text(message)))
}

/// sse-starlette's keepalive comment: `: ping - <str(datetime.now(utc))>`.
pub(crate) fn legacy_ping() -> Bytes {
    let now = chrono::Utc::now();
    let stamp = if now.timestamp_subsec_micros() == 0 {
        now.format("%Y-%m-%d %H:%M:%S+00:00").to_string()
    } else {
        now.format("%Y-%m-%d %H:%M:%S%.6f+00:00").to_string()
    };
    Bytes::from(format!(": ping - {stamp}\r\n\r\n"))
}

pub(crate) const MODERN_PING: &[u8] = b": ping\r\n\r\n";

/// The response head of a handshake-era SSE stream.
pub(crate) fn legacy_response(session_id: Option<&str>, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let h = response.headers_mut();
    h.insert("cache-control", HeaderValue::from_static("no-cache, no-transform"));
    h.insert("connection", HeaderValue::from_static("keep-alive"));
    h.insert("content-type", HeaderValue::from_static("text/event-stream"));
    if let Some(id) = session_id {
        if let Ok(v) = HeaderValue::from_str(id) {
            h.insert(super::types::MCP_SESSION_ID_HEADER, v);
        }
    }
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

/// The response head of a 2026-07-28 SSE commit.
pub(crate) fn modern_response(body: Body) -> Response {
    let mut response = Response::new(body);
    let h = response.headers_mut();
    h.insert("content-type", HeaderValue::from_static("text/event-stream"));
    h.insert("cache-control", HeaderValue::from_static("no-cache, no-transform"));
    h.insert("connection", HeaderValue::from_static("keep-alive"));
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frames() {
        let m = json!({"jsonrpc": "2.0", "id": 1, "result": {"t": "é"}});
        assert_eq!(legacy_frame(&m), Bytes::from("event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"t\":\"é\"}}\r\n\r\n"));
        assert_eq!(
            modern_frame(&m),
            Bytes::from("event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"t\":\"\\u00e9\"}}\r\n\r\n")
        );
        let ping = legacy_ping();
        assert!(ping.starts_with(b": ping - 20") && ping.ends_with(b"+00:00\r\n\r\n"), "{ping:?}");
    }
}
