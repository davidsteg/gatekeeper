//! Single-exchange HTTP serving for protocol version 2026-07-28
//! (`mcp.server._streamable_http_modern`).
//!
//! A request is one POST: no `initialize`, no `Mcp-Session-Id`. The handler
//! runs inside the response; the response defers committing to
//! `text/event-stream` until the handler emits a notification or
//! [`sse::PING_INTERVAL`] elapses, so a handler that finishes quietly still
//! gets `application/json` with the table-mapped status. A client that
//! disconnects drops the response, which cancels the handler.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::response::Response;
use http::{HeaderValue, Method, StatusCode};
use serde_json::{Map, Value};
use tokio::sync::mpsc;

use super::handler::RequestContext;
use super::inbound::{self, classify_inbound_request, error_code_http_status, find_duplicated_routing_header, ModernRoute};
use super::jsonrpc::{self, Message};
use super::kernel::{Conn, Kernel, Sink};
use super::types::{
    ErrorData, McpError, CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, HEADER_MISMATCH, INVALID_REQUEST,
    MCP_PARAM_HEADER_PREFIX, MCP_PROTOCOL_VERSION_HEADER, PARSE_ERROR, PROTOCOL_VERSION_META_KEY,
};
use super::{check_accept, schema, security_check, sse, Inbound, Mount};

fn empty(status: StatusCode, allow: Option<&'static str>) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = status;
    if let Some(a) = allow {
        r.headers_mut().insert("allow", HeaderValue::from_static(a));
    }
    r
}

/// `_write`: a JSON-RPC reply with the table-mapped status.
fn write(message: &Value) -> Response {
    let status = message
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
        .map(error_code_http_status)
        .unwrap_or(200);
    let mut r = Response::new(Body::from(jsonrpc::modern_text(message)));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
    r
}

fn reply(id: &Value, outcome: Result<Value, McpError>) -> Value {
    match outcome {
        Ok(result) => jsonrpc::response(id, result),
        Err(e) => jsonrpc::error(Some(id), &e.modern_error()),
    }
}

fn context(inbound: &Inbound, method: &str, id: &Value, version: &str) -> RequestContext {
    RequestContext {
        extensions: inbound.extensions.clone(),
        headers: inbound.headers.clone(),
        peer: inbound.peer,
        session_id: None,
        request_id: Some(id.clone()),
        method: method.to_string(),
        protocol_version: version.to_string(),
        channel: None,
    }
}

/// `_tool_input_schema`: `name`'s inputSchema from the server's own
/// `tools/list`, as this caller would see it; `None` skips validation.
async fn tool_input_schema(kernel: &Kernel, inbound: &Inbound, id: &Value, route: &ModernRoute, name: &str) -> Option<Value> {
    let mut meta = Map::new();
    meta.insert(PROTOCOL_VERSION_META_KEY.into(), Value::from(route.protocol_version.clone()));
    meta.insert(CLIENT_CAPABILITIES_META_KEY.into(), route.client_capabilities.clone());
    if let Some(info) = &route.client_info {
        meta.insert(CLIENT_INFO_META_KEY.into(), info.clone());
    }
    let mut params = Map::new();
    params.insert("_meta".into(), Value::Object(meta));
    if schema::validate_client_request("tools/list", &route.protocol_version, Some(&params)).is_err() {
        tracing::debug!("Mcp-Param header validation skipped: the request envelope fails tools/list validation");
        return None;
    }
    // PORT NOTE: the SDK walks up to 100 pages of `nextCursor`; the handler
    // trait takes no cursor, so one listing is the whole catalog.
    let conn = Conn::born_ready(&route.protocol_version);
    let ctx = context(inbound, "tools/list", id, &route.protocol_version);
    match kernel.on_request(&conn, &ctx, Some(&params), &None).await {
        Ok(result) => result
            .get("tools")
            .and_then(Value::as_array)
            .and_then(|tools| tools.iter().find(|t| t.get("name").and_then(Value::as_str) == Some(name)))
            .and_then(|t| t.get("inputSchema").cloned()),
        Err(_) => {
            tracing::error!("Mcp-Param header validation skipped: the tools/list listing failed");
            None
        }
    }
}

/// `_mcp_param_rejection`.
async fn mcp_param_rejection(
    kernel: &Kernel,
    inbound: &Inbound,
    id: &Value,
    method: &str,
    params: Option<&Map<String, Value>>,
    route: &ModernRoute,
) -> Option<ErrorData> {
    if method != "tools/call" {
        return None;
    }
    let params = params.cloned().unwrap_or_default();
    let name = params.get("name")?.as_str()?.to_string();
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return None,
    };
    let prefix = MCP_PARAM_HEADER_PREFIX.to_lowercase();
    if arguments.is_empty() && !inbound.headers.keys().any(|k| k.as_str().starts_with(&prefix)) {
        return None;
    }
    let input_schema = tool_input_schema(kernel, inbound, id, route, &name).await?;
    inbound::validate_mcp_param_headers(&input_schema, &arguments, &inbound.header_pairs())
}

/// `_INVALID_BODY`: well-formed JSON that is not one request or notification.
fn invalid_body() -> Value {
    jsonrpc::error(None, &ErrorData::new(INVALID_REQUEST, "Body must be a single JSON-RPC request or notification object"))
}

/// `_acknowledge_notification`: an id-less object is `202` for a
/// notification at a served version (and dropped: nothing on this wire acts
/// on one), a rejection otherwise. Only the version header is checked.
fn acknowledge_notification(obj: &Map<String, Value>, inbound: &Inbound) -> Response {
    let Some((method, _)) = jsonrpc::parse_notification(obj) else {
        return write(&invalid_body());
    };
    let requested = inbound.header(MCP_PROTOCOL_VERSION_HEADER).unwrap_or_default();
    if let Some(unsupported) = inbound::unsupported_protocol_version_rejection(&requested) {
        return write(&jsonrpc::error(None, &unsupported));
    }
    tracing::debug!("acknowledged and dropped client notification {method} at {requested}");
    empty(StatusCode::ACCEPTED, None)
}

pub(crate) async fn handle(mount: &Mount, inbound: Inbound) -> Response {
    if let Some(r) = security_check(&mount.config.security, &inbound) {
        return r;
    }
    if inbound.method != Method::POST {
        return empty(StatusCode::METHOD_NOT_ALLOWED, Some("POST"));
    }
    let (has_json, has_sse) = check_accept(&inbound);
    if !has_json || !has_sse {
        return empty(StatusCode::NOT_ACCEPTABLE, None);
    }
    let Ok(decoded) = jsonrpc::parse_json(&inbound.body) else {
        return write(&jsonrpc::error(None, &ErrorData::new(PARSE_ERROR, "Parse error")));
    };
    if let Some(obj) = decoded.as_object().filter(|o| !o.contains_key("id")) {
        return acknowledge_notification(obj, &inbound);
    }
    let (id, method, params) = match (decoded.as_object(), jsonrpc::parse_message(&decoded)) {
        (Some(_), Ok(Message::Request { id, method, params })) => (id, method, params),
        // A batch, a posted response, or a request whose envelope is malformed.
        _ => return write(&invalid_body()),
    };
    let pairs = inbound.header_pairs();
    if let Some(duplicated) = find_duplicated_routing_header(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))) {
        return write(&jsonrpc::error(
            Some(&id),
            &ErrorData::new(HEADER_MISMATCH, format!("{duplicated} header appears more than once")),
        ));
    }
    // `dict(request.headers)`: the last copy of a header wins.
    let folded: HashMap<String, String> = pairs.iter().cloned().collect();
    let route = match classify_inbound_request(decoded.as_object().expect("checked"), Some(&folded)) {
        Ok(route) => route,
        Err(rejection) => return write(&jsonrpc::error(Some(&id), &rejection)),
    };
    let kernel = mount.kernel.clone();
    if let Some(rejection) = mcp_param_rejection(&kernel, &inbound, &id, &method, params.as_ref(), &route).await {
        return write(&jsonrpc::error(Some(&id), &rejection));
    }

    let ctx = context(&inbound, &method, &id, &route.protocol_version);
    let (tx, mut rx) = mpsc::channel::<Value>(1);
    let version = route.protocol_version.clone();
    let reply_id = id.clone();
    let run = {
        let kernel: Arc<Kernel> = kernel.clone();
        async move {
            let conn = Conn::born_ready(&version);
            let sink: Sink = Some(tx);
            let outcome = kernel.on_request(&conn, &ctx, params.as_ref(), &sink).await;
            reply(&reply_id, outcome)
        }
    };
    let mut run = Box::pin(run);

    // The deferral window: a quiet handler that finishes in time gets JSON.
    let first: Option<Value> = tokio::select! {
        biased;
        event = rx.recv() => event,
        message = &mut run => match rx.try_recv() {
            Ok(event) => {
                // It emitted on its way out: commit SSE after all.
                let stream = async_stream::stream! {
                    yield Ok::<_, std::convert::Infallible>(sse::modern_frame(&event));
                    while let Ok(e) = rx.try_recv() {
                        yield Ok(sse::modern_frame(&e));
                    }
                    yield Ok(sse::modern_frame(&message));
                };
                return sse::modern_response(Body::from_stream(stream));
            }
            Err(_) => return write(&message),
        },
        _ = tokio::time::sleep(sse::PING_INTERVAL) => None,
    };

    let stream = async_stream::stream! {
        match first {
            Some(event) => yield Ok::<_, std::convert::Infallible>(sse::modern_frame(&event)),
            None => yield Ok(bytes::Bytes::from_static(sse::MODERN_PING)),
        }
        let final_message = loop {
            tokio::select! {
                biased;
                event = rx.recv() => match event {
                    Some(e) => yield Ok(sse::modern_frame(&e)),
                    None => break (&mut run).await,
                },
                message = &mut run => {
                    while let Ok(e) = rx.try_recv() {
                        yield Ok(sse::modern_frame(&e));
                    }
                    break message;
                }
                _ = tokio::time::sleep(sse::PING_INTERVAL) => yield Ok(bytes::Bytes::from_static(sse::MODERN_PING)),
            }
        };
        yield Ok(sse::modern_frame(&final_message));
    };
    sse::modern_response(Body::from_stream(stream))
}
