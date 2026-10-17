//! Protocol constants and the small value types every other `mcp` module
//! shares. Mirrors `mcp_types.version`, `mcp_types.jsonrpc` and the meta-key
//! constants of `mcp_types._types` (SDK 2.0.0).

use serde_json::{Map, Value};

/// Every released protocol revision, oldest to newest.
pub const KNOWN_PROTOCOL_VERSIONS: [&str; 5] =
    ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"];
/// Revisions reachable via the `initialize` handshake.
pub const HANDSHAKE_PROTOCOL_VERSIONS: [&str; 4] =
    ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
/// Revisions that use the per-request envelope (no handshake).
pub const MODERN_PROTOCOL_VERSIONS: [&str; 1] = ["2026-07-28"];
pub const LATEST_HANDSHAKE_VERSION: &str = "2025-11-25";
pub const LATEST_MODERN_VERSION: &str = "2026-07-28";
/// The version a handshake-era request without `MCP-Protocol-Version`
/// is assumed to speak (the spec's default-absent value).
pub const DEFAULT_NEGOTIATED_VERSION: &str = "2025-03-26";

pub const PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
pub const CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";
pub const CLIENT_CAPABILITIES_META_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
pub const LOG_LEVEL_META_KEY: &str = "io.modelcontextprotocol/logLevel";
pub const SERVER_INFO_META_KEY: &str = "io.modelcontextprotocol/serverInfo";
pub const SUBSCRIPTION_ID_META_KEY: &str = "io.modelcontextprotocol/subscriptionId";

pub const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
pub const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
pub const MCP_METHOD_HEADER: &str = "mcp-method";
pub const MCP_NAME_HEADER: &str = "mcp-name";
pub const MCP_PARAM_HEADER_PREFIX: &str = "Mcp-Param-";
pub const LAST_EVENT_ID_HEADER: &str = "last-event-id";

// JSON-RPC / MCP error codes.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
pub const HEADER_MISMATCH: i64 = -32020;
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i64 = -32021;
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
pub const CONNECTION_CLOSED: i64 = -32000;
pub const REQUEST_TIMEOUT: i64 = -32001;
/// Answer to a cancelled request on the 2025-era wire (LSP's RequestCancelled).
pub const REQUEST_CANCELLED: i64 = -32800;

pub fn is_handshake_version(v: &str) -> bool {
    HANDSHAKE_PROTOCOL_VERSIONS.contains(&v)
}

pub fn is_modern_version(v: &str) -> bool {
    MODERN_PROTOCOL_VERSIONS.contains(&v)
}

/// `is_version_at_least`: unknown versions compare as "not at least".
pub fn is_version_at_least(version: &str, minimum: &str) -> bool {
    let idx = |v: &str| KNOWN_PROTOCOL_VERSIONS.iter().position(|k| *k == v);
    match (idx(version), idx(minimum)) {
        (Some(a), Some(b)) => a >= b,
        _ => false,
    }
}

/// A JSON-RPC error as it goes on the wire (`ErrorData`): `data` is
/// omitted when `None`.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorData {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl ErrorData {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        ErrorData { code, message: message.into(), data: None }
    }

    pub fn with_data(code: i64, message: impl Into<String>, data: Value) -> Self {
        ErrorData { code, message: message.into(), data: Some(data) }
    }

    /// The SDK's uniform answer to params that fail schema validation.
    pub fn invalid_params() -> Self {
        ErrorData::with_data(INVALID_PARAMS, "Invalid request parameters", Value::String(String::new()))
    }

    pub fn method_not_found(method: &str) -> Self {
        ErrorData::with_data(METHOD_NOT_FOUND, "Method not found", Value::String(method.to_string()))
    }

    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("code".into(), Value::from(self.code));
        m.insert("message".into(), Value::String(self.message.clone()));
        if let Some(d) = &self.data {
            m.insert("data".into(), d.clone());
        }
        Value::Object(m)
    }
}

/// What a handler may fail with.
///
/// `Rpc` is the SDK's `MCPError`: its code/message/data reach the wire as
/// given. `Internal` is any other exception: the handshake-era dispatcher
/// answers it with `code: 0` and the message (v1 compat), the 2026-07-28
/// entry with a generic `-32603 Internal server error` so handler internals
/// never reach the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum McpError {
    Rpc(ErrorData),
    Internal(String),
}

impl McpError {
    pub fn rpc(code: i64, message: impl Into<String>) -> Self {
        McpError::Rpc(ErrorData::new(code, message))
    }

    pub fn rpc_with_data(code: i64, message: impl Into<String>, data: Value) -> Self {
        McpError::Rpc(ErrorData::with_data(code, message, data))
    }

    pub fn internal(message: impl Into<String>) -> Self {
        McpError::Internal(message.into())
    }

    /// Wire form on the handshake-era dispatcher.
    pub(crate) fn legacy_error(&self) -> ErrorData {
        match self {
            McpError::Rpc(e) => e.clone(),
            McpError::Internal(msg) => ErrorData::new(0, msg.clone()),
        }
    }

    /// Wire form on the 2026-07-28 entries (`modern_error_data`).
    pub(crate) fn modern_error(&self) -> ErrorData {
        match self {
            McpError::Rpc(e) => e.clone(),
            McpError::Internal(msg) => {
                tracing::error!("modern request handler raised: {msg}");
                ErrorData::new(INTERNAL_ERROR, "Internal server error")
            }
        }
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpError::Rpc(e) => f.write_str(&e.message),
            McpError::Internal(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for McpError {}

/// Correlation key of a request id: `"7"` and `7` are one id
/// (`coerce_request_id`), while the wire always echoes the verbatim value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RidKey {
    Int(i128),
    Str(String),
}

impl RidKey {
    pub fn of(id: &Value) -> Option<RidKey> {
        match id {
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Some(RidKey::Int(i as i128))
                } else {
                    n.as_u64().map(|u| RidKey::Int(u as i128))
                }
            }
            Value::String(s) => Some(match parse_python_int(s) {
                Some(i) => RidKey::Int(i),
                None => RidKey::Str(s.clone()),
            }),
            _ => None,
        }
    }
}

/// Python's `int(str)`: surrounding whitespace, an optional sign, digits
/// with single underscores between them.
pub(crate) fn parse_python_int(s: &str) -> Option<i128> {
    let t = s.trim();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    if !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v: i128 = cleaned.parse().ok()?;
    Some(if neg { -v } else { v })
}

/// A valid JSON-RPC request id: a (non-bool) integer or a string.
pub(crate) fn is_request_id(v: &Value) -> bool {
    match v {
        Value::Number(n) => n.is_i64() || n.is_u64(),
        Value::String(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions_compare_through_the_registry() {
        assert!(is_version_at_least("2025-11-25", "2025-06-18"));
        assert!(!is_version_at_least("2025-03-26", "2025-11-25"));
        assert!(!is_version_at_least("zzz", "2024-11-05"));
    }

    #[test]
    fn stringified_int_ids_correlate() {
        assert_eq!(RidKey::of(&json!(7)), RidKey::of(&json!("7")));
        assert_eq!(RidKey::of(&json!(" 7 ")), Some(RidKey::Int(7)));
        assert_eq!(RidKey::of(&json!("1_0")), Some(RidKey::Int(10)));
        assert_eq!(RidKey::of(&json!("abc")), Some(RidKey::Str("abc".into())));
        assert_eq!(RidKey::of(&json!(true)), None);
        assert_eq!(RidKey::of(&json!(1.5)), None);
    }

    #[test]
    fn error_data_omits_absent_data() {
        assert_eq!(ErrorData::new(0, "x").to_value(), json!({"code": 0, "message": "x"}));
        assert_eq!(
            ErrorData::invalid_params().to_value(),
            json!({"code": -32602, "message": "Invalid request parameters", "data": ""})
        );
    }
}
