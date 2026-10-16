//! Inbound request classification for the 2026-07-28 single-exchange path
//! (`mcp.shared.inbound`): the validation ladder, the header-value codec
//! and the `x-mcp-header` / `Mcp-Param-*` checks.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use serde_json::{Map, Value};

use super::types::{
    ErrorData, CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, HEADER_MISMATCH, INTERNAL_ERROR, INVALID_PARAMS,
    INVALID_REQUEST, MCP_METHOD_HEADER, MCP_NAME_HEADER, MCP_PARAM_HEADER_PREFIX, MCP_PROTOCOL_VERSION_HEADER,
    METHOD_NOT_FOUND, MISSING_REQUIRED_CLIENT_CAPABILITY, MODERN_PROTOCOL_VERSIONS, PARSE_ERROR,
    PROTOCOL_VERSION_META_KEY, UNSUPPORTED_PROTOCOL_VERSION,
};
use crate::pyfmt;

pub const X_MCP_HEADER_KEY: &str = "x-mcp-header";

/// Method -> params key mirrored as the `Mcp-Name` header.
pub fn name_bearing_param(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    }
}

/// `ERROR_CODE_HTTP_STATUS`: the HTTP status for a JSON-RPC error code on
/// the 2026-07-28 wire. Unmapped codes (INTERNAL_ERROR among them) are 200.
pub fn error_code_http_status(code: i64) -> u16 {
    match code {
        PARSE_ERROR | INVALID_REQUEST | INVALID_PARAMS | HEADER_MISMATCH | MISSING_REQUIRED_CLIENT_CAPABILITY
        | UNSUPPORTED_PROTOCOL_VERSION => 400,
        METHOD_NOT_FOUND => 404,
        INTERNAL_ERROR => 200,
        _ => 200,
    }
}

fn header_safe(value: &str) -> bool {
    value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn sentinel_payload(value: &str) -> Option<&str> {
    value.strip_prefix("=?base64?").and_then(|rest| rest.strip_suffix("?="))
}

/// Python's `str.strip()` whitespace.
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

/// Wrap `value` in the `=?base64?...?=` sentinel when it would not survive
/// an HTTP field round-trip.
pub fn encode_header_value(value: &str) -> String {
    // `.*` in the sentinel regex does not cross a newline.
    let looks_like_sentinel = sentinel_payload(value).is_some_and(|p| !p.contains('\n'));
    if header_safe(value) && value == py_strip(value) && !looks_like_sentinel {
        return value.to_string();
    }
    format!("=?base64?{}?=", base64::engine::general_purpose::STANDARD.encode(value.as_bytes()))
}

/// Inverse of [`encode_header_value`]; a malformed sentinel yields `None`.
pub fn decode_header_value(value: Option<&str>) -> Option<String> {
    let value = value?;
    let payload = match sentinel_payload(value) {
        Some(p) if !p.contains('\n') => p,
        _ => return Some(value.to_string()),
    };
    let engine = &base64::engine::general_purpose::STANDARD;
    // `b64decode(validate=True)` accepts canonical and padding-free-tail-bit
    // variants alike; the round-trip check below rejects the latter.
    let decoded = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireCanonical),
    )
    .decode(payload)
    .ok()?;
    if engine.encode(&decoded) != payload {
        return None;
    }
    String::from_utf8(decoded).ok()
}

const SUBSCHEMA_SINGLE: [&str; 11] = [
    "items",
    "contains",
    "unevaluatedItems",
    "additionalProperties",
    "propertyNames",
    "unevaluatedProperties",
    "not",
    "if",
    "then",
    "else",
    "contentSchema",
];
const SUBSCHEMA_LIST: [&str; 4] = ["allOf", "anyOf", "oneOf", "prefixItems"];
const SUBSCHEMA_MAP: [&str; 4] = ["patternProperties", "dependentSchemas", "$defs", "definitions"];

/// `(properties path, schema)` for every schema position, in the Python
/// walk's order (an explicit stack, last pushed first).
fn walk_schema_positions(root: &Value) -> Vec<(Option<Vec<String>>, &Map<String, Value>)> {
    let mut out = Vec::new();
    let mut stack: Vec<(Option<Vec<String>>, &Value)> = vec![(Some(Vec::new()), root)];
    while let Some((path, node)) = stack.pop() {
        let Some(schema) = node.as_object() else { continue };
        out.push((path.clone(), schema));
        for (kw, val) in schema {
            if kw == "properties" && val.is_object() {
                for (name, sub) in val.as_object().unwrap() {
                    let next = path.as_ref().map(|p| {
                        let mut p = p.clone();
                        p.push(name.clone());
                        p
                    });
                    stack.push((next, sub));
                }
            } else if SUBSCHEMA_SINGLE.contains(&kw.as_str()) {
                stack.push((None, val));
            } else if SUBSCHEMA_LIST.contains(&kw.as_str()) && val.is_array() {
                stack.extend(val.as_array().unwrap().iter().map(|sub| (None, sub)));
            } else if SUBSCHEMA_MAP.contains(&kw.as_str()) && val.is_object() {
                stack.extend(val.as_object().unwrap().values().map(|sub| (None, sub)));
            }
        }
    }
    out
}

fn is_rfc9110_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A reason string if any `x-mcp-header` annotation in `input_schema` is
/// invalid, else `None`.
pub fn find_invalid_x_mcp_header(input_schema: &Value) -> Option<String> {
    let mut seen: HashMap<String, String> = HashMap::new();
    for (path, schema) in walk_schema_positions(input_schema) {
        let Some(header) = schema.get(X_MCP_HEADER_KEY) else { continue };
        let path = match path {
            Some(p) if !p.is_empty() => p,
            _ => {
                return Some(format!(
                    "{X_MCP_HEADER_KEY} found at a schema position not reachable via a pure `properties` chain"
                ))
            }
        };
        let where_ = path.join(".");
        let where_r = pyfmt::repr_str(&where_);
        let Some(header) = header.as_str() else {
            return Some(format!(
                "property {where_r}: {X_MCP_HEADER_KEY} must be a string, not {}",
                pyfmt::type_name(header)
            ));
        };
        if !is_rfc9110_token(header) {
            return Some(format!(
                "property {where_r}: {X_MCP_HEADER_KEY} {} is not an RFC 9110 token",
                pyfmt::repr_str(header)
            ));
        }
        let prop_type = schema.get("type").unwrap_or(&Value::Null);
        let Some(prop_type) = prop_type.as_str() else {
            return Some(format!(
                "property {where_r}: {X_MCP_HEADER_KEY} is only permitted on integer/string/boolean properties (the type keyword is {}, not a string)",
                pyfmt::type_name(prop_type)
            ));
        };
        if !["string", "integer", "boolean"].contains(&prop_type) {
            return Some(format!(
                "property {where_r}: {X_MCP_HEADER_KEY} is only permitted on integer/string/boolean properties (got {})",
                pyfmt::repr_str(prop_type)
            ));
        }
        let lower = header.to_lowercase();
        if let Some(prev) = seen.get(&lower) {
            return Some(format!(
                "{X_MCP_HEADER_KEY} {} on property {where_r} duplicates property {}",
                pyfmt::repr_str(header),
                pyfmt::repr_str(prev)
            ));
        }
        seen.insert(lower, where_);
    }
    None
}

fn annotated_positions(input_schema: &Value) -> Vec<(Vec<String>, String, &Map<String, Value>)> {
    walk_schema_positions(input_schema)
        .into_iter()
        .filter_map(|(path, schema)| {
            let path = path.filter(|p| !p.is_empty())?;
            let token = schema.get(X_MCP_HEADER_KEY)?.as_str()?.to_string();
            Some((path, token, schema))
        })
        .collect()
}

/// Each property carrying a valid `x-mcp-header`, keyed by property path.
pub fn x_mcp_header_map(input_schema: &Value) -> Vec<(Vec<String>, String)> {
    annotated_positions(input_schema).into_iter().map(|(p, t, _)| (p, t)).collect()
}

/// Python's `str(value)` for a header-mirrorable scalar.
fn render_header_scalar(value: &Value) -> Option<String> {
    match value {
        Value::Bool(b) => Some(if *b { "true" } else { "false" }.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(pyfmt::number_str(n)),
        _ => None,
    }
}

fn value_at_path<'a>(arguments: &'a Map<String, Value>, path: &[String]) -> Option<&'a Value> {
    let mut node = arguments.get(path.first()?)?;
    for key in &path[1..] {
        node = node.as_object()?.get(key)?;
    }
    if node.is_null() {
        None
    } else {
        Some(node)
    }
}

/// The `Mcp-Param-*` headers a `tools/call` mirrors from its arguments.
pub fn mcp_param_headers(header_map: &[(Vec<String>, String)], arguments: &Map<String, Value>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (path, token) in header_map {
        let Some(rendered) = value_at_path(arguments, path).and_then(render_header_scalar) else { continue };
        let name = format!("{MCP_PARAM_HEADER_PREFIX}{token}");
        out.retain(|(n, _)| *n != name);
        out.push((name, encode_header_value(&rendered)));
    }
    out
}

/// Name of a routing header supplied more than once, from raw header lines.
pub fn find_duplicated_routing_header<'a>(headers: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<String> {
    let mut seen = HashSet::new();
    for (name, _) in headers {
        let key = name.to_ascii_lowercase();
        if [MCP_PROTOCOL_VERSION_HEADER, MCP_METHOD_HEADER, MCP_NAME_HEADER].contains(&key.as_str()) {
            if !seen.insert(key.clone()) {
                return Some(key);
            }
        }
    }
    None
}

/// A request whose envelope passed every rung.
#[derive(Debug, Clone, PartialEq)]
pub struct ModernRoute {
    pub protocol_version: String,
    pub client_info: Option<Value>,
    pub client_capabilities: Value,
}

/// The first rung that failed.
pub type Rejection = ErrorData;

fn reject(code: i64, message: impl Into<String>) -> Rejection {
    ErrorData::new(code, message)
}

/// The modern-protocol validation ladder over a decoded request body.
/// `headers` (lowercase name -> value, last copy wins) is `None` to skip
/// the header rung.
pub fn classify_inbound_request(
    body: &Map<String, Value>,
    headers: Option<&HashMap<String, String>>,
) -> Result<ModernRoute, Rejection> {
    let meta = body.get("params").and_then(|p| p.as_object()).and_then(|p| p.get("_meta")).and_then(|m| m.as_object());
    let Some(meta) = meta else {
        return Err(reject(
            INVALID_PARAMS,
            format!(
                "params._meta must be an object carrying the required {} and {} envelope keys",
                pyfmt::repr_str(PROTOCOL_VERSION_META_KEY),
                pyfmt::repr_str(CLIENT_CAPABILITIES_META_KEY)
            ),
        ));
    };
    let missing: Vec<&str> = [PROTOCOL_VERSION_META_KEY, CLIENT_CAPABILITIES_META_KEY]
        .into_iter()
        .filter(|k| !meta.contains_key(*k))
        .collect();
    if !missing.is_empty() {
        return Err(reject(
            INVALID_PARAMS,
            format!("params._meta is missing the required envelope key(s): {}", missing.join(", ")),
        ));
    }
    let protocol_version = &meta[PROTOCOL_VERSION_META_KEY];
    let client_info = meta.get(CLIENT_INFO_META_KEY).filter(|v| !v.is_null()).cloned();
    let client_capabilities = meta[CLIENT_CAPABILITIES_META_KEY].clone();
    if let Some(headers) = headers {
        let version_header = headers.get(MCP_PROTOCOL_VERSION_HEADER);
        if version_header.is_none_or(|h| protocol_version.as_str() != Some(h.as_str())) {
            return Err(reject(
                HEADER_MISMATCH,
                format!("{MCP_PROTOCOL_VERSION_HEADER} header does not match the request envelope's protocol version"),
            ));
        }
        let method = body.get("method");
        let method_header = headers.get(MCP_METHOD_HEADER);
        if method_header.map(|h| Value::String(h.clone())).as_ref() != method {
            return Err(reject(HEADER_MISMATCH, format!("{MCP_METHOD_HEADER} header does not match the request body's method")));
        }
        if let Some(name_key) = method.and_then(|m| m.as_str()).and_then(name_bearing_param) {
            let body_value = body["params"].get(name_key).filter(|v| !v.is_null());
            if let Some(body_value) = body_value {
                let decoded = decode_header_value(headers.get(MCP_NAME_HEADER).map(String::as_str));
                if decoded.map(Value::String).as_ref() != Some(body_value) {
                    return Err(reject(
                        HEADER_MISMATCH,
                        format!(
                            "{MCP_NAME_HEADER} header does not match the request body's {} parameter",
                            pyfmt::repr_str(name_key)
                        ),
                    ));
                }
            }
        }
    }
    let Some(version) = protocol_version.as_str() else {
        return Err(reject(INVALID_PARAMS, "the protocol-version envelope value must be a string"));
    };
    if !MODERN_PROTOCOL_VERSIONS.contains(&version) {
        let mut data = Map::new();
        data.insert("supported".into(), Value::from(MODERN_PROTOCOL_VERSIONS.to_vec()));
        data.insert("requested".into(), Value::from(version));
        return Err(ErrorData::with_data(UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version", Value::Object(data)));
    }
    Ok(ModernRoute { protocol_version: version.to_string(), client_info, client_capabilities })
}

fn is_canonical_decimal(s: &str) -> bool {
    let body = s.strip_prefix('-').unwrap_or(s);
    let (whole, frac) = match body.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };
    !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && frac.is_none_or(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

fn param_value_matches(prop_type: Option<&Value>, value: &Value, rendered: &str, decoded: &str) -> bool {
    let integral = match value {
        Value::Number(n) if n.is_i64() || n.is_u64() => Some(n.as_i128()),
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0).map(|f| Some(f as i128)),
        _ => None,
    };
    if prop_type.and_then(Value::as_str) == Some("integer") && is_canonical_decimal(decoded) {
        if let Some(Some(expected)) = integral {
            let (whole, fraction) = decoded.split_once('.').unwrap_or((decoded, ""));
            if !fraction.is_empty() && fraction.bytes().any(|b| b != b'0') {
                return false;
            }
            return whole.parse::<i128>().is_ok_and(|w| w == expected);
        }
    }
    decoded == rendered
}

/// Compare a `tools/call` request's `Mcp-Param-*` headers against its body
/// arguments. `headers` are the raw `(name, value)` pairs.
pub fn validate_mcp_param_headers(
    input_schema: &Value,
    arguments: &Map<String, Value>,
    headers: &[(String, String)],
) -> Option<Rejection> {
    if find_invalid_x_mcp_header(input_schema).is_some() {
        return None;
    }
    let mut folded: HashMap<String, &str> = HashMap::new();
    let mut duplicated: HashSet<String> = HashSet::new();
    for (name, value) in headers {
        let key = name.to_lowercase();
        if folded.contains_key(&key) {
            duplicated.insert(key.clone());
        }
        folded.insert(key, value);
    }
    for (path, token, schema) in annotated_positions(input_schema) {
        let header_name = format!("{MCP_PARAM_HEADER_PREFIX}{token}");
        let key = header_name.to_lowercase();
        let raw = folded.get(&key).copied();
        let value = value_at_path(arguments, &path);
        let argument = pyfmt::repr_str(&path.join("."));
        if raw.is_some() && duplicated.contains(&key) {
            return Some(reject(HEADER_MISMATCH, format!("{header_name} header appears more than once")));
        }
        let Some(value) = value else {
            if raw.is_some() {
                return Some(reject(
                    HEADER_MISMATCH,
                    format!("{header_name} header is present but the request body's {argument} argument is absent"),
                ));
            }
            continue;
        };
        let Some(rendered) = render_header_scalar(value) else {
            if raw.is_some() {
                return Some(reject(
                    HEADER_MISMATCH,
                    format!("{header_name} header does not match the request body's {argument} argument"),
                ));
            }
            continue;
        };
        let Some(raw) = raw else {
            return Some(reject(
                HEADER_MISMATCH,
                format!("{header_name} header is missing but the request body's {argument} argument is present"),
            ));
        };
        let Some(decoded) = decode_header_value(Some(raw)) else {
            return Some(reject(HEADER_MISMATCH, format!("{header_name} header carries a malformed base64 sentinel value")));
        };
        if !param_value_matches(schema.get("type"), value, &rendered, &decoded) {
            return Some(reject(
                HEADER_MISMATCH,
                format!("{header_name} header does not match the request body's {argument} argument"),
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hdrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn body(method: &str, params: Value) -> Map<String, Value> {
        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).as_object().unwrap().clone()
    }

    fn meta() -> Value {
        json!({PROTOCOL_VERSION_META_KEY: "2026-07-28", CLIENT_CAPABILITIES_META_KEY: {}})
    }

    #[test]
    fn header_codec_round_trips() {
        assert_eq!(encode_header_value("demo.echo"), "demo.echo");
        assert_eq!(encode_header_value(" x"), "=?base64?IHg=?=");
        assert_eq!(encode_header_value("é"), "=?base64?w6k=?=");
        assert_eq!(encode_header_value("=?base64?abc?="), "=?base64?PT9iYXNlNjQ/YWJjPz0=?=");
        assert_eq!(decode_header_value(Some("=?base64?ZGVtby5lY2hv?=")).as_deref(), Some("demo.echo"));
        assert_eq!(decode_header_value(Some("=?base64?w6k=?=")).as_deref(), Some("é"));
        assert_eq!(decode_header_value(Some("=?base64?w6l=?=")), None, "non-canonical tail bits");
        assert_eq!(decode_header_value(Some("=?base64?!!?=")), None);
        assert_eq!(decode_header_value(Some("=?base64?/w==?=")), None, "not UTF-8");
        assert_eq!(decode_header_value(Some("plain")).as_deref(), Some("plain"));
        assert_eq!(decode_header_value(None), None);
    }

    #[test]
    fn the_ladder_in_order() {
        let h = hdrs(&[("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/list")]);
        let err = classify_inbound_request(&body("tools/list", json!({})), Some(&h)).unwrap_err();
        assert_eq!(err.message, "params._meta must be an object carrying the required 'io.modelcontextprotocol/protocolVersion' and 'io.modelcontextprotocol/clientCapabilities' envelope keys");
        let err = classify_inbound_request(&body("tools/list", json!({"_meta": {PROTOCOL_VERSION_META_KEY: "x"}})), Some(&h))
            .unwrap_err();
        assert_eq!(err.message, "params._meta is missing the required envelope key(s): io.modelcontextprotocol/clientCapabilities");
        let route = classify_inbound_request(&body("tools/list", json!({"_meta": meta()})), Some(&h)).unwrap();
        assert_eq!(route.protocol_version, "2026-07-28");
        assert_eq!(route.client_info, None);
        let err = classify_inbound_request(&body("tools/call", json!({"_meta": meta()})), Some(&h)).unwrap_err();
        assert_eq!((err.code, err.message.as_str()), (HEADER_MISMATCH, "mcp-method header does not match the request body's method"));
        let h2 = hdrs(&[("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/call"), ("mcp-name", "b")]);
        let err = classify_inbound_request(&body("tools/call", json!({"_meta": meta(), "name": "a"})), Some(&h2)).unwrap_err();
        assert_eq!(err.message, "mcp-name header does not match the request body's 'name' parameter");
        // No body name: nothing to compare.
        assert!(classify_inbound_request(&body("tools/call", json!({"_meta": meta()})), Some(&h2)).is_ok());
        let mut m = meta();
        m[PROTOCOL_VERSION_META_KEY] = json!("2030-01-01");
        let err = classify_inbound_request(&body("tools/list", json!({"_meta": m.clone()})), None).unwrap_err();
        assert_eq!(err.to_value(), json!({"code": -32022, "message": "Unsupported protocol version",
                                          "data": {"supported": ["2026-07-28"], "requested": "2030-01-01"}}));
        let err = classify_inbound_request(&body("tools/list", json!({"_meta": m})), Some(&h)).unwrap_err();
        assert_eq!(err.code, HEADER_MISMATCH);
        let mut m = meta();
        m[PROTOCOL_VERSION_META_KEY] = json!(5);
        let err = classify_inbound_request(&body("tools/list", json!({"_meta": m})), None).unwrap_err();
        assert_eq!(err.message, "the protocol-version envelope value must be a string");
    }

    #[test]
    fn duplicate_routing_headers() {
        assert_eq!(
            find_duplicated_routing_header([("Mcp-Method", "a"), ("accept", "x"), ("mcp-method", "a")]),
            Some("mcp-method".into())
        );
        assert_eq!(find_duplicated_routing_header([("mcp-param-x", "a"), ("mcp-param-x", "b")]), None);
    }

    #[test]
    fn x_mcp_header_annotations() {
        let ok = json!({"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"},
                        "nested": {"type": "object", "properties": {"n": {"type": "integer", "x-mcp-header": "N"}}}}});
        assert_eq!(find_invalid_x_mcp_header(&ok), None);
        let mut map = x_mcp_header_map(&ok);
        map.sort();
        assert_eq!(map, vec![(vec!["nested".to_string(), "n".to_string()], "N".to_string()), (vec!["region".to_string()], "Region".to_string())]);
        assert_eq!(
            find_invalid_x_mcp_header(&json!({"x-mcp-header": "A"})).unwrap(),
            "x-mcp-header found at a schema position not reachable via a pure `properties` chain"
        );
        assert_eq!(
            find_invalid_x_mcp_header(&json!({"properties": {"a": {"x-mcp-header": 3, "type": "string"}}})).unwrap(),
            "property 'a': x-mcp-header must be a string, not int"
        );
        assert_eq!(
            find_invalid_x_mcp_header(&json!({"properties": {"a": {"x-mcp-header": "a b", "type": "string"}}})).unwrap(),
            "property 'a': x-mcp-header 'a b' is not an RFC 9110 token"
        );
        assert_eq!(
            find_invalid_x_mcp_header(&json!({"properties": {"a": {"x-mcp-header": "A", "type": "number"}}})).unwrap(),
            "property 'a': x-mcp-header is only permitted on integer/string/boolean properties (got 'number')"
        );
        assert_eq!(
            find_invalid_x_mcp_header(&json!({"properties": {"a": {"x-mcp-header": "A"}}})).unwrap(),
            "property 'a': x-mcp-header is only permitted on integer/string/boolean properties (the type keyword is NoneType, not a string)"
        );
        let dup = find_invalid_x_mcp_header(&json!({"properties": {"a": {"x-mcp-header": "A", "type": "string"},
                                                                   "b": {"x-mcp-header": "a", "type": "string"}}}))
            .unwrap();
        assert!(dup.starts_with("x-mcp-header "), "{dup}");
        assert!(dup.contains("duplicates property"), "{dup}");
        assert!(find_invalid_x_mcp_header(&json!({"anyOf": [{"properties": {"a": {"x-mcp-header": "A", "type": "string"}}}]})).is_some());
    }

    #[test]
    fn mcp_param_header_validation() {
        let schema = json!({"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"},
                            "n": {"type": "integer", "x-mcp-header": "N"}}});
        let args = json!({"region": "eu", "n": 42}).as_object().unwrap().clone();
        let h = |pairs: &[(&str, &str)]| pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        assert_eq!(validate_mcp_param_headers(&schema, &args, &h(&[("mcp-param-region", "eu"), ("mcp-param-n", "42.0")])), None);
        assert_eq!(
            validate_mcp_param_headers(&schema, &args, &h(&[("mcp-param-n", "42")])).unwrap().message,
            "Mcp-Param-Region header is missing but the request body's 'region' argument is present"
        );
        assert_eq!(
            validate_mcp_param_headers(&schema, &args, &h(&[("mcp-param-region", "us"), ("mcp-param-n", "42")])).unwrap().message,
            "Mcp-Param-Region header does not match the request body's 'region' argument"
        );
        assert_eq!(
            validate_mcp_param_headers(&schema, &args, &h(&[("mcp-param-region", "eu"), ("mcp-param-region", "eu"), ("mcp-param-n", "42")]))
                .unwrap()
                .message,
            "Mcp-Param-Region header appears more than once"
        );
        assert_eq!(
            validate_mcp_param_headers(&schema, &args, &h(&[("mcp-param-region", "=?base64?!?="), ("mcp-param-n", "42")])).unwrap().message,
            "Mcp-Param-Region header carries a malformed base64 sentinel value"
        );
        let empty = Map::new();
        assert_eq!(
            validate_mcp_param_headers(&schema, &empty, &h(&[("mcp-param-n", "1")])).unwrap().message,
            "Mcp-Param-N header is present but the request body's 'n' argument is absent"
        );
        assert_eq!(
            mcp_param_headers(&x_mcp_header_map(&schema), &json!({"region": " eu", "n": true}).as_object().unwrap().clone()),
            vec![("Mcp-Param-N".to_string(), "true".to_string()), ("Mcp-Param-Region".to_string(), "=?base64?IGV1?=".to_string())]
        );
    }

    #[test]
    fn http_status_table() {
        assert_eq!(error_code_http_status(METHOD_NOT_FOUND), 404);
        assert_eq!(error_code_http_status(HEADER_MISMATCH), 400);
        assert_eq!(error_code_http_status(INTERNAL_ERROR), 200);
        assert_eq!(error_code_http_status(0), 200);
    }
}
