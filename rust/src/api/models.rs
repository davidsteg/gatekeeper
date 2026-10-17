//! Request models and their validation (port of the request half of
//! `api/models.py` plus what FastAPI/Pydantic do with a request).
//!
//! Response models are built in `service.rs`/`app.rs` field by field, in
//! the order the Pydantic models declare them, and name no field a secret
//! could ride in (FR-10.2, FR-11.5).
//!
//! Request bodies forbid unknown fields: a typo in a field name is an
//! error, not a silently ignored edit. A body that does not validate is a
//! 422 whose message is the first Pydantic error, formatted as `app.py`'s
//! handler formats it: `"<loc without 'body'>: <msg>"`.

use serde_json::{Map, Value};

/// One field's type and constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `str = Field(max_length=n)`.
    Str(usize),
    /// `str | None = Field(None, max_length=n)`.
    OptStr(usize),
    Bool,
    /// `int = Field(ge=.., le=..)`.
    Int(i64, i64),
    /// `list[str] = Field(max_length=n)`.
    StrList(usize),
    /// `Literal[True]`.
    LiteralTrue,
}

/// A field of a request model; `required` fields have no default, the
/// others default to their kind's natural empty value (`""`, `None`, `0`,
/// `[]`) -- the only defaults `models.py` uses.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub kind: Kind,
    pub required: bool,
}

const fn req(name: &'static str, kind: Kind) -> Field {
    Field { name, kind, required: true }
}

const fn opt(name: &'static str, kind: Kind) -> Field {
    Field { name, kind, required: false }
}

pub type Model = &'static [Field];

pub const LOGIN_REQUEST: Model = &[req("identity", Kind::Str(256)), req("password", Kind::Str(4096))];
pub const TOOL_WRITE: Model = &[req("yaml", Kind::Str(262144))];
pub const TOOL_ENABLED: Model = &[req("enabled", Kind::Bool)];
pub const IDENTITY_WRITE: Model = &[
    req("id", Kind::Str(64)),
    req("role", Kind::Str(32)),
    opt("tools", Kind::StrList(4096)),
    opt("scopes", Kind::StrList(1024)),
    opt("password", Kind::Str(4096)),
];
pub const CREDENTIAL_CREATE: Model = &[
    req("name", Kind::Str(128)),
    req("kind", Kind::Str(32)),
    opt("header", Kind::OptStr(256)),
    opt("header_format", Kind::OptStr(256)),
    req("value", Kind::Str(65536)),
    opt("probe_url", Kind::OptStr(2048)),
];
pub const CREDENTIAL_ROTATE: Model =
    &[req("value", Kind::Str(65536)), opt("overlap_seconds", Kind::Int(0, 366 * 24 * 3600))];
pub const PASSWORD_CHANGE: Model = &[req("current", Kind::Str(4096)), req("password", Kind::Str(4096))];
pub const REJECT_BODY: Model = &[opt("reason", Kind::Str(240))];
pub const CREDENTIAL_FILL: Model = &[req("value", Kind::Str(65536))];
pub const APPROVE_ALL: Model = &[req("ids", Kind::StrList(1000))];
pub const REJECT_ALL: Model = &[req("ids", Kind::StrList(1000)), opt("reason", Kind::Str(240))];
pub const DEPLOY_BODY: Model = &[req("confirm", Kind::LiteralTrue)];
pub const OAUTH_START_BODY: Model = &[opt("credential", Kind::Str(128))];

/// What FastAPI made of the request body before validation.
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    /// No body bytes at all.
    Missing,
    /// Bytes that were not parsed as JSON (no or a non-JSON content type).
    Bytes,
    Json(Value),
}

/// Why a body could not even be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// `json.JSONDecodeError` at this character position: a 422
    /// `"<pos>: JSON decode error"`.
    Decode(usize),
    /// Anything else while reading JSON (not UTF-8): a 400.
    Unreadable,
}

/// FastAPI's body reading (`strict_content_type=True`): JSON only when the
/// content type is `application/json` or `application/*+json`.
pub fn read_body(content_type: Option<&str>, bytes: &[u8]) -> Result<Body, BodyError> {
    if bytes.is_empty() {
        return Ok(Body::Missing);
    }
    let Some(content_type) = content_type.filter(|c| !c.is_empty()) else {
        return Ok(Body::Bytes);
    };
    let (main, sub) = content_type_parts(content_type);
    if main != "application" || !(sub == "json" || sub.ends_with("+json")) {
        return Ok(Body::Bytes);
    }
    parse_json(bytes).map(Body::Json)
}

/// `email.message.Message.get_content_maintype/subtype`: lowercased, and
/// `text/plain` for anything that is not `type/subtype`.
fn content_type_parts(value: &str) -> (String, String) {
    let ctype = value.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match ctype.split_once('/') {
        Some((main, sub)) if !main.is_empty() && !sub.is_empty() && !sub.contains('/') => {
            (main.trim().to_string(), sub.trim().to_string())
        }
        _ => ("text".to_string(), "plain".to_string()),
    }
}

/// `json.loads(bytes)` with Python's error positions.
pub fn parse_json(bytes: &[u8]) -> Result<Value, BodyError> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Err(BodyError::Unreadable);
    };
    let chars: Vec<char> = text.chars().collect();
    if let Err(pos) = scan_document(&chars) {
        return Err(BodyError::Decode(pos));
    }
    // PORT NOTE: Python also accepts NaN/Infinity, serde_json does not; such
    // a body is reported as undecodable at position 0.
    serde_json::from_str(text).map_err(|_| BodyError::Decode(0))
}

fn skip_ws(s: &[char], mut i: usize) -> usize {
    while i < s.len() && matches!(s[i], ' ' | '\t' | '\n' | '\r') {
        i += 1;
    }
    i
}

fn scan_document(s: &[char]) -> Result<(), usize> {
    let i = scan_value(s, skip_ws(s, 0))?;
    let i = skip_ws(s, i);
    if i != s.len() {
        return Err(i); // "Extra data"
    }
    Ok(())
}

fn starts_with(s: &[char], i: usize, word: &str) -> bool {
    let w: Vec<char> = word.chars().collect();
    s.len() >= i + w.len() && s[i..i + w.len()] == w[..]
}

fn scan_value(s: &[char], i: usize) -> Result<usize, usize> {
    if i >= s.len() {
        return Err(i);
    }
    match s[i] {
        '"' => scan_string(s, i + 1),
        '{' => scan_object(s, i + 1),
        '[' => scan_array(s, i + 1),
        'n' if starts_with(s, i, "null") => Ok(i + 4),
        't' if starts_with(s, i, "true") => Ok(i + 4),
        'f' if starts_with(s, i, "false") => Ok(i + 5),
        'N' if starts_with(s, i, "NaN") => Ok(i + 3),
        'I' if starts_with(s, i, "Infinity") => Ok(i + 8),
        '-' if starts_with(s, i, "-Infinity") => Ok(i + 9),
        _ => scan_number(s, i).ok_or(i),
    }
}

/// `-?(?:0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?` anchored at `i`.
fn scan_number(s: &[char], start: usize) -> Option<usize> {
    let digit = |i: usize| i < s.len() && s[i].is_ascii_digit();
    let mut i = start;
    if i < s.len() && s[i] == '-' {
        i += 1;
    }
    if !digit(i) {
        return None;
    }
    if s[i] == '0' {
        i += 1;
    } else {
        while digit(i) {
            i += 1;
        }
    }
    if i < s.len() && s[i] == '.' && digit(i + 1) {
        i += 1;
        while digit(i) {
            i += 1;
        }
    }
    if i < s.len() && (s[i] == 'e' || s[i] == 'E') {
        let mut j = i + 1;
        if j < s.len() && (s[j] == '+' || s[j] == '-') {
            j += 1;
        }
        if digit(j) {
            while digit(j) {
                j += 1;
            }
            i = j;
        }
    }
    Some(i)
}

fn scan_string(s: &[char], mut i: usize) -> Result<usize, usize> {
    let begin = i - 1;
    loop {
        if i >= s.len() {
            return Err(begin); // "Unterminated string starting at"
        }
        let c = s[i];
        if c == '"' {
            return Ok(i + 1);
        }
        if (c as u32) < 0x20 {
            return Err(i); // "Invalid control character at"
        }
        if c == '\\' {
            if i + 1 >= s.len() {
                return Err(begin);
            }
            let esc = s[i + 1];
            if esc == 'u' {
                if i + 6 > s.len() || !s[i + 2..i + 6].iter().all(|h| h.is_ascii_hexdigit()) {
                    return Err(i + 1); // "Invalid \uXXXX escape"
                }
                i += 6;
            } else if "\"\\/bfnrt".contains(esc) {
                i += 2;
            } else {
                return Err(i); // "Invalid \escape"
            }
            continue;
        }
        i += 1;
    }
}

fn scan_object(s: &[char], i: usize) -> Result<usize, usize> {
    let mut i = skip_ws(s, i);
    if i < s.len() && s[i] == '}' {
        return Ok(i + 1);
    }
    loop {
        if i >= s.len() || s[i] != '"' {
            return Err(i); // "Expecting property name enclosed in double quotes"
        }
        i = skip_ws(s, scan_string(s, i + 1)?);
        if i >= s.len() || s[i] != ':' {
            return Err(i); // "Expecting ':' delimiter"
        }
        i = skip_ws(s, scan_value(s, skip_ws(s, i + 1))?);
        if i < s.len() && s[i] == '}' {
            return Ok(i + 1);
        }
        if i >= s.len() || s[i] != ',' {
            return Err(i); // "Expecting ',' delimiter"
        }
        let comma = i;
        i = skip_ws(s, i + 1);
        if i < s.len() && s[i] == '}' {
            return Err(comma); // "Illegal trailing comma before end of object"
        }
    }
}

fn scan_array(s: &[char], i: usize) -> Result<usize, usize> {
    let mut i = skip_ws(s, i);
    if i < s.len() && s[i] == ']' {
        return Ok(i + 1);
    }
    loop {
        i = skip_ws(s, scan_value(s, i)?);
        if i < s.len() && s[i] == ']' {
            return Ok(i + 1);
        }
        if i >= s.len() || s[i] != ',' {
            return Err(i); // "Expecting ',' delimiter"
        }
        let comma = i;
        i = skip_ws(s, i + 1);
        if i < s.len() && s[i] == ']' {
            return Err(comma); // "Illegal trailing comma before end of array"
        }
    }
}

/// One Pydantic error: where (already joined with `.`) and the message.
fn error(loc: &str, msg: impl Into<String>) -> String {
    let msg = msg.into();
    if loc.is_empty() {
        msg
    } else {
        format!("{loc}: {msg}")
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

fn check_str(loc: &str, value: &Value, max: usize) -> Result<Value, String> {
    let Value::String(s) = value else {
        return Err(error(loc, "Input should be a valid string"));
    };
    if s.chars().count() > max {
        return Err(error(loc, format!("String should have at most {max} {}", plural(max, "character"))));
    }
    Ok(value.clone())
}

fn check_bool(loc: &str, value: &Value) -> Result<Value, String> {
    let unable = || error(loc, "Input should be a valid boolean, unable to interpret input");
    match value {
        Value::Bool(_) => Ok(value.clone()),
        Value::Number(n) => match n.as_f64() {
            Some(f) if f == 0.0 => Ok(Value::Bool(false)),
            Some(f) if f == 1.0 => Ok(Value::Bool(true)),
            _ => Err(unable()),
        },
        Value::String(s) => match s.to_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Ok(Value::Bool(false)),
            "1" | "on" | "t" | "true" | "y" | "yes" => Ok(Value::Bool(true)),
            _ => Err(unable()),
        },
        _ => Err(error(loc, "Input should be a valid boolean")),
    }
}

/// Pydantic's lax `int`: ints, bools, integral floats, integer strings.
pub fn lax_int(loc: &str, value: &Value) -> Result<i64, String> {
    match value {
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                return Ok(i);
            }
            match n.as_f64() {
                Some(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.2e18 => Ok(f as i64),
                Some(f) if f.is_finite() && f.fract() != 0.0 => {
                    Err(error(loc, "Input should be a valid integer, got a number with a fractional part"))
                }
                _ => Err(error(loc, "Input should be a valid integer")),
            }
        }
        Value::String(s) => parse_int_str(s)
            .ok_or_else(|| error(loc, "Input should be a valid integer, unable to parse string as an integer")),
        _ => Err(error(loc, "Input should be a valid integer")),
    }
}

fn parse_int_str(s: &str) -> Option<i64> {
    let t = s.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse::<i64>().ok()
}

fn check_bounds(loc: &str, n: i64, ge: i64, le: i64) -> Result<i64, String> {
    if n < ge {
        return Err(error(loc, format!("Input should be greater than or equal to {ge}")));
    }
    if n > le {
        return Err(error(loc, format!("Input should be less than or equal to {le}")));
    }
    Ok(n)
}

fn check_field(name: &str, kind: Kind, value: &Value) -> Result<Value, String> {
    match kind {
        Kind::Str(max) => check_str(name, value, max),
        Kind::OptStr(max) => {
            if value.is_null() {
                Ok(Value::Null)
            } else {
                check_str(name, value, max)
            }
        }
        Kind::Bool => check_bool(name, value),
        Kind::Int(ge, le) => Ok(Value::from(check_bounds(name, lax_int(name, value)?, ge, le)?)),
        Kind::StrList(max) => {
            let Value::Array(items) = value else {
                return Err(error(name, "Input should be a valid list"));
            };
            for (index, item) in items.iter().enumerate() {
                if index == max {
                    return Err(error(
                        name,
                        format!("List should have at most {max} {} after validation, not {}", plural(max, "item"), items.len()),
                    ));
                }
                check_str(&format!("{name}.{index}"), item, usize::MAX)?;
            }
            Ok(value.clone())
        }
        Kind::LiteralTrue => {
            let truthy = match value {
                Value::Bool(b) => *b,
                Value::Number(n) => n.as_f64() == Some(1.0),
                _ => false,
            };
            if truthy {
                Ok(Value::Bool(true))
            } else {
                Err(error(name, "Input should be True"))
            }
        }
    }
}

fn natural_default(kind: Kind) -> Value {
    match kind {
        Kind::Str(_) => Value::String(String::new()),
        Kind::OptStr(_) => Value::Null,
        Kind::Bool | Kind::LiteralTrue => Value::Bool(false),
        Kind::Int(..) => Value::from(0),
        Kind::StrList(_) => Value::Array(Vec::new()),
    }
}

/// Validates a body against a model; the validated fields (defaults
/// filled in), or the first error as `app.py` prints it.
pub fn validate(model: Model, body: &Body) -> Result<Map<String, Value>, String> {
    let object = match body {
        Body::Missing => return Err("Field required".to_string()),
        Body::Json(Value::Object(map)) => map,
        _ => return Err("Input should be a valid dictionary or object to extract fields from".to_string()),
    };
    let mut out = Map::new();
    for field in model {
        match object.get(field.name) {
            Some(value) => {
                out.insert(field.name.to_string(), check_field(field.name, field.kind, value)?);
            }
            None if field.required => return Err(error(field.name, "Field required")),
            None => {
                out.insert(field.name.to_string(), natural_default(field.kind));
            }
        }
    }
    for key in object.keys() {
        if !model.iter().any(|f| f.name == key) {
            return Err(error(key, "Extra inputs are not permitted"));
        }
    }
    Ok(out)
}

// -- Query parameters ---------------------------------------------------------

/// A query parameter's type and constraints.
#[derive(Debug, Clone, Copy)]
pub enum QKind {
    /// `str = Query(default, max_length=n, pattern=..)`.
    Str { default: &'static str, max: Option<usize>, pattern: Option<&'static str> },
    /// `str | None = Query(None, max_length=n)`.
    OptStr { max: usize },
    /// `int = Query(default, ge=.., le=..)`.
    Int { default: i64, ge: i64, le: i64 },
    /// `int | None = Query(None, ge=.., le=..)`.
    OptInt { ge: i64, le: i64 },
}

/// A query value after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QValue {
    Str(String),
    Int(i64),
    None,
}

impl QValue {
    pub fn str(&self) -> Option<&str> {
        match self {
            QValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn int(&self) -> Option<i64> {
        match self {
            QValue::Int(n) => Some(*n),
            _ => None,
        }
    }
}

/// Starlette's `QueryParams`: `parse_qsl(keep_blank_values=True)`, the
/// last value of a repeated key wins.
pub fn query_value(raw_query: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(raw_query.as_bytes())
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .last()
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    regex::Regex::new(pattern).map(|re| re.is_match(value)).unwrap_or(false)
}

/// Validates the declared query parameters, in declaration order.
pub fn validate_query(raw_query: &str, params: &[(&'static str, QKind)]) -> Result<Vec<QValue>, String> {
    let mut out = Vec::with_capacity(params.len());
    for (name, kind) in params {
        let loc = format!("query.{name}");
        let given = query_value(raw_query, name);
        let value = match (kind, given) {
            (QKind::Str { default, .. }, None) => QValue::Str(default.to_string()),
            (QKind::OptStr { .. } | QKind::OptInt { .. }, None) => QValue::None,
            (QKind::Int { default, .. }, None) => QValue::Int(*default),
            (QKind::Str { max, pattern, .. }, Some(v)) => {
                if let Some(max) = max {
                    check_str(&loc, &Value::String(v.clone()), *max)?;
                }
                if let Some(pattern) = pattern {
                    if !matches_pattern(pattern, &v) {
                        return Err(error(&loc, format!("String should match pattern '{pattern}'")));
                    }
                }
                QValue::Str(v)
            }
            (QKind::OptStr { max }, Some(v)) => {
                check_str(&loc, &Value::String(v.clone()), *max)?;
                QValue::Str(v)
            }
            (QKind::Int { ge, le, .. } | QKind::OptInt { ge, le }, Some(v)) => {
                QValue::Int(check_bounds(&loc, lax_int(&loc, &Value::String(v))?, *ge, *le)?)
            }
        };
        out.push(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decode_pos(text: &str) -> Option<usize> {
        match parse_json(text.as_bytes()) {
            Err(BodyError::Decode(pos)) => Some(pos),
            Ok(_) => None,
            Err(other) => panic!("{other:?}"),
        }
    }

    #[test]
    fn json_errors_carry_pythons_positions() {
        // Checked against `json.loads` in the reference environment.
        assert_eq!(decode_pos("not json"), Some(0));
        assert_eq!(decode_pos("{\"identity\":\"root\",\"password\":\"x\""), Some(33));
        assert_eq!(decode_pos("{\"a\":1,}"), Some(6));
        assert_eq!(decode_pos("{\"a\" 1}"), Some(5));
        assert_eq!(decode_pos("[1,]"), Some(2));
        assert_eq!(decode_pos("\"\\u12\""), Some(2));
        assert_eq!(decode_pos("\"a\u{1}\""), Some(2));
        assert_eq!(decode_pos("{\"a\": \"x"), Some(6));
        assert_eq!(decode_pos("{} x"), Some(3));
        assert_eq!(decode_pos("\"a\\qb\""), Some(2));
        assert_eq!(decode_pos(""), Some(0));
        assert_eq!(decode_pos(" {\"a\": [1, 2.5e3, -0, true, null]} "), None);
    }

    #[test]
    fn body_reading_follows_the_content_type() {
        assert_eq!(read_body(Some("application/json"), b""), Ok(Body::Missing));
        assert_eq!(read_body(None, b"{}"), Ok(Body::Bytes));
        assert_eq!(read_body(Some("text/plain"), b"{}"), Ok(Body::Bytes));
        assert_eq!(read_body(Some("application/json; charset=utf-8"), b"{}"), Ok(Body::Json(json!({}))));
        assert_eq!(read_body(Some("Application/Problem+JSON"), b"[]"), Ok(Body::Json(json!([]))));
        assert_eq!(read_body(Some("application/json"), b"\xff"), Err(BodyError::Unreadable));
    }

    #[test]
    fn validation_messages_are_pydantics() {
        let v = |model: Model, body: Value| validate(model, &Body::Json(body)).unwrap_err();
        assert_eq!(v(LOGIN_REQUEST, json!({"identity": "root"})), "password: Field required");
        assert_eq!(v(LOGIN_REQUEST, json!({"identity": 1, "password": "x", "z": 1})), "identity: Input should be a valid string");
        assert_eq!(v(LOGIN_REQUEST, json!({"identity": "a", "password": "x", "z": 1})), "z: Extra inputs are not permitted");
        assert_eq!(v(IDENTITY_WRITE, json!({"id": "a".repeat(70), "role": "agent"})), "id: String should have at most 64 characters");
        assert_eq!(v(IDENTITY_WRITE, json!({"id": "a", "role": "agent", "tools": [1]})), "tools.0: Input should be a valid string");
        assert_eq!(v(CREDENTIAL_ROTATE, json!({"value": "a", "overlap_seconds": -1})), "overlap_seconds: Input should be greater than or equal to 0");
        assert_eq!(
            v(CREDENTIAL_ROTATE, json!({"value": "a", "overlap_seconds": 1.5})),
            "overlap_seconds: Input should be a valid integer, got a number with a fractional part"
        );
        assert_eq!(v(DEPLOY_BODY, json!({})), "confirm: Field required");
        assert_eq!(v(DEPLOY_BODY, json!({"confirm": false})), "confirm: Input should be True");
        assert_eq!(v(DEPLOY_BODY, json!({"confirm": "true"})), "confirm: Input should be True");
        assert_eq!(v(TOOL_ENABLED, json!({"enabled": "maybe"})), "enabled: Input should be a valid boolean, unable to interpret input");
        assert_eq!(v(TOOL_ENABLED, json!({"enabled": null})), "enabled: Input should be a valid boolean");
        assert_eq!(v(APPROVE_ALL, json!({"ids": null})), "ids: Input should be a valid list");
        let many: Vec<String> = vec!["a".into(); 1001];
        assert_eq!(v(APPROVE_ALL, json!({"ids": many})), "ids: List should have at most 1000 items after validation, not 1001");
        assert_eq!(validate(REJECT_BODY, &Body::Missing).unwrap_err(), "Field required");
        assert_eq!(
            validate(REJECT_BODY, &Body::Json(json!([1]))).unwrap_err(),
            "Input should be a valid dictionary or object to extract fields from"
        );
        // Lax coercions Pydantic accepts.
        assert_eq!(validate(DEPLOY_BODY, &Body::Json(json!({"confirm": 1}))).unwrap()["confirm"], json!(true));
        assert_eq!(validate(TOOL_ENABLED, &Body::Json(json!({"enabled": "yes"}))).unwrap()["enabled"], json!(true));
        assert_eq!(
            validate(CREDENTIAL_ROTATE, &Body::Json(json!({"value": "a", "overlap_seconds": "5"}))).unwrap()["overlap_seconds"],
            json!(5)
        );
        let filled = validate(IDENTITY_WRITE, &Body::Json(json!({"id": "a", "role": "agent"}))).unwrap();
        assert_eq!(Value::Object(filled), json!({"id": "a", "role": "agent", "tools": [], "scopes": [], "password": ""}));
    }

    #[test]
    fn query_validation_messages() {
        let audit = [
            ("identity", QKind::Str { default: "", max: Some(256), pattern: None }),
            ("outcome", QKind::Str { default: "", max: None, pattern: Some("^(|ok|denied|failed|unknown)$") }),
            ("limit", QKind::Int { default: 100, ge: 1, le: 500 }),
            ("cursor", QKind::OptStr { max: 128 }),
        ];
        assert_eq!(validate_query("limit=0", &audit).unwrap_err(), "query.limit: Input should be greater than or equal to 1");
        assert_eq!(
            validate_query("limit=abc", &audit).unwrap_err(),
            "query.limit: Input should be a valid integer, unable to parse string as an integer"
        );
        assert_eq!(validate_query("limit=5&limit=600", &audit).unwrap_err(), "query.limit: Input should be less than or equal to 500");
        assert_eq!(
            validate_query("outcome=bogus", &audit).unwrap_err(),
            "query.outcome: String should match pattern '^(|ok|denied|failed|unknown)$'"
        );
        let ok = validate_query("outcome=denied&cursor=x", &audit).unwrap();
        assert_eq!(ok, vec![QValue::Str(String::new()), QValue::Str("denied".into()), QValue::Int(100), QValue::Str("x".into())]);
    }
}
