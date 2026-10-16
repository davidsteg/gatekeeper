//! JSON-RPC 2.0 envelopes: classifying an inbound body and writing
//! outbound messages.
//!
//! The handshake-era transport validates a body against the union
//! `JSONRPCRequest | JSONRPCNotification | JSONRPCResponse | JSONRPCError`
//! and answers a failure with the text of pydantic's `ValidationError`;
//! [`parse_message`] reproduces both the classification (first member
//! that validates wins, extra keys ignored) and that text.

use serde_json::{Map, Value};

use super::types::{is_request_id, parse_python_int, ErrorData};
use crate::pyfmt;

/// One decoded JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Request { id: Value, method: String, params: Option<Map<String, Value>> },
    Notification { method: String, params: Option<Map<String, Value>> },
    Response { id: Value, result: Map<String, Value> },
    Error { id: Option<Value>, error: ErrorData },
}

struct PydErr {
    loc: String,
    msg: String,
    ty: &'static str,
    input: Value,
}

const PYDANTIC_DOCS: &str = "https://errors.pydantic.dev/2.14/v/";
const UNION_TITLE: &str = "union[JSONRPCRequest,JSONRPCNotification,JSONRPCResponse,JSONRPCError]";

fn field_missing(errs: &mut Vec<PydErr>, model: &str, field: &str, obj: &Value) {
    errs.push(PydErr { loc: format!("{model}.{field}"), msg: "Field required".into(), ty: "missing", input: obj.clone() });
}

fn check_jsonrpc(errs: &mut Vec<PydErr>, model: &str, m: &Map<String, Value>, obj: &Value) {
    match m.get("jsonrpc") {
        None => field_missing(errs, model, "jsonrpc", obj),
        Some(Value::String(s)) if s == "2.0" => {}
        Some(v) => errs.push(PydErr {
            loc: format!("{model}.jsonrpc"),
            msg: "Input should be '2.0'".into(),
            ty: "literal_error",
            input: v.clone(),
        }),
    }
}

fn check_id(errs: &mut Vec<PydErr>, model: &str, m: &Map<String, Value>, obj: &Value, nullable: bool) {
    match m.get("id") {
        None => field_missing(errs, model, "id", obj),
        Some(Value::Null) if nullable => {}
        Some(v) if is_request_id(v) => {}
        Some(v) => {
            errs.push(PydErr {
                loc: format!("{model}.id.int"),
                msg: "Input should be a valid integer".into(),
                ty: "int_type",
                input: v.clone(),
            });
            errs.push(PydErr {
                loc: format!("{model}.id.str"),
                msg: "Input should be a valid string".into(),
                ty: "string_type",
                input: v.clone(),
            });
        }
    }
}

fn check_str(errs: &mut Vec<PydErr>, loc: String, v: Option<&Value>, obj: &Value) {
    match v {
        None => errs.push(PydErr { loc, msg: "Field required".into(), ty: "missing", input: obj.clone() }),
        Some(Value::String(_)) => {}
        Some(v) => errs.push(PydErr { loc, msg: "Input should be a valid string".into(), ty: "string_type", input: v.clone() }),
    }
}

fn check_dict(errs: &mut Vec<PydErr>, loc: String, v: Option<&Value>, obj: &Value, optional: bool) {
    match v {
        None if optional => {}
        None => errs.push(PydErr { loc, msg: "Field required".into(), ty: "missing", input: obj.clone() }),
        Some(Value::Null) if optional => {}
        Some(Value::Object(_)) => {}
        Some(v) => errs.push(PydErr { loc, msg: "Input should be a valid dictionary".into(), ty: "dict_type", input: v.clone() }),
    }
}

/// pydantic's lax `int`: ints, bools, integral floats, integer strings.
fn lax_int_error(v: &Value) -> Option<(&'static str, &'static str)> {
    match v {
        Value::Bool(_) => None,
        Value::Number(n) if n.is_i64() || n.is_u64() => None,
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or(f64::NAN);
            if f.is_finite() && f.fract() == 0.0 {
                None
            } else {
                Some(("Input should be a valid integer, got a number with a fractional part", "int_from_float"))
            }
        }
        Value::String(s) => {
            if parse_python_int(s).is_some() {
                None
            } else {
                Some(("Input should be a valid integer, unable to parse string as an integer", "int_parsing"))
            }
        }
        _ => Some(("Input should be a valid integer", "int_type")),
    }
}

/// The lax-int value pydantic would store (`True` -> 1, `"12"` -> 12, `1.0` -> 1).
fn lax_int_value(v: &Value) -> i64 {
    match v {
        Value::Bool(b) => *b as i64,
        Value::Number(n) => n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64),
        Value::String(s) => parse_python_int(s).unwrap_or(0) as i64,
        _ => 0,
    }
}

fn check_error_data(errs: &mut Vec<PydErr>, m: &Map<String, Value>, obj: &Value) {
    match m.get("error") {
        None => field_missing(errs, "JSONRPCError", "error", obj),
        Some(ev @ Value::Object(e)) => {
            match e.get("code") {
                None => errs.push(PydErr {
                    loc: "JSONRPCError.error.code".into(),
                    msg: "Field required".into(),
                    ty: "missing",
                    input: ev.clone(),
                }),
                Some(code) => {
                    if let Some((msg, ty)) = lax_int_error(code) {
                        errs.push(PydErr { loc: "JSONRPCError.error.code".into(), msg: msg.into(), ty, input: code.clone() });
                    }
                }
            }
            check_str(errs, "JSONRPCError.error.message".into(), e.get("message"), ev);
        }
        Some(v) => errs.push(PydErr {
            loc: "JSONRPCError.error".into(),
            msg: "Input should be a valid dictionary or instance of ErrorData".into(),
            ty: "model_type",
            input: v.clone(),
        }),
    }
}

fn opt_params(v: Option<&Value>) -> Option<Map<String, Value>> {
    match v {
        Some(Value::Object(m)) => Some(m.clone()),
        _ => None,
    }
}

/// Classify a decoded body, or render the pydantic error text for it.
pub fn parse_message(body: &Value) -> Result<Message, String> {
    let models = ["JSONRPCRequest", "JSONRPCNotification", "JSONRPCResponse", "JSONRPCError"];
    let Value::Object(m) = body else {
        let errs: Vec<PydErr> = models
            .iter()
            .map(|model| PydErr {
                loc: (*model).to_string(),
                msg: format!("Input should be a valid dictionary or instance of {model}"),
                ty: "model_type",
                input: body.clone(),
            })
            .collect();
        return Err(render(&errs));
    };
    let mut all: Vec<PydErr> = Vec::new();

    // JSONRPCRequest
    let mut errs = Vec::new();
    check_jsonrpc(&mut errs, "JSONRPCRequest", m, body);
    check_id(&mut errs, "JSONRPCRequest", m, body, false);
    check_str(&mut errs, "JSONRPCRequest.method".into(), m.get("method"), body);
    check_dict(&mut errs, "JSONRPCRequest.params".into(), m.get("params"), body, true);
    if errs.is_empty() {
        return Ok(Message::Request {
            id: m["id"].clone(),
            method: m["method"].as_str().unwrap_or_default().to_string(),
            params: opt_params(m.get("params")),
        });
    }
    all.extend(errs);

    // JSONRPCNotification
    let mut errs = Vec::new();
    check_jsonrpc(&mut errs, "JSONRPCNotification", m, body);
    check_str(&mut errs, "JSONRPCNotification.method".into(), m.get("method"), body);
    check_dict(&mut errs, "JSONRPCNotification.params".into(), m.get("params"), body, true);
    if errs.is_empty() {
        return Ok(Message::Notification {
            method: m["method"].as_str().unwrap_or_default().to_string(),
            params: opt_params(m.get("params")),
        });
    }
    all.extend(errs);

    // JSONRPCResponse
    let mut errs = Vec::new();
    check_jsonrpc(&mut errs, "JSONRPCResponse", m, body);
    check_id(&mut errs, "JSONRPCResponse", m, body, false);
    check_dict(&mut errs, "JSONRPCResponse.result".into(), m.get("result"), body, false);
    if errs.is_empty() {
        return Ok(Message::Response {
            id: m["id"].clone(),
            result: opt_params(m.get("result")).unwrap_or_default(),
        });
    }
    all.extend(errs);

    // JSONRPCError
    let mut errs = Vec::new();
    check_jsonrpc(&mut errs, "JSONRPCError", m, body);
    check_id(&mut errs, "JSONRPCError", m, body, true);
    check_error_data(&mut errs, m, body);
    if errs.is_empty() {
        let e = m["error"].as_object().cloned().unwrap_or_default();
        let id = match &m["id"] {
            Value::Null => None,
            v => Some(v.clone()),
        };
        return Ok(Message::Error {
            id,
            error: ErrorData {
                code: lax_int_value(&e["code"]),
                message: e["message"].as_str().unwrap_or_default().to_string(),
                data: e.get("data").cloned().filter(|d| !d.is_null()),
            },
        });
    }
    all.extend(errs);
    Err(render(&all))
}

/// pydantic_core's `input_value` rendering: Python `repr`, cut to
/// 25 bytes + `...` + the last 24 bytes beyond 50 bytes.
fn input_repr(v: &Value) -> String {
    let r = pyfmt::repr_value(v);
    if r.len() <= 50 {
        return r;
    }
    let mut head = 25;
    while !r.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = r.len() - 24;
    while !r.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}...{}", &r[..head], &r[tail..])
}

fn render(errs: &[PydErr]) -> String {
    let n = errs.len();
    let mut out = format!("{n} validation error{} for {UNION_TITLE}", if n == 1 { "" } else { "s" });
    for e in errs {
        out.push('\n');
        out.push_str(&e.loc);
        out.push_str(&format!(
            "\n  {} [type={}, input_value={}, input_type={}]\n    For further information visit {PYDANTIC_DOCS}{}",
            e.msg,
            e.ty,
            input_repr(&e.input),
            pyfmt::type_name(&e.input),
            e.ty
        ));
    }
    out
}

// -- Outbound -----------------------------------------------------------------

pub fn response(id: &Value, result: Value) -> Value {
    let mut m = Map::new();
    m.insert("jsonrpc".into(), Value::from("2.0"));
    m.insert("id".into(), id.clone());
    m.insert("result".into(), result);
    Value::Object(m)
}

/// A `JSONRPCError`; `id: None` writes `"id": null` in place.
pub fn error(id: Option<&Value>, error: &ErrorData) -> Value {
    let mut m = Map::new();
    m.insert("jsonrpc".into(), Value::from("2.0"));
    m.insert("id".into(), id.cloned().unwrap_or(Value::Null));
    m.insert("error".into(), error.to_value());
    Value::Object(m)
}

pub fn notification(method: &str, params: Option<Value>) -> Value {
    let mut m = Map::new();
    m.insert("jsonrpc".into(), Value::from("2.0"));
    m.insert("method".into(), Value::from(method));
    if let Some(p) = params {
        m.insert("params".into(), p);
    }
    Value::Object(m)
}

/// Handshake-era text (`model_dump_json`): compact, raw UTF-8.
pub fn legacy_text(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// 2026-07-28 text (`json.dumps(..., separators=(",", ":"))`): compact,
/// non-ASCII escaped.
pub fn modern_text(v: &Value) -> String {
    crate::pyjson::dumps_with(v, &crate::pyjson::Opts::compact())
}

/// `pydantic_core.from_json` on a request body: its error text is the
/// serde-style message both libraries share.
pub fn parse_json(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<Value>(body).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classification_follows_the_union_order() {
        assert!(matches!(parse_message(&json!({"jsonrpc": "2.0", "id": 1, "method": "m"})), Ok(Message::Request { .. })));
        // An id that is no RequestId still validates as a notification (extra keys ignored).
        assert!(matches!(
            parse_message(&json!({"jsonrpc": "2.0", "id": 1.5, "method": "m"})),
            Ok(Message::Notification { .. })
        ));
        assert!(matches!(parse_message(&json!({"jsonrpc": "2.0", "id": 1, "result": {}})), Ok(Message::Response { .. })));
        match parse_message(&json!({"jsonrpc": "2.0", "id": null, "error": {"code": "12", "message": "m"}})) {
            Ok(Message::Error { id: None, error }) => assert_eq!(error.code, 12),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn validation_text_matches_pydantic() {
        let golden: Value =
            serde_json::from_str(include_str!("../../tests/data/mcp_envelope_errors.json")).unwrap();
        for case in golden.as_array().unwrap() {
            let got = parse_message(&case["input"]).err();
            let want = case["error"].as_str().map(str::to_string);
            assert_eq!(got, want, "input {}", case["input"]);
        }
    }

    #[test]
    fn parse_errors_read_like_jiter() {
        assert_eq!(parse_json(b"").unwrap_err(), "EOF while parsing a value at line 1 column 0");
        assert_eq!(parse_json(b"{not json").unwrap_err(), "key must be a string at line 1 column 2");
        assert_eq!(parse_json(b"nope").unwrap_err(), "expected ident at line 1 column 2");
    }

    #[test]
    fn modern_text_escapes_non_ascii() {
        assert_eq!(modern_text(&json!({"a": "é"})), "{\"a\":\"\\u00e9\"}");
        assert_eq!(legacy_text(&json!({"a": "é"})), "{\"a\":\"é\"}");
    }
}
