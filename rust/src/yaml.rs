//! YAML in and out, with PyYAML's semantics.
//!
//! Every config file gatekeeper reads or writes was, until the Rust port,
//! read by PyYAML's `SafeLoader` and written by its `SafeDumper`. PyYAML
//! implements YAML 1.1, where `yes`/`no`/`on`/`off` are booleans and `0755`
//! is an octal integer; a YAML 1.2 parser reads those as a string and as
//! 755. Existing deployments must load to the same values, so this module
//! takes only the *event stream* from `yaml-rust2` and resolves plain
//! scalars itself, with PyYAML's resolver table.
//!
//! The emitter writes block style, keeps key order (`sort_keys=False`),
//! leaves non-ASCII text unescaped (`allow_unicode=True`) and quotes any
//! string a YAML 1.1 reader would otherwise turn into another type. Its
//! bytes are not PyYAML's bytes, but loading its output -- with this
//! module or with PyYAML -- gives back the value that was dumped.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Number, Value};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// A YAML syntax error, with PyYAML-like position text.
#[derive(Debug, Clone)]
pub struct YamlError(pub String);

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for YamlError {}

// -- Loading ---------------------------------------------------------------

enum Frame {
    Seq { anchor: usize, items: Vec<Value> },
    Map { anchor: usize, map: Map<String, Value>, key: Option<Value> },
}

#[derive(Default)]
struct Builder {
    stack: Vec<Frame>,
    anchors: HashMap<usize, Value>,
    root: Option<Value>,
    error: Option<String>,
    docs: usize,
}

impl Builder {
    fn push_value(&mut self, value: Value, anchor: usize) {
        if anchor > 0 {
            self.anchors.insert(anchor, value.clone());
        }
        match self.stack.last_mut() {
            None => {
                if self.root.is_none() {
                    self.root = Some(value);
                }
            }
            Some(Frame::Seq { items, .. }) => items.push(value),
            Some(Frame::Map { map, key, .. }) => match key.take() {
                None => *key = Some(value),
                Some(k) => {
                    map.insert(key_string(&k), value);
                }
            },
        }
    }
}

/// Python dict keys can be any hashable; JSON keys are strings. Render a
/// non-string key the way `str()` would.
fn key_string(k: &Value) -> String {
    match k {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        other => crate::pyfmt::str_value(other),
    }
}

/// Marks the scalar "<<" as the merge key. Plain `<<` resolves to the merge
/// tag in PyYAML; a quoted `'<<'` is an ordinary string key. The builder
/// distinguishes them through this sentinel.
const MERGE_SENTINEL: &str = "\u{0}<<merge>>\u{0}";

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, _mark: Marker) {
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::DocumentStart => {
                self.docs += 1;
            }
            Event::Scalar(text, style, anchor, tag) => {
                match resolve_scalar(&text, style, tag.as_ref()) {
                    Ok(v) => {
                        // Merge key handling: only a plain `<<` in key position.
                        let is_key_pos = matches!(self.stack.last(), Some(Frame::Map { key: None, .. }));
                        if is_key_pos && style == TScalarStyle::Plain && text == "<<" && tag.is_none() {
                            self.push_value(Value::String(MERGE_SENTINEL.into()), 0);
                        } else {
                            self.push_value(v, anchor)
                        }
                    }
                    Err(e) => self.error = Some(e),
                }
            }
            Event::Alias(id) => match self.anchors.get(&id) {
                Some(v) => {
                    let v = v.clone();
                    self.push_value(v, 0)
                }
                None => self.error = Some("found undefined alias".into()),
            },
            Event::SequenceStart(anchor, _) => {
                self.stack.push(Frame::Seq { anchor, items: Vec::new() });
            }
            Event::SequenceEnd => {
                if let Some(Frame::Seq { anchor, items }) = self.stack.pop() {
                    self.push_value(Value::Array(items), anchor);
                }
            }
            Event::MappingStart(anchor, _) => {
                self.stack.push(Frame::Map { anchor, map: Map::new(), key: None });
            }
            Event::MappingEnd => {
                if let Some(Frame::Map { anchor, map, .. }) = self.stack.pop() {
                    self.push_value(Value::Object(map), anchor);
                }
            }
            _ => {}
        }
    }
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

static BOOL_RE: OnceLock<Regex> = OnceLock::new();
static INT_RE: OnceLock<Regex> = OnceLock::new();
static FLOAT_RE: OnceLock<Regex> = OnceLock::new();
static NULL_RE: OnceLock<Regex> = OnceLock::new();
static TIMESTAMP_RE: OnceLock<Regex> = OnceLock::new();

fn bool_re() -> &'static Regex {
    re(&BOOL_RE, r"^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$")
}
fn int_re() -> &'static Regex {
    re(
        &INT_RE,
        r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$",
    )
}
fn float_re() -> &'static Regex {
    re(
        &FLOAT_RE,
        r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
    )
}
fn null_re() -> &'static Regex {
    re(&NULL_RE, r"^(?:~|null|Null|NULL|)$")
}
fn timestamp_re() -> &'static Regex {
    re(
        &TIMESTAMP_RE,
        r"^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$",
    )
}

/// What a plain scalar resolves to under PyYAML's implicit resolvers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Implicit {
    Bool,
    Int,
    Float,
    Null,
    Timestamp,
    Merge,
    Value,
    Str,
}

fn implicit_kind(text: &str) -> Implicit {
    // PyYAML only consults resolvers whose first character matches; the
    // regexes are anchored, so testing them all is equivalent.
    if bool_re().is_match(text) {
        Implicit::Bool
    } else if float_re().is_match(text) {
        Implicit::Float
    } else if int_re().is_match(text) {
        Implicit::Int
    } else if null_re().is_match(text) {
        Implicit::Null
    } else if timestamp_re().is_match(text) {
        Implicit::Timestamp
    } else if text == "<<" {
        Implicit::Merge
    } else if text == "=" {
        Implicit::Value
    } else {
        Implicit::Str
    }
}

fn tag_suffix(tag: Option<&Tag>) -> Option<String> {
    let tag = tag?;
    if tag.handle == "!!" || tag.handle == "tag:yaml.org,2002:" {
        Some(tag.suffix.clone())
    } else if tag.handle.is_empty() && tag.suffix.starts_with("tag:yaml.org,2002:") {
        Some(tag.suffix["tag:yaml.org,2002:".len()..].to_string())
    } else if tag.handle == "!" && tag.suffix.is_empty() {
        // The non-specific tag `!` forces a string.
        Some("str".into())
    } else {
        Some(format!("{}{}", tag.handle, tag.suffix))
    }
}

fn resolve_scalar(text: &str, style: TScalarStyle, tag: Option<&Tag>) -> Result<Value, String> {
    let kind = match tag_suffix(tag) {
        Some(s) => match s.as_str() {
            "str" => Implicit::Str,
            "int" => Implicit::Int,
            "float" => Implicit::Float,
            "bool" => Implicit::Bool,
            "null" => Implicit::Null,
            "timestamp" => Implicit::Timestamp,
            "binary" => return Ok(Value::String(text.to_string())),
            other => {
                return Err(format!(
                    "could not determine a constructor for the tag '{}'",
                    if other.starts_with('!') { other.to_string() } else { format!("tag:yaml.org,2002:{other}") }
                ))
            }
        },
        None if style == TScalarStyle::Plain => implicit_kind(text),
        None => Implicit::Str,
    };
    Ok(match kind {
        Implicit::Str | Implicit::Merge | Implicit::Value | Implicit::Timestamp => {
            Value::String(text.to_string())
        }
        Implicit::Null => Value::Null,
        Implicit::Bool => {
            let lower = text.to_ascii_lowercase();
            Value::Bool(matches!(lower.as_str(), "yes" | "true" | "on"))
        }
        Implicit::Int => construct_int(text).map_err(|_| format!("invalid int {text:?}"))?,
        Implicit::Float => construct_float(text),
    })
}

fn construct_int(text: &str) -> Result<Value, ()> {
    let cleaned: String = text.chars().filter(|c| *c != '_').collect();
    let (sign, body) = match cleaned.strip_prefix('-') {
        Some(rest) => (-1i128, rest.to_string()),
        None => (1i128, cleaned.strip_prefix('+').unwrap_or(&cleaned).to_string()),
    };
    let magnitude: i128 = if body == "0" {
        0
    } else if let Some(b) = body.strip_prefix("0b") {
        i128::from_str_radix(b, 2).map_err(|_| ())?
    } else if let Some(h) = body.strip_prefix("0x") {
        i128::from_str_radix(h, 16).map_err(|_| ())?
    } else if body.starts_with('0') {
        i128::from_str_radix(&body[1..], 8).map_err(|_| ())?
    } else if body.contains(':') {
        let mut value: i128 = 0;
        for part in body.split(':') {
            value = value * 60 + part.parse::<i128>().map_err(|_| ())?;
        }
        value
    } else {
        body.parse::<i128>().map_err(|_| ())?
    };
    let v = sign * magnitude;
    if let Ok(i) = i64::try_from(v) {
        Ok(Value::Number(i.into()))
    } else if let Ok(u) = u64::try_from(v) {
        Ok(Value::Number(u.into()))
    } else {
        Ok(Value::String(text.to_string()))
    }
}

fn construct_float(text: &str) -> Value {
    let cleaned: String = text.chars().filter(|c| *c != '_').collect::<String>().to_ascii_lowercase();
    let (sign, body) = match cleaned.strip_prefix('-') {
        Some(rest) => (-1.0, rest.to_string()),
        None => (1.0, cleaned.strip_prefix('+').unwrap_or(&cleaned).to_string()),
    };
    let f = if body == ".inf" {
        f64::INFINITY
    } else if body == ".nan" {
        f64::NAN
    } else if body.contains(':') {
        let mut value = 0.0;
        for part in body.split(':') {
            value = value * 60.0 + part.parse::<f64>().unwrap_or(0.0);
        }
        value
    } else {
        body.parse::<f64>().unwrap_or(0.0)
    };
    match Number::from_f64(sign * f) {
        Some(n) => Value::Number(n),
        // JSON has no NaN/Infinity; keep the source text.
        None => Value::String(text.to_string()),
    }
}

/// `yaml.safe_load(text)`: `Value::Null` for an empty document.
pub fn load(text: &str) -> Result<Value, YamlError> {
    let mut builder = Builder::default();
    let mut parser = Parser::new_from_str(text);
    parser.load(&mut builder, false).map_err(|e| YamlError(e.to_string()))?;
    if let Some(err) = builder.error {
        return Err(YamlError(err));
    }
    let root = builder.root.unwrap_or(Value::Null);
    Ok(strip_merge_sentinels(root))
}

/// Applies `<<` merges (recorded under the sentinel key while building):
/// merged keys come first, the mapping's own keys override them -- the
/// order PyYAML's `flatten_mapping` produces.
fn strip_merge_sentinels(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            let mut merged: Option<Map<String, Value>> = None;
            for (k, v) in map {
                if k == MERGE_SENTINEL {
                    let mut m = Map::new();
                    let sources = match v {
                        Value::Array(items) => items,
                        other => vec![other],
                    };
                    for src in sources {
                        if let Value::Object(src) = strip_merge_sentinels(src) {
                            for (sk, sv) in src {
                                m.entry(sk).or_insert(sv);
                            }
                        }
                    }
                    merged = Some(m);
                } else {
                    out.insert(k, strip_merge_sentinels(v));
                }
            }
            if let Some(m) = merged {
                let mut result = m;
                for (k, v) in out {
                    result.insert(k, v);
                }
                Value::Object(result)
            } else {
                Value::Object(out)
            }
        }
        Value::Array(items) => Value::Array(items.into_iter().map(strip_merge_sentinels).collect()),
        Value::String(s) if s == MERGE_SENTINEL => Value::String("<<".into()),
        other => other,
    }
}

// -- Dumping ---------------------------------------------------------------

/// `yaml.safe_dump(value, sort_keys=False, allow_unicode=True)`.
pub fn dump(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Object(map) if !map.is_empty() => emit_map(&mut out, map, 0),
        Value::Array(items) if !items.is_empty() => emit_seq(&mut out, items, 0),
        scalar => {
            out.push_str(&scalar_text(scalar));
            out.push('\n');
            if !matches!(scalar, Value::Object(_) | Value::Array(_)) {
                // PyYAML ends a bare scalar document with an explicit end.
                out.push_str("...\n");
            }
        }
    }
    out
}

fn indent(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push(' ');
    }
}

fn is_collection(v: &Value) -> bool {
    matches!(v, Value::Object(m) if !m.is_empty()) || matches!(v, Value::Array(a) if !a.is_empty())
}

fn emit_map(out: &mut String, map: &Map<String, Value>, level: usize) {
    let mut first = true;
    for (k, v) in map {
        if !first {
            indent(out, level);
        }
        first = false;
        out.push_str(&string_text(k, true));
        out.push(':');
        emit_child(out, v, level);
    }
}

/// Writes `value` after `key:` -- inline for scalars, on following lines for
/// collections. Sequences under a mapping key are written indentless, as
/// PyYAML does.
fn emit_child(out: &mut String, v: &Value, level: usize) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            out.push('\n');
            indent(out, level + 2);
            emit_map(out, m, level + 2);
        }
        Value::Array(items) if !items.is_empty() => {
            out.push('\n');
            indent(out, level);
            emit_seq(out, items, level);
        }
        Value::String(s) if s.contains('\n') && block_literal_ok(s) => {
            out.push(' ');
            emit_literal(out, s, level + 2);
        }
        scalar => {
            out.push(' ');
            out.push_str(&scalar_text(scalar));
            out.push('\n');
        }
    }
}

fn emit_seq(out: &mut String, items: &[Value], level: usize) {
    let mut first = true;
    for item in items {
        if !first {
            indent(out, level);
        }
        first = false;
        out.push_str("- ");
        match item {
            Value::Object(m) if !m.is_empty() => emit_map(out, m, level + 2),
            Value::Array(inner) if !inner.is_empty() => emit_seq(out, inner, level + 2),
            Value::String(s) if s.contains('\n') && block_literal_ok(s) => {
                emit_literal(out, s, level + 2)
            }
            scalar => {
                out.push_str(&scalar_text(scalar));
                out.push('\n');
            }
        }
    }
    let _ = is_collection;
}

/// A literal block keeps multi-line text readable in the file. Only used
/// when the text round-trips exactly through `|` with an explicit chomping
/// indicator: no leading space on the first line (it would be read as
/// indentation), no carriage returns or other control characters.
fn block_literal_ok(s: &str) -> bool {
    !s.starts_with(' ')
        && !s.starts_with('\n')
        && !s.chars().any(|c| (c < ' ' && c != '\n') || c == '\u{7f}' || c == '\u{feff}' || c == '\u{85}' || c == '\u{2028}' || c == '\u{2029}')
        && !s.lines().any(|l| l.ends_with(' ') || l.ends_with('\t'))
}

fn emit_literal(out: &mut String, s: &str, level: usize) {
    // Chomping: `|-` strips the final newline, `|` keeps exactly one, `|+`
    // keeps all trailing newlines.
    let trailing = s.len() - s.trim_end_matches('\n').len();
    let indicator = match trailing {
        0 => "|-",
        1 => "|",
        _ => "|+",
    };
    out.push_str(indicator);
    out.push('\n');
    let body = s.trim_end_matches('\n');
    for line in body.split('\n') {
        if !line.is_empty() {
            indent(out, level);
            out.push_str(line);
        }
        out.push('\n');
    }
    for _ in 1..trailing {
        out.push('\n');
    }
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => if *b { "true".into() } else { "false".into() },
        Value::Number(n) => {
            if n.is_f64() {
                let f = n.as_f64().unwrap_or(0.0);
                let s = crate::pyfmt::float_str(f);
                // PyYAML writes `1.0e+16`-style exponents with a dot.
                if s.contains('e') && !s.contains('.') {
                    s.replacen('e', ".0e", 1)
                } else {
                    s
                }
            } else {
                n.to_string()
            }
        }
        Value::String(s) => string_text(s, false),
        Value::Array(_) => "[]".into(),
        Value::Object(_) => "{}".into(),
    }
}

/// A string as YAML text: plain when that loads back as the same string,
/// otherwise single-quoted, or double-quoted when it has characters a
/// single-quoted scalar cannot hold.
pub fn string_text(s: &str, is_key: bool) -> String {
    if plain_ok(s, is_key) {
        return s.to_string();
    }
    if s.chars().all(|c| c >= ' ' && c != '\u{7f}' && c != '\u{85}' && c != '\u{2028}' && c != '\u{2029}' && c != '\u{feff}') {
        return format!("'{}'", s.replace('\'', "''"));
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{1b}' => out.push_str("\\e"),
            '\u{c}' => out.push_str("\\f"),
            '\u{b}' => out.push_str("\\v"),
            '\u{85}' => out.push_str("\\N"),
            '\u{a0}' => out.push_str("\\_"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            c if (c as u32) < 0x20 || c == '\u{7f}' || c == '\u{feff}' => {
                out.push_str(&format!("\\x{:02X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn plain_ok(s: &str, _is_key: bool) -> bool {
    if s.is_empty() || implicit_kind(s) != Implicit::Str {
        return false;
    }
    if s.starts_with(' ') || s.ends_with(' ') || s.starts_with('\t') || s.ends_with('\t') {
        return false;
    }
    let first = s.chars().next().unwrap();
    if "-?:,[]{}#&*!|>'\"%@`".contains(first) {
        // `-foo`, `?foo`, `:foo` are fine plain in principle, but keep it
        // simple and quote every leading indicator.
        return false;
    }
    if s.contains(": ") || s.contains(" #") || s.ends_with(':') {
        return false;
    }
    if s.contains(|c: char| {
        (c as u32) < 0x20 || c == '\u{7f}' || c == '\u{85}' || c == '\u{2028}' || c == '\u{2029}' || c == '\u{feff}' || c == '\u{a0}'
    }) {
        return false;
    }
    // Flow indicators are legal in block plain scalars, but `,[]{}` in a
    // key, or a value that a flow context reads back, invites trouble.
    if s.contains(['[', ']', '{', '}', ',']) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn yaml11_scalars() {
        let v = load("a: yes\nb: off\nc: 0755\nd: 0x1f\ne: 1_000\nf: ~\ng: 1.5\nh: '0755'\ni: 2024-01-01\nj: 1e3\nk: 1.0e+3\n").unwrap();
        assert_eq!(
            v,
            json!({"a": true, "b": false, "c": 493, "d": 31, "e": 1000, "f": null, "g": 1.5,
                   "h": "0755", "i": "2024-01-01", "j": "1e3", "k": 1000.0})
        );
    }

    #[test]
    fn order_aliases_merge() {
        let v = load("base: &b {x: 1, y: 2}\nz: 0\nm:\n  <<: *b\n  y: 3\n").unwrap();
        assert_eq!(v["m"], json!({"x": 1, "y": 3}));
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["base", "z", "m"]);
    }

    #[test]
    fn empty_is_null() {
        assert_eq!(load("").unwrap(), Value::Null);
        assert_eq!(load("# only a comment\n").unwrap(), Value::Null);
    }

    #[test]
    fn round_trip() {
        let v = json!({
            "tools": [
                {"id": "docker.ps", "enabled": true, "argv": ["/usr/bin/docker", "ps", "{name}"],
                 "s1": "yes", "s2": "0755", "s3": "a: b", "s4": "", "s5": "-x", "s6": "it's",
                 "s7": "line1\nline2\n", "s8": "tab\there", "s9": "ü", "n": null, "f": 0.25,
                 "empty_list": [], "empty_map": {}, "nested": [[1, 2], {"a": [3]}],
                 "s10": "  lead", "s11": "trail\n\n", "s12": "null", "s13": "#hash", "s14": "x #y"}
            ]
        });
        let text = dump(&v);
        assert_eq!(load(&text).unwrap(), v, "{text}");
    }

    #[test]
    fn syntax_error_is_reported() {
        assert!(load("a: [1, 2\n").is_err());
    }
}
