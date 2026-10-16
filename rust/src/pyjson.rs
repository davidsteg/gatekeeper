//! `json.dumps`-compatible serialization.
//!
//! The audit log, the agent mailbox and several tool results were written
//! by Python's `json.dumps`, whose defaults differ from serde_json's
//! compact output (`", "` / `": "` separators, `\uXXXX` escapes for
//! non-ASCII). Readers of those files -- humans with `grep`, the console,
//! the vendored CLI scripts -- see the same text from the Rust port.

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Opts {
    /// `indent=`: `None` is single-line.
    pub indent: Option<usize>,
    pub sort_keys: bool,
    pub ensure_ascii: bool,
    /// `(item_separator, key_separator)`.
    pub separators: (&'static str, &'static str),
}

impl Default for Opts {
    fn default() -> Self {
        Opts { indent: None, sort_keys: false, ensure_ascii: true, separators: (", ", ": ") }
    }
}

impl Opts {
    /// `json.dumps(x)`.
    pub fn python() -> Self {
        Opts::default()
    }
    /// `json.dumps(x, ensure_ascii=False)`.
    pub fn unicode() -> Self {
        Opts { ensure_ascii: false, ..Opts::default() }
    }
    /// `json.dumps(x, indent=n)` -- Python switches the item separator to
    /// `","` when an indent is given.
    pub fn indented(n: usize) -> Self {
        Opts { indent: Some(n), separators: (",", ": "), ..Opts::default() }
    }
    /// `json.dumps(x, separators=(",", ":"))`.
    pub fn compact() -> Self {
        Opts { separators: (",", ":"), ..Opts::default() }
    }
    pub fn sorted(mut self) -> Self {
        self.sort_keys = true;
        self
    }
    pub fn ascii(mut self, ensure_ascii: bool) -> Self {
        self.ensure_ascii = ensure_ascii;
        self
    }
}

/// `json.dumps(value)` with Python's defaults.
pub fn dumps(value: &Value) -> String {
    dumps_with(value, &Opts::default())
}

pub fn dumps_with(value: &Value, opts: &Opts) -> String {
    let mut out = String::new();
    write_value(&mut out, value, opts, 0);
    out
}

fn write_value(out: &mut String, value: &Value, opts: &Opts, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(f) = n.as_f64().filter(|_| n.is_f64()) {
                if f.is_nan() {
                    out.push_str("NaN");
                } else if f.is_infinite() {
                    out.push_str(if f > 0.0 { "Infinity" } else { "-Infinity" });
                } else {
                    out.push_str(&crate::pyfmt::float_str(f));
                }
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => write_str(out, s, opts.ensure_ascii),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(opts.separators.0);
                }
                newline(out, opts, level + 1);
                write_value(out, item, opts, level + 1);
            }
            newline(out, opts, level);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if opts.sort_keys {
                entries.sort_by(|a, b| a.0.cmp(b.0));
            }
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(opts.separators.0);
                }
                newline(out, opts, level + 1);
                write_str(out, k, opts.ensure_ascii);
                out.push_str(opts.separators.1);
                write_value(out, v, opts, level + 1);
            }
            newline(out, opts, level);
            out.push('}');
        }
    }
}

fn newline(out: &mut String, opts: &Opts, level: usize) {
    if let Some(n) = opts.indent {
        out.push('\n');
        for _ in 0..n * level {
            out.push(' ');
        }
    }
}

/// A JSON string literal the way Python's encoder writes it.
pub fn write_str(out: &mut String, s: &str, ensure_ascii: bool) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if ensure_ascii && (c as u32) > 0x7e && (c as u32) != 0x7f => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A Python-style JSON string literal on its own.
pub fn quote(s: &str) -> String {
    let mut out = String::new();
    write_str(&mut out, s, true);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_separators() {
        assert_eq!(dumps(&json!({"a": 1, "b": [1, 2]})), r#"{"a": 1, "b": [1, 2]}"#);
    }

    #[test]
    fn ascii_escapes() {
        assert_eq!(dumps(&json!("ü😀")), r#""\u00fc\ud83d\ude00""#);
        assert_eq!(dumps_with(&json!("ü"), &Opts::unicode()), "\"ü\"");
        assert_eq!(dumps(&json!("\u{7f}\u{1}")), "\"\u{7f}\\u0001\"");
    }

    #[test]
    fn indent_matches_python() {
        let v = json!({"a": [1, {"b": null}], "c": {}});
        assert_eq!(
            dumps_with(&v, &Opts::indented(2)),
            "{\n  \"a\": [\n    1,\n    {\n      \"b\": null\n    }\n  ],\n  \"c\": {}\n}"
        );
    }

    #[test]
    fn sorted_compact() {
        let v = json!({"b": 1, "a": 2.5});
        assert_eq!(dumps_with(&v, &Opts::compact().sorted()), r#"{"a":2.5,"b":1}"#);
    }
}
