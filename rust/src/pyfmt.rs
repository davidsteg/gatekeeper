//! Python-compatible text formatting.
//!
//! Error messages, audit lines and API answers were produced by Python's
//! `repr()`, `str()` and `json.dumps()`. Operators grep logs for them and
//! clients parse them, so the Rust port renders them the same way. This
//! module is the single place that knows how.

use serde_json::Value;

/// Python's `repr()` of a `str`.
pub fn repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if is_printable(c) => out.push(c),
            c => {
                let code = c as u32;
                if code < 0x100 {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code < 0x10000 {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}

/// Approximation of Python's `str.isprintable()` for one character:
/// control characters, separators other than the ASCII space, and
/// unassigned/format code points are not printable.
fn is_printable(c: char) -> bool {
    let code = c as u32;
    if code < 0x20 || (0x7f..0xa0).contains(&code) {
        return false;
    }
    if c == ' ' {
        return true;
    }
    // Zs/Zl/Zp other than space, and common Cf format characters.
    if matches!(
        code,
        0xa0 | 0xad | 0x1680 | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x2064
            | 0x2066..=0x206f | 0x3000 | 0xfeff | 0xfff9..=0xfffb
    ) {
        return false;
    }
    // Surrogates cannot occur in a Rust `char`; private use and noncharacters
    // are treated as not printable, like Python.
    if (0xe000..=0xf8ff).contains(&code) || (code & 0xfffe) == 0xfffe {
        return false;
    }
    true
}

/// Python's `repr()` of a list of strings: `['a', 'b']`.
pub fn repr_list<S: AsRef<str>>(items: &[S]) -> String {
    let inner: Vec<String> = items.iter().map(|s| repr_str(s.as_ref())).collect();
    format!("[{}]", inner.join(", "))
}

/// Python's `repr()` of a sorted list of strings.
pub fn repr_sorted<I, S>(items: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut v: Vec<String> = items.into_iter().map(|s| s.as_ref().to_string()).collect();
    v.sort();
    repr_list(&v)
}

/// Python's `repr()` of a JSON-shaped value (dict/list/str/int/float/bool/None).
pub fn repr_value(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => number_str(n),
        Value::String(s) => repr_str(s),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(repr_value).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> =
                map.iter().map(|(k, v)| format!("{}: {}", repr_str(k), repr_value(v))).collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Python's `str()` of a JSON-shaped value: strings bare, the rest as `repr`.
pub fn str_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => repr_value(other),
    }
}

/// Python's `type(x).__name__` for a JSON-shaped value.
pub fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Python's `repr(float)`/`str(float)`: shortest round-trip, with an
/// exponent below 1e-4 and from 1e16 on, written `1e+16` / `1e-05`.
pub fn float_str(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let s = format!("{f:?}");
    if let Some(pos) = s.find('e') {
        let (mantissa, exp) = s.split_at(pos);
        let exp = &exp[1..];
        let (sign, digits) = match exp.strip_prefix('-') {
            Some(d) => ('-', d),
            None => ('+', exp),
        };
        let mantissa = mantissa.strip_suffix(".0").unwrap_or(mantissa);
        return format!("{mantissa}e{sign}{digits:0>2}");
    }
    s
}

pub fn number_str(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        float_str(n.as_f64().unwrap_or(0.0))
    }
}

/// Python's `str(OSError)`: `[Errno 2] No such file or directory: 'path'`.
pub fn os_error(err: &std::io::Error, path: &str) -> String {
    match err.raw_os_error() {
        Some(code) => {
            // SAFETY: strerror returns a pointer to a static string.
            let msg = unsafe {
                std::ffi::CStr::from_ptr(libc::strerror(code)).to_string_lossy().into_owned()
            };
            if path.is_empty() {
                format!("[Errno {code}] {msg}")
            } else {
                format!("[Errno {code}] {msg}: {}", repr_str(path))
            }
        }
        None => err.to_string(),
    }
}

/// `" or ".join(...)`-style helper used by several messages.
pub fn join<S: AsRef<str>>(items: &[S], sep: &str) -> String {
    items.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(sep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn repr_matches_python() {
        assert_eq!(repr_str("abc"), "'abc'");
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(repr_str("a\nb\x01"), "'a\\nb\\x01'");
        assert_eq!(repr_str("ü"), "'ü'");
        assert_eq!(repr_list(&["a", "b"]), "['a', 'b']");
        assert_eq!(repr_value(&json!({"a": [1, true, null]})), "{'a': [1, True, None]}");
    }

    #[test]
    fn floats_match_python() {
        assert_eq!(float_str(1.0), "1.0");
        assert_eq!(float_str(0.5), "0.5");
        assert_eq!(float_str(1e16), "1e+16");
        assert_eq!(float_str(1.5e16), "1.5e+16");
        assert_eq!(float_str(1e-5), "1e-05");
        assert_eq!(float_str(123456.789), "123456.789");
        assert_eq!(float_str(1e15), "1000000000000000.0");
    }
}
