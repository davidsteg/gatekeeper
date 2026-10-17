//! Python `re` compatibility for operator-written patterns.
//!
//! Tool definitions carry `pattern:` values that were written for, and
//! tested against, Python's `re` (`re.fullmatch`). Python's engine is a
//! backtracking one; so is PCRE2, which accepts the same syntax for
//! look-around, backreferences and named groups (`(?P<n>...)`,
//! `(?P=n)`). An automaton-based engine is the wrong fit here: the shipped
//! `gmail.send` body pattern `^.{1,30000}$` compiles to ~200 MB of NFA
//! under Unicode `.`, where PCRE2 needs a few kilobytes.
//!
//! This wrapper translates the few spellings that differ and compiles in
//! UTF + UCP mode, so `\d`, `\w` and `\s` are Unicode-aware like Python's
//! `str` patterns.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use pcre2::bytes::{Regex, RegexBuilder};

/// A compiled operator pattern with `re.fullmatch` / `re.search` semantics.
#[derive(Clone)]
pub struct PyRegex {
    pub source: String,
    full: Arc<Regex>,
    search: Arc<Regex>,
}

impl std::fmt::Debug for PyRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PyRegex").field(&self.source).finish()
    }
}

impl PartialEq for PyRegex {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

/// Translates Python-only syntax to its PCRE2 spelling:
/// - `\Z` (Python: end of string only) becomes `\z` (PCRE2's `\Z` also
///   matches before a final newline);
/// - `\uXXXX` / `\UXXXXXXXX` become `\x{...}`;
/// - `{,n}` (Python: `{0,n}`) becomes `{0,n}`.
///
/// Python's `$` outside multiline mode matches at the end or before a final
/// newline, which is also PCRE2's default, so it is left alone.
fn translate(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut in_class = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            match chars.get(i + 1) {
                Some('Z') if !in_class => {
                    out.push_str("\\z");
                    i += 2;
                }
                Some(&u @ ('u' | 'U')) => {
                    let width = if u == 'u' { 4 } else { 8 };
                    let hex: String = chars.iter().skip(i + 2).take(width).collect();
                    if hex.len() == width && hex.chars().all(|h| h.is_ascii_hexdigit()) {
                        out.push_str(&format!("\\x{{{hex}}}"));
                        i += 2 + width;
                    } else {
                        out.push('\\');
                        out.push(u);
                        i += 2;
                    }
                }
                Some(&n) => {
                    out.push('\\');
                    out.push(n);
                    i += 2;
                }
                None => {
                    out.push('\\');
                    i += 1;
                }
            }
            continue;
        }
        if c == '[' && !in_class {
            in_class = true;
            out.push(c);
            // A `]` right after `[` or `[^` is a literal in both engines.
            if chars.get(i + 1) == Some(&'^') {
                out.push('^');
                i += 1;
            }
            if chars.get(i + 1) == Some(&']') {
                out.push(']');
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == ']' && in_class {
            in_class = false;
        }
        if c == '{' && !in_class && chars.get(i + 1) == Some(&',') {
            // `{,n}` -> `{0,n}` when it is a quantifier.
            let rest: String = chars[i + 2..].iter().take_while(|d| d.is_ascii_digit()).collect();
            if !rest.is_empty() && chars.get(i + 2 + rest.len()) == Some(&'}') {
                out.push_str(&format!("{{0,{rest}}}"));
                i += 3 + rest.len();
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn build(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new()
        .utf(true)
        .ucp(true)
        .jit_if_available(true)
        .build(pattern)
        .map_err(|e| e.to_string())
}

impl PyRegex {
    pub fn new(pattern: &str) -> Result<PyRegex, String> {
        // Compiled patterns are cached by source, so a catalog reload does
        // not recompile them.
        static CACHE: OnceLock<Mutex<HashMap<String, PyRegex>>> = OnceLock::new();
        let cache = CACHE.get_or_init(Default::default);
        if let Some(hit) = cache.lock().unwrap().get(pattern) {
            return Ok(hit.clone());
        }
        let t = translate(pattern);
        let search = build(&t)?;
        let full = build(&format!("^(?:{t})\\z"))?;
        let compiled =
            PyRegex { source: pattern.to_string(), full: Arc::new(full), search: Arc::new(search) };
        let mut guard = cache.lock().unwrap();
        if guard.len() > 4096 {
            guard.clear();
        }
        guard.insert(pattern.to_string(), compiled.clone());
        Ok(compiled)
    }

    /// `re.fullmatch(pattern, value) is not None`. A match-limit error
    /// counts as no match -- the value is refused, never let through.
    pub fn fullmatch(&self, value: &str) -> bool {
        self.full.is_match(value.as_bytes()).unwrap_or(false)
    }

    /// `re.search(pattern, value) is not None`.
    pub fn search(&self, value: &str) -> bool {
        self.search.is_match(value.as_bytes()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fullmatch_anchors() {
        let r = PyRegex::new("[a-z]+").unwrap();
        assert!(r.fullmatch("abc"));
        assert!(!r.fullmatch("abc\n"));
        assert!(!r.fullmatch("abc1"));
        let alt = PyRegex::new("a|ab").unwrap();
        assert!(alt.fullmatch("ab"));
        let look = PyRegex::new(r"(?!-)[a-z-]+\Z").unwrap();
        assert!(look.fullmatch("a-b"));
        assert!(!look.fullmatch("-ab"));
        let dollar = PyRegex::new("abc$").unwrap();
        assert!(!dollar.fullmatch("abc\n"));
        assert!(dollar.search("xabc\n"));
    }

    #[test]
    fn python_syntax() {
        assert!(PyRegex::new(r"(?P<x>a)(?P=x)").unwrap().fullmatch("aa"));
        assert!(PyRegex::new(r"ü+").unwrap().fullmatch("üü"));
        assert!(PyRegex::new(r"a{,2}").unwrap().fullmatch("aa"));
        assert!(!PyRegex::new(r"a{,2}").unwrap().fullmatch("aaa"));
        assert!(PyRegex::new(r"\d+").unwrap().fullmatch("١٢"));
        assert!(PyRegex::new(r"[]a]+").unwrap().fullmatch("]a"));
        assert!(PyRegex::new(r"(?<=a)b").unwrap().search("ab"));
    }

    #[test]
    fn big_bounded_repeat_is_cheap() {
        let r = PyRegex::new("^.{1,30000}$").unwrap();
        assert!(r.fullmatch(&"x".repeat(30000)));
        assert!(!r.fullmatch(&"x".repeat(30001)));
        assert!(!r.fullmatch(""));
    }
}
