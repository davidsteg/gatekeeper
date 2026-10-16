//! Python `re` compatibility for operator-written patterns.
//!
//! Tool definitions carry `pattern:` values that were written for, and
//! tested against, Python's `re` (`re.fullmatch`). `fancy-regex` covers the
//! constructs the `regex` crate lacks (look-around, backreferences), and
//! this wrapper translates the few spellings that differ.

use fancy_regex::Regex;

/// A compiled operator pattern with `re.fullmatch` / `re.search` semantics.
#[derive(Debug, Clone)]
pub struct PyRegex {
    pub source: String,
    full: Regex,
    search: Regex,
}

impl PartialEq for PyRegex {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

/// Translates Python-only syntax to its fancy-regex spelling:
/// `\Z` (end of string) becomes `\z`; Python's `$` outside multiline mode
/// also matches before a final newline, which `(?:$|(?=\n\z))` would
/// emulate, but fullmatch already anchors the end, so `$` is left alone.
fn translate(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('Z') if !in_class => out.push_str("\\z"),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            }
            continue;
        }
        if c == '[' && !in_class {
            in_class = true;
        } else if c == ']' && in_class {
            in_class = false;
        }
        out.push(c);
    }
    out
}

impl PyRegex {
    pub fn new(pattern: &str) -> Result<PyRegex, String> {
        let t = translate(pattern);
        let full = Regex::new(&format!("^(?:{t})\\z")).map_err(|e| e.to_string())?;
        let search = Regex::new(&t).map_err(|e| e.to_string())?;
        Ok(PyRegex { source: pattern.to_string(), full, search })
    }

    /// `re.fullmatch(pattern, value) is not None`. A backtracking limit hit
    /// counts as no match -- the value is refused, never let through.
    pub fn fullmatch(&self, value: &str) -> bool {
        self.full.is_match(value).unwrap_or(false)
    }

    /// `re.search(pattern, value) is not None`.
    pub fn search(&self, value: &str) -> bool {
        self.search.is_match(value).unwrap_or(false)
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
    }
}
