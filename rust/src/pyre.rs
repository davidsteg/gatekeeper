//! Python `re` compatibility for operator-written patterns.
//!
//! Tool definitions carry `pattern:` values that were written for, and
//! tested against, Python's `re` (`re.fullmatch`). `fancy-regex` covers the
//! constructs the `regex` crate lacks (look-around, backreferences), and
//! this wrapper translates the few spellings that differ.

use std::sync::OnceLock;

use fancy_regex::Regex;

/// A compiled operator pattern with `re.fullmatch` / `re.search` semantics.
#[derive(Debug, Clone)]
pub struct PyRegex {
    pub source: String,
    full: Regex,
    translated: String,
    search: OnceLock<Option<Regex>>,
}

fn build(p: &str) -> Result<Regex, String> {
    fancy_regex::RegexBuilder::new(p)
        .delegate_size_limit(1 << 30)
        .delegate_dfa_size_limit(1 << 26)
        .build()
        .map_err(|e| e.to_string())
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
        // PORT NOTE: the default 10 MB compiled-size limit refuses patterns
        // Python compiles fine (the shipped `gmail.send` body pattern
        // `^.{1,30000}$` needs ~200 MB of NFA under Unicode `.`), so the
        // limit is raised. The `search` form is compiled on first use only,
        // so a catalog of fullmatch-only patterns pays for one automaton.
        // Compiled patterns are cached by source (clones share the
        // automaton), so a catalog reload does not recompile them.
        static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<String, PyRegex>>> =
            OnceLock::new();
        let cache = CACHE.get_or_init(Default::default);
        if let Some(hit) = cache.lock().unwrap().get(pattern) {
            return Ok(hit.clone());
        }
        let full = build(&format!("^(?:{t})\\z"))?;
        let compiled =
            PyRegex { source: pattern.to_string(), full, translated: t, search: OnceLock::new() };
        cache.lock().unwrap().insert(pattern.to_string(), compiled.clone());
        Ok(compiled)
    }

    /// `re.fullmatch(pattern, value) is not None`. A backtracking limit hit
    /// counts as no match -- the value is refused, never let through.
    pub fn fullmatch(&self, value: &str) -> bool {
        self.full.is_match(value).unwrap_or(false)
    }

    /// `re.search(pattern, value) is not None`.
    pub fn search(&self, value: &str) -> bool {
        // `full` compiled, so the unanchored form compiles too.
        let search = self.search.get_or_init(|| build(&self.translated).ok());
        search.as_ref().is_some_and(|r| r.is_match(value).unwrap_or(false))
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
