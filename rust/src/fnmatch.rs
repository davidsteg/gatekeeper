//! `fnmatch.fnmatchcase` (scope patterns, protected resources).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use regex::Regex;

/// `fnmatch.translate`: `*`, `?`, `[seq]`, `[!seq]`; everything else literal.
pub fn translate(pat: &str) -> String {
    let chars: Vec<char> = pat.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut res = String::from("(?s)^");
    while i < n {
        let c = chars[i];
        i += 1;
        match c {
            '*' => {
                // Collapse runs of `*`.
                while i < n && chars[i] == '*' {
                    i += 1;
                }
                res.push_str(".*");
            }
            '?' => res.push('.'),
            '[' => {
                let mut j = i;
                if j < n && chars[j] == '!' {
                    j += 1;
                }
                if j < n && chars[j] == ']' {
                    j += 1;
                }
                while j < n && chars[j] != ']' {
                    j += 1;
                }
                if j >= n {
                    res.push_str("\\[");
                } else {
                    let mut stuff: String = chars[i..j].iter().collect();
                    i = j + 1;
                    if stuff.is_empty() {
                        // `[]` matches nothing.
                        res.push_str("(?!)");
                        continue;
                    }
                    stuff = stuff.replace('\\', "\\\\");
                    let negate = stuff.starts_with('!');
                    if negate {
                        stuff = stuff[1..].to_string();
                    }
                    // Escape set-operation characters the regex crate treats
                    // specially inside a class.
                    let stuff = stuff.replace('[', "\\[").replace("&&", "\\&\\&").replace("~~", "\\~\\~").replace("--", "\\-\\-");
                    if negate {
                        res.push_str(&format!("[^{stuff}]"));
                    } else if stuff.starts_with('^') {
                        res.push_str(&format!("[\\{stuff}]"));
                    } else {
                        res.push_str(&format!("[{stuff}]"));
                    }
                }
            }
            other => res.push_str(&regex::escape(&other.to_string())),
        }
    }
    res.push('$');
    res
}

fn compiled(pat: &str) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap();
    if guard.len() > 4096 {
        guard.clear();
    }
    guard.entry(pat.to_string()).or_insert_with(|| Regex::new(&translate(pat)).ok()).clone()
}

/// `fnmatch.fnmatchcase(name, pat)`.
pub fn fnmatchcase(name: &str, pat: &str) -> bool {
    match compiled(pat) {
        Some(re) => re.is_match(name),
        None => name == pat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_like_python() {
        assert!(fnmatchcase("docker:web", "docker:*"));
        assert!(fnmatchcase("a.b", "a?b"));
        assert!(!fnmatchcase("A", "a"));
        assert!(fnmatchcase("x1", "x[0-9]"));
        assert!(!fnmatchcase("xa", "x[0-9]"));
        assert!(fnmatchcase("xa", "x[!0-9]"));
        assert!(fnmatchcase("a\nb", "a*b"));
        assert!(fnmatchcase("[", "["));
        assert!(fnmatchcase("a+b", "a+b"));
    }
}
