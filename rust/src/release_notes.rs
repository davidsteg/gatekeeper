//! Where RELEASE.md is and how it splits into versions (port of
//! `release_notes.py`), plus the request/response logic of `GET /release`
//! from `server.py`, framework-independent.
//!
//! The console API hands these sections to the React console; `/release`
//! serves them to anyone who cannot open a browser -- an agent, a deploy
//! script, an operator with `curl`. Deliberately markdown in, markdown out:
//! nothing here renders HTML.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use regex::Regex;
use serde_json::{json, Value};

/// Only headings that look like a version (`## 0.4.0`, optionally with a
/// build/pre-release suffix) start a new entry -- RELEASE.md's own
/// `## Procedure` / `## Versioning` headings stay preamble.
pub const HEADING_RE: &str = r"(?m)^## (\d+\.\d+\.\d+\S*)[ \t]*\n";

/// Where the container image bakes RELEASE.md in.
pub const IMAGE_NOTES_PATH: &str = "/usr/share/gatekeeper/RELEASE.md";

/// One `## <version>` section: (version, markdown body).
pub type Section = (String, String);

fn heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(HEADING_RE).expect("HEADING_RE"))
}

/// Cached per process: the file is small and read-only at runtime.
static CACHE: Mutex<Option<Arc<Vec<Section>>>> = Mutex::new(None);

/// Drops the cached sections (Python tests reset `_cache`).
pub fn clear_cache() {
    *CACHE.lock() = None;
}

fn is_file(path: &Path) -> bool {
    path.is_file()
}

fn walk_up(start: &Path) -> Option<String> {
    let mut here = start.to_path_buf();
    for _ in 0..6 {
        let candidate = here.join("RELEASE.md");
        if is_file(&candidate) {
            return Some(candidate.to_string_lossy().into_owned());
        }
        match here.parent() {
            Some(parent) if parent != here => here = parent.to_path_buf(),
            _ => break,
        }
    }
    None
}

/// Where RELEASE.md lives, checked in order:
///
/// 1. `GATEKEEPER_RELEASE_NOTES` -- what the container image sets.
/// 2. Walking up (at most six levels) from the running executable's
///    directory, then from this crate's source directory -- a dev checkout
///    has the real `RELEASE.md` next to `pyproject.toml`.
/// 3. `/usr/share/gatekeeper/RELEASE.md`, where the image bakes it in.
///
/// Returns `None` if none exists -- callers say so plainly (`/release`
/// answers 503) instead of failing.
// PORT NOTE: Python walked up from the module file (`__file__`). A binary has
// no such file, so the walk starts at the executable and at the crate
// directory recorded at build time; the image path is checked last even
// without the env var.
pub fn notes_path() -> Option<String> {
    if let Ok(over) = std::env::var("GATEKEEPER_RELEASE_NOTES") {
        if !over.is_empty() && is_file(Path::new(&over)) {
            return Some(over);
        }
    }
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            starts.push(dir.to_path_buf());
        }
    }
    starts.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    for start in starts {
        if let Some(found) = walk_up(&start) {
            return Some(found);
        }
    }
    if is_file(Path::new(IMAGE_NOTES_PATH)) {
        return Some(IMAGE_NOTES_PATH.to_string());
    }
    None
}

/// Python's `str.isspace` for one character.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// Splits on `## <version>` headings -- the format RELEASE.md's procedure
/// section mandates and the release workflow's CI check parses. Bodies are
/// the raw markdown between two headings, stripped. A duplicate version
/// heading is kept as its own entry, never merged.
pub fn parse_sections(text: &str) -> Vec<Section> {
    let re = heading_re();
    let mut sections = Vec::new();
    let mut current: Option<(String, usize)> = None;
    for caps in re.captures_iter(text) {
        let whole = caps.get(0).unwrap();
        if let Some((version, start)) = current.take() {
            sections.push((version, text[start..whole.start()].trim_matches(py_space).to_string()));
        }
        current = Some((caps[1].to_string(), whole.end()));
    }
    if let Some((version, start)) = current {
        sections.push((version, text[start..].trim_matches(py_space).to_string()));
    }
    sections
}

fn read_text(path: &str) -> String {
    // Python: open(path, encoding="utf-8").read(), OSError -> "".
    // PORT NOTE: a UnicodeDecodeError raised in Python; invalid UTF-8 is
    // decoded lossily here instead.
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    }
}

/// Sections of the file at `path` (`None` -> none), uncached.
pub fn load_from(path: Option<&str>) -> Vec<Section> {
    let text = path.map(read_text).unwrap_or_default();
    parse_sections(&text)
}

/// All sections, newest first (RELEASE.md's own order), as markdown.
pub fn load() -> Arc<Vec<Section>> {
    let mut cache = CACHE.lock();
    if let Some(sections) = cache.as_ref() {
        return sections.clone();
    }
    let sections = Arc::new(load_from(notes_path().as_deref()));
    *cache = Some(sections.clone());
    sections
}

/// The whole file at `path` verbatim; empty if there is none.
pub fn read_full_from(path: Option<&str>) -> String {
    path.map(read_text).unwrap_or_default()
}

/// The whole file verbatim, preamble included -- empty if there is none.
/// The preamble (release rule, procedure, versioning) is what an agent
/// managing this deployment needs to propose a release correctly.
pub fn read_full() -> String {
    read_full_from(notes_path().as_deref())
}

/// `query` over explicit sections.
pub fn query_sections(
    sections: &[Section],
    version: Option<&str>,
    search: Option<&str>,
    limit: Option<i64>,
) -> (Vec<Value>, usize) {
    let mut selected: Vec<&Section> = sections.iter().collect();
    if let Some(version) = version.filter(|v| !v.is_empty()) {
        selected.retain(|(v, _)| v == version);
    }
    if let Some(search) = search.filter(|s| !s.is_empty()) {
        let needle = search.to_lowercase();
        selected.retain(|(v, body)| v.to_lowercase().contains(&needle) || body.to_lowercase().contains(&needle));
    }
    let total = selected.len();
    if let Some(limit) = limit {
        if limit >= 0 {
            selected.truncate(limit as usize);
        }
    }
    (selected.into_iter().map(|(v, body)| json!({"version": v, "notes": body})).collect(), total)
}

/// Sections as `{"version", "notes"}` objects plus the pre-limit total.
///
/// `version` selects one exact heading, `search` keeps sections whose
/// heading or body contains the term (case-insensitive), `limit` cuts the
/// list to the newest N. Filters compose; the total counts matches before
/// `limit`.
pub fn query(version: Option<&str>, search: Option<&str>, limit: Option<i64>) -> (Vec<Value>, usize) {
    query_sections(&load(), version, search, limit)
}

// -- GET /release (server.py) -----------------------------------------------

/// A framework-independent HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

pub const JSON: &str = "application/json";
pub const PLAIN_TEXT: &str = "text/plain; charset=utf-8";
pub const MARKDOWN: &str = "text/markdown; charset=utf-8";

/// Starlette's `JSONResponse` body: compact separators, no ASCII escaping.
pub fn json_body(value: &Value) -> String {
    crate::pyjson::dumps_with(value, &crate::pyjson::Opts::compact().ascii(false))
}

fn json_response(status: u16, value: Value) -> HttpResponse {
    HttpResponse { status, content_type: JSON.into(), body: json_body(&value) }
}

/// 503, not 404: the route exists and the build simply shipped without
/// RELEASE.md. A 404 would read as "no such endpoint".
fn no_release_notes(wants_markdown: bool) -> HttpResponse {
    let message = "Release notes are not available in this build -- RELEASE.md was not \
                   found. Set GATEKEEPER_RELEASE_NOTES to its path, or use the \
                   container image, which ships it at /usr/share/gatekeeper/RELEASE.md.";
    if wants_markdown {
        return HttpResponse { status: 503, content_type: PLAIN_TEXT.into(), body: message.into() };
    }
    json_response(503, json!({"error": message}))
}

/// `params.get(key)`: the last value for a repeated key, like Starlette's
/// `QueryParams`.
fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Python's `int(text)` for a decimal string: surrounding whitespace, an
/// optional sign, and single underscores between digits are accepted.
/// Values beyond `i64` saturate (only the sign matters to the caller).
// PORT NOTE: non-ASCII Unicode digits, which Python's int() also accepts,
// are refused here.
pub fn py_int(text: &str) -> Option<i64> {
    let s = text.trim_matches(py_space);
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut value: i64 = 0;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(10)? as i64;
        value = value.saturating_mul(10).saturating_add(d);
    }
    Some(if neg { -value } else { value })
}

/// `GET /release` over explicit sources: `sections` is what `load()`
/// returns, `read_full` produces the whole file for `?full=1`.
pub fn release_response_with(
    params: &[(String, String)],
    sections: &[Section],
    read_full: impl FnOnce() -> String,
) -> HttpResponse {
    let wants_markdown = matches!(
        param(params, "format").unwrap_or("").to_lowercase().as_str(),
        "markdown" | "md" | "text"
    );
    if matches!(param(params, "full"), Some("1" | "true" | "yes")) {
        let text = read_full();
        if text.is_empty() {
            return no_release_notes(wants_markdown);
        }
        if wants_markdown {
            return HttpResponse { status: 200, content_type: MARKDOWN.into(), body: text };
        }
        return json_response(200, json!({"version": crate::VERSION, "markdown": text}));
    }

    let limit_raw = param(params, "limit");
    let limit = match limit_raw {
        None => None,
        Some(raw) => match py_int(raw) {
            Some(n) => Some(n),
            // A caller who asks for "limit=abc" gets told so, rather than
            // silently receiving the default.
            None => {
                return json_response(
                    400,
                    json!({"error": format!("limit must be an integer, not {}", crate::pyfmt::repr_str(raw))}),
                )
            }
        },
    };
    if matches!(limit, Some(n) if n < 1) {
        return json_response(400, json!({"error": "limit must be at least 1"}));
    }

    let version = param(params, "version").filter(|v| !v.is_empty());
    let search = param(params, "search").filter(|v| !v.is_empty());
    let (releases, total) = query_sections(sections, version, search, limit);
    if releases.is_empty() && sections.is_empty() {
        return no_release_notes(wants_markdown);
    }
    if let Some(version) = version {
        if releases.is_empty() {
            return json_response(
                404,
                json!({"error": format!("No release notes for version {}.", crate::pyfmt::repr_str(version))}),
            );
        }
    }
    if wants_markdown {
        let body = releases
            .iter()
            .map(|r| format!("## {}\n\n{}", r["version"].as_str().unwrap_or(""), r["notes"].as_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n\n");
        return HttpResponse { status: 200, content_type: MARKDOWN.into(), body };
    }
    let count = releases.len();
    json_response(
        200,
        json!({"version": crate::VERSION, "releases": releases, "count": count, "total": total}),
    )
}

/// `GET /release`: `?version=` selects one section, `?search=` filters,
/// `?limit=` caps the list, `?format=markdown` returns text, `?full=1` the
/// whole file verbatim. `params` are the decoded query pairs, in order
/// (blank values kept). Authentication is the HTTP layer's job: this route
/// is deliberately not public.
pub fn release_response(params: &[(String, String)]) -> HttpResponse {
    release_response_with(params, &load(), read_full)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(sections: &[Section]) -> Vec<&str> {
        sections.iter().map(|(v, _)| v.as_str()).collect()
    }

    fn p(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn body(r: &HttpResponse) -> Value {
        serde_json::from_str(&r.body).unwrap()
    }

    fn real() -> (Arc<Vec<Section>>, String) {
        (load(), read_full())
    }

    fn get(params: &[(&str, &str)]) -> HttpResponse {
        let (sections, full) = real();
        release_response_with(&p(params), &sections, || full)
    }

    /// The newest section of the real RELEASE.md. PORT NOTE: Python compared
    /// against `__version__`; the Rust crate's version is set independently
    /// of RELEASE.md during the port, so the tests use the newest heading.
    fn newest() -> String {
        load()[0].0.clone()
    }

    #[test]
    fn release_notes_path_finds_the_real_file() {
        let path = notes_path().unwrap();
        assert!(path.ends_with("RELEASE.md"));
    }

    #[test]
    fn parses_versions_in_order() {
        let text = "# Releases\n\nsome preamble\n\n\
                    ## 0.2.0\n\n**Bold summary.**\n\n- item one\n- item two\n\n\
                    ## 0.1.0\n\nOlder notes with `inline code`.\n";
        assert_eq!(versions(&parse_sections(text)), ["0.2.0", "0.1.0"]);
    }

    #[test]
    fn bodies_stay_markdown() {
        let text = "## 1.0.0\n\n**Bold** and `code` here.\n\n- first\n- second\n";
        let sections = parse_sections(text);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].1, "**Bold** and `code` here.\n\n- first\n- second");
        assert!(!sections[0].1.contains('<'));
    }

    #[test]
    fn non_version_headings_in_preamble_are_not_treated_as_releases() {
        let text = "# Releases\n\n## The rule: every change is a release\n\ntext\n\n\
                    ## Procedure\n\ntext\n\n## Versioning\n\ntext\n\n\
                    ## 0.2.0\n\nreal notes\n\n## 0.1.0\n\nolder notes\n";
        assert_eq!(versions(&parse_sections(text)), ["0.2.0", "0.1.0"]);
    }

    #[test]
    fn duplicate_version_heading_is_not_silently_merged() {
        let sections = parse_sections("## 0.3.1\n\nfirst entry\n\n## 0.3.1\n\nsecond entry\n");
        assert_eq!(sections.len(), 2);
        assert!(sections[0].1.contains("first entry"));
        assert!(sections[1].1.contains("second entry"));
    }

    #[test]
    fn empty_text_yields_no_sections() {
        assert!(parse_sections("").is_empty());
        assert!(parse_sections("# Releases\n\njust a preamble, no headings\n").is_empty());
    }

    #[test]
    fn heading_suffix_and_trailing_blanks() {
        let sections = parse_sections("## 1.0.0-rc1 \t\nbody\n## 1.0.0\n");
        assert_eq!(versions(&sections), ["1.0.0-rc1", "1.0.0"]);
        assert_eq!(sections[0].1, "body");
        assert_eq!(sections[1].1, "");
    }

    #[test]
    fn real_release_md_parses_and_includes_the_pyproject_version() {
        let sections = load();
        assert!(!sections.is_empty());
        let pyproject = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../pyproject.toml")).unwrap();
        let line = pyproject.lines().find(|l| l.starts_with("version = ")).unwrap();
        let version = line.trim_start_matches("version = ").trim_matches('"');
        assert!(versions(&sections).contains(&version));
    }

    #[test]
    fn missing_file_yields_no_sections() {
        assert!(load_from(None).is_empty());
        assert_eq!(read_full_from(None), "");
    }

    #[test]
    fn release_returns_versions_newest_first() {
        let r = get(&[]);
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, JSON);
        let b = body(&r);
        assert_eq!(b["version"], crate::VERSION);
        assert_eq!(b["releases"][0]["version"], newest());
        assert!(b["total"].as_u64().unwrap() >= b["count"].as_u64().unwrap());
    }

    #[test]
    fn version_selects_one_section_and_unknown_is_404() {
        let v = newest();
        let b = body(&get(&[("version", &v)]));
        let got: Vec<&str> = b["releases"].as_array().unwrap().iter().map(|r| r["version"].as_str().unwrap()).collect();
        assert_eq!(got, [v.as_str()]);
        let missing = get(&[("version", "99.99.99")]);
        assert_eq!(missing.status, 404);
        assert_eq!(missing.body, r#"{"error":"No release notes for version '99.99.99'."}"#);
    }

    #[test]
    fn search_filters_and_reports_the_pre_limit_total() {
        let b = body(&get(&[("search", "credential"), ("limit", "2")]));
        assert_eq!(b["count"], 2);
        assert!(b["total"].as_u64().unwrap() > 2);
        for r in b["releases"].as_array().unwrap() {
            assert!(
                r["notes"].as_str().unwrap().to_lowercase().contains("credential")
                    || r["version"].as_str().unwrap().contains("credential")
            );
        }
    }

    #[test]
    fn search_is_case_insensitive() {
        assert_eq!(body(&get(&[("search", "credential")]))["total"], body(&get(&[("search", "CREDENTIAL")]))["total"]);
    }

    #[test]
    fn a_bad_limit_is_refused_not_silently_defaulted() {
        let r = get(&[("limit", "abc")]);
        assert_eq!(r.status, 400);
        assert_eq!(r.body, r#"{"error":"limit must be an integer, not 'abc'"}"#);
        let r = get(&[("limit", "0")]);
        assert_eq!(r.status, 400);
        assert_eq!(r.body, r#"{"error":"limit must be at least 1"}"#);
        assert_eq!(get(&[("limit", "")]).status, 400);
        assert_eq!(get(&[("limit", " 1_0 ")]).status, 200);
    }

    #[test]
    fn markdown_format_returns_text_with_headings() {
        let r = get(&[("format", "markdown"), ("limit", "1")]);
        assert!(r.content_type.starts_with("text/markdown"));
        assert!(r.body.starts_with(&format!("## {}", newest())));
    }

    #[test]
    fn full_returns_the_whole_file_including_the_preamble() {
        let r = get(&[("full", "1")]);
        let markdown = body(&r)["markdown"].as_str().unwrap().to_string();
        assert!(markdown.contains("## Procedure"));
        assert!(markdown.contains("# Releases"));
        let text = get(&[("full", "1"), ("format", "markdown")]);
        assert_eq!(text.body, markdown);
        assert_eq!(text.content_type, MARKDOWN);
    }

    #[test]
    fn missing_release_md_is_503_with_a_reason() {
        let r = release_response_with(&[], &[], String::new);
        assert_eq!(r.status, 503);
        assert!(body(&r)["error"].as_str().unwrap().contains("RELEASE.md"));
        let full = release_response_with(&p(&[("full", "1")]), &[], String::new);
        assert_eq!(full.status, 503);
        let md = release_response_with(&p(&[("format", "MD")]), &[], String::new);
        assert_eq!((md.status, md.content_type.as_str()), (503, PLAIN_TEXT));
    }

    #[test]
    fn py_int_matches_python() {
        assert_eq!(py_int("5"), Some(5));
        assert_eq!(py_int(" -3\n"), Some(-3));
        assert_eq!(py_int("+1_000"), Some(1000));
        assert_eq!(py_int("1__0"), None);
        assert_eq!(py_int("_1"), None);
        assert_eq!(py_int("1.0"), None);
        assert_eq!(py_int(""), None);
    }
}
