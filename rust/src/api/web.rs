//! Serves the React console's static build at `/app` (port of
//! `api/web.py`).
//!
//! The build (`frontend/dist`, produced by `npm run build`) is found
//! through `GATEKEEPER_WEB_DIR`, else the checkout this binary was built
//! from. What the routes guarantee:
//!
//! * **CSP on every `/app` response** ([`APP_CSP`]): scripts and styles only
//!   from this origin, no inline script, no eval, Trusted Types enforced
//!   for script sinks, nothing framed, no third-party anything (FR-11.9).
//! * **Caching by content.** Hashed files under `/app/assets/` are
//!   `immutable`; `index.html` is `no-store`.
//! * **SPA fallback.** Any other `/app/...` path without a file behind it
//!   answers `index.html`. A missing file under `/app/assets/` stays a 404.
//! * **No data.** These are public bytes; everything the page shows comes
//!   from `/api/v1` behind a session.

use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use axum::body::Body;
use axum::response::Response;
use http::{HeaderName, HeaderValue, StatusCode};

use crate::pathutil::realpath;

pub const APP_PREFIX: &str = "/app";

pub const APP_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
img-src 'self' data:; font-src 'self'; manifest-src 'self'; worker-src 'self'; \
form-action 'self'; frame-ancestors 'none'; base-uri 'none'; \
require-trusted-types-for 'script'";

const HEADERS: [(&str, &str); 5] = [
    ("content-security-policy", APP_CSP),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
];

pub const WEB_DIR_ENV: &str = "GATEKEEPER_WEB_DIR";

/// GZip only from this size on (Starlette's `minimum_size=500`).
const GZIP_MINIMUM_SIZE: usize = 500;

/// Where the build is looked for.
#[derive(Debug, Clone, Default)]
pub enum WebDir {
    /// [`web_dir`], re-checked on every request.
    #[default]
    Auto,
    /// A fixed directory, or `None` for "not built" (tests).
    Fixed(Option<String>),
}

impl WebDir {
    pub fn resolve(&self) -> Option<String> {
        match self {
            WebDir::Auto => web_dir(),
            WebDir::Fixed(dir) => dir.clone().filter(|d| Path::new(d).join("index.html").is_file()),
        }
    }
}

/// The first directory holding a built `index.html`, or `None`.
///
/// PORT NOTE: Python's middle candidate was `gatekeeper/_web` inside the
/// installed package; the binary has no package directory, so it checks
/// that path in the checkout it was built from, then `frontend/dist`. A
/// container image sets `GATEKEEPER_WEB_DIR`.
pub fn web_dir() -> Option<String> {
    let repo = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let candidates = [
        std::env::var(WEB_DIR_ENV).unwrap_or_default(),
        format!("{repo}/src/gatekeeper/_web"),
        format!("{repo}/frontend/dist"),
    ];
    candidates.into_iter().find(|base| !base.is_empty() && Path::new(base).join("index.html").is_file())
}

/// `rel` inside `base`, or `None` for anything that escapes it.
fn resolve(base: &str, rel: &str) -> Option<String> {
    let root = realpath(base);
    // os.path.join: an absolute `rel` replaces the root.
    let joined = if rel.starts_with('/') { rel.to_string() } else { format!("{}/{rel}", root.trim_end_matches('/')) };
    let target = realpath(&joined);
    if target != root && !target.starts_with(&format!("{}/", root.trim_end_matches('/'))) {
        return None;
    }
    Path::new(&target).is_file().then_some(target)
}

/// `mimetypes.guess_type` for what a Vite build contains.
fn guess_type(path: &str) -> Option<&'static str> {
    let ext = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "html" | "htm" => "text/html",
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "svg" => "image/svg+xml",
        "webmanifest" => "application/manifest+json",
        "json" => "application/json",
        "png" => "image/png",
        "ico" => "image/vnd.microsoft.icon",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" => "text/plain",
        "wasm" => "application/wasm",
        "xml" => "text/xml",
        _ => return None,
    })
}

/// Starlette's `Response.init_headers`: `text/*` gets a charset.
fn content_type(media: &str) -> String {
    if media.starts_with("text/") && !media.contains("charset=") {
        format!("{media}; charset=utf-8")
    } else {
        media.to_string()
    }
}

const GZIP_EXCLUDED: [&str; 14] = [
    "application/grpc",
    "application/gzip",
    "application/x-gzip",
    "application/zip",
    "audio/*",
    "font/woff",
    "font/woff2",
    "image/avif",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
    "text/event-stream",
    "video/*",
];

/// A finished response before GZip.
struct Plain {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn with_headers(cache: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = HEADERS.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    out.push(("cache-control".into(), cache.into()));
    out
}

fn text(status: u16, body: &str, cache: &str) -> Plain {
    let mut headers = with_headers(cache);
    headers.push(("content-type".into(), "text/plain; charset=utf-8".into()));
    Plain { status, headers, body: body.as_bytes().to_vec() }
}

fn file(path: &str, media: &str, cache: &str) -> Plain {
    let Ok(body) = std::fs::read(path) else {
        return Plain { status: 500, headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())], body: b"Internal Server Error".to_vec() };
    };
    let mut headers = with_headers(cache);
    headers.push(("content-type".into(), content_type(media)));
    if let Ok(meta) = std::fs::metadata(path) {
        let mtime = meta.mtime() as f64 + meta.mtime_nsec() as f64 * 1e-9;
        if let Ok(modified) = meta.modified() {
            headers.push(("last-modified".into(), httpdate::fmt_http_date(modified)));
        }
        let base = format!("{}-{}", crate::pyfmt::float_str(mtime), meta.len());
        headers.push(("etag".into(), format!("\"{:x}\"", md5::compute(base.as_bytes()))));
    }
    // PORT NOTE: Starlette's FileResponse also answers `Range` requests; this
    // port always sends the whole file (200) and so advertises no
    // `Accept-Ranges`.
    Plain { status: 200, headers, body }
}

fn redirect(location: &str) -> Plain {
    Plain { status: 308, headers: vec![("location".into(), location.into())], body: Vec::new() }
}

fn method_not_allowed() -> Plain {
    Plain {
        status: 405,
        headers: vec![("allow".into(), "GET, HEAD".into()), ("content-type".into(), "text/plain; charset=utf-8".into())],
        body: b"Method Not Allowed".to_vec(),
    }
}

/// Serves `/app` and `/app/...`. `path` is the percent-decoded request
/// path.
pub fn handle(method: &str, path: &str, accept_encoding: &str, dir: &WebDir) -> Response {
    let get_or_head = method == "GET" || method == "HEAD";
    let plain = if path == APP_PREFIX {
        if get_or_head {
            redirect(&format!("{APP_PREFIX}/"))
        } else {
            method_not_allowed()
        }
    } else if !get_or_head {
        method_not_allowed()
    } else {
        serve(path.strip_prefix("/app/").unwrap_or(""), dir)
    };
    finish(plain, accept_encoding)
}

fn serve(rel: &str, dir: &WebDir) -> Plain {
    let Some(base) = dir.resolve() else {
        return text(
            503,
            "The console is not built into this installation. In a checkout, \
             run `npm ci --ignore-scripts && npm run build` in frontend/.",
            "no-store",
        );
    };
    let index = format!("{}/index.html", base.trim_end_matches('/'));
    if rel.is_empty() || rel == "index.html" {
        return file(&index, "text/html", "no-store");
    }
    if let Some(found) = resolve(&base, rel) {
        let immutable = rel.starts_with("assets/");
        let media = guess_type(&found).unwrap_or("application/octet-stream");
        let cache = if immutable { "public, max-age=31536000, immutable" } else { "public, max-age=3600" };
        return file(&found, media, cache);
    }
    // Only under assets/: a client route may contain a dot (a tool ID like
    // `docker.compose_ps` is one), so an extension alone proves nothing.
    if rel.starts_with("assets/") {
        return text(404, "not found", "no-store");
    }
    file(&index, "text/html", "no-store")
}

/// Starlette's `GZipMiddleware(minimum_size=500)` and the response itself.
fn finish(mut plain: Plain, accept_encoding: &str) -> Response {
    let media = plain
        .headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    let family = format!("{}/*", media.split('/').next().unwrap_or(""));
    let excluded = GZIP_EXCLUDED.contains(&media.as_str()) || GZIP_EXCLUDED.contains(&family.as_str());
    if accept_encoding.contains("gzip") && !excluded && plain.body.len() >= GZIP_MINIMUM_SIZE {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(9));
        if encoder.write_all(&plain.body).is_ok() {
            if let Ok(compressed) = encoder.finish() {
                plain.body = compressed;
                plain.headers.push(("vary".into(), "Accept-Encoding".into()));
                plain.headers.push(("content-encoding".into(), "gzip".into()));
            }
        }
    }
    let mut response = Response::new(Body::from(plain.body));
    *response.status_mut() = StatusCode::from_u16(plain.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    for (k, v) in plain.headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_csp_allows_only_this_origin() {
        let directives: std::collections::HashMap<&str, &str> = APP_CSP
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once(' ').unwrap_or((p, "")))
            .collect();
        assert_eq!(directives["default-src"], "'none'");
        assert_eq!(directives["script-src"], "'self'");
        assert_eq!(directives["require-trusted-types-for"], "'script'");
        assert_eq!(directives["frame-ancestors"], "'none'");
        for value in directives.values() {
            assert!(!value.contains("unsafe"));
            assert!(!value.contains("http") && !value.contains('*'));
        }
    }

    #[test]
    fn the_csp_is_pythons() {
        assert_eq!(
            APP_CSP,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; \
             font-src 'self'; manifest-src 'self'; worker-src 'self'; form-action 'self'; frame-ancestors 'none'; \
             base-uri 'none'; require-trusted-types-for 'script'"
        );
    }

    #[test]
    fn nothing_escapes_the_build() {
        let dir = tempfile::tempdir().unwrap();
        let dist = dir.path().join("dist");
        std::fs::create_dir_all(dist.join("assets")).unwrap();
        std::fs::write(dist.join("index.html"), "x").unwrap();
        std::fs::write(dist.join("assets/a.js"), "x").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "s").unwrap();
        let base = dist.to_str().unwrap();
        assert!(resolve(base, "assets/a.js").is_some());
        assert!(resolve(base, "../secret.txt").is_none());
        assert!(resolve(base, "assets/../../secret.txt").is_none());
        assert!(resolve(base, &format!("{}/secret.txt", dir.path().display())).is_none());
        assert!(resolve(base, "assets").is_none());
    }
}
