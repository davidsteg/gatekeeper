//! `/app`: the React console's static build (port of
//! `tests/test_api_web.py`), plus the contract it is built on: the
//! committed OpenAPI document and the Rust routes describe the same API.

mod api_env;
mod app_env;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use api_env::{make_env_with, ApiEnv, Spec};
use gatekeeper::api::app::ROUTES;
use gatekeeper::api::web::{WebDir, APP_CSP};
use gatekeeper::api::ConsoleOptions;
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// A small build in a temp dir, with a secret next to it.
struct Built {
    _dir: tempfile::TempDir,
    dist: PathBuf,
}

fn built() -> Built {
    let dir = tempfile::tempdir().unwrap();
    let dist = dir.path().join("dist");
    std::fs::create_dir_all(dist.join("assets")).unwrap();
    std::fs::write(
        dist.join("index.html"),
        r#"<!doctype html><script type="module" src="/app/assets/index-abc.js"></script>"#,
    )
    .unwrap();
    std::fs::write(dist.join("assets/index-abc.js"), "console.log('x');".repeat(100)).unwrap();
    std::fs::write(dist.join("favicon.svg"), "<svg/>").unwrap();
    let manifest = std::fs::read_to_string(repo().join("frontend/public/manifest.webmanifest")).unwrap();
    std::fs::write(dist.join("manifest.webmanifest"), manifest).unwrap();
    std::fs::write(dir.path().join("secret.txt"), "outside the build").unwrap();
    Built { _dir: dir, dist }
}

fn env_for(dir: WebDir) -> ApiEnv {
    let options = ConsoleOptions { web_dir: dir, ..ConsoleOptions::default() };
    make_env_with(Spec { options: Some(options), ..Spec::default() })
}

fn env_built(b: &Built) -> ApiEnv {
    env_for(WebDir::Fixed(Some(b.dist.to_str().unwrap().to_string())))
}

#[tokio::test]
async fn index_carries_the_console_csp() {
    let b = built();
    let env = env_built(&b);
    let response = env.client().get("/app/").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-security-policy").unwrap(), APP_CSP);
    assert_eq!(response.header("cache-control").unwrap(), "no-store");
    assert_eq!(response.header("x-content-type-options").unwrap(), "nosniff");
    assert!(response.text().contains("/app/assets/index-abc.js"));
}

#[test]
fn the_csp_allows_only_this_origin() {
    let mut directives = std::collections::HashMap::new();
    for part in APP_CSP.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once(' ').unwrap_or((part, ""));
        directives.insert(k, v);
    }
    assert_eq!(directives["default-src"], "'none'");
    assert_eq!(directives["script-src"], "'self'");
    assert_eq!(directives["require-trusted-types-for"], "'script'");
    assert_eq!(directives["frame-ancestors"], "'none'");
    for value in directives.values() {
        assert!(!value.contains("unsafe"));
        assert!(!value.contains("http") && !value.contains('*'));
    }
}

#[tokio::test]
async fn hashed_assets_are_immutable() {
    let b = built();
    let env = env_built(&b);
    let mut c = env.client();
    let response = c.get_h("/app/assets/index-abc.js", &[("accept-encoding", "gzip")]).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("cache-control").unwrap(), "public, max-age=31536000, immutable");
    assert!(response.header("content-type").unwrap().starts_with("text/javascript"));
    assert_eq!(response.header("content-encoding").as_deref(), Some("gzip"));
    assert_eq!(response.header("content-security-policy").unwrap(), APP_CSP);
    // The body really is gzip, of the file.
    let mut text = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&response.body[..]), &mut text).unwrap();
    assert_eq!(text, "console.log('x');".repeat(100));
    let icon = c.get("/app/favicon.svg").await;
    assert_eq!(icon.status, 200);
    assert!(!icon.header("cache-control").unwrap().contains("immutable"));
}

#[tokio::test]
async fn client_routes_fall_back_to_index() {
    let b = built();
    let env = env_built(&b);
    let mut c = env.client();
    for path in ["/app/tools", "/app/tools/docker.compose_ps", "/app/audit?outcome=ok"] {
        let response = c.get(path).await;
        assert_eq!(response.status, 200, "{path}");
        assert_eq!(response.header("cache-control").unwrap(), "no-store");
        assert!(response.text().contains("index-abc.js"), "{path}");
    }
}

#[tokio::test]
async fn missing_assets_are_404_not_html() {
    let b = built();
    let env = env_built(&b);
    let response = env.client().get("/app/assets/index-old.js").await;
    assert_eq!(response.status, 404);
    assert!(!response.text().contains("<script"));
}

#[tokio::test]
async fn no_path_escapes_the_build() {
    let b = built();
    let env = env_built(&b);
    let mut c = env.client();
    for path in ["/app/../secret.txt", "/app/%2e%2e/secret.txt", "/app/assets/..%2f..%2fsecret.txt", "/app/..%2fsecret.txt"] {
        let response = c.get(path).await;
        assert!(!response.text().contains("outside the build"), "{path}");
    }
}

#[tokio::test]
async fn app_needs_no_token_and_redirects_to_the_slash() {
    let b = built();
    let env = env_built(&b);
    let response = env.client().get("/app").await;
    assert_eq!(response.status, 308);
    assert_eq!(response.header("location").unwrap(), "/app/");
}

#[tokio::test]
async fn not_built_is_a_clear_503() {
    let env = env_for(WebDir::Fixed(None));
    let response = env.client().get("/app/").await;
    assert_eq!(response.status, 503);
    assert!(response.text().contains("npm run build"));
}

/// A browser fetches the manifest before anyone has signed in, so it is
/// public -- static bytes with no data in it, scoped to `/app/`.
#[tokio::test]
async fn the_web_app_manifest_is_public_and_scoped_to_app() {
    let b = built();
    let env = env_built(&b);
    let response = env.client().get("/app/manifest.webmanifest").await;
    assert_eq!(response.status, 200);
    assert!(response.header("content-type").unwrap().starts_with("application/manifest+json"));
    let manifest = response.json();
    assert_eq!((manifest["start_url"].as_str(), manifest["scope"].as_str()), (Some("/app/"), Some("/app/")));
    assert!(manifest["icons"].as_array().unwrap().iter().all(|i| i["src"].as_str().unwrap().starts_with("/app/")));
    assert!(!response.text().contains("root"));
}

/// The real build in `frontend/dist`, found by the default lookup in a
/// checkout, is served with the console CSP. Skipped when not built.
#[tokio::test]
async fn the_checkout_build_is_served_with_the_csp() {
    let dist = repo().join("frontend/dist");
    if !dist.join("index.html").is_file() {
        eprintln!("frontend/dist is not built; skipping");
        return;
    }
    let env = env_for(WebDir::Auto);
    let mut c = env.client();
    let response = c.get("/app/").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-security-policy").unwrap(), APP_CSP);
    assert_eq!(response.text(), std::fs::read_to_string(dist.join("index.html")).unwrap());
    for entry in std::fs::read_dir(dist.join("assets")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        let asset = c.get(&format!("/app/assets/{name}")).await;
        assert_eq!(asset.status, 200, "{name}");
        assert_eq!(asset.header("cache-control").unwrap(), "public, max-age=31536000, immutable");
    }
}

// -- The schema and the routes -----------------------------------------------------

/// The committed schema (what the frontend's types are generated from) and
/// the Rust route table name the same operations, both ways, with the same
/// methods. `/openapi.json` itself is not in the schema.
#[test]
fn the_schema_and_the_routes_match_both_ways() {
    let schema: Value = serde_json::from_str(&gatekeeper::api::openapi_json()).unwrap();
    let mut documented = BTreeSet::new();
    for (path, ops) in schema["paths"].as_object().unwrap() {
        for method in ops.as_object().unwrap().keys() {
            documented.insert((method.to_uppercase(), path.clone()));
        }
    }
    let routed: BTreeSet<(String, String)> =
        ROUTES.iter().filter(|r| r.in_schema).map(|r| (r.method.to_string(), r.path.to_string())).collect();
    let only_schema: Vec<_> = documented.difference(&routed).collect();
    let only_routes: Vec<_> = routed.difference(&documented).collect();
    assert!(only_schema.is_empty(), "in the schema, not routed: {only_schema:?}");
    assert!(only_routes.is_empty(), "routed, not in the schema: {only_routes:?}");
    assert!(ROUTES.iter().any(|r| r.path == "/openapi.json" && !r.in_schema));
    assert!(!documented.iter().any(|(_, p)| p == "/openapi.json"));
}

/// Each route's body model and query parameters agree with the schema's.
#[test]
fn the_schema_and_the_routes_agree_on_inputs() {
    let schema: Value = serde_json::from_str(&gatekeeper::api::openapi_json()).unwrap();
    for route in ROUTES.iter().filter(|r| r.in_schema) {
        let op = &schema["paths"][route.path][route.method.to_lowercase()];
        let has_body = op.get("requestBody").is_some();
        assert_eq!(has_body, route.body.is_some(), "{} {}", route.method, route.path);
        let mut documented: Vec<String> = op["parameters"]
            .as_array()
            .map(|ps| ps.iter().filter(|p| p["in"] == "query").map(|p| p["name"].as_str().unwrap().to_string()).collect())
            .unwrap_or_default();
        let mut routed: Vec<String> = route.query.iter().map(|(n, _)| n.to_string()).collect();
        documented.sort();
        routed.sort();
        assert_eq!(documented, routed, "{} {}", route.method, route.path);
    }
}

/// `GET /api/v1/openapi.json` serves the committed document unchanged.
#[tokio::test]
async fn the_served_schema_is_the_committed_one() {
    let env = make_env_with(Spec::default());
    let mut c = env.client();
    c.login("root").await;
    let response = c.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, 200);
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(repo().join("frontend/openapi.json")).unwrap()).unwrap();
    assert_eq!(response.json(), committed);
}
