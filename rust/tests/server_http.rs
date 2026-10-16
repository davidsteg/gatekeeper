//! The HTTP server end to end over a loopback socket (ports of
//! `test_integration_mcp.py`, `test_release_api.py`, the download route of
//! `test_artifacts.py`, `test_recovery_removed.py`'s route check,
//! `test_realip.py`, and the server/auth parts of `test_api_security.py`).

mod app_env;
mod server_env;

use std::collections::BTreeSet;

use app_env::*;
use gatekeeper::artifacts::{build, ArtifactStore, Source, SourceKind};
use gatekeeper::identity::hash_token_lookup;
use gatekeeper::server::{self, ClientAddr};
use serde_json::{json, Value};
use server_env::*;

const PING: &str = r#"{"jsonrpc": "2.0", "id": 1, "method": "ping"}"#;

fn ping() -> Value {
    serde_json::from_str(PING).unwrap()
}

// -- Health and authentication (test_integration_mcp.py) -----------------------------

#[tokio::test]
async fn health_needs_no_token() {
    let (env, _) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let live = get(&base, "/health/live", None).await;
    assert_eq!(live.status(), 200);
    assert_eq!(live.json::<Value>().await.unwrap(), json!({"status": "live"}));
    let startup = get(&base, "/health/startup", None).await;
    assert_eq!(startup.status(), 200);
    // No tool names, no identities -- only numbers.
    let keys: BTreeSet<String> = startup.json::<Value>().await.unwrap().as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, BTreeSet::from(["status".into(), "tools".into(), "disabled_by_tier1".into()]));
    let ready = get(&base, "/health/ready", None).await;
    assert_eq!(ready.status(), 200);
    assert_eq!(ready.json::<Value>().await.unwrap(), json!({"status": "ready", "executors": {"local": true}}));
}

#[tokio::test]
async fn ready_is_503_when_an_executor_is_degraded() {
    let env = builder()
        .tier1(json!({"toolkits": {"demo": {"executor": "local", "binaries": ["/nonexistent/binary"],
            "max_timeout_seconds": 5, "max_output_bytes": 1024}}}))
        .tools(vec![])
        .identities(standard_identities().0)
        .build();
    let base = serve(read_only_app(&env)).await;
    let ready = get(&base, "/health/ready", None).await;
    assert_eq!(ready.status(), 503);
    assert_eq!(ready.json::<Value>().await.unwrap(), json!({"status": "degraded", "executors": {"local": false}}));
}

#[tokio::test]
async fn mcp_without_token_is_401() {
    let (env, _) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let r = post_json(&base, "/mcp", None, ping(), &[]).await;
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Bearer");
    assert_eq!(r.headers()["content-type"], "application/json");
    assert_eq!(r.text().await.unwrap(), r#"{"error":"unauthorized"}"#);
}

#[tokio::test]
async fn mcp_with_wrong_token_is_401() {
    let (env, _) = standard_env();
    let base = serve(read_only_app(&env)).await;
    assert_eq!(post_json(&base, "/mcp", Some("gk_completely_wrong"), ping(), &[]).await.status(), 401);
}

#[tokio::test]
async fn metrics_requires_token() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    assert_eq!(get(&base, "/metrics", None).await.status(), 401);
    let r = get(&base, "/metrics", Some(&tokens.full)).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/plain; version=0.0.4; charset=utf-8");
    assert!(r.text().await.unwrap().contains("gatekeeper_tool_calls_total"));
}

// -- Protocol (test_integration_mcp.py) ----------------------------------------------

#[tokio::test]
async fn tools_list_is_filtered_per_identity() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let full: BTreeSet<String> = Mcp::connect(&base, "/mcp", &tokens.full).await.tool_names().await.into_iter().collect();
    let mut narrow_client = Mcp::modern(&base, "/mcp", &tokens.narrow);
    let narrow_result = narrow_client.request("tools/list", json!({})).await;
    let narrow: BTreeSet<String> =
        narrow_result["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().into()).collect();
    assert_eq!(full, BTreeSet::from(["demo.show".into(), "demo.echo".into()]));
    assert_eq!(narrow, BTreeSet::from(["demo.show".into()]));
    // The list differs per identity and must not be shared.
    assert_eq!(narrow_result["result"]["cacheScope"], "private");
}

#[tokio::test]
async fn the_server_identifies_itself() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    let result = &client.init["result"];
    assert_eq!(result["serverInfo"], json!({"name": "gatekeeper", "version": gatekeeper::VERSION}));
    assert_eq!(result["instructions"], server::INSTRUCTIONS);
    assert!(result["instructions"].as_str().unwrap().starts_with("Controlled access to host operations."));
    // test_version.py: the real version, never a placeholder.
    assert_ne!(gatekeeper::VERSION, "0.1.0");
    assert_ne!(gatekeeper::VERSION, "0.0.0+unknown");
    assert_eq!(gatekeeper::VERSION, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn call_tool_succeeds() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    let (text, is_error) = client.call_text("demo.show", json!({"stack": "media-jellyfin"})).await;
    assert!(!is_error);
    assert!(text.contains("media-jellyfin"), "{text}");
    // `_render`: the exit code heads the output.
    assert!(text.starts_with("exit=0\n"), "{text}");
}

#[tokio::test]
async fn a_call_is_audited_with_the_callers_address() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut client = Mcp::connect(&base, "/mcp", &tokens.narrow).await;
    client.call("demo.show", json!({"stack": "media-jellyfin"})).await;
    client.call("demo.echo", json!({"text": "x"})).await;
    let calls = audit_of(&env, "call");
    assert_eq!(calls.iter().map(|c| c["outcome"].as_str().unwrap()).collect::<Vec<_>>(), ["ok", "denied"]);
    assert!(calls.iter().all(|c| c["client"] == "127.0.0.1"), "{calls:?}");
}

#[tokio::test]
async fn call_tool_denial_is_opaque_over_protocol() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut client = Mcp::modern(&base, "/mcp", &tokens.narrow);
    let (forbidden, e1) = client.call_text("demo.echo", json!({"text": "x"})).await;
    let (nonexistent, e2) = client.call_text("demo.does_not_exist", json!({})).await;
    assert!(e1 && e2);
    assert_eq!(forbidden, nonexistent);
}

#[tokio::test]
async fn invalid_parameter_is_reported_concretely() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let mut client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    let (text, is_error) = client.call_text("demo.show", json!({"stack": "INVALID; rm -rf /"})).await;
    assert!(is_error);
    assert!(text.contains("stack"), "{text}");
}

#[tokio::test]
async fn annotations_reach_the_agent() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let tools = Mcp::modern(&base, "/mcp", &tokens.full).list_tools().await;
    let show = tools.iter().find(|t| t["name"] == "demo.show").unwrap();
    assert_eq!(show["annotations"], json!({"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true}));
    assert_eq!(show["title"], "Show compose file");
    // Derived parameters do not appear in the agent's schema.
    let props: Vec<&String> = show["inputSchema"]["properties"].as_object().unwrap().keys().collect();
    assert_eq!(props, ["stack"]);
    // Sorted by name, like `visible_tools`.
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["demo.echo", "demo.show"]);
}

#[tokio::test]
async fn a_write_tool_is_marked_destructive() {
    let (ids, tokens) = standard_identities();
    let mut specs = sh_specs(&std::path::PathBuf::from("/tmp"));
    specs[1]["category"] = json!("write");
    specs[1]["idempotent"] = json!(false);
    let env = builder().identities(ids).tools(specs).build();
    let base = serve(read_only_app(&env)).await;
    let tools = Mcp::modern(&base, "/mcp", &tokens.full).list_tools().await;
    let echo = tools.iter().find(|t| t["name"] == "demo.echo").unwrap();
    assert_eq!(echo["annotations"], json!({"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false}));
}

#[tokio::test]
async fn an_unknown_path_is_404_behind_the_token() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    assert_eq!(get(&base, "/nope", None).await.status(), 401);
    let r = get(&base, "/nope", Some(&tokens.full)).await;
    assert_eq!(r.status(), 404);
    assert_eq!(r.text().await.unwrap(), "Not Found");
}

// -- test_recovery_removed.py ----------------------------------------------------------

#[tokio::test]
async fn recovery_routes_do_not_exist() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let events = post_json(&base, "/recovery/events", Some(&tokens.full), json!({"event": "turn_stopped"}), &[]).await;
    let incidents = get(&base, "/recovery/incidents", Some(&tokens.full)).await;
    assert_eq!(events.status(), 404);
    assert_eq!(incidents.status(), 404);
}

// -- GET /release (test_release_api.py) ------------------------------------------------

async fn release(base: &str, token: &str, query: &str) -> reqwest::Response {
    get(base, &format!("/release{query}"), Some(token)).await
}

/// PORT NOTE: Python compared the newest section with `__version__`; the
/// Rust crate's version (2.0.0) is not yet a section of RELEASE.md, so the
/// newest section is compared with the file itself.
fn newest_section() -> String {
    gatekeeper::release_notes::load()[0].0.clone()
}

#[tokio::test]
async fn release_requires_a_token() {
    let (env, _) = standard_env();
    let base = serve(read_only_app(&env)).await;
    assert_eq!(get(&base, "/release", None).await.status(), 401);
}

#[tokio::test]
async fn release_returns_versions_newest_first() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let r = release(&base, &tokens.full, "").await;
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["version"], gatekeeper::VERSION);
    assert_eq!(body["releases"][0]["version"], json!(newest_section()));
    assert!(body["total"].as_u64() >= body["count"].as_u64());
}

#[tokio::test]
async fn version_selects_one_section_and_unknown_is_404() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let newest = newest_section();
    let body: Value = release(&base, &tokens.full, &format!("?version={newest}")).await.json().await.unwrap();
    let versions: Vec<&str> = body["releases"].as_array().unwrap().iter().map(|r| r["version"].as_str().unwrap()).collect();
    assert_eq!(versions, [newest.as_str()]);
    assert_eq!(release(&base, &tokens.full, "?version=99.99.99").await.status(), 404);
}

#[tokio::test]
async fn search_filters_and_reports_the_pre_limit_total() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let body: Value = release(&base, &tokens.full, "?search=credential&limit=2").await.json().await.unwrap();
    assert_eq!(body["count"], 2);
    assert!(body["total"].as_u64().unwrap() > 2);
    for r in body["releases"].as_array().unwrap() {
        assert!(r["notes"].as_str().unwrap().to_lowercase().contains("credential"));
    }
    let lower: Value = release(&base, &tokens.full, "?search=credential").await.json().await.unwrap();
    let upper: Value = release(&base, &tokens.full, "?search=CREDENTIAL").await.json().await.unwrap();
    assert_eq!(lower["total"], upper["total"]);
}

#[tokio::test]
async fn a_bad_limit_is_refused_not_silently_defaulted() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    assert_eq!(release(&base, &tokens.full, "?limit=abc").await.status(), 400);
    assert_eq!(release(&base, &tokens.full, "?limit=0").await.status(), 400);
}

#[tokio::test]
async fn markdown_and_full_formats() {
    let (env, tokens) = standard_env();
    let base = serve(read_only_app(&env)).await;
    let md = release(&base, &tokens.full, "?format=markdown&limit=1").await;
    assert!(md.headers()["content-type"].to_str().unwrap().starts_with("text/markdown"));
    assert!(md.text().await.unwrap().starts_with(&format!("## {}", newest_section())));
    let full: Value = release(&base, &tokens.full, "?full=1").await.json().await.unwrap();
    let markdown = full["markdown"].as_str().unwrap();
    assert!(markdown.contains("## Procedure") && markdown.contains("# Releases"));
    let as_text = release(&base, &tokens.full, "?full=1&format=markdown").await.text().await.unwrap();
    assert_eq!(as_text, markdown);
}

// -- GET /artifacts (test_artifacts.py) --------------------------------------------------

const COMMIT: &str = "7aa7b394cb713162db98aad29c91c342508a49c7";
const CONTRACT: &str = "example-doc";
const ADAPTER: &str = "example-kit";

#[tokio::test]
async fn http_download_streams_verified_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(repo.join("docs")).unwrap();
    std::fs::write(repo.join("docs/EXAMPLE.md"), b"# Example\n").unwrap();
    std::fs::create_dir_all(repo.join("kit/pkg")).unwrap();
    std::fs::write(repo.join("kit/pkg/main.py"), "print('hello')\n").unwrap();
    let out = dir.path().join("artifacts");
    let sources = [
        Source {
            id: CONTRACT.into(),
            kind: SourceKind::File,
            path: "docs/EXAMPLE.md".into(),
            file: "EXAMPLE.md".into(),
            media_type: "text/markdown; charset=utf-8".into(),
            text: true,
        },
        Source {
            id: ADAPTER.into(),
            kind: SourceKind::Tree,
            path: "kit".into(),
            file: "example-kit.tar.gz".into(),
            media_type: "application/gzip".into(),
            text: false,
        },
    ];
    build(repo.to_str().unwrap(), out.to_str().unwrap(), COMMIT, "0.52.0", &sources).unwrap();
    let (homelab, homelab_t) = server_env::identity("homelab", "agent", &["artifact.list"], &["artifact:*"], None);
    let (other, other_t) = server_env::identity("other", "agent", &["artifact.list"], &[&format!("artifact:{CONTRACT}")], None);
    let env = builder()
        .tier1(json!({"toolkits": {"artifact": {"executor": "artifact",
            "allowed_artifact_operations": ["list", "transfer"], "allowed_artifacts": [CONTRACT, ADAPTER],
            "handover_dir": dir.path().join("handover").to_str().unwrap(), "max_output_bytes": 200000}}}))
        .tools(vec![json!({"id": "artifact.list", "toolkit": "artifact", "version": 1, "enabled": true,
            "category": "read", "idempotent": true, "required_scopes": [], "timeout_seconds": 30,
            "max_output_bytes": 200000, "description": "artifact tool", "title": "List",
            "artifact_operation": "list", "parameters": {}})])
        .identities(vec![homelab, other])
        .build();
    env.service.set_artifact_store(ArtifactStore::new(out.to_str().unwrap()));
    let base = serve(read_only_app(&env)).await;

    let ok = get(&base, &format!("/artifacts/{ADAPTER}/{}", &COMMIT[..12]), Some(&homelab_t)).await;
    assert_eq!(ok.status(), 200);
    let sha = ok.headers()["x-artifact-sha256"].to_str().unwrap().to_string();
    assert_eq!(ok.headers()["x-artifact-commit"], COMMIT);
    assert_eq!(ok.headers()["content-type"], "application/gzip");
    assert_eq!(ok.headers()["content-disposition"], "attachment; filename=\"example-kit.tar.gz\"");
    let bytes = ok.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), std::fs::read(out.join("example-kit.tar.gz")).unwrap().as_slice());
    use sha2::Digest;
    assert_eq!(hex::encode(sha2::Sha256::digest(&bytes)), sha);

    let doc = get(&base, &format!("/artifacts/{CONTRACT}"), Some(&other_t)).await;
    assert_eq!(doc.status(), 200);
    assert_eq!(doc.headers()["content-type"], "text/markdown; charset=utf-8");

    let hidden = get(&base, &format!("/artifacts/{ADAPTER}"), Some(&other_t)).await;
    let unknown = get(&base, "/artifacts/nope", Some(&homelab_t)).await;
    assert_eq!(hidden.status(), 404);
    assert_eq!(unknown.status(), 404);
    assert_eq!(hidden.text().await.unwrap(), unknown.text().await.unwrap());
    assert_eq!(get(&base, &format!("/artifacts/{ADAPTER}"), None).await.status(), 401);

    let downloads = audit_of(&env, "artifact_download");
    assert_eq!(downloads.len(), 4);
    assert_eq!(downloads[0]["outcome"], "ok");
    assert_eq!(downloads[0]["identity"], "homelab");
    assert_eq!(downloads[2]["outcome"], "denied");
    assert!(env.audit_text().contains("\"kind\": \"artifact_download\""));
}

// -- The server/auth parts of test_api_security.py ---------------------------------------

const MCP_LIST: &str = r#"{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}"#;

fn mcp_list() -> Value {
    serde_json::from_str(MCP_LIST).unwrap()
}

#[tokio::test]
async fn a_cookie_does_not_authenticate_mcp() {
    let (env, _) = standard_env();
    let base = serve(full_app(&env)).await;
    let cookie = [("cookie", "gk_session=whatever-a-browser-sends")];
    for path in ["/mcp", "/admin/mcp"] {
        let r = post_json(&base, path, None, mcp_list(), &cookie).await;
        assert_eq!(r.status(), 401, "{path}");
        assert_eq!(r.json::<Value>().await.unwrap(), json!({"error": "unauthorized"}));
    }
    let r = http().get(format!("{base}/metrics")).header("cookie", cookie[0].1).send().await.unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn the_console_password_is_not_an_api_token() {
    let (env, _) = standard_env();
    let base = serve(full_app(&env)).await;
    assert_eq!(post_json(&base, "/mcp", Some(ROOT_PASSWORD), mcp_list(), &[]).await.status(), 401);
}

#[tokio::test]
async fn an_mcp_auth_failure_names_the_caller_but_never_the_token() {
    let (env, tokens) = standard_env();
    let base = serve(full_app(&env)).await;
    let stale = format!("gk_{}", "x".repeat(43));
    for token in [stale.as_str(), tokens.root.as_str()] {
        let r = post_json(&base, "/mcp", Some(token), mcp_list(), &[("user-agent", "stale-agent/1.0")]).await;
        assert_eq!(r.status(), 401);
    }
    post_json(&base, "/mcp", None, mcp_list(), &[]).await;
    let failures = audit_of(&env, "auth_failure");
    let [unknown, wrong_role, missing] = &failures[failures.len() - 3..] else { panic!() };
    assert_eq!(unknown["reason"], "unknown_token");
    assert_eq!(unknown["client"], "127.0.0.1");
    assert_eq!(unknown["fingerprint"], json!(hash_token_lookup(&stale)[..12]));
    assert_eq!(unknown["detail"], "POST /mcp from 127.0.0.1");
    assert_eq!((unknown["method"].as_str(), unknown["path"].as_str()), (Some("POST"), Some("/mcp")));
    assert_eq!(unknown["user_agent"], "stale-agent/1.0");
    assert!(unknown.get("identity").is_none());
    // Field order of Python's `auth_failure(reason=..., detail=..., **caller)`.
    let keys: Vec<&String> = unknown.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["ts", "kind", "reason", "detail", "client", "method", "path", "user_agent", "fingerprint"]);
    assert_eq!(wrong_role["identity"], "root");
    assert_eq!(wrong_role["client"], "127.0.0.1");
    assert_eq!(wrong_role["detail"], "role 'admin' on /mcp ('root') from 127.0.0.1");
    assert!(missing.get("fingerprint").is_none() && missing["client"] == "127.0.0.1");
    assert!(!env.audit_text().contains(&stale));
}

#[tokio::test]
async fn similar_prefixes_are_not_console_paths() {
    let (env, _) = standard_env();
    let base = serve(full_app(&env)).await;
    for path in ["/api/v1xyz", "/apixyz", "/appxyz", "/uixyz"] {
        let r = get(&base, path, None).await;
        assert_eq!(r.status(), 401, "{path}");
        assert_eq!(r.json::<Value>().await.unwrap(), json!({"error": "unauthorized"}), "{path}");
    }
}

#[tokio::test]
async fn console_paths_pass_the_bearer_check_only_with_the_ui() {
    let (env, _) = standard_env();
    let before = audit_of(&env, "auth_failure").len();
    let with_ui = serve(full_app(&env)).await;
    // The console's own router answers (here: the placeholder, so 404) --
    // what matters is that the bearer middleware let them through, and
    // that browser noise stays out of the audit log.
    for path in ["/", "/favicon.ico", "/ui/", "/app/", "/api/v1/session"] {
        assert_ne!(get(&with_ui, path, None).await.status(), 401, "{path}");
    }
    assert_eq!(audit_of(&env, "auth_failure").len(), before);
    // Without the console, the root still needs a token.
    let without = serve(read_only_app(&env)).await;
    for path in ["/", "/favicon.ico", "/ui/", "/app/", "/api/v1/session"] {
        assert_eq!(get(&without, path, None).await.status(), 401, "{path}");
    }
}

async fn proxied(env: &AppEnv, peer: &str, trusted: &[&str]) -> String {
    let trusted = Some(trusted.iter().map(|s| s.to_string()).collect());
    serve(from_peer(server::with_proxy_headers(read_only_app(env), trusted), peer)).await
}

#[tokio::test]
async fn a_trusted_proxy_reveals_the_real_client() {
    let (env, _) = standard_env();
    let base = proxied(&env, "172.18.0.5", &["172.18.0.5"]).await;
    post_json(&base, "/mcp", Some("gk_wrong"), mcp_list(), &[("x-forwarded-for", "203.0.113.7")]).await;
    let detail = audit_of(&env, "auth_failure").pop().unwrap()["detail"].as_str().unwrap().to_string();
    assert!(detail.contains("203.0.113.7") && !detail.contains("172.18.0.5"), "{detail}");
}

#[tokio::test]
async fn an_untrusted_peer_cannot_forge_its_address() {
    let (env, _) = standard_env();
    let base = proxied(&env, "203.0.113.99", &["172.18.0.5"]).await;
    post_json(&base, "/mcp", Some("gk_wrong"), mcp_list(), &[("x-forwarded-for", "10.0.0.1")]).await;
    let detail = audit_of(&env, "auth_failure").pop().unwrap()["detail"].as_str().unwrap().to_string();
    assert!(detail.contains("203.0.113.99") && !detail.contains("10.0.0.1"), "{detail}");
}

#[tokio::test]
async fn x_real_ip_reaches_the_audit_log_and_the_call_record() {
    let (env, tokens) = standard_env();
    let base = proxied(&env, "172.16.29.1", &["172.16.0.0/12"]).await;
    let mut client = Mcp::connect(&base, "/mcp", &tokens.full).await;
    // reqwest cannot add a header per request through `Mcp`, so the
    // auth-failure path carries the header here.
    post_json(&base, "/mcp", Some("gk_wrong"), mcp_list(), &[("x-real-ip", "10.10.110.102")]).await;
    let detail = audit_of(&env, "auth_failure").pop().unwrap()["detail"].as_str().unwrap().to_string();
    assert_eq!(detail, "POST /mcp from 10.10.110.102");
    // Without the header, the call record carries the proxy's own address.
    client.call("demo.echo", json!({"text": "x"})).await;
    assert_eq!(audit_of(&env, "call").pop().unwrap()["client"], "172.16.29.1");
}

// -- RealIpMiddleware (test_realip.py) ----------------------------------------------------

fn client_seen(trusted: Option<&[&str]>, peer: &str, headers: &[(&str, &str)]) -> String {
    let mut request = axum::extract::Request::new(axum::body::Body::empty());
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(peer.parse().unwrap(), 5000)));
    for (k, v) in headers {
        request.headers_mut().append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
    }
    let trusted = gatekeeper::realip::TrustedProxies::parse(trusted);
    server::apply_real_ip(&trusted, &mut request);
    server::client_addr(request.extensions()).unwrap().host
}

#[test]
fn x_real_ip_counts_only_from_a_trusted_proxy() {
    let cidr: &[&str] = &["172.16.0.0/12"];
    let all: &[&str] = &["*"];
    assert_eq!(client_seen(Some(cidr), "172.16.29.1", &[("x-real-ip", "10.10.110.102")]), "10.10.110.102");
    assert_eq!(client_seen(Some(all), "172.16.29.1", &[("x-real-ip", "10.10.110.102")]), "10.10.110.102");
    assert_eq!(client_seen(Some(cidr), "10.10.110.7", &[("x-real-ip", "1.2.3.4")]), "10.10.110.7");
    assert_eq!(client_seen(None, "172.16.29.1", &[("x-real-ip", "1.2.3.4")]), "172.16.29.1");
    assert_eq!(client_seen(None, "127.0.0.1", &[("x-real-ip", "1.2.3.4")]), "1.2.3.4");
    assert_eq!(
        client_seen(Some(all), "10.10.110.102", &[("x-forwarded-for", "10.10.110.102"), ("x-real-ip", "1.2.3.4")]),
        "10.10.110.102"
    );
    assert_eq!(client_seen(Some(all), "172.16.29.1", &[("x-real-ip", "<script>")]), "172.16.29.1");
}

#[test]
fn proxy_headers_rewrite_client_and_scheme_for_a_trusted_peer() {
    let rewrite = |trusted: &[&str], peer: &str, headers: &[(&str, &str)]| {
        let mut request = axum::extract::Request::new(axum::body::Body::empty());
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(peer.parse().unwrap(), 5000)));
        for (k, v) in headers {
            request.headers_mut().append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        let list: Vec<String> = trusted.iter().map(|s| s.to_string()).collect();
        server::apply_proxy_headers(&server::UvicornTrustedHosts::new(Some(&list)), &mut request);
        let client = server::client_addr(request.extensions()).unwrap();
        let scheme = request.extensions().get::<server::RequestScheme>().unwrap().0.clone();
        (client, scheme)
    };
    let (client, scheme) =
        rewrite(&["172.18.0.5"], "172.18.0.5", &[("x-forwarded-for", "203.0.113.7:4711"), ("x-forwarded-proto", "https")]);
    assert_eq!(client, ClientAddr { host: "203.0.113.7".into(), port: 4711 });
    assert_eq!(scheme, "https");
    let (client, scheme) = rewrite(&["172.18.0.5"], "203.0.113.99", &[("x-forwarded-for", "10.0.0.1"), ("x-forwarded-proto", "https")]);
    assert_eq!(client.host, "203.0.113.99");
    assert_eq!(scheme, "http");
    // Several headers are joined; the first untrusted hop from the right wins.
    let (client, _) = rewrite(&["10.0.0.0/8"], "10.0.0.1", &[("x-forwarded-for", "1.1.1.1, 2.2.2.2"), ("x-forwarded-for", "10.0.0.9")]);
    assert_eq!(client.host, "2.2.2.2");
    // An unknown proto leaves the scheme alone.
    let (_, scheme) = rewrite(&["*"], "9.9.9.9", &[("x-forwarded-proto", "gopher")]);
    assert_eq!(scheme, "http");
}
