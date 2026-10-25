//! 1.27.0 for `http` tools: an absent optional parameter leaves its query
//! key out, every brace in an http template must be a declared
//! placeholder, and an optional `verify:` read-back after the main request.
//! The target is a real loopback listener the test starts itself.

mod app_env;

use std::sync::{Arc, Mutex};

use app_env::*;
use gatekeeper::catalog::{parse_tool_spec, HttpVerify};
use gatekeeper::tier1::load_tier1;
use gatekeeper::validate::{build_http_request, build_http_verify, Values};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Seen = Arc<Mutex<Vec<String>>>;

/// A minimal HTTP/1.1 server: records `METHOD path?query` and answers by path.
async fn server() -> (u16, Seen) {
    server_with(|| {}).await
}

/// [`server`], running `on_post` before it answers any POST.
async fn server_with(on_post: impl Fn() + Send + Sync + 'static) -> (u16, Seen) {
    let on_post = Arc::new(on_post);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let seen = seen2.clone();
            let on_post = on_post.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                let line = text.lines().next().unwrap_or_default().to_string();
                let mut parts = line.split(' ');
                let method = parts.next().unwrap_or_default().to_string();
                let target = parts.next().unwrap_or_default().to_string();
                seen.lock().unwrap().push(format!("{method} {target}"));
                if method == "POST" {
                    on_post();
                }
                let path = target.split('?').next().unwrap_or_default();
                let (status, body) = match (method.as_str(), path) {
                    ("POST", "/api/fail") => (500, r#"{"error": "boom"}"#.to_string()),
                    ("POST", _) => (200, r#"{"ok": true}"#.to_string()),
                    ("GET", "/api/items/missing") => (404, r#"{"error": "not found"}"#.to_string()),
                    ("GET", "/api/items/empty") => (200, "null".to_string()),
                    ("GET", p) if p.starts_with("/api/items/") => {
                        (200, format!(r#"{{"id": "{}"}}"#, p.trim_start_matches("/api/items/")))
                    }
                    _ => (200, r#"{"echo": true}"#.to_string()),
                };
                let reason = if status == 200 { "OK" } else { "X" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, seen)
}

fn tier1_doc(port: u16) -> Value {
    json!({"toolkits": {"api": {
        "executor": "http", "base_url": format!("http://127.0.0.1:{port}"),
        "allowed_methods": ["GET", "POST"], "allowed_path_prefixes": ["/api/"],
        "allowed_cidrs": ["127.0.0.1/32"], "max_timeout_seconds": 10, "max_output_bytes": 65536,
    }}})
}

fn name_param(required: bool) -> Value {
    json!({"type": "string", "pattern": "^[a-z]+$", "required": required})
}

fn http_tool(id: &str, extra: Value) -> Value {
    let mut spec = json!({
        "id": id, "toolkit": "api", "version": 1, "title": "t", "description": "d",
        "category": "read", "enabled": true, "idempotent": true,
        "method": "GET", "path": "/api/search",
        "parameters": {}, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 65536,
    });
    for (k, v) in extra.as_object().unwrap() {
        spec[k] = v.clone();
    }
    spec
}

fn search_tool() -> Value {
    http_tool(
        "api.search",
        json!({
            "query": {"q": "{term}", "type": "{kind}", "page": "{page}", "fixed": "yes", "both": "{kind}-{page}"},
            "parameters": {"term": name_param(true), "kind": name_param(false), "page": name_param(false)},
        }),
    )
}

fn tier1_at(dir: &std::path::Path, doc: Value) -> gatekeeper::tier1::Tier1 {
    let mut doc = doc;
    doc["audit"] = json!({"dir": dir.join("logs").to_str().unwrap()});
    let path = write(&dir.join("toolkits.yaml"), &gatekeeper::yaml::dump(&doc));
    load_tier1(&path).unwrap()
}

fn vals(pairs: &[(&str, &str)]) -> Values {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

// -- Optional query parameters --------------------------------------------

#[test]
fn absent_optional_query_parameters_leave_their_keys_out() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(1));
    let tool = parse_tool_spec(&search_tool(), &tier1).unwrap();
    let tk = tier1.toolkit("api").unwrap();

    let req = build_http_request(&tool, &vals(&[("term", "abc")]), &tk).unwrap();
    let keys: Vec<&str> = req.query.keys().map(String::as_str).collect();
    assert_eq!(keys, ["q", "fixed"], "no key, no empty value for an absent optional");

    // One of two optionals in a combined value is still not enough: the key
    // is dropped whole, never sent half-substituted.
    let req = build_http_request(&tool, &vals(&[("term", "abc"), ("kind", "film")]), &tk).unwrap();
    assert_eq!(req.query.get("type").map(String::as_str), Some("film"));
    assert!(!req.query.contains_key("both"));
    assert!(!req.query.contains_key("page"));

    let all = vals(&[("term", "abc"), ("kind", "film"), ("page", "two")]);
    let req = build_http_request(&tool, &all, &tk).unwrap();
    assert_eq!(req.query.get("both").map(String::as_str), Some("film-two"));
    assert_eq!(req.query.len(), 5);
}

#[test]
fn a_missing_required_query_parameter_is_still_denied() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(1));
    let tool = parse_tool_spec(&search_tool(), &tier1).unwrap();
    let tk = tier1.toolkit("api").unwrap();
    // `resolve_parameters` would catch it first; build_http_request holds
    // the line on its own too.
    let err = build_http_request(&tool, &vals(&[("kind", "film")]), &tk).unwrap_err();
    assert_eq!(err.detail, "Query template 'q' needs ['term'].");
}

#[test]
fn a_missing_optional_path_placeholder_is_still_denied() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(1));
    let spec = http_tool("api.get", json!({"path": "/api/items/{name}", "parameters": {"name": name_param(false)}}));
    let tool = parse_tool_spec(&spec, &tier1).unwrap();
    let err = build_http_request(&tool, &vals(&[]), &tier1.toolkit("api").unwrap()).unwrap_err();
    assert_eq!(err.detail, "Path template needs ['name'].");
}

#[tokio::test]
async fn an_optional_filter_can_be_left_out_end_to_end() {
    let (port, seen) = server().await;
    let e = builder().tier1(tier1_doc(port)).tools(vec![search_tool()]).build();
    let who = agent("bot", &["api.search"], &[]);
    let r = e.service.call(&who, "api.search", &args(json!({"term": "abc"})), None).await.unwrap();
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
    assert_eq!(seen.lock().unwrap().as_slice(), ["GET /api/search?q=abc&fixed=yes"]);
}

// -- Stricter template syntax ---------------------------------------------

fn refused(spec: Value) -> String {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(1));
    parse_tool_spec(&spec, &tier1).unwrap_err().message
}

#[test]
fn every_brace_in_an_http_template_must_be_a_declared_placeholder() {
    let params = json!({"name": name_param(false)});
    let cases = [
        (json!({"query": {"x": "{name?}"}}), "query 'x'", "'{name?}' (unsupported syntax)"),
        (json!({"query": {"x": "{Name}"}}), "query 'x'", "'{Name}' (unsupported syntax)"),
        (json!({"query": {"x": "{ name }"}}), "query 'x'", "'{ name }' (unsupported syntax)"),
        (json!({"query": {"x": "{}"}}), "query 'x'", "'{}' (unsupported syntax)"),
        (json!({"query": {"x": "a{name"}}), "query 'x'", "'{' (unsupported syntax)"),
        (json!({"path": "/api/{name}}"}), "path", "'}' (unsupported syntax)"),
        (json!({"method": "POST", "category": "write", "body": {"a": ["{name?}"]}}), "body", "'{name?}'"),
    ];
    for (extra, location, token) in cases {
        let mut extra = extra;
        extra["parameters"] = params.clone();
        let msg = refused(http_tool("api.x", extra));
        assert!(msg.contains(&format!("{location} template")), "{msg}");
        assert!(msg.contains(token), "{msg}");
        assert!(msg.contains("required: false"), "{msg}");
    }
    // A well-formed but undeclared name keeps its established message.
    let msg = refused(http_tool("api.x", json!({"query": {"x": "{other}"}, "parameters": params})));
    assert_eq!(msg, "tool 'api.x': template references unknown parameter 'other'");
}

#[test]
fn well_formed_templates_still_load() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(1));
    parse_tool_spec(&search_tool(), &tier1).unwrap();
    // Braces in a non-string body leaf are not templates.
    let spec = http_tool(
        "api.post",
        json!({"method": "POST", "category": "write", "body": {"n": 1, "s": "{term}"},
               "parameters": {"term": name_param(true)}}),
    );
    parse_tool_spec(&spec, &tier1).unwrap();
}

/// A Stash tool as it is configured live: a GraphQL POST whose body
/// carries the query inline, selection-set braces and all.
fn stash_tool(id: &str, query: &str, variables: Value, parameters: Value) -> Value {
    http_tool(
        id,
        json!({"method": "POST", "path": "/api/graphql", "category": "read",
               "body": {"query": query, "variables": variables}, "parameters": parameters}),
    )
}

const FIND_SCENE: &str = "query FindScene($id: ID!) { findScene(id: $id) { id title date \
                          files { path size duration video_codec } studio { name } } }";

#[test]
fn graphql_bodies_with_inline_queries_load_again() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(1));
    let id_param = json!({"type": "string", "pattern": "^[0-9]+$", "required": true});
    let cases = [
        stash_tool("api.scene_get", FIND_SCENE, json!({"id": "{scene_id}"}), json!({"scene_id": id_param})),
        // The whole query inline, the placeholder inside GraphQL braces.
        stash_tool(
            "api.scene_inline",
            r#"{ findScene(id: "{scene_id}") { id files { path } } }"#,
            json!({}),
            json!({"scene_id": id_param}),
        ),
        stash_tool("api.stats", "{ stats { scene_count scenes_size performer_count } }", json!({}), json!({})),
        stash_tool(
            "api.scenes_by_path",
            "query($f: FindFilterType) { findScenes(filter: $f, scene_filter: {path: {value: \"x\", modifier: INCLUDES}}) \
             { count scenes { id files { path } } } }",
            json!({"f": {"per_page": 25}}),
            json!({}),
        ),
        // A JSON document inside a string leaf is literal text too.
        stash_tool("api.literal", "{ systemStatus { status } }", json!({"raw": "{\"a\": {}}"}), json!({})),
    ];
    for spec in cases {
        let id = spec["id"].clone();
        parse_tool_spec(&spec, &tier1).unwrap_or_else(|e| panic!("{id} must load: {}", e.message));
    }
}

#[test]
fn a_graphql_body_still_refuses_an_undeclared_placeholder_and_a_marker() {
    let id_param = json!({"scene_id": {"type": "string", "pattern": "^[0-9]+$", "required": true}});
    // A typo in the placeholder name.
    let msg = refused(stash_tool("api.x", FIND_SCENE, json!({"id": "{undeclared_param}"}), id_param.clone()));
    assert_eq!(msg, "tool 'api.x': template references unknown parameter 'undeclared_param'");
    let inline = r#"{ findScene(id: "{scene_idd}") { id } }"#;
    let msg = refused(stash_tool("api.x", inline, json!({}), id_param.clone()));
    assert_eq!(msg, "tool 'api.x': template references unknown parameter 'scene_idd'");
    // The optional marker is still refused in a body, spaces or not.
    for marker in ["{scene_id?}", "{ scene_id ? }"] {
        let msg = refused(stash_tool("api.x", FIND_SCENE, json!({"id": marker}), id_param.clone()));
        assert!(msg.contains("body template"), "{msg}");
        assert!(msg.contains(&format!("'{marker}' (unsupported syntax)")), "{msg}");
    }
    // Path and query keep the strict 1.27.0 rule.
    let mut spec = stash_tool("api.x", FIND_SCENE, json!({"id": "{scene_id}"}), id_param);
    spec["query"] = json!({"x": "{ scene_id }"});
    let msg = refused(spec);
    assert!(msg.contains("query 'x' template") && msg.contains("'{ scene_id }' (unsupported syntax)"), "{msg}");
}

#[tokio::test]
async fn a_graphql_body_is_sent_with_its_braces_and_the_value_filled_in() {
    let (port, _seen) = server().await;
    let id_param = json!({"type": "string", "pattern": "^[0-9]+$", "required": true});
    let tool = stash_tool(
        "api.scene_inline",
        r#"{ findScene(id: "{scene_id}") { id files { path } } }"#,
        json!({"id": "{scene_id}"}),
        json!({"scene_id": id_param}),
    );
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(port));
    let parsed = parse_tool_spec(&tool, &tier1).unwrap();
    let req = build_http_request(&parsed, &vals(&[("scene_id", "42")]), &tier1.toolkit("api").unwrap()).unwrap();
    assert_eq!(
        req.body,
        Some(json!({"query": r#"{ findScene(id: "42") { id files { path } } }"#, "variables": {"id": "42"}}))
    );
    let e = builder().tier1(tier1_doc(port)).tools(vec![tool]).build();
    let who = agent("bot", &["api.scene_inline"], &[]);
    let r = e.service.call(&who, "api.scene_inline", &args(json!({"scene_id": "42"})), None).await.unwrap();
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
}

#[test]
fn admin_tool_validate_reports_the_bad_placeholder() {
    let e = builder().tier1(tier1_doc(1)).tools(vec![]).build();
    let spec = http_tool("api.x", json!({"query": {"x": "{name?}"}, "parameters": {"name": name_param(false)}}));
    let out = e.admin().tool_validate("admin", &args(json!({"spec": spec}))).unwrap();
    assert_eq!(out["ok"], false);
    assert!(out["error"].as_str().unwrap().contains("'{name?}'"), "{out}");
}

// -- verify ---------------------------------------------------------------

fn write_tool(verify: Value) -> Value {
    http_tool(
        "api.save",
        json!({"method": "POST", "category": "write", "idempotent": false,
               "path": "/api/save/{name}", "body": {"name": "{name}"},
               "parameters": {"name": name_param(true)}, "verify": verify}),
    )
}

#[test]
fn verify_parses_with_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(1));
    let tool = parse_tool_spec(&write_tool(json!({"path": "/api/items/{name}"})), &tier1).unwrap();
    assert_eq!(
        tool.verify,
        Some(HttpVerify {
            method: "GET".into(),
            path_template: "/api/items/{name}".into(),
            query_template: Default::default(),
            body_template: None,
            require_body: false,
        })
    );
    let tk = tier1.toolkit("api").unwrap();
    let v = build_http_verify(&tool, &vals(&[("name", "abc")]), &tk).unwrap().unwrap();
    assert_eq!((v.method.as_str(), v.path.as_str()), ("GET", "/api/items/abc"));
    assert!(v.body.is_none());
    let plain = parse_tool_spec(&search_tool(), &tier1).unwrap();
    assert!(build_http_verify(&plain, &vals(&[("term", "a")]), &tk).unwrap().is_none());
}

#[test]
fn bad_verify_blocks_are_refused_at_load() {
    let cases = [
        (json!("GET /x"), "'verify' must be a mapping"),
        (json!({"path": "/api/x", "extra": 1}), "unknown keys ['extra']"),
        (json!({"path": "api/x"}), "'verify.path' must be a string starting with '/'"),
        (json!({"path": "/api/x", "method": 5}), "'verify.method' must be a string"),
        (json!({"path": "/api/x", "method": "POST"}), "only allowed with a fixed 'verify.body'"),
        (json!({"path": "/api/x", "method": "DELETE", "body": null}), "is not a read method"),
        (json!({"path": "/api/x", "method": "POST", "body": {"raw_param": "name"}}), "cannot use raw_param"),
        (json!({"path": "/api/x", "require_body": "yes"}), "'verify.require_body' must be true or false"),
        (json!({"path": "/api/x", "query": {"a": 1}}), "'verify.query' must be a mapping"),
        (json!({"path": "/api/{nope}"}), "unknown parameter 'nope'"),
        (json!({"path": "/api/x", "query": {"a": "{name?}"}}), "verify.query 'a' template"),
        (json!({"path": "/other/x"}), "verify path '/other/x' matches none"),
        (json!({"path": "/api/x", "method": "PUT", "body": {"a": "b"}}), "verify method 'PUT' is not in the allowlist"),
    ];
    for (verify, expected) in cases {
        let msg = refused(write_tool(verify));
        assert!(msg.contains(expected), "expected {expected:?} in {msg}");
    }
    // A write method is fine with a fixed body.
    let dir = tempfile::tempdir().unwrap();
    let tier1 = tier1_at(dir.path(), tier1_doc(1));
    let ok = write_tool(json!({"path": "/api/query", "method": "post", "body": {"id": "{name}"}}));
    assert_eq!(parse_tool_spec(&ok, &tier1).unwrap().verify.unwrap().method, "POST");
    // verify is an http-only field.
    let mut local = json!({"toolkits": {"sh": {"executor": "local", "binaries": ["/bin/true"]}}});
    local["audit"] = json!({"dir": dir.path().join("l2").to_str().unwrap()});
    let path = write(&dir.path().join("t2.yaml"), &gatekeeper::yaml::dump(&local));
    let t2 = load_tier1(&path).unwrap();
    let spec = json!({"id": "sh.x", "toolkit": "sh", "binary": "/bin/true", "argv": [], "category": "read",
                      "title": "t", "description": "d", "parameters": {}, "verify": {"path": "/x"}});
    assert!(parse_tool_spec(&spec, &t2).unwrap_err().message.contains("'verify'"));
}

async fn call_save(verify: Value, name: &str, path: &str) -> (gatekeeper::execute::ExecResult, Vec<String>, AppEnv) {
    let (port, seen) = server().await;
    let mut tool = write_tool(verify);
    tool["path"] = json!(path);
    let e = builder().tier1(tier1_doc(port)).tools(vec![tool]).build();
    let who = agent("bot", &["api.save"], &[]);
    let r = e.service.call(&who, "api.save", &args(json!({"name": name})), None).await.unwrap();
    let s = seen.lock().unwrap().clone();
    (r, s, e)
}

#[tokio::test]
async fn verify_reads_back_after_a_successful_main_request() {
    let (r, seen, e) = call_save(json!({"path": "/api/items/{name}", "query": {"full": "1"}}), "abc", "/api/save/{name}").await;
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
    assert_eq!(seen, ["POST /api/save/abc", "GET /api/items/abc?full=1"]);
    let out: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(out["main"]["status"], 200);
    assert_eq!(out["verify"]["outcome"], "ok");
    assert!(out["verify"]["body"].as_str().unwrap().contains("abc"));
    assert!(r.external_untrusted);
    let record = e.audit_lines().pop().unwrap();
    assert_eq!(record["outcome"], "ok");
    let command = record["command"].as_str().unwrap();
    assert!(command.contains("; verify: GET /api/items/abc?full=1"), "{command}");
}

#[tokio::test]
async fn a_failed_verify_fails_the_call_and_says_so() {
    let (r, seen, _e) = call_save(json!({"path": "/api/items/missing"}), "abc", "/api/save/{name}").await;
    assert_eq!(seen.len(), 2);
    assert_eq!(r.outcome, "failed");
    assert!(r.stderr.starts_with("VERIFY FAILED: the main request succeeded (HTTP 200), but the verify request did not (HTTP 404)."), "{}", r.stderr);
    let out: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(out["verify"]["status"], 404);
}

#[tokio::test]
async fn require_body_turns_an_empty_200_into_a_failure() {
    let (r, _, _e) = call_save(json!({"path": "/api/items/empty"}), "abc", "/api/save/{name}").await;
    assert_eq!(r.outcome, "ok", "without require_body an empty 200 passes");
    let (r, _, _e) = call_save(json!({"path": "/api/items/empty", "require_body": true}), "abc", "/api/save/{name}").await;
    assert_eq!(r.outcome, "failed");
    assert!(r.stderr.contains("verify response body is empty (require_body)."), "{}", r.stderr);
}

#[tokio::test]
async fn no_verify_when_the_main_request_failed() {
    let (r, seen, _e) = call_save(json!({"path": "/api/items/{name}"}), "abc", "/api/fail").await;
    assert_eq!(seen, ["POST /api/fail"], "nothing to read back");
    assert_eq!(r.outcome, "failed");
    let out: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(out["verify"]["skipped"], "main request did not succeed");
    assert_eq!(out["main"]["status"], 500);
}

#[tokio::test]
async fn a_tool_without_verify_answers_as_before() {
    let (port, _) = server().await;
    let e = builder().tier1(tier1_doc(port)).tools(vec![search_tool()]).build();
    let who = agent("bot", &["api.search"], &[]);
    let r = e.service.call(&who, "api.search", &args(json!({"term": "abc"})), None).await.unwrap();
    assert_eq!(r.stdout, r#"{"echo": true}"#);
}

#[tokio::test]
async fn a_verify_that_errors_out_keeps_the_main_result() {
    // The main POST succeeds, and while it is answered the credential
    // store becomes unreadable: the verify request then fails inside the
    // executor (a `ConfigError`, not an HTTP status). The write happened,
    // so its result must survive as a failed verify, not vanish.
    let target: Arc<Mutex<Option<std::path::PathBuf>>> = Arc::default();
    let hook = target.clone();
    let (port, seen) = server_with(move || {
        if let Some(path) = hook.lock().unwrap().as_ref() {
            std::fs::write(path, "credentials: [not, a, mapping\n").unwrap();
        }
    })
    .await;
    let mut doc = tier1_doc(port);
    doc["toolkits"]["api"]["credential"] = json!("api-key");
    let e = builder().tier1(doc).tools(vec![write_tool(json!({"path": "/api/items/{name}"}))]).credentials().build();
    e.credentials.as_ref().unwrap().create("api-key", "bearer", "s3cret-value", None, None, None, "root", "").unwrap();
    *target.lock().unwrap() = Some(e.tmp.join("credentials.yaml"));

    let who = agent("bot", &["api.save"], &[]);
    let r = e.service.call(&who, "api.save", &args(json!({"name": "abc"})), None).await.unwrap();
    assert_eq!(seen.lock().unwrap().as_slice(), ["POST /api/save/abc"], "the write went out, the verify could not");
    assert_eq!(r.outcome, "failed");
    assert!(
        r.stderr.starts_with("VERIFY FAILED: the main request succeeded (HTTP 200), but the verify request did not (HTTP None). verify request could not be sent: "),
        "{}",
        r.stderr
    );
    let out: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(out["main"]["outcome"], "ok");
    assert_eq!(out["main"]["status"], 200);
    assert_eq!(out["main"]["body"], r#"{"ok": true}"#);
    assert_eq!(out["verify"]["outcome"], "failed");
    assert!(!r.stdout.contains("s3cret-value") && !r.stderr.contains("s3cret-value"));
    let record = e.audit_lines().pop().unwrap();
    assert_eq!(record["outcome"], "failed");
}
