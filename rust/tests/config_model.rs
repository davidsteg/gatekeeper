//! Catalog/Tier 1/validate behaviour, ported from `test_catalog_versioning`,
//! `test_destinations`, `test_nested_body`, `test_http_raw_body`,
//! `test_mcp_schema_pattern`, `test_docker_compose_argv`, `test_behaviour`
//! and `test_outlook_tools` (the parts that touch these modules; the store,
//! service, MCP transport and executor halves are ported with those).

mod common;

use std::collections::HashSet;

use common::*;
use gatekeeper::catalog::{
    append_tool_version, collect_template_strings, load_catalog, nested_body_map, new_tool_entry,
    normalize_tool_entry, now_iso, parse_tool_spec, soft_delete_entry,
};
use gatekeeper::errors::DenialReason;
use gatekeeper::tier1::{load_tier1, Toolkit};
use gatekeeper::validate::{
    build_agent_call, build_argv, build_artifact_call, build_http_request, build_microsoft_call,
    build_opencode_call, check_directory, resolve_body_template, resolve_parameters, resolve_scopes, Values,
};
use serde_json::{json, Map, Value};

fn vals(pairs: &[(&str, &str)]) -> Values {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

struct Demo {
    _dir: tempfile::TempDir,
    tmp: std::path::PathBuf,
    sandbox: std::path::PathBuf,
    tier1: gatekeeper::tier1::Tier1,
}

fn demo() -> Demo {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path().to_path_buf();
    let sb = sandbox(&tmp);
    let tier1 = demo_tier1(&tmp, &sb);
    Demo { _dir: dir, tmp, sandbox: sb, tier1 }
}

// -- test_catalog_versioning ---------------------------------------------------

fn versioned_entry(tool_id: &str, toolkit: &str, binary: &str) -> Value {
    json!({
        "id": tool_id, "enabled": true, "current_version": 1, "deleted": false,
        "versions": [{
            "version": 1,
            "spec": {
                "toolkit": toolkit, "binary": binary, "title": "Show", "description": "d",
                "category": "read", "idempotent": true, "argv": ["-c", "print(1)"],
                "parameters": {}, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096,
            },
            "created_at": now_iso(), "created_by": "root", "superseded": false,
        }],
    })
}

#[test]
fn legacy_flat_tools_yaml_still_loads() {
    let d = demo();
    let c = catalog_ok(&d.tmp, &d.tier1, &tool_specs(&d.sandbox));
    assert_eq!(c.tools.keys().collect::<Vec<_>>(), vec!["demo.show", "demo.echo"]);
    assert_eq!(c.tools["demo.show"].version, 1);
    let flat = c.flat_spec_of("demo.show").unwrap();
    assert_eq!(flat["id"], "demo.show");
    assert_eq!(flat["toolkit"], "demo");
    assert_eq!(flat["enabled"], true);
}

#[test]
fn versioned_entry_loads_like_a_flat_one_and_deleted_is_kept_in_raw() {
    let d = demo();
    let c = catalog_ok(&d.tmp, &d.tier1, &[versioned_entry("demo.v1", "demo", PYTHON)]);
    assert_eq!(c.tools["demo.v1"].version, 1);
    assert_eq!(c.tools["demo.v1"].category, "read");
    let flat = c.flat_spec_of("demo.v1").unwrap();
    assert_eq!(flat["id"], "demo.v1");
    assert_eq!(flat["version"], 1);

    let mut deleted = versioned_entry("demo.v1", "demo", PYTHON);
    deleted["deleted"] = json!(true);
    let c = catalog_ok(&d.tmp, &d.tier1, &[deleted]);
    assert!(!c.tools.contains_key("demo.v1"));
    assert_eq!(c.raw_of("demo.v1").unwrap()["deleted"], true);
    assert!(c.flat_spec_of("demo.v1").is_none());

    let mut mismatch = versioned_entry("demo.v1", "demo", PYTHON);
    mismatch["current_version"] = json!(99);
    let msg = err_text(make_catalog(&d.tmp, &d.tier1, &[mismatch], true));
    assert_eq!(msg, "tools.yaml: entry 'demo.v1' has a 'current_version' that matches none of its 'versions'");
}

#[test]
fn version_entries_are_append_only() {
    let spec = obj(json!({"id": "x.y", "toolkit": "x", "enabled": true, "category": "read"}));
    let entry = new_tool_entry("x.y", &spec, "root", "2020-01-01T00:00:00");
    assert_eq!(entry["current_version"], 1);
    assert_eq!(entry["deleted"], false);
    assert_eq!(entry["versions"][0]["superseded"], false);
    assert_eq!(entry["versions"][0]["spec"], json!({"toolkit": "x", "category": "read"}));
    assert_eq!(entry["versions"][0]["created_by"], "root");

    let legacy = obj(json!({"id": "x.y", "toolkit": "x", "enabled": true, "category": "read", "title": "old"}));
    let new_spec = obj(json!({"id": "x.y", "toolkit": "x", "enabled": true, "category": "read", "title": "new"}));
    let e = append_tool_version(&legacy, "x.y", &new_spec, "root", "t2").unwrap();
    assert_eq!(e["current_version"], 2);
    assert_eq!(e["versions"][0], json!({"version": 1, "spec": {"toolkit": "x", "category": "read", "title": "old"},
        "created_at": null, "created_by": null, "superseded": true}));
    assert_eq!(e["versions"][1]["spec"]["title"], "new");
    assert_eq!(e["versions"][1]["superseded"], false);

    let mut e = new_tool_entry("x.y", &obj(json!({"id": "x.y", "title": "v1"})), "a", "t1");
    for (t, at) in [("v2", "t2"), ("v3", "t3")] {
        e = append_tool_version(e.as_object().unwrap(), "x.y", &obj(json!({"id": "x.y", "title": t})), "a", at).unwrap();
    }
    assert_eq!(e["current_version"], 3);
    let titles: Vec<&str> = e["versions"].as_array().unwrap().iter().map(|v| v["spec"]["title"].as_str().unwrap()).collect();
    assert_eq!(titles, vec!["v1", "v2", "v3"]);
    let sup: Vec<bool> = e["versions"].as_array().unwrap().iter().map(|v| v["superseded"].as_bool().unwrap()).collect();
    assert_eq!(sup, vec![true, true, false]);
    // `enabled` is inherited from the entry when the new spec has none.
    assert_eq!(e["enabled"], false);

    let deleted = soft_delete_entry(new_tool_entry("x.y", &obj(json!({"id": "x.y", "title": "v1"})), "a", "t1").as_object().unwrap());
    assert_eq!(deleted["deleted"], true);
    assert_eq!(deleted["versions"][0]["spec"]["title"], "v1");
    let flat_deleted = soft_delete_entry(&obj(json!({"id": "x.y", "title": "f", "enabled": true})));
    assert_eq!(flat_deleted["versions"][0]["spec"], json!({"title": "f"}));
    assert_eq!(flat_deleted["enabled"], true);

    let flat = obj(json!({"id": "x.y", "toolkit": "x", "enabled": true, "category": "write"}));
    let versioned = new_tool_entry("x.z", &obj(json!({"id": "x.z", "category": "read"})), "a", "t1");
    assert_eq!(normalize_tool_entry(&flat)["category"], "write");
    assert_eq!(normalize_tool_entry(&flat)["current_version"], 1);
    assert_eq!(normalize_tool_entry(versioned.as_object().unwrap())["category"], "read");
    assert_eq!(normalize_tool_entry(versioned.as_object().unwrap())["current_version"], 1);
}

#[test]
fn now_iso_is_utc_with_offset() {
    let s = now_iso();
    assert!(s.ends_with("+0000"), "{s}");
    assert_eq!(s.len(), "2026-01-01T00:00:00+0000".len());
}

// -- test_destinations (Tier 1 and catalog) -------------------------------------

#[test]
fn destination_expands_docker_toolkit() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1_text(
        dir.path(),
        &format!(
            "destinations:\n  nas1:\n    docker_host: \"unix:///var/run/docker.sock\"\n  nas2:\n    \
             docker_host: \"tcp://nas2.lan:2376\"\n    docker_tls: true\n    credential: docker-nas2-tls\n\
             toolkits:\n  docker:\n    executor: docker\n    destinations: [nas1, nas2]\n    binaries: [\"{PYTHON}\"]\n"
        ),
    )
    .unwrap();
    assert_eq!(t.toolkit("docker").unwrap().destinations, vec!["nas1", "nas2"]);
    let nas1 = t.destination("nas1").unwrap();
    assert_eq!(nas1.docker_host.as_deref(), Some("unix:///var/run/docker.sock"));
    assert_eq!(nas1.docker_tls, None);
    let nas2 = t.destination("nas2").unwrap();
    assert_eq!(nas2.docker_tls, Some(true));
    assert_eq!(nas2.credential.as_deref(), Some("docker-nas2-tls"));
    assert_eq!(
        t.credential_references().get("docker-nas2-tls").unwrap(),
        &vec!["nas2 (destination)".to_string()]
    );
    assert_eq!(err_text(t.destination("ghost")), "Unknown destination 'ghost'");

    let plain = tier1_text(
        dir.path(),
        &format!("destinations:\n  plain:\n    docker_host: \"unix:///p.sock\"\n    docker_tls: false\ntoolkits:\n  docker:\n    executor: docker\n    docker_tls: true\n    destinations: [plain]\n    binaries: [\"{PYTHON}\"]\n"),
    )
    .unwrap();
    assert_eq!(plain.destination("plain").unwrap().docker_tls, Some(false));
    assert!(plain.toolkit("docker").unwrap().docker_tls);
}

#[test]
fn toolkit_without_destinations_is_unaffected() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1_text(dir.path(), &format!("toolkits:\n  demo:\n    executor: local\n    binaries: [\"{PYTHON}\"]\n")).unwrap();
    assert!(t.destinations.is_empty());
    assert!(t.toolkit("demo").unwrap().destinations.is_empty());
    assert!(t.toolkit("demo").unwrap().docker_host.is_none());
}

fn docker_tier1(tmp: &std::path::Path, dests: &[&str]) -> gatekeeper::tier1::Tier1 {
    let mut text = String::new();
    if !dests.is_empty() {
        text.push_str("destinations:\n");
        for d in dests {
            text.push_str(&format!("  {d}:\n    docker_host: \"unix:///var/run/{d}.sock\"\n"));
        }
    }
    text.push_str("toolkits:\n  docker:\n    executor: docker\n");
    if !dests.is_empty() {
        text.push_str(&format!("    destinations: [{}]\n", dests.join(", ")));
    }
    text.push_str(&format!("    binaries: [\"{PYTHON}\"]\n    denied_args: []\n    path_roots: []\n"));
    tier1_text(tmp, &text).unwrap()
}

fn compose_up_spec() -> Value {
    json!({
        "id": "docker.compose_up", "toolkit": "docker", "binary": PYTHON, "version": 1,
        "title": "Compose up", "description": "Brings a stack up.", "category": "write",
        "idempotent": true, "enabled": true, "argv": ["-c", "print('up')"], "parameters": {},
        "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 4096,
    })
}

#[test]
fn tool_expands_into_one_id_per_destination() {
    let dir = tempfile::tempdir().unwrap();
    let t = docker_tier1(dir.path(), &["nas1", "nas2"]);
    let c = catalog_ok(dir.path(), &t, &[compose_up_spec()]);
    assert_eq!(c.tools.keys().collect::<Vec<_>>(), vec!["docker.compose_up@nas1", "docker.compose_up@nas2"]);
    let (a, b) = (&c.tools["docker.compose_up@nas1"], &c.tools["docker.compose_up@nas2"]);
    assert_eq!(a.destination.as_deref(), Some("nas1"));
    assert_eq!(b.destination.as_deref(), Some("nas2"));
    assert_eq!(a.argv, b.argv);
    // The persisted YAML keeps the bare id.
    assert_eq!(c.raw_of("docker.compose_up").cloned().map(Value::Object), Some(compose_up_spec()));
    assert!(c.raw_of("docker.compose_up@nas1").is_none());
    assert_eq!(c.grantable_ids("docker.compose_up"), vec!["docker.compose_up@nas1", "docker.compose_up@nas2"]);
    assert_eq!(c.grantable_ids("docker.compose_up@nas2"), vec!["docker.compose_up@nas2"]);
    assert!(c.grantable_ids("docker.compose").is_empty());

    let t = docker_tier1(dir.path(), &[]);
    let c = catalog_ok(dir.path(), &t, &[compose_up_spec()]);
    assert_eq!(c.tools.keys().collect::<Vec<_>>(), vec!["docker.compose_up"]);
    assert!(c.tools["docker.compose_up"].destination.is_none());
    assert_eq!(c.grantable_ids("docker.compose_up"), vec!["docker.compose_up"]);
}

#[test]
fn duplicate_tool_id_is_a_config_error() {
    let d = demo();
    let specs = tool_specs(&d.sandbox);
    let msg = err_text(make_catalog(&d.tmp, &d.tier1, &[specs[1].clone(), specs[1].clone()], false));
    assert_eq!(msg, "Duplicate tool ID 'demo.echo'");
}

// -- test_nested_body / test_http_raw_body ----------------------------------------

#[test]
fn nested_body_templates() {
    for v in [json!({"data": {"collection": "{collection}", "mode": "{mode}"}}), json!(["{a}", "{b}", 42, null]), json!(42), json!(true), Value::Null, json!("literal")] {
        assert_eq!(nested_body_map(&v, "test", "body").unwrap(), v);
    }
    let body = json!({"data": {"collection": "{collection}", "mode": "{mode}", "docID": ""}});
    assert_eq!(collect_template_strings(Some(&body)), vec!["{collection}", "{mode}", ""]);
    assert!(collect_template_strings(None).is_empty());

    let values = vals(&[("collection", "StatisticsJSONDB"), ("mode", "getAll")]);
    assert_eq!(
        resolve_body_template(&body, &values).unwrap(),
        json!({"data": {"collection": "StatisticsJSONDB", "mode": "getAll", "docID": ""}})
    );
    let err = resolve_body_template(&body, &vals(&[("collection", "x")])).unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamMissing);
    assert_eq!(err.detail, "Body template needs ['mode'].");
    let scalars = json!({"count": 42, "active": true, "tag": null, "name": "{name}"});
    assert_eq!(
        resolve_body_template(&scalars, &vals(&[("name", "test")])).unwrap(),
        json!({"count": 42, "active": true, "tag": null, "name": "test"})
    );
}

fn n8n_tier1(tmp: &std::path::Path) -> gatekeeper::tier1::Tier1 {
    tier1_text(
        tmp,
        "toolkits:\n  n8n_admin:\n    executor: http\n    base_url: \"http://127.0.0.1:5678\"\n    \
         allowed_methods: [\"GET\", \"POST\"]\n    allowed_path_prefixes: [\"/api/\"]\n    allowed_cidrs: [\"127.0.0.1/32\"]\n",
    )
    .unwrap()
}

fn workflow_create(t: &gatekeeper::tier1::Tier1, body: Value) -> gatekeeper::errors::ConfigResult<gatekeeper::catalog::ToolDef> {
    parse_tool_spec(
        &json!({
            "id": "n8n_admin.workflow_create", "toolkit": "n8n_admin", "version": 1,
            "title": "Create workflow", "description": "Creates a workflow.", "category": "write",
            "idempotent": false, "enabled": true, "method": "POST", "path": "/api/v1/workflows",
            "body": body,
            "parameters": {"workflow_json": {"type": "string", "pattern": "^.{1,30000}$", "required": true, "description": "doc"}},
            "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 65536,
        }),
        t,
    )
}

#[test]
fn raw_param_body_mode() {
    let dir = tempfile::tempdir().unwrap();
    let t = n8n_tier1(dir.path());
    let tool = workflow_create(&t, json!({"raw_param": "workflow_json"})).unwrap();
    assert_eq!(tool.body_raw_param.as_deref(), Some("workflow_json"));
    assert_eq!(tool.body_template, Some(json!({"workflow_json": "{workflow_json}"})));
    assert!(err_text(workflow_create(&t, json!({"raw_param": ["workflow_json"]}))).contains("raw_param"));
    assert!(err_text(workflow_create(&t, json!({"raw_param": "workflow_json", "name": "{name}"}))).contains("exactly one key"));
    assert!(err_text(workflow_create(&t, json!({"raw_param": "workflow_jsonn"}))).contains("unknown parameter"));
    let ordinary = workflow_create(&t, json!({"data": {"name": "{workflow_json}"}})).unwrap();
    assert!(ordinary.body_raw_param.is_none());
    assert_eq!(ordinary.body_template, Some(json!({"data": {"name": "{workflow_json}"}})));

    // The request parts the http executor will send.
    let doc = r#"{"name":"nightly-backup", "active":false}"#;
    let values = resolve_parameters(&tool, &args(json!({"workflow_json": doc}))).unwrap();
    let req = build_http_request(&tool, &values, t.toolkit("n8n_admin").unwrap()).unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/v1/workflows");
    assert_eq!(req.body, Some(json!({"workflow_json": doc})));
}

// -- test_mcp_schema_pattern / test_behaviour (schema) --------------------------

const SIX_SEGMENT_PATTERN: &str = r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,5}$";

#[test]
fn published_pattern_equals_the_definition_pattern() {
    let d = demo();
    let t = tier1_from(
        &d.tmp,
        &json!({"toolkits": {
            "file": {"executor": "file", "binaries": [], "path_roots": [d.sandbox.to_str().unwrap()],
                     "max_timeout_seconds": 30, "max_output_bytes": 131072},
            "selfdeploy2": {"executor": "local", "binaries": [PYTHON], "path_roots": [d.sandbox.to_str().unwrap()],
                            "max_timeout_seconds": 30, "max_output_bytes": 131072},
        }}),
    )
    .unwrap();
    let p = json!({"type": "string", "required": true, "pattern": SIX_SEGMENT_PATTERN, "description": "p"});
    let specs = vec![
        json!({"id": "file.write", "toolkit": "file", "executor": "file", "file_operation": "write",
               "title": "Write file", "description": "w", "category": "write", "enabled": true,
               "parameters": {"file": p, "content": {"type": "string", "required": true, "pattern": "[\\s\\S]*",
                              "allow_control_characters": true, "description": "File content"}},
               "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 65536}),
        json!({"id": "selfdeploy2.mv", "toolkit": "selfdeploy2", "binary": PYTHON, "title": "mv", "description": "mv",
               "category": "write", "enabled": true, "argv": ["-c", "print(1)", "{src}", "{dst}"],
               "parameters": {"src": p, "dst": p}, "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 65536}),
    ];
    let c = catalog_ok(&d.tmp, &t, &specs);
    for (id, param) in [("file.write", "file"), ("selfdeploy2.mv", "src"), ("selfdeploy2.mv", "dst")] {
        let tool = c.get(id).unwrap();
        let published = tool.input_schema()["properties"][param]["pattern"].clone();
        assert_eq!(published, SIX_SEGMENT_PATTERN);
        assert_eq!(published, tool.parameters[param].pattern.as_ref().unwrap().source.as_str());
        let re = tool.parameters[param].pattern.as_ref().unwrap();
        assert!(re.fullmatch("sub/file.yaml"));
        assert!(re.fullmatch("a/b/c/d/e/f"));
        assert!(!re.fullmatch("a/b/c/d/e/f/g"));
    }
    let mut bad = specs[0].clone();
    bad["parameters"]["file"]["pattern"] = json!(["^a$", "^b$"]);
    let msg = err_text(make_catalog(&d.tmp, &t, &[bad], true));
    assert_eq!(msg, "tool 'file.write': parameter 'file' has a non-string 'pattern' (list). Quote it.");
}

#[test]
fn schema_hides_derived_parameters_and_pattern_is_enforced_verbatim() {
    let d = demo();
    let c = catalog_ok(&d.tmp, &d.tier1, &tool_specs(&d.sandbox));
    let schema = c.get("demo.show").unwrap().input_schema();
    assert_eq!(
        serde_json::to_string(&schema).unwrap(),
        r#"{"type":"object","properties":{"stack":{"type":"string","pattern":"^[a-z0-9][a-z0-9_-]{0,62}$","description":"Stack name"}},"required":["stack"],"additionalProperties":false}"#
    );
    let echo = c.get("demo.echo").unwrap();
    assert_eq!(echo.agent_description(), "Outputs the given text.");

    let raw = r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$";
    let spec = json!({"id": "demo.cat", "toolkit": "demo", "binary": PYTHON, "title": "x", "description": "x",
        "category": "read", "idempotent": true, "enabled": true, "argv": ["-c", "print(1)", "{relpath}"],
        "parameters": {"relpath": {"type": "string", "required": true, "pattern": raw, "description": "rel"}},
        "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 1024});
    let c = catalog_ok(&d.tmp, &d.tier1, &[spec]);
    let tool = c.get("demo.cat").unwrap();
    assert_eq!(tool.input_schema()["properties"]["relpath"]["pattern"], raw);
    for good in ["sub/file.yaml", "file.yaml"] {
        assert_eq!(resolve_parameters(tool, &args(json!({"relpath": good}))).unwrap()["relpath"], good);
    }
    for bad in ["/abs/file.yaml", "sub//file.yaml", "sub/file.yaml\n"] {
        let err = resolve_parameters(tool, &args(json!({"relpath": bad}))).unwrap_err();
        assert!(matches!(err.reason, DenialReason::ParamInvalid | DenialReason::ControlCharacter));
    }
}

#[test]
fn integer_bounds() {
    let d = demo();
    let spec = json!({"id": "demo.tail", "toolkit": "demo", "binary": PYTHON, "title": "x", "description": "x",
        "category": "read", "idempotent": true, "enabled": true, "argv": ["-c", "print(1)", "{n}"],
        "parameters": {"n": {"type": "integer", "required": true, "minimum": 1, "maximum": 1000, "description": "x"}},
        "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 1024});
    let c = catalog_ok(&d.tmp, &d.tier1, &[spec]);
    let tool = c.get("demo.tail").unwrap();
    assert_eq!(resolve_parameters(tool, &args(json!({"n": 500}))).unwrap()["n"], "500");
    for bad in [0, 1001, -1] {
        assert_eq!(resolve_parameters(tool, &args(json!({"n": bad}))).unwrap_err().reason, DenialReason::ParamInvalid);
    }
    assert_eq!(
        resolve_parameters(tool, &args(json!({"n": 0}))).unwrap_err().detail,
        "Parameter 'n': 0 is below the minimum 1."
    );
    assert_eq!(
        resolve_parameters(tool, &args(json!({"n": 1001}))).unwrap_err().detail,
        "Parameter 'n': 1001 exceeds the maximum 1000."
    );
    for bad in [json!(true), json!(5.0), json!("5")] {
        assert_eq!(
            resolve_parameters(tool, &args(json!({"n": bad}))).unwrap_err().detail,
            "Parameter 'n' expects an integer."
        );
    }
    assert_eq!(
        tool.input_schema()["properties"]["n"],
        json!({"type": "integer", "minimum": 1, "maximum": 1000, "description": "x"})
    );
    let missing = resolve_parameters(tool, &Map::new()).unwrap_err();
    assert_eq!(missing.detail, "Required parameter 'n' is missing.");
}

#[test]
fn derived_path_and_scopes_resolve() {
    let d = demo();
    let c = catalog_ok(&d.tmp, &d.tier1, &tool_specs(&d.sandbox));
    let tool = c.get("demo.show").unwrap();
    let values = resolve_parameters(tool, &args(json!({"stack": "media-jellyfin"}))).unwrap();
    assert_eq!(resolve_scopes(tool, &values).unwrap(), vec!["stack:media-jellyfin"]);
    let argv = build_argv(tool, &values, d.tier1.toolkit("demo").unwrap()).unwrap();
    assert_eq!(argv[3], values["compose_path"]);
}

// -- test_behaviour (configuration) --------------------------------------------

#[test]
fn missing_and_empty_catalogs() {
    let d = demo();
    let c = load_catalog(d.tmp.join("does-not-exist.yaml").to_str().unwrap(), &d.tier1, false).unwrap();
    assert!(c.tools.is_empty() && c.raw.is_empty());
    let path = d.tmp.join("empty.yaml");
    for body in ["tools: []\n", "tools:\n", ""] {
        std::fs::write(&path, body).unwrap();
        assert!(load_catalog(path.to_str().unwrap(), &d.tier1, false).unwrap().tools.is_empty());
    }
    std::fs::write(&path, "tools: {}\n").unwrap();
    assert_eq!(
        err_text(load_catalog(path.to_str().unwrap(), &d.tier1, false)),
        "tools.yaml: section 'tools' is missing or not a list"
    );
}

#[test]
fn missing_and_empty_tier1() {
    let dir = tempfile::tempdir().unwrap();
    let msg = err_text(load_tier1(dir.path().join("missing.yaml").to_str().unwrap()));
    assert!(msg.contains("gatekeeper init"));
    let path = dir.path().join("toolkits.yaml");
    for body in ["toolkits: {}\n", "toolkits:\n"] {
        std::fs::write(&path, format!("{body}audit:\n  dir: /tmp/x\n")).unwrap();
        let t = load_tier1(path.to_str().unwrap()).unwrap();
        assert!(t.toolkits.is_empty());
        assert_eq!(t.rate_limits.keys().collect::<Vec<_>>(), vec!["read", "write", "write_external"]);
        assert_eq!(t.max_concurrent, 4);
        assert_eq!(t.audit_dir, "/tmp/x");
    }
}

#[test]
fn shipped_config_is_valid() {
    let ex = examples_dir();
    let tier1 = load_tier1(ex.join("toolkits.yaml").to_str().unwrap()).unwrap();
    let c = load_catalog(ex.join("tools.yaml").to_str().unwrap(), &tier1, true).unwrap();
    assert!(c.tools.contains_key("docker.compose_up@nas1"));
    assert!(c.tools.contains_key("docker.compose_up@nas2"));
    assert!(!c.tools.contains_key("docker.compose_up"));
    assert!(c.tools.contains_key("diag.uptime"));
    assert!(c.disabled_by_tier1.is_empty());
    for tool in c.tools.values().filter(|t| t.toolkit == "docker") {
        assert_eq!(tool.required_scopes, vec!["stack:{stack}"], "{}", tool.id);
    }
    let docker = tier1.toolkit("docker").unwrap();
    for critical in ["gatekeeper", "dockhand", "ix-dockhand"] {
        assert!(docker.is_protected(critical));
    }
    for flag in ["-v", "--volumes", "--rmi", "rm", "prune"] {
        assert_eq!(docker.check_args(&["compose", flag]).as_deref(), Some(flag));
    }
    let argv = &c.tools["docker.compose_ps@nas1"].argv;
    assert_eq!(&argv[argv.len() - 2..], &["--format".to_string(), "json".to_string()]);
}

#[test]
fn removed_toolkit_or_changed_executor_disables_not_fatal() {
    let d = demo();
    let empty_path = d.tmp.join("empty-tier1.yaml");
    std::fs::write(&empty_path, "toolkits: {}\n").unwrap();
    let empty = load_tier1(empty_path.to_str().unwrap()).unwrap();
    let c = make_catalog(&d.tmp, &empty, &tool_specs(&d.sandbox), false).unwrap();
    assert!(c.tools.is_empty());
    assert_eq!(c.disabled_by_tier1.len(), 2);
    assert!(c.disabled_by_tier1[0].contains("Unknown toolkit"));
    assert!(make_catalog(&d.tmp, &empty, &tool_specs(&d.sandbox), true).unwrap_err().is_tier1_violation());

    let file_tier1 = tier1_from(
        &d.tmp,
        &json!({"toolkits": {"demo": {"executor": "file", "path_roots": [d.sandbox.to_str().unwrap()],
                "protected_resources": [], "max_timeout_seconds": 10, "max_output_bytes": 4096}}}),
    )
    .unwrap();
    let stale = json!({"id": "demo.chown", "toolkit": "demo", "binary": "/usr/bin/chown", "argv": [],
        "title": "x", "description": "x", "category": "write", "idempotent": false, "enabled": true,
        "parameters": {}, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 1024});
    let c = make_catalog(&d.tmp, &file_tier1, &[stale.clone()], false).unwrap();
    assert!(c.tools.is_empty());
    assert!(c.disabled_by_tier1[0].contains("file_operation"));
    assert_eq!(c.rejected[0].0["id"], "demo.chown");
    assert!(make_catalog(&d.tmp, &file_tier1, &[stale], true).is_err());
}

#[test]
fn missing_local_binaries() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1_from(
        dir.path(),
        &json!({"toolkits": {
            "zfs": {"executor": "local", "binaries": ["/usr/bin/zfs-not-here", "/usr/bin/zpool-not-here"]},
            "diag": {"executor": "local", "binaries": [PYTHON]},
            "linux": {"executor": "ssh", "ssh_host": "diag-host.lan", "ssh_user": "gatekeeper",
                      "ssh_known_hosts": "diag-host.lan ssh-ed25519 AAAAC3Nza", "binaries": ["/usr/sbin/zfs-x"]},
        }}),
    )
    .unwrap();
    let missing = t.missing_local_binaries();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing["zfs"], vec!["/usr/bin/zfs-not-here", "/usr/bin/zpool-not-here"]);
    assert!(gatekeeper::tier1::is_runnable(PYTHON));
    assert!(!gatekeeper::tier1::is_runnable("/etc/passwd"));
}

// -- test_docker_compose_argv ----------------------------------------------------

#[test]
fn shipped_docker_tools_keep_compose_before_p() {
    let ex = examples_dir();
    let tier1 = load_tier1(ex.join("toolkits.yaml").to_str().unwrap()).unwrap();
    let c = load_catalog(ex.join("tools.yaml").to_str().unwrap(), &tier1, true).unwrap();
    let values = vals(&[("stack", "jellyfin"), ("compose_path", "/mnt/raid/jellyfin/compose.yaml"), ("tail", "100")]);
    let docker = tier1.toolkit("docker").unwrap();
    let tools: Vec<_> = c.tools.values().filter(|t| t.toolkit == "docker").collect();
    assert!(!tools.is_empty());
    for tool in tools {
        let argv = build_argv(tool, &values, docker).unwrap();
        assert_eq!(argv[..4], [tool.binary.clone().unwrap(), "compose".into(), "-p".into(), "jellyfin".into()], "{}", tool.id);
    }
    assert_eq!(
        build_argv(&c.tools["docker.compose_ps@nas1"], &values, docker).unwrap(),
        vec!["/usr/bin/docker", "compose", "-p", "jellyfin", "-f", "/mnt/raid/jellyfin/compose.yaml", "ps", "--format", "json"]
    );
    // The builder inserts nothing.
    let mut spec = c.flat_spec_of("docker.compose_ps").unwrap();
    assert_eq!(spec["argv"][0], "compose");
    let rest: Vec<Value> = spec["argv"].as_array().unwrap()[1..].to_vec();
    spec.insert("argv".into(), Value::Array(rest));
    let tool = parse_tool_spec(&Value::Object(spec), &tier1).unwrap();
    let argv = build_argv(&tool, &values, docker).unwrap();
    assert_eq!(argv[..3], ["/usr/bin/docker".to_string(), "-p".into(), "jellyfin".into()]);
    assert!(!argv.contains(&"compose".to_string()));
}

// -- test_outlook_tools (catalog level) ---------------------------------------

#[test]
fn outlook_argv_tail_is_one_element_per_parameter() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1_from(
        dir.path(),
        &json!({"toolkits": {"outlook": {"executor": "microsoft", "microsoft_script": PYTHON,
            "allowed_microsoft_actions": ["mail list", "mail get"], "credential": "microsoft"}}}),
    )
    .unwrap();
    let tk = t.toolkit("outlook").unwrap();
    let base = json!({"id": "outlook.list_messages", "toolkit": "outlook", "version": 1, "title": "List mail",
        "description": "d", "category": "read", "idempotent": true, "enabled": true, "microsoft_action": "mail list",
        "microsoft_args": {"folder": {"flag": "--folder"}, "max_results": {"flag": "--max"}},
        "parameters": {"folder": {"type": "string", "required": false, "pattern": "^[A-Za-z0-9=_-]{1,200}$", "description": "F"},
                       "max_results": {"type": "integer", "required": false, "minimum": 1, "maximum": 100, "description": "M"}},
        "required_scopes": ["Mail.Read"], "timeout_seconds": 10, "max_output_bytes": 65536});
    let tool = parse_tool_spec(&base, &t).unwrap();
    assert_eq!(
        build_microsoft_call(&tool, &vals(&[("folder", "inbox --max 999"), ("max_results", "10")]), tk).unwrap(),
        vec!["--folder", "inbox --max 999", "--max", "10"]
    );
    let mut get = base.clone();
    get["id"] = json!("outlook.get_message");
    get["microsoft_action"] = json!("mail get");
    get["microsoft_args"] = json!({"message_id": {"positional": true}});
    get["parameters"] = json!({"message_id": {"type": "string", "required": true, "pattern": "^[A-Za-z0-9=_-]{1,512}$", "description": "ID."}});
    let tool = parse_tool_spec(&get, &t).unwrap();
    assert_eq!(build_microsoft_call(&tool, &vals(&[("message_id", "AAMk-1")]), tk).unwrap(), vec!["AAMk-1"]);
    let mut del = base.clone();
    del["id"] = json!("outlook.delete");
    del["microsoft_action"] = json!("mail delete");
    del["microsoft_args"] = json!({});
    let err = parse_tool_spec(&del, &t).unwrap_err();
    assert!(err.is_tier1_violation());
}

// -- opencode / agent / artifact call checks ------------------------------------

#[test]
fn opencode_agent_and_artifact_call_checks() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir_all(work.join("repo")).unwrap();
    let w = work.to_str().unwrap();
    let t = tier1_from(
        dir.path(),
        &json!({"toolkits": {
            "oc": {"executor": "opencode", "base_url": "http://oc:4096", "allowed_cidrs": ["10.0.0.0/8"],
                   "allowed_opencode_operations": ["ask", "check"], "path_roots": [w]},
            "agent": {"executor": "agent", "mailbox_path": "/data/m.yaml",
                      "allowed_agent_operations": ["send_message", "read_messages", "mailbox_status"]},
            "art": {"executor": "artifact", "allowed_artifact_operations": ["info"], "allowed_artifacts": ["skill"]},
        }}),
    )
    .unwrap();
    let s = json!({"type": "string", "pattern": "^.{1,200}$", "required": true, "description": "s"});
    let opt = json!({"type": "string", "pattern": "^.{0,200}$", "required": false, "description": "s"});
    let base = |id: &str, tk: &str, extra: Value| {
        let mut spec = json!({"id": id, "toolkit": tk, "title": "t", "description": "d", "category": "read",
            "enabled": true, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 1024});
        for (k, v) in extra.as_object().unwrap() {
            spec[k] = v.clone();
        }
        parse_tool_spec(&spec, &t).unwrap()
    };
    let oc = t.toolkit("oc").unwrap();
    let ask = base("oc.ask", "oc", json!({"opencode_operation": "ask", "parameters": {"prompt": s, "directory": opt, "session_id": opt}}));
    assert_eq!(build_opencode_call(&ask, &vals(&[("prompt", "hi")]), oc).unwrap(), "ask");
    let repo = format!("{w}/repo");
    assert_eq!(build_opencode_call(&ask, &vals(&[("prompt", "hi"), ("directory", &repo)]), oc).unwrap(), "ask");
    let err = build_opencode_call(&ask, &vals(&[("prompt", "hi"), ("directory", "/etc")]), oc).unwrap_err();
    assert_eq!(err.reason, DenialReason::PathEscape);
    assert_eq!(err.detail, format!("directory '/etc' lies outside this toolkit's path_roots ['{w}']."));
    let err = build_opencode_call(&ask, &vals(&[("prompt", "hi"), ("directory", &format!("{w}/missing"))]), oc).unwrap_err();
    assert_eq!(err.detail, format!("directory '{w}/missing' does not exist."));
    let err = build_opencode_call(&ask, &vals(&[("prompt", "hi"), ("session_id", "../x")]), oc).unwrap_err();
    assert_eq!(err.detail, "session_id must be 1-128 characters of A-Z, a-z, 0-9, '_' or '-'.");
    let check = base("oc.check", "oc", json!({"opencode_operation": "check", "parameters": {"session_id": s}}));
    assert!(build_opencode_call(&check, &Values::new(), oc).is_err());
    assert_eq!(build_opencode_call(&check, &vals(&[("session_id", "ses_1")]), oc).unwrap(), "check");
    assert_eq!(
        check_directory("relative", oc).unwrap_err().detail,
        "directory 'relative' must be an absolute path."
    );
    assert_eq!(check_directory(&format!("{w}/a/../b"), oc).unwrap_err().reason, DenialReason::PathEscape);
    let no_roots = Toolkit { name: "x".into(), ..Toolkit::default() };
    assert_eq!(check_directory("/a", &no_roots).unwrap_err().reason, DenialReason::Tier1Violation);

    let agent = t.toolkit("agent").unwrap();
    let send = base("agent.send", "agent", json!({"agent_operation": "send_message", "parameters": {"to": s, "body": s}}));
    assert_eq!(build_agent_call(&send, &vals(&[("to", "hermes"), ("body", "x")]), agent, None).unwrap(), "send_message");
    assert!(build_agent_call(&send, &vals(&[("to", "bad id"), ("body", "x")]), agent, None).is_err());
    let known: HashSet<String> = ["hermes".to_string()].into();
    let err = build_agent_call(&send, &vals(&[("to", "ghost"), ("body", "x")]), agent, Some(&known)).unwrap_err();
    assert!(err.detail.starts_with("There is no identity 'ghost'."));
    let status = base("agent.status", "agent", json!({"agent_operation": "mailbox_status", "parameters": {}}));
    assert_eq!(build_agent_call(&status, &Values::new(), agent, Some(&known)).unwrap(), "mailbox_status");

    let art = t.toolkit("art").unwrap();
    let info = base("art.info", "art", json!({"artifact_operation": "info", "parameters": {"artifact": s, "version": opt}}));
    assert_eq!(build_artifact_call(&info, &vals(&[("artifact", "skill")]), art).unwrap(), "info");
    assert!(build_artifact_call(&info, &vals(&[("artifact", "Skill")]), art).is_err());
    assert!(build_artifact_call(&info, &vals(&[("artifact", "skill"), ("version", "abc")]), art).is_err());
    assert!(build_artifact_call(&info, &vals(&[("artifact", "skill"), ("version", "abcdef0")]), art).is_ok());
}

#[test]
fn file_tool_run_as_override() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1_from(dir.path(), &json!({"toolkits": {"files": {"executor": "file", "path_roots": ["/srv"], "run_as": "hermes"}}})).unwrap();
    assert_eq!(t.toolkit("files").unwrap().run_as.as_deref(), Some("hermes"));
    let mk = |run_as: Option<Value>| {
        let mut spec = json!({"id": "files.read", "toolkit": "files", "file_operation": "read", "title": "t",
            "description": "d", "category": "read", "enabled": true, "parameters": {}, "required_scopes": []});
        if let Some(r) = run_as {
            spec["run_as"] = r;
        }
        parse_tool_spec(&spec, &t)
    };
    assert_eq!(mk(None).unwrap().run_as, None);
    assert_eq!(mk(Some(Value::Null)).unwrap().run_as, None);
    assert_eq!(mk(Some(json!("  "))).unwrap().run_as.as_deref(), Some(""));
    assert_eq!(mk(Some(json!(" 1:2 "))).unwrap().run_as.as_deref(), Some("1:2"));
    assert!(err_text(mk(Some(json!("1")))).starts_with("tool 'files.read': 'run_as' '1' is neither"));
}
