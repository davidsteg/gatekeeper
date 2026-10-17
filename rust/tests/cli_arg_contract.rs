//! `google_args`/`microsoft_args`: what the catalog accepts and the argv
//! `validate` builds from it (port of the catalog/validate parts of
//! `tests/test_cli_arg_contract.py`; the subprocess runs against the real
//! CLI grammars belong to the executor ports).

mod common;

use common::*;
use gatekeeper::catalog::{parse_tool_spec, ToolDef};
use gatekeeper::errors::{ConfigResult, Denied};
use gatekeeper::tier1::Tier1;
use gatekeeper::validate::{build_google_call, build_microsoft_call, resolve_parameters, Values};
use serde_json::{json, Value};

fn tier1(tmp: &std::path::Path) -> Tier1 {
    tier1_from(
        tmp,
        &json!({
            "toolkits": {
                "gmail": {
                    "executor": "google", "google_script": PYTHON,
                    "allowed_google_actions": ["gmail search"], "credential": "google",
                    "max_timeout_seconds": 60, "max_output_bytes": 131072,
                },
                "outlook": {
                    "executor": "microsoft", "microsoft_script": PYTHON,
                    "allowed_microsoft_actions": ["mail list", "mail get"], "credential": "microsoft",
                    "max_timeout_seconds": 60, "max_output_bytes": 131072,
                },
            },
            "audit": {"dir": tmp.join("logs").to_str().unwrap()},
        }),
    )
    .unwrap()
}

fn with(mut spec: Value, overrides: Value) -> Value {
    for (k, v) in overrides.as_object().unwrap() {
        spec[k] = v.clone();
    }
    spec
}

fn outlook_list(t: &Tier1, overrides: Value) -> ConfigResult<ToolDef> {
    let spec = json!({
        "id": "outlook.list_messages", "toolkit": "outlook", "version": 1,
        "title": "List mail", "description": "Lists Outlook messages.", "category": "read",
        "idempotent": true, "enabled": true, "microsoft_action": "mail list",
        "microsoft_args": {"folder": {"flag": "--folder"}, "max_results": {"flag": "--max"}},
        "parameters": {
            "folder": {"type": "string", "required": false, "pattern": "^[A-Za-z0-9=_-]{1,200}$", "description": "f"},
            "max_results": {"type": "integer", "required": false, "minimum": 1, "maximum": 100, "description": "m"},
        },
        "required_scopes": ["Mail.Read"], "timeout_seconds": 30, "max_output_bytes": 65536,
    });
    parse_tool_spec(&with(spec, overrides), t)
}

fn gmail_search(t: &Tier1, overrides: Value) -> ConfigResult<ToolDef> {
    let spec = json!({
        "id": "gmail.search", "toolkit": "gmail", "version": 1, "title": "Search mail",
        "description": "Searches Gmail.", "category": "read", "idempotent": true, "enabled": true,
        "google_action": "gmail search",
        "google_args": {"query": {"positional": true}, "max_results": {"flag": "--max"}},
        "parameters": {
            "query": {"type": "string", "required": true, "pattern": "^.{1,500}$", "description": "q"},
            "max_results": {"type": "integer", "required": false, "minimum": 1, "maximum": 500, "description": "m"},
        },
        "required_scopes": ["gmail.readonly"], "timeout_seconds": 30, "max_output_bytes": 65536,
    });
    parse_tool_spec(&with(spec, overrides), t)
}

fn res(tool: &ToolDef, a: Value) -> Result<Values, Denied> {
    resolve_parameters(tool, &args(a))
}

fn vals(pairs: &[(&str, &str)]) -> Values {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn omitted_optional_flags_are_left_off() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1(dir.path());
    let tool = outlook_list(&t, json!({})).unwrap();
    let tk = t.toolkit("outlook").unwrap();
    assert!(build_microsoft_call(&tool, &res(&tool, json!({})).unwrap(), tk).unwrap().is_empty());
    assert_eq!(
        build_microsoft_call(&tool, &res(&tool, json!({"folder": "archive"})).unwrap(), tk).unwrap(),
        vec!["--folder", "archive"]
    );
    assert_eq!(
        build_microsoft_call(&tool, &res(&tool, json!({"max_results": 25})).unwrap(), tk).unwrap(),
        vec!["--max", "25"]
    );
    let g = gmail_search(&t, json!({})).unwrap();
    assert_eq!(
        build_google_call(&g, &res(&g, json!({"query": "is:unread"})).unwrap(), t.toolkit("gmail").unwrap()).unwrap(),
        vec!["is:unread"]
    );
}

#[test]
fn schema_and_runtime_agree_about_what_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1(dir.path());
    for (tool, tk) in [(outlook_list(&t, json!({})).unwrap(), "outlook"), (gmail_search(&t, json!({})).unwrap(), "gmail")] {
        let schema = tool.input_schema();
        let required: Vec<&str> = schema["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        let mut supplied = serde_json::Map::new();
        for (name, p) in tool.agent_parameters() {
            if required.contains(&name.as_str()) {
                supplied.insert(name.clone(), if p.ptype == "string" { json!("x") } else { json!(1) });
            }
        }
        let values = resolve_parameters(&tool, &supplied).unwrap();
        let toolkit = t.toolkit(tk).unwrap();
        if tk == "gmail" {
            build_google_call(&tool, &values, toolkit).unwrap();
        } else {
            build_microsoft_call(&tool, &values, toolkit).unwrap();
        }
    }
}

#[test]
fn what_is_still_a_denial() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1(dir.path());
    let g = gmail_search(&t, json!({})).unwrap();
    let err = build_google_call(&g, &vals(&[("max_results", "5")]), t.toolkit("gmail").unwrap()).unwrap_err();
    assert_eq!(err.agent_message(), "google_args.'query' needs a value.");

    let optional_positional = gmail_search(
        &t,
        json!({
            "parameters": {"query": {"type": "string", "required": false, "pattern": "^.{1,500}$", "description": "q"}},
            "google_args": {"query": {"positional": true}},
        }),
    )
    .unwrap();
    assert!(build_google_call(&optional_positional, &Values::new(), t.toolkit("gmail").unwrap()).is_err());

    let typo = outlook_list(&t, json!({"microsoft_args": {"folder": {"flag": "--folder"}, "typo": {"flag": "--max"}}})).unwrap();
    let err = build_microsoft_call(&typo, &res(&typo, json!({"folder": "inbox"})).unwrap(), t.toolkit("outlook").unwrap())
        .unwrap_err();
    assert!(err.agent_message().contains("'typo' needs a value"));
}

fn google_switch(t: &Tier1) -> ToolDef {
    gmail_search(
        t,
        json!({
            "google_args": {"query": {"positional": true}, "raw_query": {"switch": "--raw-query"}, "max_results": {"flag": "--max"}},
            "parameters": {
                "query": {"type": "string", "required": true, "pattern": "^.{1,500}$", "description": "q"},
                "raw_query": {"type": "boolean", "required": false, "description": "r"},
                "max_results": {"type": "integer", "required": false, "minimum": 1, "maximum": 500, "description": "m"},
            },
        }),
    )
    .unwrap()
}

fn microsoft_switch(t: &Tier1) -> ToolDef {
    outlook_list(
        t,
        json!({
            "microsoft_args": {"folder": {"flag": "--folder"}, "unread": {"switch": "--unread"}},
            "parameters": {
                "folder": {"type": "string", "required": false, "pattern": "^[A-Za-z0-9=_-]{1,200}$", "description": "f"},
                "unread": {"type": "boolean", "required": false, "description": "u"},
            },
        }),
    )
    .unwrap()
}

#[test]
fn switches_emit_their_fixed_flag_or_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1(dir.path());
    let g = google_switch(&t);
    let gk = t.toolkit("gmail").unwrap();
    let call = |a: Value| build_google_call(&g, &res(&g, a).unwrap(), gk).unwrap();
    assert_eq!(call(json!({"query": "is:unread", "raw_query": true})), vec!["is:unread", "--raw-query"]);
    assert_eq!(call(json!({"query": "is:unread", "raw_query": false})), vec!["is:unread"]);
    assert_eq!(call(json!({"query": "is:unread"})), vec!["is:unread"]);
    assert_eq!(
        call(json!({"query": "is:unread", "raw_query": true, "max_results": 5})),
        vec!["is:unread", "--raw-query", "--max", "5"]
    );
    assert_eq!(call(json!({"query": "is:unread", "raw_query": false, "max_results": 5})), vec!["is:unread", "--max", "5"]);

    let m = microsoft_switch(&t);
    let mk = t.toolkit("outlook").unwrap();
    assert_eq!(build_microsoft_call(&m, &res(&m, json!({"unread": true})).unwrap(), mk).unwrap(), vec!["--unread"]);
    assert!(build_microsoft_call(&m, &res(&m, json!({"unread": false})).unwrap(), mk).unwrap().is_empty());
    assert!(build_microsoft_call(&m, &res(&m, json!({})).unwrap(), mk).unwrap().is_empty());
}

#[test]
fn a_switch_takes_a_boolean_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1(dir.path());
    let g = google_switch(&t);
    for smuggled in [json!("true"), json!("--max 999"), json!(1)] {
        assert!(res(&g, json!({"query": "is:unread", "raw_query": smuggled})).is_err());
    }
    let err = build_google_call(&g, &vals(&[("query", "is:unread"), ("raw_query", "--max 999")]), t.toolkit("gmail").unwrap())
        .unwrap_err();
    assert!(err.agent_message().contains("raw_query"));

    let required = gmail_search(
        &t,
        json!({
            "google_args": {"query": {"positional": true}, "raw_query": {"switch": "--raw-query"}},
            "parameters": {
                "query": {"type": "string", "required": true, "pattern": "^.{1,500}$", "description": "q"},
                "raw_query": {"type": "boolean", "required": true, "description": "r"},
            },
        }),
    )
    .unwrap();
    let err = build_google_call(&required, &vals(&[("query", "is:unread")]), t.toolkit("gmail").unwrap()).unwrap_err();
    assert!(err.agent_message().contains("'raw_query' needs a value"));
}

#[test]
fn a_boolean_mapped_to_a_flag_still_emits_its_value() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1(dir.path());
    let tool = outlook_list(
        &t,
        json!({
            "microsoft_args": {"unread": {"flag": "--unread"}},
            "parameters": {"unread": {"type": "boolean", "required": false, "description": "u"}},
        }),
    )
    .unwrap();
    let tk = t.toolkit("outlook").unwrap();
    assert_eq!(build_microsoft_call(&tool, &res(&tool, json!({"unread": true})).unwrap(), tk).unwrap(), vec!["--unread", "true"]);
    assert_eq!(build_microsoft_call(&tool, &res(&tool, json!({"unread": false})).unwrap(), tk).unwrap(), vec!["--unread", "false"]);
    assert!(build_microsoft_call(&tool, &res(&tool, json!({})).unwrap(), tk).unwrap().is_empty());
}

fn bad(t: &Tier1, google: bool, cli_args: Value, parameters: Value) -> ConfigResult<ToolDef> {
    if google {
        gmail_search(t, json!({"google_args": cli_args, "parameters": parameters}))
    } else {
        outlook_list(t, json!({"microsoft_args": cli_args, "parameters": parameters}))
    }
}

#[test]
fn unusable_switch_declarations_are_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let t = tier1(dir.path());
    let bool_param = json!({"raw_query": {"type": "boolean", "required": false, "description": "r"}});
    for google in [true, false] {
        let field = if google { "google_args" } else { "microsoft_args" };
        let msg = err_text(bad(&t, google, json!({"raw_query": {"switch": "--raw-query", "flag": "--raw-query"}}), bool_param.clone()));
        assert!(msg.contains("switch"), "{msg}");
        assert!(msg.contains(&format!("{field}.'raw_query' sets 'switch' and also")), "{msg}");
        let msg = err_text(bad(&t, google, json!({"raw_query": {"switch": "--raw-query", "positional": true}}), bool_param.clone()));
        assert!(msg.contains("switch"));
        let msg = err_text(bad(
            &t,
            google,
            json!({"raw_query": {"switch": "--raw-query"}}),
            json!({"raw_query": {"type": "string", "required": false, "pattern": "^.{0,10}$", "description": "r"}}),
        ));
        assert!(msg.contains("boolean"), "{msg}");
        assert!(msg.contains("parameter 'raw_query' is type 'string'"), "{msg}");
        let msg = err_text(bad(&t, google, json!({"raw_query": {"switch": "--raw-query"}}), json!({})));
        assert!(msg.contains("raw_query"));
        for switch in [
            json!(""), json!(true), json!(123), Value::Null, json!("raw-query"), json!("-"), json!("--"),
            json!("--raw-query --max 999"), json!("--raw query"), json!("--raw-query=true"), json!("--{query}"),
            json!("--raw\nquery"),
        ] {
            let msg = err_text(bad(&t, google, json!({"raw_query": {"switch": switch.clone()}}), bool_param.clone()));
            assert!(msg.contains("unusable 'switch' name"), "{switch}: {msg}");
        }
        for switch in ["--raw-query", "-r", "--raw_query", "--raw-query-2"] {
            bad(&t, google, json!({"raw_query": {"switch": switch}}), bool_param.clone()).unwrap();
        }
    }
    let msg = err_text(bad(&t, true, json!({"x": {"flag": "--x", "positional": true}}), json!({})));
    assert_eq!(msg, "tool 'gmail.search': google_args.'x' is positional and also sets 'flag' -- pick one");
    let msg = err_text(bad(&t, true, json!({"x": {}}), json!({})));
    assert!(msg.contains("google_args.'x' is not positional and has no 'flag'"), "{msg}");
    let msg = err_text(bad(&t, true, json!(["x"]), json!({})));
    assert_eq!(msg, "tool 'gmail.search': 'google_args' must be a mapping");
}

/// The shipped census: every mapped arg names a declared parameter, every
/// boolean is a switch, every switch a boolean, every positional required
/// or derived.
#[test]
fn shipped_catalog_census() {
    let mut count = 0;
    for entry in std::fs::read_dir(examples_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        if !name.contains("tools") || !name.ends_with(".yaml") {
            continue;
        }
        let doc = gatekeeper::yaml::load(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for spec in doc["tools"].as_array().cloned().unwrap_or_default() {
            let params = spec.get("parameters").cloned().unwrap_or(json!({}));
            for field in ["google_args", "microsoft_args"] {
                let Some(map) = spec.get(field).and_then(|v| v.as_object()) else { continue };
                for (arg, mapping) in map {
                    count += 1;
                    let id = &spec["id"];
                    assert!(params.get(arg).is_some(), "{name}: {id}.{field} maps undeclared {arg}");
                    let p = &params[arg];
                    let is_bool = p.get("type") == Some(&json!("boolean"));
                    let has_switch = mapping.get("switch").is_some_and(|s| !s.is_null());
                    assert_eq!(is_bool, has_switch, "{name}: {id}.{field}.{arg}");
                    if mapping.get("positional") == Some(&json!(true)) {
                        assert!(
                            p.get("required") == Some(&json!(true)) || p.get("derived").is_some(),
                            "{name}: {id}.{field}.{arg}"
                        );
                    }
                }
            }
        }
    }
    assert!(count > 0, "census found no mapped args");
}

/// The argv every shipped google/microsoft tool builds with only its
/// required (and derived) parameters supplied -- the shape an omitted
/// optional flag leaves behind -- is the argv the Python implementation
/// built, frozen in `fixtures/shipped_cli_argv_golden.json` (1.16.0).
/// `tests/test_cli_grammar.py` runs exactly those argvs against the two
/// real CLI grammars (`scripts/google`, `scripts/microsoft`), so together
/// they pin that what Rust builds is what the scripts accept. A change to a
/// shipped tool's CLI mapping is edited into the fixture by hand.
#[test]
fn the_minimal_argv_of_every_shipped_cli_tool_is_the_frozen_one() {
    let golden: Value = serde_json::from_str(include_str!("fixtures/shipped_cli_argv_golden.json")).unwrap();
    let mut paths: Vec<_> = std::fs::read_dir(examples_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_str().unwrap();
            name.contains("tools") && name.ends_with(".yaml")
        })
        .collect();
    paths.sort();
    let mut specs: Vec<(String, Value)> = Vec::new();
    for path in &paths {
        let doc = gatekeeper::yaml::load(&std::fs::read_to_string(path).unwrap()).unwrap();
        let source = path.file_name().unwrap().to_str().unwrap().to_string();
        for spec in doc["tools"].as_array().cloned().unwrap_or_default() {
            specs.push((source.clone(), spec));
        }
    }
    const FIELDS: [(&str, &str); 2] = [("google_action", "google"), ("microsoft_action", "microsoft")];
    // One toolkit per shipped toolkit name, whitelisting exactly the
    // actions its tools name, with the path roots their derived paths need.
    let mut toolkits = serde_json::Map::new();
    for (_, spec) in &specs {
        for (action_field, executor) in FIELDS {
            let Some(action) = spec.get(action_field) else { continue };
            let allowed = format!("allowed_{executor}_actions");
            let entry = toolkits.entry(spec["toolkit"].as_str().unwrap().to_string()).or_insert_with(|| {
                json!({
                    "executor": executor, format!("{executor}_script"): PYTHON, allowed.clone(): [],
                    "credential": executor, "max_timeout_seconds": 60, "max_output_bytes": 131072,
                })
            });
            if !entry[&allowed].as_array().unwrap().contains(action) {
                entry[&allowed].as_array_mut().unwrap().push(action.clone());
            }
            for param in spec.get("parameters").and_then(Value::as_object).into_iter().flat_map(|m| m.values()) {
                if let Some(root) = param.get("must_resolve_under") {
                    let roots = entry.as_object_mut().unwrap().entry("path_roots").or_insert(json!([]));
                    if !roots.as_array().unwrap().contains(root) {
                        roots.as_array_mut().unwrap().push(root.clone());
                    }
                }
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let t = tier1_from(
        dir.path(),
        &json!({"toolkits": toolkits, "audit": {"dir": dir.path().join("logs").to_str().unwrap()}}),
    )
    .unwrap();

    let mut built = Vec::new();
    for (source, spec) in &specs {
        for (action_field, executor) in FIELDS {
            let Some(action) = spec.get(action_field).and_then(Value::as_str) else { continue };
            let toolkit = t.toolkit(spec["toolkit"].as_str().unwrap()).unwrap();
            let tool = parse_tool_spec(spec, &t).unwrap();
            let mut values = Values::new();
            for (name, param) in spec.get("parameters").and_then(Value::as_object).into_iter().flatten() {
                if param.get("required") != Some(&json!(true)) && param.get("derived").is_none_or(Value::is_null) {
                    continue;
                }
                let sample = match param.get("type").and_then(Value::as_str) {
                    Some("integer") => "1".to_string(),
                    Some("boolean") => "true".to_string(),
                    Some("enum") => param["values"].get(0).map(|v| v.as_str().unwrap().to_string()).unwrap_or("x".into()),
                    _ => "x".to_string(),
                };
                values.insert(name.clone(), sample);
            }
            let mut argv = if executor == "google" {
                gatekeeper::execute::google::action_argv(toolkit, action)
            } else {
                gatekeeper::execute::microsoft::action_argv(toolkit, action)
            };
            argv.extend(if executor == "google" {
                build_google_call(&tool, &values, toolkit).unwrap()
            } else {
                build_microsoft_call(&tool, &values, toolkit).unwrap()
            });
            built.push(json!({"source": source, "id": spec["id"], "executor": executor, "argv": argv}));
            break;
        }
    }
    assert!(!built.is_empty(), "no shipped google/microsoft tool was checked");
    assert_eq!(Value::Array(built), golden);
}
