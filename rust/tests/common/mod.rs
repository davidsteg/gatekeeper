//! Shared fixtures for the configuration-model tests (port of the parts of
//! `tests/conftest.py` they use). Like the Python fixtures, they write real
//! YAML files and run the real loaders.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use gatekeeper::catalog::{load_catalog, Catalog};
use gatekeeper::errors::ConfigResult;
use gatekeeper::tier1::{load_tier1, Tier1};
use serde_json::{json, Value};

/// A guaranteed-present, harmless absolute program (Python's tests use the
/// interpreter; nothing here executes it).
pub const PYTHON: &str = "/bin/sh";

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// `repo_config_dir`: the example configuration.
pub fn examples_dir() -> PathBuf {
    repo_root().join("config").join("examples")
}

pub fn write(path: &Path, text: &str) -> String {
    std::fs::write(path, text).unwrap();
    path.to_str().unwrap().to_string()
}

/// `sandbox`: a path root with two stacks.
pub fn sandbox(tmp: &Path) -> PathBuf {
    let root = tmp.join("raid");
    std::fs::create_dir_all(root.join("media-jellyfin")).unwrap();
    std::fs::create_dir_all(root.join("gatekeeper")).unwrap();
    std::fs::write(root.join("media-jellyfin/compose.yaml"), "services: {}\n").unwrap();
    std::fs::write(root.join("gatekeeper/compose.yaml"), "services: {}\n").unwrap();
    root
}

/// Loads a Tier 1 written from `doc` (dumped as YAML).
pub fn tier1_from(tmp: &Path, doc: &Value) -> ConfigResult<Tier1> {
    let path = tmp.join("toolkits.yaml");
    write(&path, &gatekeeper::yaml::dump(doc));
    load_tier1(path.to_str().unwrap())
}

/// Loads a Tier 1 from YAML text, with an `audit.dir` appended.
pub fn tier1_text(tmp: &Path, text: &str) -> ConfigResult<Tier1> {
    let path = tmp.join("toolkits.yaml");
    let logs = tmp.join("logs");
    write(&path, &format!("{text}\naudit:\n  dir: {}\n", logs.display()));
    load_tier1(path.to_str().unwrap())
}

/// The conftest `tier1` fixture: one `local` toolkit "demo".
pub fn demo_tier1(tmp: &Path, sandbox: &Path) -> Tier1 {
    tier1_from(
        tmp,
        &json!({
            "toolkits": {
                "demo": {
                    "executor": "local",
                    "binaries": [PYTHON],
                    "denied_args": ["--dangerous", "rm"],
                    "path_roots": [sandbox.to_str().unwrap()],
                    "protected_resources": ["gatekeeper", "dockhand"],
                    "max_timeout_seconds": 30,
                    "max_output_bytes": 8192,
                }
            },
            "audit": {"dir": tmp.join("logs").to_str().unwrap()},
        }),
    )
    .unwrap()
}

/// The conftest `tool_specs` fixture.
pub fn tool_specs(sandbox: &Path) -> Vec<Value> {
    let sb = sandbox.to_str().unwrap();
    vec![
        json!({
            "id": "demo.show",
            "toolkit": "demo",
            "binary": PYTHON,
            "version": 1,
            "title": "Show compose file",
            "description": "Outputs the path of the compose file.",
            "category": "read",
            "idempotent": true,
            "enabled": true,
            "argv": ["-c", "import sys; print(sys.argv[1])", "{compose_path}"],
            "parameters": {
                "stack": {
                    "type": "string",
                    "required": true,
                    "pattern": "^[a-z0-9][a-z0-9_-]{0,62}$",
                    "description": "Stack name",
                },
                "compose_path": {
                    "type": "path",
                    "derived": format!("{sb}/{{stack}}/compose.yaml"),
                    "must_resolve_under": sb,
                    "description": "derived",
                },
            },
            "required_scopes": ["stack:{stack}"],
            "timeout_seconds": 10,
            "max_output_bytes": 4096,
        }),
        json!({
            "id": "demo.echo",
            "toolkit": "demo",
            "binary": PYTHON,
            "version": 1,
            "title": "Echo",
            "description": "Outputs the given text.",
            "category": "read",
            "idempotent": true,
            "enabled": true,
            "argv": ["-c", "import sys; print(sys.argv[1])", "{text}"],
            "parameters": {
                "text": {
                    "type": "string",
                    "required": true,
                    "pattern": "^.+$",
                    "description": "arbitrary text",
                }
            },
            "required_scopes": [],
            "timeout_seconds": 10,
            "max_output_bytes": 4096,
        }),
    ]
}

/// `make_catalog`: writes `{"tools": tools}` and loads it.
pub fn make_catalog(tmp: &Path, tier1: &Tier1, tools: &[Value], strict: bool) -> ConfigResult<Catalog> {
    let path = tmp.join("tools.yaml");
    write(&path, &gatekeeper::yaml::dump(&json!({ "tools": tools })));
    load_catalog(path.to_str().unwrap(), tier1, strict)
}

/// `make_catalog(..., strict=True)` that must succeed.
pub fn catalog_ok(tmp: &Path, tier1: &Tier1, tools: &[Value]) -> Catalog {
    make_catalog(tmp, tier1, tools, true).unwrap()
}

/// The message of an error, for `pytest.raises(match=...)`-style checks.
pub fn err_text<T: std::fmt::Debug>(r: ConfigResult<T>) -> String {
    r.unwrap_err().message
}

pub fn args(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap()
}
