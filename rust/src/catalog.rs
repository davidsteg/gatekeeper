//! Tool definitions and their validation against Tier 1 (port of
//! `catalog.py`, REQUIREMENTS.md §7).
//!
//! Public API (Python name -> Rust):
//!
//! | Python | Rust |
//! |---|---|
//! | `Parameter`, `ToolDef`, `Catalog` | same-named structs |
//! | `ToolDef.input_schema()` / `agent_description()` / `agent_parameters` | [`ToolDef::input_schema`], [`ToolDef::agent_description`], [`ToolDef::agent_parameters`] |
//! | `Parameter.json_schema()` / `is_derived` | [`Parameter::json_schema`], [`Parameter::is_derived`] |
//! | `parse_tool_spec`, `load_catalog` | [`parse_tool_spec`], [`load_catalog`] |
//! | `Catalog.get/raw_of/flat_spec_of/grantable_ids` | same-named methods |
//! | `normalize_tool_entry`, `new_tool_entry`, `append_tool_version`, `soft_delete_entry`, `now_iso` | same names |
//! | `_current_version_spec`, `_expand_tool` | [`current_version_spec`], [`expand_tool`] |
//! | `_parse_cli_args`, `_str_str_map`, `_body_raw_param`, `_nested_body_map`, `_collect_template_strings` | same names without `_` |
//! | `PLACEHOLDER_RE`, `TOOL_ID_RE`, `SWITCH_RE` | [`placeholder_re`], [`tool_id_re`], [`switch_re`] |
//! | `CATEGORIES`, `PARAM_TYPES`, `*_OPERATION_PARAMS` | same-named consts |
//!
//! Raw YAML entries stay `serde_json::Value` (insertion-ordered like a
//! Python dict); parsed definitions are typed.

use std::sync::OnceLock;

use indexmap::IndexMap;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::errors::{read_config_file, ConfigError, ConfigResult};
use crate::pyfmt::{repr_list, repr_str, repr_value, type_name};
use crate::pyre::PyRegex;
use crate::runas::parse_run_as;
use crate::tier1::{
    py_eq, py_int, py_str, py_truthy, url_hostname, validate_http_base_url, Tier1, Toolkit, KUMA_INTERVAL_MAX,
    KUMA_INTERVAL_MIN, KUMA_STATUS_CODES,
};

/// Placeholders in argv, derived and scope templates.
pub const PLACEHOLDER_PATTERN: &str = r"\{([a-z_][a-z0-9_]*)\}";

/// Tool IDs follow `<toolkit>.<action>` (FR-5.1b).
///
/// PORT NOTE: Python used `TOOL_ID_RE.match`, whose `$` also matched
/// before a trailing newline, so `"docker.ps\n"` passed. That is a bug;
/// here the whole string must match.
pub const TOOL_ID_PATTERN: &str = r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$";

/// What a `switch:` may be spelled as -- one option-looking token.
pub const SWITCH_PATTERN: &str = r"^(?:--?[A-Za-z0-9][A-Za-z0-9._-]*)$";

/// `PLACEHOLDER_RE`.
pub fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(PLACEHOLDER_PATTERN).expect("static regex"))
}

/// `TOOL_ID_RE`.
pub fn tool_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(TOOL_ID_PATTERN).expect("static regex"))
}

/// `SWITCH_RE` (used with `fullmatch`; anchored here).
pub fn switch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(SWITCH_PATTERN).expect("static regex"))
}

/// Tool categories (sorted).
pub const CATEGORIES: &[&str] = &["read", "write", "write_external"];
/// Parameter types (sorted).
pub const PARAM_TYPES: &[&str] = &["boolean", "enum", "integer", "path", "string"];

/// `(required, optional)` parameter names of one operation.
pub type OpParams = (&'static [&'static str], &'static [&'static str]);

/// What each `opencode` operation reads. Enforced in both directions at
/// load time.
pub const OPENCODE_OPERATION_PARAMS: &[(&str, OpParams)] = &[
    ("ask", (&["prompt"], &["directory", "model", "agent", "title", "session_id"])),
    ("run", (&["prompt"], &["directory", "model", "agent", "title", "session_id"])),
    ("fire", (&["prompt"], &["directory", "model", "agent", "title", "session_id"])),
    ("check", (&["session_id"], &["directory"])),
    ("review_changes", (&["session_id"], &["directory"])),
    ("abort", (&["session_id"], &["directory"])),
    ("providers", (&[], &["directory"])),
    ("health", (&[], &[])),
];

/// `artifact` executor: what each operation reads.
pub const ARTIFACT_OPERATION_PARAMS: &[(&str, OpParams)] = &[
    ("list", (&[], &[])),
    ("info", (&["artifact"], &["version"])),
    ("read", (&["artifact"], &["version"])),
    ("transfer", (&["artifact"], &["version"])),
];

/// `kuma` executor: what each operation reads. `monitor_add_http` takes
/// exactly the four fields a gatekeeper-made monitor has a say in; the
/// monitor type, method, notifications and everything else are fixed in
/// `execute::kuma::http_monitor`. There is no parameter for a Kuma URL or
/// account -- both are Tier 1.
pub const KUMA_OPERATION_PARAMS: &[(&str, OpParams)] = &[
    ("monitor_list", (&[], &[])),
    ("monitor_add_http", (&["name", "url"], &["interval", "expected_status"])),
    ("monitor_pause", (&["monitor_id"], &[])),
    ("monitor_resume", (&["monitor_id"], &[])),
];

/// The `kuma` operations that change something. A tool for one of them is
/// never category `read`: `read` is what `admin.tool_create` applies
/// without a human, and these must go through approval.
pub const KUMA_WRITE_OPERATIONS: &[&str] = &["monitor_add_http", "monitor_pause", "monitor_resume"];

/// `git` executor: `push` reads the repository's key in the toolkit's
/// `repos:` and the branch. There is no parameter for a path, a remote, a
/// refspec or a flag -- the first two are Tier 1, the rest is fixed in
/// `execute::git`.
pub const GIT_OPERATION_PARAMS: &[(&str, OpParams)] = &[("push", (&["repo", "branch"], &[]))];

/// The `agent` executor's parameter contract. There is no `from` and no
/// mailbox selector in any row, and that is the point.
pub const AGENT_OPERATION_PARAMS: &[(&str, OpParams)] = &[
    ("send_message", (&["to", "body"], &["subject"])),
    ("read_messages", (&[], &["limit", "peek"])),
    ("mailbox_status", (&[], &[])),
];

/// Looks up one operation in an `*_OPERATION_PARAMS` table.
pub fn op_params(table: &[(&str, OpParams)], operation: &str) -> Option<OpParams> {
    table.iter().find(|(name, _)| *name == operation).map(|(_, p)| *p)
}

/// `sorted(table)`: the operation names of a table.
fn sorted_ops(table: &[(&str, OpParams)]) -> Vec<String> {
    let mut v: Vec<String> = table.iter().map(|(n, _)| n.to_string()).collect();
    v.sort();
    v
}

/// One declared tool parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct Parameter {
    pub name: String,
    /// Python: `type` -- one of [`PARAM_TYPES`].
    pub ptype: String,
    pub description: String,
    pub required: bool,
    pub pattern: Option<PyRegex>,
    pub values: Vec<String>,
    /// The raw `minimum`/`maximum` as written (Python stored `spec.get(...)`
    /// unconverted, and publishes it verbatim in the schema).
    pub minimum: Option<Value>,
    pub maximum: Option<Value>,
    pub derived: Option<String>,
    pub must_resolve_under: Option<String>,
    pub flag: Option<String>,
    /// The regex exactly as the definition spells it -- published verbatim
    /// in the tool's inputSchema.
    pub pattern_source: Option<String>,
    /// FR-6.3's control-character reject is off for this parameter.
    pub allow_control_characters: bool,
    /// The value is a secret the caller brings (a dataset passphrase): it
    /// never reaches the audit log or the tracing log and is masked in
    /// the output. Only a `truenas` tool's `params` may carry it.
    pub secret: bool,
}

impl Parameter {
    /// A parameter with the dataclass defaults (for tests and builders).
    pub fn new(name: &str, ptype: &str, description: &str) -> Self {
        Parameter {
            name: name.to_string(),
            ptype: ptype.to_string(),
            description: description.to_string(),
            required: false,
            pattern: None,
            values: Vec::new(),
            minimum: None,
            maximum: None,
            derived: None,
            must_resolve_under: None,
            flag: None,
            pattern_source: None,
            allow_control_characters: false,
            secret: false,
        }
    }

    /// Computed by the server, not settable by the agent (FR-5.5).
    pub fn is_derived(&self) -> bool {
        self.derived.is_some()
    }

    /// Schema fragment for `tools/list`. The published `pattern` is the
    /// definition's own string, character for character.
    pub fn json_schema(&self) -> Value {
        let mut schema = Map::new();
        match self.ptype.as_str() {
            "integer" => {
                schema.insert("type".into(), json!("integer"));
                if let Some(min) = &self.minimum {
                    schema.insert("minimum".into(), min.clone());
                }
                if let Some(max) = &self.maximum {
                    schema.insert("maximum".into(), max.clone());
                }
            }
            "boolean" => {
                schema.insert("type".into(), json!("boolean"));
            }
            "enum" => {
                schema.insert("type".into(), json!("string"));
                schema.insert("enum".into(), json!(self.values));
            }
            _ => {
                schema.insert("type".into(), json!("string"));
                if let Some(pattern) = &self.pattern {
                    let text = self.pattern_source.clone().unwrap_or_else(|| pattern.source.clone());
                    schema.insert("pattern".into(), Value::String(text));
                }
            }
        }
        if self.secret {
            schema.insert("writeOnly".into(), Value::Bool(true));
        }
        schema.insert("description".into(), Value::String(self.description.clone()));
        Value::Object(schema)
    }
}

/// One `google_args`/`microsoft_args` entry: exactly one of `positional`,
/// `flag` or `switch` is in effect. Python kept the dict
/// `{"flag", "positional", "switch"}`; [`CliArg::to_value`] gives it back.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CliArg {
    pub flag: Option<String>,
    pub positional: bool,
    pub switch: Option<String>,
}

impl CliArg {
    pub fn to_value(&self) -> Value {
        json!({"flag": self.flag, "positional": self.positional, "switch": self.switch})
    }
}

/// HTTP methods a `verify` block may use without a fixed `body`. An
/// allowlist, not a denylist of writes: any other method may change state,
/// so it is only accepted together with a fixed `verify.body`. Only `GET`,
/// because Tier 1's `allowed_methods` knows no other read method.
pub const VERIFY_READ_METHODS: &[&str] = &["GET"];

/// The keys a `verify:` block may carry.
pub const VERIFY_FIELDS: &[&str] = &["body", "method", "path", "query", "require_body"];

/// An `http` tool's `verify:` block (1.27.0): a second request that reads
/// back what the main request did. Its templates take the tool's own
/// parameters; there is no raw-body mode.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpVerify {
    /// Upper-cased; one of [`VERIFY_READ_METHODS`] unless `body` is set.
    pub method: String,
    pub path_template: String,
    pub query_template: IndexMap<String, String>,
    pub body_template: Option<Value>,
    /// A 2xx whose body is empty (`""`, `null`, `{}`, `[]`, `""`) fails
    /// the verify.
    pub require_body: bool,
}

/// A parsed, Tier-1-checked tool definition.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDef {
    pub id: String,
    pub toolkit: String,
    pub version: i64,
    pub title: String,
    pub description: String,
    pub category: String,
    pub idempotent: bool,
    pub ssh_dispatch: bool,
    pub enabled: bool,
    pub parameters: IndexMap<String, Parameter>,
    pub required_scopes: Vec<String>,
    pub timeout_seconds: i64,
    pub max_output_bytes: i64,

    // -- `docker`/`local`/`ssh` --
    pub binary: Option<String>,
    pub argv: Vec<String>,
    /// Fixed text sent to the process on stdin (`docker`/`local`, 1.25.0):
    /// a script or SQL the definition carries, never an agent value, so
    /// nothing is substituted into it.
    pub stdin: Option<String>,

    // -- `http` (FR-8.5 to FR-8.7) --
    pub http_method: Option<String>,
    pub path_template: Option<String>,
    pub query_template: IndexMap<String, String>,
    /// Nested dict/list/str template; every leaf string is a `{param}`
    /// template, other leaves pass through.
    pub body_template: Option<Value>,
    /// Raw JSON body mode (`body: {raw_param: <name>}`).
    pub body_raw_param: Option<String>,
    /// The per-file ceiling for the body's `from_file` fields (1.21.0);
    /// set exactly when the body has one ([`body_file_params`]).
    pub max_file_bytes: Option<i64>,
    /// Per-tool base_url override (0.45.5).
    pub base_url: Option<String>,
    /// Optional read-back request (`verify:`, 1.27.0), sent after a
    /// successful main request with the same toolkit and the same
    /// validated parameter values.
    pub verify: Option<HttpVerify>,

    // -- `truenas` --
    pub rpc_method: Option<String>,
    /// The method starts a middleware job (`job: true`, 1.24.0): its answer
    /// is a job id, and the call waits for the job's own result.
    pub rpc_job: bool,
    /// One template per positional RPC argument. A value is a string or a
    /// nested object/array whose leaf strings are `{param}` templates
    /// (1.23.0); a leaf that is exactly `{param}` of an integer or boolean
    /// parameter is sent as a JSON number or boolean.
    pub params_template: Option<IndexMap<String, Value>>,

    // -- `file` --
    pub file_operation: Option<String>,
    /// A `write` tool's fixed file mode (1.25.0).
    pub file_mode: Option<u32>,
    /// A `delete` tool's `delete: {max_entries, files_only}` (1.28.0).
    /// `None` without a block: the ceiling, `MAX_DELETE_ENTRIES`.
    pub delete_max_entries: Option<i64>,
    pub delete_files_only: bool,

    // -- `google` --
    pub google_action: Option<String>,
    pub google_args: Option<IndexMap<String, CliArg>>,

    // -- `microsoft` --
    pub microsoft_action: Option<String>,
    pub microsoft_args: Option<IndexMap<String, CliArg>>,

    // -- `opencode` / `agent` / `artifact` --
    pub opencode_operation: Option<String>,
    pub agent_operation: Option<String>,
    pub artifact_operation: Option<String>,
    /// The `kuma` executor's operation (`tier1::KUMA_OPERATIONS`), fixed
    /// per tool like `agent_operation`.
    pub kuma_operation: Option<String>,
    /// The `git` executor's operation (`tier1::GIT_OPERATIONS`), fixed per
    /// tool like `agent_operation`.
    pub git_operation: Option<String>,

    /// Per-tool override of the toolkit's `run_as` (file executor only).
    /// `None` inherits the toolkit's; `Some("")` explicitly clears it.
    pub run_as: Option<String>,

    /// Set only on destination-qualified copies (`<id>@<destination>`).
    pub destination: Option<String>,
}

impl ToolDef {
    /// Only the parameters settable by the agent.
    pub fn agent_parameters(&self) -> IndexMap<String, &Parameter> {
        self.parameters
            .iter()
            .filter(|(_, p)| !p.is_derived())
            .map(|(n, p)| (n.clone(), p))
            .collect()
    }

    /// The MCP `inputSchema`.
    pub fn input_schema(&self) -> Value {
        let agent = self.agent_parameters();
        let mut properties = Map::new();
        for (name, p) in &agent {
            properties.insert(name.clone(), p.json_schema());
        }
        let mut required: Vec<String> =
            agent.iter().filter(|(_, p)| p.required).map(|(n, _)| n.clone()).collect();
        required.sort();
        json!({
            "type": "object",
            "properties": Value::Object(properties),
            "required": required,
            "additionalProperties": false,
        })
    }

    /// Description for the agent. Non-idempotent tools are explicitly
    /// marked (FR-6.10).
    pub fn agent_description(&self) -> String {
        let mut parts = vec![self.description.clone()];
        if !self.idempotent {
            parts.push(
                "NOT IDEMPOTENT: calling again repeats the effect. After a \
                 timeout the outcome is unknown -- do not retry without \
                 checking the state first."
                    .to_string(),
            );
        }
        if self.category == "write_external" {
            parts.push("Has externally visible effects and cannot be undone.".to_string());
        }
        parts.join(" ")
    }
}

/// The placeholder names in `template`, in order of appearance, deduplicated.
pub fn placeholders(template: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for cap in placeholder_re().captures_iter(template) {
        let name = cap[1].to_string();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn repr_opt(v: &Option<String>) -> String {
    match v {
        Some(s) => repr_str(s),
        None => "None".to_string(),
    }
}

/// Python's iteration of a value (`for x in value`): a list's items, a
/// string's characters, a dict's keys.
fn py_iter(v: &Value) -> ConfigResult<Vec<Value>> {
    match v {
        Value::Array(items) => Ok(items.clone()),
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        Value::Object(m) => Ok(m.keys().map(|k| Value::String(k.clone())).collect()),
        other => Err(ConfigError::new(format!("{} object is not iterable", repr_str(type_name(other))))),
    }
}

/// `spec.get(key)` with a `None` value treated like an absent key.
fn get_some<'a>(spec: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    spec.get(key).filter(|v| !v.is_null())
}

fn parse_parameter(name: &str, spec: &Value, where_: &str) -> ConfigResult<Parameter> {
    let Value::Object(spec) = spec else {
        return Err(ConfigError::new(format!(
            "{where_}: parameter {} expects a mapping",
            repr_str(name)
        )));
    };

    let ptype = match spec.get("type") {
        Some(Value::String(t)) if PARAM_TYPES.contains(&t.as_str()) => t.clone(),
        other => {
            return Err(ConfigError::new(format!(
                "{where_}: parameter {} has unknown type {} (allowed: {})",
                repr_str(name),
                repr_value(other.unwrap_or(&Value::Null)),
                repr_list(PARAM_TYPES)
            )))
        }
    };

    let mut pattern = None;
    let mut pattern_source = None;
    if let Some(raw_pattern) = spec.get("pattern").filter(|v| py_truthy(v)) {
        let Value::String(raw_pattern) = raw_pattern else {
            return Err(ConfigError::new(format!(
                "{where_}: parameter {} has a non-string 'pattern' ({}). Quote it.",
                repr_str(name),
                type_name(raw_pattern)
            )));
        };
        // PORT NOTE: the error text after "invalid pattern:" comes from the
        // Rust regex engine, not from Python's `re.error`.
        let compiled = PyRegex::new(raw_pattern).map_err(|exc| {
            ConfigError::new(format!(
                "{where_}: parameter {} has an invalid pattern: {exc}",
                repr_str(name)
            ))
        })?;
        pattern = Some(compiled);
        pattern_source = Some(raw_pattern.clone());
    }

    // PORT NOTE: a non-string `derived`/`must_resolve_under`/`flag` crashed
    // Python later (TypeError); here it is taken as its `str()`.
    let derived = get_some(spec, "derived").map(py_str);

    // FR-5.7: There is no unvalidated free-text parameter.
    if ptype == "string" && pattern.is_none() && derived.is_none() {
        return Err(ConfigError::new(format!(
            "{where_}: parameter {} is a string without 'pattern'. \
             Unvalidated free-text parameters are not permitted (FR-5.7).",
            repr_str(name)
        )));
    }
    if ptype == "enum" && !spec.get("values").is_some_and(py_truthy) {
        return Err(ConfigError::new(format!(
            "{where_}: parameter {} is an enum without 'values'",
            repr_str(name)
        )));
    }
    if ptype == "path" {
        if derived.is_none() {
            return Err(ConfigError::new(format!(
                "{where_}: parameter {} is a path without 'derived'. \
                 Paths are built by the server, never supplied by the agent.",
                repr_str(name)
            )));
        }
        if !spec.get("must_resolve_under").is_some_and(py_truthy) {
            return Err(ConfigError::new(format!(
                "{where_}: parameter {} is a path without 'must_resolve_under'",
                repr_str(name)
            )));
        }
    }

    let secret = spec.get("secret").is_some_and(py_truthy);
    if secret && (ptype != "string" || derived.is_some()) {
        return Err(ConfigError::new(format!(
            "{where_}: parameter {} is secret, so it must be a string with a 'pattern', not derived",
            repr_str(name)
        )));
    }

    let values = match spec.get("values") {
        None => Vec::new(),
        Some(v) => py_iter(v)?.iter().map(py_str).collect(),
    };

    Ok(Parameter {
        name: name.to_string(),
        ptype,
        description: spec.get("description").map(py_str).unwrap_or_default(),
        required: spec.get("required").is_some_and(py_truthy),
        pattern,
        values,
        minimum: get_some(spec, "minimum").cloned(),
        maximum: get_some(spec, "maximum").cloned(),
        derived,
        must_resolve_under: get_some(spec, "must_resolve_under").map(py_str),
        flag: get_some(spec, "flag").map(py_str),
        pattern_source,
        allow_control_characters: spec.get("allow_control_characters").is_some_and(py_truthy),
        secret,
    })
}

/// `_validate_opencode_params` / `_validate_agent_params`: both halves of a
/// fixed parameter contract, with the opencode/agent wording.
fn validate_named_op_params(
    executor: &str,
    table: &[(&str, OpParams)],
    operation: &str,
    parameters: &IndexMap<String, Parameter>,
    where_: &str,
) -> ConfigResult<()> {
    let (required, optional) = op_params(table, operation).unwrap_or((&[], &[]));
    for name in required {
        match parameters.get(*name) {
            None => {
                return Err(ConfigError::new(format!(
                    "{where_}: {executor} operation {} needs a {} parameter",
                    repr_str(operation),
                    repr_str(name)
                )))
            }
            Some(p) if !p.required => {
                return Err(ConfigError::new(format!(
                    "{where_}: parameter {} must be required for {executor} operation {}",
                    repr_str(name),
                    repr_str(operation)
                )))
            }
            _ => {}
        }
    }
    let unknown = unknown_params(parameters, required, optional);
    if !unknown.is_empty() {
        return Err(ConfigError::new(format!(
            "{where_}: {executor} operation {} does not read {} -- it reads {}. \
             A parameter it does not read would be accepted and silently ignored.",
            repr_str(operation),
            repr_list(&unknown),
            known_text(required, optional)
        )));
    }
    Ok(())
}

fn unknown_params(parameters: &IndexMap<String, Parameter>, required: &[&str], optional: &[&str]) -> Vec<String> {
    let mut unknown: Vec<String> = parameters
        .keys()
        .filter(|n| !required.contains(&n.as_str()) && !optional.contains(&n.as_str()))
        .cloned()
        .collect();
    unknown.sort();
    unknown
}

/// `sorted(known) or 'no parameters'`, as Python formats it.
fn known_text(required: &[&str], optional: &[&str]) -> String {
    let mut known: Vec<&str> = required.iter().chain(optional.iter()).copied().collect();
    known.sort();
    known.dedup();
    if known.is_empty() {
        "no parameters".to_string()
    } else {
        repr_list(&known)
    }
}

/// `_validate_op_params` (the `artifact` wording).
fn validate_op_params(
    executor: &str,
    table: &[(&str, OpParams)],
    operation: &str,
    parameters: &IndexMap<String, Parameter>,
    where_: &str,
) -> ConfigResult<()> {
    let (required, optional) = op_params(table, operation).unwrap_or((&[], &[]));
    for name in required {
        if !parameters.get(*name).is_some_and(|p| p.required) {
            return Err(ConfigError::new(format!(
                "{where_}: {executor} operation {} needs a required {} parameter",
                repr_str(operation),
                repr_str(name)
            )));
        }
    }
    let unknown = unknown_params(parameters, required, optional);
    if !unknown.is_empty() {
        return Err(ConfigError::new(format!(
            "{where_}: {executor} operation {} does not read {} -- it reads {}.",
            repr_str(operation),
            repr_list(&unknown),
            known_text(required, optional)
        )));
    }
    Ok(())
}

/// A declared `minimum`/`maximum` compared with a fixed bound, as Python's
/// `<`/`>` would (a bool counts as 0/1).
///
/// PORT NOTE: a non-numeric bound (a string, a list) raised TypeError in
/// Python's `_validate_kuma_params`; here it simply fails the check, so the
/// definition is refused with the same message as an out-of-range bound.
fn bound_as_f64(bound: &Value) -> Option<f64> {
    match bound {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        _ => None,
    }
}

/// `_validate_kuma_params`: the `kuma` limits a tool definition must not
/// loosen, at load time.
///
/// `execute::kuma::check_values` enforces the same floor at call time; this
/// is what makes a definition that would publish a wider schema than the
/// executor accepts fail when it is written, not on an agent's call.
fn validate_kuma_params(
    operation: &str,
    category: &str,
    parameters: &IndexMap<String, Parameter>,
    where_: &str,
) -> ConfigResult<()> {
    if KUMA_WRITE_OPERATIONS.contains(&operation) && category == "read" {
        return Err(ConfigError::new(format!(
            "{where_}: kuma operation {} changes monitors -- its category must be 'write', not 'read'",
            repr_str(operation)
        )));
    }
    let below = |b: &Option<Value>, limit: i64| match b {
        None => true,
        Some(v) => bound_as_f64(v).is_none_or(|x| x < limit as f64),
    };
    let above = |b: &Option<Value>, limit: i64| match b {
        None => true,
        Some(v) => bound_as_f64(v).is_none_or(|x| x > limit as f64),
    };
    if let Some(interval) = parameters.get("interval") {
        if interval.ptype != "integer"
            || below(&interval.minimum, KUMA_INTERVAL_MIN)
            || above(&interval.maximum, KUMA_INTERVAL_MAX)
        {
            return Err(ConfigError::new(format!(
                "{where_}: parameter 'interval' must be an integer with minimum >= \
                 {KUMA_INTERVAL_MIN} and maximum <= {KUMA_INTERVAL_MAX}"
            )));
        }
    }
    if let Some(status) = parameters.get("expected_status") {
        if status.ptype != "enum" || !status.values.iter().all(|v| KUMA_STATUS_CODES.contains(&v.as_str())) {
            return Err(ConfigError::new(format!(
                "{where_}: parameter 'expected_status' must be an enum over {}",
                repr_list(KUMA_STATUS_CODES)
            )));
        }
    }
    if let Some(url) = parameters.get("url") {
        if url.ptype != "string" {
            return Err(ConfigError::new(format!("{where_}: parameter 'url' must be a string with a pattern")));
        }
    }
    if let Some(monitor_id) = parameters.get("monitor_id") {
        if monitor_id.ptype != "integer" || below(&monitor_id.minimum, 1) {
            return Err(ConfigError::new(format!(
                "{where_}: parameter 'monitor_id' must be an integer with minimum >= 1"
            )));
        }
    }
    Ok(())
}

/// `_validate_git_params`: a `push` changes a remote, so it is never
/// category `read` (which `admin.tool_create` applies without a human).
/// `repo` and `branch` are strings or enums; what they may contain is
/// `execute::git::check_values`' call-time floor, which no schema can
/// widen.
fn validate_git_params(
    operation: &str,
    category: &str,
    parameters: &IndexMap<String, Parameter>,
    where_: &str,
) -> ConfigResult<()> {
    if category == "read" {
        return Err(ConfigError::new(format!(
            "{where_}: git operation {} changes a remote -- its category must be 'write', not 'read'",
            repr_str(operation)
        )));
    }
    for name in ["repo", "branch"] {
        if let Some(param) = parameters.get(name) {
            if param.ptype != "string" && param.ptype != "enum" {
                return Err(ConfigError::new(format!(
                    "{where_}: parameter {} must be a string or an enum",
                    repr_str(name)
                )));
            }
        }
    }
    Ok(())
}

/// FR-4.5: a tool may stay below the toolkit limits, never exceed them.
fn validate_ceilings(tool: &ToolDef, toolkit: &Toolkit, where_: &str) -> ConfigResult<()> {
    if tool.timeout_seconds > toolkit.max_timeout_seconds {
        return Err(ConfigError::tier1(format!(
            "{where_}: timeout_seconds={} exceeds the toolkit maximum {}",
            tool.timeout_seconds, toolkit.max_timeout_seconds
        )));
    }
    if tool.max_output_bytes > toolkit.max_output_bytes {
        return Err(ConfigError::tier1(format!(
            "{where_}: max_output_bytes={} exceeds the toolkit maximum {}",
            tool.max_output_bytes, toolkit.max_output_bytes
        )));
    }
    Ok(())
}

fn check_param_roots(tool: &ToolDef, toolkit: &Toolkit, where_: &str) -> ConfigResult<()> {
    for param in tool.parameters.values() {
        if let Some(root) = param.must_resolve_under.as_deref().filter(|r| !r.is_empty()) {
            toolkit
                .check_path_root(root)
                .map_err(|exc| ConfigError::tier1(format!("{where_}: {exc}")))?;
        }
    }
    Ok(())
}

/// FR-4.6: validation against Tier 1 -- at load time and again at
/// execution time (Tier 1 may have been tightened by a redeploy).
pub fn validate_against_tier1(tool: &ToolDef, toolkit: &Toolkit) -> ConfigResult<()> {
    let where_ = format!("tool {}", repr_str(&tool.id));
    let where_ = where_.as_str();
    let tk_name = repr_str(&toolkit.name);

    match toolkit.executor.as_str() {
        "docker" | "local" | "ssh" => {
            toolkit
                .check_binary(tool.binary.as_deref().unwrap_or(""))
                .map_err(|exc| ConfigError::tier1(exc.message))?;
            if let Some(denied) = toolkit.check_args(&tool.argv) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: argv template contains denied argument {}",
                    repr_str(&denied)
                )));
            }
            check_param_roots(tool, toolkit, where_)?;
        }
        "http" => {
            if !toolkit.allows_method(tool.http_method.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: method {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.http_method),
                    repr_list(&toolkit.allowed_methods)
                )));
            }
            // The literal portion before the first placeholder is what a
            // redeploy promised (FR-8.6).
            let template = tool.path_template.as_deref().unwrap_or("");
            let literal_prefix = template.split('{').next().unwrap_or("");
            if !toolkit.allows_path(literal_prefix) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: path {} matches none of the allowed_path_prefixes {} of toolkit {tk_name}",
                    repr_opt(&tool.path_template),
                    repr_list(&toolkit.allowed_path_prefixes)
                )));
            }
            // A verify request is held to exactly the main request's Tier 1
            // limits: same toolkit, allowlisted method, allowed path.
            if let Some(verify) = &tool.verify {
                if !toolkit.allows_method(&verify.method) {
                    return Err(ConfigError::tier1(format!(
                        "{where_}: verify method {} is not in the allowlist {} of toolkit {tk_name}",
                        repr_str(&verify.method),
                        repr_list(&toolkit.allowed_methods)
                    )));
                }
                let verify_prefix = verify.path_template.split('{').next().unwrap_or("");
                if !toolkit.allows_path(verify_prefix) {
                    return Err(ConfigError::tier1(format!(
                        "{where_}: verify path {} matches none of the allowed_path_prefixes {} of toolkit {tk_name}",
                        repr_str(&verify.path_template),
                        repr_list(&toolkit.allowed_path_prefixes)
                    )));
                }
            }
            // A body `from_file` reads the gatekeeper host's disk, so its
            // root is Tier 1's to allow (FR-4.10), as for a local tool.
            if tool.max_file_bytes.is_some() {
                check_param_roots(tool, toolkit, where_)?;
            }
            // A per-tool base_url override on a hostname toolkit names a
            // host too; one outside `allowed_hosts` could never connect, so
            // it is disabled here instead of failing on every call.
            if let Some(base_url) = tool.base_url.as_deref().filter(|b| !b.is_empty()) {
                let override_host = url_hostname(base_url);
                if !toolkit.allows_host(&override_host) {
                    return Err(ConfigError::tier1(format!(
                        "{where_}: base_url host {} is not in the allowed_hosts {} of toolkit {tk_name}",
                        repr_str(&override_host),
                        repr_list(&toolkit.allowed_hosts)
                    )));
                }
            }
        }
        "truenas" => {
            if !toolkit.allows_rpc_method(tool.rpc_method.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: RPC method {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.rpc_method),
                    repr_list(&toolkit.allowed_rpc_methods)
                )));
            }
            if tool.rpc_job && !toolkit.allows_rpc_method(crate::execute::truenas::JOB_METHOD) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: a job tool waits with {}, which is not in the allowlist {} of toolkit {tk_name}",
                    repr_str(crate::execute::truenas::JOB_METHOD),
                    repr_list(&toolkit.allowed_rpc_methods)
                )));
            }
        }
        "google" => {
            if !toolkit.allows_google_action(tool.google_action.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: google action {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.google_action),
                    repr_list(&toolkit.allowed_google_actions)
                )));
            }
            check_param_roots(tool, toolkit, where_)?;
        }
        "microsoft" => {
            if !toolkit.allows_microsoft_action(tool.microsoft_action.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: microsoft action {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.microsoft_action),
                    repr_list(&toolkit.allowed_microsoft_actions)
                )));
            }
            check_param_roots(tool, toolkit, where_)?;
        }
        "opencode" => {
            if !toolkit.allows_opencode_operation(tool.opencode_operation.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: opencode operation {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.opencode_operation),
                    repr_list(&toolkit.allowed_opencode_operations)
                )));
            }
            if tool.parameters.contains_key("directory") && toolkit.path_roots.is_empty() {
                return Err(ConfigError::tier1(format!(
                    "{where_}: declares a 'directory' parameter, but toolkit {tk_name} \
                     has no path_roots to validate it against"
                )));
            }
        }
        "artifact" => {
            if !toolkit.allows_artifact_operation(tool.artifact_operation.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: artifact operation {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.artifact_operation),
                    repr_list(&toolkit.allowed_artifact_operations)
                )));
            }
        }
        "kuma" => {
            if !toolkit.allows_kuma_operation(tool.kuma_operation.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: kuma operation {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.kuma_operation),
                    repr_list(&toolkit.allowed_kuma_operations)
                )));
            }
        }
        "git" => {
            if !toolkit.allows_git_operation(tool.git_operation.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: git operation {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.git_operation),
                    repr_list(&toolkit.allowed_git_operations)
                )));
            }
            if let Some(repo) = tool.parameters.get("repo").filter(|p| p.ptype == "enum") {
                let mut unknown: Vec<String> =
                    repo.values.iter().filter(|v| toolkit.git_repo(v).is_none()).cloned().collect();
                unknown.sort();
                unknown.dedup();
                if !unknown.is_empty() {
                    return Err(ConfigError::tier1(format!(
                        "{where_}: repo values {} are not in the 'repos' of toolkit {tk_name}",
                        repr_list(&unknown)
                    )));
                }
            }
        }
        "agent" => {
            if !toolkit.allows_agent_operation(tool.agent_operation.as_deref().unwrap_or("")) {
                return Err(ConfigError::tier1(format!(
                    "{where_}: agent operation {} is not in the allowlist {} of toolkit {tk_name}",
                    repr_opt(&tool.agent_operation),
                    repr_list(&toolkit.allowed_agent_operations)
                )));
            }
        }
        _ => {}
    }
    validate_ceilings(tool, toolkit, where_)
}

/// `_parse_cli_args`: parses `google_args`/`microsoft_args` -- one reader,
/// two names. An entry is exactly one of `{positional: true}`,
/// `{flag: --name}` or `{switch: --name}` (boolean parameter only).
pub fn parse_cli_args(
    raw: &Value,
    parameters: &IndexMap<String, Parameter>,
    where_: &str,
    field: &str,
) -> ConfigResult<IndexMap<String, CliArg>> {
    let Value::Object(raw) = raw else {
        return Err(ConfigError::new(format!("{where_}: {} must be a mapping", repr_str(field))));
    };
    let mut parsed = IndexMap::new();
    for (arg_name, arg_spec) in raw {
        if arg_name.is_empty() {
            return Err(ConfigError::new(format!("{where_}: {field} key must be a non-empty string")));
        }
        let Value::Object(arg_spec) = arg_spec else {
            return Err(ConfigError::new(format!(
                "{where_}: {field}.{} must be a mapping",
                repr_str(arg_name)
            )));
        };
        let flag = get_some(arg_spec, "flag");
        let positional = arg_spec.get("positional").is_some_and(py_truthy);

        // `in`, not `.get()`: an explicit `switch: null` is a broken
        // declaration, not an absent one.
        if let Some(switch) = arg_spec.get("switch") {
            if positional || flag.is_some() {
                return Err(ConfigError::new(format!(
                    "{where_}: {field}.{} sets 'switch' and also \
                     'flag'/'positional' -- a switch carries no value, pick one",
                    repr_str(arg_name)
                )));
            }
            let switch = match switch {
                Value::String(s) if switch_re().is_match(s) => s.clone(),
                other => {
                    return Err(ConfigError::new(format!(
                        "{where_}: {field}.{} has an unusable 'switch' name {} -- it must be a \
                         single option token like '--raw-query' (no whitespace, no '=', no placeholder)",
                        repr_str(arg_name),
                        repr_value(other)
                    )))
                }
            };
            let Some(param) = parameters.get(arg_name) else {
                return Err(ConfigError::new(format!(
                    "{where_}: {field}.{} sets 'switch', but the tool \
                     declares no parameter of that name",
                    repr_str(arg_name)
                )));
            };
            if param.ptype != "boolean" {
                return Err(ConfigError::new(format!(
                    "{where_}: {field}.{} sets 'switch', but parameter {} is type {} -- a switch \
                     needs a 'boolean', which is what decides whether the flag is there",
                    repr_str(arg_name),
                    repr_str(arg_name),
                    repr_str(&param.ptype)
                )));
            }
            parsed.insert(arg_name.clone(), CliArg { flag: None, positional: false, switch: Some(switch) });
            continue;
        }

        if positional && flag.is_some() {
            return Err(ConfigError::new(format!(
                "{where_}: {field}.{} is positional and also sets 'flag' -- pick one",
                repr_str(arg_name)
            )));
        }
        if !positional && !flag.is_some_and(py_truthy) {
            return Err(ConfigError::new(format!(
                "{where_}: {field}.{} is not positional \
                 and has no 'flag' -- a non-positional arg needs a flag name \
                 (or a 'switch', for a boolean the CLI takes without a value)",
                repr_str(arg_name)
            )));
        }
        parsed.insert(
            arg_name.clone(),
            CliArg { flag: flag.map(py_str), positional, switch: None },
        );
    }
    Ok(parsed)
}

/// `_str_str_map`: a flat string->string template map (query/params).
pub fn str_str_map(value: Option<&Value>, where_: &str, field: &str) -> ConfigResult<IndexMap<String, String>> {
    match value {
        None | Some(Value::Null) => Ok(IndexMap::new()),
        Some(Value::Object(m)) => {
            let mut out = IndexMap::new();
            for (k, v) in m {
                let Value::String(s) = v else {
                    return Err(ConfigError::new(format!(
                        "{where_}: '{field}' must be a mapping of string to string"
                    )));
                };
                out.insert(k.clone(), s.clone());
            }
            Ok(out)
        }
        Some(_) => Err(ConfigError::new(format!("{where_}: '{field}' must be a mapping of string to string"))),
    }
}

/// A truenas tool's `params`: one template per positional argument, each
/// a string or a nested object/array (1.23.0). Every leaf that is not a
/// string (a number, a boolean, null) is sent as written.
pub fn rpc_params_map(value: Option<&Value>, where_: &str) -> ConfigResult<IndexMap<String, Value>> {
    match value {
        None | Some(Value::Null) => Ok(IndexMap::new()),
        Some(Value::Object(m)) => Ok(m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
        Some(_) => Err(ConfigError::new(format!(
            "{where_}: 'params' must be a mapping of argument name to template"
        ))),
    }
}

/// `_body_raw_param`: recognises `body: {raw_param: <name>}`. `Ok(None)`
/// for an ordinary body template.
pub fn body_raw_param(value: &Value, where_: &str, field: &str) -> ConfigResult<Option<String>> {
    let Value::Object(m) = value else { return Ok(None) };
    let Some(name) = m.get("raw_param") else { return Ok(None) };
    if m.len() != 1 {
        let mut others: Vec<&str> = m.keys().filter(|k| *k != "raw_param").map(|k| k.as_str()).collect();
        others.sort();
        return Err(ConfigError::new(format!(
            "{where_}: '{field}' with 'raw_param' must have exactly one key -- \
             the raw value is the entire body, so the other keys \
             ({}) could never be sent. Move them to 'query' or the path.",
            repr_list(&others)
        )));
    }
    match name {
        Value::String(s) if !s.is_empty() => Ok(Some(s.clone())),
        other => Err(ConfigError::new(format!(
            "{where_}: '{field}.raw_param' must be the name of a parameter \
             (a non-empty string), not {}",
            repr_value(other)
        ))),
    }
}

/// `_nested_body_map`: a body template that may be nested. Every JSON
/// value is acceptable, so this only copies.
pub fn nested_body_map(value: &Value, _where: &str, _field: &str) -> ConfigResult<Value> {
    Ok(value.clone())
}

/// Anything brace-shaped in an `http` template: a complete `{...}` group,
/// or a lone `{`/`}` with no partner.
fn brace_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{[^{}]*\}|[{}]").expect("static regex"))
}

/// Every brace in an `http` path/query/body template is a known
/// placeholder (1.27.0).
///
/// [`placeholder_re`] only *finds* the well-formed `{name}` shape, so the
/// unknown-parameter guard never saw `{name?}`, `{Name}`, `{ name }` or a
/// stray brace -- such a template loaded (and passed `admin.tool_validate`)
/// and the text went to the target literally. There is no escaping and no
/// other placeholder syntax, so any brace that is not exactly
/// `{<declared parameter>}` is a configuration error. For an optional query
/// value the answer is not a marker but `required: false`: an absent
/// optional leaves its key out (`validate::build_http_request`).
pub fn check_http_placeholder_syntax(
    templates: &[(String, String)],
    parameters: &IndexMap<String, Parameter>,
    where_: &str,
) -> ConfigResult<()> {
    for (location, template) in templates {
        for m in brace_token_re().find_iter(template) {
            let token = m.as_str();
            let name = placeholder_re()
                .captures(token)
                .filter(|c| c.get(0).map(|g| g.as_str()) == Some(token))
                .map(|c| c[1].to_string());
            // A well-formed `{name}` is the unknown-parameter guard's to
            // judge (its message is a frozen fixture); this check is only
            // about shapes that guard cannot see.
            if name.is_some() {
                continue;
            }
            let what = "unsupported syntax";
            let declared: Vec<String> = {
                let mut d: Vec<String> = parameters.keys().cloned().collect();
                d.sort();
                d
            };
            return Err(ConfigError::new(format!(
                "{where_}: {location} template {} contains {} ({what}), which is not a known \
                 placeholder. The only placeholder syntax is '{{name}}' with a declared parameter \
                 (declared: {}); for an optional query value declare the parameter with \
                 required: false instead of marking the placeholder.",
                repr_str(template),
                repr_str(token),
                repr_list(&declared)
            )));
        }
    }
    Ok(())
}

/// Parses an http tool's optional `verify:` block (1.27.0).
///
/// verify only reads: a method in [`VERIFY_READ_METHODS`] needs no body;
/// any other method is accepted only with a *fixed* `body` template.
/// Placeholders inside it are allowed -- the caller adds them to the
/// unknown-parameter guard, so each is a declared, validated parameter.
/// Raw-body mode (the agent's own document as the body) is refused.
pub fn parse_verify(value: &Value, where_: &str) -> ConfigResult<HttpVerify> {
    let Value::Object(m) = value else {
        return Err(ConfigError::new(format!("{where_}: 'verify' must be a mapping")));
    };
    let mut unknown: Vec<String> = m.keys().filter(|k| !VERIFY_FIELDS.contains(&k.as_str())).cloned().collect();
    if !unknown.is_empty() {
        unknown.sort();
        return Err(ConfigError::new(format!("{where_}: 'verify' has unknown keys {}", repr_list(&unknown))));
    }
    let method = match m.get("method") {
        None | Some(Value::Null) => "GET".to_string(),
        Some(Value::String(s)) if !s.is_empty() => s.to_uppercase(),
        Some(_) => return Err(ConfigError::new(format!("{where_}: 'verify.method' must be a string"))),
    };
    let path_template = match m.get("path") {
        Some(Value::String(p)) if p.starts_with('/') => p.clone(),
        _ => {
            return Err(ConfigError::new(format!(
                "{where_}: 'verify.path' must be a string starting with '/'"
            )))
        }
    };
    let query_template = str_str_map(m.get("query"), where_, "verify.query")?;
    let body_template = match get_some(m, "body") {
        None => None,
        Some(Value::Object(b)) if b.contains_key("raw_param") => {
            return Err(ConfigError::new(format!(
                "{where_}: 'verify.body' cannot use raw_param -- a verify body must be a fixed template"
            )))
        }
        Some(raw) => {
            if !body_file_params(Some(raw), where_)?.is_empty() {
                return Err(ConfigError::new(format!(
                    "{where_}: 'verify.body' cannot read 'from_file' -- a verify body must be a fixed template"
                )));
            }
            Some(nested_body_map(raw, where_, "verify.body")?)
        }
    };
    if !VERIFY_READ_METHODS.contains(&method.as_str()) && body_template.is_none() {
        return Err(ConfigError::new(format!(
            "{where_}: verify method {} is not a read method ({}) and writes or may write; it is \
             only allowed with a fixed 'verify.body'",
            repr_str(&method),
            VERIFY_READ_METHODS.join(", ")
        )));
    }
    let require_body = match m.get("require_body") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(ConfigError::new(format!("{where_}: 'verify.require_body' must be true or false"))),
    };
    Ok(HttpVerify { method, path_template, query_template, body_template, require_body })
}

/// `_collect_template_strings`: a nested body template's leaf strings.
pub fn collect_template_strings(body: Option<&Value>) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Object(m) => m.values().for_each(|x| walk(x, out)),
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Some(b) = body {
        walk(b, &mut out);
    }
    out
}

/// The only encoding a body `from_file` field can have: the file's bytes
/// go into a JSON string, so they have to be text-safe.
pub const BODY_FILE_ENCODINGS: &[&str] = &["base64"];

/// The ceiling no tool's `max_file_bytes` may exceed: the whole file is
/// held in memory, and once more as base64, for the length of a call.
pub const MAX_FILE_BYTES_CEILING: i64 = 10 * 1024 * 1024;

/// The parameters a body template reads files from, in order (1.21.0).
///
/// A mapping with a `from_file` key is not an ordinary body object: it is
/// `{from_file: <path parameter>, encoding: base64}`, which the executor
/// replaces by that file's content (`execute::http::fill_body_files`), and
/// exactly those two keys. `Err` names the first malformed one.
pub fn body_file_params(body: Option<&Value>, where_: &str) -> ConfigResult<Vec<String>> {
    fn walk(v: &Value, at: &str, where_: &str, out: &mut Vec<String>) -> ConfigResult<()> {
        match v {
            Value::Object(m) if m.contains_key("from_file") => {
                let mut unknown: Vec<&str> =
                    m.keys().map(String::as_str).filter(|k| *k != "from_file" && *k != "encoding").collect();
                unknown.sort();
                if !unknown.is_empty() {
                    return Err(ConfigError::new(format!(
                        "{where_}: '{at}' reads a file and takes only 'from_file' and 'encoding' \
                         -- unknown fields {}",
                        repr_list(&unknown)
                    )));
                }
                let name = match &m["from_file"] {
                    Value::String(s) if !s.is_empty() => s.clone(),
                    other => {
                        return Err(ConfigError::new(format!(
                            "{where_}: '{at}.from_file' must be the name of a path parameter, not {}",
                            repr_value(other)
                        )))
                    }
                };
                match m.get("encoding") {
                    Some(Value::String(e)) if BODY_FILE_ENCODINGS.contains(&e.as_str()) => {}
                    other => {
                        return Err(ConfigError::new(format!(
                            "{where_}: '{at}.encoding' must be one of {}, not {}",
                            repr_list(BODY_FILE_ENCODINGS),
                            repr_value(other.unwrap_or(&Value::Null))
                        )))
                    }
                }
                out.push(name);
            }
            Value::Object(m) => {
                for (k, x) in m {
                    walk(x, &format!("{at}.{k}"), where_, out)?;
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(x, &format!("{at}[{i}]"), where_, out)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut out = Vec::new();
    if let Some(b) = body {
        walk(b, "body", where_, &mut out)?;
    }
    Ok(out)
}

/// The fields any tool spec may carry, whatever its executor. `executor`
/// is only a reminder for the reader; it has to name the toolkit's own.
const COMMON_TOOL_FIELDS: &[&str] = &[
    "category",
    "description",
    "enabled",
    "executor",
    "id",
    "idempotent",
    "max_output_bytes",
    "parameters",
    "required_scopes",
    "ssh_dispatch",
    "timeout_seconds",
    "title",
    "toolkit",
    "version",
];

/// `delete: {max_entries: N, files_only: bool}` on a delete tool (1.28.0).
/// Both keys are optional; `max_entries` is 1 to `MAX_DELETE_ENTRIES`.
fn parse_delete_block(value: &Value, where_: &str) -> ConfigResult<(i64, bool)> {
    use crate::execute::bounded_delete::MAX_DELETE_ENTRIES;
    let Value::Object(block) = value else {
        return Err(ConfigError::new(format!("{where_}: 'delete' must be a mapping")));
    };
    let unknown: Vec<&str> = block.keys().map(String::as_str).filter(|k| !["files_only", "max_entries"].contains(k)).collect();
    if !unknown.is_empty() {
        return Err(ConfigError::new(format!("{where_}: 'delete' has unknown keys {}", repr_list(&unknown))));
    }
    let max_entries = match block.get("max_entries") {
        None | Some(Value::Null) => MAX_DELETE_ENTRIES,
        Some(Value::Number(n)) => match n.as_i64() {
            Some(n) if (1..=MAX_DELETE_ENTRIES).contains(&n) => n,
            _ => {
                return Err(ConfigError::new(format!(
                    "{where_}: 'delete.max_entries' must be an integer from 1 to {MAX_DELETE_ENTRIES} (MAX_DELETE_ENTRIES), not {n}"
                )))
            }
        },
        Some(other) => {
            return Err(ConfigError::new(format!(
                "{where_}: 'delete.max_entries' must be an integer from 1 to {MAX_DELETE_ENTRIES}, not {}",
                repr_value(other)
            )))
        }
    };
    let files_only = match block.get("files_only") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            return Err(ConfigError::new(format!(
                "{where_}: 'delete.files_only' must be true or false, not {}",
                repr_value(other)
            )))
        }
    };
    Ok((max_entries, files_only))
}

/// The fields only a tool on one executor reads.
fn executor_tool_fields(executor: &str) -> &'static [&'static str] {
    match executor {
        "docker" | "local" => &["argv", "binary", "stdin"],
        "ssh" => &["argv", "binary"],
        "http" => &["base_url", "body", "max_file_bytes", "method", "path", "query", "verify"],
        "truenas" => &["job", "method", "params"],
        "file" => &["delete", "file_operation", "mode", "operation", "run_as"],
        "google" => &["google_action", "google_args"],
        "microsoft" => &["microsoft_action", "microsoft_args"],
        "opencode" => &["opencode_operation", "operation"],
        "agent" => &["agent_operation", "operation"],
        "artifact" => &["artifact_operation", "operation"],
        "kuma" => &["kuma_operation", "operation"],
        "git" => &["git_operation", "operation"],
        _ => &[],
    }
}

/// The longest fixed `stdin` text a tool may carry (1.25.0).
pub const MAX_STDIN_BYTES: usize = 65536;

/// The file modes a `write` tool may fix (1.25.0): owner-only, group-read,
/// world-read. Nothing executable, nothing world-writable.
pub const FILE_MODES: &[&str] = &["0600", "0640", "0644"];

/// The fields a parameter spec may carry.
const PARAMETER_FIELDS: &[&str] = &[
    "allow_control_characters",
    "derived",
    "description",
    "flag",
    "maximum",
    "minimum",
    "must_resolve_under",
    "pattern",
    "required",
    "secret",
    "type",
    "values",
];

/// The fields a `google_args`/`microsoft_args` entry may carry.
const CLI_ARG_FIELDS: &[&str] = &["flag", "positional", "switch"];

/// Every field of `spec` that nothing reads for a tool on `executor`, as
/// a dotted path (`parameters.repo.patern`), sorted (1.21.0). A field
/// nothing reads is not harmless: the tool looks like it does what the
/// field says, and does something else.
pub fn unknown_tool_fields(spec: &Map<String, Value>, executor: &str) -> Vec<String> {
    let known = executor_tool_fields(executor);
    let mut out: Vec<String> = spec
        .keys()
        .filter(|k| !COMMON_TOOL_FIELDS.contains(&k.as_str()) && !known.contains(&k.as_str()))
        .cloned()
        .collect();
    if let Some(Value::Object(params)) = spec.get("parameters") {
        for (name, p) in params {
            if let Value::Object(p) = p {
                out.extend(
                    p.keys().filter(|k| !PARAMETER_FIELDS.contains(&k.as_str())).map(|k| format!("parameters.{name}.{k}")),
                );
            }
        }
    }
    for args_key in ["google_args", "microsoft_args"] {
        if !known.contains(&args_key) {
            continue;
        }
        if let Some(Value::Object(args)) = spec.get(args_key) {
            for (name, a) in args {
                if let Value::Object(a) = a {
                    out.extend(
                        a.keys().filter(|k| !CLI_ARG_FIELDS.contains(&k.as_str())).map(|k| format!("{args_key}.{name}.{k}")),
                    );
                }
            }
        }
    }
    out.sort();
    out
}

/// The strict half of [`parse_tool_spec`]: no field nothing reads, and an
/// `executor` that names the toolkit's own. Runs after `parse_tool`, so
/// a definition that is wrong anyway keeps that error.
fn check_tool_fields(spec: &Value, tier1: &Tier1) -> ConfigResult<()> {
    let Value::Object(spec) = spec else { return Ok(()) };
    let Some(Value::String(toolkit_name)) = spec.get("toolkit") else { return Ok(()) };
    let Ok(toolkit) = tier1.toolkit(toolkit_name) else { return Ok(()) };
    let where_ = format!("tool {}", repr_value(spec.get("id").unwrap_or(&Value::Null)));
    let unknown = unknown_tool_fields(spec, &toolkit.executor);
    if !unknown.is_empty() {
        return Err(ConfigError::new(format!(
            "{where_}: unknown fields {} -- nothing reads them for a tool on the {} executor, so the \
             tool would not do what they say. Remove or correct them.",
            repr_list(&unknown),
            repr_str(&toolkit.executor)
        )));
    }
    if let Some(executor) = spec.get("executor").filter(|v| !v.is_null()) {
        if !py_eq(executor, &Value::String(toolkit.executor.clone())) {
            return Err(ConfigError::new(format!(
                "{where_}: executor={} does not match toolkit {}, whose executor is {}",
                repr_value(executor),
                repr_str(toolkit_name),
                repr_str(&toolkit.executor)
            )));
        }
    }
    Ok(())
}

fn parse_tool(spec: &Value, tier1: &Tier1) -> ConfigResult<ToolDef> {
    let Value::Object(spec) = spec else {
        return Err(ConfigError::new("tools.yaml: every entry must be a mapping"));
    };

    let tool_id = match spec.get("id") {
        Some(Value::String(s)) if tool_id_re().is_match(s) => s.clone(),
        other => {
            return Err(ConfigError::new(format!(
                "Tool ID {} does not match the scheme <toolkit>.<action>",
                repr_value(other.unwrap_or(&Value::Null))
            )))
        }
    };
    let where_owned = format!("tool {}", repr_str(&tool_id));
    let where_ = where_owned.as_str();

    let Some(Value::String(toolkit_name)) = spec.get("toolkit") else {
        return Err(ConfigError::new(format!("{where_}: field 'toolkit' is missing")));
    };
    if !tool_id.starts_with(&format!("{toolkit_name}.")) {
        return Err(ConfigError::new(format!(
            "{where_}: ID prefix does not match toolkit {}",
            repr_str(toolkit_name)
        )));
    }
    // A removed toolkit is a Tier 1 violation, not a syntax error (FR-4.7).
    let toolkit = tier1.toolkit(toolkit_name).map_err(|exc| ConfigError::tier1(format!("{where_}: {exc}")))?;

    let category = match spec.get("category") {
        Some(Value::String(c)) if CATEGORIES.contains(&c.as_str()) => c.clone(),
        other => {
            return Err(ConfigError::new(format!(
                "{where_}: category={} is unknown (allowed: {})",
                repr_value(other.unwrap_or(&Value::Null)),
                repr_list(CATEGORIES)
            )))
        }
    };

    let mut parameters: IndexMap<String, Parameter> = IndexMap::new();
    match spec.get("parameters") {
        Some(Value::Object(m)) => {
            for (name, pspec) in m {
                parameters.insert(name.clone(), parse_parameter(name, pspec, where_)?);
            }
        }
        Some(v) if py_truthy(v) => {
            // PORT NOTE: Python crashed with AttributeError on a non-mapping.
            return Err(ConfigError::new(format!("{where_}: 'parameters' must be a mapping")));
        }
        _ => {}
    }
    let scopes: Vec<String> = match spec.get("required_scopes") {
        Some(v) if py_truthy(v) => py_iter(v)?.iter().map(py_str).collect(),
        _ => Vec::new(),
    };

    let mut tool = ToolDef {
        id: tool_id.clone(),
        toolkit: toolkit_name.clone(),
        version: 1,
        title: String::new(),
        description: String::new(),
        category,
        idempotent: false,
        ssh_dispatch: false,
        enabled: false,
        parameters: IndexMap::new(),
        required_scopes: scopes.clone(),
        timeout_seconds: 30,
        max_output_bytes: 65536,
        binary: None,
        argv: Vec::new(),
        stdin: None,
        http_method: None,
        path_template: None,
        query_template: IndexMap::new(),
        body_template: None,
        body_raw_param: None,
        max_file_bytes: None,
        base_url: None,
        verify: None,
        rpc_method: None,
        rpc_job: false,
        params_template: None,
        file_operation: None,
        file_mode: None,
        delete_max_entries: None,
        delete_files_only: false,
        google_action: None,
        google_args: None,
        microsoft_action: None,
        microsoft_args: None,
        opencode_operation: None,
        agent_operation: None,
        artifact_operation: None,
        kuma_operation: None,
        git_operation: None,
        run_as: None,
        destination: None,
    };
    // Every template string that may contain a `{param}` placeholder.
    let mut all_templates: Vec<String> = Vec::new();

    // `spec.get(a) or spec.get(b)`.
    let either = |a: &str, b: &str| -> Option<Value> {
        spec.get(a).filter(|v| py_truthy(v)).or_else(|| spec.get(b)).cloned()
    };
    let nonempty_str = |v: Option<Value>| -> Option<String> {
        match v {
            Some(Value::String(s)) if !s.is_empty() => Some(s),
            _ => None,
        }
    };

    // Refused rather than ignored: a definition that means to feed a
    // process must not quietly run it with nothing on stdin.
    if spec.get("stdin").is_some_and(|v| !v.is_null()) && !["docker", "local"].contains(&toolkit.executor.as_str()) {
        return Err(ConfigError::new(format!(
            "{where_}: 'stdin' is only supported on docker and local tools, not {}",
            repr_str(&toolkit.executor)
        )));
    }

    match toolkit.executor.as_str() {
        "docker" | "local" | "ssh" => {
            let Some(Value::String(binary)) = spec.get("binary") else {
                return Err(ConfigError::new(format!("{where_}: field 'binary' is missing")));
            };
            tool.binary = Some(binary.clone());
            let argv = match spec.get("argv") {
                None => Vec::new(),
                Some(Value::Array(items)) if items.iter().all(|a| a.is_string()) => {
                    items.iter().map(py_str).collect()
                }
                Some(_) => return Err(ConfigError::new(format!("{where_}: 'argv' must be a list of strings"))),
            };
            match spec.get("stdin") {
                None | Some(Value::Null) => {}
                Some(Value::String(text)) if text.len() <= MAX_STDIN_BYTES => tool.stdin = Some(text.clone()),
                Some(Value::String(_)) => {
                    return Err(ConfigError::new(format!(
                        "{where_}: 'stdin' is longer than {MAX_STDIN_BYTES} bytes"
                    )))
                }
                Some(_) => return Err(ConfigError::new(format!("{where_}: 'stdin' must be a string"))),
            }
            all_templates.extend(argv.iter().cloned());
            tool.argv = argv;
        }
        "http" => {
            let Some(Value::String(method)) = spec.get("method") else {
                return Err(ConfigError::new(format!("{where_}: field 'method' is missing")));
            };
            tool.http_method = Some(method.clone());
            let path_template = match spec.get("path") {
                Some(Value::String(p)) if p.starts_with('/') => p.clone(),
                _ => {
                    return Err(ConfigError::new(format!(
                        "{where_}: field 'path' must be a string starting with '/'"
                    )))
                }
            };
            tool.query_template = str_str_map(spec.get("query"), where_, "query")?;
            if let Some(raw_body) = get_some(spec, "body") {
                tool.body_raw_param = body_raw_param(raw_body, where_, "body")?;
                tool.body_template = Some(match &tool.body_raw_param {
                    // Desugared to the wrapper it replaces.
                    Some(name) => json!({ name.clone(): format!("{{{name}}}") }),
                    None => nested_body_map(raw_body, where_, "body")?,
                });
            }
            if let Some(base) = get_some(spec, "base_url") {
                tool.base_url = Some(validate_http_base_url(&py_str(base), where_, "base_url")?);
            }
            let file_params = body_file_params(tool.body_template.as_ref(), where_)?;
            for name in &file_params {
                match parameters.get(name) {
                    Some(p) if p.ptype == "path" => {}
                    _ => {
                        return Err(ConfigError::new(format!(
                            "{where_}: body reads 'from_file' {}, which is not a declared parameter \
                             of type 'path' -- only a derived path checked against \
                             'must_resolve_under' may name the file",
                            repr_str(name)
                        )))
                    }
                }
            }
            match (file_params.is_empty(), get_some(spec, "max_file_bytes")) {
                (true, None) => {}
                (true, Some(_)) => {
                    return Err(ConfigError::new(format!(
                        "{where_}: 'max_file_bytes' is only meaningful with a body 'from_file' field"
                    )))
                }
                (false, None) => {
                    return Err(ConfigError::new(format!(
                        "{where_}: a body 'from_file' field needs 'max_file_bytes', the largest \
                         file the tool may send"
                    )))
                }
                (false, Some(raw)) => {
                    let limit = py_int(raw)?;
                    if !(1..=MAX_FILE_BYTES_CEILING).contains(&limit) {
                        return Err(ConfigError::new(format!(
                            "{where_}: max_file_bytes={limit} must be between 1 and {MAX_FILE_BYTES_CEILING}"
                        )));
                    }
                    tool.max_file_bytes = Some(limit);
                }
            }
            // A tool that sends a local file out is never `read`, which
            // `admin.tool_enable` applies without a human.
            if !file_params.is_empty() && tool.category == "read" {
                return Err(ConfigError::new(format!(
                    "{where_}: a body 'from_file' field sends a local file to the target -- \
                     its category cannot be 'read'"
                )));
            }
            if let Some(raw_verify) = get_some(spec, "verify") {
                tool.verify = Some(parse_verify(raw_verify, where_)?);
            }
            // Every brace in an http template must be exactly
            // `{<declared parameter>}` (1.27.0) -- before, `{name?}`,
            // `{Name}`, `{ name }` or a stray brace loaded and went to the
            // target literally.
            let mut located: Vec<(String, String)> = vec![("path".into(), path_template.clone())];
            located.extend(tool.query_template.iter().map(|(k, v)| (format!("query {}", repr_str(k)), v.clone())));
            located.extend(collect_template_strings(tool.body_template.as_ref()).into_iter().map(|v| ("body".into(), v)));
            if let Some(v) = &tool.verify {
                located.push(("verify.path".into(), v.path_template.clone()));
                located.extend(v.query_template.iter().map(|(k, t)| (format!("verify.query {}", repr_str(k)), t.clone())));
                located.extend(
                    collect_template_strings(v.body_template.as_ref()).into_iter().map(|t| ("verify.body".into(), t)),
                );
            }
            check_http_placeholder_syntax(&located, &parameters, where_)?;
            all_templates.push(path_template.clone());
            all_templates.extend(tool.query_template.values().cloned());
            all_templates.extend(collect_template_strings(tool.body_template.as_ref()));
            if let Some(v) = &tool.verify {
                all_templates.push(v.path_template.clone());
                all_templates.extend(v.query_template.values().cloned());
                all_templates.extend(collect_template_strings(v.body_template.as_ref()));
            }
            tool.path_template = Some(path_template);
        }
        "truenas" => {
            let Some(Value::String(method)) = spec.get("method") else {
                return Err(ConfigError::new(format!("{where_}: field 'method' is missing")));
            };
            tool.rpc_method = Some(method.clone());
            tool.rpc_job = spec.get("job").is_some_and(py_truthy);
            let params = rpc_params_map(spec.get("params"), where_)?;
            for value in params.values() {
                all_templates.extend(collect_template_strings(Some(value)));
            }
            tool.params_template = Some(params);
        }
        "file" => {
            let op = either("file_operation", "operation");
            let op = match op {
                Some(Value::String(s)) if ["read", "write", "patch", "list", "delete"].contains(&s.as_str()) => s,
                _ => {
                    return Err(ConfigError::new(format!(
                        "{where_}: field 'file_operation' must be one of read/write/patch/list/delete"
                    )))
                }
            };
            if op == "delete" && tool.category == "read" {
                return Err(ConfigError::new(format!("{where_}: a delete tool's category cannot be 'read'")));
            }
            match spec.get("mode") {
                None | Some(Value::Null) => {}
                Some(Value::String(m)) if op == "write" && FILE_MODES.contains(&m.as_str()) => {
                    tool.file_mode = Some(u32::from_str_radix(m, 8).expect("allowlisted octal"));
                }
                Some(other) => {
                    return Err(ConfigError::new(format!(
                        "{where_}: 'mode' {} is not allowed -- only a write tool takes one, as a quoted string of {}",
                        repr_value(other),
                        repr_list(FILE_MODES)
                    )))
                }
            }
            match get_some(spec, "delete") {
                None => {}
                Some(block) if op == "delete" => {
                    let (max_entries, files_only) = parse_delete_block(block, where_)?;
                    tool.delete_max_entries = Some(max_entries);
                    tool.delete_files_only = files_only;
                }
                Some(_) => {
                    return Err(ConfigError::new(format!(
                        "{where_}: 'delete' options only apply to file_operation: delete"
                    )))
                }
            }
            tool.file_operation = Some(op);
            // Per-tool `run_as` override. An empty string is distinct from
            // unset: it means "run as the container user".
            if let Some(raw_run_as) = spec.get("run_as") {
                if !raw_run_as.is_null() {
                    let run_as = py_str(raw_run_as).trim().to_string();
                    if !run_as.is_empty() {
                        parse_run_as(&run_as).map_err(|exc| ConfigError::new(format!("{where_}: {exc}")))?;
                    }
                    tool.run_as = Some(run_as);
                }
            }
        }
        "google" | "microsoft" => {
            let provider = toolkit.executor.as_str();
            let action_key = format!("{provider}_action");
            let args_key = format!("{provider}_args");
            let Some(action) = nonempty_str(spec.get(&action_key).cloned()) else {
                return Err(ConfigError::new(format!("{where_}: field '{action_key}' is missing")));
            };
            let raw_args = match spec.get(&args_key) {
                Some(v) if py_truthy(v) => v.clone(),
                _ => Value::Object(Map::new()),
            };
            let args = parse_cli_args(&raw_args, &parameters, where_, &args_key)?;
            all_templates.extend(args.values().map(|e| e.flag.clone().unwrap_or_default()));
            if provider == "google" {
                tool.google_action = Some(action);
                tool.google_args = Some(args);
            } else {
                tool.microsoft_action = Some(action);
                tool.microsoft_args = Some(args);
            }
        }
        "opencode" => {
            let Some(op) = nonempty_str(either("opencode_operation", "operation")) else {
                return Err(ConfigError::new(format!("{where_}: field 'opencode_operation' is missing")));
            };
            if op_params(OPENCODE_OPERATION_PARAMS, &op).is_none() {
                return Err(ConfigError::new(format!(
                    "{where_}: opencode_operation {} is unknown (known: {})",
                    repr_str(&op),
                    repr_list(&sorted_ops(OPENCODE_OPERATION_PARAMS))
                )));
            }
            validate_named_op_params("opencode", OPENCODE_OPERATION_PARAMS, &op, &parameters, where_)?;
            tool.opencode_operation = Some(op);
        }
        "agent" => {
            let Some(op) = nonempty_str(either("agent_operation", "operation")) else {
                return Err(ConfigError::new(format!("{where_}: field 'agent_operation' is missing")));
            };
            if op_params(AGENT_OPERATION_PARAMS, &op).is_none() {
                return Err(ConfigError::new(format!(
                    "{where_}: agent_operation {} is unknown (known: {})",
                    repr_str(&op),
                    repr_list(&sorted_ops(AGENT_OPERATION_PARAMS))
                )));
            }
            validate_named_op_params("agent", AGENT_OPERATION_PARAMS, &op, &parameters, where_)?;
            tool.agent_operation = Some(op);
        }
        "artifact" => {
            let Some(op) = nonempty_str(either("artifact_operation", "operation")) else {
                return Err(ConfigError::new(format!("{where_}: field 'artifact_operation' is missing")));
            };
            if op_params(ARTIFACT_OPERATION_PARAMS, &op).is_none() {
                return Err(ConfigError::new(format!(
                    "{where_}: artifact_operation {} is unknown (known: {})",
                    repr_str(&op),
                    repr_list(&sorted_ops(ARTIFACT_OPERATION_PARAMS))
                )));
            }
            validate_op_params("artifact", ARTIFACT_OPERATION_PARAMS, &op, &parameters, where_)?;
            tool.artifact_operation = Some(op);
        }
        "kuma" => {
            let Some(op) = nonempty_str(either("kuma_operation", "operation")) else {
                return Err(ConfigError::new(format!("{where_}: field 'kuma_operation' is missing")));
            };
            if op_params(KUMA_OPERATION_PARAMS, &op).is_none() {
                return Err(ConfigError::new(format!(
                    "{where_}: kuma_operation {} is unknown (known: {})",
                    repr_str(&op),
                    repr_list(&sorted_ops(KUMA_OPERATION_PARAMS))
                )));
            }
            validate_op_params("kuma", KUMA_OPERATION_PARAMS, &op, &parameters, where_)?;
            validate_kuma_params(&op, &tool.category, &parameters, where_)?;
            tool.kuma_operation = Some(op);
        }
        "git" => {
            let Some(op) = nonempty_str(either("git_operation", "operation")) else {
                return Err(ConfigError::new(format!("{where_}: field 'git_operation' is missing")));
            };
            if op_params(GIT_OPERATION_PARAMS, &op).is_none() {
                return Err(ConfigError::new(format!(
                    "{where_}: git_operation {} is unknown (known: {})",
                    repr_str(&op),
                    repr_list(&sorted_ops(GIT_OPERATION_PARAMS))
                )));
            }
            validate_op_params("git", GIT_OPERATION_PARAMS, &op, &parameters, where_)?;
            validate_git_params(&op, &tool.category, &parameters, where_)?;
            tool.git_operation = Some(op);
        }
        _ => {}
    }

    // A secret goes only where it is sent: a truenas tool's `params`.
    // Scopes and derived values are logged, and the other executors put
    // their values on a command line, in a URL or in a file.
    let secrets: Vec<&String> = parameters.values().filter(|p| p.secret).map(|p| &p.name).collect();
    if !secrets.is_empty() {
        // A file write's content and a patch's replacement text are sent
        // to the file, nowhere else (1.25.0).
        let file_text = toolkit.executor == "file"
            && matches!(tool.file_operation.as_deref(), Some("write") | Some("patch"))
            && secrets.iter().all(|s| s.as_str() == "content" || s.as_str() == "new_string");
        if toolkit.executor != "truenas" && !file_text {
            return Err(ConfigError::new(format!(
                "{where_}: secret parameters are only supported on truenas tools and on a file write's \
                 'content' or a patch's 'new_string', not {}",
                repr_str(&toolkit.executor)
            )));
        }
        let logged = scopes.iter().chain(parameters.values().filter_map(|p| p.derived.as_ref()));
        for template in logged {
            if let Some(name) = placeholders(template).into_iter().find(|p| secrets.contains(&p)) {
                return Err(ConfigError::new(format!(
                    "{where_}: secret parameter {} may only be used in 'params'",
                    repr_str(&name)
                )));
            }
        }
    }

    // Every placeholder must point to a declared parameter.
    let derived_templates = parameters.values().map(|p| p.derived.clone().unwrap_or_default());
    for template in all_templates.into_iter().chain(scopes).chain(derived_templates) {
        for placeholder in placeholders(&template) {
            if !parameters.contains_key(&placeholder) {
                return Err(ConfigError::new(format!(
                    "{where_}: template references unknown parameter {}",
                    repr_str(&placeholder)
                )));
            }
        }
    }

    // PORT NOTE: a non-integer `version`/`timeout_seconds`/... was an
    // uncaught ValueError in Python (a startup crash); here it is a
    // ConfigError, so the one tool is disabled like any other bad entry.
    let int_or = |key: &str, default: i64| -> ConfigResult<i64> {
        match spec.get(key) {
            None => Ok(default),
            Some(v) => py_int(v),
        }
    };
    tool.version = int_or("version", 1)?;
    tool.title = spec.get("title").map(py_str).unwrap_or_else(|| tool_id.clone());
    tool.description = spec.get("description").map(py_str).unwrap_or_default();
    tool.idempotent = spec.get("idempotent").is_some_and(py_truthy);
    tool.ssh_dispatch = spec.get("ssh_dispatch").is_some_and(py_truthy);
    tool.enabled = spec.get("enabled").is_some_and(py_truthy);
    tool.timeout_seconds = int_or("timeout_seconds", 30)?;
    tool.max_output_bytes = int_or("max_output_bytes", 65536)?;
    tool.parameters = parameters;

    validate_against_tier1(&tool, toolkit)?;
    Ok(tool)
}

/// `_expand_tool`: one `ToolDef` per destination the toolkit declares
/// (FR-8.3h), id `<id>@<destination>`; the unmodified tool otherwise.
pub fn expand_tool(tool: &ToolDef, toolkit: &Toolkit) -> Vec<ToolDef> {
    if toolkit.destinations.is_empty() {
        return vec![tool.clone()];
    }
    toolkit
        .destinations
        .iter()
        .map(|dest| {
            let mut t = tool.clone();
            t.id = format!("{}@{dest}", tool.id);
            t.destination = Some(dest.clone());
            t
        })
        .collect()
}

// -- Versioned entries (FR-3.1/3.3) ------------------------------------------

/// Bookkeeping keys that live on a raw entry rather than inside a
/// version's own `spec`.
pub const ENTRY_KEYS: &[&str] = &["current_version", "deleted", "enabled", "id", "versions"];
/// Additionally stripped from a version's stored `spec`.
pub const VERSION_SPEC_STRIP: &[&str] = &["enabled", "id", "version"];

/// Timestamp for a new tool version / pending action record (UTC,
/// `%Y-%m-%dT%H:%M:%S%z`).
pub fn now_iso() -> String {
    crate::timeutil::now_utc_iso()
}

fn is_versioned(entry: &Map<String, Value>) -> bool {
    matches!(entry.get("versions"), Some(Value::Array(_)))
}

fn strip_fields(source: &Map<String, Value>) -> Map<String, Value> {
    source
        .iter()
        .filter(|(k, _)| !VERSION_SPEC_STRIP.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn get_bool(m: &Map<String, Value>, key: &str) -> bool {
    m.get(key).is_some_and(py_truthy)
}

fn versions_of(entry: &Map<String, Value>) -> Vec<Value> {
    match entry.get("versions") {
        Some(Value::Array(v)) => v.clone(),
        _ => Vec::new(),
    }
}

fn version_record(version: i64, spec: Map<String, Value>, created_at: Value, created_by: Value, superseded: bool) -> Value {
    json!({
        "version": version,
        "spec": Value::Object(spec),
        "created_at": created_at,
        "created_by": created_by,
        "superseded": superseded,
    })
}

/// `_current_version_spec`: resolves one raw entry to
/// `(spec, version, enabled, deleted)`. `spec` is the flat,
/// `parse_tool_spec`-shaped mapping. `Ok(None)` when a versioned entry's
/// `current_version` matches none of its `versions`.
pub fn current_version_spec(
    entry: &Map<String, Value>,
) -> ConfigResult<Option<(Map<String, Value>, i64, bool, bool)>> {
    let tool_id = entry.get("id").cloned().unwrap_or(Value::Null);
    if !is_versioned(entry) {
        let mut spec = entry.clone();
        if !spec.contains_key("version") {
            spec.insert("version".into(), json!(1));
        }
        let version = py_int(&spec["version"])?;
        return Ok(Some((spec, version, get_bool(entry, "enabled"), false)));
    }

    let versions = versions_of(entry);
    let current = entry.get("current_version").cloned().unwrap_or(Value::Null);
    let matched = versions.iter().find_map(|v| match v {
        Value::Object(m) if py_eq(m.get("version").unwrap_or(&Value::Null), &current) => Some(m),
        _ => None,
    });
    let Some(matched) = matched else { return Ok(None) };
    let mut spec = match matched.get("spec") {
        Some(Value::Object(m)) => m.clone(),
        Some(v) if py_truthy(v) => {
            // PORT NOTE: Python's `dict(...)` raised on a non-mapping spec.
            return Err(ConfigError::new(format!(
                "tools.yaml: entry {}: a version's 'spec' must be a mapping",
                repr_value(&tool_id)
            )));
        }
        _ => Map::new(),
    };
    spec.insert("id".into(), tool_id);
    let version_num = py_int(matched.get("version").unwrap_or(&current))?;
    spec.insert("version".into(), json!(version_num));
    Ok(Some((spec, version_num, get_bool(entry, "enabled"), get_bool(entry, "deleted"))))
}

/// The raw `tools.yaml` entry for a brand-new tool -- version 1.
pub fn new_tool_entry(tool_id: &str, spec: &Map<String, Value>, actor: &str, created_at: &str) -> Value {
    json!({
        "id": tool_id,
        "enabled": get_bool(spec, "enabled"),
        "current_version": 1,
        "deleted": false,
        "versions": [version_record(1, strip_fields(spec), json!(created_at), json!(actor), false)],
    })
}

/// Appends a new version to an existing raw entry -- never overwrites
/// (FR-3.1/3.3). A legacy flat entry becomes version 1 (superseded) and
/// the new spec version 2.
pub fn append_tool_version(
    existing_entry: &Map<String, Value>,
    tool_id: &str,
    spec: &Map<String, Value>,
    actor: &str,
    created_at: &str,
) -> ConfigResult<Value> {
    let mut versions: Vec<Value>;
    let next_version;
    if is_versioned(existing_entry) {
        versions = versions_of(existing_entry);
        let mut max = 0i64;
        let mut any = false;
        for v in &versions {
            let Value::Object(m) = v else {
                return Err(ConfigError::new(format!(
                    "tools.yaml: entry {}: every version must be a mapping",
                    repr_str(tool_id)
                )));
            };
            let n = match m.get("version") {
                None => 0,
                Some(x) => py_int(x)?,
            };
            max = if any { max.max(n) } else { n };
            any = true;
        }
        next_version = max + 1;
        let current = existing_entry.get("current_version").cloned().unwrap_or(Value::Null);
        for v in versions.iter_mut() {
            if let Value::Object(m) = v {
                if py_eq(m.get("version").unwrap_or(&Value::Null), &current) {
                    m.insert("superseded".into(), json!(true));
                }
            }
        }
    } else {
        versions = vec![version_record(1, strip_fields(existing_entry), Value::Null, Value::Null, true)];
        next_version = 2;
    }
    versions.push(version_record(next_version, strip_fields(spec), json!(created_at), json!(actor), false));
    let enabled = match spec.get("enabled") {
        Some(v) => py_truthy(v),
        None => get_bool(existing_entry, "enabled"),
    };
    Ok(json!({
        "id": tool_id,
        "enabled": enabled,
        "current_version": next_version,
        "deleted": false,
        "versions": versions,
    }))
}

/// Marks a raw entry deleted without discarding its version history
/// (FR-3.1); a legacy flat entry is converted to versioned shape first.
pub fn soft_delete_entry(existing_entry: &Map<String, Value>) -> Value {
    if is_versioned(existing_entry) {
        let mut entry = existing_entry.clone();
        entry.insert("deleted".into(), json!(true));
        return Value::Object(entry);
    }
    json!({
        "id": existing_entry.get("id").cloned().unwrap_or(Value::Null),
        "enabled": get_bool(existing_entry, "enabled"),
        "current_version": 1,
        "deleted": true,
        "versions": [version_record(1, strip_fields(existing_entry), Value::Null, Value::Null, false)],
    })
}

/// A JSON-serializable, version-shape-agnostic view of one raw entry (for
/// `admin.tool_get`/`tool_list` and the console).
pub fn normalize_tool_entry(entry: &Map<String, Value>) -> Value {
    // PORT NOTE: an unconvertible `version` raised in Python; the category
    // is reported as unknown (null) instead.
    let resolved = current_version_spec(entry).ok().flatten();
    let (versions, current_version) = if is_versioned(entry) {
        (versions_of(entry), entry.get("current_version").cloned().unwrap_or(Value::Null))
    } else {
        (vec![version_record(1, strip_fields(entry), Value::Null, Value::Null, false)], json!(1))
    };
    json!({
        "id": entry.get("id").cloned().unwrap_or(Value::Null),
        "enabled": get_bool(entry, "enabled"),
        "deleted": get_bool(entry, "deleted"),
        "current_version": current_version,
        "category": resolved.and_then(|(spec, ..)| spec.get("category").cloned()).unwrap_or(Value::Null),
        "versions": versions,
    })
}

/// Public entry point for a single definition. The admin API and the UI
/// take exactly the same path as startup.
///
/// Stricter than startup in one way (1.21.0): a field nothing reads is an
/// error here ([`unknown_tool_fields`]), so `admin.tool_validate`,
/// `admin.tool_create`/`tool_update` and the console refuse it. Startup
/// and reload only warn ([`Catalog::unknown_fields`]), so a stored tool
/// that already carries one keeps loading.
pub fn parse_tool_spec(spec: &Value, tier1: &Tier1) -> ConfigResult<ToolDef> {
    let tool = parse_tool(spec, tier1)?;
    check_tool_fields(spec, tier1)?;
    Ok(tool)
}

/// The loaded catalog.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    pub tools: IndexMap<String, ToolDef>,
    pub disabled_by_tier1: Vec<String>,
    /// The unmodified YAML entries in file order (each a mapping).
    pub raw: Vec<Value>,
    /// Definitions that violate Tier 1: the resolved flat spec plus reason.
    pub rejected: Vec<(Value, String)>,
    /// Loaded tools carrying fields nothing reads, one warning each
    /// (1.21.0). A write with such a field is refused ([`parse_tool_spec`]).
    pub unknown_fields: Vec<String>,
}

impl Catalog {
    /// An enabled tool by id.
    pub fn get(&self, tool_id: &str) -> Option<&ToolDef> {
        self.tools.get(tool_id).filter(|t| t.enabled)
    }

    /// The raw entry whose `id` is `tool_id`.
    pub fn raw_of(&self, tool_id: &str) -> Option<&Map<String, Value>> {
        self.raw.iter().find_map(|spec| match spec {
            Value::Object(m) if m.get("id").and_then(|v| v.as_str()) == Some(tool_id) => Some(m),
            _ => None,
        })
    }

    /// The catalog id(s) a grant against `tool_id` resolves to: itself, or
    /// its `<id>@<destination>` expansions (sorted).
    pub fn grantable_ids(&self, tool_id: &str) -> Vec<String> {
        if self.tools.contains_key(tool_id) {
            return vec![tool_id.to_string()];
        }
        let prefix = format!("{tool_id}@");
        let mut ids: Vec<String> = self.tools.keys().filter(|t| t.starts_with(&prefix)).cloned().collect();
        ids.sort();
        ids
    }

    /// The effective, editable flat spec for `tool_id`; `None` for an
    /// unknown id, a deleted tool, or an unresolvable `current_version`.
    pub fn flat_spec_of(&self, tool_id: &str) -> Option<Map<String, Value>> {
        let raw = self.raw_of(tool_id)?;
        if get_bool(raw, "deleted") {
            return None;
        }
        let (mut spec, _version, enabled, _deleted) = current_version_spec(raw).ok().flatten()?;
        spec.insert("enabled".into(), json!(enabled));
        Some(spec)
    }
}

/// Loads the seed catalog.
///
/// FR-4.7: definitions that violate the current Tier 1 are logged and
/// disabled; with `strict` loading aborts instead (for CI). A missing file
/// is the state after installation: an empty catalog.
pub fn load_catalog(path: &str, tier1: &Tier1, strict: bool) -> ConfigResult<Catalog> {
    if !std::path::Path::new(path).exists() {
        return Ok(Catalog::default());
    }
    let text = read_config_file(path, "")?;
    // PORT NOTE: a YAML syntax error was an uncaught YAMLError in Python.
    let raw = crate::atomic::safe_load(&text).map_err(|e| ConfigError::new(format!("{path}: {e}")))?;
    load_catalog_value(&raw, tier1, strict)
}

/// [`load_catalog`] on an already-parsed `tools.yaml` document.
pub fn load_catalog_value(raw: &Value, tier1: &Tier1, strict: bool) -> ConfigResult<Catalog> {
    let entries: Vec<Value> = match raw {
        Value::Object(m) => match m.get("tools") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            Some(_) => return Err(ConfigError::new("tools.yaml: section 'tools' is missing or not a list")),
        },
        v if !py_truthy(v) => Vec::new(),
        _ => return Err(ConfigError::new("tools.yaml: section 'tools' is missing or not a list")),
    };

    let mut catalog = Catalog::default();
    for entry in &entries {
        let Value::Object(entry_map) = entry else {
            return Err(ConfigError::new("tools.yaml: every entry must be a mapping"));
        };
        let Some((mut spec, _version, enabled, deleted)) = current_version_spec(entry_map)? else {
            return Err(ConfigError::new(format!(
                "tools.yaml: entry {} has a 'current_version' that matches none of its 'versions'",
                repr_value(entry_map.get("id").unwrap_or(&Value::Null))
            )));
        };
        if deleted {
            continue;
        }
        spec.insert("enabled".into(), json!(enabled));
        let spec = Value::Object(spec);

        let tool = match parse_tool(&spec, tier1) {
            Ok(t) => t,
            Err(exc) => {
                if strict {
                    return Err(exc);
                }
                catalog.disabled_by_tier1.push(exc.message.clone());
                catalog.rejected.push((spec, exc.message));
                continue;
            }
        };
        let toolkit = tier1.toolkit(&tool.toolkit)?;
        if let Err(exc) = check_tool_fields(&spec, tier1) {
            catalog.unknown_fields.push(exc.message);
        }
        for expanded in expand_tool(&tool, toolkit) {
            if catalog.tools.contains_key(&expanded.id) {
                return Err(ConfigError::new(format!("Duplicate tool ID {}", repr_str(&expanded.id))));
            }
            catalog.tools.insert(expanded.id.clone(), expanded);
        }
    }
    catalog.raw = entries;
    Ok(catalog)
}
