//! Parameter validation and request construction (port of `validate.py`,
//! REQUIREMENTS.md §8).
//!
//! The fundamental guarantee is FR-5.4: *a parameter always expands to
//! exactly one argv element.* That is structural, not a question of
//! escaping: each argv template element resolves to exactly one string and
//! is passed as a single list element to `execve`, with no shell to split
//! it again. The control-character check is defense in depth (FR-6.3); the
//! primary protection is the per-parameter allowlist (FR-6.2).
//!
//! Also home to the small checks `validate.py` imported from executor
//! modules, so the executor ports can reuse them from here:
//! [`check_session_id`] and [`check_directory`] (from `execute_opencode`),
//! [`id_re`]/[`version_re`] (`ID_RE`/`VERSION_RE` from `artifacts`).

use std::collections::HashSet;
use std::sync::OnceLock;

use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};

use crate::catalog::{op_params, placeholder_re, CliArg, Parameter, ToolDef, AGENT_OPERATION_PARAMS, OPENCODE_OPERATION_PARAMS};
use crate::errors::{DenialReason, Denied};
use crate::pyfmt::{repr_list, repr_str, str_value};
use crate::tier1::{pure_posix_parts, pure_posix_within, Toolkit};

/// Resolved parameter values: name -> string, in resolution order (agent
/// parameters in declaration order, then derived ones).
pub type Values = IndexMap<String, String>;

fn denied(reason: DenialReason, detail: impl Into<String>) -> Denied {
    Denied::new(reason, detail)
}

// -- Helpers shared with executor ports ----------------------------------

/// `execute_opencode._SESSION_ID_RE`.
pub const SESSION_ID_PATTERN: &str = r"^[A-Za-z0-9_-]{1,128}$";
/// `artifacts.ID_RE`: an artifact id from the image's manifest.
pub const ARTIFACT_ID_PATTERN: &str = r"^[a-z0-9][a-z0-9-]{0,62}$";
/// `artifacts.VERSION_RE`: a commit id or a prefix of >= 7 hex digits.
pub const ARTIFACT_VERSION_PATTERN: &str = r"^[0-9a-f]{7,40}$";
/// An identity id, as `store.create_identity` writes them.
pub const RECIPIENT_PATTERN: &str = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$";

fn cached(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

/// `execute_opencode._SESSION_ID_RE` (fullmatch semantics).
pub fn session_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    cached(&RE, SESSION_ID_PATTERN)
}

/// `artifacts.ID_RE` (fullmatch semantics).
pub fn id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    cached(&RE, ARTIFACT_ID_PATTERN)
}

/// `artifacts.VERSION_RE` (fullmatch semantics).
pub fn version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    cached(&RE, ARTIFACT_VERSION_PATTERN)
}

/// `RECIPIENT_RE` (fullmatch semantics).
pub fn recipient_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    cached(&RE, RECIPIENT_PATTERN)
}

/// `execute_opencode.check_session_id`: FR-8.7's counterpart for the one
/// parameter that reaches a request path.
pub fn check_session_id(session_id: &str) -> Result<String, Denied> {
    if !session_id_re().is_match(session_id) {
        return Err(denied(
            DenialReason::ParamInvalid,
            "session_id must be 1-128 characters of A-Z, a-z, 0-9, '_' or '-'.",
        ));
    }
    Ok(session_id.to_string())
}

/// `execute_opencode.check_directory`: a `directory` against the
/// toolkit's `path_roots` (FR-4.10). Purely lexical (the path names a
/// directory in the opencode container); existence is checked only where
/// the matching root is visible here.
pub fn check_directory(directory: &str, toolkit: &Toolkit) -> Result<String, Denied> {
    if !directory.starts_with('/') {
        return Err(denied(
            DenialReason::ParamInvalid,
            format!("directory {} must be an absolute path.", repr_str(directory)),
        ));
    }
    if pure_posix_parts(directory).iter().any(|p| p == "..") {
        return Err(denied(
            DenialReason::PathEscape,
            format!("directory {} contains a '..' segment.", repr_str(directory)),
        ));
    }
    if toolkit.path_roots.is_empty() {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!(
                "Toolkit {} declares no path_roots, so no 'directory' can be accepted for it.",
                repr_str(&toolkit.name)
            ),
        ));
    }
    for root in &toolkit.path_roots {
        if pure_posix_within(directory, root) {
            check_exists_if_visible(directory, root)?;
            return Ok(directory.to_string());
        }
    }
    Err(denied(
        DenialReason::PathEscape,
        format!(
            "directory {} lies outside this toolkit's path_roots {}.",
            repr_str(directory),
            repr_list(&toolkit.path_roots)
        ),
    ))
}

/// Rejects a typo'd directory -- but only where that is answerable.
fn check_exists_if_visible(directory: &str, root: &str) -> Result<(), Denied> {
    if !std::path::Path::new(root).is_dir() {
        return Ok(());
    }
    if !std::path::Path::new(directory).is_dir() {
        return Err(denied(
            DenialReason::ParamInvalid,
            format!("directory {} does not exist.", repr_str(directory)),
        ));
    }
    Ok(())
}

// -- Parameter validation ----------------------------------------------------

/// FR-6.3: control characters (`< U+0020`, `U+007F`) and NUL are an
/// attack indicator. Run before the pattern check.
pub fn reject_control_characters(name: &str, value: &str) -> Result<(), Denied> {
    for ch in value.chars() {
        let cp = ch as u32;
        if cp < 0x20 || cp == 0x7F {
            return Err(denied(
                DenialReason::ControlCharacter,
                format!("Parameter {} contains a control character (U+{cp:04X}).", repr_str(name)),
            ));
        }
    }
    Ok(())
}

/// Numeric comparison of an agent-supplied integer with a declared bound;
/// `None` when the bound is not a number.
fn cmp_bound(value: &serde_json::Number, bound: &Value) -> Option<std::cmp::Ordering> {
    let as_i128 = |n: &serde_json::Number| n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from));
    let bound_num = match bound {
        Value::Number(n) => n.clone(),
        Value::Bool(b) => serde_json::Number::from(i64::from(*b)),
        // PORT NOTE: a non-numeric bound raised TypeError in Python at call
        // time; here it is ignored.
        _ => return None,
    };
    match (as_i128(value), as_i128(&bound_num)) {
        (Some(a), Some(b)) => Some(a.cmp(&b)),
        _ => value.as_f64()?.partial_cmp(&bound_num.as_f64()?),
    }
}

/// `_validate_scalar`: validates one agent-supplied value and returns it as
/// a string (`"true"`/`"false"` for booleans, decimal for integers).
pub fn validate_scalar(param: &Parameter, value: &Value) -> Result<String, Denied> {
    let name = repr_str(&param.name);

    if param.ptype == "boolean" {
        let Value::Bool(b) = value else {
            return Err(denied(DenialReason::ParamInvalid, format!("Parameter {name} expects a boolean.")));
        };
        return Ok(if *b { "true" } else { "false" }.to_string());
    }

    if param.ptype == "integer" {
        let n = match value {
            Value::Number(n) if !n.is_f64() => n,
            _ => {
                return Err(denied(DenialReason::ParamInvalid, format!("Parameter {name} expects an integer.")))
            }
        };
        if let Some(min) = &param.minimum {
            if cmp_bound(n, min) == Some(std::cmp::Ordering::Less) {
                return Err(denied(
                    DenialReason::ParamInvalid,
                    format!("Parameter {name}: {n} is below the minimum {}.", str_value(min)),
                ));
            }
        }
        if let Some(max) = &param.maximum {
            if cmp_bound(n, max) == Some(std::cmp::Ordering::Greater) {
                return Err(denied(
                    DenialReason::ParamInvalid,
                    format!("Parameter {name}: {n} exceeds the maximum {}.", str_value(max)),
                ));
            }
        }
        return Ok(n.to_string());
    }

    let Value::String(value) = value else {
        return Err(denied(DenialReason::ParamInvalid, format!("Parameter {name} expects a string.")));
    };

    if !param.allow_control_characters {
        reject_control_characters(&param.name, value)?;
    }

    if param.ptype == "enum" {
        if !param.values.iter().any(|v| v == value) {
            return Err(denied(
                DenialReason::ParamInvalid,
                format!("Parameter {name}: {} is not an allowed value.", repr_str(value)),
            ));
        }
        return Ok(value.clone());
    }

    // string -- allowlist via pattern, *full* match.
    if let Some(pattern) = &param.pattern {
        if !pattern.fullmatch(value) {
            return Err(denied(
                DenialReason::ParamInvalid,
                format!("Parameter {name}: value does not match the allowed pattern."),
            ));
        }
    }
    Ok(value.clone())
}

/// `_substitute`: replaces placeholders. The result is always exactly one
/// string. Callers check [`placeholders_missing`] first; a missing value
/// would leave its placeholder in place.
pub fn substitute(template: &str, values: &Values) -> String {
    placeholder_re()
        .replace_all(template, |caps: &regex::Captures<'_>| {
            values.get(&caps[1]).cloned().unwrap_or_else(|| caps[0].to_string())
        })
        .into_owned()
}

/// `_placeholders_missing`, sorted (the shape every message prints).
pub fn placeholders_missing(template: &str, values: &Values) -> Vec<String> {
    let mut missing: Vec<String> = placeholder_re()
        .captures_iter(template)
        .map(|c| c[1].to_string())
        .filter(|p| !values.contains_key(p))
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

/// `_resolve_body_template`: leaf strings get `{param}` substitution,
/// other leaves pass through unchanged.
pub fn resolve_body_template(template: &Value, values: &Values) -> Result<Value, Denied> {
    match template {
        Value::String(s) => {
            let missing = placeholders_missing(s, values);
            if !missing.is_empty() {
                return Err(denied(
                    DenialReason::ParamMissing,
                    format!("Body template needs {}.", repr_list(&missing)),
                ));
            }
            Ok(Value::String(substitute(s, values)))
        }
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                out.insert(k.clone(), resolve_body_template(v, values)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(a) => a.iter().map(|v| resolve_body_template(v, values)).collect::<Result<Vec<_>, _>>().map(Value::Array),
        other => Ok(other.clone()),
    }
}

/// `_resolve_path`: resolves a derived path (symlinks included, FR-4.3)
/// and checks it against its root with `commonpath`, not a string prefix.
pub fn resolve_path(param: &Parameter, raw: &str) -> Result<String, Denied> {
    let root = param.must_resolve_under.as_deref().unwrap_or("");
    if raw.split(['\\', '/']).any(|seg| seg == "..") {
        return Err(denied(
            DenialReason::PathEscape,
            format!("Parameter {}: path contains '..'.", repr_str(&param.name)),
        ));
    }
    let escape = || {
        denied(
            DenialReason::PathEscape,
            format!("Parameter {}: path resolves outside {}.", repr_str(&param.name), repr_str(root)),
        )
    };
    // A path whose links cannot be fully resolved is never "under" anything.
    let (Ok(real), Ok(real_root)) = (crate::pathutil::realpath(raw), crate::pathutil::realpath(root)) else {
        return Err(escape());
    };
    match crate::pathutil::commonpath(&[real.as_str(), real_root.as_str()]) {
        Some(common) if common == real_root => Ok(real),
        _ => Err(escape()),
    }
}

/// Validates the agent input and adds the derived values.
pub fn resolve_parameters(tool: &ToolDef, arguments: &Map<String, Value>) -> Result<Values, Denied> {
    for name in arguments.keys() {
        let Some(param) = tool.parameters.get(name) else {
            return Err(denied(DenialReason::ParamUnknown, format!("Unknown parameter {}.", repr_str(name))));
        };
        if param.is_derived() {
            // FR-5.5: derived values are computed by the server.
            return Err(denied(
                DenialReason::ParamDerivedSupplied,
                format!(
                    "Parameter {} is determined by the server and must not be supplied.",
                    repr_str(name)
                ),
            ));
        }
    }

    let mut resolved = Values::new();
    for (name, param) in tool.parameters.iter().filter(|(_, p)| !p.is_derived()) {
        match arguments.get(name) {
            None => {
                if param.required {
                    return Err(denied(
                        DenialReason::ParamMissing,
                        format!("Required parameter {} is missing.", repr_str(name)),
                    ));
                }
            }
            Some(value) => {
                let v = validate_scalar(param, value)?;
                resolved.insert(name.clone(), v);
            }
        }
    }

    // Derived parameters after the agent parameters, so they can build on them.
    for (name, param) in &tool.parameters {
        let Some(template) = &param.derived else { continue };
        let missing = placeholders_missing(template, &resolved);
        if !missing.is_empty() {
            return Err(denied(
                DenialReason::ParamMissing,
                format!("Derived parameter {} needs {}.", repr_str(name), repr_list(&missing)),
            ));
        }
        let raw = substitute(template, &resolved);
        let value = if param.ptype == "path" { resolve_path(param, &raw)? } else { raw };
        resolved.insert(name.clone(), value);
    }
    // A kuma tool's `fixed:` values (1.29.0). The catalog refuses a key that
    // is also a declared parameter, so the caller can never send one (it
    // would be `Unknown parameter`), and nothing above can have set it.
    for (name, value) in &tool.kuma_fixed {
        resolved.insert(name.clone(), value.to_string());
    }
    Ok(resolved)
}

/// Builds the argument list and checks it again against Tier 1, on the
/// *resolved* argv.
pub fn build_argv(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<Vec<String>, Denied> {
    let binary = tool.binary.clone().unwrap_or_default();
    let mut argv = vec![binary.clone()];
    for element in &tool.argv {
        let missing = placeholders_missing(element, values);
        if !missing.is_empty() {
            return Err(denied(
                DenialReason::ParamMissing,
                format!("Argument template needs {}.", repr_list(&missing)),
            ));
        }
        // Exactly one list element per template element -- FR-5.4.
        argv.push(substitute(element, values));
    }

    // PORT NOTE: Python let `check_binary`'s ConfigError escape the
    // caller's `except Denied` (skipping the audit entry); it is a denial
    // here.
    toolkit
        .check_binary(&binary)
        .map_err(|exc| denied(DenialReason::Tier1Violation, exc.message))?;
    if let Some(arg) = toolkit.check_args(&argv) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Argument {} is denied for this toolkit.", repr_str(&arg)),
        ));
    }
    Ok(argv)
}

/// `_reject_path_traversal`: FR-8.7 -- `..` in a resolved path segment is
/// rejected, literally and after one percent-decoding pass.
pub fn reject_path_traversal(name: &str, path: &str) -> Result<(), Denied> {
    if path.split('/').any(|s| s == "..") {
        return Err(denied(
            DenialReason::PathEscape,
            format!("{name}: resolved path {} contains a '..' segment.", repr_str(path)),
        ));
    }
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
    if decoded != path && decoded.split('/').any(|s| s == "..") {
        return Err(denied(
            DenialReason::PathEscape,
            format!("{name}: resolved path {} percent-decodes to a '..' segment.", repr_str(path)),
        ));
    }
    Ok(())
}

/// What [`build_http_request`] returns -- Python's `(method, path, query,
/// body)` tuple.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: IndexMap<String, String>,
    pub body: Option<Value>,
}

/// An `http` tool's `follow_redirect:` block (1.30.0).
///
/// `max` is always 1: one hop, from the toolkit's own target to one of
/// `allowed_hosts`. Every host is an exact name -- no wildcard, no IP
/// literal -- and must also be in the toolkit's Tier 1
/// `redirect_allowed_hosts` (checked in `catalog::validate_against_tier1`),
/// so a console-written tool can narrow where a redirect may go but never
/// widen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowRedirect {
    pub max: u32,
    pub allowed_hosts: Vec<String>,
}

/// The ceiling of `output_tail_lines` (1.30.0).
pub const MAX_OUTPUT_TAIL_LINES: i64 = 1000;

/// Parses and checks `follow_redirect: {max: 1, allowed_hosts: [...]}`.
pub fn parse_follow_redirect(value: &Value, where_: &str) -> crate::errors::ConfigResult<FollowRedirect> {
    use crate::errors::ConfigError;
    let Value::Object(m) = value else {
        return Err(ConfigError::new(format!(
            "{where_}: 'follow_redirect' must be a mapping {{max: 1, allowed_hosts: [...]}}"
        )));
    };
    let mut unknown: Vec<String> =
        m.keys().filter(|k| k.as_str() != "max" && k.as_str() != "allowed_hosts").cloned().collect();
    if !unknown.is_empty() {
        unknown.sort();
        return Err(ConfigError::new(format!("{where_}: 'follow_redirect' has unknown keys {}", repr_list(&unknown))));
    }
    match m.get("max") {
        Some(Value::Number(n)) if n.as_i64() == Some(1) => {}
        other => {
            return Err(ConfigError::new(format!(
                "{where_}: 'follow_redirect.max' must be 1 -- gatekeeper follows at most one redirect, not {}",
                crate::pyfmt::repr_value(other.unwrap_or(&Value::Null))
            )))
        }
    }
    let hosts = crate::tier1::parse_host_list(m.get("allowed_hosts"), &format!("{where_}: follow_redirect"))?;
    if hosts.is_empty() {
        return Err(ConfigError::new(format!(
            "{where_}: 'follow_redirect.allowed_hosts' must not be empty -- name the exact hosts a redirect may go to"
        )));
    }
    Ok(FollowRedirect { max: 1, allowed_hosts: hosts })
}

/// Parses and checks `output_tail_lines: N` (1 to [`MAX_OUTPUT_TAIL_LINES`]).
pub fn parse_output_tail_lines(value: &Value, where_: &str) -> crate::errors::ConfigResult<usize> {
    use crate::errors::ConfigError;
    match value {
        Value::Number(n) if n.as_i64().is_some_and(|v| (1..=MAX_OUTPUT_TAIL_LINES).contains(&v)) => {
            Ok(n.as_i64().unwrap() as usize)
        }
        other => Err(ConfigError::new(format!(
            "{where_}: 'output_tail_lines' must be an integer from 1 to {MAX_OUTPUT_TAIL_LINES}, not {}",
            crate::pyfmt::repr_value(other)
        ))),
    }
}

/// Builds the HTTP request parts and checks the result against Tier 1
/// (FR-8.5/8.7). Scheme and host are never built here.
pub fn build_http_request(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<HttpRequest, Denied> {
    let method = tool.http_method.clone().unwrap_or_default();
    let template = tool.path_template.clone().unwrap_or_default();

    let missing = placeholders_missing(&template, values);
    if !missing.is_empty() {
        return Err(denied(DenialReason::ParamMissing, format!("Path template needs {}.", repr_list(&missing))));
    }
    let path = substitute(&template, values);
    reject_path_traversal("path", &path)?;

    if !toolkit.allows_path(&path) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Resolved path {} is outside the toolkit's allowed prefixes.", repr_str(&path)),
        ));
    }
    if !toolkit.allows_method(&method) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Method {} is not allowed for this toolkit.", repr_str(&method)),
        ));
    }

    let mut query = IndexMap::new();
    for (key, template) in &tool.query_template {
        let missing = placeholders_missing(template, values);
        if !missing.is_empty() {
            // An optional parameter the agent did not supply leaves its
            // query key out entirely -- no key, no empty value -- so the
            // target's own default applies, as an omitted optional CLI
            // argument is left off the argv. Only when *every* missing name
            // is a declared, optional, non-derived parameter: a required (or
            // undeclared) name is still a denial, even for a caller that
            // skipped `resolve_parameters`. The key is dropped as a whole,
            // never sent half-substituted. Path placeholders stay mandatory
            // (a path without its segment is another endpoint), and body
            // templates are unchanged (absent vs. null vs. empty is the
            // target's semantics, not ours to guess).
            let all_optional = missing.iter().all(|name| {
                tool.parameters.get(name).is_some_and(|p| !p.required && !p.is_derived())
            });
            if all_optional {
                continue;
            }
            return Err(denied(
                DenialReason::ParamMissing,
                format!("Query template {} needs {}.", repr_str(key), repr_list(&missing)),
            ));
        }
        query.insert(key.clone(), substitute(template, values));
    }

    let body = match &tool.body_template {
        Some(t) => Some(resolve_body_file_fields(resolve_body_template(t, values)?, tool, values)?),
        None => None,
    };
    Ok(HttpRequest { method, path, query, body })
}

/// Builds an `http` tool's optional `verify` request (1.27.0) exactly like
/// the main one: same parameter values, same substitution, same Tier 1
/// re-check of the resolved path and method -- [`build_http_request`] on a
/// copy of the tool whose request fields are the verify block's. `None`
/// when the tool has no `verify`.
pub fn build_http_verify(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<Option<HttpRequest>, Denied> {
    let Some(verify) = &tool.verify else { return Ok(None) };
    let mut verify_tool = tool.clone();
    verify_tool.http_method = Some(verify.method.clone());
    verify_tool.path_template = Some(verify.path_template.clone());
    verify_tool.query_template = verify.query_template.clone();
    verify_tool.body_template = verify.body_template.clone();
    verify_tool.body_raw_param = None;
    verify_tool.max_file_bytes = None;
    verify_tool.verify = None;
    build_http_request(&verify_tool, values, toolkit).map(Some)
}

/// The body's `{from_file: <param>, encoding}` fields, pointed at the file
/// (1.21.0): each becomes `{from_file: <resolved path>, encoding,
/// must_resolve_under, max_file_bytes}`, which `execute::http` replaces by
/// the file's content just before sending. Never the content itself: this
/// body is what the audit log may describe.
fn resolve_body_file_fields(body: Value, tool: &ToolDef, values: &Values) -> Result<Value, Denied> {
    match body {
        Value::Object(m) if m.contains_key("from_file") => {
            let name = m["from_file"].as_str().unwrap_or_default().to_string();
            let (Some(param), Some(path)) = (tool.parameters.get(&name), values.get(&name)) else {
                return Err(denied(
                    DenialReason::ParamMissing,
                    format!("Body file needs parameter {}.", repr_str(&name)),
                ));
            };
            let mut marker = Map::new();
            marker.insert("from_file".into(), Value::String(path.clone()));
            marker.insert("encoding".into(), m.get("encoding").cloned().unwrap_or(Value::Null));
            marker.insert(
                "must_resolve_under".into(),
                Value::String(param.must_resolve_under.clone().unwrap_or_default()),
            );
            marker.insert("max_file_bytes".into(), tool.max_file_bytes.map(Value::from).unwrap_or(Value::Null));
            Ok(Value::Object(marker))
        }
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                out.insert(k, resolve_body_file_fields(v, tool, values)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(a) => {
            a.into_iter().map(|v| resolve_body_file_fields(v, tool, values)).collect::<Result<Vec<_>, _>>().map(Value::Array)
        }
        other => Ok(other),
    }
}

/// Builds `(method, params)` for the truenas executor and re-checks the
/// method against Tier 1.
pub fn build_rpc_call(
    tool: &ToolDef,
    values: &Values,
    toolkit: &Toolkit,
) -> Result<(String, IndexMap<String, Value>), Denied> {
    let method = tool.rpc_method.clone().unwrap_or_default();
    if !toolkit.allows_rpc_method(&method) {
        return Err(denied(
            DenialReason::RpcMethodDenied,
            format!("RPC method {} is not allowed for this toolkit.", repr_str(&method)),
        ));
    }
    let mut params = IndexMap::new();
    if let Some(templates) = &tool.params_template {
        for (key, template) in templates {
            params.insert(key.clone(), resolve_rpc_template(template, key, tool, values)?);
        }
    }
    Ok((method, params))
}

/// One RPC argument: leaf strings get `{param}` substitution, other leaves
/// pass through. A leaf that is exactly `{name}` of an integer or boolean
/// parameter becomes a JSON number or boolean, so `quota: "{quota}"`
/// reaches the API as `quota: 1073741824`.
fn resolve_rpc_template(template: &Value, key: &str, tool: &ToolDef, values: &Values) -> Result<Value, Denied> {
    match template {
        Value::String(s) => {
            let missing = placeholders_missing(s, values);
            if !missing.is_empty() {
                return Err(denied(
                    DenialReason::ParamMissing,
                    format!("Params template {} needs {}.", repr_str(key), repr_list(&missing)),
                ));
            }
            if let Some(param) = whole_placeholder(s).and_then(|name| tool.parameters.get(name)) {
                let raw = values.get(&param.name).map(String::as_str).unwrap_or_default();
                match param.ptype.as_str() {
                    "integer" => {
                        if let Ok(n) = raw.parse::<i64>() {
                            return Ok(Value::from(n));
                        }
                        if let Ok(n) = raw.parse::<u64>() {
                            return Ok(Value::from(n));
                        }
                    }
                    "boolean" => return Ok(Value::Bool(raw == "true")),
                    _ => {}
                }
            }
            Ok(Value::String(substitute(s, values)))
        }
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                out.insert(k.clone(), resolve_rpc_template(v, key, tool, values)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(a) => {
            a.iter().map(|v| resolve_rpc_template(v, key, tool, values)).collect::<Result<Vec<_>, _>>().map(Value::Array)
        }
        other => Ok(other.clone()),
    }
}

/// The parameter name when `template` is one placeholder and nothing else.
fn whole_placeholder(template: &str) -> Option<&str> {
    let caps = placeholder_re().captures(template)?;
    let whole = caps.get(0)?;
    (whole.start() == 0 && whole.end() == template.len()).then(|| caps.get(1).map(|m| m.as_str())).flatten()
}

/// `_build_cli_args`: the argv tail both vendored-CLI executors build.
///
/// A positional entry is the bare value, a flag entry the pair `--flag
/// value`, a switch entry the fixed token when its boolean is true. An
/// optional, unsupplied, non-positional parameter is left off entirely.
pub fn build_cli_args(
    arg_specs: &IndexMap<String, CliArg>,
    values: &Values,
    tool: &ToolDef,
    field: &str,
) -> Result<Vec<String>, Denied> {
    let mut args = Vec::new();
    for (arg_name, spec) in arg_specs {
        let Some(value) = values.get(arg_name) else {
            if let Some(param) = tool.parameters.get(arg_name) {
                if !param.required && !spec.positional {
                    continue;
                }
            }
            return Err(denied(
                DenialReason::ParamMissing,
                format!("{field}.{} needs a value.", repr_str(arg_name)),
            ));
        };
        if let Some(switch) = &spec.switch {
            if value != "true" && value != "false" {
                return Err(denied(
                    DenialReason::ParamInvalid,
                    format!("{field}.{} is a switch and takes a boolean.", repr_str(arg_name)),
                ));
            }
            if value == "true" {
                args.push(switch.clone());
            }
        } else if spec.positional {
            args.push(value.clone());
        } else {
            // Validated at parse time: a non-positional entry has a flag.
            args.push(spec.flag.clone().unwrap_or_default());
            args.push(value.clone());
        }
    }
    Ok(args)
}

/// The argv tail for the `google` executor, the action re-checked.
pub fn build_google_call(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<Vec<String>, Denied> {
    let action = tool.google_action.clone().unwrap_or_default();
    if !toolkit.allows_google_action(&action) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Google action {} is not allowed for this toolkit.", repr_str(&action)),
        ));
    }
    build_cli_args(tool.google_args.as_ref().unwrap_or(&IndexMap::new()), values, tool, "google_args")
}

/// `build_google_call` for the `microsoft` executor.
pub fn build_microsoft_call(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<Vec<String>, Denied> {
    let action = tool.microsoft_action.clone().unwrap_or_default();
    if !toolkit.allows_microsoft_action(&action) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Microsoft action {} is not allowed for this toolkit.", repr_str(&action)),
        ));
    }
    build_cli_args(tool.microsoft_args.as_ref().unwrap_or(&IndexMap::new()), values, tool, "microsoft_args")
}

/// Checks an `opencode` call against Tier 1 and returns its operation;
/// `session_id` and `directory` are checked here.
pub fn build_opencode_call(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<String, Denied> {
    let operation = tool.opencode_operation.clone().unwrap_or_default();
    if !toolkit.allows_opencode_operation(&operation) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Opencode operation {} is not allowed for this toolkit.", repr_str(&operation)),
        ));
    }
    let (required, _optional) = op_params(OPENCODE_OPERATION_PARAMS, &operation).unwrap_or((&[], &[]));
    let session_id = values.get("session_id").map(String::as_str).unwrap_or("");
    if required.contains(&"session_id") || !session_id.is_empty() {
        check_session_id(session_id)?;
    }
    if let Some(directory) = values.get("directory").filter(|d| !d.is_empty()) {
        check_directory(directory, toolkit)?;
    }
    Ok(operation)
}

/// The `kuma` operation, re-checked against Tier 1, with the executor's
/// own value floor (`execute::kuma::check_values`) applied here, inside
/// `Service::call`'s audited block, so a bad URL is a denial and not a
/// connection to Kuma that then fails.
pub fn build_kuma_call(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<String, Denied> {
    let operation = tool.kuma_operation.clone().unwrap_or_default();
    if !toolkit.allows_kuma_operation(&operation) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Kuma operation {} is not allowed for this toolkit.", repr_str(&operation)),
        ));
    }
    crate::execute::kuma::check_values(&operation, values)?;
    if operation == "monitor_add_port" {
        let hostname = values.get("hostname").map(String::as_str).unwrap_or("");
        crate::execute::kuma::check_monitor_target(toolkit, hostname)?;
    }
    Ok(operation)
}

/// The `git` operation, re-checked against Tier 1, with
/// `execute::git::check_values` applied here so a `main` branch or an
/// unknown repo is an audited denial before git ever runs.
pub fn build_git_call(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<String, Denied> {
    let operation = tool.git_operation.clone().unwrap_or_default();
    if !toolkit.allows_git_operation(&operation) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Git operation {} is not allowed for this toolkit.", repr_str(&operation)),
        ));
    }
    crate::execute::git::check_values(toolkit, values)?;
    Ok(operation)
}

/// The `artifact` operation, re-checked against Tier 1, and the shape of
/// the only two values a call can supply.
pub fn build_artifact_call(tool: &ToolDef, values: &Values, toolkit: &Toolkit) -> Result<String, Denied> {
    let operation = tool.artifact_operation.clone().unwrap_or_default();
    if !toolkit.allows_artifact_operation(&operation) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Artifact operation {} is not allowed for this toolkit.", repr_str(&operation)),
        ));
    }
    if let Some(artifact) = values.get("artifact") {
        if !id_re().is_match(artifact) {
            return Err(denied(
                DenialReason::ParamInvalid,
                "Parameter 'artifact' must be an artifact id (lowercase letters, digits, '-').",
            ));
        }
    }
    if let Some(version) = values.get("version").filter(|v| !v.is_empty()) {
        if !version_re().is_match(version) {
            return Err(denied(
                DenialReason::ParamInvalid,
                "Parameter 'version' must be a commit id or a prefix of at least 7 hex digits.",
            ));
        }
    }
    Ok(operation)
}

/// Checks an `agent` (mailbox) call against Tier 1 and returns its
/// operation. `known_recipients` is the live identity set; `None` degrades
/// to the shape test.
pub fn build_agent_call(
    tool: &ToolDef,
    values: &Values,
    toolkit: &Toolkit,
    known_recipients: Option<&HashSet<String>>,
) -> Result<String, Denied> {
    let operation = tool.agent_operation.clone().unwrap_or_default();
    if !toolkit.allows_agent_operation(&operation) {
        return Err(denied(
            DenialReason::Tier1Violation,
            format!("Agent operation {} is not allowed for this toolkit.", repr_str(&operation)),
        ));
    }
    let (required, _optional) = op_params(AGENT_OPERATION_PARAMS, &operation).unwrap_or((&[], &[]));
    if required.contains(&"to") {
        let recipient = values.get("to").map(String::as_str).unwrap_or("");
        if !recipient_re().is_match(recipient) {
            return Err(denied(
                DenialReason::ParamInvalid,
                "Parameter 'to' must be a gatekeeper identity id (letters, digits, '-' and '_').",
            ));
        }
        if let Some(known) = known_recipients {
            if !known.contains(recipient) {
                return Err(denied(
                    DenialReason::ParamInvalid,
                    format!(
                        "There is no identity {}. A message can only be \
                         addressed to a configured gatekeeper identity -- an unknown \
                         one has no mailbox anybody would ever read.",
                        repr_str(recipient)
                    ),
                ));
            }
        }
    }
    Ok(operation)
}

/// Resolves `required_scopes` with the validated parameter values.
pub fn resolve_scopes(tool: &ToolDef, values: &Values) -> Result<Vec<String>, Denied> {
    let mut scopes = Vec::new();
    for template in &tool.required_scopes {
        let missing = placeholders_missing(template, values);
        if !missing.is_empty() {
            return Err(denied(
                DenialReason::ParamMissing,
                format!("Scope template needs {}.", repr_list(&missing)),
            ));
        }
        scopes.push(substitute(template, values));
    }
    Ok(scopes)
}

/// FR-4.12: protected resources, independent of rights and scopes. The
/// resource is the part of a scope after its first `:`.
pub fn check_protected<S: AsRef<str>>(scopes: &[S], toolkit: &Toolkit) -> Result<(), Denied> {
    for scope in scopes {
        let resource = scope.as_ref().split_once(':').map(|(_, r)| r).unwrap_or("");
        if !resource.is_empty() && toolkit.is_protected(resource) {
            return Err(denied(
                DenialReason::ProtectedResource,
                format!("Resource {} is protected and reachable by no tool.", repr_str(resource)),
            ));
        }
    }
    Ok(())
}
