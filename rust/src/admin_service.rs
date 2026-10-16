//! The `admin.*` MCP surface's application layer (port of
//! `admin_service.py`, REQUIREMENTS.md FR-2.8-3.7).
//!
//! [`AdminService`] wraps `ConfigStore` + `PendingStore` and is the single
//! dispatch point `admin_server` calls into for every `admin.*` tool.
//! Every mutating action goes through the *same* store mutators a human
//! console write uses -- there is no second, more lenient path.
//!
//! One dispatch table ([`EXPOSED`], enforced by [`AdminService::call`])
//! decides, per action, whether a change applies immediately or is written
//! to the pending queue: read-only queries execute directly;
//! `proposal_withdraw`, `tool_create` (forced inert), `tool_disable` and
//! `cred_delete` auto-apply; `tool_enable`/`tool_update` auto-apply for a
//! `read` tool and are queued otherwise; `tool_delete`, `grant_set`,
//! `role_set`, `cred_propose` and `cred_update` are always queued;
//! `toolkit_*` and `credential_bind` go to the toolkit-proposal queue.
//!
//! `approve`/`reject` are deliberately not methods here and not in
//! [`EXPOSED`]: the only place a pending item becomes a live change is
//! [`apply_pending`], called only from the console API's request-decision
//! routes. FR-2.8's self-approval prevention is structural.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::api::service::{credential_summaries, read_audit, toolkit_summaries, AuditFilter};
use crate::catalog::{normalize_tool_entry, parse_tool_spec};
use crate::credentials::{check_header_format, is_header_name, value_shape, CredentialMeta, CredentialStore, HEADER_KINDS};
use crate::credentials::KINDS as CREDENTIAL_KINDS;
use crate::errors::{ConfigError, ConfigResult};
use crate::identity::{ROLES, UI_ROLES};
use crate::pending::{PendingAction, PendingStore};
use crate::pyfmt::{repr_list, repr_sorted, repr_str, repr_value, str_value};
use crate::release_notes;
use crate::store::{write_refused, ConfigStore};
use crate::tier1::{py_int, py_truthy};
use crate::toolkit_proposals::{ToolkitProposalStore, BIND_FIELD, KINDS, STATUSES};

/// Same cause as the console popup's fallback, phrased for a caller with
/// no browser.
const NO_RELEASE_NOTES: &str = "Release notes are not available in this build -- RELEASE.md was not \
found. Set GATEKEEPER_RELEASE_NOTES to its path, or use the container \
image, which ships it at /usr/share/gatekeeper/RELEASE.md.";

/// The credential-name rule for `cred_propose`/`cred_update`.
const CREDENTIAL_NAME_PATTERN: &str = "^[a-z][a-z0-9_-]*$";

/// `_CREDENTIAL_NAME_RE.match(name)`.
///
/// PORT NOTE: Python's `$` also matched before a trailing newline, so
/// `"abc\n"` passed; the Rust check anchors at the true end of input.
fn valid_credential_name(name: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\A[a-z][a-z0-9_-]*\z").unwrap()).is_match(name)
}

/// Argument names `credential_bind`/`cred_update` refuse outright.
const BIND_VALUE_ARGS: [&str; 9] =
    ["value", "secret", "token", "password", "passphrase", "api_key", "apikey", "key", "credential_value"];

/// Tier 1 fields that stay deploy-time only (FR-4.11).
const BIND_DEPLOY_TIME_ARGS: [&str; 6] = [
    "destination",
    "destinations",
    "path_roots",
    "protected_resources",
    "max_timeout_seconds",
    "max_output_bytes",
];

/// Fields that are proposable, just not from `credential_bind`.
const BIND_UPDATE_ARGS: [&str; 4] = ["executor", "binaries", "denied_args", "run_as"];

/// The complete, fixed set of `admin.*` actions reachable from
/// `/admin/mcp` (FR-2.8/2.9), in Python's `_EXPOSED` order.
pub const EXPOSED: [&str; 25] = [
    "tool_list",
    "tool_get",
    "tool_create",
    "tool_update",
    "tool_enable",
    "tool_disable",
    "tool_delete",
    "tool_validate",
    "grant_list",
    "grant_set",
    "role_set",
    "audit_query",
    "pending_list",
    "proposal_list",
    "release_notes",
    "toolkit_list",
    "cred_list",
    "cred_delete",
    "toolkit_propose",
    "toolkit_update",
    "toolkit_delete",
    "proposal_withdraw",
    "cred_propose",
    "cred_update",
    "credential_bind",
];

/// `AdminActionError`: a malformed `admin.*` call.
pub fn admin_error(message: impl Into<String>) -> ConfigError {
    ConfigError::admin(message)
}

type Args = Map<String, Value>;

fn require_str<'a>(args: &'a Args, name: &str) -> ConfigResult<&'a str> {
    match args.get(name) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s),
        _ => Err(admin_error(format!("'{name}' is required and must be a non-empty string."))),
    }
}

fn require_dict<'a>(args: &'a Args, name: &str) -> ConfigResult<&'a Map<String, Value>> {
    match args.get(name) {
        Some(Value::Object(m)) => Ok(m),
        _ => Err(admin_error(format!("'{name}' is required and must be a mapping."))),
    }
}

/// `str(args.get(name) or "")`.
fn str_or_empty(args: &Args, name: &str) -> String {
    match args.get(name) {
        Some(v) if py_truthy(v) => str_value(v),
        _ => String::new(),
    }
}

/// `args.get(name) or None`, as a string.
fn opt_truthy_str(args: &Args, name: &str) -> Option<String> {
    match args.get(name) {
        Some(v) if py_truthy(v) => Some(str_value(v)),
        _ => None,
    }
}

/// `int(x)`; Python's ValueError/TypeError becomes an `AdminActionError`.
fn int_arg(v: &Value) -> ConfigResult<i64> {
    // PORT NOTE: Python raised a bare ValueError/TypeError here.
    py_int(v).map_err(|e| admin_error(e.message))
}

/// `sorted(set(args) & names)` as a Python list repr, or `None`.
fn args_in(args: &Args, names: &[&str]) -> Option<String> {
    let found: BTreeSet<&str> = args.keys().map(String::as_str).filter(|k| names.contains(k)).collect();
    if found.is_empty() {
        None
    } else {
        Some(repr_list(&found.into_iter().collect::<Vec<_>>()))
    }
}

fn count_args_in(args: &Args, names: &[&str]) -> usize {
    args.keys().filter(|k| names.contains(&k.as_str())).count()
}

fn pending_reply(item: &PendingAction) -> Value {
    json!({"applied": false, "pending": true, "pending_id": item.id})
}

fn opt_value(v: &Option<String>) -> Value {
    v.as_ref().map(|s| Value::String(s.clone())).unwrap_or(Value::Null)
}

pub struct AdminService {
    pub store: Arc<ConfigStore>,
    pub pending: Arc<PendingStore>,
    pub toolkit_proposals: Arc<ToolkitProposalStore>,
    /// `None` on a deployment with no credential store configured.
    pub credentials: Option<Arc<CredentialStore>>,
}

impl std::fmt::Debug for AdminService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminService").finish()
    }
}

impl AdminService {
    pub fn new(
        store: Arc<ConfigStore>,
        pending: Arc<PendingStore>,
        toolkit_proposals: Arc<ToolkitProposalStore>,
        credentials: Option<Arc<CredentialStore>>,
    ) -> AdminService {
        AdminService { store, pending, toolkit_proposals, credentials }
    }

    /// The exact set of action names reachable from `/admin/mcp` is
    /// [`EXPOSED`]; anything else is refused before any method runs.
    pub fn call(&self, actor: &str, name: &str, args: &Args) -> ConfigResult<Value> {
        if !EXPOSED.contains(&name) {
            return Err(admin_error(format!("Unknown admin tool {}.", repr_str(name))));
        }
        match name {
            "tool_list" => self.tool_list(actor, args),
            "tool_get" => self.tool_get(actor, args),
            "tool_create" => self.tool_create(actor, args),
            "tool_update" => self.tool_update(actor, args),
            "tool_enable" => self.tool_enable(actor, args),
            "tool_disable" => self.tool_disable(actor, args),
            "tool_delete" => self.tool_delete(actor, args),
            "tool_validate" => self.tool_validate(actor, args),
            "grant_list" => self.grant_list(actor, args),
            "grant_set" => self.grant_set(actor, args),
            "role_set" => self.role_set(actor, args),
            "audit_query" => self.audit_query(actor, args),
            "pending_list" => self.pending_list(actor, args),
            "proposal_list" => self.proposal_list(actor, args),
            "release_notes" => self.release_notes(actor, args),
            "toolkit_list" => self.toolkit_list(actor, args),
            "cred_list" => self.cred_list(actor, args),
            "cred_delete" => self.cred_delete(actor, args),
            "toolkit_propose" => self.toolkit_propose(actor, args),
            "toolkit_update" => self.toolkit_update(actor, args),
            "toolkit_delete" => self.toolkit_delete(actor, args),
            "proposal_withdraw" => self.proposal_withdraw(actor, args),
            "cred_propose" => self.cred_propose(actor, args),
            "cred_update" => self.cred_update(actor, args),
            "credential_bind" => self.credential_bind(actor, args),
            _ => Err(admin_error(format!("Unknown admin tool {}.", repr_str(name)))),
        }
    }

    fn credential_names(&self, credentials: &CredentialStore) -> ConfigResult<Vec<CredentialMeta>> {
        credentials.names(None)
    }

    // -- Read-only -----------------------------------------------------------

    /// The catalog id(s) `grant_set` actually accepts for `tool_id`.
    fn grantable_ids(&self, tool_id: &str) -> Vec<String> {
        self.store.service.catalog().grantable_ids(tool_id)
    }

    pub fn tool_list(&self, _actor: &str, args: &Args) -> ConfigResult<Value> {
        let include_deleted = args.get("include_deleted").is_some_and(py_truthy);
        let catalog = self.store.service.catalog();
        let mut out: Vec<Value> = Vec::new();
        for raw in &catalog.raw {
            let Value::Object(raw) = raw else { continue };
            let mut entry = normalize_tool_entry(raw);
            if entry["deleted"].as_bool().unwrap_or(false) && !include_deleted {
                continue;
            }
            let id = entry["id"].as_str().unwrap_or("").to_string();
            entry["grantable_ids"] = json!(self.grantable_ids(&id));
            out.push(entry);
        }
        let key = |e: &Value| match &e["id"] {
            v if py_truthy(v) => str_value(v),
            _ => String::new(),
        };
        out.sort_by_key(key);
        Ok(json!({ "tools": out }))
    }

    pub fn tool_get(&self, _actor: &str, args: &Args) -> ConfigResult<Value> {
        let tool_id = require_str(args, "id")?;
        let catalog = self.store.service.catalog();
        let Some(raw) = catalog.raw_of(tool_id) else {
            return Err(admin_error(format!("No tool with ID {}.", repr_str(tool_id))));
        };
        let mut entry = normalize_tool_entry(raw);
        entry["grantable_ids"] = json!(self.grantable_ids(tool_id));
        Ok(entry)
    }

    pub fn tool_validate(&self, _actor: &str, args: &Args) -> ConfigResult<Value> {
        let spec = require_dict(args, "spec")?;
        match parse_tool_spec(&Value::Object(spec.clone()), &self.store.service.tier1()) {
            Err(exc) => Ok(json!({"ok": false, "error": exc.message})),
            Ok(tool) => Ok(json!({"ok": true, "id": tool.id, "category": tool.category})),
        }
    }

    pub fn grant_list(&self, _actor: &str, args: &Args) -> ConfigResult<Value> {
        let tool_id = args.get("tool_id").filter(|v| py_truthy(v));
        let identity_id = args.get("identity_id").filter(|v| py_truthy(v));
        let mut out: Vec<Value> = Vec::new();
        for ident in self.store.identities.read().identities.values() {
            if let Some(identity_id) = identity_id {
                if Value::String(ident.id.clone()) != *identity_id {
                    continue;
                }
            }
            let tools: Vec<String> = ident.tools.iter().cloned().collect();
            if let Some(tool_id) = tool_id {
                if !tools.iter().any(|t| Value::String(t.clone()) == *tool_id) {
                    continue;
                }
            }
            out.push(json!({
                "identity": ident.id,
                "role": ident.role,
                "tools": tools,
                "scopes": ident.scopes,
            }));
        }
        out.sort_by(|a, b| a["identity"].as_str().cmp(&b["identity"].as_str()));
        Ok(json!({ "grants": out }))
    }

    pub fn audit_query(&self, _actor: &str, args: &Args) -> ConfigResult<Value> {
        let limit = match args.get("limit") {
            Some(v) if py_truthy(v) => int_arg(v)?,
            _ => 200,
        };
        let path = crate::pathutil::join(&self.store.service.tier1().audit_dir, "audit.jsonl");
        let filter = AuditFilter {
            identity: str_or_empty(args, "identity"),
            tool: str_or_empty(args, "tool"),
            outcome: str_or_empty(args, "outcome"),
            since: None,
        };
        let (records, truncated) = read_audit(&path, limit.clamp(1, 1000) as usize, &filter);
        Ok(json!({"entries": records, "truncated": truncated}))
    }

    /// The deployment's own RELEASE.md, for the agent that manages it.
    pub fn release_notes(&self, _actor: &str, args: &Args) -> ConfigResult<Value> {
        if args.get("full").is_some_and(py_truthy) {
            let text = release_notes::read_full();
            if text.is_empty() {
                return Err(admin_error(NO_RELEASE_NOTES));
            }
            return Ok(json!({"current_version": crate::VERSION, "markdown": text}));
        }
        let limit = match args.get("limit") {
            None | Some(Value::Null) => 10,
            Some(v) => int_arg(v)?.max(1),
        };
        let version = opt_truthy_str(args, "version").filter(|v| !v.is_empty());
        let search = opt_truthy_str(args, "search").filter(|s| !s.is_empty());
        let (releases, total) = release_notes::query(version.as_deref(), search.as_deref(), Some(limit));
        if releases.is_empty() && release_notes::query(None, None, None).1 == 0 {
            return Err(admin_error(NO_RELEASE_NOTES));
        }
        if let Some(version) = &version {
            if releases.is_empty() {
                return Err(admin_error(format!("No release notes for version {}.", repr_str(version))));
            }
        }
        let count = releases.len();
        Ok(json!({
            "current_version": crate::VERSION,
            "releases": releases,
            "count": count,
            "total": total,
            "truncated": total > count,
        }))
    }

    /// Reads the queue -- and, first, closes what is no longer decidable.
    pub fn pending_list(&self, _actor: &str, args: &Args) -> ConfigResult<Value> {
        sweep_vanished_pendings(&self.store, &self.pending, self.credentials.as_deref(), "system")?;
        let status = opt_truthy_str(args, "status");
        let items = self.pending.list(status.as_deref())?;
        Ok(json!({ "pending": items.iter().map(PendingAction::to_spec).collect::<Vec<_>>() }))
    }

    /// Lists the toolkit-proposal queue, optionally by `kind`/`status`.
    pub fn proposal_list(&self, _actor: &str, args: &Args) -> ConfigResult<Value> {
        let kind = args.get("kind").filter(|v| py_truthy(v));
        let status = args.get("status").filter(|v| py_truthy(v));
        if let Some(kind) = kind {
            if !kind.as_str().is_some_and(|k| KINDS.contains(&k)) {
                return Err(admin_error(format!(
                    "Unknown proposal kind {} (one of {}).",
                    repr_value(kind),
                    repr_sorted(KINDS)
                )));
            }
        }
        if let Some(status) = status {
            if !status.as_str().is_some_and(|s| STATUSES.contains(&s)) {
                return Err(admin_error(format!(
                    "Unknown proposal status {} (one of {}).",
                    repr_value(status),
                    repr_sorted(STATUSES)
                )));
            }
        }
        let mut items = self.toolkit_proposals.list(status.and_then(Value::as_str))?;
        if let Some(kind) = kind.and_then(Value::as_str) {
            items.retain(|i| i.kind == kind);
        }
        Ok(json!({ "proposals": items.iter().map(|i| i.to_spec()).collect::<Vec<_>>() }))
    }

    /// Lists live Tier 1 toolkits + destinations. Read-only.
    pub fn toolkit_list(&self, _actor: &str, _args: &Args) -> ConfigResult<Value> {
        let tier1 = self.store.service.tier1();
        let mut destinations: Vec<&String> = tier1.destinations.keys().collect();
        destinations.sort();
        Ok(json!({"toolkits": toolkit_summaries(&tier1), "destinations": destinations}))
    }

    pub fn cred_list(&self, _actor: &str, _args: &Args) -> ConfigResult<Value> {
        let Some(credentials) = self.credentials.as_deref() else {
            return Ok(json!({"credentials": []}));
        };
        Ok(json!({"credentials": credential_summaries(credentials, &self.store.service.tier1())?}))
    }

    // -- Always auto-apply ---------------------------------------------------

    pub fn tool_create(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let mut spec = require_dict(args, "spec")?.clone();
        // Always-inert creation: enabling is a separate, auditable step.
        spec.insert("enabled".into(), json!(false));
        let tool_id = self.store.save_tool(&spec, actor, &self.store.tools_revision(), None)?;
        Ok(json!({"applied": true, "id": tool_id}))
    }

    pub fn tool_disable(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let tool_id = require_str(args, "id")?;
        self.store.set_tool_enabled(tool_id, false, actor, &self.store.tools_revision())?;
        Ok(json!({"applied": true, "id": tool_id}))
    }

    /// Deletes a credential *slot* by name; refused while still bound.
    pub fn cred_delete(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let Some(credentials) = self.credentials.as_deref() else {
            return Err(admin_error(
                "No credential store is configured on this deployment -- \
                 there is no credential slot to delete.",
            ));
        };
        let name = require_str(args, "name")?;
        let known: Vec<String> = self.credential_names(credentials)?.into_iter().map(|m| m.name).collect();
        if !known.iter().any(|k| k == name) {
            return Err(admin_error(format!(
                "No credential slot named {} exists (known credentials: {}). Check admin.cred_list.",
                repr_str(name),
                repr_sorted(&known)
            )));
        }
        let refs = self.store.service.tier1().credential_references();
        if let Some(used_by) = refs.get(name).filter(|u| !u.is_empty()) {
            return Err(admin_error(format!(
                "Credential {} is still referenced by {} -- deleting it would leave those refusing \
                 every call with 'credential is not configured yet'. Point them at another slot \
                 first (admin.credential_bind, human-approved), then delete this one.",
                repr_str(name),
                repr_sorted(used_by)
            )));
        }
        credentials.delete(name, actor, &credentials.revision())?;
        Ok(json!({"applied": true, "name": name}))
    }

    // -- Category-conditional ------------------------------------------------

    pub fn tool_enable(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let tool_id = require_str(args, "id")?;
        let Some(flat) = self.store.service.catalog().flat_spec_of(tool_id) else {
            return Err(admin_error(format!("No tool with ID {}.", repr_str(tool_id))));
        };
        if flat.get("category").and_then(Value::as_str) == Some("read") {
            self.store.set_tool_enabled(tool_id, true, actor, &self.store.tools_revision())?;
            return Ok(json!({"applied": true, "id": tool_id}));
        }
        let mut payload = Map::new();
        payload.insert("id".into(), json!(tool_id));
        let item = self.pending.propose("tool_enable", actor, payload, &self.store.tool_revision(tool_id))?;
        Ok(pending_reply(&item))
    }

    pub fn tool_update(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let tool_id = require_str(args, "id")?;
        let mut spec = require_dict(args, "spec")?.clone();
        spec.entry("id").or_insert_with(|| json!(tool_id));
        if spec["id"] != json!(tool_id) {
            return Err(admin_error("'spec.id' must match 'id' -- renaming is not supported here."));
        }
        // Validate up front: a definition that would fail should not
        // consume a pending-queue slot.
        let tool = parse_tool_spec(&Value::Object(spec.clone()), &self.store.service.tier1())?;
        if tool.category == "read" {
            let new_id = self.store.save_tool(&spec, actor, &self.store.tools_revision(), Some(tool_id))?;
            return Ok(json!({"applied": true, "id": new_id}));
        }
        let mut payload = Map::new();
        payload.insert("spec".into(), Value::Object(spec));
        payload.insert("replaces".into(), json!(tool_id));
        let item = self.pending.propose("tool_update", actor, payload, &self.store.tool_revision(tool_id))?;
        Ok(pending_reply(&item))
    }

    // -- Always pending ------------------------------------------------------

    pub fn tool_delete(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let tool_id = require_str(args, "id")?;
        if self.store.service.catalog().raw_of(tool_id).is_none() {
            return Err(admin_error(format!("No tool with ID {}.", repr_str(tool_id))));
        }
        let mut payload = Map::new();
        payload.insert("id".into(), json!(tool_id));
        let item = self.pending.propose("tool_delete", actor, payload, &self.store.tool_revision(tool_id))?;
        Ok(pending_reply(&item))
    }

    pub fn grant_set(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let identity_id = require_str(args, "identity_id")?;
        let Some(existing) = self.store.identities.read().identities.get(identity_id).cloned() else {
            return Err(admin_error(format!("No identity {}.", repr_str(identity_id))));
        };
        if existing.role != "agent" {
            // Only an `agent` identity ever authenticates on `/mcp`.
            return Err(admin_error(format!(
                "{} has role {}, not 'agent' -- tool grants only take effect for an agent identity.",
                repr_str(identity_id),
                repr_str(&existing.role)
            )));
        }
        let raw_tools: Vec<String> = match args.get("tools") {
            Some(Value::Array(items)) if items.iter().all(Value::is_string) => {
                items.iter().filter_map(|t| t.as_str().map(str::to_string)).collect()
            }
            _ => return Err(admin_error("'tools' is required and must be a list of strings.")),
        };
        let scopes: Vec<String> = if args.contains_key("scopes") {
            match args.get("scopes") {
                Some(Value::Array(items)) if items.iter().all(Value::is_string) => {
                    items.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()
                }
                _ => return Err(admin_error("'scopes' must be a list of strings.")),
            }
        } else {
            existing.scopes.clone()
        };
        let tools: BTreeSet<String> = raw_tools.into_iter().collect();
        let mut payload = Map::new();
        payload.insert("identity_id".into(), json!(identity_id));
        payload.insert("role".into(), json!(existing.role));
        payload.insert("tools".into(), json!(tools));
        payload.insert("scopes".into(), json!(scopes));
        // Snapshotted so an archived proposal still shows its diff.
        payload.insert("prev_tools".into(), json!(existing.tools));
        let item = self.pending.propose("grant_set", actor, payload, &self.store.identity_revision(identity_id))?;
        Ok(pending_reply(&item))
    }

    pub fn role_set(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let identity_id = require_str(args, "identity_id")?;
        let Some(existing) = self.store.identities.read().identities.get(identity_id).cloned() else {
            return Err(admin_error(format!("No identity {}.", repr_str(identity_id))));
        };
        let role = require_str(args, "role")?;
        if !ROLES.contains(&role) {
            return Err(admin_error(format!("Unknown role {}.", repr_str(role))));
        }
        if UI_ROLES.contains(&role) && existing.password_hash.is_empty() {
            return Err(admin_error(format!(
                "{} has no console password -- role {} needs one to sign in, and this proposal \
                 cannot set one. A human must set a password directly in the identity editor.",
                repr_str(identity_id),
                repr_str(role)
            )));
        }
        let mut payload = Map::new();
        payload.insert("identity_id".into(), json!(identity_id));
        payload.insert("role".into(), json!(role));
        payload.insert("tools".into(), json!(existing.tools));
        payload.insert("scopes".into(), json!(existing.scopes));
        let item = self.pending.propose("role_set", actor, payload, &self.store.identity_revision(identity_id))?;
        Ok(pending_reply(&item))
    }

    /// Always writes to the toolkit-proposal queue, never auto-applies.
    pub fn toolkit_propose(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let name = require_str(args, "name")?;
        let spec = require_dict(args, "spec")?.clone();
        let item = self.toolkit_proposals.propose(name, spec, actor, "create")?;
        Ok(json!({"applied": false, "pending": true, "proposal_id": item.id}))
    }

    /// Proposes changing a toolkit's executor, binaries, denied_args,
    /// run_as, and an http/opencode toolkit's allowed_hosts/allowed_cidrs
    /// (`toolkit_proposals::UPDATE_WRITABLE_FIELDS`).
    pub fn toolkit_update(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let name = require_str(args, "name")?;
        let updates = require_dict(args, "updates")?.clone();
        if updates.is_empty() {
            return Ok(json!({"applied": false, "error": "No updates provided."}));
        }
        let item = self.toolkit_proposals.propose(name, updates, actor, "update")?;
        Ok(json!({"applied": false, "pending": true, "proposal_id": item.id}))
    }

    /// Proposes removing an existing toolkit from Tier 1.
    pub fn toolkit_delete(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let name = require_str(args, "name")?;
        let item = self.toolkit_proposals.propose(name, Map::new(), actor, "delete")?;
        Ok(json!({"applied": false, "pending": true, "proposal_id": item.id}))
    }

    /// Takes back a still-pending toolkit proposal the caller filed itself.
    pub fn proposal_withdraw(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let proposal_id = require_str(args, "proposal_id")?;
        let item = self.toolkit_proposals.withdraw(proposal_id, actor)?;
        Ok(json!({"withdrawn": true, "proposal_id": item.id, "name": item.name}))
    }

    /// Proposes pointing an existing toolkit at an existing credential
    /// *slot* -- two names, nothing else (FR-10.2/10.8).
    pub fn credential_bind(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        if let Some(smuggled) = args_in(args, &BIND_VALUE_ARGS) {
            let verb = if count_args_in(args, &BIND_VALUE_ARGS) == 1 { "is" } else { "are" };
            return Err(admin_error(format!(
                "{smuggled} {verb} not a valid argument here -- this binds a toolkit to a credential \
                 *name*. No operation on /admin/mcp ever carries secret material (FR-10.2/10.8); a \
                 value is typed by a human in /app/credentials and never reaches this queue."
            )));
        }
        if let Some(deploy_time) = args_in(args, &BIND_DEPLOY_TIME_ARGS) {
            return Err(admin_error(format!(
                "{deploy_time} cannot be proposed -- this binds a credential at the toolkit level \
                 only. Destination-level credential overrides, path_roots, protected_resources and \
                 limits stay deploy-time only (FR-4.11) and need a redeploy."
            )));
        }
        if let Some(update_args) = args_in(args, &BIND_UPDATE_ARGS) {
            return Err(admin_error(format!(
                "{update_args} cannot be proposed here -- this tool sets a toolkit's credential and \
                 nothing else. Use admin.toolkit_update for those fields."
            )));
        }

        let toolkit = require_str(args, "toolkit")?;
        let credential = require_str(args, "credential")?;

        // The running Tier 1 -- the same source `toolkit_list` reports.
        let tier1 = self.store.service.tier1();
        if !tier1.toolkits.contains_key(toolkit) {
            let known: Vec<&String> = tier1.toolkits.keys().collect();
            return Err(admin_error(format!(
                "No toolkit named {} in the running configuration (known toolkits: {}). Check \
                 admin.toolkit_list.",
                repr_str(toolkit),
                repr_sorted(known)
            )));
        }
        let Some(credentials) = self.credentials.as_deref() else {
            return Err(admin_error(
                "No credential store is configured on this deployment -- \
                 there is no credential slot to bind to.",
            ));
        };
        let known: Vec<String> = self.credential_names(credentials)?.into_iter().map(|m| m.name).collect();
        if !known.iter().any(|k| k == credential) {
            return Err(admin_error(format!(
                "No credential slot named {} exists (known credentials: {}). Propose it first with \
                 admin.cred_propose, or check admin.cred_list.",
                repr_str(credential),
                repr_sorted(&known)
            )));
        }
        let mut spec = Map::new();
        spec.insert(BIND_FIELD.into(), json!(credential));
        let item = self.toolkit_proposals.propose(toolkit, spec, actor, "bind")?;
        Ok(json!({"applied": false, "pending": true, "proposal_id": item.id}))
    }

    /// Proposes a named, typed credential slot -- never a value.
    pub fn cred_propose(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let Some(credentials) = self.credentials.as_deref() else {
            return Err(admin_error(
                "No credential store is configured on this deployment -- nothing to propose against.",
            ));
        };
        if args.contains_key("value") {
            return Err(admin_error(
                "'value' is not a valid argument here -- this proposes a \
                 credential's name/kind/header only. The secret value is \
                 always typed by a human in /app/requests at approval time, never \
                 sent over /admin/mcp (FR-10.2/10.8).",
            ));
        }
        let name = require_str(args, "name")?;
        if !valid_credential_name(name) {
            return Err(admin_error(format!(
                "{} is not a valid credential name -- must match {}.",
                repr_str(name),
                repr_str(CREDENTIAL_NAME_PATTERN)
            )));
        }
        let kind = require_str(args, "kind")?;
        if !CREDENTIAL_KINDS.contains(&kind) {
            return Err(admin_error(format!(
                "Unknown credential kind {} (allowed: {}).",
                repr_str(kind),
                repr_sorted(CREDENTIAL_KINDS)
            )));
        }
        let header = match args.get("header") {
            None | Some(Value::Null) => None,
            Some(Value::String(h)) => Some(h.clone()),
            Some(_) => return Err(admin_error("'header' must be a string if given.")),
        };
        let probe_url = match args.get("probe_url") {
            None | Some(Value::Null) => None,
            Some(Value::String(p)) => Some(p.clone()),
            Some(_) => return Err(admin_error("'probe_url' must be a string if given.")),
        };
        if let Some(p) = probe_url.as_deref().filter(|p| !p.is_empty()) {
            if !(p.starts_with("http://") || p.starts_with("https://")) {
                return Err(admin_error("'probe_url' must be an http(s) URL if given."));
            }
        }
        if (kind == "api_key_header" || kind == "url_query") && header.as_deref().is_none_or(str::is_empty) {
            return Err(admin_error(format!(
                "kind {} requires a 'header' (header/param name).",
                repr_str(kind)
            )));
        }
        let header_format = match args.get("header_format") {
            None | Some(Value::Null) => None,
            Some(Value::String(f)) => Some(f.clone()),
            Some(_) => return Err(admin_error("'header_format' must be a string if given.")),
        };
        let header_format =
            check_header_format(kind, header_format.as_deref()).map_err(|exc| admin_error(exc.message))?;
        if self.credential_names(credentials)?.iter().any(|m| m.name == name) {
            return Err(admin_error(format!("A credential named {} already exists.", repr_str(name))));
        }
        let mut payload = Map::new();
        payload.insert("name".into(), json!(name));
        payload.insert("kind".into(), json!(kind));
        payload.insert("header".into(), opt_value(&header));
        payload.insert("probe_url".into(), opt_value(&probe_url));
        if let Some(f) = header_format.filter(|f| !f.is_empty()) {
            payload.insert("header_format".into(), json!(f));
        }
        let item = self.pending.propose("cred_propose", actor, payload, &credentials.revision())?;
        Ok(pending_reply(&item))
    }

    /// Proposes changing an existing slot's kind, header, probe URL and/or
    /// name -- keeping the stored value (FR-10.2/10.8).
    pub fn cred_update(&self, actor: &str, args: &Args) -> ConfigResult<Value> {
        let Some(credentials) = self.credentials.as_deref() else {
            return Err(admin_error(
                "No credential store is configured on this deployment -- \
                 there is no credential slot to update.",
            ));
        };
        if let Some(smuggled) = args_in(args, &BIND_VALUE_ARGS) {
            let verb = if count_args_in(args, &BIND_VALUE_ARGS) == 1 { "is" } else { "are" };
            return Err(admin_error(format!(
                "{smuggled} {verb} not a valid argument here -- this changes a credential's \
                 name/kind/header and keeps its stored value. No operation on /admin/mcp ever \
                 carries secret material (FR-10.2/10.8); a new value is a rotation, typed by a \
                 human in /app/credentials."
            )));
        }
        let name = require_str(args, "name")?;
        let metas = self.credential_names(credentials)?;
        let Some(current) = metas.iter().find(|m| m.name == name).cloned() else {
            let known: Vec<&String> = metas.iter().map(|m| &m.name).collect();
            return Err(admin_error(format!(
                "No credential slot named {} exists (known credentials: {}). Check admin.cred_list.",
                repr_str(name),
                repr_sorted(known)
            )));
        };
        for field in ["new_name", "kind", "header", "header_format", "probe_url"] {
            if let Some(v) = args.get(field) {
                if !v.is_null() && !v.is_string() {
                    return Err(admin_error(format!("'{field}' must be a string if given.")));
                }
            }
        }
        let arg_str = |k: &str| args.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);

        let mut new_name = arg_str("new_name");
        if new_name.as_deref() == Some(name) {
            new_name = None;
        }
        if let Some(new_name) = &new_name {
            if !valid_credential_name(new_name) {
                return Err(admin_error(format!(
                    "{} is not a valid credential name -- must match {}.",
                    repr_str(new_name),
                    repr_str(CREDENTIAL_NAME_PATTERN)
                )));
            }
            if metas.iter().any(|m| &m.name == new_name) {
                return Err(admin_error(format!("A credential named {} already exists.", repr_str(new_name))));
            }
            let refs = self.store.service.tier1().credential_references();
            if let Some(used_by) = refs.get(name).filter(|u| !u.is_empty()) {
                return Err(admin_error(format!(
                    "Credential {} is still referenced by {} -- renaming it would leave those \
                     pointing at a slot that no longer exists, and the binding is Tier 1 (FR-10.4). \
                     Kind and header can be changed without a rename: leave out 'new_name'.",
                    repr_str(name),
                    repr_sorted(used_by)
                )));
            }
        }

        let kind = arg_str("kind").unwrap_or_else(|| current.kind.clone());
        if !CREDENTIAL_KINDS.contains(&kind.as_str()) {
            return Err(admin_error(format!(
                "Unknown credential kind {} (allowed: {}).",
                repr_str(&kind),
                repr_sorted(CREDENTIAL_KINDS)
            )));
        }
        if value_shape(&kind) != value_shape(&current.kind) {
            return Err(admin_error(format!(
                "Cannot change {} from {} to {}: the stored value is a {}, and {} needs a {}. The \
                 value cannot be read back to convert it -- propose a new slot with admin.cred_propose.",
                repr_str(name),
                repr_str(&current.kind),
                repr_str(&kind),
                value_shape(&current.kind).unwrap_or("value"),
                repr_str(&kind),
                value_shape(&kind).unwrap_or("value"),
            )));
        }
        let header_kind = HEADER_KINDS.contains(&kind.as_str());
        let header = if args.contains_key("header") {
            arg_str("header")
        } else if header_kind {
            // A kind that takes no header drops the old one.
            current.header.clone()
        } else {
            None
        };
        if header_kind && header.as_deref().is_none_or(str::is_empty) {
            return Err(admin_error(format!(
                "kind {} requires a 'header' (header/param name).",
                repr_str(&kind)
            )));
        }
        if header.is_some() && !header_kind {
            return Err(admin_error(format!(
                "kind {} takes no 'header' -- it builds its own (bearer, basic) or is not sent as a \
                 header at all.",
                repr_str(&kind)
            )));
        }
        if let Some(h) = &header {
            if !is_header_name(h) {
                return Err(admin_error(format!("{} is not a valid header/param name.", repr_str(h))));
            }
        }
        let header_format = if args.contains_key("header_format") {
            arg_str("header_format")
        } else if kind == "api_key_header" {
            // Kept only while the slot stays an `api_key_header`.
            current.header_format.clone()
        } else {
            None
        };
        let header_format =
            check_header_format(&kind, header_format.as_deref()).map_err(|exc| admin_error(exc.message))?;
        let probe_url = if args.contains_key("probe_url") {
            args.get("probe_url")
                .and_then(Value::as_str)
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
        } else {
            current.probe_url.clone()
        };
        if let Some(p) = probe_url.as_deref().filter(|p| !p.is_empty()) {
            if !(p.starts_with("http://") || p.starts_with("https://")) {
                return Err(admin_error("'probe_url' must be an http(s) URL if given."));
            }
        }

        let prev = json!({
            "kind": current.kind, "header": current.header,
            "header_format": current.header_format, "probe_url": current.probe_url,
        });
        let proposed = json!({
            "kind": kind, "header": header, "header_format": header_format, "probe_url": probe_url,
        });
        if new_name.is_none() && prev == proposed {
            return Err(admin_error(format!(
                "Nothing to change: {} already has kind {}{}.",
                repr_str(name),
                repr_str(&kind),
                match header.as_deref().filter(|h| !h.is_empty()) {
                    Some(h) => format!(", header {}", repr_str(h)),
                    None => String::new(),
                }
            )));
        }
        let mut payload = Map::new();
        payload.insert("name".into(), json!(name));
        payload.insert("new_name".into(), opt_value(&new_name));
        payload.insert("kind".into(), json!(kind));
        payload.insert("header".into(), opt_value(&header));
        payload.insert("header_format".into(), opt_value(&header_format));
        payload.insert("probe_url".into(), opt_value(&probe_url));
        // Snapshotted for the reviewer's diff.
        payload.insert("prev".into(), prev);
        let item = self.pending.propose("cred_update", actor, payload, &credentials.record_revision(name)?)?;
        Ok(pending_reply(&item))
    }
}

// -- Applying an approved pending action (called only from the console API) --

/// Which store's per-record fingerprint a pending kind is gated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Tools,
    Identities,
    Credentials,
}

/// `_APPLIERS`: proposed action -> (target kind, payload field naming the
/// target). The applier itself is [`apply`].
fn applier_entry(action: &str) -> Option<(TargetKind, &'static str)> {
    match action {
        "tool_update" => Some((TargetKind::Tools, "replaces")),
        "tool_enable" | "tool_delete" => Some((TargetKind::Tools, "id")),
        "grant_set" | "role_set" => Some((TargetKind::Identities, "identity_id")),
        "cred_update" => Some((TargetKind::Credentials, "name")),
        _ => None,
    }
}

fn payload_str<'a>(item: &'a PendingAction, key: &str) -> ConfigResult<&'a str> {
    // PORT NOTE: Python raised KeyError/TypeError for a malformed payload.
    item.payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| write_refused(format!("Pending action {} has no valid {}.", repr_str(&item.id), repr_str(key))))
}

fn payload_strings(item: &PendingAction, key: &str) -> ConfigResult<Vec<String>> {
    match item.payload.get(key) {
        Some(Value::Array(a)) => Ok(a.iter().map(str_value).collect()),
        _ => Err(write_refused(format!("Pending action {} has no valid {}.", repr_str(&item.id), repr_str(key)))),
    }
}

fn payload_opt(item: &PendingAction, key: &str) -> Option<String> {
    item.payload.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// The appliers (`_apply_tool_update`, ...). Returns what Python's returned:
/// the tool id for `tool_update`, `None` otherwise.
fn apply(store: &ConfigStore, item: &PendingAction, credentials: Option<&CredentialStore>) -> ConfigResult<Value> {
    match item.action.as_str() {
        "tool_update" => {
            let Some(Value::Object(spec)) = item.payload.get("spec") else {
                return Err(write_refused(format!("Pending action {} has no valid 'spec'.", repr_str(&item.id))));
            };
            let replaces = payload_opt(item, "replaces");
            let id = store.save_tool(spec, &item.actor, &store.tools_revision(), replaces.as_deref())?;
            Ok(json!(id))
        }
        "tool_enable" => {
            store.set_tool_enabled(payload_str(item, "id")?, true, &item.actor, &store.tools_revision())?;
            Ok(Value::Null)
        }
        "tool_delete" => {
            store.delete_tool(payload_str(item, "id")?, &item.actor, &store.tools_revision())?;
            Ok(Value::Null)
        }
        "grant_set" | "role_set" => {
            let identity_id = payload_str(item, "identity_id")?;
            store.save_identity(
                identity_id,
                payload_str(item, "role")?,
                &payload_strings(item, "tools")?,
                &payload_strings(item, "scopes")?,
                &item.actor,
                &store.identities_revision(),
                Some(identity_id),
                "",
            )?;
            Ok(Value::Null)
        }
        "cred_update" => {
            let Some(credentials) = credentials else {
                return Err(write_refused("No credential store is configured on this deployment."));
            };
            let name = payload_str(item, "name")?;
            let new_name = payload_opt(item, "new_name");
            if new_name.is_some() {
                // Checked again here: a toolkit may have been bound to this
                // slot while the rename waited in the queue.
                let refs = store.service.tier1().credential_references();
                if let Some(used_by) = refs.get(name).filter(|u| !u.is_empty()) {
                    return Err(write_refused(format!(
                        "Credential {} is now referenced by {}; renaming it would leave that binding \
                         dangling. Reject this and ask for the change without a rename.",
                        repr_str(name),
                        repr_sorted(used_by)
                    )));
                }
            }
            credentials.update(
                name,
                payload_str(item, "kind")?,
                item.payload.get("header").and_then(Value::as_str),
                item.payload.get("probe_url").and_then(Value::as_str),
                new_name.as_deref(),
                item.payload.get("header_format").and_then(Value::as_str),
                &item.actor,
                &credentials.revision(),
            )?;
            Ok(Value::Null)
        }
        other => Err(write_refused(format!("Unknown pending action type {}.", repr_str(other)))),
    }
}

/// `_target_rev`: the live per-record revision of what one pending item
/// targets, or `None` if it targets no record this module can resolve
/// (`""` is a real answer: the record is gone).
fn target_rev(
    store: &ConfigStore,
    item: &PendingAction,
    credentials: Option<&CredentialStore>,
) -> ConfigResult<Option<String>> {
    let Some((kind, field)) = applier_entry(&item.action) else {
        return Ok(None);
    };
    let Some(target_id) = item.payload.get(field).and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    Ok(match kind {
        TargetKind::Tools => Some(store.tool_revision(target_id)),
        TargetKind::Credentials => match credentials {
            None => None,
            Some(c) => Some(c.record_revision(target_id)?),
        },
        TargetKind::Identities => Some(store.identity_revision(target_id)),
    })
}

/// Closes every queued proposal whose target record no longer exists (and,
/// with `credentials`, every `cred_propose`/renaming `cred_update` whose
/// name has been taken since). Idempotent.
pub fn sweep_vanished_pendings(
    store: &ConfigStore,
    pending: &PendingStore,
    credentials: Option<&CredentialStore>,
    decided_by: &str,
) -> ConfigResult<Vec<PendingAction>> {
    // PORT NOTE: a credential store read error while judging an item makes
    // the sweep leave that item alone (Python would have raised).
    let mut closed = pending.close_vanished_targets(
        |item| target_rev(store, item, credentials).ok().flatten(),
        decided_by,
    )?;
    if let Some(credentials) = credentials {
        let taken: HashSet<String> = credentials.names(None)?.into_iter().map(|m| m.name).collect();
        closed.extend(pending.close_taken_credentials(&taken, decided_by)?);
    }
    Ok(closed)
}

/// Approves and applies one pending action -- the only function that turns
/// a proposal into a live change. Called only from the console API's
/// request-decision routes; not reachable from `/admin/mcp` (FR-2.8/2.9).
pub fn apply_pending(
    store: &ConfigStore,
    pending: &PendingStore,
    action_id: &str,
    decided_by: &str,
    credentials: Option<&CredentialStore>,
) -> ConfigResult<Value> {
    let Some(item) = pending.get(action_id)? else {
        return Err(write_refused(format!("No pending action {}.", repr_str(action_id))));
    };
    let Some((kind, _field)) = applier_entry(&item.action) else {
        return Err(write_refused(format!("Unknown pending action type {}.", repr_str(&item.action))));
    };
    if kind == TargetKind::Credentials && credentials.is_none() {
        // Refused before the staleness gate, which would otherwise read the
        // unanswerable revision as "the slot is gone".
        return Err(write_refused("No credential store is configured on this deployment."));
    }
    // A read error while computing the live revision must neither close the
    // item as stale nor let `apply` run: it is carried to `apply`, which
    // reports it and leaves the item pending.
    let rev_error: RefCell<Option<ConfigError>> = RefCell::new(None);
    pending.approve(
        action_id,
        decided_by,
        |pending_item| match target_rev(store, pending_item, credentials) {
            // `None` here means the payload does not name a target; routed
            // into the vanished-target gate rather than an error.
            Ok(rev) => rev.unwrap_or_default(),
            Err(e) => {
                *rev_error.borrow_mut() = Some(e);
                pending_item.base_rev.clone()
            }
        },
        |pending_item| {
            if let Some(e) = rev_error.borrow_mut().take() {
                return Err(e);
            }
            apply(store, pending_item, credentials)
        },
    )
}
