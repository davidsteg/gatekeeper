//! The toolkit-proposal queue for the `admin.*` MCP surface (port of
//! `toolkit_proposals.py`).
//!
//! A toolkit proposal changes Tier 1 (`toolkits.yaml`) -- what is possible
//! at all, not merely who may do what -- so it has its own file
//! (`toolkit_proposals.yaml`) and its own store, never `PendingStore`.
//!
//! Four kinds share the queue: `create` (a brand-new toolkit, full body),
//! `update` (only `UPDATE_WRITABLE_FIELDS` of an existing toolkit),
//! `delete` (an existing toolkit no live tool references) and `bind`
//! (exactly `{"credential": <name>}` on an existing toolkit).
//!
//! `deploy` is the only function that ever writes `toolkits.yaml`: it
//! merges, validates the merged text with the exact `load_tier1` startup
//! uses (in a temp file, nothing real touched), then writes atomically,
//! reloads the running service, audits and marks the proposal `deployed`.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use ipnet::IpNet;
use serde_json::{json, Map, Value};

use crate::atomic::{atomic_write_cfg, dump, load_cached, revision, safe_load, writable};
use crate::audit::AuditLog;
use crate::catalog::{current_version_spec, now_iso};
use crate::errors::{ConfigError, ConfigResult};
use crate::pyfmt::{repr_list, repr_str, repr_value, str_value};
use crate::runas::parse_run_as;
use crate::service::Service;
use crate::tier1::{
    ip_network, is_public_address, load_tier1, parse_network_allowlist, pure_posix_within, py_truthy,
    url_hostname, NETWORK_EXECUTORS,
};

/// What a toolkit proposal may be in.
pub const STATUSES: [&str; 4] = ["pending", "deployed", "rejected", "withdrawn"];

/// The four shapes a proposal can take.
pub const KINDS: [&str; 4] = ["create", "update", "delete", "bind"];

/// The one and only field a `bind` proposal carries.
pub const BIND_FIELD: &str = "credential";

/// Fields `update`-kind proposals may change. `protected_resources`
/// stays deploy-time only (FR-4.11).
///
/// `allowed_hosts` and `allowed_cidrs` are here as of 1.10.0, the first
/// fields in this set that change *where* a toolkit may connect -- a
/// deliberate move of that line: a public API whose addresses drift
/// (api.github.com) otherwise needs a host-side file edit every time it
/// moves. Nothing applies without a human approving the card, and no
/// proposal can lift what `load_tier1` enforces: exact names only in
/// `allowed_hosts`, and no non-public address for a hostname toolkit.
/// Only on toolkits whose executor reads them ([`NETWORK_FIELDS`],
/// checked at deploy).
///
/// 1.11.0 adds an http toolkit's `allowed_methods`/`allowed_path_prefixes`
/// and the two ceilings (`max_timeout_seconds`, `max_output_bytes`), on the
/// same terms: always a human-approved card, the card shows the current
/// value next to the proposed one, and `load_tier1` re-validates the whole
/// merged file before anything is written.
///
/// 1.22.0 adds `path_roots`, so a new `from_file` tool no longer needs a
/// hand edit of toolkits.yaml. On top of the same human-approved card,
/// every entry must be an absolute, `..`-free path other than `/` that
/// exists in this container as a directory, and no tool on the toolkit may
/// keep a `must_resolve_under` outside the new list
/// ([`check_path_roots`], at submit and again at deploy). Not on an `ssh`
/// toolkit, whose roots are on another host this container cannot check.
/// `protected_resources` remains redeploy-only.
pub const UPDATE_WRITABLE_FIELDS: [&str; 11] = [
    "executor",
    "binaries",
    "denied_args",
    "run_as",
    "allowed_hosts",
    "allowed_cidrs",
    "allowed_methods",
    "allowed_path_prefixes",
    "max_timeout_seconds",
    "max_output_bytes",
    "path_roots",
];

/// Executors whose `path_roots` are not paths in this container, so an
/// update proposal cannot check them and may not change them.
pub const REMOTE_PATH_EXECUTORS: [&str; 1] = ["ssh"];

/// The update fields that change a toolkit's network reach -- valid only
/// on an executor that connects to a URL (`tier1::NETWORK_EXECUTORS`).
/// Sorted, as Python's `sorted(NETWORK_FIELDS & ...)` iterates them.
pub const NETWORK_FIELDS: [&str; 2] = ["allowed_cidrs", "allowed_hosts"];

/// Executor-specific update fields and the executors that read them
/// (sorted by field, as `sorted(set(FIELD_EXECUTORS) & ...)` iterates). A
/// field outside its executors would be silently ignored by `load_tier1`
/// (it parses only what an executor uses), so `deploy()` refuses it rather
/// than writing a restriction that does not exist.
pub const FIELD_EXECUTORS: [(&str, &[&str]); 4] = [
    ("allowed_cidrs", NETWORK_EXECUTORS),
    ("allowed_hosts", NETWORK_EXECUTORS),
    ("allowed_methods", &["http"]),
    ("allowed_path_prefixes", &["http"]),
];

/// The two ceilings (sorted). Positive integers; `load_tier1` enforces the
/// same.
pub const LIMIT_FIELDS: [&str; 2] = ["max_output_bytes", "max_timeout_seconds"];

/// A proposed CIDR wider than this (an IPv4 network shorter than /16, an
/// IPv6 one shorter than /48) needs `confirm_broad_cidrs: true` on the
/// proposal (FR-8.15).
pub const BROAD_PREFIX_V4: u8 = 16;
pub const BROAD_PREFIX_V6: u8 = 48;

fn propose_action_name(kind: &str) -> &'static str {
    match kind {
        "update" => "toolkit_update_propose",
        "delete" => "toolkit_delete_propose",
        "bind" => "credential_bind_propose",
        _ => "toolkit_propose",
    }
}

fn deploy_action_name(kind: &str) -> &'static str {
    match kind {
        "update" => "toolkit_update_deploy",
        "delete" => "toolkit_delete_deploy",
        "bind" => "credential_bind_deploy",
        _ => "toolkit_deploy",
    }
}

/// `ToolkitProposalWriteRefused`.
pub fn proposal_refused(message: impl Into<String>) -> ConfigError {
    ConfigError::refused(message)
}

/// `sorted(set)` rendered as Python's list repr.
fn sorted_repr<'a, I: IntoIterator<Item = &'a str>>(items: I) -> String {
    let set: BTreeSet<&str> = items.into_iter().collect();
    repr_list(&set.into_iter().collect::<Vec<_>>())
}

fn writable_fields_repr() -> String {
    sorted_repr(UPDATE_WRITABLE_FIELDS)
}

/// Why a `create` proposal for an existing toolkit name is refused (one
/// text for `propose` and `deploy`).
pub fn name_collision_message(name: &str) -> String {
    format!(
        "A toolkit named {} already exists in toolkits.yaml -- a \
         'create' proposal only adds a new toolkit, and deploying this one \
         would silently overwrite it. If a second, separate toolkit is \
         what you want, propose it under a different name. If you meant to \
         change the existing one: executor, binaries, denied_args, run_as, \
         allowed_hosts, allowed_cidrs, allowed_methods, allowed_path_prefixes, \
         path_roots and the two limits go through admin.toolkit_update; \
         protected_resources has no proposal path -- edit \
         toolkits.yaml and reload (SIGHUP or restart).",
        repr_str(name)
    )
}

fn read_yaml_file(path: &str) -> ConfigResult<Value> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::new(format!("{path} cannot be read: {}", crate::pyfmt::os_error(&e, path))))?;
    // PORT NOTE: Python let a YAMLError escape; it is a ConfigError here.
    let raw = safe_load(&text).map_err(|e| ConfigError::new(format!("{path}: {e}")))?;
    Ok(if py_truthy(&raw) { raw } else { Value::Object(Map::new()) })
}

/// Tool ids in `tools_path` whose `toolkit` is `toolkit_name` and which
/// are not soft-deleted.
fn tools_referencing_toolkit(tools_path: &str, toolkit_name: &str) -> ConfigResult<BTreeSet<String>> {
    if !std::path::Path::new(tools_path).exists() {
        return Ok(BTreeSet::new());
    }
    let raw = read_yaml_file(tools_path)?;
    let Some(Value::Array(entries)) = raw.get("tools") else {
        return Ok(BTreeSet::new());
    };
    Ok(entries
        .iter()
        .filter_map(|e| e.as_object())
        .filter(|e| {
            e.get("toolkit").and_then(Value::as_str) == Some(toolkit_name)
                && !e.get("deleted").is_some_and(py_truthy)
        })
        .map(|e| str_value(e.get("id").unwrap_or(&Value::Null)))
        .collect())
}

/// Every non-deleted tool on `toolkit_name` (by its current version) that
/// a toolkit with `roots` as its `path_roots` would no longer load:
/// a `must_resolve_under` outside every root, or a `directory` parameter
/// with no root at all. Lexical, the same `pure_posix_within` the catalog's
/// own Tier 1 check uses. Each as "'<id>' (must_resolve_under '<root>')".
fn tools_outside_roots(tools_path: &str, toolkit_name: &str, roots: &[String]) -> ConfigResult<Vec<String>> {
    if !std::path::Path::new(tools_path).exists() {
        return Ok(Vec::new());
    }
    let raw = read_yaml_file(tools_path)?;
    let Some(Value::Array(entries)) = raw.get("tools") else {
        return Ok(Vec::new());
    };
    let mut blocked = Vec::new();
    for entry in entries.iter().filter_map(Value::as_object) {
        let Some((spec, _, _, deleted)) = current_version_spec(entry)? else { continue };
        if deleted || entry.get("deleted").is_some_and(py_truthy) {
            continue;
        }
        if spec.get("toolkit").and_then(Value::as_str) != Some(toolkit_name) {
            continue;
        }
        let id = repr_str(&str_value(spec.get("id").unwrap_or(&Value::Null)));
        let Some(Value::Object(parameters)) = spec.get("parameters") else { continue };
        for (param, pspec) in parameters {
            if let Some(root) = pspec.get("must_resolve_under").and_then(Value::as_str).filter(|r| !r.is_empty()) {
                if !roots.iter().any(|allowed| pure_posix_within(root, allowed)) {
                    blocked.push(format!("{id} (must_resolve_under {})", repr_str(root)));
                }
            } else if param == "directory" && roots.is_empty() {
                blocked.push(format!("{id} (a 'directory' parameter, which needs a root)"));
            }
        }
    }
    Ok(blocked)
}

/// What a proposed `path_roots` must meet, beyond `load_tier1`'s shape
/// check, at submit and again at deploy (FR-4.11's one runtime path):
///
/// 1. A list of strings, on a toolkit whose roots are paths in this
///    container (not [`REMOTE_PATH_EXECUTORS`]).
/// 2. Every entry absolute, without a `..` component, and not `/` itself.
/// 3. Every entry exists here and is a directory -- checked now, so a typo
///    is refused instead of loading as a root nothing can be under.
/// 4. No tool on the toolkit is left with a `must_resolve_under` outside
///    the new list ([`tools_outside_roots`]); the error names them, since
///    the reload would otherwise quietly disable them.
fn check_path_roots(name: &str, value: &Value, executor: Option<&str>, tools_path: &str) -> ConfigResult<Vec<String>> {
    let where_ = format!("toolkit {}", repr_str(name));
    if let Some(executor) = executor.filter(|e| REMOTE_PATH_EXECUTORS.contains(e)) {
        return Err(proposal_refused(format!(
            "Cannot propose path_roots for {where_}: its executor {} reads them on the remote host, \
             which this container cannot check. Edit toolkits.yaml and reload (SIGHUP or restart).",
            repr_str(executor)
        )));
    }
    let Value::Array(items) = value else {
        return Err(proposal_refused(format!(
            "Cannot propose path_roots={} for {where_}: it must be a list of absolute directory paths.",
            repr_value(value)
        )));
    };
    let mut roots = Vec::new();
    for item in items {
        let Value::String(root) = item else {
            return Err(proposal_refused(format!(
                "Cannot propose path_roots for {where_}: entry {} is not a string.",
                repr_value(item)
            )));
        };
        let refuse = |why: &str| proposal_refused(format!("Cannot propose path_roots for {where_}: {} {why}", repr_str(root)));
        if !root.starts_with('/') {
            return Err(refuse("is not an absolute path."));
        }
        let parts: Vec<&str> = root.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
        if parts.contains(&"..") {
            return Err(refuse("contains '..'."));
        }
        if parts.is_empty() {
            return Err(refuse("is the filesystem root, which would put every path in reach."));
        }
        match std::fs::metadata(root) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(refuse("is not a directory in this container.")),
            Err(_) => return Err(refuse("does not exist in this container.")),
        }
        roots.push(root.clone());
    }
    let blocked = tools_outside_roots(tools_path, name, &roots)?;
    if !blocked.is_empty() {
        return Err(proposal_refused(format!(
            "Cannot change path_roots of {where_} to {}: {} tool(s) would lie outside them: {}. Change or \
             delete those tools first, or keep their roots in the list.",
            repr_list(&roots),
            blocked.len(),
            blocked.join(", ")
        )));
    }
    Ok(roots)
}

#[cfg(test)]
thread_local! {
    /// Tests pin `resolve_addresses` per thread (Python monkeypatches it).
    pub(crate) static TEST_DNS: std::cell::RefCell<Option<std::collections::HashMap<String, Vec<IpAddr>>>> =
        const { std::cell::RefCell::new(None) };
}

/// `ipaddress.ip_address(text)`: an IPv4 or IPv6 literal, an IPv6 scope id
/// accepted (and dropped).
fn ip_address(text: &str) -> Option<IpAddr> {
    if let Ok(v4) = text.parse::<std::net::Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    let bare = text.split_once('%').map(|(a, _)| a).unwrap_or(text);
    bare.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
}

/// Every address `host` resolves to right now; empty when it does not
/// resolve.
fn resolve_addresses(host: &str) -> Vec<IpAddr> {
    #[cfg(test)]
    if let Some(answer) = TEST_DNS.with(|t| t.borrow().as_ref().map(|m| m.get(host).cloned().unwrap_or_default())) {
        return answer;
    }
    if let Some(literal) = ip_address(host.trim_matches(|c| c == '[' || c == ']')) {
        return vec![literal];
    }
    // PORT NOTE: Python let a UnicodeError from the idna codec escape; a
    // name that cannot be encoded resolves to nothing here.
    match crate::execute::http::getaddrinfo_sync(host, 0) {
        Ok(infos) => infos.iter().filter_map(|info| ip_address(&info.raw)).collect(),
        Err(_) => Vec::new(),
    }
}

/// A network counts as public when both its ends are public addresses.
fn network_is_public(network: &IpNet) -> bool {
    is_public_address(network.network()) && is_public_address(network.broadcast())
}

/// The two rules a proposed `allowed_cidrs` must meet, beyond shape:
///
/// 1. No network wider than `BROAD_PREFIX_*` without `confirm_broad_cidrs`.
/// 2. No private, loopback, link-local or otherwise non-public network on
///    a toolkit whose target is external -- a `base_url` (or destination)
///    whose host is, or right now resolves to, a public address. A host
///    that does not resolve at all is not judged here.
///
/// Applied to proposals only (create and update), at submit and again at
/// deploy. `load_tier1` does not run it, so toolkits written by hand load
/// unchanged.
fn check_network_policy(
    body: &Map<String, Value>,
    confirm_broad: bool,
    where_: &str,
    destination_urls: &[String],
) -> ConfigResult<()> {
    let cidrs = match body.get("allowed_cidrs") {
        Some(v) if py_truthy(v) => v,
        _ => return Ok(()),
    };
    let Value::Array(cidrs) = cidrs else {
        return Ok(()); // load_tier1 reports the shape
    };
    let mut networks = Vec::new();
    for raw in cidrs {
        match ip_network(&str_value(raw)) {
            Ok(n) => networks.push(n),
            Err(_) => return Ok(()), // load_tier1 reports the bad entry
        }
    }
    let broad: Vec<String> = networks
        .iter()
        .filter(|n| match n {
            IpNet::V4(n) => n.prefix_len() < BROAD_PREFIX_V4,
            IpNet::V6(n) => n.prefix_len() < BROAD_PREFIX_V6,
        })
        .map(ToString::to_string)
        .collect();
    if !broad.is_empty() && !confirm_broad {
        return Err(proposal_refused(format!(
            "{where_}: allowed_cidrs {} are wider than /16 (IPv4) or \
             /48 (IPv6). Narrow them to the service's own range, or propose \
             again with confirm_broad_cidrs: true if this width is intended \
             -- the reviewer then sees it flagged.",
            repr_list(&broad)
        )));
    }
    let private: Vec<String> =
        networks.iter().filter(|n| !network_is_public(n)).map(ToString::to_string).collect();
    if private.is_empty() {
        return Ok(());
    }
    let mut urls: Vec<&str> = Vec::new();
    if let Some(Value::String(u)) = body.get("base_url") {
        urls.push(u);
    }
    urls.extend(destination_urls.iter().map(String::as_str));
    for url in urls {
        let host = url_hostname(url);
        if host.is_empty() {
            continue;
        }
        let addresses = resolve_addresses(&host);
        if !addresses.is_empty() && addresses.iter().all(|a| is_public_address(*a)) {
            return Err(proposal_refused(format!(
                "{where_}: allowed_cidrs {} are private or otherwise \
                 non-public networks, but this toolkit's target {} is \
                 a public address. A private range is only for a LAN \
                 service; for a public one, list its public range or use \
                 allowed_hosts.",
                repr_list(&private),
                repr_str(&host)
            )));
        }
    }
    Ok(())
}

/// The base_urls of the destinations `body` names, from toolkits.yaml.
fn destination_urls(body: &Map<String, Value>, raw: &Value) -> Vec<String> {
    let names = match body.get("destinations") {
        Some(v) if py_truthy(v) => v,
        _ => return Vec::new(),
    };
    let (Value::Array(names), Some(Value::Object(section))) = (names, raw.get("destinations")) else {
        return Vec::new();
    };
    names
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|dest| match section.get(dest) {
            Some(Value::Object(spec)) => spec.get("base_url").and_then(Value::as_str).map(str::to_string),
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolkitProposal {
    pub id: String,
    /// The toolkit's name -- its key under `toolkits:`.
    pub name: String,
    /// `create`: the full body. `update`: just the changed fields. `bind`:
    /// `{"credential": <name>}`. `delete`: empty.
    pub spec: Map<String, Value>,
    pub actor: String,
    pub kind: String,
    pub status: String,
    pub created_at: String,
    pub decided_by: Option<String>,
    pub decided_at: Option<String>,
    pub reason: Option<String>,
    /// The proposer's explicit "yes, this wide" for a CIDR broader than
    /// `BROAD_PREFIX_*` (see `check_network_policy`). Not part of `spec`:
    /// it is said about the proposal, never written to toolkits.yaml.
    pub confirm_broad_cidrs: bool,
}

fn opt(v: &Option<String>) -> Value {
    v.as_ref().map(|s| Value::String(s.clone())).unwrap_or(Value::Null)
}

impl ToolkitProposal {
    pub fn to_spec(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "spec": Value::Object(self.spec.clone()),
            "actor": self.actor,
            "kind": self.kind,
            "status": self.status,
            "created_at": self.created_at,
            "decided_by": opt(&self.decided_by),
            "decided_at": opt(&self.decided_at),
            "reason": opt(&self.reason),
            "confirm_broad_cidrs": self.confirm_broad_cidrs,
        })
    }
}

/// `str(spec.get(k) or default)`.
fn str_or(spec: &Map<String, Value>, key: &str, default: &str) -> String {
    match spec.get(key) {
        Some(v) if py_truthy(v) => str_value(v),
        _ => default.to_string(),
    }
}

fn opt_str(spec: &Map<String, Value>, key: &str) -> Option<String> {
    match spec.get(key) {
        None | Some(Value::Null) => None,
        Some(v) => Some(str_value(v)),
    }
}

fn from_spec(spec: &Map<String, Value>) -> ToolkitProposal {
    let s = |k: &str| str_value(spec.get(k).unwrap_or(&Value::Null));
    ToolkitProposal {
        id: s("id"),
        name: s("name"),
        spec: match spec.get("spec") {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        },
        actor: s("actor"),
        kind: str_or(spec, "kind", "create"),
        status: str_or(spec, "status", "pending"),
        created_at: str_or(spec, "created_at", ""),
        decided_by: opt_str(spec, "decided_by"),
        decided_at: opt_str(spec, "decided_at"),
        reason: opt_str(spec, "reason"),
        confirm_broad_cidrs: spec.get("confirm_broad_cidrs").is_some_and(py_truthy),
    }
}

fn id_of(e: &Map<String, Value>) -> Option<&str> {
    e.get("id").and_then(Value::as_str)
}

/// Owns `toolkit_proposals.yaml` and is the only writer of the real
/// `toolkits.yaml` outside of a redeploy.
pub struct ToolkitProposalStore {
    pub path: String,
    pub audit: Arc<AuditLog>,
    pub service: Arc<Service>,
    pub toolkits_path: String,
    pub tools_path: String,
    pub identities_path: String,
    lock: Mutex<()>,
}

impl std::fmt::Debug for ToolkitProposalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolkitProposalStore").field("path", &self.path).finish()
    }
}

impl ToolkitProposalStore {
    pub fn new(
        path: &str,
        audit: Arc<AuditLog>,
        service: Arc<Service>,
        toolkits_path: &str,
        tools_path: &str,
        identities_path: &str,
    ) -> ToolkitProposalStore {
        ToolkitProposalStore {
            path: path.to_string(),
            audit,
            service,
            toolkits_path: toolkits_path.to_string(),
            tools_path: tools_path.to_string(),
            identities_path: identities_path.to_string(),
            lock: Mutex::new(()),
        }
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn audit_write(&self, event: Value) -> ConfigResult<()> {
        // PORT NOTE: Python let the OSError of a failed audit write escape.
        self.audit.write(event).map_err(|e| ConfigError::new(format!("The audit log could not be written: {e}")))
    }

    pub fn revision(&self) -> String {
        revision(&self.path)
    }

    fn load(&self) -> ConfigResult<Vec<Map<String, Value>>> {
        let raw = load_cached(&self.path)?.filter(py_truthy).unwrap_or_else(|| Value::Object(Map::new()));
        let entries = match raw.get("proposals") {
            None | Some(Value::Null) => return Ok(Vec::new()),
            Some(Value::Array(a)) => a.clone(),
            Some(_) => {
                return Err(ConfigError::new(
                    "toolkit_proposals.yaml: section 'proposals' is missing or not a list",
                ))
            }
        };
        Ok(entries.into_iter().filter_map(|e| if let Value::Object(m) = e { Some(m) } else { None }).collect())
    }

    fn write(&self, entries: &[Map<String, Value>]) -> ConfigResult<()> {
        let list: Vec<Value> = entries.iter().cloned().map(Value::Object).collect();
        atomic_write_cfg(&self.path, &dump(&json!({ "proposals": list })))
    }

    // -- Reads ---------------------------------------------------------------

    /// Every proposal, oldest first; `status` filters.
    pub fn list(&self, status: Option<&str>) -> ConfigResult<Vec<ToolkitProposal>> {
        let mut items: Vec<ToolkitProposal> = self.load()?.iter().map(from_spec).collect();
        items.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        if let Some(status) = status.filter(|s| !s.is_empty()) {
            items.retain(|i| i.status == status);
        }
        Ok(items)
    }

    pub fn get(&self, proposal_id: &str) -> ConfigResult<Option<ToolkitProposal>> {
        Ok(self.load()?.iter().find(|e| id_of(e) == Some(proposal_id)).map(from_spec))
    }

    // -- Writes --------------------------------------------------------------

    pub fn propose(
        &self,
        name: &str,
        spec: Map<String, Value>,
        actor: &str,
        kind: &str,
    ) -> ConfigResult<ToolkitProposal> {
        self.propose_with(name, spec, actor, kind, false)
    }

    /// `propose(..., confirm_broad_cidrs=...)`.
    pub fn propose_with(
        &self,
        name: &str,
        spec: Map<String, Value>,
        actor: &str,
        kind: &str,
        confirm_broad_cidrs: bool,
    ) -> ConfigResult<ToolkitProposal> {
        if name.is_empty() {
            return Err(proposal_refused("A toolkit proposal needs a non-empty 'name'."));
        }
        if !KINDS.contains(&kind) {
            return Err(proposal_refused(format!("Unknown proposal kind {}.", repr_str(kind))));
        }
        if kind == "update" {
            if spec.is_empty() {
                return Err(proposal_refused("An update proposal needs at least one changed field."));
            }
            let illegal: Vec<&str> =
                spec.keys().map(String::as_str).filter(|k| !UPDATE_WRITABLE_FIELDS.contains(k)).collect();
            if !illegal.is_empty() {
                return Err(proposal_refused(format!(
                    "Cannot propose changing {} -- only {} are writable via an \
                     update proposal. protected_resources has no proposal \
                     path -- edit toolkits.yaml and reload (SIGHUP or \
                     restart).",
                    sorted_repr(illegal),
                    writable_fields_repr()
                )));
            }
            // PORT NOTE: Python iterated `LIMIT_FIELDS & set(spec)` in set
            // order; sorted here, which only decides which field is named
            // when both are invalid.
            for field in LIMIT_FIELDS {
                let Some(value) = spec.get(field) else { continue };
                let positive = match value {
                    Value::Number(n) => n.as_u64().is_some_and(|v| v > 0) || n.as_i64().is_some_and(|v| v > 0),
                    _ => false,
                };
                if !positive {
                    return Err(proposal_refused(format!(
                        "Cannot propose {field}={}: it must be a positive integer.",
                        repr_value(value)
                    )));
                }
            }
        }
        if let Some(run_as) = spec.get("run_as").filter(|v| !v.is_null()) {
            // Shape only, for immediate feedback; deploy() is the gate.
            if let Err(exc) = parse_run_as(&str_value(run_as)) {
                return Err(proposal_refused(format!("Cannot propose this 'run_as': {exc}")));
            }
        }
        // PORT NOTE: Python iterated `NETWORK_FIELDS & set(spec)`, a set
        // whose order depends on the hash seed; the port checks the two
        // fields in sorted order, which only decides which error is named
        // when both are malformed.
        for field in NETWORK_FIELDS {
            // Shape only, for immediate feedback, exactly like `run_as`
            // above -- a wildcard or an IP literal in allowed_hosts is
            // refused now instead of failing at review. `deploy()`'s full
            // `load_tier1` stays the authoritative gate.
            let Some(value) = spec.get(field).filter(|v| !v.is_null()) else { continue };
            let other = if field == "allowed_hosts" { "allowed_cidrs" } else { "allowed_hosts" };
            let mut probe = Map::new();
            probe.insert(field.to_string(), value.clone());
            probe.insert(other.to_string(), Value::Null);
            if let Err(exc) = parse_network_allowlist(&probe, &format!("toolkit {}", repr_str(name))) {
                return Err(proposal_refused(format!(
                    "Cannot propose this {}: {}",
                    repr_str(field),
                    exc.message
                )));
            }
        }
        if (kind == "create" || kind == "update") && spec.contains_key("allowed_cidrs") {
            let live = self.live_raw()?;
            let mut body = Map::new();
            if kind == "update" {
                if let Some(Value::Object(existing)) = live.get("toolkits").and_then(|t| t.get(name)) {
                    body = existing.clone();
                }
            }
            for (k, v) in &spec {
                body.insert(k.clone(), v.clone());
            }
            check_network_policy(
                &body,
                confirm_broad_cidrs,
                &format!("toolkit {}", repr_str(name)),
                &destination_urls(&body, &live),
            )?;
        }
        if kind == "update" {
            if let Some(value) = spec.get("path_roots") {
                let live = self.live_raw()?;
                let existing = live.get("toolkits").and_then(|t| t.get(name));
                let executor = spec
                    .get("executor")
                    .or_else(|| existing.and_then(|e| e.get("executor")))
                    .and_then(Value::as_str);
                check_path_roots(name, value, executor, &self.tools_path)?;
            }
        }
        if kind == "delete" && !spec.is_empty() {
            return Err(proposal_refused(
                "A delete proposal takes no 'spec' -- there is nothing to \
                 change, only a toolkit to remove.",
            ));
        }
        if kind == "bind" {
            let extra: Vec<&str> = spec.keys().map(String::as_str).filter(|k| *k != BIND_FIELD).collect();
            if !extra.is_empty() || !spec.contains_key(BIND_FIELD) {
                return Err(proposal_refused(format!(
                    "A bind proposal carries exactly {{'{BIND_FIELD}': <name>}} and nothing else{}",
                    if extra.is_empty() { ".".to_string() } else { format!(" -- got {} as well.", sorted_repr(extra)) }
                )));
            }
            match spec.get(BIND_FIELD) {
                Some(Value::String(c)) if !c.is_empty() => {}
                _ => {
                    return Err(proposal_refused(format!(
                        "A bind proposal's '{BIND_FIELD}' must be a non-empty credential name."
                    )))
                }
            }
        }
        let _guard = self.guard();
        let mut entries = self.load()?;
        if kind == "create" {
            if self.live_toolkit_names()?.contains(name) {
                return Err(proposal_refused(name_collision_message(name)));
            }
            let queued = entries.iter().find(|e| {
                e.get("name").and_then(Value::as_str) == Some(name)
                    && str_or(e, "kind", "create") == "create"
                    && e.get("status").and_then(Value::as_str) == Some("pending")
            });
            if let Some(queued) = queued {
                return Err(proposal_refused(format!(
                    "A 'create' proposal for toolkit {} is already pending ({}). Only one of the two \
                     could ever deploy. Withdraw it first with admin.proposal_withdraw if this one \
                     replaces it.",
                    repr_str(name),
                    crate::pyfmt::str_value(queued.get("id").unwrap_or(&Value::Null))
                )));
            }
        }
        let item = ToolkitProposal {
            id: crate::identity::token_urlsafe(12),
            name: name.to_string(),
            spec: spec.clone(),
            actor: actor.to_string(),
            kind: kind.to_string(),
            status: "pending".into(),
            created_at: now_iso(),
            decided_by: None,
            decided_at: None,
            reason: None,
            confirm_broad_cidrs,
        };
        if let Value::Object(m) = item.to_spec() {
            entries.push(m);
        }
        self.write(&entries)?;
        let mut event = json!({
            "kind": "admin_change",
            "actor": actor,
            "action": propose_action_name(kind),
            "target": name,
            "spec": Value::Object(spec),
        });
        if confirm_broad_cidrs {
            event["confirm_broad_cidrs"] = json!(true);
        }
        self.audit_write(event)?;
        Ok(item)
    }

    /// toolkits.yaml as a mapping (empty when missing or not a mapping).
    fn live_raw(&self) -> ConfigResult<Value> {
        if !std::path::Path::new(&self.toolkits_path).exists() {
            return Ok(Value::Object(Map::new()));
        }
        let raw = read_yaml_file(&self.toolkits_path)?;
        Ok(if raw.is_object() { raw } else { Value::Object(Map::new()) })
    }

    /// Toolkit names in toolkits.yaml as `deploy()` will see them (the
    /// file, not the running Tier 1).
    fn live_toolkit_names(&self) -> ConfigResult<BTreeSet<String>> {
        if !std::path::Path::new(&self.toolkits_path).exists() {
            return Ok(BTreeSet::new());
        }
        let raw = read_yaml_file(&self.toolkits_path)?;
        Ok(match raw.get("toolkits") {
            Some(Value::Object(m)) => m.keys().cloned().collect(),
            _ => BTreeSet::new(),
        })
    }

    fn find<'a>(
        entries: &'a mut [Map<String, Value>],
        proposal_id: &str,
    ) -> ConfigResult<&'a mut Map<String, Value>> {
        entries
            .iter_mut()
            .find(|e| id_of(e) == Some(proposal_id))
            .ok_or_else(|| proposal_refused(format!("No toolkit proposal {}.", repr_str(proposal_id))))
    }

    fn status_repr(entry: &Map<String, Value>) -> String {
        repr_value(entry.get("status").unwrap_or(&Value::Null))
    }

    /// The proposer takes its own still-pending proposal back. Not a
    /// decision; only the identity that filed it may withdraw it.
    pub fn withdraw(&self, proposal_id: &str, actor: &str) -> ConfigResult<ToolkitProposal> {
        let _guard = self.guard();
        let mut entries = self.load()?;
        let matched = Self::find(&mut entries, proposal_id)?;
        if matched.get("actor").and_then(Value::as_str) != Some(actor) {
            return Err(proposal_refused(format!(
                "Toolkit proposal {} was filed by {}; only the proposer can withdraw it. A human \
                 can reject it at /app/requests (Toolkit tab).",
                repr_str(proposal_id),
                repr_value(matched.get("actor").unwrap_or(&Value::Null))
            )));
        }
        if matched.get("status").and_then(Value::as_str) != Some("pending") {
            return Err(proposal_refused(format!(
                "Toolkit proposal {} is already {}.",
                repr_str(proposal_id),
                Self::status_repr(matched)
            )));
        }
        matched.insert("status".into(), json!("withdrawn"));
        matched.insert("decided_by".into(), json!(actor));
        matched.insert("decided_at".into(), json!(now_iso()));
        let item = from_spec(matched);
        let target = matched.get("name").cloned().unwrap_or(Value::Null);
        self.write(&entries)?;
        self.audit_write(json!({
            "kind": "admin_change",
            "actor": actor,
            "action": "toolkit_withdraw",
            "target": target,
            "proposal_id": proposal_id,
        }))?;
        Ok(item)
    }

    pub fn reject(&self, proposal_id: &str, decided_by: &str, reason: &str) -> ConfigResult<ToolkitProposal> {
        let _guard = self.guard();
        let mut entries = self.load()?;
        let matched = Self::find(&mut entries, proposal_id)?;
        if matched.get("status").and_then(Value::as_str) != Some("pending") {
            return Err(proposal_refused(format!(
                "Toolkit proposal {} is already {}.",
                repr_str(proposal_id),
                Self::status_repr(matched)
            )));
        }
        matched.insert("status".into(), json!("rejected"));
        matched.insert("decided_by".into(), json!(decided_by));
        matched.insert("decided_at".into(), json!(now_iso()));
        matched.insert("reason".into(), json!(reason));
        let item = from_spec(matched);
        let target = matched.get("name").cloned().unwrap_or(Value::Null);
        let original_actor = matched.get("actor").cloned().unwrap_or(Value::Null);
        self.write(&entries)?;
        self.audit_write(json!({
            "kind": "admin_change",
            "actor": decided_by,
            "action": "toolkit_reject",
            "target": target,
            "proposal_id": proposal_id,
            "original_actor": original_actor,
            "reason": reason,
        }))?;
        Ok(item)
    }

    /// Approves and deploys one proposal. Refuses (nothing real touched) on
    /// a collision or a Tier 1 validation failure, and again -- with
    /// `toolkits.yaml` already written but the proposal left `pending` --
    /// if `reload_config` itself errors.
    pub fn deploy(&self, proposal_id: &str, decided_by: &str) -> ConfigResult<ToolkitProposal> {
        let _guard = self.guard();
        let mut entries = self.load()?;
        let index = entries
            .iter()
            .position(|e| id_of(e) == Some(proposal_id))
            .ok_or_else(|| proposal_refused(format!("No toolkit proposal {}.", repr_str(proposal_id))))?;
        if entries[index].get("status").and_then(Value::as_str) != Some("pending") {
            return Err(proposal_refused(format!(
                "Toolkit proposal {} is already {}.",
                repr_str(proposal_id),
                Self::status_repr(&entries[index])
            )));
        }
        let item = from_spec(&entries[index]);

        if !std::path::Path::new(&self.toolkits_path).exists() {
            return Err(proposal_refused(format!("{} not found.", self.toolkits_path)));
        }
        if !writable(&self.toolkits_path) {
            return Err(proposal_refused(format!(
                "{} is not writable. The file or its directory is mounted read-only.",
                crate::pathutil::basename(&self.toolkits_path)
            )));
        }
        let raw = read_yaml_file(&self.toolkits_path)?;
        let raw_value = raw.clone();
        let Value::Object(raw) = raw else {
            // PORT NOTE: Python raised AttributeError on a non-mapping file.
            return Err(proposal_refused("toolkits.yaml: section 'toolkits' is not a mapping."));
        };
        let toolkit_section = match raw.get("toolkits") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => return Err(proposal_refused("toolkits.yaml: section 'toolkits' is not a mapping.")),
        };

        let missing = |tail: &str| {
            proposal_refused(format!(
                "No toolkit named {} exists in toolkits.yaml -- {tail}",
                repr_str(&item.name)
            ))
        };
        let moved = "it may have been renamed or removed by a redeploy since this proposal was made. \
                     Reject this proposal.";

        let mut merged_toolkits = toolkit_section.clone();
        let mut before_fields: Option<Map<String, Value>> = None;
        match item.kind.as_str() {
            "update" => {
                let Some(Value::Object(existing)) = toolkit_section.get(&item.name) else {
                    return Err(missing(moved));
                };
                let illegal: Vec<&str> =
                    item.spec.keys().map(String::as_str).filter(|k| !UPDATE_WRITABLE_FIELDS.contains(k)).collect();
                if !illegal.is_empty() {
                    // Defense in depth: deploy() re-checks its own input.
                    return Err(proposal_refused(format!(
                        "Cannot change {} at runtime -- only {} are writable via an update proposal.",
                        sorted_repr(illegal),
                        writable_fields_repr()
                    )));
                }
                before_fields = Some(
                    item.spec
                        .keys()
                        .map(|k| (k.clone(), existing.get(k).cloned().unwrap_or(Value::Null)))
                        .collect(),
                );
                let mut body = existing.clone();
                for (k, v) in &item.spec {
                    body.insert(k.clone(), v.clone());
                }
                let network: Vec<&str> =
                    NETWORK_FIELDS.iter().copied().filter(|f| item.spec.contains_key(*f)).collect();
                let executor = body.get("executor").cloned().unwrap_or(Value::Null);
                for (field, readers) in FIELD_EXECUTORS {
                    if !item.spec.contains_key(field) {
                        continue;
                    }
                    let reads = matches!(&executor, Value::String(e) if readers.contains(&e.as_str()));
                    if !reads {
                        let mut sorted_readers = readers.to_vec();
                        sorted_readers.sort_unstable();
                        return Err(proposal_refused(format!(
                            "Cannot change {} on toolkit {}: its executor {} does not use it. Only \
                             an {} toolkit has {field}.{}",
                            repr_str(field),
                            repr_str(&item.name),
                            repr_value(&executor),
                            sorted_readers.join(" or "),
                            if NETWORK_FIELDS.contains(&field) { " (It does not connect to a URL.)" } else { "" }
                        )));
                    }
                }
                if item.spec.contains_key("allowed_cidrs") {
                    check_network_policy(
                        &body,
                        item.confirm_broad_cidrs,
                        &format!("toolkit {}", repr_str(&item.name)),
                        &destination_urls(&body, &raw_value),
                    )?;
                }
                if let Some(value) = item.spec.get("path_roots") {
                    // Again, against the disk and tools.yaml as they are now:
                    // a directory may be gone, a tool added since submit.
                    check_path_roots(&item.name, value, executor.as_str(), &self.tools_path)?;
                }
                // A null network field removes the key, so the remaining
                // one alone decides -- load_tier1 then refuses the toolkit
                // if that leaves it with neither.
                for field in &network {
                    if body.get(*field).is_none_or(Value::is_null) {
                        body.shift_remove(*field);
                    }
                }
                merged_toolkits.insert(item.name.clone(), Value::Object(body));
            }
            "bind" => {
                let Some(Value::Object(existing)) = toolkit_section.get(&item.name) else {
                    return Err(missing(moved));
                };
                let extra: Vec<&str> = item.spec.keys().map(String::as_str).filter(|k| *k != BIND_FIELD).collect();
                if !extra.is_empty() || !item.spec.contains_key(BIND_FIELD) {
                    return Err(proposal_refused(format!(
                        "A bind proposal may only set '{BIND_FIELD}'{}",
                        if extra.is_empty() {
                            ".".to_string()
                        } else {
                            format!(" -- this one also carries {}.", sorted_repr(extra))
                        }
                    )));
                }
                let mut before = Map::new();
                before.insert(BIND_FIELD.into(), existing.get(BIND_FIELD).cloned().unwrap_or(Value::Null));
                before_fields = Some(before);
                let mut body = existing.clone();
                body.insert(BIND_FIELD.into(), item.spec[BIND_FIELD].clone());
                merged_toolkits.insert(item.name.clone(), Value::Object(body));
            }
            "delete" => {
                let Some(Value::Object(existing)) = toolkit_section.get(&item.name) else {
                    return Err(missing("it may already have been removed. Reject this proposal."));
                };
                let referencing = tools_referencing_toolkit(&self.tools_path, &item.name)?;
                if !referencing.is_empty() {
                    let list: Vec<&str> = referencing.iter().map(String::as_str).collect();
                    return Err(proposal_refused(format!(
                        "Toolkit {} is still referenced by {} tool(s): {}. Delete or reassign those tools first.",
                        repr_str(&item.name),
                        referencing.len(),
                        repr_list(&list)
                    )));
                }
                let mut before = Map::new();
                before.insert(item.name.clone(), Value::Object(existing.clone()));
                before_fields = Some(before);
                merged_toolkits.shift_remove(&item.name);
            }
            _ => {
                if toolkit_section.contains_key(&item.name) {
                    // A redeploy added the name while the proposal waited.
                    return Err(proposal_refused(format!(
                        "{} Reject this proposal.",
                        name_collision_message(&item.name)
                    )));
                }
                if item.spec.contains_key("allowed_cidrs") {
                    check_network_policy(
                        &item.spec,
                        item.confirm_broad_cidrs,
                        &format!("toolkit {}", repr_str(&item.name)),
                        &destination_urls(&item.spec, &raw_value),
                    )?;
                }
                merged_toolkits.insert(item.name.clone(), Value::Object(item.spec.clone()));
            }
        }

        let mut merged = raw.clone();
        merged.insert("toolkits".into(), Value::Object(merged_toolkits.clone()));
        let merged_text = dump(&Value::Object(merged));

        // Validate the merged configuration exactly as startup would,
        // before anything real is touched.
        let abs = crate::pathutil::abspath(&self.toolkits_path);
        let directory = {
            let d = crate::pathutil::dirname(&abs);
            if d.is_empty() { ".".to_string() } else { d }
        };
        let validated = {
            use std::io::Write as _;
            let mut tmp = tempfile::Builder::new()
                .prefix(".gk-toolkit-validate-")
                .suffix(".yaml")
                .tempfile_in(&directory)
                .map_err(|e| proposal_refused(format!("{directory}: {}", crate::pyfmt::os_error(&e, &directory))))?;
            tmp.write_all(merged_text.as_bytes())
                .and_then(|_| tmp.flush())
                .map_err(|e| proposal_refused(format!("{e}")))?;
            let path = tmp.path().to_string_lossy().into_owned();
            let result = load_tier1(&path);
            drop(tmp); // unlinks
            result.map_err(|exc| {
                proposal_refused(format!("Proposed toolkit {} is invalid: {exc}", repr_str(&item.name)))
            })?
        };

        if item.kind == "bind" {
            // Does the *reference* actually resolve? Read it back through
            // the same walk startup and the console use.
            let credential = str_value(&item.spec[BIND_FIELD]);
            let bound = validated.toolkits.get(&item.name);
            if bound.is_none_or(|b| b.credential.as_deref() != Some(credential.as_str())) {
                return Err(proposal_refused(format!(
                    "Binding {} to credential {} did not survive a Tier 1 reload -- toolkits.yaml was \
                     not touched. Reject this proposal.",
                    repr_str(&item.name),
                    repr_str(&credential)
                )));
            }
            let refs = validated.credential_references();
            if !refs.get(&credential).is_some_and(|names| names.contains(&item.name)) {
                return Err(proposal_refused(format!(
                    "Toolkit {} does not appear among the references to credential {} after \
                     validation -- toolkits.yaml was not touched. Reject this proposal.",
                    repr_str(&item.name),
                    repr_str(&credential)
                )));
            }
        }

        let mut before_names: Vec<String> = toolkit_section.keys().cloned().collect();
        before_names.sort();
        atomic_write_cfg(&self.toolkits_path, &merged_text)?;

        if let Some(error) =
            self.service.reload_config(&self.toolkits_path, &self.tools_path, &self.identities_path)
        {
            // Defensive only. Left `pending` so a human sees this failed.
            return Err(proposal_refused(format!(
                "toolkits.yaml was written, but reloading it into this running process failed: \
                 {error}. A SIGHUP or restart should pick it up; investigate before re-deploying."
            )));
        }

        let matched = &mut entries[index];
        matched.insert("status".into(), json!("deployed"));
        matched.insert("decided_by".into(), json!(decided_by));
        matched.insert("decided_at".into(), json!(now_iso()));
        let deployed = from_spec(matched);
        self.write(&entries)?;
        let mut after_names: Vec<String> = merged_toolkits.keys().cloned().collect();
        after_names.sort();
        let mut record = Map::new();
        record.insert("kind".into(), json!("admin_change"));
        record.insert("actor".into(), json!(decided_by));
        record.insert("action".into(), json!(deploy_action_name(&item.kind)));
        record.insert("target".into(), json!(item.name));
        record.insert("proposal_id".into(), json!(proposal_id));
        record.insert("original_actor".into(), json!(item.actor));
        record.insert("before_toolkits".into(), json!(before_names));
        record.insert("after_toolkits".into(), json!(after_names));
        if let Some(before_fields) = before_fields {
            record.insert("before_fields".into(), Value::Object(before_fields));
            record.insert("after_fields".into(), Value::Object(item.spec.clone()));
        }
        self.audit_write(Value::Object(record))?;
        Ok(deployed)
    }
}

#[cfg(test)]
#[path = "toolkit_update_fields_tests.rs"]
mod toolkit_update_fields_tests;
