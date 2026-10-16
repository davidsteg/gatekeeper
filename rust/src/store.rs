//! Write access to Tier 2 (port of `store.py`, REQUIREMENTS.md §7).
//!
//! Here -- and only here -- does gatekeeper modify its own configuration.
//! Five guarantees underpin this layer:
//!
//! 1. **Tier 1 remains untouchable.** There is no function here that
//!    writes `toolkits.yaml` (FR-4.11).
//! 2. **Only one validation path.** Every definition runs through
//!    `parse_tool_spec` -- the same function that checks at startup.
//! 3. **Atomic.** Sibling temp file, fsync, rename.
//! 4. **What holds is on disk.** After every write the file is reloaded
//!    and the running state swapped out.
//! 5. **No silent overwriting.** Every form carries the revision of the
//!    file it was built from; a concurrent write refuses the request.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

pub use crate::atomic::{revision, writable};
use crate::atomic::{atomic_write_cfg, dump};
use crate::audit::AuditLog;
use crate::catalog::{append_tool_version, load_catalog, new_tool_entry, now_iso, parse_tool_spec, soft_delete_entry};
use crate::errors::{ConfigError, ConfigResult};
use crate::identity::{
    dump_identities, generate_token, hash_token, hash_token_lookup, load_identities, verify_token, Identity,
    ADMIN_ROLE, MIN_PASSWORD_LENGTH, ROLES, UI_ROLES,
};
pub use crate::identity::to_spec;
use crate::pyfmt::repr_str;
use crate::service::{Service, SharedIdentities};

/// `WriteRefused`: a write attempt was refused, with a human-readable
/// reason.
pub fn write_refused(message: impl Into<String>) -> ConfigError {
    ConfigError::refused(message)
}

/// Deterministic sha256 fingerprint of one record, truncated to 16 hex
/// chars like `atomic::revision`'s whole-file hash. `None` (the record
/// does not exist) fingerprints as "".
///
/// `json.dumps(record, sort_keys=True, default=str)`: every value here is
/// already JSON-shaped (the YAML loader keeps timestamps as strings), so
/// `default=str` never applies.
pub fn fingerprint(record: Option<&Value>) -> String {
    match record {
        None => String::new(),
        Some(record) => {
            let encoded = crate::pyjson::dumps_with(record, &crate::pyjson::Opts::python().sorted());
            crate::atomic::sha256_hex(encoded.as_bytes())[..16].to_string()
        }
    }
}

fn basename(path: &str) -> &str {
    crate::pathutil::basename(path)
}

/// Python's `str.isalnum()` on the id with `-`/`_` removed.
fn valid_identity_id(identity_id: &str) -> bool {
    let stripped: String = identity_id.chars().filter(|c| *c != '-' && *c != '_').collect();
    !identity_id.is_empty() && !stripped.is_empty() && stripped.chars().all(char::is_alphanumeric)
}

fn audit_write(audit: &AuditLog, event: Value) -> ConfigResult<()> {
    // PORT NOTE: Python let the OSError of a failed audit write escape;
    // it is a ConfigError with the same effect here.
    audit.write(event).map_err(|e| ConfigError::new(format!("The audit log could not be written: {e}")))
}

/// Owns the Tier 2 files and the runtime state derived from them.
pub struct ConfigStore {
    pub service: Arc<Service>,
    /// The live identity store -- the same handle the auth layer reads.
    pub identities: SharedIdentities,
    pub audit: Arc<AuditLog>,
    pub tools_path: String,
    pub identities_path: String,
    lock: Mutex<()>,
}

impl std::fmt::Debug for ConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigStore")
            .field("tools_path", &self.tools_path)
            .field("identities_path", &self.identities_path)
            .finish()
    }
}

impl ConfigStore {
    pub fn new(
        service: Arc<Service>,
        identities: SharedIdentities,
        audit: Arc<AuditLog>,
        tools_path: &str,
        identities_path: &str,
    ) -> ConfigStore {
        ConfigStore {
            service,
            identities,
            audit,
            tools_path: tools_path.to_string(),
            identities_path: identities_path.to_string(),
            lock: Mutex::new(()),
        }
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    // -- State ---------------------------------------------------------------

    pub fn tools_revision(&self) -> String {
        revision(&self.tools_path)
    }

    pub fn identities_revision(&self) -> String {
        revision(&self.identities_path)
    }

    /// Fingerprint of a single tool's raw entry -- unaffected by any other
    /// entry changing. Gates pending-proposal staleness only.
    pub fn tool_revision(&self, tool_id: &str) -> String {
        let catalog = self.service.catalog();
        let raw = catalog.raw_of(tool_id).map(|m| Value::Object(m.clone()));
        fingerprint(raw.as_ref())
    }

    /// Fingerprint of a single identity's spec.
    pub fn identity_revision(&self, identity_id: &str) -> String {
        let spec = self.identities.read().identities.get(identity_id).map(to_spec);
        fingerprint(spec.as_ref())
    }

    /// `{"tools": bool, "identities": bool}`.
    pub fn writability(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("tools".into(), json!(writable(&self.tools_path)));
        out.insert("identities".into(), json!(writable(&self.identities_path)));
        out
    }

    /// Optimistic concurrency.
    fn check(&self, path: &str, supplied: &str) -> ConfigResult<()> {
        if !writable(path) {
            return Err(write_refused(format!(
                "{} is not writable. The file or its directory is mounted read-only.",
                basename(path)
            )));
        }
        let current = revision(path);
        if !supplied.is_empty() && !current.is_empty() && supplied != current {
            return Err(write_refused(
                "The file changed since this form was opened. Reload the page \
                 and apply your edit again -- otherwise it would silently \
                 discard someone else's change.",
            ));
        }
        Ok(())
    }

    // -- Tools ---------------------------------------------------------------

    fn write_tools(&self, specs: Vec<Value>) -> ConfigResult<()> {
        atomic_write_cfg(&self.tools_path, &dump(&json!({ "tools": specs })))?;
        // Reload from the file, not from memory: only this proves that the
        // running state matches what a restart would produce.
        let catalog = load_catalog(&self.tools_path, &self.service.tier1(), false)?;
        self.service.set_catalog(catalog);
        // ...and tell the agents already connected.
        self.service.catalog_notifier.tool_catalog_changed();
        Ok(())
    }

    fn specs(&self) -> Vec<Value> {
        self.service.catalog().raw.clone()
    }

    /// Creates a definition or replaces it. Returns the tool ID.
    pub fn save_tool(
        &self,
        spec: &Map<String, Value>,
        actor: &str,
        rev: &str,
        replaces: Option<&str>,
    ) -> ConfigResult<String> {
        let _guard = self.guard();
        self.check(&self.tools_path, rev)?;

        // The same validation path as at startup.
        let tool = parse_tool_spec(&Value::Object(spec.clone()), &self.service.tier1())?;

        let mut specs = self.specs();
        let exists = specs.iter().any(|s| s.get("id").and_then(Value::as_str) == Some(tool.id.as_str()));
        if replaces.is_none() && exists {
            return Err(write_refused(format!("A tool with ID {} already exists.", repr_str(&tool.id))));
        }
        if let Some(replaces) = replaces {
            if tool.id != replaces && exists {
                return Err(write_refused(format!("A tool with ID {} already exists.", repr_str(&tool.id))));
            }
        }

        let now = now_iso();
        match replaces {
            None => specs.push(new_tool_entry(&tool.id, spec, actor, &now)),
            Some(replaces) => {
                let old_entry = specs.iter().find_map(|s| match s {
                    Value::Object(m) if m.get("id").and_then(Value::as_str) == Some(replaces) => Some(m.clone()),
                    _ => None,
                });
                let Some(old_entry) = old_entry else {
                    return Err(write_refused(format!("No tool with ID {}.", repr_str(replaces))));
                };
                let new_entry = append_tool_version(&old_entry, &tool.id, spec, actor, &now)?;
                specs = specs
                    .into_iter()
                    .map(|s| if s.get("id").and_then(Value::as_str) == Some(replaces) { new_entry.clone() } else { s })
                    .collect();
            }
        }

        self.write_tools(specs)?;
        let is_update = replaces.is_some_and(|r| !r.is_empty());
        let previous_id = match replaces {
            Some(r) if r != tool.id => Value::String(r.to_string()),
            _ => Value::Null,
        };
        audit_write(
            &self.audit,
            json!({
                "kind": "admin_change",
                "actor": actor,
                "action": if is_update { "tool_update" } else { "tool_create" },
                "target": tool.id,
                "previous_id": previous_id,
                "spec": Value::Object(spec.clone()),
            }),
        )?;
        if let Some(replaces) = replaces {
            if replaces != tool.id {
                self.orphan_warning(replaces)?;
            }
        }
        Ok(tool.id)
    }

    pub fn set_tool_enabled(&self, tool_id: &str, enabled: bool, actor: &str, rev: &str) -> ConfigResult<()> {
        let _guard = self.guard();
        self.check(&self.tools_path, rev)?;
        let mut specs = self.specs();
        if !specs.iter().any(|s| s.get("id").and_then(Value::as_str) == Some(tool_id)) {
            return Err(write_refused(format!("No tool with ID {}.", repr_str(tool_id))));
        }
        for spec in specs.iter_mut() {
            if spec.get("id").and_then(Value::as_str) == Some(tool_id) {
                if let Value::Object(m) = spec {
                    m.insert("enabled".into(), json!(enabled));
                }
            }
        }
        self.write_tools(specs)?;
        audit_write(
            &self.audit,
            json!({
                "kind": "admin_change",
                "actor": actor,
                "action": if enabled { "tool_enable" } else { "tool_disable" },
                "target": tool_id,
            }),
        )
    }

    /// Soft-deletes: the entry is marked `deleted: true` and excluded from
    /// the live catalog, but its version history stays on disk (FR-3.1).
    pub fn delete_tool(&self, tool_id: &str, actor: &str, rev: &str) -> ConfigResult<()> {
        let _guard = self.guard();
        self.check(&self.tools_path, rev)?;
        let specs = self.specs();
        let target = specs.iter().find_map(|s| match s {
            Value::Object(m) if m.get("id").and_then(Value::as_str) == Some(tool_id) => Some(m.clone()),
            _ => None,
        });
        let target = match target {
            Some(t) if !t.get("deleted").is_some_and(crate::tier1::py_truthy) => t,
            _ => return Err(write_refused(format!("No tool with ID {}.", repr_str(tool_id)))),
        };
        let deleted_entry = soft_delete_entry(&target);
        self.write_tools(
            specs
                .into_iter()
                .map(|s| if s.get("id").and_then(Value::as_str) == Some(tool_id) { deleted_entry.clone() } else { s })
                .collect(),
        )?;
        audit_write(
            &self.audit,
            json!({
                "kind": "admin_change",
                "actor": actor,
                "action": "tool_delete",
                "target": tool_id,
                // The full definition: a deletion can be restored from the log.
                "spec": Value::Object(target),
            }),
        )?;
        self.orphan_warning(tool_id)
    }

    /// Records who now holds a right to a tool that no longer exists.
    fn orphan_warning(&self, tool_id: &str) -> ConfigResult<()> {
        let mut holders: Vec<String> = self
            .identities
            .read()
            .identities
            .values()
            .filter(|i| i.holds_definition(tool_id))
            .map(|i| i.id.clone())
            .collect();
        holders.sort();
        if holders.is_empty() {
            return Ok(());
        }
        audit_write(
            &self.audit,
            json!({
                "kind": "admin_note",
                "action": "dangling_grant",
                "target": tool_id,
                "identities": holders,
            }),
        )
    }

    // -- Identities ------------------------------------------------------------

    fn write_identities(&self, payload: &Value) -> ConfigResult<()> {
        atomic_write_cfg(&self.identities_path, &dump(payload))?;
        let fresh = load_identities(&self.identities_path)?;
        // Swap the contents, not the handle: the auth layer holds the handle.
        self.identities.write().identities = fresh.identities;
        // A grant change is a catalog change from where an agent sits.
        self.service.catalog_notifier.tool_catalog_changed();
        Ok(())
    }

    fn check_password(password: &str) -> ConfigResult<()> {
        if password.chars().count() < MIN_PASSWORD_LENGTH {
            return Err(write_refused(format!(
                "The console password must be at least {MIN_PASSWORD_LENGTH} characters long."
            )));
        }
        Ok(())
    }

    fn check_role_and_id(role: &str, identity_id: &str) -> ConfigResult<()> {
        if !ROLES.contains(&role) {
            return Err(write_refused(format!("Unknown role {}.", repr_str(role))));
        }
        if !valid_identity_id(identity_id) {
            return Err(write_refused("Identity ID must be alphanumeric (dashes and underscores allowed)."));
        }
        Ok(())
    }

    /// Expands bare tool IDs to their destination-qualified catalog IDs and
    /// refuses unknown ones. Returns the sorted resolved set.
    fn resolve_tools(&self, tools: &[String]) -> ConfigResult<Vec<String>> {
        let catalog = self.service.catalog();
        let mut resolved: BTreeSet<String> = BTreeSet::new();
        for tid in tools {
            if catalog.tools.contains_key(tid) {
                resolved.insert(tid.clone());
            } else {
                let prefix = format!("{tid}@");
                let expanded: Vec<&String> = catalog.tools.keys().filter(|t| t.starts_with(&prefix)).collect();
                if expanded.is_empty() {
                    resolved.insert(tid.clone()); // caught by the unknown check
                } else {
                    resolved.extend(expanded.into_iter().cloned());
                }
            }
        }
        let bases: BTreeSet<&str> =
            catalog.tools.keys().filter_map(|t| t.rsplit_once('@').map(|(b, _)| b)).collect();
        let unknown: BTreeSet<&String> = tools
            .iter()
            .filter(|t| !catalog.tools.contains_key(*t) && !bases.contains(t.as_str()))
            .collect();
        if !unknown.is_empty() {
            let list: Vec<&str> = unknown.iter().map(|s| s.as_str()).collect();
            return Err(write_refused(format!("Unknown tool IDs: {}", list.join(", "))));
        }
        Ok(resolved.into_iter().collect())
    }

    fn no_room(role: &str) -> ConfigError {
        write_refused(format!(
            "role {} cannot sign in to the console, so a password would be a door without a room. \
             Choose {} instead.",
            repr_str(role),
            UI_ROLES.join(" or ")
        ))
    }

    /// Changes an existing identity. `password = ""` means: the existing
    /// console password stays.
    #[allow(clippy::too_many_arguments)]
    pub fn save_identity(
        &self,
        identity_id: &str,
        role: &str,
        tools: &[String],
        scopes: &[String],
        actor: &str,
        rev: &str,
        replaces: Option<&str>,
        password: &str,
    ) -> ConfigResult<()> {
        let _guard = self.guard();
        self.check(&self.identities_path, rev)?;
        Self::check_role_and_id(role, identity_id)?;

        let current = self.identities.read().clone();
        if replaces.is_none() && current.identities.contains_key(identity_id) {
            return Err(write_refused(format!("An identity {} already exists.", repr_str(identity_id))));
        }
        if let Some(replaces) = replaces {
            if identity_id != replaces && current.identities.contains_key(identity_id) {
                return Err(write_refused(format!("An identity {} already exists.", repr_str(identity_id))));
            }
        }

        let resolved_tools = self.resolve_tools(tools)?;

        let payload = dump_identities(&current);
        let entries: Vec<Value> = payload["identities"].as_array().cloned().unwrap_or_default();

        let Some(replaces) = replaces else {
            // New identities get a token immediately, otherwise there would
            // be an entry without a valid hash.
            return Err(write_refused("Use create_identity() for new entries -- a token is required."));
        };

        // PORT NOTE: Python raised KeyError for an unknown `replaces`.
        let Some(previous) = current.identities.get(replaces) else {
            return Err(write_refused(format!("No identity {}.", repr_str(replaces))));
        };
        let ui_role = UI_ROLES.contains(&role);
        if !password.is_empty() && !ui_role {
            // Must fail *before* writing: the loader rejects a password on
            // an agent role, and the write reloads immediately.
            return Err(Self::no_room(role));
        }
        let password_hash = if !password.is_empty() {
            Self::check_password(password)?;
            hash_token(password)
        } else if ui_role {
            previous.password_hash.clone()
        } else {
            // Role `agent`: console access is removed, and the hash with it.
            String::new()
        };

        if ui_role && password_hash.is_empty() {
            return Err(write_refused(format!(
                "role {} needs a console password -- without one, {} could not sign in. Set one in this form.",
                repr_str(role),
                repr_str(identity_id)
            )));
        }

        let kept_scopes: Vec<String> = scopes.iter().filter(|s| !s.is_empty()).cloned().collect();
        let mut updated = Map::new();
        updated.insert("id".into(), json!(identity_id));
        updated.insert("role".into(), json!(role));
        updated.insert("token_hash".into(), json!(previous.token_hash));
        updated.insert("tools".into(), json!(resolved_tools));
        updated.insert("scopes".into(), json!(kept_scopes));
        if !password_hash.is_empty() {
            updated.insert("password_hash".into(), json!(password_hash));
        }
        // The token is not changing -- carry its lookup index over.
        if !previous.token_lookup.is_empty() {
            updated.insert("token_lookup".into(), json!(previous.token_lookup));
        }
        let updated = Value::Object(updated);
        let entries: Vec<Value> = entries
            .into_iter()
            .map(|e| if e.get("id").and_then(Value::as_str) == Some(replaces) { updated.clone() } else { e })
            .collect();

        self.guard_last_admin(&entries, &format!("changing {}", repr_str(replaces)))?;
        self.write_identities(&json!({ "identities": entries }))?;
        audit_write(
            &self.audit,
            json!({
                "kind": "admin_change",
                "actor": actor,
                "action": "identity_update",
                "target": identity_id,
                "previous_id": if replaces != identity_id { json!(replaces) } else { Value::Null },
                "role": role,
                "tools": resolved_tools,
                "scopes": kept_scopes,
                // The plaintext is never logged, but the fact is.
                "password_changed": !password.is_empty(),
            }),
        )
    }

    /// Creates an identity and returns the plaintext token exactly once.
    #[allow(clippy::too_many_arguments)]
    pub fn create_identity(
        &self,
        identity_id: &str,
        role: &str,
        tools: &[String],
        scopes: &[String],
        actor: &str,
        rev: &str,
        password: &str,
    ) -> ConfigResult<String> {
        let _guard = self.guard();
        self.check(&self.identities_path, rev)?;
        Self::check_role_and_id(role, identity_id)?;
        let current = self.identities.read().clone();
        if current.identities.contains_key(identity_id) {
            return Err(write_refused(format!("An identity {} already exists.", repr_str(identity_id))));
        }
        let resolved_tools = self.resolve_tools(tools)?;
        let ui_role = UI_ROLES.contains(&role);
        if ui_role && password.is_empty() {
            return Err(write_refused(format!(
                "role {} signs in to the console and therefore needs a password.",
                repr_str(role)
            )));
        }
        if !password.is_empty() && !ui_role {
            return Err(Self::no_room(role));
        }
        if !password.is_empty() {
            Self::check_password(password)?;
        }

        let token = generate_token();
        let kept_scopes: Vec<String> = scopes.iter().filter(|s| !s.is_empty()).cloned().collect();
        let mut entry = Map::new();
        entry.insert("id".into(), json!(identity_id));
        entry.insert("role".into(), json!(role));
        entry.insert("token_hash".into(), json!(hash_token(&token)));
        entry.insert("token_lookup".into(), json!(hash_token_lookup(&token)));
        entry.insert("tools".into(), json!(resolved_tools));
        entry.insert("scopes".into(), json!(kept_scopes));
        if !password.is_empty() {
            entry.insert("password_hash".into(), json!(hash_token(password)));
        }
        let mut payload = dump_identities(&current);
        if let Some(Value::Array(list)) = payload.get_mut("identities") {
            list.push(Value::Object(entry));
        }
        self.write_identities(&payload)?;
        // The plaintext is deliberately NOT logged (FR-2.6).
        audit_write(
            &self.audit,
            json!({
                "kind": "admin_change",
                "actor": actor,
                "action": "identity_create",
                "target": identity_id,
                "role": role,
                "tools": resolved_tools,
                "scopes": kept_scopes,
            }),
        )?;
        Ok(token)
    }

    pub fn rotate_token(&self, identity_id: &str, actor: &str, rev: &str) -> ConfigResult<String> {
        let _guard = self.guard();
        self.check(&self.identities_path, rev)?;
        let current = self.identities.read().clone();
        if !current.identities.contains_key(identity_id) {
            return Err(write_refused(format!("No identity {}.", repr_str(identity_id))));
        }
        let token = generate_token();
        let mut payload = dump_identities(&current);
        for_entry(&mut payload, identity_id, |entry| {
            entry.insert("token_hash".into(), json!(hash_token(&token)));
            entry.insert("token_lookup".into(), json!(hash_token_lookup(&token)));
        });
        self.write_identities(&payload)?;
        audit_write(
            &self.audit,
            json!({"kind": "admin_change", "actor": actor, "action": "token_rotate", "target": identity_id}),
        )?;
        Ok(token)
    }

    /// Sets the console password of an identity. `require_current` applies
    /// to self-service: changing one's own password needs the old one.
    #[allow(clippy::too_many_arguments)]
    pub fn set_password(
        &self,
        identity_id: &str,
        password: &str,
        actor: &str,
        rev: &str,
        current_password: &str,
        require_current: bool,
    ) -> ConfigResult<()> {
        let _guard = self.guard();
        self.check(&self.identities_path, rev)?;
        let current = self.identities.read().clone();
        let Some(identity) = current.identities.get(identity_id) else {
            return Err(write_refused(format!("No identity {}.", repr_str(identity_id))));
        };
        if !UI_ROLES.contains(&identity.role.as_str()) {
            return Err(write_refused(format!(
                "{} has role {} and does not sign in to the console. A password would change nothing.",
                repr_str(identity_id),
                repr_str(&identity.role)
            )));
        }
        if require_current && !verify_token(current_password, &identity.password_hash) {
            return Err(write_refused("The current password is not correct."));
        }
        Self::check_password(password)?;

        let mut payload = dump_identities(&current);
        for_entry(&mut payload, identity_id, |entry| {
            entry.insert("password_hash".into(), json!(hash_token(password)));
        });
        self.write_identities(&payload)?;
        audit_write(
            &self.audit,
            json!({
                "kind": "admin_change",
                "actor": actor,
                "action": "password_set",
                "target": identity_id,
                "self_service": identity_id == actor,
            }),
        )
    }

    pub fn delete_identity(&self, identity_id: &str, actor: &str, rev: &str) -> ConfigResult<()> {
        let _guard = self.guard();
        self.check(&self.identities_path, rev)?;
        let current = self.identities.read().clone();
        if !current.identities.contains_key(identity_id) {
            return Err(write_refused(format!("No identity {}.", repr_str(identity_id))));
        }
        let payload = dump_identities(&current);
        let entries: Vec<Value> = payload["identities"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.get("id").and_then(Value::as_str) != Some(identity_id))
            .collect();
        self.guard_last_admin(&entries, &format!("deleting {}", repr_str(identity_id)))?;
        self.write_identities(&json!({ "identities": entries }))?;
        audit_write(
            &self.audit,
            json!({"kind": "admin_change", "actor": actor, "action": "identity_delete", "target": identity_id}),
        )
    }

    /// Prevents lockout: some `admin` must remain, and -- if there was one
    /// before -- an admin with a console password.
    fn guard_last_admin(&self, entries: &[Value], action: &str) -> ConfigResult<()> {
        let is_admin = |e: &Value| e.get("role").and_then(Value::as_str) == Some(ADMIN_ROLE);
        if !entries.iter().any(is_admin) {
            return Err(write_refused(format!(
                "Refused: {action} would leave no identity with role 'admin', \
                 and nobody could sign in to create one."
            )));
        }
        let had_console = self
            .identities
            .read()
            .identities
            .values()
            .any(|i: &Identity| i.role == ADMIN_ROLE && !i.password_hash.is_empty());
        let keeps_console = entries
            .iter()
            .any(|e| is_admin(e) && e.get("password_hash").is_some_and(crate::tier1::py_truthy));
        if had_console && !keeps_console {
            return Err(write_refused(format!(
                "Refused: {action} would leave no administrator with a \
                 console password, and nobody could sign in to set one."
            )));
        }
        Ok(())
    }
}

fn for_entry(payload: &mut Value, identity_id: &str, mut f: impl FnMut(&mut Map<String, Value>)) {
    if let Some(Value::Array(entries)) = payload.get_mut("identities") {
        for entry in entries.iter_mut() {
            if let Value::Object(m) = entry {
                if m.get("id").and_then(Value::as_str) == Some(identity_id) {
                    f(m);
                }
            }
        }
    }
}

/// Sets a console password directly in `identities.yaml` -- the path
/// without a running service (`gatekeeper password`, startup).
pub fn set_password_in_file(path: &str, identity_id: &str, password: &str) -> ConfigResult<()> {
    let store = load_identities(path)?;
    let Some(identity) = store.identities.get(identity_id) else {
        let mut known: Vec<&String> = store.identities.keys().collect();
        known.sort();
        let known = if known.is_empty() {
            "none".to_string()
        } else {
            known.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        };
        return Err(ConfigError::new(format!(
            "No identity {} in {path}. Known: {known}",
            repr_str(identity_id)
        )));
    };
    if !UI_ROLES.contains(&identity.role.as_str()) {
        return Err(ConfigError::new(format!(
            "{} has role {} and does not sign in to the console. Only {} do.",
            repr_str(identity_id),
            repr_str(&identity.role),
            UI_ROLES.join(" and ")
        )));
    }
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ConfigError::new(format!(
            "The console password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )));
    }
    if !writable(path) {
        return Err(ConfigError::new(format!(
            "{path} is not writable. The file or its directory is mounted read-only."
        )));
    }
    let mut payload = dump_identities(&store);
    for_entry(&mut payload, identity_id, |entry| {
        entry.insert("password_hash".into(), json!(hash_token(password)));
    });
    crate::atomic::atomic_write(path, &dump(&payload)).map_err(|e| {
        // PORT NOTE: Python let the OSError escape; same text as a ConfigError.
        ConfigError::new(crate::pyfmt::os_error(&e, path))
    })
}

/// Reads exactly one tool definition from the form field.
pub fn load_tool_yaml(text: &str) -> ConfigResult<Map<String, Value>> {
    // PORT NOTE: the YAML error text is this parser's, not PyYAML's.
    let parsed = crate::yaml::load(text).map_err(|exc| write_refused(format!("Not valid YAML: {exc}")))?;
    let Value::Object(parsed) = parsed else {
        return Err(write_refused("Expected a single tool definition as a YAML mapping."));
    };
    if matches!(parsed.get("tools"), Some(Value::Array(_))) {
        return Err(write_refused("Paste one tool definition, not the whole file -- drop the 'tools:' key."));
    }
    Ok(parsed)
}

/// `yaml.safe_dump(spec, sort_keys=False, allow_unicode=True)`.
pub fn tool_to_yaml(spec: &Map<String, Value>) -> String {
    crate::yaml::dump(&Value::Object(spec.clone()))
}
