//! The pending-actions queue for the `admin.*` MCP surface (port of
//! `pending.py`).
//!
//! Low-risk admin actions apply immediately; anything that expands what an
//! agent can do or touch is written here instead and waits for a human to
//! approve or reject it through `/app/requests`. `pending.yaml` is a Tier 2
//! file written with the same atomic-write / revision primitives as
//! `tools.yaml` and `identities.yaml`.
//!
//! `approve` does not decide *what* a proposal does: it re-checks the
//! captured `base_rev` against the live revision of the targeted record
//! and, if it moved, marks the item `stale` instead of applying (no silent
//! re-basing). Otherwise the caller-supplied `apply` callback performs the
//! mutation through the same store mutator a console write would use.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value};

use crate::atomic;
use crate::audit::AuditLog;
use crate::errors::{ConfigError, ConfigResult};
use crate::pyfmt::{repr_str, repr_value, str_value};

/// What a pending item may be in.
pub const STATUSES: [&str; 4] = ["pending", "approved", "rejected", "stale"];

/// The reasons an item is marked `stale`, shared by every path that can
/// mark one, so `/app/requests` shows the same sentence either way.
pub const STALE_VANISHED_REASON: &str = "What this targeted no longer exists. Nothing to apply.";
pub const STALE_CHANGED_REASON: &str =
    "Configuration changed since this was proposed. Re-propose from the current state.";
/// A `cred_propose` (or a renaming `cred_update`) whose name was taken
/// after it was proposed.
pub const STALE_TAKEN_REASON: &str =
    "A credential with this name exists now. Propose a new name, or rotate the existing credential.";

/// `PendingWriteRefused`: a pending-queue write was refused.
pub fn pending_write_refused(message: impl Into<String>) -> ConfigError {
    ConfigError::refused(message)
}

#[derive(Debug, Clone, PartialEq)]
pub struct PendingAction {
    pub id: String,
    pub action: String,
    pub actor: String,
    pub payload: Map<String, Value>,
    /// Revision of the record this action targets, captured at propose time.
    pub base_rev: String,
    pub status: String,
    pub created_at: String,
    pub decided_by: Option<String>,
    pub decided_at: Option<String>,
    pub reason: Option<String>,
}

fn opt(v: &Option<String>) -> Value {
    match v {
        Some(s) => Value::String(s.clone()),
        None => Value::Null,
    }
}

impl PendingAction {
    pub fn to_spec(&self) -> Value {
        let mut spec = Map::new();
        spec.insert("id".into(), self.id.clone().into());
        spec.insert("action".into(), self.action.clone().into());
        spec.insert("actor".into(), self.actor.clone().into());
        spec.insert("payload".into(), Value::Object(self.payload.clone()));
        spec.insert("base_rev".into(), self.base_rev.clone().into());
        spec.insert("status".into(), self.status.clone().into());
        spec.insert("created_at".into(), self.created_at.clone().into());
        spec.insert("decided_by".into(), opt(&self.decided_by));
        spec.insert("decided_at".into(), opt(&self.decided_at));
        spec.insert("reason".into(), opt(&self.reason));
        Value::Object(spec)
    }
}

/// Python truthiness.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
    }
}

/// `str(spec.get(key))` -- a missing key reads `"None"`, as in Python.
fn str_of(spec: &Map<String, Value>, key: &str) -> String {
    str_value(spec.get(key).unwrap_or(&Value::Null))
}

/// `str(spec.get(key) or default)`.
fn str_or(spec: &Map<String, Value>, key: &str, default: &str) -> String {
    if truthy(spec.get(key)) {
        str_of(spec, key)
    } else {
        default.to_string()
    }
}

/// `spec.get(key)` for an optional text field.
///
/// PORT NOTE: Python kept whatever value the file held; a non-string is
/// carried as its `str()` here.
fn opt_of(spec: &Map<String, Value>, key: &str) -> Option<String> {
    match spec.get(key) {
        None | Some(Value::Null) => None,
        Some(v) => Some(str_value(v)),
    }
}

fn from_spec(spec: &Map<String, Value>) -> PendingAction {
    PendingAction {
        id: str_of(spec, "id"),
        action: str_of(spec, "action"),
        actor: str_of(spec, "actor"),
        payload: match spec.get("payload") {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        },
        base_rev: str_or(spec, "base_rev", ""),
        status: str_or(spec, "status", "pending"),
        created_at: str_or(spec, "created_at", ""),
        decided_by: opt_of(spec, "decided_by"),
        decided_at: opt_of(spec, "decided_at"),
        reason: opt_of(spec, "reason"),
    }
}

fn id_matches(entry: &Map<String, Value>, action_id: &str) -> bool {
    matches!(entry.get("id"), Some(Value::String(s)) if s == action_id)
}

fn status_repr(entry: &Map<String, Value>) -> String {
    repr_value(entry.get("status").unwrap_or(&Value::Null))
}

/// Owns `pending.yaml`.
pub struct PendingStore {
    pub path: String,
    pub audit: Arc<AuditLog>,
    lock: Mutex<()>,
}

impl std::fmt::Debug for PendingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingStore").field("path", &self.path).finish()
    }
}

type Entries = Vec<Map<String, Value>>;

impl PendingStore {
    pub fn new(path: &str, audit: Arc<AuditLog>) -> PendingStore {
        PendingStore { path: path.to_string(), audit, lock: Mutex::new(()) }
    }

    pub fn revision(&self) -> String {
        atomic::revision(&self.path)
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn load(&self) -> ConfigResult<Entries> {
        let raw = atomic::load_cached(&self.path)?;
        let entries = match raw {
            None | Some(Value::Null) => Value::Null,
            Some(Value::Object(mut map)) => map.remove("pending").unwrap_or(Value::Null),
            // PORT NOTE: Python raised AttributeError for a file whose top
            // level is not a mapping; it is the same refusal as a bad section.
            Some(_) => Value::Bool(false),
        };
        match entries {
            Value::Null => Ok(Vec::new()),
            Value::Array(items) => Ok(items
                .into_iter()
                .filter_map(|e| match e {
                    Value::Object(m) => Some(m),
                    _ => None,
                })
                .collect()),
            _ => Err(ConfigError::new("pending.yaml: section 'pending' is missing or not a list")),
        }
    }

    fn write(&self, entries: &Entries) -> ConfigResult<()> {
        let mut payload = Map::new();
        payload.insert(
            "pending".into(),
            Value::Array(entries.iter().cloned().map(Value::Object).collect()),
        );
        atomic::atomic_write_cfg(&self.path, &atomic::dump(&Value::Object(payload)))
    }

    fn audit_write(&self, entry: Value) -> ConfigResult<()> {
        // PORT NOTE: Python let the OSError escape; same effect here.
        self.audit
            .write(entry)
            .map_err(|e| ConfigError::new(format!("The audit log could not be written: {e}")))
    }

    fn audit_decision(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        item: &PendingAction,
        extra: &[(&str, Value)],
    ) -> ConfigResult<()> {
        let mut entry = Map::new();
        entry.insert("kind".into(), "admin_change".into());
        entry.insert("actor".into(), actor.into());
        entry.insert("action".into(), action.into());
        entry.insert("target".into(), target.into());
        entry.insert("proposed_action".into(), item.action.clone().into());
        entry.insert("original_actor".into(), item.actor.clone().into());
        for (k, v) in extra {
            entry.insert((*k).into(), v.clone());
        }
        self.audit_write(Value::Object(entry))
    }

    // -- Reads -------------------------------------------------------------

    /// Every item, oldest first; `status` filters (empty = no filter).
    pub fn list(&self, status: Option<&str>) -> ConfigResult<Vec<PendingAction>> {
        let mut items: Vec<PendingAction> = self.load()?.iter().map(from_spec).collect();
        items.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        if let Some(status) = status.filter(|s| !s.is_empty()) {
            items.retain(|i| i.status == status);
        }
        Ok(items)
    }

    pub fn get(&self, action_id: &str) -> ConfigResult<Option<PendingAction>> {
        Ok(self.load()?.iter().find(|e| id_matches(e, action_id)).map(from_spec))
    }

    // -- Writes --------------------------------------------------------------

    pub fn propose(
        &self,
        action: &str,
        actor: &str,
        payload: Map<String, Value>,
        base_rev: &str,
    ) -> ConfigResult<PendingAction> {
        let _guard = self.guard();
        let mut entries = self.load()?;
        let item = PendingAction {
            id: crate::identity::token_urlsafe(12),
            action: action.to_string(),
            actor: actor.to_string(),
            payload,
            base_rev: base_rev.to_string(),
            status: "pending".into(),
            created_at: crate::timeutil::now_utc_iso(),
            decided_by: None,
            decided_at: None,
            reason: None,
        };
        if let Value::Object(spec) = item.to_spec() {
            entries.push(spec);
        }
        self.write(&entries)?;
        let mut entry = Map::new();
        entry.insert("kind".into(), "admin_change".into());
        entry.insert("actor".into(), actor.into());
        entry.insert("action".into(), "pending_propose".into());
        entry.insert("target".into(), item.id.clone().into());
        entry.insert("proposed_action".into(), action.into());
        entry.insert("payload".into(), Value::Object(item.payload.clone()));
        self.audit_write(Value::Object(entry))?;
        Ok(item)
    }

    pub fn reject(&self, action_id: &str, decided_by: &str, reason: &str) -> ConfigResult<PendingAction> {
        let _guard = self.guard();
        let mut entries = self.load()?;
        let Some(index) = entries.iter().position(|e| id_matches(e, action_id)) else {
            return Err(pending_write_refused(format!("No pending action {}.", repr_str(action_id))));
        };
        let matched = &mut entries[index];
        if matched.get("status") != Some(&Value::String("pending".into())) {
            return Err(pending_write_refused(format!(
                "Pending action {} is already {}.",
                repr_str(action_id),
                status_repr(matched)
            )));
        }
        matched.insert("status".into(), "rejected".into());
        matched.insert("decided_by".into(), decided_by.into());
        matched.insert("decided_at".into(), crate::timeutil::now_utc_iso().into());
        matched.insert("reason".into(), reason.into());
        let item = from_spec(matched);
        let mut audit = Map::new();
        audit.insert("kind".into(), "admin_change".into());
        audit.insert("actor".into(), decided_by.into());
        audit.insert("action".into(), "pending_reject".into());
        audit.insert("target".into(), action_id.into());
        audit.insert("proposed_action".into(), matched.get("action").cloned().unwrap_or(Value::Null));
        audit.insert("original_actor".into(), matched.get("actor").cloned().unwrap_or(Value::Null));
        audit.insert("reason".into(), reason.into());
        self.write(&entries)?;
        self.audit_write(Value::Object(audit))?;
        Ok(item)
    }

    /// Marks `stale` every still-`pending` item whose target record has
    /// vanished, and returns the ones it closed -- the self-healing half
    /// of `approve`'s guard, run on the read path.
    ///
    /// `live_rev` returns the live per-record revision of what the item
    /// targets, or `None` for an item this sweep must not judge. Only `""`
    /// (the record existed at propose time and is gone now) closes an
    /// item. Idempotent; a read-only `pending.yaml` is left alone.
    pub fn close_vanished_targets<F>(&self, mut live_rev: F, decided_by: &str) -> ConfigResult<Vec<PendingAction>>
    where
        F: FnMut(&PendingAction) -> Option<String>,
    {
        if !atomic::writable(&self.path) {
            return Ok(Vec::new());
        }
        let _guard = self.guard();
        let mut entries = self.load()?;
        let mut closed = Vec::new();
        for entry in entries.iter_mut() {
            if entry.get("status") != Some(&Value::String("pending".into())) {
                continue;
            }
            let item = from_spec(entry);
            // No `base_rev`: proposed against a record that did not exist
            // yet; "gone" is not a thing it can be.
            if item.base_rev.is_empty() {
                continue;
            }
            match live_rev(&item) {
                Some(rev) if rev.is_empty() => {}
                _ => continue,
            }
            mark_stale(entry, decided_by, STALE_VANISHED_REASON);
            closed.push(from_spec(entry));
        }
        self.finish_sweep(&entries, closed, decided_by, STALE_VANISHED_REASON)
    }

    /// Marks `stale` every still-`pending` `cred_propose` whose name is in
    /// `taken` -- and every renaming `cred_update` whose new name is.
    pub fn close_taken_credentials(&self, taken: &HashSet<String>, decided_by: &str) -> ConfigResult<Vec<PendingAction>> {
        if taken.is_empty() || !atomic::writable(&self.path) {
            return Ok(Vec::new());
        }
        let _guard = self.guard();
        let mut entries = self.load()?;
        let mut closed = Vec::new();
        for entry in entries.iter_mut() {
            if entry.get("status") != Some(&Value::String("pending".into())) {
                continue;
            }
            let Some(Value::Object(payload)) = entry.get("payload") else {
                continue;
            };
            // The name the write would create: a new slot's, or a rename's
            // target.
            let wanted = match entry.get("action").and_then(Value::as_str) {
                Some("cred_propose") => payload.get("name"),
                Some("cred_update") => payload.get("new_name"),
                _ => continue,
            };
            match wanted {
                Some(Value::String(name)) if !name.is_empty() && taken.contains(name) => {}
                _ => continue,
            }
            mark_stale(entry, decided_by, STALE_TAKEN_REASON);
            closed.push(from_spec(entry));
        }
        self.finish_sweep(&entries, closed, decided_by, STALE_TAKEN_REASON)
    }

    fn finish_sweep(
        &self,
        entries: &Entries,
        closed: Vec<PendingAction>,
        decided_by: &str,
        reason: &str,
    ) -> ConfigResult<Vec<PendingAction>> {
        if closed.is_empty() {
            return Ok(closed);
        }
        self.write(entries)?;
        for item in &closed {
            self.audit_decision(decided_by, "pending_stale", &item.id, item, &[("reason", reason.into())])?;
        }
        Ok(closed)
    }

    /// Approves one item.
    ///
    /// `current_rev` reads the live revision of the record the action
    /// targets; if it no longer matches the proposal's `base_rev` (a
    /// vanished target, `""`, counts as changed) the item is marked
    /// `stale`, a refusal is returned and `apply` is never called.
    /// Otherwise `apply` performs the mutation; its error propagates
    /// unchanged (the item stays `pending`), and on success the item is
    /// marked `approved` and `apply`'s result returned.
    pub fn approve<T, E, R, A>(&self, action_id: &str, decided_by: &str, current_rev: R, apply: A) -> Result<T, E>
    where
        E: From<ConfigError>,
        R: FnOnce(&PendingAction) -> String,
        A: FnOnce(&PendingAction) -> Result<T, E>,
    {
        let _guard = self.guard();
        let mut entries = self.load()?;
        let Some(index) = entries.iter().position(|e| id_matches(e, action_id)) else {
            return Err(pending_write_refused(format!("No pending action {}.", repr_str(action_id))).into());
        };
        if entries[index].get("status") != Some(&Value::String("pending".into())) {
            return Err(pending_write_refused(format!(
                "Pending action {} is already {}.",
                repr_str(action_id),
                status_repr(&entries[index])
            ))
            .into());
        }
        let item = from_spec(&entries[index]);

        let live_rev = current_rev(&item);
        if !item.base_rev.is_empty() && item.base_rev != live_rev {
            let vanished = live_rev.is_empty();
            let reason = if vanished { STALE_VANISHED_REASON } else { STALE_CHANGED_REASON };
            mark_stale(&mut entries[index], decided_by, reason);
            self.write(&entries)?;
            self.audit_decision(decided_by, "pending_stale", action_id, &item, &[])?;
            return Err(pending_write_refused(format!(
                "Pending action {} is stale: {} It has been marked 'stale' -- re-propose from the current state.",
                repr_str(action_id),
                if vanished {
                    "what it targeted no longer exists."
                } else {
                    "the configuration changed since it was proposed."
                }
            ))
            .into());
        }

        let result = apply(&item)?;

        let matched = &mut entries[index];
        matched.insert("status".into(), "approved".into());
        matched.insert("decided_by".into(), decided_by.into());
        matched.insert("decided_at".into(), crate::timeutil::now_utc_iso().into());
        self.write(&entries)?;
        self.audit_decision(decided_by, "pending_approve", action_id, &item, &[])?;
        Ok(result)
    }
}

fn mark_stale(entry: &mut Map<String, Value>, decided_by: &str, reason: &str) {
    entry.insert("status".into(), "stale".into());
    entry.insert("decided_by".into(), decided_by.into());
    entry.insert("decided_at".into(), crate::timeutil::now_utc_iso().into());
    entry.insert("reason".into(), reason.into());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Env {
        _dir: tempfile::TempDir,
        pending: PendingStore,
    }

    impl Env {
        fn audit(&self) -> Vec<Value> {
            std::fs::read_to_string(self.pending.audit.path())
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::new(dir.path().join("logs").to_str().unwrap()).unwrap());
        let pending = PendingStore::new(dir.path().join("pending.yaml").to_str().unwrap(), audit);
        Env { _dir: dir, pending }
    }

    fn payload(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn ok(_: &PendingAction) -> Result<(), ConfigError> {
        Ok(())
    }

    #[test]
    fn propose_then_list_then_reject() {
        let e = env();
        let item = e.pending.propose("tool_delete", "hermes", payload(json!({"id": "demo.show"})), "rev1").unwrap();
        assert_eq!(item.status, "pending");
        assert_eq!(item.id.len(), 16);
        let listed = e.pending.list(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], item);

        let rejected = e.pending.reject(&item.id, "root", "not needed").unwrap();
        assert_eq!(rejected.status, "rejected");
        assert_eq!(rejected.reason.as_deref(), Some("not needed"));
        assert_eq!(e.pending.get(&item.id).unwrap().unwrap().status, "rejected");
        assert!(e.pending.list(Some("pending")).unwrap().is_empty());

        let err = e.pending.reject(&item.id, "root", "").unwrap_err();
        assert!(err.is_write_refused());
        assert_eq!(err.message, format!("Pending action '{}' is already 'rejected'.", item.id));
        let err = e.pending.reject("does-not-exist", "root", "").unwrap_err();
        assert_eq!(err.message, "No pending action 'does-not-exist'.");

        let actions: Vec<Value> = e.audit().iter().map(|l| l["action"].clone()).collect();
        assert_eq!(actions, [json!("pending_propose"), json!("pending_reject")]);
        let reject = &e.audit()[1];
        assert_eq!(reject["proposed_action"], "tool_delete");
        assert_eq!(reject["original_actor"], "hermes");
    }

    #[test]
    fn file_format() {
        let e = env();
        let item = e.pending.propose("grant_set", "hermes", payload(json!({"identity_id": "bot", "tools": ["a"]})), "").unwrap();
        let text = std::fs::read_to_string(&e.pending.path).unwrap();
        assert!(text.starts_with(atomic::HEADER));
        let loaded = crate::yaml::load(&text).unwrap();
        assert_eq!(loaded, json!({"pending": [item.to_spec()]}));
        let keys: Vec<String> = loaded["pending"][0].as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            ["id", "action", "actor", "payload", "base_rev", "status", "created_at", "decided_by", "decided_at", "reason"]
        );
        assert!(item.created_at.ends_with("+0000"));
    }

    #[test]
    fn approve_applies_and_marks_approved() {
        let e = env();
        let item = e.pending.propose("tool_delete", "hermes", payload(json!({"id": "demo.show"})), "rev1").unwrap();
        let result: Result<String, ConfigError> =
            e.pending.approve(&item.id, "root", |_| "rev1".into(), |i| Ok(format!("applied {}", i.payload["id"])));
        assert_eq!(result.unwrap(), "applied \"demo.show\"");
        let approved = e.pending.get(&item.id).unwrap().unwrap();
        assert_eq!(approved.status, "approved");
        assert_eq!(approved.decided_by.as_deref(), Some("root"));
        assert!(e.audit().iter().any(|l| l["action"] == "pending_approve"));
        let err = e.pending.approve(&item.id, "root", |_| "rev1".into(), ok).unwrap_err();
        assert!(err.message.contains("already 'approved'"));
        let err = e.pending.approve("nope", "root", |_| String::new(), ok).unwrap_err();
        assert_eq!(err.message, "No pending action 'nope'.");
    }

    #[test]
    fn approve_marks_stale_when_target_changed() {
        let e = env();
        let item = e.pending.propose("tool_delete", "hermes", payload(json!({"id": "demo.show"})), "rev1").unwrap();
        let mut called = false;
        let err = e
            .pending
            .approve(&item.id, "root", |_| "rev2".into(), |_| {
                called = true;
                Ok::<(), ConfigError>(())
            })
            .unwrap_err();
        assert!(!called);
        assert_eq!(
            err.message,
            format!(
                "Pending action '{}' is stale: the configuration changed since it was proposed. It has been marked 'stale' -- re-propose from the current state.",
                item.id
            )
        );
        let marked = e.pending.get(&item.id).unwrap().unwrap();
        assert_eq!(marked.status, "stale");
        assert_eq!(marked.reason.as_deref(), Some(STALE_CHANGED_REASON));
        // Still refused -- status is 'stale', not 'pending'.
        let err = e.pending.approve(&item.id, "root", |_| "rev1".into(), ok).unwrap_err();
        assert!(err.message.contains("already 'stale'"));
    }

    #[test]
    fn approve_marks_stale_when_target_vanished() {
        let e = env();
        let item = e.pending.propose("tool_delete", "hermes", payload(json!({"id": "demo.show"})), "rev1").unwrap();
        let err = e.pending.approve(&item.id, "root", |_| String::new(), ok).unwrap_err();
        assert!(err.message.contains("is stale: what it targeted no longer exists."));
        assert!(!err.message.to_lowercase().contains("no tool with id"));
        let marked = e.pending.get(&item.id).unwrap().unwrap();
        assert_eq!(marked.status, "stale");
        assert_eq!(marked.decided_by.as_deref(), Some("root"));
        assert!(marked.reason.unwrap().contains("no longer exists"));
        let stale = e.audit().into_iter().find(|l| l["action"] == "pending_stale").unwrap();
        assert!(stale.get("reason").is_none());
    }

    #[test]
    fn approve_still_applies_when_there_was_no_base_rev() {
        let e = env();
        let item = e.pending.propose("tool_delete", "hermes", payload(json!({"id": "demo.ghost"})), "").unwrap();
        let mut applied = Vec::new();
        e.pending
            .approve(&item.id, "root", |_| String::new(), |i| {
                applied.push(i.payload["id"].clone());
                Ok::<(), ConfigError>(())
            })
            .unwrap();
        assert_eq!(applied, [json!("demo.ghost")]);
        assert_eq!(e.pending.get(&item.id).unwrap().unwrap().status, "approved");
    }

    #[test]
    fn a_failing_apply_keeps_the_item_pending() {
        let e = env();
        let item = e.pending.propose("tool_delete", "hermes", payload(json!({})), "rev").unwrap();
        let err = e
            .pending
            .approve(&item.id, "root", |_| "rev".into(), |_| Err::<(), _>(ConfigError::refused("nope")))
            .unwrap_err();
        assert_eq!(err.message, "nope");
        assert_eq!(e.pending.get(&item.id).unwrap().unwrap().status, "pending");
    }

    #[test]
    fn sweep_closes_only_vanished_targets_and_is_idempotent() {
        let e = env();
        let gone = e.pending.propose("tool_delete", "hermes", payload(json!({"id": "a"})), "rev-a").unwrap();
        let moved = e.pending.propose("tool_enable", "hermes", payload(json!({"id": "b"})), "rev-b").unwrap();
        let unjudged = e.pending.propose("cred_propose", "hermes", payload(json!({"name": "x"})), "deadbeef").unwrap();
        let fresh = e.pending.propose("tool_delete", "hermes", payload(json!({"id": "ghost"})), "").unwrap();
        let decided = e.pending.propose("tool_delete", "hermes", payload(json!({"id": "a"})), "rev-a").unwrap();
        e.pending.reject(&decided.id, "root", "not needed").unwrap();

        let live = |i: &PendingAction| -> Option<String> {
            match (i.action.as_str(), i.payload.get("id").and_then(Value::as_str)) {
                ("cred_propose", _) => None,
                (_, Some("a")) | (_, Some("ghost")) => Some(String::new()),
                (_, Some("b")) => Some("rev-b2".into()),
                _ => None,
            }
        };
        let closed = e.pending.close_vanished_targets(live, "system").unwrap();
        assert_eq!(closed.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), [gone.id.clone()]);
        let healed = e.pending.get(&gone.id).unwrap().unwrap();
        assert_eq!(healed.status, "stale");
        assert_eq!(healed.reason.as_deref(), Some(STALE_VANISHED_REASON));
        assert_eq!(healed.decided_by.as_deref(), Some("system"));
        assert!(healed.decided_at.is_some());
        for id in [&moved.id, &unjudged.id, &fresh.id] {
            assert_eq!(e.pending.get(id).unwrap().unwrap().status, "pending");
        }
        let d = e.pending.get(&decided.id).unwrap().unwrap();
        assert_eq!((d.status.as_str(), d.reason.as_deref()), ("rejected", Some("not needed")));

        let rev = e.pending.revision();
        assert!(e.pending.close_vanished_targets(live, "system").unwrap().is_empty());
        assert_eq!(e.pending.revision(), rev);
        assert_eq!(e.pending.get(&gone.id).unwrap().unwrap(), healed);

        let stales: Vec<Value> = e.audit().into_iter().filter(|l| l["action"] == "pending_stale").collect();
        assert_eq!(stales.len(), 1);
        assert_eq!(stales[0]["target"], json!(gone.id));
        assert_eq!(stales[0]["proposed_action"], "tool_delete");
        assert_eq!(stales[0]["reason"], STALE_VANISHED_REASON);
    }

    #[test]
    fn close_taken_credentials() {
        let e = env();
        let propose = e.pending.propose("cred_propose", "hermes", payload(json!({"name": "media"})), "").unwrap();
        let rename = e.pending.propose("cred_update", "hermes", payload(json!({"name": "j", "new_name": "media"})), "r").unwrap();
        let keep = e.pending.propose("cred_update", "hermes", payload(json!({"name": "media", "new_name": null})), "r").unwrap();
        let other = e.pending.propose("cred_propose", "hermes", payload(json!({"name": "free"})), "").unwrap();
        assert!(e.pending.close_taken_credentials(&HashSet::new(), "system").unwrap().is_empty());
        let taken: HashSet<String> = ["media".to_string()].into_iter().collect();
        let closed = e.pending.close_taken_credentials(&taken, "system").unwrap();
        assert_eq!(closed.len(), 2);
        for id in [&propose.id, &rename.id] {
            let item = e.pending.get(id).unwrap().unwrap();
            assert_eq!((item.status.as_str(), item.reason.as_deref()), ("stale", Some(STALE_TAKEN_REASON)));
        }
        for id in [&keep.id, &other.id] {
            assert_eq!(e.pending.get(id).unwrap().unwrap().status, "pending");
        }
        assert!(e.pending.close_taken_credentials(&taken, "system").unwrap().is_empty());
    }

    #[test]
    fn bad_file_shapes() {
        let e = env();
        std::fs::write(&e.pending.path, "pending: {a: 1}\n").unwrap();
        assert_eq!(
            e.pending.list(None).unwrap_err().message,
            "pending.yaml: section 'pending' is missing or not a list"
        );
        std::fs::write(&e.pending.path, "pending: [x, {id: a, status: null}]\n").unwrap();
        let items = e.pending.list(None).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].status, "pending");
        assert_eq!(items[0].action, "None");
        std::fs::write(&e.pending.path, "other: 1\n").unwrap();
        assert!(e.pending.list(None).unwrap().is_empty());
    }
}
