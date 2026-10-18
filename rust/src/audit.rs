//! Audit log (port of `audit.py`, REQUIREMENTS.md §12).
//!
//! Append-only, JSON Lines, with rotation. Rotation is not cosmetic: an
//! append-only log without a limit eventually fills the dataset, and then
//! not only gatekeeper stops (FR-9.5).
//!
//! Every line is `json.dumps(record, ensure_ascii=False)` as Python wrote
//! it (`", "`/`": "` separators, non-ASCII unescaped), with the local-time
//! `ts` as the first key.

use std::io::Write;
use std::sync::{Arc, Mutex, RwLock};

use serde_json::{Map, Value};

use crate::pyjson;

/// Substrings that mark a field name as secret-bearing -- regardless of
/// where it appears. Matched against a *normalized* key (lowercased, with
/// `-`, `_`, `.` and spaces stripped), so `api_key`, `X-Api-Key`, `apiKey`
/// and `apikey` all collapse onto the same token. Deliberately generous: a
/// wrongly masked field costs readability, a missed one costs a secret.
const NEVER_LOG: [&str; 5] = ["token", "authorization", "password", "apikey", "secret"];

/// Keys that match a `NEVER_LOG` token but describe a secret instead of
/// carrying one (FR-10.7). Stored normalized.
const LOGGABLE: [&str; 1] = ["passwordchanged"];

/// True if `key` names a field whose value must never be logged.
pub fn is_secret_key(key: &str) -> bool {
    let normalized: String =
        key.to_lowercase().chars().filter(|c| !matches!(c, '-' | '_' | '.' | ' ')).collect();
    if LOGGABLE.contains(&normalized.as_str()) {
        return false;
    }
    NEVER_LOG.iter().any(|token| normalized.contains(token))
}

/// Masks known secrets in outputs (FR-10.6).
///
/// The set is fed from `CredentialStore::plaintext_values_for_masking()` at
/// startup and refreshed on every create/rotate/delete. It covers exactly
/// the secrets gatekeeper holds itself -- which is why the key-name rule
/// above has to stand on its own for everything else.
#[derive(Default)]
pub struct Redactor {
    secrets: RwLock<Vec<String>>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.secrets.read().map(|s| s.len()).unwrap_or(0);
        f.debug_struct("Redactor").field("secrets", &format_args!("<{count} masked>")).finish()
    }
}

impl Redactor {
    pub fn new() -> Self {
        Redactor::default()
    }

    pub fn with_secrets(secrets: Vec<String>) -> Self {
        Redactor { secrets: RwLock::new(secrets) }
    }

    /// `redactor(text)`: every known secret replaced by `***`.
    pub fn redact(&self, text: &str) -> String {
        let secrets = self.secrets.read().unwrap_or_else(|e| e.into_inner()).clone();
        let mut text = text.to_string();
        for secret in &secrets {
            if !secret.is_empty() && text.contains(secret.as_str()) {
                text = text.replace(secret.as_str(), "***");
            }
        }
        text
    }

    /// Replaces the known-secret set (FR-10.6), swapped atomically.
    pub fn set_secrets(&self, secrets: Vec<String>) {
        *self.secrets.write().unwrap_or_else(|e| e.into_inner()) = secrets;
    }
}

/// Called with every record after it is on disk (the console's live
/// updates). Gets the scrubbed record, runs on the writer's thread, and
/// must not block.
pub type Listener = Box<dyn Fn(&Value) + Send + Sync>;

/// The fields of one `call` record (`AuditLog.call`'s keyword arguments).
#[derive(Debug, Clone, Default)]
pub struct CallRecord {
    pub identity: String,
    pub tool_id: String,
    pub tool_version: Option<i64>,
    pub parameters: Value,
    pub scopes: Vec<String>,
    pub outcome: String,
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub truncated: bool,
    pub denial_reason: Option<String>,
    pub detail: Option<String>,
    pub credential_names: Vec<String>,
    pub client: Option<String>,
    /// What the executor was actually handed -- the argv, the HTTP request
    /// line, the RPC method -- as one line (1.19.0). `None` when the call
    /// was denied before a request existed.
    pub command: Option<String>,
}

/// A logged parameter value is cut after this many characters, so a
/// file's content or a blob does not flood the log (1.19.0).
pub const MAX_PARAMETER_CHARS: usize = 1000;
/// Same for the recorded `command`.
pub const MAX_COMMAND_CHARS: usize = 2000;

/// `text`, cut after `max` characters with a note of how much was dropped.
pub fn clip(text: &str, max: usize) -> String {
    let total = text.chars().count();
    if total <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max).collect();
    format!("{kept}… [+{} chars]", total - max)
}

/// A string as a call record logs it: secret-shaped values masked
/// ([`crate::secretmask`], a `cmd` parameter of `export TOKEN=...` is not
/// caught by its key name), then clipped to `max` characters.
fn loggable(text: &str, max: usize) -> String {
    clip(&crate::secretmask::mask_secrets(text), max)
}

/// Every string in `value` masked and clipped, as [`loggable`].
fn clip_strings(value: Value, max: usize) -> Value {
    match value {
        Value::String(s) => Value::String(loggable(&s, max)),
        Value::Array(items) => Value::Array(items.into_iter().map(|i| clip_strings(i, max)).collect()),
        Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (k, clip_strings(v, max))).collect()),
        other => other,
    }
}

/// Writes structured records, rotates by size.
pub struct AuditLog {
    dir: String,
    path: String,
    max_bytes: u64,
    keep: usize,
    redact: Arc<Redactor>,
    lock: Mutex<()>,
    listeners: RwLock<Vec<Listener>>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("path", &self.path)
            .field("max_bytes", &self.max_bytes)
            .field("keep", &self.keep)
            .finish()
    }
}

pub const DEFAULT_MAX_BYTES: u64 = 32 * 1024 * 1024;
pub const DEFAULT_KEEP_FILES: usize = 10;

impl AuditLog {
    /// `AuditLog(directory)` with the default rotation limits. Creates the
    /// directory.
    pub fn new(directory: &str) -> std::io::Result<AuditLog> {
        AuditLog::with_options(directory, DEFAULT_MAX_BYTES, DEFAULT_KEEP_FILES, None)
    }

    pub fn with_options(
        directory: &str,
        max_bytes: u64,
        keep_files: usize,
        redactor: Option<Arc<Redactor>>,
    ) -> std::io::Result<AuditLog> {
        std::fs::create_dir_all(directory)?;
        Ok(AuditLog {
            dir: directory.to_string(),
            path: crate::pathutil::join(directory, "audit.jsonl"),
            max_bytes,
            keep: keep_files,
            redact: redactor.unwrap_or_default(),
            lock: Mutex::new(()),
            listeners: RwLock::new(Vec::new()),
        })
    }

    pub fn dir(&self) -> &str {
        &self.dir
    }

    /// `<dir>/audit.jsonl`.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn redactor(&self) -> &Arc<Redactor> {
        &self.redact
    }

    pub fn add_listener(&self, listener: Listener) {
        self.listeners.write().unwrap_or_else(|e| e.into_inner()).push(listener);
    }

    fn rotate_if_needed(&self) -> std::io::Result<()> {
        let size = match std::fs::metadata(&self.path) {
            Ok(meta) => meta.len(),
            Err(_) => return Ok(()),
        };
        if size < self.max_bytes {
            return Ok(());
        }
        let mut index = self.keep as i64 - 1;
        while index > 0 {
            let src = format!("{}.{}", self.path, index);
            let dst = format!("{}.{}", self.path, index + 1);
            if std::path::Path::new(&src).exists() {
                std::fs::rename(&src, &dst)?;
            }
            index -= 1;
        }
        std::fs::rename(&self.path, format!("{}.1", self.path))
    }

    /// Appends one record: `{"ts": <local time>, **event}`, scrubbed. A
    /// non-object `event` is written as `{"ts": ...}` alone.
    pub fn write(&self, event: Value) -> std::io::Result<()> {
        let mut record = Map::new();
        record.insert("ts".into(), Value::String(crate::timeutil::now_local_iso()));
        if let Value::Object(map) = event {
            for (k, v) in map {
                record.insert(k, v);
            }
        }
        let scrubbed = scrub(Value::Object(record), &self.redact);
        let line = pyjson::dumps_with(&scrubbed, &pyjson::Opts::unicode());
        {
            let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            self.rotate_if_needed()?;
            let mut handle =
                std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
            handle.write_all(format!("{line}\n").as_bytes())?;
        }
        let listeners = self.listeners.read().unwrap_or_else(|e| e.into_inner());
        for listener in listeners.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| listener(&scrubbed)));
            if result.is_err() {
                // The record is on disk; telling a browser about it is
                // best-effort and must never fail the audited action.
                tracing::error!("audit listener failed");
            }
        }
        Ok(())
    }

    /// A call -- successful, denied, or with unclear outcome.
    /// `denial_reason` records the *true* reason, even if the agent got
    /// only the opaque answer of FR-7.7.
    pub fn call(&self, record: CallRecord) -> std::io::Result<()> {
        let mut event = Map::new();
        event.insert("kind".into(), "call".into());
        event.insert("identity".into(), record.identity.into());
        event.insert("tool".into(), record.tool_id.into());
        event.insert("tool_version".into(), record.tool_version.into());
        // Scrubbed and masked before clipping: a secret cut in half by the
        // clip would no longer match, and half of it would land.
        let parameters = clip_strings(scrub(record.parameters, &self.redact), MAX_PARAMETER_CHARS);
        event.insert("parameters".into(), parameters);
        if let Some(command) = record.command {
            event.insert("command".into(), loggable(&self.redact.redact(&command), MAX_COMMAND_CHARS).into());
        }
        event.insert("scopes".into(), record.scopes.into());
        event.insert("outcome".into(), record.outcome.into());
        event.insert("exit_code".into(), record.exit_code.into());
        event.insert("duration_ms".into(), record.duration_ms.into());
        event.insert("output_truncated".into(), record.truncated.into());
        event.insert("denial_reason".into(), record.denial_reason.into());
        event.insert("detail".into(), record.detail.into());
        // FR-10.7: names of used credentials, never their values.
        event.insert("credentials".into(), record.credential_names.into());
        // The caller's address; absent when not called over HTTP.
        if let Some(client) = record.client.filter(|c| !c.is_empty()) {
            event.insert("client".into(), client.into());
        }
        self.write(Value::Object(event))
    }

    /// Refreshes the known-secret set used to mask output (FR-10.6).
    pub fn set_secrets(&self, secrets: Vec<String>) {
        self.redact.set_secrets(secrets);
    }

    /// Masks known credential values in `text` (FR-10.6) -- used by the
    /// executors to scrub a response before it reaches the agent.
    pub fn redact(&self, text: &str) -> String {
        self.redact.redact(text)
    }

    /// `extra` carries optional metadata such as the caller's address.
    pub fn auth_failure(&self, reason: &str, detail: &str, extra: Map<String, Value>) -> std::io::Result<()> {
        let mut event = Map::new();
        event.insert("kind".into(), "auth_failure".into());
        event.insert("reason".into(), reason.into());
        event.insert("detail".into(), detail.into());
        for (k, v) in extra {
            event.insert(k, v);
        }
        self.write(Value::Object(event))
    }

    pub fn startup(&self, payload: Value) -> std::io::Result<()> {
        let mut event = Map::new();
        event.insert("kind".into(), "startup".into());
        if let Value::Object(map) = payload {
            for (k, v) in map {
                event.insert(k, v);
            }
        }
        self.write(Value::Object(event))
    }
}

/// Removes obvious secrets and masks known values.
pub fn scrub(value: Value, redact: &Redactor) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| {
                    let v = if is_secret_key(&key) { Value::String("***".into()) } else { scrub(item, redact) };
                    (key, v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(|i| scrub(i, redact)).collect()),
        Value::String(s) => Value::String(redact.redact(&s)),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lines(log: &AuditLog) -> Vec<String> {
        std::fs::read_to_string(log.path()).unwrap().lines().map(str::to_string).collect()
    }

    #[test]
    fn secret_keys_are_normalized() {
        for key in ["token", "api_key", "X-Api-Key", "apiKey", "access_token", "Authorization", "client.secret", "new password"] {
            assert!(is_secret_key(key), "{key}");
        }
        for key in ["password_changed", "Password-Changed", "name", "kind", "header"] {
            assert!(!is_secret_key(key), "{key}");
        }
    }

    #[test]
    fn write_format_matches_python() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("logs").to_str().unwrap()).unwrap();
        log.write(json!({"kind": "x", "msg": "Grüße \"q\"", "token": "abc", "n": [1, 2.5, null]})).unwrap();
        let line = &lines(&log)[0];
        assert!(line.starts_with("{\"ts\": \""), "{line}");
        assert!(line.ends_with(r#", "kind": "x", "msg": "Grüße \"q\"", "token": "***", "n": [1, 2.5, null]}"#), "{line}");
        let parsed: Value = serde_json::from_str(line).unwrap();
        let ts = parsed["ts"].as_str().unwrap();
        assert_eq!(ts.len(), "2026-01-01T00:00:00+0000".len());
    }

    #[test]
    fn call_record_shape() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_str().unwrap()).unwrap();
        log.call(CallRecord {
            identity: "bot".into(),
            tool_id: "demo.show".into(),
            tool_version: Some(2),
            parameters: json!({"path": "/srv", "api_key": "k"}),
            scopes: vec!["/srv".into()],
            outcome: "ok".into(),
            ..Default::default()
        })
        .unwrap();
        log.call(CallRecord { client: Some("10.0.0.1".into()), ..Default::default() }).unwrap();
        let all = lines(&log);
        let first: Value = serde_json::from_str(&all[0]).unwrap();
        let keys: Vec<&String> = first.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["ts", "kind", "identity", "tool", "tool_version", "parameters", "scopes", "outcome", "exit_code",
             "duration_ms", "output_truncated", "denial_reason", "detail", "credentials"]
        );
        assert_eq!(first["parameters"]["api_key"], "***");
        assert_eq!(first["credentials"], json!([]));
        let second: Value = serde_json::from_str(&all[1]).unwrap();
        assert_eq!(second["client"], "10.0.0.1");
    }

    #[test]
    fn call_records_command_and_clips_after_masking() {
        let dir = tempfile::tempdir().unwrap();
        let redactor = Arc::new(Redactor::with_secrets(vec!["topsecret".into()]));
        let log = AuditLog::with_options(dir.path().to_str().unwrap(), DEFAULT_MAX_BYTES, 10, Some(redactor)).unwrap();
        // The secret straddles the clip point: masked first, it never lands
        // half-visible.
        let edge = format!("{}topsecret", "a".repeat(MAX_PARAMETER_CHARS - 4));
        log.call(CallRecord {
            parameters: json!({"content": edge, "nested": {"list": ["b".repeat(MAX_PARAMETER_CHARS + 1)]}}),
            command: Some(format!("cmd {}", "c".repeat(MAX_COMMAND_CHARS))),
            ..Default::default()
        })
        .unwrap();
        let record: Value = serde_json::from_str(&lines(&log)[0]).unwrap();
        let content = record["parameters"]["content"].as_str().unwrap();
        assert!(!content.contains("tops"), "{content}");
        assert!(content.ends_with("a***"), "{content}");
        assert!(record["parameters"]["nested"]["list"][0].as_str().unwrap().ends_with("… [+1 chars]"));
        assert!(record["command"].as_str().unwrap().ends_with("… [+4 chars]"));
        let keys: Vec<&String> = record.as_object().unwrap().keys().collect();
        assert_eq!(keys[5..7], ["parameters", "command"]);
        assert_eq!(clip("äöü", 2), "äö… [+1 chars]");
        assert_eq!(clip("abc", 3), "abc");
    }

    #[test]
    fn redactor_masks_known_values_and_listeners_get_scrubbed_records() {
        let dir = tempfile::tempdir().unwrap();
        let redactor = Arc::new(Redactor::new());
        let log = AuditLog::with_options(dir.path().to_str().unwrap(), DEFAULT_MAX_BYTES, 10, Some(redactor.clone())).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        log.add_listener(Box::new(|_| panic!("a failing listener must not fail the write")));
        log.add_listener(Box::new(move |r| sink.lock().unwrap().push(r.clone())));
        log.set_secrets(vec!["super-secret".into(), String::new()]);
        assert_eq!(log.redact("x super-secret y"), "x *** y");
        log.write(json!({"kind": "call", "detail": "leaked super-secret here"})).unwrap();
        assert!(!std::fs::read_to_string(log.path()).unwrap().contains("super-secret"));
        assert_eq!(seen.lock().unwrap()[0]["detail"], "leaked *** here");
        assert!(!format!("{redactor:?}").contains("super-secret"));
    }

    #[test]
    fn rotates_by_size() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::with_options(dir.path().to_str().unwrap(), 10, 3, None).unwrap();
        for i in 0..5 {
            log.write(json!({"i": i})).unwrap();
        }
        let base = log.path().to_string();
        assert!(std::path::Path::new(&format!("{base}.1")).exists());
        assert!(std::path::Path::new(&format!("{base}.3")).exists());
        assert!(!std::path::Path::new(&format!("{base}.4")).exists());
        assert!(lines(&log)[0].contains("\"i\": 4"));
    }

    #[test]
    fn auth_failure_and_startup() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_str().unwrap()).unwrap();
        let mut extra = Map::new();
        extra.insert("client".into(), json!("1.2.3.4"));
        log.auth_failure("unknown_token", "", extra).unwrap();
        log.startup(json!({"version": "2.0.0"})).unwrap();
        let all = lines(&log);
        assert!(all[0].ends_with(r#""kind": "auth_failure", "reason": "unknown_token", "detail": "", "client": "1.2.3.4"}"#));
        assert!(all[1].ends_with(r#""kind": "startup", "version": "2.0.0"}"#));
    }
}
