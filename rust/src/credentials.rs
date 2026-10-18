//! The credential store (port of `credentials.py`, REQUIREMENTS.md §11).
//!
//! > gatekeeper is a credential consumer with lifecycle management --
//! > not a credential provider.
//!
//! Named, encrypted-at-rest secrets that toolkits reference by name
//! (FR-10.1). The one requirement everything else here serves: **no
//! operation, for no role, ever returns a credential value** (FR-10.2).
//! Create, rotate, delete -- yes. Read -- never. The only function that
//! returns a plaintext tied to a name is [`CredentialStore::resolve`], for
//! the executors; values never appear in `Debug` output, logs or errors.
//!
//! The file format and the Fernet tokens are the Python implementation's:
//! a `credentials.yaml` written by either side is read by the other.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use regex::Regex;
use serde_json::{Map, Value};

use crate::atomic;
use crate::audit::AuditLog;
use crate::errors::{ConfigError, ConfigResult};
use crate::pyfmt::{repr_sorted, repr_str, str_value};

/// Kinds understood by the executors (see the Python module for what each
/// one means: header kinds, bearer/basic, the truenas JSON-RPC key, URL
/// path/query injection, docker TLS bundles, SSH keys/passwords, OAuth2
/// bundles).
pub const KINDS: [&str; 10] = [
    "api_key_header",
    "bearer",
    "basic",
    "ws_api_key",
    "url_path",
    "url_query",
    "docker_tls",
    "ssh_private_key",
    "ssh_password",
    "oauth2",
];

/// Kinds whose `header` field is required: the header name for
/// api_key_header, the query parameter name for url_query.
pub const HEADER_KINDS: [&str; 2] = ["api_key_header", "url_query"];

/// What shape of value each kind expects. `update` may change a slot's kind
/// only within one shape: the stored value cannot be read back (FR-10.2).
pub const VALUE_SHAPES: [(&str, &str); 10] = [
    ("api_key_header", "token"),
    ("bearer", "token"),
    ("url_path", "token"),
    ("url_query", "token"),
    ("ws_api_key", "token"),
    ("basic", "user:password"),
    ("docker_tls", "docker TLS bundle"),
    ("ssh_private_key", "SSH private key"),
    ("ssh_password", "SSH password"),
    ("oauth2", "OAuth2 bundle"),
];

pub fn value_shape(kind: &str) -> Option<&'static str> {
    VALUE_SHAPES.iter().find(|(k, _)| *k == kind).map(|(_, s)| *s)
}

pub fn is_kind(kind: &str) -> bool {
    KINDS.contains(&kind)
}

/// An HTTP header name (RFC 9110 `token`), which is also a safe query
/// parameter name. Refuses CR/LF and spaces.
pub const HEADER_NAME_PATTERN: &str = r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$";

/// `HEADER_NAME_RE.match(header)`.
///
/// PORT NOTE: Python's `$` also matched before a trailing newline, so
/// `"X-Token\n"` passed; the Rust check anchors at the true end of input.
pub fn is_header_name(header: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[A-Za-z0-9!#$%&'*+.^_`|~-]+\z").unwrap()).is_match(header)
}

/// The placeholder a `header_format` must contain exactly once.
pub const VALUE_PLACEHOLDER: &str = "{value}";

/// Fields that make up a slot's identity -- what `record_revision`
/// fingerprints. Probe and suspect metadata are left out on purpose.
const IDENTITY_FIELDS: [&str; 5] = ["kind", "header", "header_format", "probe_url", "created_at"];

pub const PROBE_STATUSES: [&str; 4] = ["no_probe_url", "verified", "auth_failed", "unreachable"];

/// Env var holding the base64 urlsafe Fernet key directly.
pub const KEY_ENV: &str = "GATEKEEPER_CREDENTIAL_KEY";
/// Env var holding a path to a file containing that same key.
pub const KEY_FILE_ENV: &str = "GATEKEEPER_CREDENTIAL_KEY_FILE";

fn refused(message: impl Into<String>) -> ConfigError {
    ConfigError::credential_refused(message)
}

/// Validates an `api_key_header` slot's optional header value format and
/// returns it normalized (`None` for empty), or a `WriteRefused`.
pub fn check_header_format(kind: &str, header_format: Option<&str>) -> ConfigResult<Option<String>> {
    let Some(header_format) = header_format.filter(|f| !f.is_empty()) else {
        return Ok(None);
    };
    if kind != "api_key_header" {
        return Err(refused(format!(
            "A header format only applies to kind 'api_key_header', not {}.",
            repr_str(kind)
        )));
    }
    if header_format.chars().count() > 256 {
        return Err(refused("A header format must be at most 256 characters."));
    }
    if header_format.matches(VALUE_PLACEHOLDER).count() != 1 {
        return Err(refused(format!(
            "A header format must contain {VALUE_PLACEHOLDER} exactly once, \
             e.g. MediaBrowser Token=\"{{value}}\"."
        )));
    }
    if header_format.chars().any(|ch| (ch as u32) < 0x20 || ch as u32 == 0x7f) {
        return Err(refused("A header format must be one line without control characters."));
    }
    Ok(Some(header_format.to_string()))
}

/// The header value a request carries: the secret, or the format with the
/// secret in place of `{value}`.
pub fn format_header_value(header_format: Option<&str>, value: &str) -> String {
    match header_format {
        Some(f) if !f.is_empty() => f.replacen(VALUE_PLACEHOLDER, value, 1),
        _ => value.to_string(),
    }
}

/// A fresh Fernet key, base64 urlsafe -- for `gatekeeper credential-key`.
pub fn generate_master_key() -> String {
    fernet::Fernet::generate_key()
}

/// Python's message for `str.encode("ascii")` failing.
fn ascii_encode_error(raw: &str) -> Option<String> {
    let (pos, ch) = raw.chars().enumerate().find(|(_, c)| !c.is_ascii())?;
    let code = ch as u32;
    let esc = if code < 0x100 {
        format!("\\x{code:02x}")
    } else if code < 0x10000 {
        format!("\\u{code:04x}")
    } else {
        format!("\\U{code:08x}")
    };
    Some(format!(
        "'ascii' codec can't encode character '{esc}' in position {pos}: ordinal not in range(128)"
    ))
}

/// Builds a Fernet the way `cryptography.fernet.Fernet(key)` does
/// (lenient urlsafe base64, exactly 32 bytes).
fn fernet_from_key(raw: &str) -> Result<fernet::Fernet, String> {
    if let Some(err) = ascii_encode_error(raw) {
        return Err(err);
    }
    const MSG: &str = "Fernet key must be 32 url-safe base64-encoded bytes.";
    let bytes = crate::identity::py_b64decode(raw, true).ok_or_else(|| MSG.to_string())?;
    if bytes.len() != 32 {
        return Err(MSG.to_string());
    }
    use base64::Engine as _;
    let canonical = base64::engine::general_purpose::URL_SAFE.encode(&bytes);
    fernet::Fernet::new(&canonical).ok_or_else(|| MSG.to_string())
}

/// Reads the master key from its deploy-time source. Never generated
/// implicitly (FR-10.3). `Ok(None)` if neither source is set.
pub fn load_master_key() -> ConfigResult<Option<String>> {
    let mut raw = std::env::var(KEY_ENV).unwrap_or_default();
    if raw.is_empty() {
        if let Ok(path) = std::env::var(KEY_FILE_ENV) {
            if !path.is_empty() {
                match std::fs::read_to_string(&path) {
                    Ok(text) => raw = text.trim().to_string(),
                    Err(exc) => {
                        return Err(ConfigError::new(format!(
                            "{KEY_FILE_ENV} points at {}, which cannot be read: {}",
                            repr_str(&path),
                            crate::pyfmt::os_error(&exc, &path)
                        )))
                    }
                }
            }
        }
    }
    if raw.is_empty() {
        return Ok(None);
    }
    if let Err(exc) = fernet_from_key(&raw) {
        return Err(ConfigError::new(format!(
            "{KEY_ENV} (or the file named by {KEY_FILE_ENV}) does not hold a \
             valid Fernet key. Generate one with 'gatekeeper credential-key'. ({exc})"
        )));
    }
    Ok(Some(raw))
}

/// What `names()` returns. Structurally excludes any value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMeta {
    pub name: String,
    pub kind: String,
    pub header: Option<String>,
    pub created_at: String,
    pub rotated_at: Option<String>,
    pub in_overlap: bool,
    pub probe_url: Option<String>,
    pub header_format: Option<String>,
    pub probe_status: String,
    pub probe_checked_at: Option<String>,
    pub suspect_status: Option<String>,
    pub suspect_at: Option<String>,
    pub used_by: Vec<String>,
}

/// Internal only: what an executor needs to authenticate a request. Never
/// constructed by, or returned to, the API or the config store. `Debug`
/// masks the values.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedCredential {
    pub name: String,
    pub kind: String,
    pub header: Option<String>,
    pub value: String,
    pub previous_value: Option<String>,
    pub header_format: Option<String>,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("header", &self.header)
            .field("value", &"***")
            .field("previous_value", &self.previous_value.as_ref().map(|_| "***"))
            .field("header_format", &self.header_format)
            .finish()
    }
}

/// UTC, not local time: `resolve` compares `previous_expires_at > now()` as
/// strings, which is only monotonic across a fixed offset.
pub fn now() -> String {
    crate::timeutil::now_utc_iso()
}

fn classify_probe_status(status_code: u16) -> &'static str {
    if (200..300).contains(&status_code) {
        "verified"
    } else if status_code == 401 || status_code == 403 {
        "auth_failed"
    } else {
        "unreachable"
    }
}

/// Python truthiness of an optional YAML value.
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

/// `spec.get(key)` as an optional string (non-strings via `str()`).
fn opt_str(spec: &Value, key: &str) -> Option<String> {
    match spec.get(key) {
        None | Some(Value::Null) => None,
        Some(v) => Some(str_value(v)),
    }
}

/// `str(spec.get(key, default))`.
fn str_or(spec: &Value, key: &str, default: &str) -> String {
    match spec.get(key) {
        None => default.to_string(),
        Some(v) => str_value(v),
    }
}

fn opt_value(v: Option<&str>) -> Value {
    match v {
        Some(s) => Value::String(s.to_string()),
        None => Value::Null,
    }
}

pub type OnChange = Arc<dyn Fn() + Send + Sync>;

/// Owns `credentials.yaml`. Parallel to the config store, deliberately
/// separate: mixing credential writes into the same type as tool/identity
/// writes would make it one accidental refactor away from a read path.
pub struct CredentialStore {
    pub path: String,
    pub audit: Arc<AuditLog>,
    /// Called after create/rotate/delete (every file write) so the caller
    /// can refresh whatever needs the current plaintext set (the audit-log
    /// Redactor). Never told *which* value changed.
    on_change: RwLock<Option<OnChange>>,
    lock: Mutex<()>,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore").field("path", &self.path).finish()
    }
}

type Section = Map<String, Value>;

impl CredentialStore {
    pub fn new(path: &str, audit: Arc<AuditLog>) -> CredentialStore {
        CredentialStore {
            path: path.to_string(),
            audit,
            on_change: RwLock::new(None),
            lock: Mutex::new(()),
        }
    }

    pub fn with_on_change(path: &str, audit: Arc<AuditLog>, on_change: OnChange) -> CredentialStore {
        let store = CredentialStore::new(path, audit);
        store.set_on_change(Some(on_change));
        store
    }

    /// Installs (or clears) the change hook -- after construction, so the
    /// hook can hold a `Weak` to the store itself.
    pub fn set_on_change(&self, on_change: Option<OnChange>) {
        *self.on_change.write().unwrap_or_else(|e| e.into_inner()) = on_change;
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn audit_write(&self, entry: Value) -> ConfigResult<()> {
        // PORT NOTE: Python let the OSError of a failed audit write escape;
        // here it is a ConfigError with the same effect (the call fails).
        self.audit
            .write(entry)
            .map_err(|e| ConfigError::new(format!("The audit log could not be written: {e}")))
    }

    // -- Loading -----------------------------------------------------------

    /// The `credentials` section, `{}` for a missing file. Raw: holds the
    /// ciphertexts, so it never leaves this module except in tests.
    pub fn raw(&self) -> ConfigResult<Section> {
        if !std::path::Path::new(&self.path).exists() {
            return Ok(Map::new());
        }
        let text = std::fs::read_to_string(&self.path).map_err(|e| {
            ConfigError::new(format!("{} cannot be read: {}", self.path, crate::pyfmt::os_error(&e, &self.path)))
        })?;
        let data = atomic::safe_load(&text).map_err(|e| ConfigError::new(format!("{}: {e}", self.path)))?;
        let section = match &data {
            Value::Object(map) => map.get("credentials").cloned().unwrap_or(Value::Null),
            _ => Value::Null,
        };
        if !truthy(Some(&section)) {
            return Ok(Map::new());
        }
        match section {
            Value::Object(map) => Ok(map),
            _ => Err(ConfigError::new(format!("{}: section 'credentials' must be a mapping", self.path))),
        }
    }

    fn write_section(&self, section: Section) -> ConfigResult<()> {
        let mut payload = Map::new();
        payload.insert("credentials".into(), Value::Object(section));
        atomic::atomic_write_cfg(&self.path, &atomic::dump(&Value::Object(payload)))?;
        let hook = self.on_change.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(hook) = hook {
            hook();
        }
        Ok(())
    }

    pub fn revision(&self) -> String {
        atomic::revision(&self.path)
    }

    /// Runs the change hook for a write made by another process
    /// (`gatekeeper credential-set` next to a running server): the server
    /// calls it on SIGHUP, so output masking and executor caches follow.
    pub fn notify_changed(&self) {
        let hook = self.on_change.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    pub fn writable(&self) -> bool {
        atomic::writable(&self.path)
    }

    /// Fingerprint of one slot's identity fields, "" if it does not exist
    /// -- the per-record staleness gate for a pending `cred_update`. Never
    /// covers the ciphertext.
    pub fn record_revision(&self, name: &str) -> ConfigResult<String> {
        let section = self.raw()?;
        let Some(spec) = section.get(name) else {
            return Ok(String::new());
        };
        let mut record = Map::new();
        for field in IDENTITY_FIELDS {
            record.insert(field.into(), spec.get(field).cloned().unwrap_or(Value::Null));
        }
        let encoded = crate::pyjson::dumps_with(&Value::Object(record), &crate::pyjson::Opts::python().sorted());
        Ok(atomic::sha256_hex(encoded.as_bytes())[..16].to_string())
    }

    fn check(&self, supplied: &str) -> ConfigResult<()> {
        let current = self.revision();
        if !supplied.is_empty() && !current.is_empty() && supplied != current {
            return Err(refused(
                "The file changed since this form was opened. Reload the page \
                 and apply your edit again -- otherwise it would silently \
                 discard someone else's change.",
            ));
        }
        Ok(())
    }

    // -- Encryption ----------------------------------------------------

    fn fernet(&self) -> ConfigResult<fernet::Fernet> {
        let Some(key) = load_master_key()? else {
            return Err(ConfigError::new(format!(
                "No credential master key is configured ({KEY_ENV} or \
                 {KEY_FILE_ENV}), but {} needs one. Generate a key \
                 with 'gatekeeper credential-key' and set it before starting.",
                self.path
            )));
        };
        fernet_from_key(&key).map_err(ConfigError::new)
    }

    fn encrypt(&self, value: &str) -> ConfigResult<String> {
        Ok(self.fernet()?.encrypt(value.as_bytes()))
    }

    fn decrypt(&self, ciphertext: &str) -> ConfigResult<String> {
        let fernet = self.fernet()?;
        // Python's Fernet.decrypt without a ttl does not check the token's
        // timestamp at all; the crate always rejects tokens from more than
        // 60 s in the future, so pass a "now" no timestamp can exceed.
        let plain = fernet
            .decrypt_at_time(ciphertext, None, u64::MAX - 60)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok());
        plain.ok_or_else(|| {
            ConfigError::new(
                "A credential could not be decrypted -- the master key does \
                 not match the one it was encrypted with.",
            )
        })
    }

    // -- Public, write-only surface -----------------------------------

    /// Metadata only -- FR-10.2. `used_by` maps name -> toolkit names that
    /// reference it, purely for display.
    pub fn names(&self, used_by: Option<&HashMap<String, Vec<String>>>) -> ConfigResult<Vec<CredentialMeta>> {
        let mut metas = Vec::new();
        for (name, spec) in self.raw()? {
            metas.push(CredentialMeta {
                kind: str_or(&spec, "kind", ""),
                header: opt_str(&spec, "header"),
                created_at: str_or(&spec, "created_at", ""),
                rotated_at: opt_str(&spec, "rotated_at"),
                in_overlap: truthy(spec.get("previous_ciphertext")),
                probe_url: opt_str(&spec, "probe_url"),
                header_format: opt_str(&spec, "header_format"),
                probe_status: if truthy(spec.get("probe_status")) {
                    str_or(&spec, "probe_status", "")
                } else {
                    "no_probe_url".to_string()
                },
                probe_checked_at: opt_str(&spec, "probe_checked_at"),
                suspect_status: opt_str(&spec, "suspect_status"),
                suspect_at: opt_str(&spec, "suspect_at"),
                used_by: used_by.and_then(|m| m.get(&name)).cloned().unwrap_or_default(),
                name,
            });
        }
        metas.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(metas)
    }

    /// Creates a slot. Audits name and kind only -- never the value.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        name: &str,
        kind: &str,
        value: &str,
        header: Option<&str>,
        probe_url: Option<&str>,
        header_format: Option<&str>,
        actor: &str,
        rev: &str,
    ) -> ConfigResult<()> {
        if !is_kind(kind) {
            return Err(refused(format!(
                "Unknown credential kind {} (allowed: {})",
                repr_str(kind),
                repr_sorted(KINDS)
            )));
        }
        if HEADER_KINDS.contains(&kind) && header.is_none_or(str::is_empty) {
            return Err(refused(format!("kind {} requires a header/param name", repr_str(kind))));
        }
        let header_format = check_header_format(kind, header_format)?;
        if value.is_empty() {
            return Err(refused("A credential needs a value"));
        }
        let probe_url = probe_url.map(str::trim).filter(|u| !u.is_empty());
        if let Some(url) = probe_url {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(refused("probe_url must be an http(s) URL"));
            }
        }
        {
            let _guard = self.guard();
            self.check(rev)?;
            let mut section = self.raw()?;
            if section.contains_key(name) {
                return Err(refused(format!("A credential named {} already exists.", repr_str(name))));
            }
            let mut spec = Map::new();
            spec.insert("kind".into(), kind.into());
            spec.insert("header".into(), opt_value(header));
            spec.insert("header_format".into(), opt_value(header_format.as_deref()));
            spec.insert("ciphertext".into(), self.encrypt(value)?.into());
            spec.insert("created_at".into(), now().into());
            spec.insert("rotated_at".into(), Value::Null);
            spec.insert("previous_ciphertext".into(), Value::Null);
            spec.insert("previous_expires_at".into(), Value::Null);
            spec.insert("probe_url".into(), opt_value(probe_url));
            spec.insert("probe_status".into(), "no_probe_url".into());
            spec.insert("probe_checked_at".into(), Value::Null);
            spec.insert("suspect_status".into(), Value::Null);
            spec.insert("suspect_at".into(), Value::Null);
            section.insert(name.to_string(), Value::Object(spec));
            self.write_section(section)?;
        }
        let mut entry = Map::new();
        entry.insert("kind".into(), "admin_change".into());
        entry.insert("actor".into(), actor.into());
        entry.insert("action".into(), "credential_create".into());
        entry.insert("target".into(), name.into());
        entry.insert("credential_kind".into(), kind.into());
        if let Some(f) = &header_format {
            entry.insert("header_format".into(), f.clone().into());
        }
        self.audit_write(Value::Object(entry))
    }

    /// Replaces a slot's value; with `overlap_seconds > 0` the old value
    /// keeps resolving until the window ends.
    pub fn rotate(&self, name: &str, value: &str, overlap_seconds: i64, actor: &str, rev: &str) -> ConfigResult<()> {
        if value.is_empty() {
            return Err(refused("A credential needs a value"));
        }
        if overlap_seconds < 0 {
            return Err(refused("overlap_seconds must not be negative"));
        }
        {
            let _guard = self.guard();
            self.check(rev)?;
            let mut section = self.raw()?;
            let Some(existing) = section.get(name).cloned() else {
                return Err(refused(format!("No credential named {}.", repr_str(name))));
            };
            let mut updated = existing.as_object().cloned().unwrap_or_default();
            let previous_ciphertext = if overlap_seconds > 0 {
                // PORT NOTE: Python raised KeyError for a slot without
                // `ciphertext`; it carries null here.
                existing.get("ciphertext").cloned().unwrap_or(Value::Null)
            } else {
                Value::Null
            };
            let previous_expires_at = if overlap_seconds > 0 {
                // UTC, same reasoning as `now`.
                let at = chrono::Utc::now() + chrono::Duration::seconds(overlap_seconds);
                Value::String(at.format("%Y-%m-%dT%H:%M:%S%z").to_string())
            } else {
                Value::Null
            };
            updated.insert("ciphertext".into(), self.encrypt(value)?.into());
            updated.insert("rotated_at".into(), now().into());
            updated.insert("previous_ciphertext".into(), previous_ciphertext);
            updated.insert("previous_expires_at".into(), previous_expires_at);
            let probe_status = if truthy(existing.get("probe_url")) { "unreachable" } else { "no_probe_url" };
            updated.insert("probe_status".into(), probe_status.into());
            updated.insert("probe_checked_at".into(), Value::Null);
            updated.insert("suspect_status".into(), Value::Null);
            updated.insert("suspect_at".into(), Value::Null);
            section.insert(name.to_string(), Value::Object(updated));
            self.write_section(section)?;
        }
        let mut entry = Map::new();
        entry.insert("kind".into(), "admin_change".into());
        entry.insert("actor".into(), actor.into());
        entry.insert("action".into(), "credential_rotate".into());
        entry.insert("target".into(), name.into());
        entry.insert("overlap_seconds".into(), overlap_seconds.into());
        self.audit_write(Value::Object(entry))
    }

    /// Changes a slot's name, kind, header and probe URL in place, keeping
    /// its value (and any rotation overlap) untouched. The value is never
    /// decrypted here. Binding checks are the caller's business.
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &self,
        name: &str,
        kind: &str,
        header: Option<&str>,
        probe_url: Option<&str>,
        new_name: Option<&str>,
        header_format: Option<&str>,
        actor: &str,
        rev: &str,
    ) -> ConfigResult<()> {
        if !is_kind(kind) {
            return Err(refused(format!(
                "Unknown credential kind {} (allowed: {})",
                repr_str(kind),
                repr_sorted(KINDS)
            )));
        }
        let header = header.filter(|h| !h.is_empty());
        if HEADER_KINDS.contains(&kind) && header.is_none() {
            return Err(refused(format!("kind {} requires a header/param name", repr_str(kind))));
        }
        if let Some(h) = header {
            if !is_header_name(h) {
                return Err(refused(format!("{} is not a valid header/param name", repr_str(h))));
            }
        }
        let header_format = check_header_format(kind, header_format)?;
        let probe_url = probe_url.map(str::trim).filter(|u| !u.is_empty());
        if let Some(url) = probe_url {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(refused("probe_url must be an http(s) URL"));
            }
        }
        let target = new_name.filter(|n| !n.is_empty()).unwrap_or(name).to_string();
        let changed: Vec<String>;
        {
            let _guard = self.guard();
            self.check(rev)?;
            let section = self.raw()?;
            let Some(existing) = section.get(name).cloned() else {
                return Err(refused(format!("No credential named {}.", repr_str(name))));
            };
            let old_kind = str_or(&existing, "kind", "");
            if value_shape(&old_kind) != value_shape(kind) {
                return Err(refused(format!(
                    "Cannot change {} from {} to {}: the stored value is a {}, and \
                     {} needs a {}. Create a new credential for that instead.",
                    repr_str(name),
                    repr_str(&old_kind),
                    repr_str(kind),
                    value_shape(&old_kind).unwrap_or("value"),
                    repr_str(kind),
                    value_shape(kind).unwrap_or("value"),
                )));
            }
            if target != name && section.contains_key(&target) {
                return Err(refused(format!("A credential named {} already exists.", repr_str(&target))));
            }
            let fields: [(&str, Value); 4] = [
                ("kind", Value::String(kind.to_string())),
                ("header", opt_value(header)),
                ("header_format", opt_value(header_format.as_deref())),
                ("probe_url", opt_value(probe_url)),
            ];
            let mut list: Vec<String> = fields
                .iter()
                .filter(|(field, new)| existing.get(*field).unwrap_or(&Value::Null) != new)
                .map(|(field, _)| field.to_string())
                .collect();
            if target != name {
                list.insert(0, "name".into());
            }
            changed = list;
            let mut updated = existing.as_object().cloned().unwrap_or_default();
            for (field, new) in fields {
                updated.insert(field.into(), new);
            }
            // The old verdicts were about the old header/kind.
            updated.insert(
                "probe_status".into(),
                if probe_url.is_some() { "unreachable" } else { "no_probe_url" }.into(),
            );
            updated.insert("probe_checked_at".into(), Value::Null);
            updated.insert("suspect_status".into(), Value::Null);
            updated.insert("suspect_at".into(), Value::Null);
            // Rebuilt rather than remove/insert so a rename keeps the slot's
            // place in the file.
            let mut rebuilt = Map::new();
            let mut updated = Some(Value::Object(updated));
            for (key, spec) in section {
                if key == name {
                    rebuilt.insert(target.clone(), updated.take().unwrap_or(Value::Null));
                } else {
                    rebuilt.insert(key, spec);
                }
            }
            self.write_section(rebuilt)?;
        }
        let mut entry = Map::new();
        entry.insert("kind".into(), "admin_change".into());
        entry.insert("actor".into(), actor.into());
        entry.insert("action".into(), "credential_update".into());
        entry.insert("target".into(), name.into());
        entry.insert("credential_kind".into(), kind.into());
        entry.insert("header".into(), opt_value(header));
        entry.insert("header_format".into(), opt_value(header_format.as_deref()));
        entry.insert("changed".into(), changed.into());
        if target != name {
            entry.insert("new_name".into(), target.into());
        }
        self.audit_write(Value::Object(entry))
    }

    pub fn delete(&self, name: &str, actor: &str, rev: &str) -> ConfigResult<()> {
        {
            let _guard = self.guard();
            self.check(rev)?;
            let mut section = self.raw()?;
            if section.shift_remove(name).is_none() {
                return Err(refused(format!("No credential named {}.", repr_str(name))));
            }
            self.write_section(section)?;
        }
        let mut entry = Map::new();
        entry.insert("kind".into(), "admin_change".into());
        entry.insert("actor".into(), actor.into());
        entry.insert("action".into(), "credential_delete".into());
        entry.insert("target".into(), name.into());
        self.audit_write(Value::Object(entry))
    }

    /// All current *and* in-overlap plaintext values, for the audit
    /// Redactor (FR-10.6) -- an unordered bag of strings, never tied to a
    /// name. A missing/wrong master key is an error, not an empty bag.
    pub fn plaintext_values_for_masking(&self) -> ConfigResult<Vec<String>> {
        let section = self.raw()?;
        if section.is_empty() {
            return Ok(Vec::new());
        }
        self.fernet()?;
        let mut values = Vec::new();
        for spec in section.values() {
            if truthy(spec.get("ciphertext")) {
                values.push(self.decrypt(&str_or(spec, "ciphertext", ""))?);
            }
            if truthy(spec.get("previous_ciphertext")) {
                values.push(self.decrypt(&str_or(spec, "previous_ciphertext", ""))?);
            }
        }
        Ok(values)
    }

    /// Detection-only credential probe: one GET, no retries, carrying the
    /// credential exactly as an `http` tool would ([`probe_auth`]). Only
    /// display metadata is persisted.
    pub async fn probe_credential(&self, name: &str) -> ConfigResult<String> {
        let resolved = self.resolve(name)?;
        let probe_url = {
            let _guard = self.guard();
            match self.raw()?.get(name) {
                Some(spec) if truthy(spec.get("probe_url")) => str_or(spec, "probe_url", ""),
                _ => String::new(),
            }
        };
        let status = match resolved {
            Some(resolved) if !probe_url.is_empty() => probe(&probe_url, &resolved).await,
            _ => "no_probe_url",
        };

        let checked_at = now();
        {
            let _guard = self.guard();
            let mut section = self.raw()?;
            if let Some(existing) = section.get(name).cloned() {
                let mut updated = existing.as_object().cloned().unwrap_or_default();
                updated.insert("probe_status".into(), status.into());
                updated.insert("probe_checked_at".into(), checked_at.into());
                section.insert(name.to_string(), Value::Object(updated));
                self.write_section(section)?;
            }
        }
        Ok(status.to_string())
    }

    /// Records display-only suspicion metadata after an auth failure.
    pub fn mark_suspect(&self, name: &str, status: &str) -> ConfigResult<()> {
        let _guard = self.guard();
        let mut section = self.raw()?;
        let Some(existing) = section.get(name).cloned() else {
            return Ok(());
        };
        let mut updated = existing.as_object().cloned().unwrap_or_default();
        updated.insert("suspect_status".into(), status.into());
        updated.insert("suspect_at".into(), now().into());
        section.insert(name.to_string(), Value::Object(updated));
        self.write_section(section)
    }

    // -- Internal: the only decrypt point used by executors ---------------

    /// Python's `_resolve`. Used only by the http/ssh/truenas/opencode
    /// executors, the service's docker TLS and google token
    /// materialization, this store's own probe, and the OAuth sign-in's
    /// client lookup. Nothing in `api` or the config store may call it, and
    /// no value it returns may reach a response, a page or the audit log
    /// (FR-10.2/10.7).
    pub fn resolve(&self, name: &str) -> ConfigResult<Option<ResolvedCredential>> {
        let section = self.raw()?;
        let Some(spec) = section.get(name) else {
            return Ok(None);
        };
        let mut previous_value = None;
        let expires_at = opt_str(spec, "previous_expires_at");
        if truthy(spec.get("previous_ciphertext")) {
            if let Some(expires_at) = expires_at.filter(|e| !e.is_empty()) {
                if expires_at > now() {
                    previous_value = Some(self.decrypt(&str_or(spec, "previous_ciphertext", ""))?);
                }
            }
        }
        // PORT NOTE: Python raised KeyError for a slot without `ciphertext`;
        // it is the decrypt error here.
        let ciphertext = str_or(spec, "ciphertext", "");
        Ok(Some(ResolvedCredential {
            name: name.to_string(),
            kind: str_or(spec, "kind", ""),
            header: opt_str(spec, "header"),
            value: self.decrypt(&ciphertext)?,
            previous_value,
            header_format: opt_str(spec, "header_format"),
        }))
    }
}

/// The headers and query parameters a probe sends: for every kind an
/// `http` tool authenticates with (`api_key_header` with its
/// `header_format`, `bearer`, `basic`, `url_query`), the very
/// `credential_headers`/`credential_query` the executor calls, so a probe
/// cannot pass with a header the tools never send (1.22.0). The other
/// kinds never reach an http request; they keep the `Bearer` GET the probe
/// always sent, which is how a TrueNAS REST API, say, takes the key.
pub fn probe_auth(credential: &ResolvedCredential) -> (Vec<(String, String)>, Vec<(String, String)>) {
    use crate::execute::http::{credential_headers, credential_query};
    if matches!(credential.kind.as_str(), "api_key_header" | "bearer" | "basic" | "url_query") {
        return (credential_headers(Some(credential)), credential_query(Some(credential)));
    }
    (vec![("Authorization".into(), format!("Bearer {}", credential.value))], Vec::new())
}

/// Why a slot is likely to fail every call, from its metadata alone; for
/// `cred_list` and the console. Never looks at the value.
pub fn credential_warnings(meta: &CredentialMeta) -> Vec<String> {
    let mut warnings = Vec::new();
    let authorization = meta.header.as_deref().is_some_and(|h| h.eq_ignore_ascii_case("authorization"));
    if meta.kind == "api_key_header" && authorization && meta.header_format.as_deref().is_none_or(str::is_empty) {
        warnings.push(
            "Sent as 'Authorization: <value>' with no scheme: this slot has no header_format. Most APIs \
             want 'Bearer {value}' (or 'token {value}'); set header_format, or use kind 'bearer'."
                .to_string(),
        );
    }
    warnings
}

/// One `GET probe_url` with the credential as [`probe_auth`] builds it,
/// TLS verified, 3 s timeout. Any transport failure is `unreachable`.
async fn probe(url: &str, credential: &ResolvedCredential) -> &'static str {
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(3)).build() {
        Ok(c) => c,
        Err(_) => return "unreachable",
    };
    let (headers, query) = probe_auth(credential);
    let mut request = client.get(url);
    if !query.is_empty() {
        request = request.query(&query);
    }
    for (name, value) in headers {
        request = request.header(name, value);
    }
    match request.send().await {
        Ok(response) => classify_probe_status(response.status().as_u16()),
        Err(_) => "unreachable",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Serializes tests that touch the master-key environment variables.
    pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) struct Env {
        pub dir: tempfile::TempDir,
        pub store: CredentialStore,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Env {
        pub fn audit_lines(&self) -> Vec<Value> {
            std::fs::read_to_string(self.store.audit.path())
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    pub(crate) fn env() -> Env {
        let guard = env_lock();
        std::env::remove_var(KEY_FILE_ENV);
        std::env::set_var(KEY_ENV, generate_master_key());
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::new(dir.path().join("logs").to_str().unwrap()).unwrap());
        let store = CredentialStore::new(dir.path().join("credentials.yaml").to_str().unwrap(), audit);
        Env { dir, store, _guard: guard }
    }

    fn create_sonarr(store: &CredentialStore, value: &str) {
        store
            .create("sonarr", "api_key_header", value, Some("X-Api-Key"), None, None, "admin", "")
            .unwrap();
    }

    #[test]
    fn create_never_returns_a_value() {
        let e = env();
        create_sonarr(&e.store, "super-secret-key");
        let metas = e.store.names(None).unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].name, "sonarr");
        assert_eq!(metas[0].kind, "api_key_header");
        assert!(!format!("{:?}", metas[0]).contains("super-secret-key"));
        let resolved = e.store.resolve("sonarr").unwrap().unwrap();
        assert!(!format!("{resolved:?}").contains("super-secret-key"));
    }

    #[test]
    fn create_refusals() {
        let e = env();
        create_sonarr(&e.store, "a");
        let err = e.store.create("sonarr", "api_key_header", "b", Some("X-Api-Key"), None, None, "x", "").unwrap_err();
        assert!(err.is_write_refused());
        assert_eq!(err.message, "A credential named 'sonarr' already exists.");
        let err = e.store.create("x", "not_a_kind", "a", None, None, None, "x", "").unwrap_err();
        assert_eq!(
            err.message,
            "Unknown credential kind 'not_a_kind' (allowed: ['api_key_header', 'basic', 'bearer', 'docker_tls', 'oauth2', 'ssh_password', 'ssh_private_key', 'url_path', 'url_query', 'ws_api_key'])"
        );
        let err = e.store.create("x", "api_key_header", "a", None, None, None, "x", "").unwrap_err();
        assert_eq!(err.message, "kind 'api_key_header' requires a header/param name");
        let err = e.store.create("x", "bearer", "", None, None, None, "x", "").unwrap_err();
        assert_eq!(err.message, "A credential needs a value");
        let err = e.store.create("x", "bearer", "v", None, Some("ftp://x"), None, "x", "").unwrap_err();
        assert_eq!(err.message, "probe_url must be an http(s) URL");
        let err = e.store.create("x", "bearer", "v", None, None, Some("T {value}"), "x", "").unwrap_err();
        assert_eq!(err.message, "A header format only applies to kind 'api_key_header', not 'bearer'.");
    }

    #[test]
    fn resolve_round_trips_internally() {
        let e = env();
        create_sonarr(&e.store, "super-secret-key");
        let resolved = e.store.resolve("sonarr").unwrap().unwrap();
        assert_eq!(resolved.value, "super-secret-key");
        assert_eq!(resolved.header.as_deref(), Some("X-Api-Key"));
        assert!(e.store.resolve("nope").unwrap().is_none());
    }

    #[test]
    fn rotation_with_and_without_overlap() {
        let e = env();
        create_sonarr(&e.store, "old");
        e.store.rotate("sonarr", "new", 3600, "x", &e.store.revision()).unwrap();
        let resolved = e.store.resolve("sonarr").unwrap().unwrap();
        assert_eq!(resolved.value, "new");
        assert_eq!(resolved.previous_value.as_deref(), Some("old"));
        let meta = &e.store.names(None).unwrap()[0];
        assert!(meta.in_overlap);
        assert!(meta.rotated_at.is_some());
        assert!(now().ends_with("+0000"));
        let raw = e.store.raw().unwrap();
        assert!(raw["sonarr"]["previous_expires_at"].as_str().unwrap().ends_with("+0000"));

        e.store.rotate("sonarr", "newer", 0, "x", &e.store.revision()).unwrap();
        let resolved = e.store.resolve("sonarr").unwrap().unwrap();
        assert_eq!(resolved.value, "newer");
        assert!(resolved.previous_value.is_none());

        let err = e.store.rotate("nope", "x", 0, "x", "").unwrap_err();
        assert_eq!(err.message, "No credential named 'nope'.");
        let err = e.store.rotate("sonarr", "x", -1, "x", "").unwrap_err();
        assert_eq!(err.message, "overlap_seconds must not be negative");
    }

    #[test]
    fn delete_and_concurrency_check() {
        let e = env();
        create_sonarr(&e.store, "a");
        let err = e.store.rotate("sonarr", "b", 0, "x", "stale-revision").unwrap_err();
        assert!(err.is_write_refused());
        assert!(err.message.starts_with("The file changed since this form was opened."));
        e.store.delete("sonarr", "x", &e.store.revision()).unwrap();
        assert!(e.store.names(None).unwrap().is_empty());
        assert!(e.store.resolve("sonarr").unwrap().is_none());
        let err = e.store.delete("nope", "x", "").unwrap_err();
        assert_eq!(err.message, "No credential named 'nope'.");
    }

    #[test]
    fn file_bytes_never_contain_plaintext() {
        let e = env();
        create_sonarr(&e.store, "super-secret-key-xyz");
        let raw = std::fs::read_to_string(&e.store.path).unwrap();
        assert!(!raw.contains("super-secret-key-xyz"));
        assert!(raw.starts_with(atomic::HEADER));
    }

    #[test]
    fn missing_and_wrong_master_key() {
        let e = env();
        create_sonarr(&e.store, "a");
        std::env::remove_var(KEY_ENV);
        let err = e.store.resolve("sonarr").unwrap_err();
        assert!(err.message.starts_with("No credential master key is configured"));
        std::env::set_var(KEY_ENV, generate_master_key());
        let err = e.store.resolve("sonarr").unwrap_err();
        assert_eq!(
            err.message,
            "A credential could not be decrypted -- the master key does not match the one it was encrypted with."
        );
        std::env::set_var(KEY_ENV, "not-a-key");
        let err = e.store.resolve("sonarr").unwrap_err();
        assert_eq!(
            err.message,
            "GATEKEEPER_CREDENTIAL_KEY (or the file named by GATEKEEPER_CREDENTIAL_KEY_FILE) does not hold a valid Fernet key. Generate one with 'gatekeeper credential-key'. (Fernet key must be 32 url-safe base64-encoded bytes.)"
        );
    }

    #[test]
    fn key_file_and_lenient_key() {
        let e = env();
        let key = generate_master_key();
        let key_path = e.dir.path().join("key");
        std::fs::write(&key_path, format!("{key}\n")).unwrap();
        std::env::remove_var(KEY_ENV);
        std::env::set_var(KEY_FILE_ENV, &key_path);
        create_sonarr(&e.store, "v");
        assert_eq!(e.store.resolve("sonarr").unwrap().unwrap().value, "v");
        // A trailing newline in the env var is tolerated, as by Python's
        // non-strict base64.
        std::env::remove_var(KEY_FILE_ENV);
        std::env::set_var(KEY_ENV, format!("{key}\n"));
        assert_eq!(e.store.resolve("sonarr").unwrap().unwrap().value, "v");
        std::env::remove_var(KEY_ENV);
        std::env::set_var(KEY_FILE_ENV, e.dir.path().join("missing"));
        let err = load_master_key().unwrap_err();
        assert!(err.message.starts_with("GATEKEEPER_CREDENTIAL_KEY_FILE points at '"), "{}", err.message);
        assert!(err.message.contains("which cannot be read: [Errno 2] No such file or directory: '"), "{}", err.message);
        std::env::remove_var(KEY_FILE_ENV);
    }

    #[test]
    fn empty_store_needs_no_key() {
        let e = env();
        std::env::remove_var(KEY_ENV);
        assert!(e.store.names(None).unwrap().is_empty());
        assert!(e.store.plaintext_values_for_masking().unwrap().is_empty());
    }

    #[test]
    fn masking_scrubs_secret_from_audit_log() {
        let e = env();
        let redactor = e.store.audit.redactor().clone();
        let store = Arc::new(CredentialStore::new(&e.store.path, e.store.audit.clone()));
        let weak = Arc::downgrade(&store);
        store.set_on_change(Some(Arc::new(move || {
            if let Some(s) = weak.upgrade() {
                redactor.set_secrets(s.plaintext_values_for_masking().unwrap());
            }
        })));
        create_sonarr(&store, "super-secret-key-xyz");
        assert_eq!(store.audit.redact("the response was super-secret-key-xyz"), "the response was ***");
        store.audit.write(serde_json::json!({"kind": "call", "detail": "leaked super-secret-key-xyz here"})).unwrap();
        let lines = e.audit_lines();
        assert!(lines.iter().any(|l| l["action"] == "credential_create"));
        assert!(lines.iter().all(|l| !l.to_string().contains("super-secret-key-xyz")));
    }

    #[test]
    fn mark_suspect_preserves_secret() {
        let e = env();
        e.store.create("probe", "bearer", "secret-token", None, None, None, "admin", "").unwrap();
        let before = e.store.raw().unwrap()["probe"]["ciphertext"].clone();
        let rev = e.store.record_revision("probe").unwrap();
        e.store.mark_suspect("probe", "auth_failed").unwrap();
        let meta = &e.store.names(None).unwrap()[0];
        assert_eq!(meta.suspect_status.as_deref(), Some("auth_failed"));
        assert!(meta.suspect_at.is_some());
        assert_eq!(e.store.raw().unwrap()["probe"]["ciphertext"], before);
        assert_eq!(e.store.resolve("probe").unwrap().unwrap().value, "secret-token");
        // Suspicion is not part of the slot's identity.
        assert_eq!(e.store.record_revision("probe").unwrap(), rev);
        assert_eq!(e.store.record_revision("nope").unwrap(), "");
        e.store.mark_suspect("nope", "auth_failed").unwrap();
    }

    #[test]
    fn header_format_checks() {
        assert_eq!(check_header_format("api_key_header", None).unwrap(), None);
        assert_eq!(check_header_format("bearer", Some("")).unwrap(), None);
        assert_eq!(
            check_header_format("api_key_header", Some("MediaBrowser Token=\"{value}\"")).unwrap().as_deref(),
            Some("MediaBrowser Token=\"{value}\"")
        );
        for (f, reason) in [
            ("MediaBrowser Token=x", "exactly once"),
            ("{value} {value}", "exactly once"),
            ("MediaBrowser Token=\"{value}\"\r\nX-Evil: 1", "one line"),
        ] {
            let err = check_header_format("api_key_header", Some(f)).unwrap_err();
            assert!(err.message.contains(reason), "{}", err.message);
        }
        let long = format!("{}{{value}}", "x".repeat(250));
        assert_eq!(check_header_format("api_key_header", Some(&long)).unwrap_err().message, "A header format must be at most 256 characters.");
        assert_eq!(
            check_header_format("api_key_header", Some("x")).unwrap_err().message,
            "A header format must contain {value} exactly once, e.g. MediaBrowser Token=\"{value}\"."
        );
        assert_eq!(format_header_value(Some("Token {value}"), "s"), "Token s");
        assert_eq!(format_header_value(None, "s"), "s");
    }

    // -- update (store-level parts of test_cred_update.py) -----------------

    const SECRET: &str = "jellyfin-token-0123456789abcdef";

    fn jellyfin() -> Env {
        let e = env();
        e.store.create("jellyfin", "api_key_header", SECRET, Some("X-Emby-Token"), None, None, "root", "").unwrap();
        e
    }

    fn last_update(e: &Env) -> Value {
        e.audit_lines().into_iter().filter(|l| l["action"] == "credential_update").last().unwrap()
    }

    #[test]
    fn header_repair_keeps_the_value() {
        let e = jellyfin();
        e.store.mark_suspect("jellyfin", "auth_failed").unwrap();
        e.store
            .update("jellyfin", "api_key_header", Some("Authorization"), None, None, None, "root", &e.store.revision())
            .unwrap();
        let meta = &e.store.names(None).unwrap()[0];
        assert_eq!((meta.kind.as_str(), meta.header.as_deref()), ("api_key_header", Some("Authorization")));
        assert_eq!(meta.suspect_status, None);
        assert_eq!(e.store.resolve("jellyfin").unwrap().unwrap().value, SECRET);
        let update = last_update(&e);
        assert_eq!(update["target"], "jellyfin");
        assert_eq!(update["header"], "Authorization");
        assert_eq!(update["changed"], serde_json::json!(["header"]));
        assert!(e.audit_lines().iter().all(|l| !l.to_string().contains(SECRET)));
    }

    #[test]
    fn kind_changes_only_within_one_value_shape() {
        let e = jellyfin();
        let err = e.store.update("jellyfin", "oauth2", None, None, None, None, "root", &e.store.revision()).unwrap_err();
        assert!(err.is_write_refused());
        assert_eq!(
            err.message,
            "Cannot change 'jellyfin' from 'api_key_header' to 'oauth2': the stored value is a token, and 'oauth2' needs a OAuth2 bundle. Create a new credential for that instead."
        );
        e.store.update("jellyfin", "bearer", None, None, None, None, "root", "").unwrap();
        let meta = &e.store.names(None).unwrap()[0];
        assert_eq!((meta.kind.as_str(), meta.header.as_deref()), ("bearer", None));
    }

    #[test]
    fn update_refusals() {
        let e = jellyfin();
        for header in ["X-Token\r\nX-Evil: 1", "Bad Header", "a:b", "X-Token\n"] {
            let err = e.store.update("jellyfin", "api_key_header", Some(header), None, None, None, "root", "").unwrap_err();
            assert!(err.message.contains("is not a valid header/param name"), "{}", err.message);
        }
        let err = e.store.update("nope", "bearer", None, None, None, None, "root", "").unwrap_err();
        assert_eq!(err.message, "No credential named 'nope'.");
        let err = e.store.update("jellyfin", "url_query", None, None, None, None, "root", "").unwrap_err();
        assert_eq!(err.message, "kind 'url_query' requires a header/param name");
        e.store.create("emby", "bearer", "other", None, None, None, "root", "").unwrap();
        let err = e.store.update("jellyfin", "api_key_header", Some("X"), None, Some("emby"), None, "root", "").unwrap_err();
        assert_eq!(err.message, "A credential named 'emby' already exists.");
    }

    #[test]
    fn rename_keeps_the_value_and_the_place() {
        let e = jellyfin();
        e.store.create("zzz", "bearer", "other", None, None, None, "root", "").unwrap();
        e.store
            .update("jellyfin", "api_key_header", Some("Authorization"), None, Some("jellyfin-main"), None, "root", "")
            .unwrap();
        let keys: Vec<String> = e.store.raw().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["jellyfin-main", "zzz"]);
        assert_eq!(e.store.resolve("jellyfin-main").unwrap().unwrap().value, SECRET);
        let update = last_update(&e);
        assert_eq!(update["new_name"], "jellyfin-main");
        assert_eq!(update["changed"], serde_json::json!(["name", "header"]));
    }

    #[test]
    fn header_format_is_applied_and_dropped() {
        let e = jellyfin();
        e.store
            .update("jellyfin", "api_key_header", Some("Authorization"), None, None, Some("MediaBrowser Token=\"{value}\""), "root", "")
            .unwrap();
        let meta = &e.store.names(None).unwrap()[0];
        assert_eq!(meta.header_format.as_deref(), Some("MediaBrowser Token=\"{value}\""));
        assert_eq!(last_update(&e)["changed"], serde_json::json!(["header", "header_format"]));
        e.store.update("jellyfin", "bearer", None, None, None, None, "root", "").unwrap();
        assert_eq!(e.store.names(None).unwrap()[0].header_format, None);
        assert_eq!(e.store.resolve("jellyfin").unwrap().unwrap().value, SECRET);
    }

    // -- probes ----------------------------------------------------------------

    /// A one-shot HTTP server answering every request with `status`.
    async fn serve(status: u16) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let reply = format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            sock.write_all(reply.as_bytes()).await.unwrap();
            request.lines().map(str::to_string).collect()
        });
        (format!("http://{addr}/me"), handle)
    }

    async fn assert_probe(status: Option<u16>, expected: &str) {
        let e = env();
        let (url, server) = match status {
            Some(s) => {
                let (u, h) = serve(s).await;
                (u, Some(h))
            }
            // Nothing listens on a port we just released.
            None => {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let port = l.local_addr().unwrap().port();
                drop(l);
                (format!("http://127.0.0.1:{port}/me"), None)
            }
        };
        e.store.create("probe", "bearer", "secret-token", None, Some(&url), None, "admin", "").unwrap();
        let before = e.store.raw().unwrap()["probe"]["ciphertext"].clone();
        assert_eq!(e.store.probe_credential("probe").await.unwrap(), expected);
        let after = e.store.raw().unwrap()["probe"].clone();
        assert_eq!(after["ciphertext"], before);
        assert_eq!(after["previous_ciphertext"], Value::Null);
        assert_eq!(e.store.resolve("probe").unwrap().unwrap().value, "secret-token");
        assert_eq!(e.store.names(None).unwrap()[0].probe_status, expected);
        if let Some(server) = server {
            let request = server.await.unwrap();
            assert!(request[0].starts_with("GET /me "));
            assert!(request.iter().any(|l| l.eq_ignore_ascii_case("authorization: Bearer secret-token")));
        }
    }

    #[tokio::test]
    async fn probe_statuses_preserve_secret() {
        assert_probe(Some(204), "verified").await;
        assert_probe(Some(401), "auth_failed").await;
        assert_probe(Some(500), "unreachable").await;
        assert_probe(None, "unreachable").await;
    }

    /// A one-shot server that, like GitHub, takes only `Authorization:
    /// Bearer secret-token` and answers 401 to anything else.
    async fn serve_bearer_only() -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let lines: Vec<String> = String::from_utf8_lossy(&buf[..n]).lines().map(str::to_string).collect();
            let ok = lines.iter().any(|l| l.eq_ignore_ascii_case("authorization: Bearer secret-token"));
            let status = if ok { 200 } else { 401 };
            let reply = format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            sock.write_all(reply.as_bytes()).await.unwrap();
            lines
        });
        (format!("http://{addr}/user"), handle)
    }

    /// 1.22.0: the probe sends what the http tools send. An
    /// `api_key_header` slot on `Authorization` without the `Bearer`
    /// scheme used to probe as "verified" (the probe added `Bearer` on its
    /// own) while every tool call got a 401.
    #[tokio::test]
    async fn probe_sends_the_header_exactly_as_the_tools_do() {
        for (kind, header, format, expected, sent) in [
            ("api_key_header", Some("Authorization"), None, "auth_failed", "authorization: secret-token"),
            ("api_key_header", Some("Authorization"), Some("token {value}"), "auth_failed", "authorization: token secret-token"),
            ("api_key_header", Some("Authorization"), Some("Bearer {value}"), "verified", "authorization: Bearer secret-token"),
            ("bearer", None, None, "verified", "authorization: Bearer secret-token"),
        ] {
            let e = env();
            let (url, server) = serve_bearer_only().await;
            e.store.create("github", kind, "secret-token", header, Some(&url), format, "admin", "").unwrap();
            assert_eq!(e.store.probe_credential("github").await.unwrap(), expected, "{kind} {format:?}");
            let request = server.await.unwrap();
            assert!(request.iter().any(|l| l.eq_ignore_ascii_case(sent)), "{kind} {format:?}: {request:?}");
            // The same function the http executor calls builds it.
            let resolved = e.store.resolve("github").unwrap().unwrap();
            assert_eq!(probe_auth(&resolved).0, crate::execute::http::credential_headers(Some(&resolved)));
        }
    }

    #[tokio::test]
    async fn probe_puts_a_url_query_credential_in_the_query() {
        let e = env();
        let (url, server) = serve(200).await;
        e.store.create("tg", "url_query", "secret-token", Some("apikey"), Some(&url), None, "admin", "").unwrap();
        assert_eq!(e.store.probe_credential("tg").await.unwrap(), "verified");
        let request = server.await.unwrap();
        assert!(request[0].starts_with("GET /me?apikey=secret-token "), "{request:?}");
        assert!(!request.iter().any(|l| l.to_ascii_lowercase().starts_with("authorization:")));
    }

    #[test]
    fn authorization_header_without_a_format_is_warned_about() {
        let e = env();
        e.store.create("github", "api_key_header", "t", Some("Authorization"), None, None, "admin", "").unwrap();
        e.store.create("fine", "api_key_header", "t", Some("authorization"), None, Some("Bearer {value}"), "admin", "").unwrap();
        e.store.create("other", "api_key_header", "t", Some("X-Api-Key"), None, None, "admin", "").unwrap();
        e.store.create("tok", "bearer", "t", None, None, None, "admin", "").unwrap();
        let warned: Vec<String> = e
            .store
            .names(None)
            .unwrap()
            .iter()
            .filter(|m| !credential_warnings(m).is_empty())
            .map(|m| m.name.clone())
            .collect();
        assert_eq!(warned, ["github"]);
    }

    #[tokio::test]
    async fn probe_missing_url_does_not_call_network() {
        let e = env();
        e.store.create("probe", "bearer", "secret-token", None, None, None, "admin", "").unwrap();
        assert_eq!(e.store.probe_credential("probe").await.unwrap(), "no_probe_url");
        let raw = e.store.raw().unwrap();
        assert_eq!(raw["probe"]["probe_status"], "no_probe_url");
        assert!(raw["probe"]["probe_checked_at"].is_string());
        assert_eq!(e.store.probe_credential("nope").await.unwrap(), "no_probe_url");
    }
}
