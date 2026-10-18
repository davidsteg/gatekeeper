//! Identities, tokens, passwords and permissions (port of `identity.py`,
//! REQUIREMENTS.md §4 and §9).
//!
//! An identity carries two separate credentials, and the separation is
//! intentional (FR-11.5):
//!
//! * **Token** -- for the API. Goes as `Authorization: Bearer ...` to `/mcp`
//!   and belongs in an agent's configuration, not in a browser.
//! * **Password** -- for the console at `/app`. Only `viewer` and `admin`
//!   have one; an agent gets none, because it never logs in anywhere.
//!
//! Both are stored exclusively as scrypt hashes (FR-2.4), in the exact
//! `scrypt$n$r$p$<b64 salt>$<b64 dk>` format the Python implementation
//! wrote (standard base64 alphabet, with padding), so an existing
//! `identities.yaml` keeps working byte for byte.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use base64::Engine as _;
use indexmap::IndexMap;
use rand::RngCore;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::errors::{read_config_file, ConfigError, ConfigResult};
use crate::pyfmt::{repr_str, repr_value, str_value};

/// scrypt parameters. n=2**15 costs about 32 MB and ~50 ms -- plenty for a
/// handful of tokens per second, expensive enough for brute force.
pub const SCRYPT_N: u64 = 1 << 15;
pub const SCRYPT_R: u64 = 8;
pub const SCRYPT_P: u64 = 1;
pub const SCRYPT_DKLEN: usize = 32;
/// `maxmem=` passed to `hashlib.scrypt`.
const SCRYPT_MAXMEM: u64 = 64 * 1024 * 1024;

const PREFIX: &str = "scrypt";

/// `viewer` and `admin` distinguish reading and writing in the operations
/// UI. Without this separation, anyone allowed to view the audit log would
/// also have the right to create tools and grant permissions.
pub const ROLES: [&str; 3] = ["agent", "viewer", "admin"];

/// Roles that may sign in to the UI. `agent` is not among them: an agent
/// token is meant for `/mcp` and does not open the console.
pub const UI_ROLES: [&str; 2] = ["viewer", "admin"];

/// Only this role may write.
pub const ADMIN_ROLE: &str = "admin";

/// Minimum length of a console password (in characters).
pub const MIN_PASSWORD_LENGTH: usize = 12;

// -- Python-compatible helpers ---------------------------------------------

/// `secrets.token_bytes(n)`.
pub fn token_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// `secrets.token_urlsafe(n)`: `n` random bytes, urlsafe base64 without
/// padding.
pub fn token_urlsafe(n: usize) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes(n))
}

/// `base64.b64decode(s)` (or `urlsafe_b64decode` with `urlsafe`), with
/// CPython's non-strict `binascii.a2b_base64` rules: characters outside the
/// alphabet are skipped, padding must be complete, and decoding stops at
/// the first complete pad sequence. `None` where Python raises.
pub fn py_b64decode(s: &str, urlsafe: bool) -> Option<Vec<u8>> {
    if !s.is_ascii() {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut quad_pos = 0u8;
    let mut left_char = 0u32;
    let mut pads = 0u8;
    for &byte in s.as_bytes() {
        let ch = match (urlsafe, byte) {
            (true, b'-') => b'+',
            (true, b'_') => b'/',
            (_, b) => b,
        };
        if ch == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    return Some(out);
                }
            }
            continue;
        }
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        } as u32;
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left_char = value;
            }
            1 => {
                quad_pos = 2;
                out.push(((left_char << 2) | (value >> 4)) as u8);
                left_char = value & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push(((left_char << 4) | (value >> 2)) as u8);
                left_char = value & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push(((left_char << 6) | value) as u8);
                left_char = 0;
            }
        }
    }
    if quad_pos != 0 {
        return None;
    }
    Some(out)
}

fn b64encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// `hashlib.scrypt(...)` with the checks that make CPython/OpenSSL raise
/// `ValueError` -- `None` in exactly those cases.
fn py_scrypt(password: &[u8], salt: &[u8], n: u64, r: u64, p: u64, dklen: usize) -> Option<Vec<u8>> {
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 || dklen == 0 {
        return None;
    }
    if r > u32::MAX as u64 || p > u32::MAX as u64 {
        return None;
    }
    // OpenSSL's EVP_PBE_scrypt memory accounting: B (p*128*r) plus
    // V (32*r*(N+2) 32-bit words).
    let blen = p.checked_mul(128)?.checked_mul(r)?;
    let vlen = r.checked_mul(128)?.checked_mul(n.checked_add(2)?)?;
    if blen.checked_add(vlen)? > SCRYPT_MAXMEM {
        return None;
    }
    let log_n = n.trailing_zeros() as u8;
    let params = scrypt::Params::new(log_n, r as u32, p as u32, scrypt::Params::RECOMMENDED_LEN).ok()?;
    let mut out = vec![0u8; dklen];
    scrypt::scrypt(password, salt, &params, &mut out).ok()?;
    Some(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// -- Hashing -----------------------------------------------------------------

/// Produces `scrypt$n$r$p$salt$hash` with a fresh 16-byte salt.
///
/// The same function hashes tokens and passwords -- there is no reason to
/// maintain two methods, and the weaker one would be the one forgotten.
pub fn hash_token(token: &str) -> String {
    hash_token_with_salt(token, &token_bytes(16))
}

/// `hash_token(token, salt=salt)`. An empty salt means "generate one", as
/// in Python (`salt or secrets.token_bytes(16)`).
pub fn hash_token_with_salt(token: &str, salt: &[u8]) -> String {
    let fresh;
    let salt = if salt.is_empty() {
        fresh = token_bytes(16);
        &fresh[..]
    } else {
        salt
    };
    let derived = py_scrypt(token.as_bytes(), salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
        .expect("fixed scrypt parameters are valid");
    [
        PREFIX.to_string(),
        SCRYPT_N.to_string(),
        SCRYPT_R.to_string(),
        SCRYPT_P.to_string(),
        b64encode(salt),
        b64encode(&derived),
    ]
    .join("$")
}

/// `int(s)` for the small non-negative integers of a hash string.
fn py_int(s: &str) -> Option<u64> {
    let t = s.trim();
    let t = t.strip_prefix('+').unwrap_or(t);
    if t.is_empty() || t.starts_with('_') || t.ends_with('_') || t.contains("__") {
        return None;
    }
    let digits: String = t.chars().filter(|c| *c != '_').collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Verifies a token against its hash -- in constant time (FR-2.5).
pub fn verify_token(token: &str, encoded: &str) -> bool {
    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 6 || parts[0] != PREFIX {
        return false;
    }
    let (Some(n), Some(r), Some(p)) = (py_int(parts[1]), py_int(parts[2]), py_int(parts[3])) else {
        return false;
    };
    let (Some(salt), Some(expected)) = (py_b64decode(parts[4], false), py_b64decode(parts[5], false))
    else {
        return false;
    };
    match py_scrypt(token.as_bytes(), &salt, n, r, p, expected.len()) {
        Some(derived) => constant_time_eq(&derived, &expected),
        None => false,
    }
}

/// A fast, deterministic index for [`IdentityStore::authenticate`] (NFR-3
/// addendum -- an unauthenticated caller must not be able to stall the
/// server).
///
/// Plain SHA-256, unsalted and unkeyed -- deliberately, and safely: what it
/// indexes is a [`generate_token`] output with 256 bits of entropy, never a
/// human-chosen secret, so a fast hash is exactly as hard to invert as a
/// slow one.
pub fn hash_token_lookup(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Generates a new agent token.
pub fn generate_token() -> String {
    format!("gk_{}", token_urlsafe(32))
}

/// Generates a console password. Without the `gk_` prefix: the prefix marks
/// an API token, and the two should be distinguishable even in plaintext.
pub fn generate_password() -> String {
    token_urlsafe(18)
}

/// A hash that no password matches, so that a sign-in with an unknown ID
/// takes just as long as one with a known ID. Computed on first use.
fn decoy_hash() -> &'static str {
    static DECOY: OnceLock<String> = OnceLock::new();
    DECOY.get_or_init(|| hash_token(&token_urlsafe(32)))
}

// -- Identities ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub id: String,
    pub role: String,
    pub token_hash: String,
    pub tools: BTreeSet<String>,
    pub scopes: Vec<String>,
    /// Empty means: this identity cannot sign in to the console. For
    /// `agent` this is the normal case.
    pub password_hash: String,
    /// `hash_token_lookup(token)`, or "" for an identity written before this
    /// field existed; `authenticate()` falls back to a direct scrypt check
    /// for exactly those.
    pub token_lookup: String,
}

impl Identity {
    /// May and can this identity sign in to the console? The role allows
    /// it, and a password is set.
    pub fn can_sign_in(&self) -> bool {
        UI_ROLES.contains(&self.role.as_str()) && !self.password_hash.is_empty()
    }

    /// FR-7.5: rights attach to tool IDs, never to a whole toolkit. No
    /// prefix or wildcard matching.
    pub fn may_call(&self, tool_id: &str) -> bool {
        self.tools.contains(tool_id)
    }

    /// Whether this identity holds a grant on the YAML definition
    /// `base_tool_id` names -- the bare id, or any destination expansion
    /// (`base_tool_id@nas1`, FR-8.3h). Display only, never authorization.
    pub fn holds_definition(&self, base_tool_id: &str) -> bool {
        let prefix = format!("{base_tool_id}@");
        self.tools.contains(base_tool_id) || self.tools.iter().any(|t| t.starts_with(&prefix))
    }

    /// Checks a resolved scope against the profile patterns.
    pub fn covers_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|pattern| crate::fnmatch::fnmatchcase(scope, pattern))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityStore {
    /// Keyed by id, in file order.
    pub identities: IndexMap<String, Identity>,
}

impl IdentityStore {
    pub fn new(identities: IndexMap<String, Identity>) -> Self {
        IdentityStore { identities }
    }

    /// Resolves an API token to an identity.
    ///
    /// Indexed identities: one map lookup on `token_lookup`, then scrypt
    /// against only the matching candidate(s). Un-indexed identities (older
    /// files) fall back to the exhaustive scrypt scan, over just those.
    /// Applies exclusively to `/mcp`; the console uses
    /// [`IdentityStore::authenticate_console`].
    pub fn authenticate(&self, token: &str) -> Option<&Identity> {
        let lookup = hash_token_lookup(token);
        let mut by_lookup: std::collections::HashMap<&str, Vec<&Identity>> =
            std::collections::HashMap::new();
        let mut unindexed: Vec<&Identity> = Vec::new();
        for identity in self.identities.values() {
            if identity.token_lookup.is_empty() {
                unindexed.push(identity);
            } else {
                by_lookup.entry(identity.token_lookup.as_str()).or_default().push(identity);
            }
        }

        if let Some(candidates) = by_lookup.get(lookup.as_str()) {
            let mut found = None;
            for identity in candidates {
                if verify_token(token, &identity.token_hash) {
                    found = Some(*identity);
                }
            }
            return found;
        }

        let mut found = None;
        for identity in unindexed {
            if verify_token(token, &identity.token_hash) {
                found = Some(identity);
            }
        }
        found
    }

    /// IDs whose `token_lookup` is this token's, without any scrypt.
    ///
    /// Only asked after [`IdentityStore::authenticate`] has already refused
    /// the token, for the audit record: a match then means the identity's
    /// `token_lookup` and `token_hash` disagree (one was edited by hand, or
    /// copied from a different token) -- a broken entry, not a stranger's
    /// token.
    pub fn lookup_matches(&self, token: &str) -> Vec<String> {
        let lookup = hash_token_lookup(token);
        self.identities.values().filter(|i| i.token_lookup == lookup).map(|i| i.id.clone()).collect()
    }

    /// Checks ID and password for sign-in to the console (`/app`). For an
    /// unknown ID scrypt is still computed once, against a decoy hash, so
    /// the response time is no directory of console accounts.
    pub fn authenticate_console(&self, identity_id: &str, password: &str) -> Option<&Identity> {
        match self.identities.get(identity_id) {
            Some(identity) if identity.can_sign_in() => {
                if verify_token(password, &identity.password_hash) {
                    Some(identity)
                } else {
                    None
                }
            }
            _ => {
                verify_token(password, decoy_hash());
                None
            }
        }
    }
}

fn get<'a>(spec: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    spec.get(key)
}

/// Python truthiness of a YAML value.
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

/// Loads `identities.yaml`.
pub fn load_identities(path: &str) -> ConfigResult<IdentityStore> {
    if !std::path::Path::new(path).exists() {
        return Err(ConfigError::new(format!(
            "{path} not found. Without identities nobody can authenticate -- \
             run 'gatekeeper init' to create one administrator."
        )));
    }
    let text = read_config_file(path, "Run 'gatekeeper init' to create one.")?;
    // PORT NOTE: a YAML syntax error was a raw yaml.YAMLError in Python; it
    // is a ConfigError naming the file here.
    let raw = crate::atomic::safe_load(&text).map_err(|e| ConfigError::new(format!("{path}: {e}")))?;
    let empty = Map::new();
    let raw = raw.as_object().unwrap_or(&empty);

    let entries = match raw.get("identities") {
        Some(Value::Array(items)) if !items.is_empty() => items,
        _ => return Err(ConfigError::new("identities.yaml: 'identities' is missing or empty")),
    };

    let mut identities: IndexMap<String, Identity> = IndexMap::new();
    for spec in entries {
        let Some(spec) = spec.as_object() else {
            return Err(ConfigError::new("identities.yaml: every entry must be a mapping"));
        };
        let identity_id = match get(spec, "id") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => return Err(ConfigError::new("identities.yaml: 'id' is missing")),
        };
        let r#where = format!("identity {}", repr_str(&identity_id));

        let role_value = get(spec, "role").cloned().unwrap_or_else(|| json!("agent"));
        let role = match &role_value {
            Value::String(s) if ROLES.contains(&s.as_str()) => s.clone(),
            other => {
                return Err(ConfigError::new(format!(
                    "{where}: role={} is unknown",
                    repr_value(other)
                )))
            }
        };

        let token_hash = match get(spec, "token_hash") {
            Some(Value::String(s)) if s.starts_with(&format!("{PREFIX}$")) => s.clone(),
            _ => {
                return Err(ConfigError::new(format!(
                    "{where}: 'token_hash' is missing or not an scrypt hash. \
                     Plaintext tokens do not belong in this file."
                )))
            }
        };
        if token_hash.contains("REPLACE_ME") {
            // Fail closed: a placeholder would otherwise produce a server
            // that starts but rejects every token -- hard to diagnose.
            return Err(ConfigError::new(format!(
                "{where}: token_hash is still the placeholder from the example \
                 file. Generate a real hash with: gatekeeper token"
            )));
        }

        // Optional: a file from before console sign-in has no password.
        let password_hash = if truthy(get(spec, "password_hash")) {
            match get(spec, "password_hash") {
                Some(Value::String(s)) => s.clone(),
                _ => return Err(ConfigError::new(format!("{where}: 'password_hash' must be a string"))),
            }
        } else {
            String::new()
        };
        if !password_hash.is_empty() && !password_hash.starts_with(&format!("{PREFIX}$")) {
            return Err(ConfigError::new(format!(
                "{where}: 'password_hash' is not an scrypt hash. Plaintext \
                 passwords do not belong in this file -- set one with: \
                 gatekeeper password --identity {identity_id}"
            )));
        }
        if password_hash.contains("REPLACE_ME") {
            return Err(ConfigError::new(format!(
                "{where}: password_hash is still the placeholder from the \
                 example file. Set a real one with: gatekeeper password \
                 --identity {identity_id}"
            )));
        }
        if !password_hash.is_empty() && !UI_ROLES.contains(&role.as_str()) {
            // An agent never signs in anywhere; a password on an agent
            // usually indicates a wrongly set role.
            return Err(ConfigError::new(format!(
                "{where}: role={} has a password_hash, but only {} can sign in to the console.",
                repr_str(&role),
                UI_ROLES.join(" and ")
            )));
        }

        // Optional, same reasoning as `password_hash`.
        let token_lookup = if truthy(get(spec, "token_lookup")) {
            match get(spec, "token_lookup") {
                Some(Value::String(s)) => s.clone(),
                _ => return Err(ConfigError::new(format!("{where}: 'token_lookup' must be a string"))),
            }
        } else {
            String::new()
        };
        if !token_lookup.is_empty()
            && (token_lookup.chars().count() != 64
                || !token_lookup.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')))
        {
            return Err(ConfigError::new(format!(
                "{where}: 'token_lookup' is not a SHA-256 hex digest. It is \
                 computed alongside token_hash, never typed by hand -- \
                 regenerate the token with: gatekeeper token"
            )));
        }

        let tools_value = get(spec, "tools");
        let tools: Vec<Value> = if truthy(tools_value) {
            match tools_value {
                Some(Value::Array(items)) => items.clone(),
                _ => return Err(ConfigError::new(format!("{where}: 'tools' must be a list"))),
            }
        } else {
            Vec::new()
        };
        let mut tool_set = BTreeSet::new();
        for entry in &tools {
            let Value::String(entry) = entry else {
                return Err(ConfigError::new(format!("{where}: tool entries must be strings")));
            };
            if entry.contains('*') {
                return Err(ConfigError::new(format!(
                    "{where}: wildcard {} in 'tools' is not permitted. \
                     Rights are granted on individual tool IDs (FR-7.5).",
                    repr_str(entry)
                )));
            }
            tool_set.insert(entry.clone());
        }

        let scopes_value = get(spec, "scopes");
        let scopes: Vec<String> = if truthy(scopes_value) {
            match scopes_value {
                Some(Value::Array(items)) => items.iter().map(str_value).collect(),
                _ => return Err(ConfigError::new(format!("{where}: 'scopes' must be a list"))),
            }
        } else {
            Vec::new()
        };

        if identities.contains_key(&identity_id) {
            return Err(ConfigError::new(format!("Duplicate identity {}", repr_str(&identity_id))));
        }

        identities.insert(
            identity_id.clone(),
            Identity {
                id: identity_id,
                role,
                token_hash,
                tools: tool_set,
                scopes,
                password_hash,
                token_lookup,
            },
        );
    }

    Ok(IdentityStore { identities })
}

/// For the startup log (NFR-7) -- without hashes.
pub fn summarize(store: &IdentityStore) -> Vec<Value> {
    store
        .identities
        .values()
        .map(|i| {
            json!({
                "id": i.id,
                "role": i.role,
                "tools": i.tools.len(),
                "scopes": i.scopes,
                "console": i.can_sign_in(),
            })
        })
        .collect()
}

/// Serializes an identity back to YAML form. Contains the hashes, never a
/// plaintext (FR-2.6).
pub fn to_spec(identity: &Identity) -> Value {
    let mut spec = Map::new();
    spec.insert("id".into(), json!(identity.id));
    spec.insert("role".into(), json!(identity.role));
    spec.insert("token_hash".into(), json!(identity.token_hash));
    spec.insert("tools".into(), json!(identity.tools.iter().collect::<Vec<_>>()));
    spec.insert("scopes".into(), json!(identity.scopes));
    // Only write what exists.
    if !identity.password_hash.is_empty() {
        spec.insert("password_hash".into(), json!(identity.password_hash));
    }
    if !identity.token_lookup.is_empty() {
        spec.insert("token_lookup".into(), json!(identity.token_lookup));
    }
    Value::Object(spec)
}

pub fn dump_identities(store: &IdentityStore) -> Value {
    json!({"identities": store.identities.values().map(to_spec).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, text: &str) -> String {
        let path = dir.path().join("identities.yaml");
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn hash_round_trip_and_format() {
        let h = hash_token_with_salt("secret", b"0123456789abcdef");
        let parts: Vec<&str> = h.split('$').collect();
        assert_eq!(&parts[..4], &["scrypt", "32768", "8", "1"]);
        assert_eq!(parts[4], "MDEyMzQ1Njc4OWFiY2RlZg==");
        assert!(verify_token("secret", &h));
        assert!(!verify_token("Secret", &h));
        assert!(!verify_token("secret", "bcrypt$1$2$3$4$5"));
        assert!(!verify_token("secret", "scrypt$x$8$1$AA==$AA=="));
        assert!(!verify_token("secret", "scrypt$32767$8$1$AA==$AA=="));
        // Too much memory for maxmem=64MiB: hashlib raises, so no match.
        assert!(!verify_token("secret", "scrypt$65536$8$1$AA==$AA=="));
        assert!(!verify_token("secret", ""));
    }

    #[test]
    fn b64decode_is_lenient_like_python() {
        assert_eq!(py_b64decode("YWJj", false).unwrap(), b"abc");
        assert_eq!(py_b64decode("YWI=", false).unwrap(), b"ab");
        assert_eq!(py_b64decode("YW\nI=", false).unwrap(), b"ab");
        assert_eq!(py_b64decode("YWI=garbage", false).unwrap(), b"ab");
        assert!(py_b64decode("YWI", false).is_none());
        assert!(py_b64decode("Y", false).is_none());
        assert_eq!(py_b64decode("-_8=", true).unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn tokens_and_passwords() {
        let t = generate_token();
        assert!(t.starts_with("gk_"));
        assert_eq!(t.len(), 3 + 43);
        assert_eq!(generate_password().len(), 24);
        assert_eq!(
            hash_token_lookup("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn identity(id: &str, role: &str, token: &str, indexed: bool, password: Option<&str>) -> Identity {
        Identity {
            id: id.into(),
            role: role.into(),
            token_hash: hash_token(token),
            tools: BTreeSet::new(),
            scopes: vec![],
            password_hash: password.map(hash_token).unwrap_or_default(),
            token_lookup: if indexed { hash_token_lookup(token) } else { String::new() },
        }
    }

    #[test]
    fn authenticate_indexed_and_unindexed() {
        let mut map = IndexMap::new();
        map.insert("a".into(), identity("a", "agent", "tok-a", true, None));
        map.insert("b".into(), identity("b", "admin", "tok-b", false, Some("pw-pw-pw-pw-pw")));
        let store = IdentityStore::new(map);
        assert_eq!(store.authenticate("tok-a").unwrap().id, "a");
        assert_eq!(store.authenticate("tok-b").unwrap().id, "b");
        assert!(store.authenticate("nope").is_none());
        assert_eq!(store.authenticate_console("b", "pw-pw-pw-pw-pw").unwrap().id, "b");
        assert!(store.authenticate_console("b", "wrong").is_none());
        assert!(store.authenticate_console("a", "pw-pw-pw-pw-pw").is_none());
        assert!(store.authenticate_console("ghost", "x").is_none());
        // A token is not a password.
        assert!(store.authenticate_console("b", "tok-b").is_none());
    }

    #[test]
    fn lookup_matches_names_an_identity_whose_hash_disagrees() {
        let mut broken = identity("broken", "agent", "other", true, None);
        broken.token_lookup = hash_token_lookup("presented");
        let mut map = IndexMap::new();
        map.insert("broken".into(), broken);
        let store = IdentityStore::new(map);
        assert!(store.authenticate("presented").is_none());
        assert_eq!(store.lookup_matches("presented"), ["broken"]);
        assert!(store.lookup_matches("other").is_empty());
    }

    #[test]
    fn grants_and_scopes() {
        let mut i = identity("a", "agent", "t", true, None);
        i.tools = ["demo.show".to_string(), "docker.ps@nas1".to_string()].into_iter().collect();
        i.scopes = vec!["/srv/*".into()];
        assert!(i.may_call("demo.show"));
        assert!(!i.may_call("docker.ps"));
        assert!(i.holds_definition("docker.ps"));
        assert!(i.holds_definition("demo.show"));
        assert!(!i.holds_definition("demo"));
        assert!(i.covers_scope("/srv/a"));
        assert!(!i.covers_scope("/etc/a"));
    }

    #[test]
    fn load_and_dump() {
        let dir = tempfile::tempdir().unwrap();
        let h = hash_token("t");
        let lookup = hash_token_lookup("t");
        let text = format!(
            "identities:\n- id: root\n  role: admin\n  token_hash: '{h}'\n  password_hash: '{h}'\n  token_lookup: {lookup}\n  tools: [b.x, a.y]\n  scopes: [1, '/srv/*']\n- id: bot\n  token_hash: '{h}'\n"
        );
        let store = load_identities(&write(&dir, &text)).unwrap();
        let root = &store.identities["root"];
        assert!(root.can_sign_in());
        assert_eq!(root.scopes, vec!["1".to_string(), "/srv/*".to_string()]);
        assert_eq!(store.identities["bot"].role, "agent");
        let spec = to_spec(root);
        assert_eq!(spec["tools"], json!(["a.y", "b.x"]));
        let keys: Vec<&String> = spec.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["id", "role", "token_hash", "tools", "scopes", "password_hash", "token_lookup"]);
        let bot = to_spec(&store.identities["bot"]);
        assert!(bot.get("password_hash").is_none());
        assert_eq!(summarize(&store)[0]["console"], json!(true));
        assert_eq!(dump_identities(&store)["identities"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn validation_messages() {
        let dir = tempfile::tempdir().unwrap();
        let h = "scrypt$32768$8$1$AA==$AA==";
        let cases: Vec<(String, &str)> = vec![
            ("identities: []\n".into(), "identities.yaml: 'identities' is missing or empty"),
            ("identities: [x]\n".into(), "identities.yaml: every entry must be a mapping"),
            ("identities: [{role: admin}]\n".into(), "identities.yaml: 'id' is missing"),
            ("identities: [{id: a, role: root}]\n".into(), "identity 'a': role='root' is unknown"),
            (
                "identities: [{id: a, token_hash: plain}]\n".into(),
                "identity 'a': 'token_hash' is missing or not an scrypt hash. Plaintext tokens do not belong in this file.",
            ),
            (
                "identities: [{id: a, token_hash: scrypt$REPLACE_ME}]\n".into(),
                "identity 'a': token_hash is still the placeholder from the example file. Generate a real hash with: gatekeeper token",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}', password_hash: 5}}]\n"),
                "identity 'a': 'password_hash' must be a string",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}', password_hash: pw}}]\n"),
                "identity 'a': 'password_hash' is not an scrypt hash. Plaintext passwords do not belong in this file -- set one with: gatekeeper password --identity a",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}', password_hash: '{h}'}}]\n"),
                "identity 'a': role='agent' has a password_hash, but only viewer and admin can sign in to the console.",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}', token_lookup: ABC}}]\n"),
                "identity 'a': 'token_lookup' is not a SHA-256 hex digest. It is computed alongside token_hash, never typed by hand -- regenerate the token with: gatekeeper token",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}', tools: x}}]\n"),
                "identity 'a': 'tools' must be a list",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}', tools: [1]}}]\n"),
                "identity 'a': tool entries must be strings",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}', tools: ['demo.*']}}]\n"),
                "identity 'a': wildcard 'demo.*' in 'tools' is not permitted. Rights are granted on individual tool IDs (FR-7.5).",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}', scopes: x}}]\n"),
                "identity 'a': 'scopes' must be a list",
            ),
            (
                format!("identities: [{{id: a, token_hash: '{h}'}}, {{id: a, token_hash: '{h}'}}]\n"),
                "Duplicate identity 'a'",
            ),
        ];
        for (text, expected) in cases {
            let err = load_identities(&write(&dir, &text)).unwrap_err();
            assert_eq!(err.message, expected, "for {text}");
        }
        let missing = dir.path().join("nope.yaml");
        let err = load_identities(missing.to_str().unwrap()).unwrap_err();
        assert!(err.message.ends_with(
            "not found. Without identities nobody can authenticate -- run 'gatekeeper init' to create one administrator."
        ));
    }
}
