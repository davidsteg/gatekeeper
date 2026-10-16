//! Shared atomic-write / optimistic-concurrency helpers for Tier 2 files
//! (port of `_atomic.py`).

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::errors::{ConfigError, ConfigResult};

/// Header of every written file. Anyone who later opens it by hand should
/// immediately see that a console is co-writing here.
pub const HEADER: &str = "# Managed by gatekeeper. The admin console writes this file;\n\
# manual changes are possible but will be lost on the next write\n\
# from the UI unless they have been reloaded beforehand.\n";

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Short fingerprint of the file content for the concurrency check; `""`
/// for a file that cannot be read.
pub fn revision(path: &str) -> String {
    match std::fs::read(path) {
        Ok(data) => sha256_hex(&data)[..16].to_string(),
        Err(_) => String::new(),
    }
}

/// `yaml.safe_load` of a whole config file's text.
pub fn safe_load(text: &str) -> Result<Value, crate::yaml::YamlError> {
    crate::yaml::load(text)
}

fn cache() -> &'static Mutex<HashMap<String, (String, Value)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (String, Value)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `safe_load` of `path`, parsed once per distinct file content. Missing
/// file -> `Ok(None)`. Returns an owned copy, because the stores' write
/// paths mutate what they load before writing it back.
pub fn load_cached(path: &str) -> ConfigResult<Option<Value>> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ConfigError::new(format!(
                "{path} cannot be read: {}",
                crate::pyfmt::os_error(&e, path)
            )))
        }
    };
    let digest = sha256_hex(&data);
    let key = abspath(path);
    if let Some((d, v)) = cache().lock().unwrap().get(&key) {
        if *d == digest {
            return Ok(Some(v.clone()));
        }
    }
    let text = String::from_utf8_lossy(&data);
    let value = safe_load(&text).map_err(|e| ConfigError::new(format!("{path}: {e}")))?;
    cache().lock().unwrap().insert(key, (digest, value.clone()));
    Ok(Some(value))
}

/// `os.path.abspath`.
pub fn abspath(path: &str) -> String {
    crate::pathutil::abspath(path)
}

/// Writes `text` to a sibling temp file, fsyncs it and renames it over
/// `path`. A crash in between leaves the old file, never a half-written one.
pub fn atomic_write(path: &str, text: &str) -> std::io::Result<()> {
    let abs = abspath(path);
    let dir = Path::new(&abs).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| ".".into());
    let mut tmp = tempfile::Builder::new().prefix(".gk-").suffix(".tmp").tempfile_in(&dir)?;
    tmp.write_all(text.as_bytes())?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    // Keep the mode of an existing file (Python's NamedTemporaryFile creates
    // 0600 too, and `os.replace` carries the temp file's mode).
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// `atomic_write`, with the I/O error turned into a `ConfigError`.
pub fn atomic_write_cfg(path: &str, text: &str) -> ConfigResult<()> {
    atomic_write(path, text).map_err(|e| {
        ConfigError::refused(format!("{path} could not be written: {}", crate::pyfmt::os_error(&e, path)))
    })
}

/// The managed-file header plus the YAML dump of `payload`.
pub fn dump(payload: &Value) -> String {
    format!("{HEADER}{}", crate::yaml::dump(payload))
}

fn access(path: &str, mode: libc::c_int) -> bool {
    match std::ffi::CString::new(path) {
        // SAFETY: valid NUL-terminated path.
        Ok(c) => unsafe { libc::access(c.as_ptr(), mode) == 0 },
        Err(_) => false,
    }
}

/// Can anything be written here at all? The directory is checked, not just
/// the file: the rename creates a new file.
pub fn writable(path: &str) -> bool {
    let abs = abspath(path);
    let dir = Path::new(&abs)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ".".into());
    access(&dir, libc::W_OK) && (!Path::new(path).exists() || access(path, libc::W_OK))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn write_then_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.yaml");
        let p = path.to_str().unwrap();
        assert_eq!(revision(p), "");
        atomic_write(p, &dump(&json!({"tools": []}))).unwrap();
        let text = std::fs::read_to_string(p).unwrap();
        assert!(text.starts_with(HEADER));
        assert_eq!(revision(p).len(), 16);
        assert_eq!(load_cached(p).unwrap().unwrap(), json!({"tools": []}));
        assert!(writable(p));
        // No stray temp files.
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }
}
