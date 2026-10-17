//! Files and strings the retired Python implementation wrote, frozen in
//! `tests/fixtures/python_written/` before it was removed (1.16.0), and
//! read back here: an existing deployment's identities, credential store
//! and audit log were written by Python, and must stay readable.
//!
//! These replace the live cross-language checks that used to drive the
//! Python package. The fixtures are never regenerated.

use serde_json::Value;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/python_written");

fn fixture() -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURES}/identity_and_credentials.json")).unwrap())
        .unwrap()
}

#[test]
fn a_python_hash_verifies_in_rust() {
    let f = fixture();
    let (token, hash) = (f["token"].as_str().unwrap(), f["token_hash"].as_str().unwrap());
    assert!(hash.starts_with("scrypt$32768$8$1$"));
    assert!(gatekeeper::identity::verify_token(token, hash));
    assert!(!gatekeeper::identity::verify_token("gk_python-made-token-e", hash));
}

#[test]
fn rust_hashes_are_the_bytes_python_wrote() {
    let f = fixture();
    // Same salt, same bytes: what Python's `hash_token('x', salt=...)`
    // returned, so a Rust hash verifies wherever a Python one did.
    assert_eq!(gatekeeper::identity::hash_token_with_salt("x", b"0123456789abcdef"), f["salted_x"].as_str().unwrap());
    assert_eq!(gatekeeper::identity::hash_token_lookup("gk_abc"), f["lookup_gk_abc"].as_str().unwrap());
    let hash = gatekeeper::identity::hash_token("rust-made-password-ü");
    assert!(gatekeeper::identity::verify_token("rust-made-password-ü", &hash));
    assert!(!gatekeeper::identity::verify_token("wrong", &hash));
}

#[test]
fn a_python_written_credential_store_resolves_and_survives_a_rust_write() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.yaml");
    std::fs::copy(format!("{FIXTURES}/credentials.yaml"), &path).unwrap();
    // The store reads the key from the environment; no other test in this
    // binary touches it.
    std::env::set_var(gatekeeper::credentials::KEY_ENV, f["credential_key"].as_str().unwrap());
    let logs = dir.path().join("logs");
    let audit = std::sync::Arc::new(gatekeeper::audit::AuditLog::new(logs.to_str().unwrap()).unwrap());
    let store = gatekeeper::credentials::CredentialStore::new(path.to_str().unwrap(), audit);

    // Python created `py` and rotated it with an overlap.
    let resolved = store.resolve("py").unwrap().unwrap();
    assert_eq!(resolved.value, "pythön-new");
    assert_eq!(resolved.previous_value.as_deref(), Some("pythön-secret"));
    assert_eq!(resolved.header.as_deref(), Some("X-Api-Key"));
    // Both sides compute the same record revision for the slot.
    assert_eq!(store.record_revision("py").unwrap(), f["record_revision_py"].as_str().unwrap());

    // Rust rewrites the file; Python's entry survives it.
    store.create("rs", "bearer", "rüst-secret", None, None, None, "a", "").unwrap();
    store.rotate("rs", "rüst-new", 60, "a", "").unwrap();
    let rs = store.resolve("rs").unwrap().unwrap();
    assert_eq!((rs.value.as_str(), rs.previous_value.as_deref()), ("rüst-new", Some("rüst-secret")));
    assert_eq!(store.resolve("py").unwrap().unwrap().value, "pythön-new");
    assert_eq!(store.record_revision("py").unwrap(), f["record_revision_py"].as_str().unwrap());
}

#[test]
fn audit_lines_are_what_python_json_dumps_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let log = gatekeeper::audit::AuditLog::new(dir.path().to_str().unwrap()).unwrap();
    log.write(serde_json::json!({"kind": "call", "detail": "Grüße\n\"q\" \u{1}", "n": [1, 2.5, null, true], "x-api-key": "k"}))
        .unwrap();
    let line = std::fs::read_to_string(log.path()).unwrap();
    let line = line.trim_end_matches('\n');
    let record: Value = serde_json::from_str(line).unwrap();
    let ts = record["ts"].as_str().unwrap();
    // `json.dumps(record, ensure_ascii=False)` of the same record, as the
    // Python implementation printed it (with `ts` left as a placeholder).
    let python = r#"{"ts": "@TS@", "kind": "call", "detail": "Grüße\n\"q\" \u0001", "n": [1, 2.5, null, true], "x-api-key": "***"}"#;
    assert_eq!(line, python.replace("@TS@", ts));
}
