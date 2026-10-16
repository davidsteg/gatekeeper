//! Cross-language checks against the Python reference implementation:
//! scrypt hashes and Fernet tokens written by one side are read by the
//! other. Skipped when the reference venv is not present.

use std::process::Command;

fn python(script: &str, args: &[&str]) -> Option<String> {
    let interpreter = std::env::var("GATEKEEPER_INTEROP_PYTHON")
        .unwrap_or_else(|_| "/tmp/claude-0/venv/bin/python".into());
    if !std::path::Path::new(&interpreter).exists() {
        eprintln!("skipping: {interpreter} not found");
        return None;
    }
    let out = Command::new(&interpreter).arg("-I").arg("-c").arg(script).args(args).output().unwrap();
    assert!(out.status.success(), "python failed: {}", String::from_utf8_lossy(&out.stderr));
    Some(String::from_utf8(out.stdout).unwrap().trim_end_matches('\n').to_string())
}

#[test]
fn python_hash_verifies_in_rust() {
    let Some(hash) = python(
        "import sys; from gatekeeper.identity import hash_token; print(hash_token(sys.argv[1]))",
        &["gk_python-made-token-é"],
    ) else {
        return;
    };
    assert!(hash.starts_with("scrypt$32768$8$1$"));
    assert!(gatekeeper::identity::verify_token("gk_python-made-token-é", &hash));
    assert!(!gatekeeper::identity::verify_token("gk_python-made-token-e", &hash));
}

#[test]
fn rust_hash_verifies_in_python() {
    let hash = gatekeeper::identity::hash_token("rust-made-password-ü");
    let Some(out) = python(
        "import sys; from gatekeeper.identity import verify_token; \
         print(verify_token(sys.argv[1], sys.argv[3]), verify_token(sys.argv[2], sys.argv[3]))",
        &["rust-made-password-ü", "wrong", &hash],
    ) else {
        return;
    };
    assert_eq!(out, "True False");
    // Same salt, same bytes.
    let salted = gatekeeper::identity::hash_token_with_salt("x", b"0123456789abcdef");
    let Some(py) = python(
        "from gatekeeper.identity import hash_token; print(hash_token('x', salt=b'0123456789abcdef'))",
        &[],
    ) else {
        return;
    };
    assert_eq!(salted, py);
    let Some(lookup) = python(
        "from gatekeeper.identity import hash_token_lookup; print(hash_token_lookup('gk_abc'))",
        &[],
    ) else {
        return;
    };
    assert_eq!(lookup, gatekeeper::identity::hash_token_lookup("gk_abc"));
}

#[test]
fn fernet_tokens_interoperate() {
    let key = gatekeeper::credentials::generate_master_key();
    // Python encrypts, Rust decrypts (through the store, from a file Python wrote).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.yaml");
    let script = r#"import os, sys; os.environ['GATEKEEPER_CREDENTIAL_KEY'] = sys.argv[1]
from gatekeeper.audit import AuditLog
from gatekeeper.credentials import CredentialStore
s = CredentialStore(path=sys.argv[2], audit=AuditLog(sys.argv[3]))
if sys.argv[4] == 'create':
    s.create('py', kind='api_key_header', header='X-Api-Key', value='pythön-secret', actor='a', rev='')
    s.rotate('py', value='pythön-new', overlap_seconds=3600, actor='a', rev='')
    print('ok')
else:
    r = s._resolve('rs')
    print(r.value, r.previous_value, s.record_revision('rs'))
"#;
    let logs = dir.path().join("logs");
    let args = [key.as_str(), path.to_str().unwrap(), logs.to_str().unwrap()];
    let Some(out) = python(script, &[args[0], args[1], args[2], "create"]) else {
        return;
    };
    assert_eq!(out, "ok");

    // The store reads the key from the environment; this test binary has
    // no other test touching it.
    std::env::set_var(gatekeeper::credentials::KEY_ENV, &key);
    let audit = std::sync::Arc::new(gatekeeper::audit::AuditLog::new(logs.to_str().unwrap()).unwrap());
    let store = gatekeeper::credentials::CredentialStore::new(path.to_str().unwrap(), audit);
    let resolved = store.resolve("py").unwrap().unwrap();
    assert_eq!(resolved.value, "pythön-new");
    assert_eq!(resolved.previous_value.as_deref(), Some("pythön-secret"));
    assert_eq!(resolved.header.as_deref(), Some("X-Api-Key"));

    // Rust encrypts, Python decrypts -- and both compute the same record
    // revision for the slot.
    store.create("rs", "bearer", "rüst-secret", None, None, None, "a", "").unwrap();
    store.rotate("rs", "rüst-new", 60, "a", "").unwrap();
    let rev = store.record_revision("rs").unwrap();
    let out = python(script, &[args[0], args[1], args[2], "resolve"]).unwrap();
    assert_eq!(out, format!("rüst-new rüst-secret {rev}"));
    // Python's own entry survived the Rust rewrite of the file.
    assert_eq!(store.resolve("py").unwrap().unwrap().value, "pythön-new");
}

#[test]
fn audit_lines_match_python_json_dumps() {
    let dir = tempfile::tempdir().unwrap();
    let log = gatekeeper::audit::AuditLog::new(dir.path().to_str().unwrap()).unwrap();
    log.write(serde_json::json!({"kind": "call", "detail": "Grüße\n\"q\" \u{1}", "n": [1, 2.5, null, true], "x-api-key": "k"}))
        .unwrap();
    let line = std::fs::read_to_string(log.path()).unwrap();
    let line = line.trim_end_matches('\n');
    let Some(py) = python(
        "import json, sys; r = json.loads(sys.argv[1]); print(json.dumps(r, ensure_ascii=False))",
        &[line],
    ) else {
        return;
    };
    assert_eq!(py, line);
    assert!(line.contains("\"x-api-key\": \"***\""));
}
