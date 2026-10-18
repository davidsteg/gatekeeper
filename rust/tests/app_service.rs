//! `Service::call` end to end with real local executors (the service-level
//! parts of `test_behaviour.py`, `test_negative_corpus.py`,
//! `test_destinations.py`, `test_runas.py`, `test_agent_messaging.py` /
//! `test_mailbox_notify.py` and `test_artifacts.py`).

mod app_env;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use app_env::*;
use gatekeeper::artifacts::{build, ArtifactStore, Source, SourceKind};
use gatekeeper::errors::{DenialReason, OPAQUE_DENIAL};
use gatekeeper::execute::{ExecResult, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use gatekeeper::identity::{generate_token, hash_token, Identity};
use gatekeeper::service::{CallError, Service};
use serde_json::{json, Value};

async fn call(e: &AppEnv, who: &Identity, tool: &str, a: Value) -> Result<ExecResult, CallError> {
    e.service.call(who, tool, &args(a), None).await
}

fn denial(r: Result<ExecResult, CallError>) -> gatekeeper::errors::Denied {
    match r {
        Err(CallError::Denied(d)) => d,
        other => panic!("expected a denial, got {other:?}"),
    }
}

fn full() -> Identity {
    agent("full", &["demo.show", "demo.echo"], &["stack:*"])
}

fn narrow() -> Identity {
    agent("narrow", &["demo.show"], &["stack:media-*"])
}

/// An executable shell script under `dir`.
fn script(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_str().unwrap().to_string()
}

fn last_audit(e: &AppEnv) -> Value {
    e.audit_lines().pop().unwrap()
}

// -- test_behaviour.py ----------------------------------------------------------

#[tokio::test]
async fn successful_call() {
    let e = AppEnv::new();
    let result = call(&e, &full(), "demo.show", json!({"stack": "media-jellyfin"})).await.unwrap();
    assert_eq!(result.outcome, OUTCOME_OK);
    assert_eq!(result.exit_code, Some(0));
    assert!(result.stdout.contains("media-jellyfin"));
    let record = last_audit(&e);
    assert_eq!(record["outcome"], "ok");
    assert_eq!(record["tool_version"], 1);
    assert!(record["duration_ms"].is_i64());
}

#[tokio::test]
async fn audit_records_the_command_and_clips_long_values() {
    let e = AppEnv::new();
    call(&e, &full(), "demo.show", json!({"stack": "media-jellyfin"})).await.unwrap();
    let record = last_audit(&e);
    let command = record["command"].as_str().unwrap();
    assert!(command.starts_with(&format!("{SH} -c ")), "{command}");
    assert!(command.ends_with("/media-jellyfin/compose.yaml"), "{command}");
    assert_eq!(record["parameters"]["stack"], "media-jellyfin");

    let long = "x".repeat(5000);
    call(&e, &full(), "demo.echo", json!({"text": long})).await.unwrap();
    let record = last_audit(&e);
    let text = record["parameters"]["text"].as_str().unwrap();
    assert!(text.ends_with("… [+4000 chars]"), "{}", &text[990..]);
    let command = record["command"].as_str().unwrap();
    assert!(command.chars().count() < 2100, "{}", command.len());
    assert!(command.contains("chars]"));

    // Denied before a request existed: no command.
    denial(call(&e, &narrow(), "demo.echo", json!({"text": "x"})).await);
    assert!(last_audit(&e).get("command").is_none());
}

#[tokio::test]
async fn audit_command_masks_secret_named_parameters() {
    let dir = tempfile::tempdir().unwrap();
    let sb = sandbox(dir.path());
    let mut specs = sh_specs(&sb);
    specs.push(json!({
        "id": "demo.login", "toolkit": "demo", "binary": SH, "version": 1,
        "title": "Login", "description": "Takes a token.",
        "category": "read", "idempotent": true, "enabled": true,
        "argv": ["-c", "true", "sh", "--token={api_token}"],
        "parameters": {"api_token": {"type": "string", "required": true, "pattern": "^.+$",
                                     "description": "a token"}},
        "required_scopes": [],
        "timeout_seconds": 10, "max_output_bytes": 4096,
    }));
    let e = builder().tier1(demo_tier1_doc(dir.path(), &sb)).tools(specs).build();
    let who = agent("full", &["demo.login"], &[]);
    call(&e, &who, "demo.login", json!({"api_token": "s3cr3t-value"})).await.unwrap();
    let line = e.audit_lines().pop().unwrap();
    assert_eq!(line["parameters"]["api_token"], "***");
    assert!(line["command"].as_str().unwrap().ends_with("--token=***"), "{}", line["command"]);
    assert!(!line.to_string().contains("s3cr3t-value"));
}

/// A loopback HTTP target that answers 201 to everything and keeps the
/// request bodies it was sent.
async fn blob_target() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = bodies.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let mut raw = Vec::new();
            let mut buf = [0u8; 8192];
            // Headers, then exactly Content-Length bytes of body.
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw).to_string();
                if let Some(end) = text.find("\r\n\r\n") {
                    let len = text[..end]
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
                        .unwrap_or(0);
                    if raw.len() >= end + 4 + len {
                        seen.lock().unwrap().push(text[end + 4..].to_string());
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let reply = r#"{"sha":"abc123"}"#;
            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    (port, bodies)
}

#[tokio::test]
async fn body_file_content_never_reaches_the_audit_log() {
    let (port, bodies) = blob_target().await;
    let dir = tempfile::tempdir().unwrap();
    let sb = sandbox(dir.path());
    let scratch = dir.path().join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let root = scratch.to_str().unwrap().to_string();
    let content = "UNIQUE-FILE-CONTENT-4711 ".repeat(40);
    std::fs::write(scratch.join("notes.txt"), &content).unwrap();
    std::fs::write(scratch.join("big.txt"), "x".repeat(5000)).unwrap();
    let encoded = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&content)
    };

    let mut doc = demo_tier1_doc(dir.path(), &sb);
    doc["toolkits"]["gh"] = json!({
        "executor": "http", "base_url": format!("http://127.0.0.1:{port}"),
        "allowed_methods": ["POST"], "allowed_path_prefixes": ["/repos/"],
        "allowed_cidrs": ["127.0.0.1/32"], "path_roots": [root],
    });
    let mut specs = sh_specs(&sb);
    specs.push(json!({
        "id": "gh.blob", "toolkit": "gh", "version": 1, "title": "Blob", "description": "d",
        "category": "write_external", "idempotent": true, "enabled": true,
        "method": "POST", "path": "/repos/x/git/blobs",
        "body": {"content": {"from_file": "path", "encoding": "base64"}, "encoding": "base64"},
        "max_file_bytes": 4096,
        "parameters": {
            "file": {"type": "string", "pattern": "^[a-z]+\\.txt$", "required": true},
            "path": {"type": "path", "derived": format!("{root}/{{file}}"), "must_resolve_under": root},
        },
        "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096,
    }));
    let e = builder().tier1(doc).tools(specs).build();
    let who = agent("full", &["gh.blob"], &[]);

    let result = call(&e, &who, "gh.blob", json!({"file": "notes.txt"})).await.unwrap();
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    let sent: Value = serde_json::from_str(&bodies.lock().unwrap()[0]).unwrap();
    assert_eq!(sent["content"], encoded.as_str());
    let line = last_audit(&e);
    assert_eq!(line["outcome"], "ok");
    assert_eq!(line["parameters"]["path"], format!("{root}/notes.txt"));
    assert_eq!(line["files"], json!([{"path": format!("{root}/notes.txt"), "bytes": content.len()}]));
    assert!(line["command"].as_str().unwrap().contains(&format!("{root}/notes.txt")), "{}", line["command"]);

    // Over the limit: refused, nothing sent, the audit names path and size.
    let r = call(&e, &who, "gh.blob", json!({"file": "big.txt"})).await.unwrap();
    assert_eq!(r.outcome, OUTCOME_FAILED);
    let line = last_audit(&e);
    assert_eq!(line["denial_reason"], "param_invalid");
    assert!(line["detail"].as_str().unwrap().contains("is 5000 bytes"), "{}", line["detail"]);
    assert_eq!(bodies.lock().unwrap().len(), 1);

    let log = std::fs::read_to_string(e.audit.path()).unwrap();
    assert!(!log.contains("UNIQUE-FILE-CONTENT"));
    assert!(!log.contains(&encoded[..40]));
    assert!(!log.contains("xxxxxxxxxx"));
}

#[tokio::test]
async fn narrow_identity_within_scope_and_sibling_prefix_rejected() {
    let e = AppEnv::new();
    let result = call(&e, &narrow(), "demo.show", json!({"stack": "media-jellyfin"})).await.unwrap();
    assert_eq!(result.outcome, OUTCOME_OK);
    let d = denial(call(&e, &narrow(), "demo.show", json!({"stack": "mediatools"})).await);
    assert_eq!(d.reason, DenialReason::ScopeMismatch);
    assert_eq!(d.agent_message(), OPAQUE_DENIAL);
    let d = denial(call(&e, &narrow(), "demo.show", json!({"stack": "dev-thing"})).await);
    assert_eq!(d.reason, DenialReason::ScopeMismatch);
}

#[tokio::test]
async fn rate_limit_applies() {
    let dir = tempfile::tempdir().unwrap();
    let sb = sandbox(dir.path());
    let mut doc = demo_tier1_doc(dir.path(), &sb);
    doc["rate_limits"] = json!({"read": {"count": 1, "window_seconds": 60}});
    let e = builder().tier1(doc).tools(sh_specs(&sb)).build();
    call(&e, &full(), "demo.show", json!({"stack": "media-jellyfin"})).await.unwrap();
    let d = denial(call(&e, &full(), "demo.show", json!({"stack": "media-jellyfin"})).await);
    assert_eq!(d.reason, DenialReason::RateLimited);
}

#[tokio::test]
async fn audit_records_denial_reason() {
    let e = AppEnv::new();
    denial(call(&e, &narrow(), "demo.echo", json!({"text": "x"})).await);
    let record = last_audit(&e);
    assert_eq!(record["outcome"], "denied");
    assert_eq!(record["denial_reason"], "not_granted");
    assert_eq!(record["identity"], "narrow");
}

#[tokio::test]
async fn output_cap_and_timeouts_go_through_the_service() {
    let e = AppEnv::new();
    let mut tools = sh_specs(&e.sandbox);
    tools.push(json!({
        "id": "demo.big", "toolkit": "demo", "binary": SH, "version": 1, "title": "big",
        "description": "d", "category": "read", "idempotent": true, "enabled": true,
        "argv": ["-c", "i=0; while [ $i -lt 600 ]; do printf '0123456789'; i=$((i+1)); done"],
        "parameters": {}, "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 4096,
    }));
    for (id, idempotent) in [("demo.slowread", true), ("demo.slowwrite", false)] {
        tools.push(json!({
            "id": id, "toolkit": "demo", "binary": SH, "version": 1, "title": "slow",
            "description": "d", "category": if idempotent { "read" } else { "write" },
            "idempotent": idempotent, "enabled": true, "argv": ["-c", "sleep 5"],
            "parameters": {}, "required_scopes": [], "timeout_seconds": 1, "max_output_bytes": 4096,
        }));
    }
    write(Path::new(&e.tools_path), &gatekeeper::yaml::dump(&json!({ "tools": tools })));
    assert!(e.service.reload_config(&e.toolkits_path, &e.tools_path, &e.identities_path).is_none());
    let who = agent("w", &["demo.big", "demo.slowread", "demo.slowwrite"], &[]);

    let big = call(&e, &who, "demo.big", json!({})).await.unwrap();
    assert!(big.truncated);
    assert_eq!(big.stdout.len(), 4096);

    let (read, write) =
        tokio::join!(call(&e, &who, "demo.slowread", json!({})), call(&e, &who, "demo.slowwrite", json!({})));
    assert_eq!(read.unwrap().outcome, OUTCOME_FAILED);
    let write = write.unwrap();
    assert_eq!(write.outcome, OUTCOME_UNKNOWN);
    assert!(write.stderr.contains("UNKNOWN"));
}

#[tokio::test]
async fn missing_binary_is_an_executor_unavailable_denial() {
    let e = AppEnv::new();
    let ghost = e.tmp.join("no-such-binary");
    let mut doc = demo_tier1_doc(&e.tmp, &e.sandbox);
    doc["toolkits"]["demo"]["binaries"] = json!([SH, ghost.to_str().unwrap()]);
    write(Path::new(&e.toolkits_path), &gatekeeper::yaml::dump(&doc));
    let mut tools = sh_specs(&e.sandbox);
    tools.push(json!({
        "id": "demo.ghost", "toolkit": "demo", "binary": ghost.to_str().unwrap(), "version": 1,
        "title": "g", "description": "d", "category": "read", "idempotent": true, "enabled": true,
        "argv": [], "parameters": {}, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096,
    }));
    write(Path::new(&e.tools_path), &gatekeeper::yaml::dump(&json!({ "tools": tools })));
    assert!(e.service.reload_config(&e.toolkits_path, &e.tools_path, &e.identities_path).is_none());
    let d = denial(call(&e, &agent("g", &["demo.ghost"], &[]), "demo.ghost", json!({})).await);
    assert_eq!(d.reason, DenialReason::ExecutorUnavailable);
    // As in Python, the executor's own denial propagates without a call record.
    assert!(e.audit_lines().iter().all(|l| l["tool"] != "demo.ghost"));
    // The startup warning and the readiness probe agree.
    assert!(!e.service.tier1().missing_local_binaries().is_empty());
    assert!(!e.service.probe_one(&e.service.tier1().toolkits["demo"]).await);
}

#[tokio::test]
async fn probes_local_and_file() {
    let e = AppEnv::new();
    assert_eq!(e.service.probe_executors().await, BTreeMap::from([("local".to_string(), true)]));
    assert!(e.service.render_metrics().contains("gatekeeper_executor_ready{executor=\"local\"} 1"));

    for (roots, ready) in [(json!([e.sandbox.to_str().unwrap()]), true), (json!([]), false)] {
        let f = builder()
            .tier1(json!({"toolkits": {"files": {"executor": "file", "path_roots": roots,
                "protected_resources": [], "max_timeout_seconds": 10, "max_output_bytes": 4096}}}))
            .tools(vec![])
            .build();
        assert_eq!(f.service.probe_executors().await, BTreeMap::from([("file".to_string(), ready)]));
    }
}

#[tokio::test]
async fn metrics_count_ok_and_denied() {
    let e = AppEnv::new();
    call(&e, &full(), "demo.show", json!({"stack": "media-jellyfin"})).await.unwrap();
    call(&e, &full(), "demo.show", json!({"stack": "media-jellyfin"})).await.unwrap();
    denial(call(&e, &narrow(), "demo.echo", json!({"text": "x"})).await);
    let m = e.service.metrics();
    assert_eq!(m[&("demo.show".into(), "full".into(), "ok".into())], 2);
    assert_eq!(m[&("demo.echo".into(), "narrow".into(), "denied".into())], 1);
    let text = e.service.render_metrics();
    assert!(text.contains("gatekeeper_tool_calls_total{tool=\"demo.show\",identity=\"full\",outcome=\"ok\"} 2\n"));
    assert!(text.starts_with("# HELP gatekeeper_tool_calls_total"));
}

#[tokio::test]
async fn unknown_tool_names_share_one_series_and_cannot_forge_lines() {
    let e = AppEnv::new();
    let forged = "x\"} 1\ngatekeeper_executor_ready{executor=\"evil\"} 1\n#";
    for name in [forged.to_string(), "y".repeat(100_000)] {
        let denied = denial(call(&e, &full(), &name, json!({})).await);
        assert!(denied.detail.len() < 1000, "{}", denied.detail.len());
    }
    let m = e.service.metrics();
    assert_eq!(m[&("<unknown>".into(), "full".into(), "denied".into())], 2);
    assert_eq!(m.len(), 1);
    let text = e.service.render_metrics();
    assert!(!text.contains("executor=\"evil\""), "{text}");
}

// -- test_negative_corpus.py (service-level) --------------------------------------

#[tokio::test]
async fn denial_is_indistinguishable() {
    let e = AppEnv::new();
    let missing_right = denial(call(&e, &narrow(), "demo.echo", json!({"text": "hello"})).await);
    let no_such_tool = denial(call(&e, &narrow(), "demo.does_not_exist", json!({})).await);
    assert_eq!(missing_right.agent_message(), no_such_tool.agent_message());
    assert_eq!(missing_right.agent_message(), OPAQUE_DENIAL);
    assert_eq!(missing_right.reason, DenialReason::NotGranted);
    assert_eq!(no_such_tool.reason, DenialReason::UnknownTool);
}

#[tokio::test]
async fn parameter_attacks_are_denied_and_audited() {
    let e = AppEnv::new();
    for (a, reason) in [
        (json!({"stack": "x; rm -rf /"}), DenialReason::ParamInvalid),
        (json!({"stack": "gatekeeper"}), DenialReason::ProtectedResource),
        (json!({"stack": "media-jellyfin", "compose_path": "/etc/passwd"}), DenialReason::ParamDerivedSupplied),
        (json!({"stack": "media-jellyfin", "extra": "1"}), DenialReason::ParamUnknown),
        (json!({}), DenialReason::ParamMissing),
    ] {
        let d = denial(call(&e, &full(), "demo.show", a.clone()).await);
        assert_eq!(d.reason, reason, "{a}");
        let record = last_audit(&e);
        assert_eq!(record["outcome"], "denied");
        assert_eq!(record["denial_reason"], json!(reason.as_str()));
    }
}

#[test]
fn invisible_tools_stay_invisible() {
    let e = AppEnv::new();
    let names: Vec<String> = e.service.visible_tools(&narrow()).into_iter().map(|v| v.name).collect();
    assert_eq!(names, ["demo.show"]);
    let views = e.service.visible_tools(&full());
    let view = views.iter().find(|v| v.name == "demo.show").unwrap();
    // Derived parameters are not part of the agent-facing schema.
    assert!(view.input_schema["properties"].get("compose_path").is_none());
    assert_eq!(view.input_schema["required"], json!(["stack"]));
}

#[tokio::test]
async fn disabled_tool_is_denied() {
    let e = AppEnv::new();
    e.store.set_tool_enabled("demo.show", false, "root", &e.store.tools_revision()).unwrap();
    let d = denial(call(&e, &full(), "demo.show", json!({"stack": "media-jellyfin"})).await);
    assert_eq!(d.agent_message(), OPAQUE_DENIAL);
    assert!(e.service.visible_tools(&full()).iter().all(|v| v.name != "demo.show"));
}

// -- test_destinations.py (service-level) ------------------------------------------

/// Two destinations of one docker toolkit whose "docker" binary is a
/// script printing the `DOCKER_HOST` it was given.
fn docker_env(extra_dest: Value, toolkit_extra: Value, credentials: bool) -> AppEnv {
    let bin_dir = tempfile::tempdir().unwrap().keep();
    let docker = script(&bin_dir, "docker", "printf '%s' \"$DOCKER_HOST\"");
    let mut destinations = json!({
        "nas1": {"docker_host": "unix:///var/run/nas1.sock"},
        "nas2": {"docker_host": "unix:///var/run/nas2.sock"},
    });
    destinations.as_object_mut().unwrap().extend(obj(extra_dest));
    let dest_names: Vec<String> = destinations.as_object().unwrap().keys().cloned().collect();
    let mut toolkit = json!({"executor": "docker", "destinations": dest_names, "binaries": [docker.clone()],
                             "denied_args": [], "path_roots": []});
    toolkit.as_object_mut().unwrap().extend(obj(toolkit_extra));
    let tool = json!({
        "id": "docker.compose_up", "toolkit": "docker", "binary": docker, "version": 1,
        "title": "Compose up", "description": "Brings a stack up.", "category": "write",
        "idempotent": true, "enabled": true, "argv": [], "parameters": {}, "required_scopes": [],
        "timeout_seconds": 10, "max_output_bytes": 4096,
    });
    let mut b = builder()
        .tier1(json!({"destinations": destinations, "toolkits": {"docker": toolkit}}))
        .tools(vec![tool]);
    if credentials {
        b = b.credentials();
    }
    b.build()
}

#[tokio::test]
async fn grant_on_one_destination_does_not_reach_the_other() {
    let e = docker_env(json!({}), json!({}), false);
    let ids: Vec<String> = e.service.catalog().tools.keys().cloned().collect();
    assert_eq!(ids, ["docker.compose_up@nas1", "docker.compose_up@nas2"]);
    let nas1_only = agent("agent1", &["docker.compose_up@nas1"], &[]);
    denial(call(&e, &nas1_only, "docker.compose_up@nas2", json!({})).await);
    let nas2_only = agent("agent1", &["docker.compose_up@nas2"], &[]);
    let result = call(&e, &nas2_only, "docker.compose_up@nas2", json!({})).await.unwrap();
    assert_eq!(result.outcome, OUTCOME_OK);
    assert_eq!(result.stdout, "unix:///var/run/nas2.sock");
}

#[tokio::test]
async fn resolve_toolkit_overrides_falls_back_and_denies_unknown() {
    let e = docker_env(
        json!({"plain": {"docker_host": "unix:///var/run/plain.sock", "docker_tls": false},
               "secure": {"docker_host": "tcp://secure.lan:2376"}}),
        json!({"docker_tls": true}),
        false,
    );
    let tier1 = e.service.tier1();
    let toolkit = &tier1.toolkits["docker"];
    let nas1 = Service::resolve_toolkit(&tier1, toolkit, Some("nas1")).unwrap();
    assert_eq!(nas1.docker_host.as_deref(), Some("unix:///var/run/nas1.sock"));
    assert_eq!(nas1.binaries, toolkit.binaries);
    assert_eq!(Service::resolve_toolkit(&tier1, toolkit, None).unwrap(), *toolkit);
    assert!(!Service::resolve_toolkit(&tier1, toolkit, Some("plain")).unwrap().docker_tls);
    assert!(Service::resolve_toolkit(&tier1, toolkit, Some("secure")).unwrap().docker_tls);
    let d = Service::resolve_toolkit(&tier1, toolkit, Some("does-not-exist")).unwrap_err();
    assert_eq!(d.reason, DenialReason::Tier1Violation);
}

#[tokio::test]
async fn probe_executors_reports_per_destination() {
    let e = docker_env(json!({}), json!({}), false);
    assert_eq!(
        e.service.probe_executors().await,
        BTreeMap::from([("docker@nas1".to_string(), true), ("docker@nas2".to_string(), true)])
    );
}

fn tls_bundle(cert: &str) -> String {
    json!({"cert": cert, "key": "KEY-PEM", "ca": "CA-PEM"}).to_string()
}

#[tokio::test]
async fn docker_tls_env_materializes_caches_and_invalidates() {
    let e = docker_env(json!({}), json!({"docker_tls": true, "credential": "docker-nas2-tls"}), true);
    let creds = e.credentials.as_ref().unwrap();
    creds.create("docker-nas2-tls", "docker_tls", &tls_bundle("CERT-PEM"), None, None, None, "admin", "").unwrap();
    let tier1 = e.service.tier1();
    let nas2 = Service::resolve_toolkit(&tier1, &tier1.toolkits["docker"], Some("nas2")).unwrap();
    let env = e.service.environment(&nas2).unwrap().unwrap();
    assert_eq!(env["DOCKER_HOST"], "unix:///var/run/nas2.sock");
    assert_eq!(env["DOCKER_TLS_VERIFY"], "1");
    let cert_path = PathBuf::from(&env["DOCKER_CERT_PATH"]);
    assert_eq!(std::fs::read_to_string(cert_path.join("cert.pem")).unwrap(), "CERT-PEM");
    assert_eq!(std::fs::read_to_string(cert_path.join("key.pem")).unwrap(), "KEY-PEM");
    assert_eq!(std::fs::read_to_string(cert_path.join("ca.pem")).unwrap(), "CA-PEM");
    assert_eq!(e.service.environment(&nas2).unwrap().unwrap()["DOCKER_CERT_PATH"], env["DOCKER_CERT_PATH"]);

    e.service.invalidate_docker_tls_cache();
    creds.rotate("docker-nas2-tls", &tls_bundle("NEW-CERT"), 0, "admin", &creds.revision()).unwrap();
    let new_env = e.service.environment(&nas2).unwrap().unwrap();
    let new_path = PathBuf::from(&new_env["DOCKER_CERT_PATH"]);
    assert_eq!(std::fs::read_to_string(new_path.join("cert.pem")).unwrap(), "NEW-CERT");
    e.service.invalidate_docker_tls_cache();
}

#[tokio::test]
async fn docker_tls_env_refusals_are_denials() {
    // No credential store at all.
    let e = docker_env(json!({}), json!({"docker_tls": true, "credential": "docker-nas2-tls"}), false);
    let tk = e.service.tier1().toolkits["docker"].clone();
    let mut nas2 = tk.clone();
    nas2.docker_host = Some("tcp://nas2:2376".into());
    assert_eq!(e.service.environment(&nas2).unwrap_err().reason, DenialReason::CredentialUnavailable);
    // No credential name.
    nas2.credential = None;
    assert!(e.service.environment(&nas2).is_err());
    // Wrong kind.
    let e = docker_env(json!({}), json!({"docker_tls": true, "credential": "not-tls"}), true);
    e.credentials.as_ref().unwrap().create("not-tls", "bearer", "a-bearer-token", None, None, None, "admin", "").unwrap();
    let mut nas2 = e.service.tier1().toolkits["docker"].clone();
    nas2.docker_host = Some("tcp://nas2:2376".into());
    assert!(e.service.environment(&nas2).is_err());
    // And through call(): an audited denial, not a crash.
    let who = agent("a", &["docker.compose_up@nas1"], &[]);
    let d = denial(call(&e, &who, "docker.compose_up@nas1", json!({})).await);
    assert_eq!(d.reason, DenialReason::CredentialUnavailable);
    assert_eq!(last_audit(&e)["outcome"], "denied");
}

// -- test_runas.py (service wiring) --------------------------------------------------

/// The `run_as` helper replaced by a script that records the request it
/// was handed on stdin and reports success: the service-level tests check
/// which `run_as` reaches the executor, not the privilege drop.
fn spy_helper_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap().keep();
        let captures = dir.join("captures");
        std::fs::create_dir(&captures).unwrap();
        let helper = script(
            &dir,
            "gatekeeper-spy",
            &format!(
                "cat > \"{}/req.$$\"\nprintf '%s' '{{\"outcome\": \"ok\", \"exit_code\": 0, \"stdout\": \"\", \"stderr\": \"\", \"truncated\": false}}'",
                captures.display()
            ),
        );
        gatekeeper::privdrop::set_self_exe(helper);
        captures
    })
}

/// The `run_as` the helper received for a call on `path` (`None` when the
/// call ran in-process and never reached the helper).
fn captured_run_as(path: &str) -> Option<Value> {
    for entry in std::fs::read_dir(spy_helper_dir()).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        let Ok(request) = serde_json::from_str::<Value>(&text) else { continue };
        if request["path"] == path {
            return Some(request["run_as"].clone());
        }
    }
    None
}

fn file_env(toolkit_run_as: Option<&str>, tool_run_as: Option<&str>) -> AppEnv {
    spy_helper_dir();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_str().unwrap().to_string();
    let mut tk = json!({"executor": "file", "path_roots": [root]});
    if let Some(r) = toolkit_run_as {
        tk["run_as"] = json!(r);
    }
    let mut tools = Vec::new();
    for op in ["read", "write"] {
        let mut params = json!({"path": {"type": "string", "required": true, "pattern": "^/.*"}});
        if op == "write" {
            params["content"] = json!({"type": "string", "required": true, "pattern": "[\\s\\S]*",
                                       "allow_control_characters": true});
        }
        let mut spec = json!({"id": format!("files.{op}"), "toolkit": "files",
                              "category": op, "file_operation": op, "enabled": true, "parameters": params});
        if let Some(r) = tool_run_as {
            spec["run_as"] = json!(r);
        }
        tools.push(spec);
    }
    let e = builder().tier1(json!({"toolkits": {"files": tk}})).tools(tools).build();
    // The root outlives the test, like the env's own temp files.
    let _ = dir.keep();
    e
}

fn file_agent() -> Identity {
    let token = generate_token();
    let mut id = agent("agent", &["files.read", "files.write"], &[]);
    id.token_hash = hash_token(&token);
    id
}

fn root_of(e: &AppEnv) -> String {
    e.service.tier1().toolkits["files"].path_roots[0].clone()
}

#[tokio::test]
async fn tool_run_as_wins_over_toolkit_run_as() {
    let e = file_env(Some("568:568"), Some("root"));
    let path = format!("{}/x.txt", root_of(&e));
    let result = call(&e, &file_agent(), "files.read", json!({"path": path})).await.unwrap();
    assert_eq!(result.outcome, OUTCOME_OK);
    assert_eq!(captured_run_as(&path), Some(json!("root")));
    let path2 = format!("{}/y.txt", root_of(&e));
    call(&e, &file_agent(), "files.write", json!({"path": path2, "content": "x"})).await.unwrap();
    assert_eq!(captured_run_as(&path2), Some(json!("root")));
}

#[tokio::test]
async fn tool_without_run_as_inherits_toolkit_run_as() {
    let e = file_env(Some("3001:3001"), None);
    let path = format!("{}/x.txt", root_of(&e));
    call(&e, &file_agent(), "files.read", json!({"path": path})).await.unwrap();
    assert_eq!(captured_run_as(&path), Some(json!("3001:3001")));
}

#[tokio::test]
async fn tool_run_as_empty_string_clears_toolkit_run_as() {
    let e = file_env(Some("root"), Some(""));
    let path = format!("{}/x.txt", root_of(&e));
    std::fs::write(&path, "in-process").unwrap();
    let result = call(&e, &file_agent(), "files.read", json!({"path": path})).await.unwrap();
    // Ran in-process: the real file content, and the helper never saw it.
    assert_eq!(result.outcome, OUTCOME_OK);
    assert!(result.stdout.contains("in-process"));
    assert_eq!(captured_run_as(&path), None);
}

// -- Secret masking in tool output (1.18.0) ----------------------------------------

/// A `file` toolkit with a read and a write tool, `redact_secrets` as given
/// (`None` leaves the executor default, which is on).
fn masking_env(redact_secrets: Option<bool>) -> (AppEnv, String) {
    let dir = tempfile::tempdir().unwrap().keep();
    let root = dir.to_str().unwrap().to_string();
    let mut tk = json!({"executor": "file", "path_roots": [root]});
    if let Some(on) = redact_secrets {
        tk["redact_secrets"] = json!(on);
    }
    let mut tools = Vec::new();
    for op in ["read", "write"] {
        let mut params = json!({"path": {"type": "string", "required": true, "pattern": "^/.*"}});
        if op == "write" {
            params["content"] = json!({"type": "string", "required": true, "pattern": "[\\s\\S]*",
                                       "allow_control_characters": true});
        }
        tools.push(json!({"id": format!("files.{op}"), "toolkit": "files",
                          "category": op, "file_operation": op, "enabled": true, "parameters": params}));
    }
    let e = builder().tier1(json!({"toolkits": {"files": tk}})).tools(tools).build();
    (e, root)
}

#[tokio::test]
async fn config_reads_come_back_with_secrets_masked() {
    let (e, root) = masking_env(None);
    let path = format!("{root}/.env");
    std::fs::write(&path, "APP_NAME=web\nDB_PASSWORD=hunter2\nDATABASE_URL=postgres://app:s3cret@db/app\n").unwrap();
    let result = call(&e, &file_agent(), "files.read", json!({"path": path})).await.unwrap();
    assert_eq!(result.outcome, OUTCOME_OK);
    assert!(result.stdout.contains("APP_NAME=web"), "{}", result.stdout);
    assert!(result.stdout.contains("DB_PASSWORD=[redacted]"), "{}", result.stdout);
    assert!(result.stdout.contains("postgres://app:[redacted]@db/app"), "{}", result.stdout);
    assert!(!result.stdout.contains("hunter2") && !result.stdout.contains("s3cret"));
}

#[tokio::test]
async fn writing_a_masked_value_back_is_refused() {
    let (e, root) = masking_env(None);
    let path = format!("{root}/.env");
    std::fs::write(&path, "DB_PASSWORD=hunter2\n").unwrap();
    let result = call(&e, &file_agent(), "files.write",
                      json!({"path": path, "content": "DB_PASSWORD=[redacted]\nNEW=1\n"})).await.unwrap();
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(result.denial_reason.as_deref(), Some("param_invalid"));
    assert!(result.stderr.contains("[redacted]"), "{}", result.stderr);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "DB_PASSWORD=hunter2\n");
    assert_eq!(last_audit(&e)["denial_reason"], "param_invalid");
}

#[tokio::test]
async fn redact_secrets_false_returns_the_file_as_is() {
    let (e, root) = masking_env(Some(false));
    let path = format!("{root}/.env");
    std::fs::write(&path, "DB_PASSWORD=hunter2\n").unwrap();
    let result = call(&e, &file_agent(), "files.read", json!({"path": path})).await.unwrap();
    assert!(result.stdout.contains("DB_PASSWORD=hunter2"), "{}", result.stdout);
    let written = call(&e, &file_agent(), "files.write",
                       json!({"path": path, "content": "note: [redacted] stays literal\n"})).await.unwrap();
    assert_eq!(written.outcome, OUTCOME_OK);
}

#[tokio::test]
async fn local_tool_output_carries_no_known_credential() {
    // Known-secret masking now reaches `local`/`docker` and `file` output
    // too, not only the executors that were handed the redactor.
    let e = AppEnv::new();
    e.audit.set_secrets(vec!["media-jellyfin".into()]);
    let result = call(&e, &full(), "demo.show", json!({"stack": "media-jellyfin"})).await.unwrap();
    assert!(!result.stdout.contains("media-jellyfin"), "{}", result.stdout);
    assert!(result.stdout.contains("***"), "{}", result.stdout);
}

// -- Mailbox through the service (test_agent_messaging.py / test_mailbox_notify.py) --

fn agent_env() -> AppEnv {
    let dir = tempfile::tempdir().unwrap().keep();
    let mailbox = dir.join("messages.yaml");
    let ops = ["send_message", "read_messages", "mailbox_status"];
    let tools: Vec<Value> = vec![
        json!({"id": "agent.send_message", "toolkit": "agent", "agent_operation": "send_message", "version": 1,
               "title": "Send", "description": "d", "category": "write", "idempotent": false, "enabled": true,
               "parameters": {
                   "to": {"type": "string", "required": true, "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$", "description": "to"},
                   "subject": {"type": "string", "required": false, "pattern": "^.{0,120}$", "description": "s"},
                   "body": {"type": "string", "required": true, "pattern": "[\\s\\S]{1,4000}",
                            "allow_control_characters": true, "description": "b"}},
               "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 8192}),
        json!({"id": "agent.read_messages", "toolkit": "agent", "agent_operation": "read_messages", "version": 1,
               "title": "Read", "description": "d", "category": "read", "idempotent": false, "enabled": true,
               "parameters": {}, "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 8192}),
    ];
    let ids = vec![
        json!({"id": "dev", "role": "agent", "token_hash": hash_token(&generate_token()),
               "tools": ["agent.send_message", "agent.read_messages"], "scopes": []}),
        json!({"id": "homelab", "role": "agent", "token_hash": hash_token(&generate_token()),
               "tools": ["agent.send_message", "agent.read_messages"], "scopes": []}),
    ];
    builder()
        .tier1(json!({"toolkits": {"agent": {"executor": "agent", "mailbox_path": mailbox.to_str().unwrap(),
            "allowed_agent_operations": ops, "max_timeout_seconds": 10, "max_output_bytes": 65536}}}))
        .tools(tools)
        .identities(ids)
        .build()
}

#[tokio::test]
async fn mailbox_delivery_through_the_service() {
    std::env::remove_var("GATEKEEPER_NOTIFY_URL");
    let e = agent_env();
    let sent = call(
        &e,
        &e.identity("dev"),
        "agent.send_message",
        json!({"to": "homelab", "subject": "deploy", "body": "jellyfin restarted"}),
    )
    .await
    .unwrap();
    assert_eq!(sent.outcome, OUTCOME_OK);
    let sent: Value = serde_json::from_str(&sent.stdout).unwrap();
    assert_eq!(sent["delivered"], true);
    let toolkit = e.service.tier1().toolkits["agent"].clone();
    assert_eq!(e.service.mailbox(&toolkit).unread_count("homelab").unwrap(), 1);
    // One store per mailbox path.
    assert!(std::sync::Arc::ptr_eq(&e.service.mailbox(&toolkit), &e.service.mailbox(&toolkit)));

    // Isolation: the sender's own mailbox is empty.
    let own = call(&e, &e.identity("dev"), "agent.read_messages", json!({})).await.unwrap();
    assert!(!own.stdout.contains("jellyfin restarted"));
    let read = call(&e, &e.identity("homelab"), "agent.read_messages", json!({})).await.unwrap();
    assert_eq!(read.outcome, OUTCOME_OK);
    assert!(read.stdout.contains("jellyfin restarted"));
    assert!(read.stdout.contains("\"from\": \"dev\""));
    assert_eq!(e.service.mailbox(&toolkit).unread_count("homelab").unwrap(), 0);
}

#[tokio::test]
async fn mailbox_refuses_an_unknown_recipient_and_a_claimed_sender() {
    let e = agent_env();
    let d = denial(call(&e, &e.identity("dev"), "agent.send_message", json!({"to": "nobody", "body": "x"})).await);
    assert!(d.agent_message().starts_with("There is no identity 'nobody'."));
    let d = denial(
        call(&e, &e.identity("dev"), "agent.send_message", json!({"to": "homelab", "body": "x", "from": "homelab"})).await,
    );
    assert_eq!(d.reason, DenialReason::ParamUnknown);
}

// -- Artifacts through the service (test_artifacts.py) ---------------------------------

const COMMIT: &str = "7aa7b394cb713162db98aad29c91c342508a49c7";
const CONTRACT: &str = "example-doc";
const ADAPTER: &str = "example-kit";

fn artifact_env() -> AppEnv {
    let dir = tempfile::tempdir().unwrap().keep();
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join("docs")).unwrap();
    std::fs::write(repo.join("docs/EXAMPLE.md"), b"# Example document\r\n\nreleased with the image\n").unwrap();
    std::fs::create_dir_all(repo.join("kit/pkg")).unwrap();
    std::fs::write(repo.join("kit/pkg/main.py"), "print('hello')\n").unwrap();
    let out = dir.join("artifacts");
    let sources = [
        Source {
            id: CONTRACT.into(),
            kind: SourceKind::File,
            path: "docs/EXAMPLE.md".into(),
            file: "EXAMPLE.md".into(),
            media_type: "text/markdown; charset=utf-8".into(),
            text: true,
        },
        Source {
            id: ADAPTER.into(),
            kind: SourceKind::Tree,
            path: "kit".into(),
            file: "example-kit.tar.gz".into(),
            media_type: "application/gzip".into(),
            text: false,
        },
    ];
    build(repo.to_str().unwrap(), out.to_str().unwrap(), COMMIT, "0.52.0", &sources).unwrap();

    let params = json!({"artifact": {"type": "string", "required": true, "pattern": "^[a-z0-9-]+$", "description": "id"},
                        "version": {"type": "string", "pattern": "^[0-9a-f]{7,40}$", "description": "commit"}});
    let tool = |id: &str, op: &str, params: Value| {
        json!({"id": id, "toolkit": "artifact", "version": 1, "enabled": true, "category": "read",
               "idempotent": true, "required_scopes": [], "timeout_seconds": 30, "max_output_bytes": 200000,
               "description": "artifact tool", "title": id, "artifact_operation": op, "parameters": params})
    };
    let tools = vec![
        tool("artifact.list", "list", json!({})),
        tool("artifact.info", "info", params.clone()),
        tool("artifact.read", "read", params),
    ];
    let names = ["artifact.list", "artifact.info", "artifact.read"];
    let ids = vec![
        json!({"id": "homelab", "role": "agent", "token_hash": hash_token(&generate_token()),
               "tools": names, "scopes": ["artifact:*"]}),
        json!({"id": "other", "role": "agent", "token_hash": hash_token(&generate_token()),
               "tools": names, "scopes": [format!("artifact:{CONTRACT}")]}),
    ];
    let e = builder()
        .tier1(json!({"toolkits": {"artifact": {"executor": "artifact",
            "allowed_artifact_operations": ["list", "info", "read", "transfer"],
            "allowed_artifacts": [CONTRACT, ADAPTER], "handover_dir": dir.join("handover").to_str().unwrap(),
            "max_output_bytes": 200000}}}))
        .tools(tools)
        .identities(ids)
        .build();
    e.service.set_artifact_store(ArtifactStore::new(out.to_str().unwrap()));
    e
}

fn artifact_ids(stdout: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(stdout).unwrap();
    let mut ids: Vec<String> = v["artifacts"].as_array().unwrap().iter().map(|a| a["id"].as_str().unwrap().to_string()).collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn artifact_list_is_filtered_by_scope() {
    let e = artifact_env();
    let full = call(&e, &e.identity("homelab"), "artifact.list", json!({})).await.unwrap();
    assert_eq!(artifact_ids(&full.stdout), [CONTRACT, ADAPTER].iter().map(|s| s.to_string()).collect::<Vec<_>>().tap_sorted());
    let v: Value = serde_json::from_str(&full.stdout).unwrap();
    assert_eq!(v["commit"], COMMIT);
    let narrow = call(&e, &e.identity("other"), "artifact.list", json!({})).await.unwrap();
    assert_eq!(artifact_ids(&narrow.stdout), [CONTRACT]);
}

#[tokio::test]
async fn artifact_missing_scope_looks_unknown_and_reads_work() {
    let e = artifact_env();
    let hidden = call(&e, &e.identity("other"), "artifact.info", json!({"artifact": ADAPTER})).await.unwrap();
    let unknown = call(&e, &e.identity("other"), "artifact.info", json!({"artifact": "does-not-exist"})).await.unwrap();
    assert_eq!(hidden.outcome, "failed");
    assert_eq!(unknown.outcome, "failed");
    assert_eq!(hidden.stderr, unknown.stderr);

    let info = call(&e, &e.identity("homelab"), "artifact.info", json!({"artifact": CONTRACT, "version": &COMMIT[..7]}))
        .await
        .unwrap();
    let info: Value = serde_json::from_str(&info.stdout).unwrap();
    assert_eq!(info["commit"], COMMIT);
    assert_eq!(info["download_path"], format!("/artifacts/{CONTRACT}/{COMMIT}"));
    let text = call(&e, &e.identity("homelab"), "artifact.read", json!({"artifact": CONTRACT})).await.unwrap();
    assert!(text.stdout.starts_with("# Example document\n"));
    let binary = call(&e, &e.identity("homelab"), "artifact.read", json!({"artifact": ADAPTER})).await.unwrap();
    assert!(binary.outcome == "failed" && binary.stderr.contains("artifact.transfer"));
    denial(call(&e, &e.identity("homelab"), "artifact.info", json!({"artifact": "../etc"})).await);
}

trait TapSorted {
    fn tap_sorted(self) -> Self;
}

impl TapSorted for Vec<String> {
    fn tap_sorted(mut self) -> Self {
        self.sort();
        self
    }
}
