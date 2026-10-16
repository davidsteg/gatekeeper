//! Tests for the `ssh` executor (port of `tests/test_execute_ssh.py`).
//!
//! Against a real russh server with an ephemeral host key, not a mock: the
//! properties that matter -- argv elements arrive shell-quoted, host-key
//! pinning actually rejects an unpinned/wrong key, a denied arg never
//! reaches the wire -- are exactly what a mocked `run()` would assume away.
//! The server never spawns a shell; it echoes the command string it
//! received, which doubles as a check on exactly what was sent.

use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::LineEnding;
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};

use super::*;
use crate::catalog::parse_tool_spec;
use crate::credentials::tests::env;
use crate::tier1::{load_tier1, Tier1};
use crate::validate::{build_argv, Values};

#[derive(Clone)]
struct Recording {
    authorized: KeyData,
    password: &'static str,
}

impl russh::server::Handler for Recording {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if key.key_data() == &self.authorized { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if password == self.password { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(&mut self, _channel: Channel<Msg>, _session: &mut Session) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        session.channel_success(channel)?;
        let handle = session.handle();
        tokio::spawn(async move {
            let code = if command.contains("slow") {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = handle.data(channel, CryptoVec::from("late\n".to_string())).await;
                0
            } else if command.contains("denied-binary") {
                let _ = handle.extended_data(channel, 1, CryptoVec::from("not found\n".to_string())).await;
                127
            } else {
                let _ = handle.data(channel, CryptoVec::from(format!("ran: {command}\n"))).await;
                0
            };
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }
}

struct SshServer {
    port: u16,
    known_hosts: String,
    client_private_key: String,
}

fn new_key() -> PrivateKey {
    PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap()
}

fn openssh_private(key: &PrivateKey) -> String {
    key.to_openssh(LineEnding::LF).unwrap().to_string()
}

fn openssh_public(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap()
}

async fn ssh_server() -> SshServer {
    let host_key = new_key();
    let client_key = new_key();
    let handler = Recording { authorized: client_key.public_key().key_data().clone(), password: "sekret" };
    let known_hosts = format!("127.0.0.1 {}", openssh_public(&host_key));
    let config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let (config, handler) = (config.clone(), handler.clone());
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    SshServer { port, known_hosts, client_private_key: openssh_private(&client_key) }
}

fn ssh_tier1(dir: &std::path::Path, name: &str, port: u16, known_hosts: &str) -> Tier1 {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "toolkits:\n  demo_ssh:\n    executor: ssh\n    ssh_host: \"127.0.0.1\"\n    ssh_port: {port}\n    ssh_user: \"gatekeeper\"\n    ssh_known_hosts: \"{known_hosts}\"\n    binaries: [\"/usr/bin/uptime\", \"/usr/bin/denied-binary\"]\n    denied_args: [\"--evil\"]\n    credential: demo_ssh_key\naudit:\n  dir: {}\n",
            dir.join("logs").display()
        ),
    )
    .unwrap();
    load_tier1(path.to_str().unwrap()).unwrap()
}

fn tool(tier1: &Tier1, overrides: Value) -> ToolDef {
    let mut spec = serde_json::json!({
        "id": "demo_ssh.uptime", "toolkit": "demo_ssh", "version": 1,
        "title": "Uptime", "description": "test", "category": "read",
        "enabled": true, "binary": "/usr/bin/uptime", "argv": ["{arg}"],
        "parameters": {"arg": {"type": "string", "pattern": "^.*$", "required": true}},
        "timeout_seconds": 5, "max_output_bytes": 65536,
    });
    for (k, v) in overrides.as_object().unwrap() {
        spec[k] = v.clone();
    }
    parse_tool_spec(&spec, tier1).unwrap()
}

fn args_tool(tier1: &Tier1, argv: Value) -> ToolDef {
    tool(
        tier1,
        serde_json::json!({"argv": argv, "parameters": {"args": {"type": "string", "pattern": "^.*$", "required": true}}}),
    )
}

fn values(pairs: &[(&str, &str)]) -> Values {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

use serde_json::Value;

async fn exec(argv: &[String], tk: &Toolkit, store: Option<&CredentialStore>, timeout: f64, idempotent: bool, tool: Option<&ToolDef>) -> ExecResult {
    run(argv, tk, store, timeout, 65536, idempotent, None, tool).await.unwrap()
}

#[tokio::test]
async fn successful_command() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let argv = build_argv(&tool(&tier1, serde_json::json!({})), &values(&[("arg", "-a")]), tk).unwrap();
    let r = exec(&argv, tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(r.exit_code, Some(0));
    assert_eq!(r.stdout, "ran: /usr/bin/uptime -a\n");
    assert!(!r.external_untrusted);
}

#[tokio::test]
async fn nonzero_exit_and_stderr() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let r = exec(&["/usr/bin/denied-binary".to_string()], tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.exit_code, Some(127));
    assert_eq!(r.stderr, "not found\n");
}

#[tokio::test]
async fn argv_elements_are_shell_quoted() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let dangerous = "; rm -rf / #";
    let argv = build_argv(&tool(&tier1, serde_json::json!({})), &values(&[("arg", dangerous)]), tk).unwrap();
    let r = exec(&argv, tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_OK);
    assert!(r.stdout.contains(&format!("ran: /usr/bin/uptime {}", shlex_quote(dangerous))));
    assert_eq!(r.stdout, "ran: /usr/bin/uptime '; rm -rf / #'\n");
}

#[tokio::test]
async fn wrong_host_key_is_refused() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let wrong = format!("127.0.0.1 {}", openssh_public(&new_key()));
    let tier1 = ssh_tier1(e.dir.path(), "tk-wrong.yaml", server.port, &wrong);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let argv = build_argv(&tool(&tier1, serde_json::json!({})), &values(&[("arg", "-a")]), tk).unwrap();
    let r = exec(&argv, tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(
        r.stderr,
        "Host key for 127.0.0.1 did not match ssh_known_hosts -- refusing to connect (possible MITM): Host key is not trusted for host 127.0.0.1"
    );
}

#[tokio::test]
async fn revoked_host_key_is_refused() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let key = server.known_hosts.strip_prefix("127.0.0.1 ").unwrap();
    let pinned = format!("{}\n@revoked * {key}", server.known_hosts);
    let mut tk = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts).toolkit("demo_ssh").unwrap().clone();
    tk.ssh_known_hosts = Some(pinned);
    let r = exec(&["/usr/bin/uptime".to_string()], &tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert!(r.stderr.ends_with("(possible MITM): Host key is revoked for host 127.0.0.1"), "{}", r.stderr);
}

#[tokio::test]
async fn missing_credential_denied() {
    let e = env();
    let server = ssh_server().await;
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let r = exec(&["/usr/bin/uptime".to_string()], tk, None, 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "No credential store is configured, but this toolkit needs one.");
    let r = exec(&["/usr/bin/uptime".to_string()], tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.stderr, "Credential 'demo_ssh_key' is not configured yet.");
}

#[tokio::test]
async fn wrong_client_key_is_refused() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &openssh_private(&new_key()), None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let r = exec(&["/usr/bin/uptime".to_string()], tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "SSH connection failed: Permission denied for user gatekeeper on host 127.0.0.1");
}

#[tokio::test]
async fn password_credential_authenticates() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_password", "sekret", None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let r = exec(&["/usr/bin/uptime".to_string()], tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
}

#[tokio::test]
async fn timeout_on_non_idempotent_is_unknown() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let r = exec(&["true; slow".to_string()], tk, Some(&e.store), 0.3, false, None).await;
    assert_eq!(r.outcome, OUTCOME_UNKNOWN);
    assert_eq!(
        r.stderr,
        "Timeout of 0.3s exceeded. The outcome is UNKNOWN: the command may have run on the remote host. Do not retry without checking the state first."
    );
}

#[test]
fn auth_plan_matches_credential_kind() {
    let cred = |kind: &str, value: &str| ResolvedCredential {
        name: "demo_ssh_key".into(),
        kind: kind.into(),
        header: None,
        value: value.into(),
        previous_value: None,
        header_format: None,
    };
    // ssh_password -> password, no client keys.
    let plan = auth_plan(Some(&cred("ssh_password", "sekret"))).unwrap();
    assert_eq!(plan.preferred_auth(), "password");
    assert!(matches!(plan, AuthPlan::Password(ref p) if p == "sekret"));
    // ssh_private_key -> exactly that key.
    let key = new_key();
    let plan = auth_plan(Some(&cred("ssh_private_key", &openssh_private(&key)))).unwrap();
    assert_eq!(plan.preferred_auth(), "publickey");
    match plan {
        AuthPlan::PublicKey(k) => assert_eq!(k.public_key().key_data(), key.public_key().key_data()),
        other => panic!("{other:?}"),
    }
    assert_eq!(auth_plan(None).unwrap().preferred_auth(), "none");
    assert!(auth_plan(Some(&cred("ssh_private_key", "not a key"))).is_err());
}

#[tokio::test]
async fn non_ssh_credential_denied_before_connect() {
    let e = env();
    e.store.create("demo_ssh_key", "bearer", "tok", None, None, None, "test", "").unwrap();
    // Nothing listens on port 1: reaching connect() would fail differently.
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", 1, "127.0.0.1 ssh-ed25519 AAAA");
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let r = exec(&["/usr/bin/uptime".to_string()], tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "Credential 'demo_ssh_key' is not an ssh_private_key or ssh_password credential.");
}

#[tokio::test]
async fn connection_refused_is_reported() {
    let e = env();
    let server_key = openssh_public(&new_key());
    e.store.create("demo_ssh_key", "ssh_password", "x", None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", 1, &format!("127.0.0.1 {server_key}"));
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let r = exec(&["/usr/bin/uptime".to_string()], tk, Some(&e.store), 5.0, true, None).await;
    assert_eq!(r.stderr, "SSH connection failed: [Errno 111] Connect call failed ('127.0.0.1', 1)");
}

#[tokio::test]
async fn probe_reachable_and_unreachable() {
    let server = ssh_server().await;
    let dir = tempfile::tempdir().unwrap();
    let tier1 = ssh_tier1(dir.path(), "tk.yaml", server.port, &server.known_hosts);
    assert!(probe(tier1.toolkit("demo_ssh").unwrap()).await);
    let tier1 = ssh_tier1(
        dir.path(),
        "tk-unreachable.yaml",
        1,
        "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVALIDKEYVALUEXXXXXXXXXXXXXXXXXXXXXXXXX",
    );
    assert!(!probe(tier1.toolkit("demo_ssh").unwrap()).await);
}

#[tokio::test]
async fn dispatch_mode_returns_immediately() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let t = tool(
        &tier1,
        serde_json::json!({"id": "demo_ssh.sleep", "category": "write", "idempotent": false, "ssh_dispatch": true}),
    );
    let before = std::time::Instant::now();
    let r = exec(&["sleep 30".to_string()], tk, Some(&e.store), 25.0, false, Some(&t)).await;
    assert!(before.elapsed() < Duration::from_secs(5));
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(
        r.stdout.trim_end_matches('\n'),
        "ran: setsid nohup 'sleep 30' </dev/null >>/tmp/gatekeeper-dispatch.log 2>&1 & echo dispatched"
    );
}

#[tokio::test]
async fn args_string_splits_into_separate_tokens() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let t = args_tool(&tier1, serde_json::json!(["{args}"]));
    let argv = build_argv(&t, &values(&[("args", "--oneline -3")]), tk).unwrap();
    assert_eq!(argv, vec!["/usr/bin/uptime".to_string(), "--oneline -3".to_string()]);
    let r = exec(&argv, tk, Some(&e.store), 5.0, true, Some(&t)).await;
    assert_eq!(r.outcome, OUTCOME_OK);
    assert_eq!(r.stdout.trim_end_matches('\n'), "ran: /usr/bin/uptime --oneline -3");
}

#[tokio::test]
async fn empty_args_appends_no_element() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let t = args_tool(&tier1, serde_json::json!(["-p", "{args}"]));
    for value in ["", "   "] {
        let argv = build_argv(&t, &values(&[("args", value)]), tk).unwrap();
        let r = exec(&argv, tk, Some(&e.store), 5.0, true, Some(&t)).await;
        assert_eq!(r.outcome, OUTCOME_OK);
        assert_eq!(r.stdout.trim_end_matches('\n'), "ran: /usr/bin/uptime -p");
    }
}

#[tokio::test]
async fn args_with_embedded_quotes_round_trips() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let t = args_tool(&tier1, serde_json::json!(["{args}"]));
    let argv = build_argv(&t, &values(&[("args", "commit -m 'fixed it; rm -rf /'")]), tk).unwrap();
    let r = exec(&argv, tk, Some(&e.store), 5.0, true, Some(&t)).await;
    assert_eq!(r.outcome, OUTCOME_OK);
    assert_eq!(r.stdout.trim_end_matches('\n'), "ran: /usr/bin/uptime commit -m 'fixed it; rm -rf /'");
}

#[tokio::test]
async fn args_with_unbalanced_quote_is_denied() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let t = args_tool(&tier1, serde_json::json!(["{args}"]));
    let argv = build_argv(&t, &values(&[("args", "commit -m 'oops")]), tk).unwrap();
    let r = exec(&argv, tk, Some(&e.store), 5.0, true, Some(&t)).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "args \"commit -m 'oops\" is not a parseable argument string: No closing quotation");
}

#[tokio::test]
async fn denied_arg_inside_args_string_is_caught_after_split() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let t = args_tool(&tier1, serde_json::json!(["{args}"]));
    let argv = build_argv(&t, &values(&[("args", "-p --evil")]), tk).unwrap();
    let r = exec(&argv, tk, Some(&e.store), 5.0, true, Some(&t)).await;
    assert_eq!(r.outcome, OUTCOME_FAILED);
    assert_eq!(r.stderr, "Argument '--evil' is denied for this toolkit.");
}

/// The exact string Python's `execute_ssh.run` builds for this argv.
const PY_BEACON: &str = r#"setsid nohup sh -c 'nohup sh -c '"'"''"'"'"'"'"'"'"'"'compose up -d gatekeeper --wait'"'"'"'"'"'"'"'"' </dev/null >>/tmp/gatekeeper-recreate.log 2>&1; echo EXIT=$? >>/tmp/gatekeeper-recreate.log'"'"'' & echo dispatched"#;

#[tokio::test]
async fn recreate_beacon_dispatch_wrap() {
    let e = env();
    let server = ssh_server().await;
    e.store.create("demo_ssh_key", "ssh_private_key", &server.client_private_key, None, None, None, "test", "").unwrap();
    let tier1 = ssh_tier1(e.dir.path(), "tk.yaml", server.port, &server.known_hosts);
    let tk = tier1.toolkit("demo_ssh").unwrap();
    let t = tool(
        &tier1,
        serde_json::json!({"id": "demo_ssh.sleep", "category": "write", "idempotent": false, "ssh_dispatch": true}),
    );
    let argv: Vec<String> = ["compose", "up", "-d", "gatekeeper"].iter().map(|s| s.to_string()).collect();
    let r = exec(&argv, tk, Some(&e.store), 25.0, false, Some(&t)).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(r.stdout.trim_end_matches('\n'), format!("ran: {PY_BEACON}"));
}

#[test]
fn shlex_matches_python() {
    // Expected values produced by CPython's shlex.
    let split: &[(&str, &[&str])] = &[
        ("a b", &["a", "b"]),
        ("commit -m 'fixed it; rm -rf /'", &["commit", "-m", "fixed it; rm -rf /"]),
        ("\"a\\\"b\" c", &["a\"b", "c"]),
        ("a\\ b", &["a b"]),
        ("''", &[""]),
        ("\"\"", &[""]),
        ("x\"\"y", &["xy"]),
        ("\"a\\nb\"", &["a\\nb"]),
        ("'a\\b'", &["a\\b"]),
        ("  lead  trail  ", &["lead", "trail"]),
        ("a\tb\nc", &["a", "b", "c"]),
        ("\"\\\\\"", &["\\"]),
        ("#x y", &["#x", "y"]),
    ];
    for (input, expected) in split {
        assert_eq!(shlex_split(input).unwrap(), expected.to_vec(), "{input:?}");
    }
    assert_eq!(shlex_split("commit -m 'oops").unwrap_err(), "No closing quotation");
    assert_eq!(shlex_split("a\\").unwrap_err(), "No escaped character");
    for (input, expected) in [
        ("", "''"),
        ("abc", "abc"),
        ("a b", "'a b'"),
        ("it's", "'it'\"'\"'s'"),
        ("; rm -rf / #", "'; rm -rf / #'"),
        ("--oneline", "--oneline"),
        ("a@b%c+d=e:f,g.h/i-j_k", "a@b%c+d=e:f,g.h/i-j_k"),
        ("x$y", "'x$y'"),
    ] {
        assert_eq!(shlex_quote(input), expected);
    }
    let argv: Vec<String> = ["compose", "up", "-d", "gatekeeper"].iter().map(|s| s.to_string()).collect();
    assert_eq!(build_command(&argv, true), PY_BEACON);
}

#[test]
fn known_hosts_matching_follows_asyncssh() {
    let key = openssh_public(&new_key());
    let data = PublicKey::from_openssh(&key).unwrap().key_data().clone();
    let trusted = |text: &str, host: &str, addr: &str, port: Option<u16>| {
        KnownHosts::parse(text).unwrap().host_keys(host, addr, port).trusted.contains(&data)
    };
    // Plain host, with the fallback from `[host]:port` to the bare host.
    assert!(trusted(&format!("127.0.0.1 {key}"), "127.0.0.1", "127.0.0.1", Some(2222)));
    assert!(trusted(&format!("[127.0.0.1]:2222 {key}"), "127.0.0.1", "127.0.0.1", Some(2222)));
    assert!(!trusted(&format!("[127.0.0.1]:2222 {key}"), "127.0.0.1", "127.0.0.1", None));
    // The peer address matches even when the host name does not.
    assert!(trusted(&format!("nas.lan,10.0.0.5 {key}"), "other", "10.0.0.5", None));
    // Wildcards, negation, CIDR.
    assert!(trusted(&format!("127.0.0.* {key}"), "127.0.0.1", "", None));
    assert!(!trusted(&format!("*,!127.0.0.1 {key}"), "127.0.0.1", "127.0.0.1", None));
    assert!(trusted(&format!("127.0.0.0/8 {key}"), "localhost", "127.0.0.1", None));
    assert!(!trusted(&format!("10.0.0.0/8 {key}"), "localhost", "127.0.0.1", None));
    // Hashed entry for `[127.0.0.1]:2222`, produced by Python's hmac/sha1.
    let hashed = "|1|MDEyMzQ1Njc4OWFiY2RlZmdoaWo=|kjl9J932vxVxCmU2IfKMefPFSKM=";
    assert!(trusted(&format!("{hashed} {key}"), "127.0.0.1", "", Some(2222)));
    assert!(!trusted(&format!("{hashed} {key}"), "127.0.0.2", "", Some(2222)));
    // Revoked and CA entries never trust.
    let kh = KnownHosts::parse(&format!("@revoked 127.0.0.1 {key}")).unwrap();
    assert!(kh.host_keys("127.0.0.1", "", None).revoked.contains(&data));
    assert!(!trusted(&format!("@cert-authority 127.0.0.1 {key}"), "127.0.0.1", "", None));
    // Comments, blank lines and unparseable keys are skipped.
    assert!(trusted(&format!("# c\n\n127.0.0.1 ssh-ed25519 AAAA\n127.0.0.1 {key}"), "127.0.0.1", "", None));
    // Malformed lines fail closed with asyncssh's messages.
    assert_eq!(KnownHosts::parse("lonely").unwrap_err(), "Invalid known hosts entry: lonely");
    assert_eq!(KnownHosts::parse(&format!("@bogus h {key}")).unwrap_err(), "Invalid known hosts marker: bogus");
    assert_eq!(
        KnownHosts::parse(&format!("|2|AAAA|BBBB {key}")).unwrap_err(),
        "Invalid known hosts hash type: 2"
    );
}
