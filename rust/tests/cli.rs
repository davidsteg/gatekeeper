//! The `gatekeeper` binary itself (ports of the CLI parts of
//! `test_audit_dir.py`, `test_selfdrop.py` and `test_runas.py`), plus one
//! end-to-end agent session with the Python MCP SDK against `serve`.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use gatekeeper::identity::{generate_token, hash_token, hash_token_lookup};

mod common;
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_gatekeeper");
const STANDARD: &str = "/var/log/gatekeeper";

/// The binary with a clean gatekeeper environment.
fn gatekeeper() -> Command {
    gatekeeper_at(Path::new(BIN))
}

/// The binary at `path` (a copy of [`BIN`]), with no inherited `GATEKEEPER_*`.
fn gatekeeper_at(path: &Path) -> Command {
    let mut cmd = Command::new(path);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GATEKEEPER_") {
            cmd.env_remove(&key);
        }
    }
    cmd
}

fn run(cmd: &mut Command) -> (i32, String, String) {
    let Output { status, stdout, stderr } = cmd.output().unwrap();
    (
        status.code().unwrap_or(-1),
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

fn load(path: &Path) -> Value {
    gatekeeper::yaml::load(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Runs `gatekeeper init` and returns the audit dir it wrote.
fn init(config_dir: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut cmd = gatekeeper();
    cmd.arg("init").arg("--config-dir").arg(config_dir).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let (code, _, stderr) = run(&mut cmd);
    assert_eq!(code, 0, "{stderr}");
    load(&config_dir.join("toolkits.yaml"))["audit"]["dir"].as_str().unwrap().to_string()
}

// -- test_audit_dir.py ---------------------------------------------------------------

#[test]
fn the_env_names_the_audit_dir() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(init(&tmp.path().join("cfg"), &[], &[("GATEKEEPER_AUDIT_DIR", STANDARD)]), STANDARD);
}

#[test]
fn without_the_env_it_stays_self_contained() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("cfg");
    assert_eq!(init(&config, &[], &[]), config.join("logs").to_str().unwrap());
}

#[test]
fn the_flag_beats_the_env() {
    let tmp = tempfile::tempdir().unwrap();
    let written = init(&tmp.path().join("cfg"), &["--audit-dir", "/somewhere/else"], &[("GATEKEEPER_AUDIT_DIR", STANDARD)]);
    assert_eq!(written, "/somewhere/else");
}

#[test]
fn the_audit_dir_is_not_inside_the_config_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("cfg");
    let written = init(&config, &[], &[("GATEKEEPER_AUDIT_DIR", STANDARD)]);
    assert!(!written.starts_with(config.to_str().unwrap()));
}

// -- init, check, token, password, credential-key --------------------------------------

#[test]
fn init_refuses_to_overwrite_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("cfg");
    init(&config, &[], &[]);
    let (code, _, stderr) = run(gatekeeper().arg("init").arg("--config-dir").arg(&config));
    assert_eq!(code, 1);
    assert!(stderr.starts_with("Refusing to overwrite:\n  "), "{stderr}");
    assert!(stderr.contains("Pass --force to replace them."));
    let (code, stdout, _) = run(gatekeeper().arg("init").arg("--config-dir").arg(&config).arg("--force"));
    assert_eq!(code, 0);
    assert!(stdout.starts_with("Created:\n"), "{stdout}");
    assert!(stdout.contains("Administrator API token for /mcp (shown once):"));
}

#[test]
fn an_initialised_config_checks_clean_and_a_broken_one_does_not() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("cfg");
    init(&config, &[], &[]);
    let (code, stdout, stderr) = run(gatekeeper().arg("check").env("GATEKEEPER_CONFIG_DIR", &config));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "OK: 0 toolkits, 0 tools, 1 identities\n");
    std::fs::write(config.join("toolkits.yaml"), "toolkits: [\n").unwrap();
    let (code, _, stderr) = run(gatekeeper().arg("check").env("GATEKEEPER_CONFIG_DIR", &config));
    assert_eq!(code, 1);
    assert!(stderr.starts_with("ERROR: "), "{stderr}");
}

#[test]
fn token_hashes_a_given_token() {
    let (code, stdout, _) = run(gatekeeper().args(["token", "--token", "abc"]));
    assert_eq!(code, 0);
    assert!(stdout.starts_with("Token (shown once, goes into the agent config.yaml):\n  abc\n\n"), "{stdout}");
    assert!(stdout.contains(&format!("token_lookup (goes into identities.yaml too")));
    assert!(stdout.contains(&hash_token_lookup("abc")));
}

#[test]
fn credential_key_prints_a_key_once() {
    let (code, stdout, _) = run(gatekeeper().arg("credential-key"));
    assert_eq!(code, 0);
    assert!(stdout.starts_with("Credential master key (shown once):\n  "), "{stdout}");
}

#[test]
fn password_sets_the_console_password() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("cfg");
    init(&config, &[], &[]);
    let (code, stdout, stderr) = run(
        gatekeeper().args(["password", "--identity", "admin", "--password", "a-new-password-1"]).env("GATEKEEPER_CONFIG_DIR", &config),
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.starts_with("Console password for 'admin' in "), "{stdout}");
    assert!(!stdout.contains("Password (shown once)"));
    let (code, _, stderr) =
        run(gatekeeper().args(["password", "--identity", "ghost"]).env("GATEKEEPER_CONFIG_DIR", &config));
    assert_eq!(code, 1);
    assert!(stderr.starts_with("ERROR: "), "{stderr}");
}

#[test]
fn a_missing_subcommand_is_a_usage_error() {
    let (code, _, stderr) = run(&mut gatekeeper());
    assert_eq!(code, 2);
    assert!(stderr.to_lowercase().contains("usage"), "{stderr}");
}

/// The files `init` writes match the Python CLI's, secrets aside: what
/// `python -m gatekeeper init --audit-dir /audit` wrote, frozen in
/// `fixtures/init_golden/` when the Python implementation was removed
/// (1.16.0), with the hash values masked.
#[test]
fn init_writes_what_the_python_cli_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let rust = tmp.path().join("rust");
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/init_golden");
    init(&rust, &["--audit-dir", "/audit"], &[]);
    for name in ["toolkits.yaml", "tools.yaml"] {
        assert_eq!(
            std::fs::read_to_string(rust.join(name)).unwrap(),
            std::fs::read_to_string(golden.join(name)).unwrap(),
            "{name}"
        );
    }
    let mask = |text: String| -> Vec<String> {
        text.lines().map(|l| l.split_once(": \"").map(|(k, _)| format!("{k}: <hash>")).unwrap_or(l.to_string())).collect()
    };
    let masked: Vec<String> =
        std::fs::read_to_string(golden.join("identities.masked.yaml")).unwrap().lines().map(str::to_string).collect();
    assert_eq!(mask(std::fs::read_to_string(rust.join("identities.yaml")).unwrap()), masked);
}

// -- test_selfdrop.py / test_runas.py: the CLI wiring ----------------------------------

fn is_root() -> bool {
    // SAFETY: getuid has no preconditions.
    unsafe { libc_getuid() == 0 }
}

extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

#[test]
fn a_failed_drop_aborts_startup_rather_than_serving_as_root() {
    if !is_root() {
        eprintln!("skipping: needs root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) =
        run(gatekeeper().arg("check").env("GATEKEEPER_CONFIG_DIR", tmp.path()).env("GATEKEEPER_DROP_TO", "0:0"));
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stderr.contains("Configuration error"), "{stderr}");
}

#[test]
fn require_run_as_refuses_to_start_without_the_privilege() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    if !is_root() {
        eprintln!("skipping: needs root to become nobody");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("cfg");
    let logs = tmp.path().join("logs");
    std::fs::create_dir(&logs).unwrap();
    init(&config, &[], &[]);
    std::fs::write(
        config.join("toolkits.yaml"),
        format!(
            "audit:\n  dir: {}\ntoolkits:\n  agentcfg:\n    executor: file\n    path_roots: [{}]\n    \
             run_as: \"3001:3001\"\n    max_timeout_seconds: 15\n    max_output_bytes: 4096\n",
            logs.display(),
            tmp.path().display()
        ),
    )
    .unwrap();
    // nobody must be able to execute the binary, and the build tree may sit
    // under a home directory it cannot enter (the CI runner's is 0750).
    let bin = tmp.path().join("gatekeeper");
    std::fs::copy(BIN, &bin).unwrap();
    for entry in walk(tmp.path()) {
        std::fs::set_permissions(entry, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    let port = free_port();
    let mut cmd = gatekeeper_at(&bin);
    cmd.arg("serve")
        .env("GATEKEEPER_CONFIG_DIR", &config)
        .env("GATEKEEPER_PORT", port.to_string())
        .env("GATEKEEPER_REQUIRE_RUN_AS", "1")
        .uid(65534)
        .gid(65534)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().unwrap();
    let output = wait_with_timeout(child, Duration::from_secs(25)).expect("serve did not exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("GATEKEEPER_REQUIRE_RUN_AS"), "{stderr}");
    assert!(stderr.contains("cannot assume another user"), "{stderr}");
}

#[test]
fn the_switch_reads_the_usual_truthy_values() {
    for (value, aborts) in [("1", true), ("true", true), ("yes", true), ("0", false), ("", false)] {
        // The only test in this binary touching this variable.
        std::env::set_var("GATEKEEPER_REQUIRE_RUN_AS", value);
        assert_eq!(gatekeeper::cli::require_run_as(), aborts, "{value:?}");
    }
    std::env::remove_var("GATEKEEPER_REQUIRE_RUN_AS");
}

// -- An end-to-end agent session against `serve` -----------------------------------------

/// A config dir with one `local` echo tool, granted to an agent whose token
/// the test knows.
fn echo_deployment(dir: &Path) -> String {
    let token = generate_token();
    let logs = dir.join("logs");
    let toolkits = json!({
        "toolkits": {"demo": {"executor": "local", "binaries": ["/bin/sh"], "denied_args": [],
                              "max_timeout_seconds": 10, "max_output_bytes": 4096}},
        "audit": {"dir": logs.to_str().unwrap()},
    });
    let tools = json!({"tools": [{
        "id": "demo.echo", "toolkit": "demo", "binary": "/bin/sh", "version": 1,
        "title": "Echo", "description": "Outputs the given text.",
        "category": "read", "idempotent": true, "enabled": true,
        "argv": ["-c", "printf '%s\\n' \"$1\"", "sh", "{text}"],
        "parameters": {"text": {"type": "string", "required": true, "pattern": "^.+$", "description": "text"}},
        "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 4096,
    }]});
    let identities = json!({"identities": [{
        "id": "agent", "role": "agent", "token_hash": hash_token(&token), "token_lookup": hash_token_lookup(&token),
        "tools": ["demo.echo"], "scopes": [],
    }]});
    for (name, doc) in [("toolkits.yaml", toolkits), ("tools.yaml", tools), ("identities.yaml", identities)] {
        std::fs::write(dir.join(name), gatekeeper::yaml::dump(&doc)).unwrap();
    }
    token
}

struct Server(std::process::Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_python_sdk_agent_session_against_the_real_serve_binary() {
    let Some(python) = common::mcp_python() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let token = echo_deployment(tmp.path());
    let port = free_port();
    let server = Server(
        gatekeeper()
            .args(["serve", "--host", "127.0.0.1", "--port", &port.to_string(), "--no-bootstrap"])
            .env("GATEKEEPER_CONFIG_DIR", tmp.path())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(tmp.path().join("serve.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    let base = format!("http://127.0.0.1:{port}");
    wait_until_live(port);

    let output = Command::new(&python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/agent_session.py"))
        .arg(&base)
        .arg(&token)
        .output()
        .unwrap();
    drop(server);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let log = std::fs::read_to_string(tmp.path().join("serve.log")).unwrap_or_default();
    let audit = std::fs::read_to_string(tmp.path().join("logs/audit.jsonl")).unwrap_or_default();
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{}\nserve:\n{log}\naudit:\n{audit}",
        String::from_utf8_lossy(&output.stderr)
    );
    for line in [
        "ok legacy (2025-11-25): tools/list + tools/call demo.echo",
        "ok auto (2026-07-28): tools/list + tools/call demo.echo",
        "ALL OK",
    ] {
        assert!(stdout.contains(line), "missing {line:?} in\n{stdout}");
    }
    // The calls were audited by the binary, into the configured directory.
    assert!(audit.contains("\"demo.echo\""), "{audit}");
}

// -- helpers ------------------------------------------------------------------------------

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_until_live(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            use std::io::{Read, Write};
            let _ = stream.write_all(b"GET /health/live HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            if response.starts_with("HTTP/1.1 200") {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("serve did not come up on port {port}");
}

fn wait_with_timeout(mut child: std::process::Child, timeout: Duration) -> Option<Output> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return Some(child.wait_with_output().unwrap());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    None
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![root.to_path_buf()];
    if root.is_dir() {
        for entry in std::fs::read_dir(root).unwrap() {
            out.extend(walk(&entry.unwrap().path()));
        }
    }
    out
}
