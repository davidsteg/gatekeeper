//! Interop: `gatekeeper::mcp` against the real Python MCP SDK.
//!
//! * `the_python_sdk_client_works_against_the_rust_server`: the SDK's
//!   `Client` lists tools, calls tools and receives `tools/list_changed`,
//!   once as a handshake-era session (standalone GET stream) and once at
//!   2026-07-28 (`subscriptions/listen`), plus both modes on the stateless
//!   mount (`tests/interop/client_test.py`).
//! * `the_wire_matches_the_python_sdk`: one raw-HTTP probe
//!   (`tests/interop/probe.py`, every error path of both eras and both
//!   mounts) against the SDK configured like gatekeeper
//!   (`tests/interop/ref_server.py`) and against the Rust echo server; the
//!   two transcripts must be identical.
//!
//! Both skip (pass with a note) when the Python reference venv is missing.
//! Override its interpreter with `GATEKEEPER_INTEROP_PYTHON`.

#[path = "../examples/mcp_echo.rs"]
mod echo;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

fn python() -> Option<PathBuf> {
    let path = std::env::var_os("GATEKEEPER_INTEROP_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/claude-0/venv/bin/python"));
    if path.exists() {
        Some(path)
    } else {
        eprintln!("skipping: no Python reference interpreter at {}", path.display());
        None
    }
}

fn interop_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("interop")
}

/// The Rust echo server on an ephemeral loopback port.
async fn serve_rust() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = echo::build_app();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    format!("http://{addr}")
}

async fn run_script(python: &Path, script: &str, base: &str) -> (bool, String, String) {
    let output = tokio::time::timeout(
        Duration::from_secs(180),
        Command::new(python).arg(interop_dir().join(script)).arg(base).kill_on_drop(true).output(),
    )
    .await
    .expect("script timed out")
    .expect("script runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_python_sdk_client_works_against_the_rust_server() {
    let Some(python) = python() else { return };
    let base = serve_rust().await;
    let (ok, stdout, stderr) = run_script(&python, "client_test.py", &base).await;
    assert!(ok, "client_test.py failed\nstdout:\n{stdout}\nstderr:\n{stderr}");
    for line in [
        "ok legacy: list_tools + call_tool",
        "ok legacy: tools/list_changed on the standalone stream",
        "ok 2026-07-28: list_tools + call_tool",
        "ok 2026-07-28: tools/list_changed on the listen stream, refetch sees the change",
        "ALL OK",
    ] {
        assert!(stdout.contains(line), "missing {line:?} in\n{stdout}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wire_matches_the_python_sdk() {
    let Some(python) = python() else { return };

    // The reference: the Python SDK, wired the way gatekeeper wires it.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("src");
    let mut reference = Command::new(&python)
        .arg(interop_dir().join("ref_server.py"))
        .env("PYTHONPATH", &src)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("ref_server.py starts");
    let mut lines = BufReader::new(reference.stdout.take().unwrap()).lines();
    let port = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(line) = lines.next_line().await.unwrap() {
            if let Some(p) = line.strip_prefix("PORT ") {
                return p.trim().to_string();
            }
        }
        panic!("ref_server.py exited without a port");
    })
    .await
    .expect("ref_server.py did not start");

    let (py_ok, py_out, py_err) = run_script(&python, "probe.py", &format!("http://127.0.0.1:{port}")).await;
    let _ = reference.kill().await;
    assert!(py_ok, "probe.py failed against the reference\n{py_err}");

    let base = serve_rust().await;
    let (rs_ok, rs_out, rs_err) = run_script(&python, "probe.py", &base).await;
    assert!(rs_ok, "probe.py failed against the Rust server\n{rs_err}\n{rs_out}");

    assert!(py_out.lines().count() > 600, "suspiciously short transcript:\n{py_out}");
    if py_out != rs_out {
        let py: Vec<&str> = py_out.lines().collect();
        let rs: Vec<&str> = rs_out.lines().collect();
        let first = py.iter().zip(&rs).position(|(a, b)| a != b).unwrap_or(py.len().min(rs.len()));
        let lo = first.saturating_sub(8);
        panic!(
            "transcripts differ at line {}\n--- python ---\n{}\n--- rust ---\n{}",
            first + 1,
            py[lo..(first + 4).min(py.len())].join("\n"),
            rs[lo..(first + 4).min(rs.len())].join("\n"),
        );
    }
}
