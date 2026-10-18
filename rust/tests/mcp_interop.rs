//! Interop: `gatekeeper::mcp` against the real Python MCP SDK.
//!
//! * `the_python_sdk_client_works_against_the_rust_server`: the SDK's
//!   `Client` lists tools, calls tools and receives `tools/list_changed`,
//!   once as a handshake-era session (standalone GET stream) and once at
//!   2026-07-28 (`subscriptions/listen`), plus both modes on the stateless
//!   mount (`tests/interop/client_test.py`).
//! * `the_wire_matches_the_python_sdk`: one raw-HTTP probe
//!   (`tests/interop/probe.py`, every error path of both eras and both
//!   mounts) against the Rust echo server; the transcript must be
//!   identical to the one the same probe recorded against the Python SDK
//!   server configured like gatekeeper was
//!   (`tests/fixtures/mcp_wire_python_transcript.txt`, frozen when the
//!   Python implementation was removed, 1.17.0).
//!
//! Both need an interpreter with the MCP SDK and skip (pass with a note)
//! without one -- see `common::mcp_python`. Set
//! `GATEKEEPER_INTEROP_DUMP=<dir>` to keep both transcripts
//! (`python.txt`, `rust.txt`) for diffing.

#[path = "../examples/mcp_echo.rs"]
mod echo;
mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::process::Command;

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
    let Some(python) = common::mcp_python() else { return };
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
    let Some(python) = common::mcp_python() else { return };

    // The reference: the probe against the Python SDK, wired the way the
    // Python gatekeeper wired it -- recorded once, frozen.
    let py_out = include_str!("fixtures/mcp_wire_python_transcript.txt");

    let base = serve_rust().await;
    let (rs_ok, rs_out, rs_err) = run_script(&python, "probe.py", &base).await;
    assert!(rs_ok, "probe.py failed against the Rust server\n{rs_err}\n{rs_out}");

    // `GATEKEEPER_INTEROP_DUMP=<dir>` keeps both transcripts for diffing.
    if let Some(dir) = std::env::var_os("GATEKEEPER_INTEROP_DUMP") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).expect("dump dir");
        std::fs::write(dir.join("python.txt"), py_out).expect("write python.txt");
        std::fs::write(dir.join("rust.txt"), &rs_out).expect("write rust.txt");
    }

    assert!(py_out.lines().count() > 600, "suspiciously short transcript:\n{py_out}");
    if py_out != rs_out.as_str() {
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
