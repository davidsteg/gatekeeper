//! Process execution (port of `execute.py`'s `run`; REQUIREMENTS.md §8).
//! Serves both the `docker` and the `local` executor.
//!
//! No shell interpreter, hard timeouts, bounded output. The execution
//! itself is the smallest part -- the effort goes into behaving honestly on
//! timeout.

use std::collections::HashMap;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

use super::{elapsed_ms, ExecResult, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::errors::{DenialReason, Denied};
use crate::privdrop::{EXIT_NOT_EXECUTABLE, EXIT_NOT_FOUND, MARKER, UNPRIV_ENTRY};

/// Reads up to `limit` bytes and reports whether truncation occurred.
async fn read_capped<R: AsyncRead + Unpin>(stream: Option<&mut R>, limit: usize) -> (Vec<u8>, bool) {
    let Some(stream) = stream else {
        return (Vec::new(), false);
    };
    let mut out: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut chunk = vec![0u8; 8192];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if out.len() + n > limit {
            out.extend_from_slice(&chunk[..limit - out.len()]);
            truncated = true;
            // Continue reading and discarding so the process does not block
            // on a full pipe and run into the timeout.
            let mut sink = vec![0u8; 65536];
            while let Ok(n) = stream.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    (out, truncated)
}

/// Starts the child in its own session (`start_new_session=True`), so a
/// timeout can kill the whole tree -- `docker compose` starts
/// subprocesses, and a kill on the parent alone would leave them behind.
pub(crate) fn new_session(command: &mut Command) {
    // SAFETY: `setsid` is async-signal-safe and touches no memory.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Terminates the process and its children (`_terminate`): the session's
/// process group as a whole, falling back to the process alone.
pub(crate) fn kill_group(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    if let Some(pid) = child.id() {
        // SAFETY: plain syscalls on a pid this process spawned.
        unsafe {
            let pgid = libc::getpgid(pid as libc::pid_t);
            if pgid > 0 && libc::killpg(pgid, libc::SIGKILL) == 0 {
                return;
            }
        }
    }
    let _ = child.start_kill();
}

/// Python's `returncode`: the exit code, or minus the signal number.
pub(crate) fn returncode(status: ExitStatus) -> i64 {
    use std::os::unix::process::ExitStatusExt;
    match status.code() {
        Some(code) => code as i64,
        None => -(status.signal().unwrap_or(0) as i64),
    }
}

/// `asyncio.wait_for(..., timeout=seconds)`; a negative value acts as 0.
pub(crate) fn timeout_duration(seconds: i64) -> Duration {
    Duration::from_secs(seconds.max(0) as u64)
}

/// Capabilities this process would hand to anything it `execve`s
/// (`_ambient_capabilities`).
///
/// Non-zero only where gatekeeper was started unprivileged but kept
/// CAP_SETUID/CAP_SETGID across that drop. Read per call rather than
/// cached: it is one small procfs read against a process spawn.
pub fn ambient_capabilities() -> u64 {
    crate::runas::capability_sets()
        .and_then(|sets| sets.get("CapAmb").copied())
        .unwrap_or(0)
}

/// The argv handed to the kernel: `argv` itself, or -- when this process
/// holds ambient capabilities -- this binary's `__unpriv` entry in front of
/// it, which clears them before becoming `argv`.
pub fn spawn_argv(argv: &[String], ambient: u64) -> Result<Vec<String>, std::io::Error> {
    if ambient == 0 {
        return Ok(argv.to_vec());
    }
    let exe = crate::privdrop::self_exe()?;
    let mut spawn = vec![exe.to_string_lossy().into_owned(), UNPRIV_ENTRY.to_string()];
    spawn.extend(argv.iter().cloned());
    Ok(spawn)
}

/// Executes `argv` without a shell (`execute.run`).
///
/// On timeout the process tree is killed. The result is then `unknown`
/// instead of `failed`, unless the operation is idempotent: reporting a
/// timeout as failure provokes exactly the retry that creates a duplicate
/// on an already-completed write (FR-6.9).
///
/// `env` replaces the environment when given; `None` inherits it.
pub async fn run(
    argv: &[String],
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    cwd: Option<&str>,
    env: Option<&HashMap<String, String>>,
) -> Result<ExecResult, Denied> {
    run_with_ambient(argv, timeout_seconds, max_output_bytes, idempotent, cwd, env, ambient_capabilities()).await
}

/// [`run`] with the ambient capability mask given rather than read -- the
/// seam the tests use where Python monkeypatched `_ambient_capabilities`.
#[doc(hidden)]
pub async fn run_with_ambient(
    argv: &[String],
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    cwd: Option<&str>,
    env: Option<&HashMap<String, String>>,
    ambient: u64,
) -> Result<ExecResult, Denied> {
    let started = Instant::now();
    let name = argv.first().cloned().unwrap_or_default();
    let not_found = || Denied::new(DenialReason::ExecutorUnavailable, format!("Executable not found: {name}"));
    let no_permission =
        || Denied::new(DenialReason::ExecutorUnavailable, format!("No permission to execute {name}"));

    // A whitelisted binary has no use for gatekeeper's own capabilities and
    // must not inherit them; where there are none to inherit -- every
    // deployment but one -- this is exactly the plain spawn, with no extra
    // process in the way. See `privdrop`.
    let wrapped = ambient != 0;
    let spawn = spawn_argv(argv, ambient).map_err(|_| not_found())?;
    let Some((program, args)) = spawn.split_first() else {
        // PORT NOTE: Python raised an uncaught IndexError on an empty argv.
        return Err(not_found());
    };

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    if let Some(vars) = env {
        command.env_clear().envs(vars);
    }
    new_session(&mut command);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Err(match e.raw_os_error() {
                Some(libc::ENOENT) => not_found(),
                Some(libc::EACCES) | Some(libc::EPERM) => no_permission(),
                // PORT NOTE: Python let any other OSError (ENOEXEC, ...)
                // propagate uncaught; it becomes the denial the wrapped
                // path already uses for the same case.
                _ => Denied::new(
                    DenialReason::ExecutorUnavailable,
                    format!("Cannot run {name}: {}", crate::pyfmt::os_error(&e, "")),
                ),
            });
        }
    };

    let limit = max_output_bytes.max(0) as usize;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let gathered = tokio::time::timeout(timeout_duration(timeout_seconds), async {
        tokio::join!(read_capped(stdout.as_mut(), limit), read_capped(stderr.as_mut(), limit))
    })
    .await;

    let ((stdout_bytes, out_truncated), (stderr_bytes, err_truncated)) = match gathered {
        Ok(result) => result,
        Err(_) => {
            kill_group(&mut child);
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            let message = if idempotent {
                format!("Timeout of {timeout_seconds}s exceeded, process killed.")
            } else {
                format!(
                    "Timeout of {timeout_seconds}s exceeded, process killed. \
                     The outcome is UNKNOWN: the operation may have completed. \
                     Do not retry without checking the state first."
                )
            };
            let outcome = if idempotent { OUTCOME_FAILED } else { OUTCOME_UNKNOWN };
            return Ok(ExecResult::new(outcome, None, "", message, false, elapsed_ms(started)));
        }
    };

    let code = child.wait().await.ok().map(returncode);
    let stderr_text = String::from_utf8_lossy(&stderr_bytes).into_owned();

    // The wrapper never got as far as the binary. Raise what an unwrapped
    // spawn would have raised for the same cause, so whether a deployment
    // inherits ambient capabilities stays invisible to every caller.
    if wrapped && matches!(code, Some(c) if c == EXIT_NOT_FOUND as i64 || c == EXIT_NOT_EXECUTABLE as i64) {
        if let Some(rest) = stderr_text.strip_prefix(MARKER) {
            let detail = rest.trim();
            if detail == "not found" {
                return Err(not_found());
            }
            if detail == "no permission" {
                return Err(no_permission());
            }
            return Err(Denied::new(DenialReason::ExecutorUnavailable, format!("Cannot run {name}: {detail}")));
        }
    }

    let outcome = if code == Some(0) { OUTCOME_OK } else { OUTCOME_FAILED };
    Ok(ExecResult::new(
        outcome,
        code,
        String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr_text,
        out_truncated || err_truncated,
        elapsed_ms(started),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    async fn run_simple(items: &[&str], timeout: i64, max: i64, idempotent: bool) -> Result<ExecResult, Denied> {
        run(&argv(items), timeout, max, idempotent, None, None).await
    }

    #[tokio::test]
    async fn output_and_exit_code() {
        let r = run_simple(&["/bin/sh", "-c", "echo out; echo err >&2; exit 3"], 30, 65536, true).await.unwrap();
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.exit_code, Some(3));
        assert_eq!(r.stdout, "out\n");
        assert_eq!(r.stderr, "err\n");
        assert!(!r.truncated);
        let r = run_simple(&["/bin/echo", "hello"], 30, 65536, true).await.unwrap();
        assert_eq!(r.outcome, OUTCOME_OK);
        assert_eq!(r.exit_code, Some(0));
    }

    #[tokio::test]
    async fn output_is_capped() {
        let r = run_simple(&["/bin/sh", "-c", "head -c 100000 /dev/zero | tr '\\0' x"], 20, 1024, true)
            .await
            .unwrap();
        assert!(r.truncated);
        assert_eq!(r.stdout.len(), 1024);
        assert_eq!(r.outcome, OUTCOME_OK, "draining keeps the writer from blocking");
    }

    #[tokio::test]
    async fn timeout_on_idempotent_tool_is_a_failure() {
        let r = run_simple(&["/bin/sleep", "30"], 1, 1024, true).await.unwrap();
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.exit_code, None);
        assert_eq!(r.stderr, "Timeout of 1s exceeded, process killed.");
        assert!(r.duration_ms < 10_000);
    }

    #[tokio::test]
    async fn timeout_on_non_idempotent_tool_is_unknown() {
        let r = run_simple(&["/bin/sleep", "30"], 1, 1024, false).await.unwrap();
        assert_eq!(r.outcome, OUTCOME_UNKNOWN);
        assert!(r.stderr.contains("UNKNOWN"));
        assert!(r.stderr.contains("Do not retry"));
    }

    #[tokio::test]
    async fn timeout_kills_the_whole_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("pid");
        let script = format!("/bin/sleep 30 & echo $! > {}; wait", marker.display());
        let r = run_simple(&["/bin/sh", "-c", &script], 1, 1024, true).await.unwrap();
        assert_eq!(r.outcome, OUTCOME_FAILED);
        let pid: i32 = std::fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
        // The grandchild is gone (or a zombie awaiting its reaper).
        std::thread::sleep(Duration::from_millis(200));
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        assert!(status.is_empty() || status.contains("State:\tZ"), "{status}");
    }

    #[tokio::test]
    async fn no_shell_interpretation() {
        let r = run_simple(&["/bin/echo", "$(id); `whoami`"], 10, 4096, true).await.unwrap();
        assert_eq!(r.stdout.trim(), "$(id); `whoami`");
    }

    #[tokio::test]
    async fn utf8_is_decoded_with_replacement() {
        let r = run_simple(&["/bin/sh", "-c", "printf 'a\\377b'"], 10, 4096, true).await.unwrap();
        assert_eq!(r.stdout, "a\u{fffd}b");
    }

    #[tokio::test]
    async fn missing_binary_is_reported() {
        let err = run_simple(&["/nonexistent/binary", "arg"], 5, 1024, true).await.unwrap_err();
        assert_eq!(err.reason, DenialReason::ExecutorUnavailable);
        assert_eq!(err.detail, "Executable not found: /nonexistent/binary");
    }

    #[tokio::test]
    async fn non_executable_file_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("not-executable");
        std::fs::write(&target, "#!/bin/sh\necho nope\n").unwrap();
        let target = target.to_string_lossy().into_owned();
        let err = run_simple(&[&target], 5, 1024, true).await.unwrap_err();
        // As root, EACCES still applies: no execute bit is set at all.
        assert_eq!(err.detail, format!("No permission to execute {target}"));
    }

    #[tokio::test]
    async fn cwd_and_env_are_applied() {
        let env: HashMap<String, String> = [("GK_X".to_string(), "42".to_string())].into();
        let r = run(&argv(&["/bin/sh", "-c", "pwd; echo $GK_X; echo ${HOME:-unset}"]), 10, 4096, true, Some("/"), Some(&env))
            .await
            .unwrap();
        assert_eq!(r.stdout, "/\n42\nunset\n");
    }

    #[test]
    fn no_ambient_capabilities_means_no_wrapper() {
        let a = argv(&["/bin/echo", "hello"]);
        assert_eq!(spawn_argv(&a, 0).unwrap(), a);
    }

    #[test]
    fn ambient_capabilities_put_the_wrapper_in_front() {
        let a = argv(&["/bin/echo", "hello"]);
        let setid = (1u64 << crate::runas::CAP_SETUID) | (1u64 << crate::runas::CAP_SETGID);
        let spawned = spawn_argv(&a, setid).unwrap();
        let exe = crate::privdrop::self_exe().unwrap().to_string_lossy().into_owned();
        assert_eq!(spawned, vec![exe, UNPRIV_ENTRY.to_string(), "/bin/echo".into(), "hello".into()]);
    }

    #[test]
    fn a_plain_process_reports_no_ambient_capabilities() {
        assert_eq!(ambient_capabilities(), 0);
    }
}
