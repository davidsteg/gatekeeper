//! Built-in file executor (port of `execute_file.py`; REQUIREMENTS.md §8,
//! FR-4).
//!
//! Unlike the `local` executor (which runs external binaries via argv), the
//! `file` executor performs read/write/patch/list operations directly in
//! this process -- no shell, no process spawn, no argv chaining. Every
//! operation is constrained by `path_roots` and `protected_resources` in
//! Tier 1, and the operation type is fixed per tool.
//!
//! One exception to "no process spawn": a toolkit that sets `run_as` runs
//! its operations as a different OS user, which an in-process executor
//! structurally cannot do -- see [`crate::runas`] for why that means a
//! child process and what it guarantees. A toolkit *without* `run_as` takes
//! the in-process path.

use std::io::ErrorKind;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::local::{kill_group, returncode, timeout_duration};
use super::{elapsed_ms, ExecResult, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::pathutil;
use crate::pyfmt::{os_error, repr_list, repr_str, str_value};
use crate::tier1::Toolkit;

/// What every operation returns (Python's 5-tuple
/// `(outcome, exit_code, stdout, stderr, truncated)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    pub outcome: &'static str,
    pub exit_code: Option<i64>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

fn ok(stdout: String, truncated: bool) -> Op {
    Op { outcome: OUTCOME_OK, exit_code: Some(0), stdout, stderr: String::new(), truncated }
}

fn failed(stderr: String) -> Op {
    Op { outcome: OUTCOME_FAILED, exit_code: Some(1), stdout: String::new(), stderr, truncated: false }
}

/// One file executor call -- the keyword arguments of Python's
/// `execute_file.run`.
#[derive(Debug, Clone, Default)]
pub struct FileCall {
    pub operation: String,
    pub path: String,
    pub content: Option<String>,
    pub old_string: Option<String>,
    pub new_string: Option<String>,
    pub path_roots: Vec<String>,
    pub protected: Vec<String>,
    pub timeout_seconds: i64,
    pub max_output_bytes: i64,
    /// Python default: `False`.
    pub idempotent: bool,
    /// Tier 1 (toolkit, or a narrowing per-tool override), never a
    /// parameter.
    pub run_as: Option<String>,
}

/// Python's `ValueError("lstat: embedded null character in path")`, which
/// `os.path.realpath` raises for a path with a NUL in it.
const EMBEDDED_NUL: &str = "lstat: embedded null character in path";

fn realpath_checked(path: &str) -> Result<String, String> {
    if path.contains('\0') {
        return Err(EMBEDDED_NUL.to_string());
    }
    Ok(pathutil::realpath(path))
}

/// `Path(p).parts` for an absolute, normalized path: the root, then each
/// component.
fn path_parts(path: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    if path.starts_with("//") && !path.starts_with("///") {
        parts.push("//");
    } else if path.starts_with('/') {
        parts.push("/");
    }
    parts.extend(path.split('/').filter(|c| !c.is_empty() && *c != "."));
    parts
}

/// Resolves `path` and checks it against `path_roots`.
///
/// Rejects `..` traversal, symlinks that escape the root, and any path that
/// touches a protected resource directory. Returns the resolved path; the
/// error is the message Python's `ValueError` carried.
///
/// Public because the `run_as` child re-runs it after its drop: the
/// parent's check is the real gate, the child's is there so the half that
/// may hold elevated rights never trusts a path it did not itself check.
pub fn validate_path(path: &str, path_roots: &[String], protected: &[String]) -> Result<String, String> {
    if !path.starts_with('/') {
        return Err(format!("Path must be absolute: {}", repr_str(path)));
    }

    // realpath resolves symlinks (FR-4.3).
    let resolved = realpath_checked(path)?;

    if path_roots.is_empty() {
        return Err("No path_roots configured for this toolkit".to_string());
    }

    let mut allowed = false;
    for root in path_roots {
        let root_resolved = realpath_checked(root)?;
        if pathutil::is_under(&resolved, &root_resolved) {
            allowed = true;
            break;
        }
    }
    if !allowed {
        return Err(format!(
            "Path {} (resolved to {resolved}) is outside allowed roots: {}",
            repr_str(path),
            repr_list(path_roots)
        ));
    }

    // protected_resources -- reject if any segment matches.
    let parts = path_parts(&resolved);
    for prot in protected {
        if parts.iter().any(|p| p == prot) {
            return Err(format!(
                "Path {} touches protected resource {}",
                repr_str(path),
                repr_str(prot)
            ));
        }
    }

    Ok(resolved)
}

/// Dispatches to the one operation, on an already-validated path.
///
/// Shared by the in-process path and the `run_as` child, so there is one
/// implementation of read, write, patch and list, not a privileged copy
/// that could drift from the unprivileged one. `Err` is the text of an
/// exception Python's caller turned into a failed result.
pub fn perform(
    operation: &str,
    path: &str,
    content: Option<&str>,
    old_string: Option<&str>,
    new_string: Option<&str>,
    max_output_bytes: i64,
) -> Result<Op, String> {
    match operation {
        "read" => read(path, max_output_bytes),
        "write" => {
            let content = content.ok_or("'content' parameter is required for write")?;
            Ok(write(path, content))
        }
        "patch" => match (old_string, new_string) {
            (Some(old), Some(new)) => patch(path, old, new),
            _ => Err("'old_string' and 'new_string' are required for patch".to_string()),
        },
        "list" => list(path, max_output_bytes),
        other => Err(format!("Unknown file operation: {}", repr_str(other))),
    }
}

/// Executes a file operation (`execute_file.run`).
pub async fn run(call: &FileCall) -> ExecResult {
    let started = Instant::now();

    let validated = match validate_path(&call.path, &call.path_roots, &call.protected) {
        Ok(p) => p,
        Err(exc) => {
            return ExecResult::new(OUTCOME_FAILED, Some(1), "", exc, false, elapsed_ms(started));
        }
    };

    if let Some(run_as) = &call.run_as {
        // Path already checked above against this toolkit's Tier 1 roots --
        // the child re-checks it anyway (see `validate_path`).
        return run_as_user(run_as, call, &validated, started).await;
    }

    match perform(
        &call.operation,
        &validated,
        call.content.as_deref(),
        call.old_string.as_deref(),
        call.new_string.as_deref(),
        call.max_output_bytes,
    ) {
        Ok(op) => ExecResult::new(op.outcome, op.exit_code, op.stdout, op.stderr, op.truncated, elapsed_ms(started)),
        Err(exc) => ExecResult::new(OUTCOME_FAILED, Some(1), "", exc, false, elapsed_ms(started)),
    }
}

/// Readiness (`service._probe_one` for `file`): in-process, so nothing can
/// fail to connect. The one configuration that cannot work is a toolkit
/// with no roots, which `validate_path` denies every call for.
/// Deliberately not an `isdir` check on the roots -- a `run_as` toolkit's
/// roots may be unstattable for the server and usable for its user.
pub async fn probe(toolkit: &Toolkit) -> bool {
    !toolkit.path_roots.is_empty()
}

/// Runs one operation in a child process that first becomes `run_as`.
///
/// argv is fixed -- this binary and the hidden `__runas` argument, nothing
/// else. The request goes over stdin.
async fn run_as_user(run_as: &str, call: &FileCall, path: &str, started: Instant) -> ExecResult {
    let request = crate::pyjson::dumps(&json!({
        "run_as": run_as,
        "operation": call.operation,
        "path": path,
        "content": call.content,
        "old_string": call.old_string,
        "new_string": call.new_string,
        "path_roots": call.path_roots,
        "protected": call.protected,
        "max_output_bytes": call.max_output_bytes,
    }));

    let done = |outcome: &str, exit_code: Option<i64>, out: String, err: String, trunc: bool| {
        ExecResult::new(outcome, exit_code, out, err, trunc, elapsed_ms(started))
    };

    let exe = match crate::privdrop::self_exe() {
        Ok(exe) => exe,
        Err(exc) => {
            return done(OUTCOME_FAILED, Some(1), String::new(), format!("Cannot start the run_as helper: {exc}"), false);
        }
    };
    let mut command = tokio::process::Command::new(&exe);
    command
        .arg(crate::privdrop::RUNAS_ENTRY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    super::local::new_session(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(exc) => {
            return done(
                OUTCOME_FAILED,
                Some(1),
                String::new(),
                format!("Cannot start the run_as helper: {}", os_error(&exc, &exe.to_string_lossy())),
                false,
            );
        }
    };

    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let communicated = {
        let communicate = async {
            let write = async {
                if let Some(mut pipe) = stdin.take() {
                    // A helper that died early closes its end; Python's
                    // `communicate` ignores the broken pipe too.
                    let _ = pipe.write_all(request.as_bytes()).await;
                    let _ = pipe.shutdown().await;
                }
            };
            let read_out = async {
                let mut buf = Vec::new();
                if let Some(pipe) = stdout.as_mut() {
                    let _ = pipe.read_to_end(&mut buf).await;
                }
                buf
            };
            let read_err = async {
                let mut buf = Vec::new();
                if let Some(pipe) = stderr.as_mut() {
                    let _ = pipe.read_to_end(&mut buf).await;
                }
                buf
            };
            let ((), out, err) = tokio::join!(write, read_out, read_err);
            let status = child.wait().await;
            (out, err, status)
        };
        tokio::time::timeout(timeout_duration(call.timeout_seconds), communicate).await
    };

    let (stdout_bytes, stderr_bytes, status) = match communicated {
        Ok(result) => result,
        Err(_) => {
            kill_group(&mut child);
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            // Same honesty rule as `execute.run` (FR-6.9): a killed `write`
            // may or may not have hit the disk.
            let t = call.timeout_seconds;
            let message = if call.idempotent {
                format!("Timeout of {t}s exceeded, run_as helper killed.")
            } else {
                format!(
                    "Timeout of {t}s exceeded, run_as helper killed. \
                     The outcome is UNKNOWN: the operation may have completed. \
                     Do not retry without checking the state first."
                )
            };
            let outcome = if call.idempotent { OUTCOME_FAILED } else { OUTCOME_UNKNOWN };
            return done(outcome, None, String::new(), message, false);
        }
    };
    let code = status.ok().map(returncode);

    let parsed = std::str::from_utf8(&stdout_bytes)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        // PORT NOTE: Python raised an uncaught TypeError for a JSON value
        // that is not an object; it is treated as a helper failure here.
        .and_then(|value| match value {
            Value::Object(map) if map.contains_key("outcome") => Some(map),
            _ => None,
        });
    let Some(payload) = parsed else {
        // The helper writes a JSON result even when the operation fails,
        // so getting here means it died before it could. Its stderr is the
        // only useful thing left; capped.
        let text = String::from_utf8_lossy(&stderr_bytes);
        let detail: String = text.chars().take(2000).collect::<String>().trim().to_string();
        let shown = code.map_or("None".to_string(), |c| c.to_string());
        return done(
            OUTCOME_FAILED,
            code,
            String::new(),
            format!(
                "run_as helper failed (exit {shown}): {}",
                if detail.is_empty() { "no output" } else { &detail }
            ),
            false,
        );
    };

    let outcome = str_value(&payload["outcome"]);
    let mut out = payload.get("stdout").map_or(String::new(), str_value);
    let err = payload.get("stderr").map_or(String::new(), str_value);
    let mut truncated = payload.get("truncated").is_some_and(crate::tier1::py_truthy);
    let exit_code = match payload.get("exit_code") {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::Bool(b)) => Some(*b as i64),
        _ => None,
    };

    // The child caps its own output; re-capping here means a helper that
    // ever stopped doing so cannot widen this toolkit's `max_output_bytes`.
    let limit = call.max_output_bytes.max(0) as usize;
    if out.len() > limit {
        out = truncate_utf8(&out, limit);
        truncated = true;
    }
    done(&outcome, exit_code, out, err, truncated)
}

/// `s.encode()[:limit].decode(errors="ignore")` for a valid UTF-8 string.
fn truncate_utf8(s: &str, limit: usize) -> String {
    let mut end = limit.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn is_permission(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM))
}

fn errno(err: &std::io::Error) -> Option<i32> {
    err.raw_os_error()
}

/// Reads a file, capped at `max_output_bytes`.
fn read(path: &str, max_output_bytes: i64) -> Result<Op, String> {
    let mut data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) if errno(&e) == Some(libc::ENOENT) => return Ok(failed(format!("File not found: {path}"))),
        Err(e) if errno(&e) == Some(libc::EISDIR) => return Ok(failed(format!("Is a directory: {path}"))),
        Err(e) if is_permission(&e) => return Ok(failed(format!("Permission denied: {path}"))),
        Err(e) => return Err(os_error(&e, path)),
    };

    let limit = max_output_bytes.max(0) as usize;
    let mut truncated = false;
    if data.len() > limit {
        data.truncate(limit);
        truncated = true;
    }

    let text = String::from_utf8_lossy(&data).into_owned();
    let suffix = if truncated { "\n... [truncated]" } else { "" };
    Ok(ok(text + suffix, truncated))
}

/// `Path.mkdir(parents=True, exist_ok=True)`, with Python's error paths:
/// the error names the directory whose own `mkdir` failed.
fn mkdir_parents(path: &Path) -> Result<(), (std::io::Error, String)> {
    let name = || path.to_string_lossy().into_owned();
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let parent = match path.parent() {
                Some(parent) if parent != path => parent,
                _ => return Err((e, name())),
            };
            mkdir_parents(parent)?;
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() != ErrorKind::NotFound && path.is_dir() => Ok(()),
                Err(e) => Err((e, name())),
            }
        }
        Err(_) if path.is_dir() => Ok(()),
        Err(e) => Err((e, name())),
    }
}

/// Writes content to a file, creating parent directories.
fn write(path: &str, content: &str) -> Op {
    let parent = Path::new(path).parent().unwrap_or(Path::new("/"));
    if let Err((err, dir)) = mkdir_parents(parent) {
        if is_permission(&err) {
            return failed(format!("Permission denied: {path}"));
        }
        return failed(format!("Write error: {}", os_error(&err, &dir)));
    }
    if let Err(err) = std::fs::write(path, content.as_bytes()) {
        if is_permission(&err) {
            return failed(format!("Permission denied: {path}"));
        }
        return failed(format!("Write error: {}", os_error(&err, path)));
    }
    // `len(content)` -- characters, not bytes.
    ok(format!("Written {} bytes to {path}", content.chars().count()), false)
}

/// Python's `UnicodeDecodeError` text for strict UTF-8 decoding.
fn utf8_error_text(data: &[u8], err: &std::str::Utf8Error) -> String {
    let pos = err.valid_up_to();
    match err.error_len() {
        Some(_) => {
            let byte = data[pos];
            let reason = if (0x80..=0xC1).contains(&byte) || byte >= 0xF5 {
                "invalid start byte"
            } else {
                "invalid continuation byte"
            };
            format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {pos}: {reason}")
        }
        None => {
            let end = data.len() - 1;
            if end > pos {
                format!("'utf-8' codec can't decode bytes in position {pos}-{end}: unexpected end of data")
            } else {
                format!(
                    "'utf-8' codec can't decode byte 0x{:02x} in position {pos}: unexpected end of data",
                    data[pos]
                )
            }
        }
    }
}

/// Replaces `old_string` with `new_string` in a file.
fn patch(path: &str, old_string: &str, new_string: &str) -> Result<Op, String> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if errno(&e) == Some(libc::ENOENT) => return Ok(failed(format!("File not found: {path}"))),
        Err(e) if is_permission(&e) => return Ok(failed(format!("Permission denied: {path}"))),
        Err(e) => return Err(os_error(&e, path)),
    };
    let content = match std::str::from_utf8(&raw) {
        Ok(text) => text,
        Err(e) => return Err(utf8_error_text(&raw, &e)),
    };

    // `str.count`, which counts "" as len+1 like `matches("")` does.
    let count = content.matches(old_string).count();
    if count == 0 {
        return Ok(failed(format!("old_string not found in {path}")));
    }
    if count > 1 {
        return Ok(failed(format!("old_string found {count} times in {path} \u{2014} must be unique")));
    }

    let new_content = content.replacen(old_string, new_string, 1);
    if let Err(e) = std::fs::write(path, new_content.as_bytes()) {
        if is_permission(&e) {
            return Ok(failed(format!("Permission denied: {path}")));
        }
        return Err(os_error(&e, path));
    }

    Ok(ok(format!("Patched 1 occurrence in {path}"), false))
}

/// Lists directory entries (one per line), `d ` or `f ` prefixed.
fn list(path: &str, max_output_bytes: i64) -> Result<Op, String> {
    let reader = match std::fs::read_dir(path) {
        Ok(reader) => reader,
        Err(e) if errno(&e) == Some(libc::ENOENT) => return Ok(failed(format!("Directory not found: {path}"))),
        Err(e) if errno(&e) == Some(libc::ENOTDIR) => return Ok(failed(format!("Not a directory: {path}"))),
        Err(e) if is_permission(&e) => return Ok(failed(format!("Permission denied: {path}"))),
        Err(e) => return Err(os_error(&e, path)),
    };
    let mut entries: Vec<(String, std::path::PathBuf)> = Vec::new();
    for entry in reader {
        let entry = entry.map_err(|e| os_error(&e, path))?;
        entries.push((entry.file_name().to_string_lossy().into_owned(), entry.path()));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut lines: Vec<String> = Vec::new();
    let mut total: i64 = 0;
    let mut truncated = false;
    for (name, full) in &entries {
        let prefix = if full.is_dir() { "d " } else { "f " };
        let line = format!("{prefix}{name}");
        total += line.chars().count() as i64 + 1;
        if total > max_output_bytes {
            truncated = true;
            break;
        }
        lines.push(line);
    }

    let mut text = lines.join("\n");
    if truncated {
        text.push_str("\n... [truncated]");
    }
    Ok(ok(text, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(op: &str, path: &str, root: &str) -> FileCall {
        FileCall {
            operation: op.into(),
            path: path.into(),
            path_roots: vec![root.into()],
            protected: ["gatekeeper", "dockhand", "ix-dockhand", "traefik"].iter().map(|s| s.to_string()).collect(),
            timeout_seconds: 5,
            max_output_bytes: 65536,
            ..Default::default()
        }
    }

    fn tmp() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap().to_string_lossy().into_owned();
        (dir, root)
    }

    #[tokio::test]
    async fn read_file() {
        let (_d, root) = tmp();
        let f = format!("{root}/test.txt");
        std::fs::write(&f, "hello world").unwrap();
        let r = run(&call("read", &f, &root)).await;
        assert_eq!(r.outcome, "ok");
        assert!(r.stdout.contains("hello world"));
    }

    #[tokio::test]
    async fn read_nonexistent() {
        let (_d, root) = tmp();
        let r = run(&call("read", &format!("{root}/missing.txt"), &root)).await;
        assert_eq!(r.outcome, "failed");
        assert!(r.stderr.to_lowercase().contains("not found"));
        assert_eq!(r.stderr, format!("File not found: {root}/missing.txt"));
    }

    #[tokio::test]
    async fn read_directory_and_errors() {
        let (_d, root) = tmp();
        let r = run(&call("read", &root, &root)).await;
        assert_eq!(r.stderr, format!("Is a directory: {root}"));
        std::fs::write(format!("{root}/f"), "x").unwrap();
        let r = run(&call("read", &format!("{root}/f/x"), &root)).await;
        assert_eq!(r.stderr, format!("[Errno 20] Not a directory: '{root}/f/x'"));
        let r = run(&call("frobnicate", &format!("{root}/f"), &root)).await;
        assert_eq!(r.stderr, "Unknown file operation: 'frobnicate'");
        assert_eq!(r.exit_code, Some(1));
    }

    #[tokio::test]
    async fn write_file_and_parents() {
        let (_d, root) = tmp();
        let path = format!("{root}/subdir/output.txt");
        let mut c = call("write", &path, &root);
        c.content = Some("new content".into());
        let r = run(&c).await;
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.stdout, format!("Written 11 bytes to {path}"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new content");

        let deep = format!("{root}/deep/nested/dir/file.yaml");
        let mut c = call("write", &deep, &root);
        c.content = Some("key: välue".into());
        let r = run(&c).await;
        assert_eq!(r.outcome, "ok");
        // `len(content)` counts characters.
        assert_eq!(r.stdout, format!("Written 10 bytes to {deep}"));
        assert!(Path::new(&deep).exists());

        let mut c = call("write", &format!("{root}/x"), &root);
        c.content = None;
        let r = run(&c).await;
        assert_eq!(r.stderr, "'content' parameter is required for write");
    }

    #[tokio::test]
    async fn write_error_names_the_failing_directory() {
        let (_d, root) = tmp();
        std::fs::write(format!("{root}/f"), "x").unwrap();
        let mut c = call("write", &format!("{root}/f/y/z/out.txt"), &root);
        c.content = Some("x".into());
        let r = run(&c).await;
        assert_eq!(r.stderr, format!("Write error: [Errno 20] Not a directory: '{root}/f/y/z'"));
    }

    #[tokio::test]
    async fn patch_cases() {
        let (_d, root) = tmp();
        let path = format!("{root}/config.yaml");
        std::fs::write(&path, "version: 1\nname: test\n").unwrap();
        let mut c = call("patch", &path, &root);
        c.old_string = Some("version: 1".into());
        c.new_string = Some("version: 2".into());
        let r = run(&c).await;
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.stdout, format!("Patched 1 occurrence in {path}"));
        assert!(std::fs::read_to_string(&path).unwrap().contains("version: 2"));

        let other = format!("{root}/config.txt");
        std::fs::write(&other, "nothing relevant here").unwrap();
        let mut c = call("patch", &other, &root);
        c.old_string = Some("missing".into());
        c.new_string = Some("found".into());
        let r = run(&c).await;
        assert_eq!(r.outcome, "failed");
        assert!(r.stderr.to_lowercase().contains("not found"));

        let dupes = format!("{root}/dupes.txt");
        std::fs::write(&dupes, "x=1\nx=1\n").unwrap();
        let mut c = call("patch", &dupes, &root);
        c.old_string = Some("x=1".into());
        c.new_string = Some("x=2".into());
        let r = run(&c).await;
        assert_eq!(r.outcome, "failed");
        assert_eq!(r.stderr, format!("old_string found 2 times in {dupes} \u{2014} must be unique"));

        let mut c = call("patch", &dupes, &root);
        c.old_string = Some("x".into());
        let r = run(&c).await;
        assert_eq!(r.stderr, "'old_string' and 'new_string' are required for patch");

        let bad = format!("{root}/bad.bin");
        std::fs::write(&bad, b"ab\xff").unwrap();
        let mut c = call("patch", &bad, &root);
        c.old_string = Some("a".into());
        c.new_string = Some("b".into());
        let r = run(&c).await;
        assert_eq!(r.stderr, "'utf-8' codec can't decode byte 0xff in position 2: invalid start byte");
    }

    #[test]
    fn utf8_error_texts_match_python() {
        let cases: [(&[u8], &str); 4] = [
            (b"ab\xe2\x82", "'utf-8' codec can't decode bytes in position 2-3: unexpected end of data"),
            (b"ab\xe2\x28x", "'utf-8' codec can't decode byte 0xe2 in position 2: invalid continuation byte"),
            (b"\xf0\x90\x80", "'utf-8' codec can't decode bytes in position 0-2: unexpected end of data"),
            (b"\xed\xa0\x80", "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte"),
        ];
        for (data, want) in cases {
            let err = std::str::from_utf8(data).unwrap_err();
            assert_eq!(utf8_error_text(data, &err), want);
        }
    }

    #[tokio::test]
    async fn list_dir() {
        let (_d, root) = tmp();
        std::fs::create_dir(format!("{root}/mydir")).unwrap();
        std::fs::write(format!("{root}/file1.txt"), "a").unwrap();
        std::fs::write(format!("{root}/file2.yaml"), "b").unwrap();
        let r = run(&call("list", &root, &root)).await;
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.stdout, "f file1.txt\nf file2.yaml\nd mydir");

        let mut c = call("list", &root, &root);
        c.max_output_bytes = 15;
        let r = run(&c).await;
        assert!(r.truncated);
        assert_eq!(r.stdout, "f file1.txt\n... [truncated]");

        let r = run(&call("list", &format!("{root}/nope"), &root)).await;
        assert_eq!(r.stderr, format!("Directory not found: {root}/nope"));
        let r = run(&call("list", &format!("{root}/file1.txt"), &root)).await;
        assert_eq!(r.stderr, format!("Not a directory: {root}/file1.txt"));
    }

    #[tokio::test]
    async fn path_traversal_rejected() {
        let (_d, root) = tmp();
        let evil = format!("{root}/../../etc/passwd");
        let r = run(&call("read", &evil, &root)).await;
        assert_eq!(r.outcome, "failed");
        assert!(r.stderr.to_lowercase().contains("outside allowed roots"));
        assert_eq!(
            r.stderr,
            format!("Path '{evil}' (resolved to {}) is outside allowed roots: ['{root}']", pathutil::realpath(&evil))
        );
    }

    #[tokio::test]
    async fn protected_and_shape_rejections() {
        let (_d, root) = tmp();
        let evil = format!("{root}/gatekeeper/config.yaml");
        std::fs::create_dir_all(format!("{root}/gatekeeper")).unwrap();
        std::fs::write(&evil, "secret").unwrap();
        let mut c = call("read", &evil, &root);
        c.protected = vec!["gatekeeper".into()];
        let r = run(&c).await;
        assert_eq!(r.outcome, "failed");
        assert_eq!(r.stderr, format!("Path '{evil}' touches protected resource 'gatekeeper'"));

        let target = format!("{root}/dockhand/compose.yaml");
        let mut c = call("write", &target, &root);
        c.content = Some("malicious".into());
        c.protected = vec!["dockhand".into()];
        let r = run(&c).await;
        assert!(r.stderr.to_lowercase().contains("protected resource"));
        assert!(!Path::new(&target).exists());

        let r = run(&call("read", "relative/x", &root)).await;
        assert_eq!(r.stderr, "Path must be absolute: 'relative/x'");
        let mut c = call("read", &format!("{root}/x"), &root);
        c.path_roots.clear();
        assert_eq!(run(&c).await.stderr, "No path_roots configured for this toolkit");
        let r = run(&call("read", &format!("{root}/a\0b"), &root)).await;
        assert_eq!(r.stderr, EMBEDDED_NUL);
    }

    #[tokio::test]
    async fn symlink_escape_rejected() {
        let (_d, root) = tmp();
        let (_o, outside) = tmp();
        std::fs::write(format!("{outside}/secret"), "s").unwrap();
        std::os::unix::fs::symlink(&outside, format!("{root}/link")).unwrap();
        let r = run(&call("read", &format!("{root}/link/secret"), &root)).await;
        assert!(r.stderr.contains("is outside allowed roots"), "{}", r.stderr);
    }

    #[tokio::test]
    async fn read_truncation() {
        let (_d, root) = tmp();
        let path = format!("{root}/big.txt");
        std::fs::write(&path, "A".repeat(200)).unwrap();
        let mut c = call("read", &path, &root);
        c.max_output_bytes = 100;
        let r = run(&c).await;
        assert_eq!(r.outcome, "ok");
        assert!(r.truncated);
        assert!(r.stdout.contains("truncated"));
        assert_eq!(r.stdout, format!("{}\n... [truncated]", "A".repeat(100)));
    }

    #[test]
    fn truncate_utf8_drops_partial_characters() {
        assert_eq!(truncate_utf8("aé", 2), "a");
        assert_eq!(truncate_utf8("aé", 3), "aé");
    }
}
