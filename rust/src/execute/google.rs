//! The `google` executor (port of `execute_google.py`; REQUIREMENTS.md
//! §8, FR-8.3a-f counterpart).
//!
//! The vendored `google_api.py` CLI is a thin wrapper around the Google
//! REST APIs (gmail, calendar, drive) that authenticates via an OAuth2
//! token file and emits JSON on stdout. It stays Python: this executor
//! runs it as a local subprocess -- the same argv model as `local`/`docker`
//! (FR-5.3/5.4/6.1, no shell) -- and parses the JSON output, capping list
//! length the way the `http` executor does for REST responses (FR-8.12).
//!
//! Why a separate executor rather than a `local` toolkit: Google responses
//! are external, potentially prompt-injection-bearing data
//! (`external_untrusted`), `gmail search` can return thousands of messages
//! ([`cap_json`]), and `allowed_google_actions` is a per-toolkit whitelist
//! of action strings (FR-8.3c's counterpart).
//!
//! The OAuth credential is *not* passed through argv (FR-10.2). The caller
//! (`service`) materializes the `oauth2` bundle to
//! `<tmp HOME>/.hermes/google_token.json` (0600) and hands that `HOME` in
//! `env`; the script reads `~/.hermes/google_token.json` from there.
//!
//! **Where the script and interpreter come from.** Python ran the script
//! with `sys.executable`. The Rust binary has no interpreter of its own, so
//! [`python_interpreter`] takes `GATEKEEPER_PYTHON`, else `python3` found on
//! `PATH` (resolved to an absolute path here, because the child's env is
//! only what `env` carries -- typically just `HOME`). The script is the
//! toolkit's `google_script`; when that path does not exist, the image's
//! own copy stands in ([`google_fallback_script`]).
//!
//! This module also holds what the `microsoft` executor shares with it:
//! the subprocess runner ([`run_subprocess`]) and the vendored-script
//! location rules.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::errors::{DenialReason, Denied};
use crate::execute::{elapsed_ms, ExecResult, Redact, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::pyfmt::{repr_str, str_value};
use crate::pyjson;
use crate::tier1::Toolkit;

// -- Shared with `microsoft`: interpreter, script location, JSON cap -------

/// Where the Docker image installs the vendored CLI scripts.
pub const VENDOR_DIR: &str = "/usr/share/gatekeeper/vendor";

pub use super::http::{cap_json, MAX_JSON_ITEMS};

/// `_cap_json(value, limit=n, budget=[n])`.
pub fn cap_json_items(value: &Value, limit: i64) -> Value {
    let mut budget = limit;
    cap_json(value, &mut budget)
}

/// The interpreter the vendored scripts run under: `GATEKEEPER_PYTHON`
/// when set, else `python3` from `PATH` (as an absolute path, since the
/// child's own env usually has no `PATH`), else the bare name.
pub fn python_interpreter() -> String {
    if let Ok(value) = std::env::var("GATEKEEPER_PYTHON") {
        if !value.is_empty() {
            return value;
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("python3");
            if candidate.is_file() && access(&candidate.to_string_lossy(), libc::X_OK) {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    "python3".into()
}

/// Where a vendored script stands in when a toolkit names a path this
/// filesystem lacks: `$<env_var>` when set, else the image's copy under
/// [`VENDOR_DIR`], else -- in a development checkout -- the copy in
/// `src/gatekeeper/<subdir>/`.
///
/// PORT NOTE: Python's fallback was the fixed `tier1.*_FALLBACK_SCRIPT`
/// (`/opt/gatekeeper/...`); the Rust image installs the scripts under
/// [`VENDOR_DIR`] instead. `tier1::missing_*_script` still names the old
/// constant -- the lead should point both at the same place.
pub fn vendored_script(env_var: &str, subdir: &str, name: &str) -> String {
    if let Ok(value) = std::env::var(env_var) {
        if !value.is_empty() {
            return value;
        }
    }
    // Where the image installs the vendored scripts -- the same paths
    // tier1's startup warning checks.
    let installed = match name {
        "google_api.py" => crate::tier1::GOOGLE_FALLBACK_SCRIPT.to_string(),
        "microsoft_api.py" => crate::tier1::MICROSOFT_FALLBACK_SCRIPT.to_string(),
        _ => format!("{VENDOR_DIR}/{name}"),
    };
    if Path::new(&installed).is_file() {
        return installed;
    }
    let dev = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("src")
        .join("gatekeeper")
        .join(subdir)
        .join(name);
    if dev.is_file() {
        if let Ok(abs) = dev.canonicalize() {
            return abs.to_string_lossy().into_owned();
        }
    }
    installed
}

/// The `google_api.py` the fallback substitutes (`GOOGLE_FALLBACK_SCRIPT`'s
/// role): `GATEKEEPER_GOOGLE_SCRIPT`, else the image / checkout copy.
pub fn google_fallback_script() -> String {
    vendored_script("GATEKEEPER_GOOGLE_SCRIPT", "_google_api", "google_api.py")
}

pub(crate) fn access(path: &str, mode: libc::c_int) -> bool {
    match std::ffi::CString::new(path) {
        // SAFETY: a valid NUL-terminated path; access(2) only reads it.
        Ok(c) => unsafe { libc::access(c.as_ptr(), mode) == 0 },
        Err(_) => false,
    }
}

/// `os.path.isfile(p) and os.access(p, os.R_OK)`.
pub(crate) fn readable_file(path: &str) -> bool {
    Path::new(path).is_file() && access(path, libc::R_OK)
}

/// Python truthiness of a JSON value.
pub(crate) fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `err.get(a) or err.get(b)` -- the first truthy value, else the last.
pub(crate) fn or_get(err: &Map<String, Value>, a: &str, b: &str) -> Value {
    let first = err.get(a).cloned().unwrap_or(Value::Null);
    if truthy(&first) {
        return first;
    }
    err.get(b).cloned().unwrap_or(Value::Null)
}

/// `value == number` with Python's int/float equality (`401.0 == 401`).
pub(crate) fn eq_int(value: &Value, number: i64) -> bool {
    match value {
        Value::Number(n) => n.as_f64() == Some(number as f64),
        _ => false,
    }
}

/// Parses JSON stdout and caps list length (FR-8.12). Not JSON -> as is.
pub(crate) fn cap_stdout(stdout: &str) -> String {
    match serde_json::from_str::<Value>(stdout) {
        Ok(parsed) => {
            let capped = cap_json_items(&parsed, MAX_JSON_ITEMS);
            pyjson::dumps_with(&capped, &pyjson::Opts::unicode())
        }
        Err(_) => stdout.to_string(),
    }
}

// -- The subprocess runner (both vendored CLIs) ----------------------------

/// What [`run_subprocess`] reports: Python's `Result` of `_run_subprocess`.
pub(crate) struct Spawned {
    pub exit_code: Option<i64>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub duration_ms: i64,
}

async fn read_capped<R: AsyncRead + Unpin>(stream: Option<R>, limit: usize) -> (Vec<u8>, bool) {
    let Some(mut stream) = stream else {
        return (Vec::new(), false);
    };
    let mut out: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 8192];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if out.len() + n > limit {
            let take = limit - out.len();
            out.extend_from_slice(&buf[..take]);
            // Drain the rest so the child never blocks on a full pipe.
            let mut sink = vec![0u8; 65536];
            while let Ok(m) = stream.read(&mut sink).await {
                if m == 0 {
                    break;
                }
            }
            return (out, true);
        }
        out.extend_from_slice(&buf[..n]);
    }
    (out, false)
}

/// Kills the child's whole process group (it runs in its own session).
fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        // SAFETY: plain kill(2) on the group this module created.
        unsafe {
            libc::killpg(pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

/// `execute_google._run_subprocess` + the caller's `wait_for`: no shell,
/// stdin from `/dev/null`, capped reads, a new session, and on timeout a
/// kill of the whole process group.
///
/// `env` = `None` inherits gatekeeper's environment (Python's `env=None`);
/// `Some` gives the child exactly those variables.
///
/// Returns `Err(Ok(denied))` when the executable cannot be started and
/// `Err(Err(()))` on timeout.
// Deliberately not `execute::local::run`: Python did not use `execute.run`
// here either, since that wraps the child in `_unpriv`.
pub(crate) async fn run_subprocess(
    argv: &[String],
    env: Option<&HashMap<String, String>>,
    timeout_seconds: i64,
    max_output_bytes: i64,
) -> Result<Spawned, Result<Denied, ()>> {
    let deadline = Duration::from_secs_f64(timeout_seconds.max(0) as f64);
    let limit = max_output_bytes.max(0) as usize;
    let mut command = tokio::process::Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(env) = env {
        command.env_clear().envs(env);
    }
    // start_new_session=True
    // SAFETY: setsid(2) is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(Ok(Denied::new(
                DenialReason::ExecutorUnavailable,
                format!("Executable not found: {}", argv[0]),
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(Ok(Denied::new(
                DenialReason::ExecutorUnavailable,
                format!("No permission to execute {}", argv[0]),
            )));
        }
        // PORT NOTE: any other spawn error escaped `run()` in Python; it is
        // reported as the executor being unavailable here.
        Err(err) => {
            return Err(Ok(Denied::new(
                DenialReason::ExecutorUnavailable,
                format!("Could not execute {}: {err}", argv[0]),
            )));
        }
    };
    let started = Instant::now();
    let pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let work = async {
        let ((out, out_trunc), (err, err_trunc)) =
            tokio::join!(read_capped(stdout, limit), read_capped(stderr, limit));
        let status = child.wait().await;
        (out, out_trunc, err, err_trunc, status)
    };
    match tokio::time::timeout(deadline, work).await {
        Ok((out, out_trunc, err, err_trunc, status)) => {
            let exit_code = status.ok().map(|s| {
                use std::os::unix::process::ExitStatusExt;
                match s.code() {
                    Some(code) => code as i64,
                    None => -(s.signal().unwrap_or(0) as i64),
                }
            });
            Ok(Spawned {
                exit_code,
                stdout: String::from_utf8_lossy(&out).into_owned(),
                stderr: String::from_utf8_lossy(&err).into_owned(),
                truncated: out_trunc || err_trunc,
                duration_ms: elapsed_ms(started),
            })
        }
        Err(_) => {
            kill_group(pid);
            Err(Err(()))
        }
    }
}

/// `docker ps --filter name=<container>` for a `*_container` toolkit's
/// probe: `docker` present and answering is enough.
pub(crate) async fn probe_container(container: &str) -> bool {
    let spawned = tokio::process::Command::new("docker")
        .args(["ps", "--filter", &format!("name={container}"), "--format", "{{.Names}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = spawned else {
        return false;
    };
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => status.success(),
        _ => false,
    }
}

/// The shared body of both vendored-CLI executors' `run`, after the
/// whitelist check and argv build. `provider` is `"Google"` or
/// `"Microsoft"` for the timeout message; `interpret` turns an exit into
/// `(outcome, stdout, stderr)`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_cli(
    argv: Vec<String>,
    started: Instant,
    provider: &str,
    interpret: fn(Option<i64>, &str, &str) -> (&'static str, String, String),
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    env: Option<&HashMap<String, String>>,
    redact: Option<&Redact>,
) -> ExecResult {
    let result = match run_subprocess(&argv, env, timeout_seconds, max_output_bytes).await {
        Ok(result) => result,
        Err(Err(())) => {
            let stderr = if idempotent {
                format!("Timeout of {timeout_seconds}s exceeded.")
            } else {
                format!(
                    "Timeout of {timeout_seconds}s exceeded. The outcome is UNKNOWN: the call may \
                     have reached {provider}. Do not retry without checking the state first."
                )
            };
            return ExecResult::new(
                if idempotent { OUTCOME_FAILED } else { OUTCOME_UNKNOWN },
                None,
                "",
                stderr,
                false,
                elapsed_ms(started),
            )
            .untrusted(true);
        }
        Err(Ok(denial)) => {
            return ExecResult::new(OUTCOME_FAILED, None, "", denial.agent_message(), false, elapsed_ms(started));
        }
    };

    let (outcome, mut stdout_text, mut stderr_text) =
        interpret(result.exit_code, &result.stdout, &result.stderr);

    if outcome == OUTCOME_OK && !stdout_text.is_empty() && !result.truncated {
        stdout_text = cap_stdout(&stdout_text);
    }

    if let Some(redact) = redact {
        stdout_text = redact(&stdout_text);
        stderr_text = redact(&stderr_text);
    }

    ExecResult::new(outcome, result.exit_code, stdout_text, stderr_text, result.truncated, result.duration_ms)
        .untrusted(true)
}

/// `re.split(r"[^a-z0-9]+", name.lower())`.
pub(crate) fn name_parts(name: &str) -> Vec<String> {
    name.to_lowercase()
        .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
        .map(str::to_string)
        .collect()
}

// -- google ----------------------------------------------------------------

/// The service tokens this executor recognizes in -- and can supply from
/// -- a toolkit name. Narrower than google_api.py's own grammar (which also
/// dispatches `contacts`, `sheets`, `docs`).
pub const GOOGLE_SERVICES: &[&str] = &["gmail", "calendar", "drive"];

/// The script path this call actually runs: the toolkit's own
/// `google_script`, or `fallback` when that path does not exist here (and
/// `fallback` does). Never substituted for a `google_container` toolkit,
/// whose script lives on another container's filesystem. `warn = false` is
/// for `probe`, which must not log a line per poll.
pub fn resolve_script(toolkit: &Toolkit, warn: bool, fallback: &str) -> String {
    let configured = toolkit.google_script.clone().unwrap_or_default();
    if toolkit.google_container.as_deref().is_some_and(|c| !c.is_empty()) {
        return configured;
    }
    if Path::new(&configured).is_file() {
        return configured;
    }
    if !Path::new(fallback).is_file() {
        // Neither exists: fail the ordinary way, naming the configured path.
        return configured;
    }
    if warn {
        tracing::warn!(
            "Toolkit {}: google_script {} does not exist -- falling back to the image's copy at {} \
             (baked in since 0.40.1). Update google_script in toolkits.yaml so the configuration \
             names the script that actually runs.",
            repr_str(&toolkit.name),
            configured,
            fallback
        );
    }
    fallback.to_string()
}

/// The CLI service token this toolkit's actions run under, from its name
/// (`gmail`, `google-calendar`, ...); `None` when the name says nothing.
pub fn service_prefix(toolkit: &Toolkit) -> Option<String> {
    name_parts(&toolkit.name).into_iter().find(|p| GOOGLE_SERVICES.contains(&p.as_str()))
}

/// `google_action` as argv words, with the service token in front when the
/// action does not already name one.
pub fn action_argv(toolkit: &Toolkit, google_action: &str) -> Vec<String> {
    let parts: Vec<String> = google_action.split_whitespace().map(str::to_string).collect();
    if parts.is_empty() || GOOGLE_SERVICES.contains(&parts[0].as_str()) {
        return parts;
    }
    match service_prefix(toolkit) {
        None => parts,
        Some(service) => std::iter::once(service).chain(parts).collect(),
    }
}

/// The full argv, with `fallback` as the stand-in script.
pub fn build_argv_with(toolkit: &Toolkit, google_action: &str, args: &[String], fallback: &str) -> Vec<String> {
    let action_parts = action_argv(toolkit, google_action);
    let script = resolve_script(toolkit, true, fallback);
    let mut argv = match toolkit.google_container.as_deref() {
        Some(container) if !container.is_empty() => {
            vec!["docker".into(), "exec".into(), container.to_string(), "python".into(), script]
        }
        _ => vec![python_interpreter(), script],
    };
    argv.extend(action_parts);
    argv.extend(args.iter().cloned());
    argv
}

/// `_build_argv`: interpreter, script, service + action, per-call tail.
pub fn build_argv(toolkit: &Toolkit, google_action: &str, args: &[String]) -> Vec<String> {
    build_argv_with(toolkit, google_action, args, &google_fallback_script())
}

/// Turns a google_api.py exit into `(outcome, stdout, stderr)`.
pub fn interpret_exit(exit_code: Option<i64>, stdout: &str, stderr: &str) -> (&'static str, String, String) {
    if exit_code == Some(0) {
        return (OUTCOME_OK, stdout.to_string(), stderr.to_string());
    }
    let detail = stderr.trim();
    if let Ok(Value::Object(err)) = serde_json::from_str::<Value>(detail) {
        let msg_v = {
            let v = or_get(&err, "message", "error");
            if truthy(&v) { v } else { Value::String(detail.to_string()) }
        };
        let msg = str_value(&msg_v);
        let code = or_get(&err, "code", "status");
        if eq_int(&code, 401) || code == Value::String("UNAUTHENTICATED".into()) || msg.contains("invalid_grant") {
            return (
                OUTCOME_FAILED,
                String::new(),
                format!(
                    "Google authentication failed (token expired or revoked): {msg}. Re-run the \
                     OAuth consent flow to obtain a new refresh token."
                ),
            );
        }
        if eq_int(&code, 403)
            || code == Value::String("PERMISSION_DENIED".into())
            || msg.to_lowercase().contains("insufficient")
        {
            return (
                OUTCOME_FAILED,
                String::new(),
                format!(
                    "Google denied the request: scope not covered by the refresh token ({msg}). \
                     Re-authorize with the additional scope, or grant the identity the required scope."
                ),
            );
        }
        return (OUTCOME_FAILED, String::new(), format!("Google API error ({}): {msg}", str_value(&code)));
    }
    let text = if detail.is_empty() {
        format!("google_api.py exited {}", exit_code.map_or("None".to_string(), |c| c.to_string()))
    } else {
        detail.to_string()
    };
    (OUTCOME_FAILED, String::new(), text)
}

/// Runs google_api.py as a subprocess and parses its JSON output. `env`
/// carries the materialized token's `HOME`, never argv (FR-10.2).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    google_action: &str,
    args: &[String],
    toolkit: &Toolkit,
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    env: Option<&HashMap<String, String>>,
    redact: Option<&Redact>,
) -> ExecResult {
    run_with(
        google_action,
        args,
        toolkit,
        timeout_seconds,
        max_output_bytes,
        idempotent,
        env,
        redact,
        &google_fallback_script(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with(
    google_action: &str,
    args: &[String],
    toolkit: &Toolkit,
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    env: Option<&HashMap<String, String>>,
    redact: Option<&Redact>,
    fallback: &str,
) -> ExecResult {
    let started = Instant::now();
    // Defensive re-check: the action is fixed per tool, not agent-suppliable.
    if !toolkit.allows_google_action(google_action) {
        return ExecResult::new(
            OUTCOME_FAILED,
            None,
            "",
            format!("Google action {} is not allowed for this toolkit.", repr_str(google_action)),
            false,
            elapsed_ms(started),
        );
    }
    let argv = build_argv_with(toolkit, google_action, args, fallback);
    run_cli(argv, started, "Google", interpret_exit, timeout_seconds, max_output_bytes, idempotent, env, redact)
        .await
}

/// For `/health/ready`: the script file exists (or, with
/// `google_container`, `docker` answers). Never runs google_api.py.
pub async fn probe(toolkit: &Toolkit) -> bool {
    probe_with(toolkit, &google_fallback_script()).await
}

pub(crate) async fn probe_with(toolkit: &Toolkit, fallback: &str) -> bool {
    if let Some(container) = toolkit.google_container.as_deref().filter(|c| !c.is_empty()) {
        return probe_container(container).await;
    }
    readable_file(&resolve_script(toolkit, false, fallback))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier1::load_tier1;
    use serde_json::json;

    const STUB: &str = r#"import json, os, sys, time

token_path = os.path.join(os.environ.get("HOME", ""), ".hermes", "google_token.json")
if not os.path.isfile(token_path):
    print(json.dumps({"error": "token file not found", "code": 401}))
    sys.exit(1)

action = " ".join(sys.argv[1:])

if "expire" in action:
    print(json.dumps({"error": "invalid_grant", "message": "Token expired"}), file=sys.stderr)
    sys.exit(1)

if "scope" in action:
    print(json.dumps({"error": "Request had insufficient permissions", "code": 403}), file=sys.stderr)
    sys.exit(1)

if "slow" in action:
    time.sleep(2)

if "big" in action:
    print(json.dumps([{"id": str(i)} for i in range(1000)]))
    sys.exit(0)

if action.startswith("gmail search"):
    print(json.dumps([{"id": "msg1", "snippet": "hello"}, {"id": "msg2", "snippet": "world"}]))
elif action.startswith("gmail labels"):
    print(json.dumps([{"id": "INBOX", "name": "INBOX"}, {"id": "UNREAD", "name": "UNREAD"}]))
else:
    print(json.dumps({"ok": True, "action": action}))
sys.exit(0)
"#;

    const WHO_STUB: &str = r#"import json, os, sys
print(json.dumps({"ran": os.path.abspath(__file__), "action": " ".join(sys.argv[1:])}))
sys.exit(0)
"#;

    struct Env {
        dir: tempfile::TempDir,
        script: String,
        home: HashMap<String, String>,
    }

    fn setup() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("google_api.py");
        std::fs::write(&script, STUB).unwrap();
        let hermes = dir.path().join("fake-home").join(".hermes");
        std::fs::create_dir_all(&hermes).unwrap();
        std::fs::write(
            hermes.join("google_token.json"),
            r#"{"client_id": "c", "client_secret": "s", "refresh_token": "r"}"#,
        )
        .unwrap();
        let home = HashMap::from([(
            "HOME".to_string(),
            dir.path().join("fake-home").to_string_lossy().into_owned(),
        )]);
        Env { script: script.to_string_lossy().into_owned(), dir, home }
    }

    fn toolkit_named(env: &Env, name: &str, script: &str, actions: &[&str], container: Option<&str>) -> Toolkit {
        let mut spec = json!({
            "executor": "google",
            "google_script": script,
            "allowed_google_actions": actions,
            "credential": "google",
            "max_timeout_seconds": 20,
            "max_output_bytes": 131072,
        });
        if let Some(c) = container {
            spec["google_container"] = json!(c);
        }
        let doc = json!({"toolkits": {name: spec}, "audit": {"dir": env.dir.path().join("logs").to_str().unwrap()}});
        let path = env.dir.path().join(format!("toolkits-{name}.yaml"));
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        load_tier1(path.to_str().unwrap()).unwrap().toolkit(name).unwrap().clone()
    }

    fn gmail(env: &Env) -> Toolkit {
        toolkit_named(
            env,
            "gmail",
            &env.script.clone(),
            &["gmail search", "gmail labels", "gmail search expire", "gmail search scope", "gmail search slow", "gmail search big"],
            None,
        )
    }

    async fn call(tk: &Toolkit, env: &Env, action: &str, args: &[&str], timeout: i64, max: i64, idem: bool) -> ExecResult {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        run_with(action, &args, tk, timeout, max, idem, Some(&env.home), None, "/etc/nonexistent/baked.py").await
    }

    #[tokio::test]
    async fn successful_search() {
        let env = setup();
        let tk = gmail(&env);
        let r = call(&tk, &env, "gmail search", &["is:unread", "--max", "10"], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_OK, "{r:?}");
        let payload: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(payload[0]["id"], "msg1");
        assert!(r.external_untrusted);
    }

    #[tokio::test]
    async fn json_output_capped_at_max_items() {
        let env = setup();
        let tk = gmail(&env);
        let r = call(&tk, &env, "gmail search big", &[], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_OK);
        let payload: Value = serde_json::from_str(&r.stdout).unwrap();
        assert!(payload.as_array().unwrap().len() <= 500);
    }

    #[tokio::test]
    async fn token_expired_clear_message() {
        let env = setup();
        let r = call(&gmail(&env), &env, "gmail search expire", &[], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        // As in Python: no `code`, and "invalid_grant" is the `error`, not the message.
        assert_eq!(r.stderr, "Google API error (None): Token expired");
    }

    #[tokio::test]
    async fn scope_denied_clear_message() {
        let env = setup();
        let r = call(&gmail(&env), &env, "gmail search scope", &[], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(r.stderr.contains("scope not covered by the refresh token (Request had insufficient permissions)"));
    }

    #[tokio::test]
    async fn timeouts() {
        let env = setup();
        let tk = gmail(&env);
        let r = call(&tk, &env, "gmail search slow", &[], 1, 65536, false).await;
        assert_eq!(r.outcome, OUTCOME_UNKNOWN);
        assert!(r.stderr.contains("may have reached Google"));
        assert!(r.external_untrusted);
        let r = call(&tk, &env, "gmail search slow", &[], 1, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.stderr, "Timeout of 1s exceeded.");
    }

    #[tokio::test]
    async fn response_truncated_at_max_output_bytes() {
        let env = setup();
        let r = call(&gmail(&env), &env, "gmail search big", &[], 10, 50, true).await;
        assert!(r.truncated);
        assert_eq!(r.stdout.len(), 50);
    }

    #[tokio::test]
    async fn action_not_in_allowlist_denied() {
        let env = setup();
        let r = call(&gmail(&env), &env, "gmail delete", &[], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.stderr, "Google action 'gmail delete' is not allowed for this toolkit.");
    }

    #[tokio::test]
    async fn redact_applies_to_output() {
        let env = setup();
        let tk = gmail(&env);
        let redact: Redact = std::sync::Arc::new(|s: &str| s.replace("msg1", "***"));
        let args = vec!["x".to_string()];
        let r = run_with("gmail search", &args, &tk, 10, 65536, true, Some(&env.home), Some(&redact), "/x").await;
        assert!(r.stdout.contains("***") && !r.stdout.contains("msg1"));
    }

    #[tokio::test]
    async fn probes() {
        let env = setup();
        assert!(probe_with(&gmail(&env), "/etc/nonexistent").await);
        let missing = env.dir.path().join("nonexistent.py");
        let tk = toolkit_named(&env, "gmail2", missing.to_str().unwrap(), &["gmail search"], None);
        assert!(!probe_with(&tk, "/etc/nonexistent").await);
    }

    #[tokio::test]
    async fn a_bare_action_runs_under_its_service() {
        let env = setup();
        let tk = toolkit_named(&env, "gmail", &env.script.clone(), &["labels"], None);
        let argv = build_argv(&tk, "labels", &[]);
        assert_eq!(argv[2..].join(" "), "gmail labels");
        let r = call(&tk, &env, "labels", &[], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_OK);
        assert_eq!(r.exit_code, Some(0));
        let ids: Vec<String> = serde_json::from_str::<Vec<Value>>(&r.stdout)
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids, ["INBOX", "UNREAD"]);
    }

    #[test]
    fn the_service_comes_from_the_toolkit_name() {
        let env = setup();
        for (name, action, expected) in [
            ("gmail", "labels", "gmail labels"),
            ("calendar", "list", "calendar list"),
            ("drive", "search", "drive search"),
            ("google-calendar", "list", "calendar list"),
        ] {
            let tk = toolkit_named(&env, name, &env.script.clone(), &[action], None);
            assert_eq!(build_argv(&tk, action, &[])[2..].join(" "), expected);
        }
        let tk = toolkit_named(&env, "gmail", &env.script.clone(), &["gmail search"], None);
        assert_eq!(build_argv(&tk, "gmail search", &["is:unread".into()])[2..], ["gmail", "search", "is:unread"]);
        let tk = toolkit_named(&env, "gmail", &env.script.clone(), &["search"], None);
        let tail: Vec<String> = ["is:unread from:a b", "--max", "10"].iter().map(|s| s.to_string()).collect();
        assert_eq!(build_argv(&tk, "search", &tail)[2..], ["gmail", "search", "is:unread from:a b", "--max", "10"]);
        let tk = toolkit_named(&env, "mailbox", &env.script.clone(), &["labels"], None);
        assert_eq!(build_argv(&tk, "labels", &[])[2..], ["labels"]);
        assert_eq!(build_argv(&tk, "labels", &[])[0], python_interpreter());
    }

    // -- The fallback (test_google_fallback.py) ----------------------------

    const LEGACY: &str = "/etc/nonexistent/google_api.py";

    #[tokio::test]
    async fn a_legacy_script_path_runs_the_baked_copy() {
        let env = setup();
        let baked = env.dir.path().join("baked_google_api.py");
        std::fs::write(&baked, WHO_STUB).unwrap();
        let baked = baked.to_str().unwrap().to_string();
        let tk = toolkit_named(&env, "gmail", LEGACY, &["gmail search"], None);
        let home = HashMap::from([("HOME".to_string(), "/nonexistent-home".to_string())]);
        let args = vec!["is:unread".to_string()];
        let r = run_with("gmail search", &args, &tk, 10, 65536, true, Some(&home), None, &baked).await;
        assert_eq!(r.outcome, OUTCOME_OK, "{r:?}");
        let payload: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(payload["ran"], json!(baked));
        assert_eq!(payload["action"], "gmail search is:unread");
        assert!(probe_with(&tk, &baked).await);

        // An existing script is used unchanged.
        let own = env.dir.path().join("own_google_api.py");
        std::fs::write(&own, WHO_STUB).unwrap();
        let tk = toolkit_named(&env, "gmail", own.to_str().unwrap(), &["gmail search"], None);
        let r = run_with("gmail search", &args, &tk, 10, 65536, true, Some(&home), None, &baked).await;
        assert_eq!(serde_json::from_str::<Value>(&r.stdout).unwrap()["ran"], json!(own.to_str().unwrap()));

        // A container toolkit never falls back.
        let tk = toolkit_named(&env, "gmail", LEGACY, &["gmail search"], Some("hermes-google"));
        let argv = build_argv_with(&tk, "gmail search", &args, &baked);
        assert_eq!(argv[..3], ["docker", "exec", "hermes-google"]);
        assert!(argv.contains(&LEGACY.to_string()) && !argv.contains(&baked));
    }

    #[tokio::test]
    async fn without_a_baked_copy_the_configured_path_is_kept() {
        let env = setup();
        let tk = toolkit_named(&env, "gmail", LEGACY, &["gmail search"], None);
        let home = HashMap::from([("HOME".to_string(), "/nonexistent-home".to_string())]);
        let r = run_with("gmail search", &[], &tk, 10, 65536, true, Some(&home), None, "/etc/nonexistent/baked.py").await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(r.stderr.contains(LEGACY), "{}", r.stderr);
    }

    #[test]
    fn interpret_exit_messages() {
        let (o, _, e) = interpret_exit(Some(2), "", "usage: boom\n");
        assert_eq!((o, e.as_str()), (OUTCOME_FAILED, "usage: boom"));
        let (_, _, e) = interpret_exit(Some(3), "", "");
        assert_eq!(e, "google_api.py exited 3");
        let (_, _, e) = interpret_exit(Some(1), "", r#"{"error": "x", "code": 500}"#);
        assert_eq!(e, "Google API error (500): x");
        let (_, _, e) = interpret_exit(Some(1), "", r#"{"message": "nope", "code": "UNAUTHENTICATED"}"#);
        assert!(e.starts_with("Google authentication failed"));
        let (_, _, e) = interpret_exit(Some(1), "", r#"{"other": 1}"#);
        assert_eq!(e, r#"Google API error (None): {"other": 1}"#);
    }

    #[test]
    fn cap_json_matches_python() {
        let v = json!({"a": [1, 2, 3], "b": {"c": 1}});
        assert_eq!(cap_json_items(&v, 3), json!({"a": [1, 2, 3]}));
        assert_eq!(cap_json_items(&v, 2), json!({"a": [1, 2]}));
        assert_eq!(cap_json_items(&json!([[1], [2]]), 1), json!([[1]]));
        assert_eq!(cap_json_items(&json!([1, [2]]), 1), json!([1]));
        assert_eq!(cap_json_items(&json!({"a": 1, "b": [1]}), 1), json!({"a": 1}));
    }
}
