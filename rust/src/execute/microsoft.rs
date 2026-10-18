//! The `microsoft` executor -- the Outlook/Graph counterpart of `google`
//! (port of `execute_microsoft.py`).
//!
//! The vendored `scripts/microsoft/microsoft_api.py` (stays Python) wraps
//! Microsoft Graph's mail endpoints, authenticates with an OAuth2 token
//! file (`$HOME/.hermes/microsoft_token.json`, materialized 0600 by the
//! service and handed over via `HOME`, never argv -- FR-10.2) and emits
//! JSON on stdout. Everything `google`'s module docs say about why this is
//! a separate executor holds here unchanged; the subprocess runner, the
//! interpreter lookup and the JSON cap are `google`'s, reused rather than
//! copied.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use serde_json::Value;

use crate::execute::google::{
    eq_int, name_parts, or_get, probe_container, python_interpreter, readable_file, run_cli, truthy,
    vendored_script,
};
use crate::execute::{elapsed_ms, ExecResult, Redact, OUTCOME_FAILED, OUTCOME_OK};
use crate::pyfmt::{repr_str, str_value};
use crate::tier1::Toolkit;

/// The `microsoft_api.py` the fallback substitutes
/// (`MICROSOFT_FALLBACK_SCRIPT`'s role): `GATEKEEPER_MICROSOFT_SCRIPT`,
/// else the image / checkout copy (see [`vendored_script`]).
pub fn microsoft_fallback_script() -> String {
    vendored_script("GATEKEEPER_MICROSOFT_SCRIPT", "microsoft", "microsoft_api.py")
}

/// The services microsoft_api.py dispatches on.
pub const MICROSOFT_SERVICES: &[&str] = &["mail"];

/// The service a bare action runs under when the toolkit name says
/// nothing: Graph mail is the only service this script has.
pub const DEFAULT_MICROSOFT_SERVICE: &str = "mail";

/// Tool-shaped action names, mapped to the CLI action word they mean. A
/// fixed table of four rather than a rule; it widens nothing -- Tier 1
/// still matches the configured action verbatim before translation.
pub const MICROSOFT_ACTION_ALIASES: &[(&str, &str)] = &[
    ("list_messages", "list"),
    ("get_message", "get"),
    ("list_folders", "folders"),
    ("send_mail", "send"),
];

fn alias(word: &str) -> Option<&'static str> {
    MICROSOFT_ACTION_ALIASES.iter().find(|(k, _)| *k == word).map(|(_, v)| *v)
}

/// The script path this call actually runs (see `google::resolve_script`).
pub fn resolve_script(toolkit: &Toolkit, warn: bool, fallback: &str) -> String {
    let configured = toolkit.microsoft_script.clone().unwrap_or_default();
    if toolkit.microsoft_container.as_deref().is_some_and(|c| !c.is_empty()) {
        return configured;
    }
    if Path::new(&configured).is_file() {
        return configured;
    }
    if !Path::new(fallback).is_file() {
        return configured;
    }
    if warn {
        tracing::warn!(
            "Toolkit {}: microsoft_script {} does not exist -- falling back to the image's copy at {}. \
             Update microsoft_script in toolkits.yaml so the configuration names the script that \
             actually runs.",
            repr_str(&toolkit.name),
            configured,
            fallback
        );
    }
    fallback.to_string()
}

/// The CLI service token: from the toolkit name where it names one, else
/// [`DEFAULT_MICROSOFT_SERVICE`].
pub fn service_prefix(toolkit: &Toolkit) -> String {
    name_parts(&toolkit.name)
        .into_iter()
        .find(|p| MICROSOFT_SERVICES.contains(&p.as_str()))
        .unwrap_or_else(|| DEFAULT_MICROSOFT_SERVICE.to_string())
}

/// `microsoft_action` as argv words the CLI accepts: alias translation,
/// then the service token in front of a bare action.
pub fn action_argv(toolkit: &Toolkit, microsoft_action: &str) -> Vec<String> {
    let parts: Vec<String> = microsoft_action.split_whitespace().map(str::to_string).collect();
    if parts.is_empty() {
        return parts;
    }
    let (service, mut rest) = if MICROSOFT_SERVICES.contains(&parts[0].as_str()) {
        (parts[0].clone(), parts[1..].to_vec())
    } else {
        (service_prefix(toolkit), parts)
    };
    if rest.len() == 1 {
        if let Some(word) = alias(&rest[0]) {
            rest = vec![word.to_string()];
        }
    }
    std::iter::once(service).chain(rest).collect()
}

pub fn build_argv_with(toolkit: &Toolkit, microsoft_action: &str, args: &[String], fallback: &str) -> Vec<String> {
    let action_parts = action_argv(toolkit, microsoft_action);
    let script = resolve_script(toolkit, true, fallback);
    let mut argv = match toolkit.microsoft_container.as_deref() {
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
pub fn build_argv(toolkit: &Toolkit, microsoft_action: &str, args: &[String]) -> Vec<String> {
    build_argv_with(toolkit, microsoft_action, args, &microsoft_fallback_script())
}

/// Turns a microsoft_api.py exit into `(outcome, stdout, stderr)`.
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
        let is_str = |s: &str| code == Value::String(s.into());
        if eq_int(&code, 401) || is_str("401") || is_str("InvalidAuthenticationToken") || msg.contains("invalid_grant") {
            return (
                OUTCOME_FAILED,
                String::new(),
                format!(
                    "Microsoft authentication failed (token expired or revoked): {msg}. Re-run the \
                     OAuth consent flow from the console to obtain a new refresh token."
                ),
            );
        }
        if eq_int(&code, 403)
            || is_str("403")
            || is_str("ErrorAccessDenied")
            || msg.to_lowercase().contains("insufficient")
            || msg.contains("invalid_scope")
        {
            return (
                OUTCOME_FAILED,
                String::new(),
                format!(
                    "Microsoft denied the request: scope not covered by the refresh token ({msg}). \
                     Re-authorize with the additional scope, or grant the identity the required scope."
                ),
            );
        }
        return (OUTCOME_FAILED, String::new(), format!("Microsoft Graph error ({}): {msg}", str_value(&code)));
    }
    let text = if detail.is_empty() {
        format!("microsoft_api.py exited {}", exit_code.map_or("None".to_string(), |c| c.to_string()))
    } else {
        detail.to_string()
    };
    (OUTCOME_FAILED, String::new(), text)
}

/// Runs microsoft_api.py as a subprocess and parses its JSON output.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    microsoft_action: &str,
    args: &[String],
    toolkit: &Toolkit,
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    env: Option<&HashMap<String, String>>,
    redact: Option<&Redact>,
) -> ExecResult {
    run_with(
        microsoft_action,
        args,
        toolkit,
        timeout_seconds,
        max_output_bytes,
        idempotent,
        env,
        redact,
        &microsoft_fallback_script(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with(
    microsoft_action: &str,
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
    if !toolkit.allows_microsoft_action(microsoft_action) {
        return ExecResult::new(
            OUTCOME_FAILED,
            None,
            "",
            format!("Microsoft action {} is not allowed for this toolkit.", repr_str(microsoft_action)),
            false,
            elapsed_ms(started),
        );
    }
    let argv = build_argv_with(toolkit, microsoft_action, args, fallback);
    run_cli(argv, started, "Microsoft", interpret_exit, timeout_seconds, max_output_bytes, idempotent, env, redact)
        .await
}

/// For `/health/ready`: the script file exists (or, with
/// `microsoft_container`, `docker` answers). Never runs the script.
pub async fn probe(toolkit: &Toolkit) -> bool {
    probe_with(toolkit, &microsoft_fallback_script()).await
}

pub(crate) async fn probe_with(toolkit: &Toolkit, fallback: &str) -> bool {
    if let Some(container) = toolkit.microsoft_container.as_deref().filter(|c| !c.is_empty()) {
        return probe_container(container).await;
    }
    readable_file(&resolve_script(toolkit, false, fallback))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execute::{OUTCOME_UNKNOWN};
    use crate::tier1::load_tier1;
    use serde_json::json;

    const STUB: &str = r#"import json, os, sys, time

token_path = os.path.join(os.environ.get("HOME", ""), ".hermes", "microsoft_token.json")
if not os.path.isfile(token_path):
    print(json.dumps({"code": 401, "message": "token file not found"}), file=sys.stderr)
    sys.exit(1)

action = " ".join(sys.argv[1:])

if "expire" in action:
    print(json.dumps({"code": 401, "message": "invalid_grant"}), file=sys.stderr)
    sys.exit(1)
if "scope" in action:
    print(json.dumps({"code": 403, "message": "insufficient privileges"}), file=sys.stderr)
    sys.exit(1)
if "boom" in action:
    print("not json at all", file=sys.stderr)
    sys.exit(2)
if "slow" in action:
    time.sleep(2)
if "big" in action:
    print(json.dumps([{"id": str(i)} for i in range(1000)]))
    sys.exit(0)

if action.startswith("mail list"):
    print(json.dumps([{"id": "AAMk-1", "subject": "hello"}]))
elif action.startswith("mail send"):
    print(json.dumps({"status": "sent", "http_status": 202, "argv": sys.argv[1:]}))
elif action.startswith("mail folders"):
    print(json.dumps([{"id": "AAMk-inbox", "name": "Inbox"}]))
else:
    print(json.dumps({"ok": True, "action": action}))
sys.exit(0)
"#;

    const NO_FALLBACK: &str = "/etc/nonexistent/microsoft_api.py";

    struct Env {
        dir: tempfile::TempDir,
        script: String,
        home: HashMap<String, String>,
    }

    fn setup() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("microsoft_api.py");
        std::fs::write(&script, STUB).unwrap();
        let hermes = dir.path().join("fake-home").join(".hermes");
        std::fs::create_dir_all(&hermes).unwrap();
        std::fs::write(hermes.join("microsoft_token.json"), r#"{"refresh_token": "1.AXEAsecret-refresh"}"#).unwrap();
        let home = HashMap::from([(
            "HOME".to_string(),
            dir.path().join("fake-home").to_string_lossy().into_owned(),
        )]);
        Env { script: script.to_string_lossy().into_owned(), dir, home }
    }

    fn toolkit_with(env: &Env, file: &str, script: &str, actions: &[&str]) -> Toolkit {
        let doc = json!({
            "toolkits": {"outlook": {
                "executor": "microsoft",
                "microsoft_script": script,
                "allowed_microsoft_actions": actions,
                "credential": "msgraph",
                "max_timeout_seconds": 20,
                "max_output_bytes": 131072,
            }},
            "audit": {"dir": env.dir.path().join("logs").to_str().unwrap()},
        });
        let path = env.dir.path().join(file);
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        load_tier1(path.to_str().unwrap()).unwrap().toolkit("outlook").unwrap().clone()
    }

    fn outlook(env: &Env) -> Toolkit {
        toolkit_with(
            env,
            "toolkits.yaml",
            &env.script.clone(),
            &[
                "mail list", "mail get", "mail folders", "mail send", "mail list expire", "mail list scope",
                "mail list slow", "mail list big", "mail list boom",
            ],
        )
    }

    async fn call(tk: &Toolkit, env: &Env, action: &str, args: &[&str], timeout: i64, max: i64, idem: bool) -> ExecResult {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        run_with(action, &args, tk, timeout, max, idem, Some(&env.home), None, NO_FALLBACK).await
    }

    #[tokio::test]
    async fn the_executor_runs_the_script_and_parses_its_json() {
        let env = setup();
        let r = call(&outlook(&env), &env, "mail list", &["--folder", "inbox", "--max", "10"], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_OK, "{r:?}");
        assert_eq!(serde_json::from_str::<Value>(&r.stdout).unwrap(), json!([{"id": "AAMk-1", "subject": "hello"}]));
        assert!(r.external_untrusted);
    }

    #[test]
    fn argv_shape() {
        let env = setup();
        let tk = outlook(&env);
        assert_eq!(action_argv(&tk, "list"), ["mail", "list"]);
        assert_eq!(action_argv(&tk, "mail list"), ["mail", "list"]);
        let argv = build_argv_with(&tk, "mail list", &["--folder".into(), "inbox".into()], NO_FALLBACK);
        assert_eq!(argv[0], python_interpreter());
        assert_eq!(argv[1], env.script);
        assert_eq!(argv[2..], ["mail", "list", "--folder", "inbox"]);
        assert!(!argv.iter().any(|a| a.contains("secret-refresh")));
    }

    #[tokio::test]
    async fn failures_say_what_to_do() {
        let env = setup();
        let tk = outlook(&env);
        let r = call(&tk, &env, "mail delete", &[], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(r.stderr.contains("not allowed"));
        let r = call(&tk, &env, "mail list expire", &[], 10, 65536, true).await;
        assert!(r.stderr.contains("authentication failed") && r.stderr.contains("Re-run the OAuth consent flow"));
        let r = call(&tk, &env, "mail list scope", &[], 10, 65536, true).await;
        assert!(r.stderr.contains("scope not covered"));
        let r = call(&tk, &env, "mail list boom", &[], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.stderr, "not json at all");
        assert_eq!(r.exit_code, Some(2));
    }

    #[tokio::test]
    async fn a_long_list_is_capped_and_a_timeout_is_unknown() {
        let env = setup();
        let tk = outlook(&env);
        let r = call(&tk, &env, "mail list big", &[], 10, 1_000_000, true).await;
        assert_eq!(r.outcome, OUTCOME_OK);
        assert!(serde_json::from_str::<Vec<Value>>(&r.stdout).unwrap().len() < 1000);
        let r = call(&tk, &env, "mail list slow", &[], 1, 65536, false).await;
        assert_eq!(r.outcome, OUTCOME_UNKNOWN);
        assert!(r.stderr.contains("may have reached Microsoft"));
    }

    #[tokio::test]
    async fn a_missing_script_and_the_fallback() {
        let env = setup();
        let tk = toolkit_with(&env, "missing.yaml", "/nonexistent/microsoft_api.py", &["mail list"]);
        let r = call(&tk, &env, "mail list", &[], 5, 8192, true).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(!probe_with(&tk, NO_FALLBACK).await);
        assert!(probe_with(&outlook(&env), NO_FALLBACK).await);

        let tk = toolkit_with(&env, "fallback.yaml", "/srv/host-mount/microsoft_api.py", &["mail list"]);
        assert_eq!(build_argv_with(&tk, "mail list", &[], &env.script)[1], env.script);
        let r = run_with("mail list", &[], &tk, 10, 8192, true, Some(&env.home), None, &env.script).await;
        assert_eq!(r.outcome, OUTCOME_OK);
        assert!(probe_with(&tk, &env.script).await);
    }

    #[test]
    fn every_spelling_of_the_four_actions_reaches_the_cli_word() {
        let env = setup();
        let tk = outlook(&env);
        for (action, expected) in [
            ("list_messages", ["mail", "list"]),
            ("mail list_messages", ["mail", "list"]),
            ("get_message", ["mail", "get"]),
            ("mail get_message", ["mail", "get"]),
            ("list_folders", ["mail", "folders"]),
            ("mail list_folders", ["mail", "folders"]),
            ("send_mail", ["mail", "send"]),
            ("mail send_mail", ["mail", "send"]),
            ("list", ["mail", "list"]),
            ("mail list", ["mail", "list"]),
            ("get", ["mail", "get"]),
            ("folders", ["mail", "folders"]),
            ("send", ["mail", "send"]),
            ("mail send", ["mail", "send"]),
        ] {
            assert_eq!(action_argv(&tk, action), expected, "{action}");
        }
        assert_eq!(action_argv(&tk, "archive_message"), ["mail", "archive_message"]);
        assert_eq!(action_argv(&tk, "mail move"), ["mail", "move"]);
        assert!(action_argv(&tk, "").is_empty());
    }

    #[tokio::test]
    async fn a_tool_shaped_toolkit() {
        let env = setup();
        let tk = toolkit_with(
            &env,
            "tool-shaped.yaml",
            &env.script.clone(),
            &["list_messages", "get_message", "list_folders", "send_mail"],
        );
        let argv = build_argv_with(&tk, "get_message", &["AAMk-1".into()], NO_FALLBACK);
        assert_eq!(argv[2..], ["mail", "get", "AAMk-1"]);
        let r = call(&tk, &env, "list_messages", &["--folder", "inbox"], 10, 65536, true).await;
        assert_eq!(r.outcome, OUTCOME_OK);
        assert_eq!(serde_json::from_str::<Value>(&r.stdout).unwrap(), json!([{"id": "AAMk-1", "subject": "hello"}]));

        let ro = toolkit_with(&env, "ro.yaml", &env.script.clone(), &["list_messages", "get_message", "list_folders"]);
        for action in ["send_mail", "mail send"] {
            let r = call(&ro, &env, action, &[], 10, 65536, true).await;
            assert_eq!(r.outcome, OUTCOME_FAILED);
            assert!(r.stderr.contains("not allowed"));
        }
    }

    #[test]
    fn interpret_exit_codes() {
        let (_, _, e) = interpret_exit(Some(1), "", r#"{"code": "ErrorAccessDenied", "message": "x"}"#);
        assert!(e.starts_with("Microsoft denied the request"));
        let (_, _, e) = interpret_exit(Some(1), "", r#"{"code": "InvalidAuthenticationToken", "message": "x"}"#);
        assert!(e.starts_with("Microsoft authentication failed"));
        let (_, _, e) = interpret_exit(Some(1), "", r#"{"code": "Other", "message": "x"}"#);
        assert_eq!(e, "Microsoft Graph error (Other): x");
        let (_, _, e) = interpret_exit(None, "", "");
        assert_eq!(e, "microsoft_api.py exited None");
    }
}
