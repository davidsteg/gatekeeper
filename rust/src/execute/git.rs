//! The `git` executor: push one branch from an allowlisted repository
//! (port of `execute_git.py`).
//!
//! A worker that commits into a checkout on this host still needs the
//! result on GitHub, and the obvious ways to get it there are the ones
//! gatekeeper exists to replace: a token in the worker's environment or in
//! the checkout's `.git/config`, or the worker shipping file contents
//! through an API call. This executor pushes instead. The caller names a
//! repository (a key in the toolkit's `repos:`) and a branch, nothing else;
//! the path, the remote and the token are Tier 1 and the credential store.
//!
//! One operation, `push`, and it is narrow on purpose:
//!
//! * The target is always `refs/heads/<branch>` with the branch under
//!   [`GIT_PUSH_BRANCH_PREFIX`] (`feat/`). `main` is not refused by a rule
//!   that could be edited, it is simply not a name this module builds.
//! * The refspec has no `+`, and there is no force, force-with-lease,
//!   delete or mirror flag anywhere in this file. A push that is not a
//!   fast-forward is rejected by git itself, and reported as such.
//! * The output is the old and new SHA of the remote branch and a capped
//!   list of the commits that went over -- never a diff or file content.
//!
//! **The worker's repository is read, never trusted.** Whoever writes into
//! the checkout also writes its `.git/config` and `.git/hooks`, and a push
//! run *in* that repository would execute its `pre-push` hook, follow its
//! `url.<x>.insteadOf` to wherever it points, and hand the token to its
//! `credential.helper`. So no git command here runs in it. Each call builds
//! a throwaway bare repository whose config gatekeeper writes, borrows the
//! worker's object store as an alternate (so nothing is copied), and
//! fetches the one branch from the worker's path -- the only thing that
//! touches the worker's repository is `git upload-pack`, which ignores the
//! repository's hooks and code-running config keys. The push then runs in
//! the throwaway repository: no hooks, no system or global config, no
//! credential helper, no redirects, https only.
//!
//! **The token never sits in argv.** It reaches git as
//! `http.<remote>.extraHeader` through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`
//! in the child's environment -- readable by the same user and root, not by
//! a `ps` on the host (FR-10.2) -- and only for the two steps that talk to
//! the remote. Every text that leaves this module is scrubbed of the token
//! and of the encoded header before the audit redactor sees it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine as _;
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use super::opencode::splitlines;
use super::{elapsed_ms, ExecResult, Redact, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::api::deps::py_strip;
use crate::credentials::{CredentialStore, ResolvedCredential};
use crate::errors::{ConfigError, DenialReason, Denied};
use crate::pyfmt::{repr_list, repr_str};
use crate::pyjson;
use crate::tier1::{is_runnable, GitRepo, Toolkit, DEFAULT_GIT_BINARY, GIT_PUSH_BRANCH_PREFIX};
use crate::validate::Values;

/// How many commits the output lists, and how much of each subject. The
/// total is reported separately, so a long branch is visibly cut, not
/// silently short.
pub const MAX_COMMITS: usize = 20;
pub const MAX_SUBJECT_CHARS: usize = 100;

/// Ceiling on the remote heads a new branch's commit list is measured
/// against (`rev-list --not ...`). Only bounds argv on a remote with an
/// unusual number of branches; past it the count can only come out high.
const MAX_EXCLUDED_HEADS: usize = 256;

/// How much of git's own stderr a failure carries.
const MAX_ERROR_CHARS: usize = 2000;

/// The only lines of git's stderr a failure passes on to the caller: what
/// the remote said (`remote: ...`) and git's own words about reaching it.
/// Everything else stays out, because git quotes local files in its errors
/// -- an `objects/info/alternates` or `packed-refs` the worker pointed at
/// `/etc/gatekeeper/credentials.yaml` comes back one line per error, and
/// the caller is the worker.
const PASSED_STDERR_PREFIXES: &[&str] = &[
    "remote: ",
    "fatal: unable to access ",
    "fatal: Authentication failed",
    "fatal: could not read Username",
    "error: failed to push some refs",
    "error: RPC failed",
];

const MAX_BRANCH_CHARS: usize = 200;

/// `/dev/null` (`os.devnull`).
const DEVNULL: &str = "/dev/null";

/// One path component of a branch under the prefix: no leading '.' or
/// '-', none of git's ref metacharacters (`^[A-Za-z0-9_][A-Za-z0-9._-]*$`).
/// Stricter than `git check-ref-format`, which is the point.
// PORT NOTE: Python's `re.match` with `$` also matched before a trailing
// newline, so `feat/x\n` passed the component check there (and failed in
// git later); here the whole component must match.
fn is_branch_component(part: &str) -> bool {
    let bytes = part.as_bytes();
    !bytes.is_empty()
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        && bytes[1..].iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `^[0-9a-f]{40}([0-9a-f]{24})?$`: a SHA-1 or SHA-256 object name.
fn is_sha(text: &str) -> bool {
    (text.len() == 40 || text.len() == 64) && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The executor's own floor under whatever the tool definition says: the
/// repo is a key of the toolkit's `repos:`, the branch is a plain name
/// under `feat/`.
pub fn check_values(toolkit: &Toolkit, values: &Values) -> Result<(), Denied> {
    let repo = values.get("repo").map(String::as_str).unwrap_or("");
    if toolkit.git_repo(repo).is_none() {
        let names: Vec<&str> = toolkit.git_repos.iter().map(|r| r.name.as_str()).collect();
        return Err(Denied::new(
            DenialReason::Tier1Violation,
            format!(
                "Repository {} is not one this toolkit may push from (allowed: {}).",
                repr_str(repo),
                repr_list(&names)
            ),
        ));
    }
    let branch = values.get("branch").map(String::as_str).unwrap_or("");
    let Some(rest) = branch.strip_prefix(GIT_PUSH_BRANCH_PREFIX) else {
        return Err(Denied::new(
            DenialReason::ParamInvalid,
            format!(
                "Parameter 'branch' must start with {}; nothing else can be pushed.",
                repr_str(GIT_PUSH_BRANCH_PREFIX)
            ),
        ));
    };
    if branch.chars().count() > MAX_BRANCH_CHARS
        || rest.is_empty()
        || branch.contains("..")
        || branch.ends_with('.')
        || branch.ends_with(".lock")
        || rest.split('/').any(|part| !is_branch_component(part) || part.ends_with(".lock"))
    {
        return Err(Denied::new(
            DenialReason::ParamInvalid,
            format!(
                "Parameter 'branch' must be {GIT_PUSH_BRANCH_PREFIX}<name>, with letters, digits, '.', '_', '-' \
                 and '/' between parts, at most {MAX_BRANCH_CHARS} characters."
            ),
        ));
    }
    Ok(())
}

/// The Authorization header for git over https, and every form of the
/// secret that must never appear in an output.
///
/// A `bearer` credential is a token on its own (GitHub's convention is any
/// user name with the token as password); a `basic` one is `user:token`.
/// Git over https takes Basic, not Bearer.
fn auth_header(credential: &ResolvedCredential) -> Result<(String, Vec<String>), Denied> {
    let (token, pair) = match credential.kind.as_str() {
        "bearer" => (credential.value.clone(), format!("x-access-token:{}", credential.value)),
        "basic" if credential.value.contains(':') => {
            let token = credential.value.split_once(':').map(|(_, t)| t).unwrap_or("").to_string();
            (token, credential.value.clone())
        }
        _ => {
            return Err(Denied::new(
                DenialReason::CredentialUnavailable,
                format!(
                    "Credential {} must be kind 'bearer' (a token) or 'basic' (user:token).",
                    repr_str(&credential.name)
                ),
            ))
        }
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(pair.as_bytes());
    let secrets: Vec<String> = [credential.value.clone(), token, pair, encoded.clone()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    Ok((format!("Authorization: Basic {encoded}"), secrets))
}

/// `stderr` with only the [`PASSED_STDERR_PREFIXES`] lines left.
fn passed_stderr(stderr: &str) -> String {
    splitlines(stderr)
        .into_iter()
        .filter(|line| PASSED_STDERR_PREFIXES.iter().any(|prefix| line.starts_with(prefix)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Checks the worker repository's layout before anything reads it, and
/// returns its object store (for use as an alternate).
///
/// The worker writes this directory, and git follows what it finds there:
/// a `.git` *file* (`gitdir: /some/other/repo/.git`) or a symlinked `.git`
/// makes the fetch read a different repository, and a worker-side
/// `objects/info/alternates` makes every git step here open whatever paths
/// it lists. So `.git` must be a real directory (or the path itself a bare
/// repository), the parts git reads must not be symlinks, and the worker's
/// object store must not borrow from anywhere else. A linked worktree or a
/// submodule checkout, whose `.git` is a file, is refused: push from the
/// main checkout.
fn checked_object_dir(repo: &GitRepo) -> Result<String, Denied> {
    let refuse = |what: String| {
        Denied::new(
            DenialReason::ExecutorUnavailable,
            format!("Repository {} cannot be pushed from: {what}.", repr_str(&repo.name)),
        )
    };
    let base = std::path::Path::new(&repo.path);
    let dotgit = base.join(".git");
    let gitdir = match std::fs::symlink_metadata(&dotgit) {
        Ok(meta) if meta.file_type().is_dir() => dotgit,
        Ok(_) => return Err(refuse("its .git is not a directory (a symlink, or a worktree or submodule file)".into())),
        Err(_) => base.to_path_buf(),
    };
    for part in ["objects", "refs", "HEAD", "packed-refs", "config", "commondir", "objects/info", "objects/pack"] {
        if let Ok(meta) = std::fs::symlink_metadata(gitdir.join(part)) {
            if meta.file_type().is_symlink() {
                return Err(refuse(format!("{part} is a symlink")));
            }
        }
    }
    for part in ["commondir", "objects/info/alternates", "objects/info/http-alternates"] {
        if std::fs::symlink_metadata(gitdir.join(part)).is_ok() {
            return Err(refuse(format!("it has {part}")));
        }
    }
    let objects = gitdir.join("objects");
    match std::fs::symlink_metadata(&objects) {
        Ok(meta) if meta.file_type().is_dir() => Ok(objects.to_string_lossy().into_owned()),
        _ => Err(refuse("it is not a git repository".into())),
    }
}

/// `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`.
fn config_env(entries: &[(String, String)]) -> Vec<(String, String)> {
    let mut env = vec![("GIT_CONFIG_COUNT".to_string(), entries.len().to_string())];
    for (i, (key, value)) in entries.iter().enumerate() {
        env.push((format!("GIT_CONFIG_KEY_{i}"), key.clone()));
        env.push((format!("GIT_CONFIG_VALUE_{i}"), value.clone()));
    }
    env
}

/// Python's `_Failed`: a step that did not work, with the result of the git
/// command that failed (or a stand-in for the step that never ran).
struct Failed {
    message: String,
    result: ExecResult,
}

/// What `_push` can end in besides its summary.
enum Stop {
    Denied(Denied),
    Failed(Failed),
}

impl From<Denied> for Stop {
    fn from(denial: Denied) -> Self {
        Stop::Denied(denial)
    }
}

/// An `OSError` around the throwaway repository (a full disk, a
/// read-only `/tmp`).
// PORT NOTE: Python let these propagate out of `run()` uncaught; here they
// are a failed call naming the step.
fn os_failure(what: &str, err: &std::io::Error) -> Stop {
    Stop::Failed(Failed {
        message: format!("Could not prepare the push ({what}): {}", crate::pyfmt::os_error(err, "")),
        result: ExecResult::new(OUTCOME_FAILED, None, "", "", false, 0),
    })
}

#[cfg(test)]
tokio::task_local! {
    /// Every git argv and environment, for the test that proves the token
    /// stays out of argv (Python monkeypatched `execute.run`).
    pub(crate) static SPY: std::sync::Arc<parking_lot::Mutex<Vec<(Vec<String>, HashMap<String, String>)>>>;
}

/// One push.
///
/// `Err` only for a credential store that cannot be read or decrypted --
/// what escaped Python's `run()` as an exception.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    operation: &str,
    values: &Values,
    toolkit: &Toolkit,
    credentials: Option<&CredentialStore>,
    timeout_seconds: i64,
    max_output_bytes: i64,
    idempotent: bool,
    redact: Option<&Redact>,
) -> Result<ExecResult, ConfigError> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(timeout_seconds.max(0) as u64);
    let mut secrets: Vec<String> = Vec::new();

    let clean = |text: &str, secrets: &[String]| -> String {
        let mut sorted: Vec<&String> = secrets.iter().collect();
        sorted.sort_by_key(|s| std::cmp::Reverse(s.chars().count()));
        let mut text = text.to_string();
        for secret in sorted {
            text = text.replace(secret.as_str(), "***");
        }
        match redact {
            Some(r) => r(&text),
            None => text,
        }
    };
    let denied = |denial: Denied, secrets: &[String]| -> ExecResult {
        let mut result =
            ExecResult::new(OUTCOME_FAILED, None, "", clean(&denial.agent_message(), secrets), false, elapsed_ms(started));
        result.denial_reason = Some(denial.reason.as_str().to_string());
        result.denial_detail = Some(denial.detail);
        result
    };

    // Defensive re-checks: `operation` is fixed per tool and the values
    // were validated by `validate::build_git_call`.
    if operation != "push" || !toolkit.allows_git_operation(operation) {
        return Ok(denied(
            Denied::new(
                DenialReason::Tier1Violation,
                format!("Git operation {} is not allowed for this toolkit.", repr_str(operation)),
            ),
            &secrets,
        ));
    }
    if let Err(denial) = check_values(toolkit, values) {
        return Ok(denied(denial, &secrets));
    }
    let repo = toolkit.git_repo(&values["repo"]).expect("checked by check_values").clone();
    let branch = values["branch"].clone();

    let name = toolkit.credential.as_deref().unwrap_or("");
    let (Some(store), false) = (credentials, name.is_empty()) else {
        return Ok(denied(
            Denied::new(DenialReason::CredentialUnavailable, "This toolkit needs a push token in the credential store."),
            &secrets,
        ));
    };
    let Some(credential) = store.resolve(name)? else {
        return Ok(denied(
            Denied::new(
                DenialReason::CredentialUnavailable,
                format!("Credential {} is not configured yet.", repr_str(name)),
            ),
            &secrets,
        ));
    };
    let header = match auth_header(&credential) {
        Ok((header, all)) => {
            secrets = all;
            header
        }
        Err(denial) => return Ok(denied(denial, &secrets)),
    };

    if !std::path::Path::new(&repo.path).is_dir() {
        return Ok(denied(
            Denied::new(
                DenialReason::ExecutorUnavailable,
                format!("Repository {} does not exist at its configured path.", repr_str(&repo.name)),
            ),
            &secrets,
        ));
    }

    let git = toolkit.git_binary.clone().filter(|g| !g.is_empty()).unwrap_or_else(|| DEFAULT_GIT_BINARY.to_string());
    // `shutil.rmtree(workdir, ignore_errors=True)` is the TempDir's drop.
    let outcome = match tempfile::Builder::new().prefix("gatekeeper-git-").tempdir() {
        Ok(workdir) => {
            let push = Push {
                repo: &repo,
                branch: &branch,
                header: &header,
                workdir: workdir.path().to_string_lossy().into_owned(),
                git: &git,
                deadline,
                max_output_bytes,
                idempotent,
            };
            push.run().await
        }
        Err(err) => Err(os_failure("tempdir", &err)),
    };

    let summary = match outcome {
        Ok(summary) => summary,
        Err(Stop::Denied(denial)) => return Ok(denied(denial, &secrets)),
        Err(Stop::Failed(failure)) => {
            let result = failure.result;
            let timed_out = result.exit_code.is_none();
            let mut message = failure.message;
            // PORT NOTE (both sides): only the lines git got from the remote
            // or wrote about reaching it; see PASSED_STDERR_PREFIXES.
            let passed = passed_stderr(&result.stderr);
            let stderr = py_strip(&passed);
            if !stderr.is_empty() {
                let chars: Vec<char> = stderr.chars().collect();
                let tail: String = chars[chars.len().saturating_sub(MAX_ERROR_CHARS)..].iter().collect();
                message.push('\n');
                message.push_str(&tail);
            }
            let outcome = if timed_out { result.outcome.as_str() } else { OUTCOME_FAILED };
            return Ok(ExecResult::new(
                outcome,
                result.exit_code,
                "",
                clean(&message, &secrets),
                false,
                elapsed_ms(started),
            )
            .untrusted(true));
        }
    };

    let mut stdout = pyjson::dumps_with(&summary, &pyjson::Opts::unicode());
    let max = max_output_bytes.max(0) as usize;
    let truncated = stdout.len() > max;
    if truncated {
        stdout = String::from_utf8_lossy(&stdout.as_bytes()[..max]).into_owned();
    }
    // Commit subjects are whatever the worker wrote.
    Ok(ExecResult::new(OUTCOME_OK, Some(0), clean(&stdout, &secrets), "", truncated, elapsed_ms(started))
        .untrusted(true))
}

/// `_push`'s arguments.
struct Push<'a> {
    repo: &'a GitRepo,
    branch: &'a str,
    header: &'a str,
    workdir: String,
    git: &'a str,
    deadline: Instant,
    max_output_bytes: i64,
    idempotent: bool,
}

fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

impl Push<'_> {
    /// One git command in the throwaway repository's working directory,
    /// with a fresh environment and exactly `config` as its config.
    async fn git(
        &self,
        argv: Vec<String>,
        config: &[(String, String)],
        idempotent_step: bool,
        what: &str,
    ) -> Result<ExecResult, Stop> {
        let remaining = self.deadline.saturating_duration_since(Instant::now()).as_secs() as i64;
        if remaining <= 0 {
            return Err(Stop::Failed(Failed {
                message: format!("Timeout exceeded before {what}."),
                result: ExecResult::new(OUTCOME_FAILED, None, "", "", false, 0),
            }));
        }
        let home = format!("{}/home", self.workdir);
        let mut env: HashMap<String, String> = HashMap::new();
        for (key, value) in [
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("HOME", home.as_str()),
            ("XDG_CONFIG_HOME", home.as_str()),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", DEVNULL),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("LC_ALL", "C"),
        ] {
            env.insert(key.to_string(), value.to_string());
        }
        env.extend(config_env(config));
        let mut full = vec![self.git.to_string()];
        full.extend(argv);
        #[cfg(test)]
        let _ = SPY.try_with(|spy| spy.lock().push((full.clone(), env.clone())));
        let result = super::local::run(
            &full,
            remaining,
            self.max_output_bytes.max(1 << 16),
            idempotent_step,
            Some(&self.workdir),
            Some(&env),
        )
        .await?;
        if result.outcome != OUTCOME_OK {
            let mut result = result;
            // Only the steps that carry the token talk to the remote. A
            // local step's stderr is about local files, so none of it is
            // kept -- not even as `remote: ` lines, which is how
            // upload-pack's own errors from the worker's side arrive --
            // except the one line the fetch's caller looks for.
            let talks_to_remote = config.iter().any(|(key, _)| key.ends_with(".extraHeader"));
            if !talks_to_remote {
                result.stderr = splitlines(&result.stderr)
                    .into_iter()
                    .filter(|line| line.starts_with("fatal: couldn't find remote ref "))
                    .collect::<Vec<_>>()
                    .join("\n");
            }
            return Err(Stop::Failed(Failed { message: format!("git {what} failed."), result }));
        }
        Ok(result)
    }

    async fn run(&self) -> Result<Value, Stop> {
        let repo = self.repo;
        let branch = self.branch;
        let bare = format!("{}/push.git", self.workdir);
        let home = format!("{}/home", self.workdir);
        std::fs::create_dir(&home).map_err(|e| os_failure("home", &e))?;
        let reference = format!("refs/heads/{branch}");
        let refspec = format!("{reference}:{reference}");

        let hardening = pairs(&[
            ("core.hooksPath", DEVNULL),
            ("core.fsmonitor", "false"),
            ("credential.helper", ""),
            ("core.askPass", ""),
            ("http.followRedirects", "false"),
            ("protocol.allow", "never"),
            ("safe.directory", &repo.path),
            ("safe.directory", &format!("{}/.git", repo.path.trim_end_matches('/'))),
        ]);
        let scheme = repo.remote.split(':').next().unwrap_or("");
        let mut remote_config = hardening.clone();
        remote_config.push((format!("protocol.{scheme}.allow"), "always".to_string()));
        remote_config.push((format!("http.{}.extraHeader", repo.remote), self.header.to_string()));

        let gd = format!("--git-dir={bare}");
        let objects = checked_object_dir(repo)?;
        self.git(args(&["init", "--bare", "--quiet", "--template=", &bare]), &hardening, true, "init").await?;
        let info = format!("{bare}/objects/info");
        std::fs::create_dir_all(&info).map_err(|e| os_failure("objects/info", &e))?;
        std::fs::write(format!("{info}/alternates"), format!("{}\n", crate::pathutil::abspath(&objects)))
            .map_err(|e| os_failure("alternates", &e))?;

        let mut fetch_config = hardening.clone();
        fetch_config.push(("protocol.file.allow".to_string(), "always".to_string()));
        let fetched = self
            .git(
                args(&[
                    &gd,
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--no-recurse-submodules",
                    "--no-write-fetch-head",
                    &repo.path,
                    &refspec,
                ]),
                &fetch_config,
                true,
                "reading the branch from the repository",
            )
            .await;
        if let Err(Stop::Failed(failure)) = &fetched {
            if failure.result.stderr.contains("couldn't find remote ref") {
                return Err(Stop::Denied(Denied::new(
                    DenialReason::ParamInvalid,
                    format!(
                        "Branch {} does not exist in repository {}.",
                        repr_str(branch),
                        repr_str(&repo.name)
                    ),
                )));
            }
        }
        fetched?;
        let new = py_strip(
            &self
                .git(args(&[&gd, "rev-parse", "--verify", &format!("{reference}^{{commit}}")]), &hardening, true, "rev-parse")
                .await?
                .stdout,
        )
        .to_string();

        let listed = self
            .git(
                args(&[&gd, "ls-remote", "--heads", &repo.remote]),
                &remote_config,
                true,
                &format!("ls-remote against {}", repo.remote),
            )
            .await?;
        let mut heads: IndexMap<String, String> = IndexMap::new();
        for line in splitlines(&listed.stdout) {
            let (sha, name) = line.split_once('\t').unwrap_or((line, ""));
            if is_sha(sha) && name.starts_with("refs/heads/") {
                heads.insert(name.to_string(), sha.to_string());
            }
        }
        let old = heads.get(&reference).cloned();

        let mut summary = Map::new();
        summary.insert("repo".into(), json!(repo.name));
        summary.insert("branch".into(), json!(branch));
        summary.insert("remote".into(), json!(repo.remote));
        summary.insert("old".into(), json!(old));
        summary.insert("new".into(), json!(new));
        if old.as_deref() == Some(new.as_str()) {
            summary.insert("status".into(), json!("up_to_date"));
            summary.insert("commits".into(), json!([]));
            summary.insert("commits_total".into(), json!(0));
            summary.insert("commits_truncated".into(), json!(false));
            return Ok(Value::Object(summary));
        }

        // What goes over: everything reachable from `new` that the remote
        // already has is excluded -- its old tip for an update, every head
        // it has (as far as those objects exist here) for a new branch.
        let exclude: Vec<String> = match old.as_deref() {
            Some(o) if !o.is_empty() => vec![o.to_string()],
            _ => heads.values().take(MAX_EXCLUDED_HEADS).cloned().collect(),
        };
        let mut not_args: Vec<String> = Vec::new();
        if !exclude.is_empty() {
            not_args.push("--not".to_string());
            not_args.extend(exclude);
        }
        let mut count_args = args(&[&gd, "rev-list", "--count", "--ignore-missing", &new]);
        count_args.extend(not_args.iter().cloned());
        let count = self.git(count_args, &hardening, true, "rev-list").await?;
        let max_count = format!("--max-count={MAX_COMMITS}");
        let mut log_args = args(&[
            &gd,
            "log",
            "--no-decorate",
            "--no-show-signature",
            &max_count,
            "--format=%h %s",
            "--ignore-missing",
            &new,
        ]);
        log_args.extend(not_args.iter().cloned());
        let log = self.git(log_args, &hardening, true, "log").await?;
        let commits: Vec<String> = splitlines(&log.stdout)
            .into_iter()
            .filter(|line| !line.is_empty())
            .map(|line| line.chars().take(MAX_SUBJECT_CHARS).collect())
            .collect();
        // PORT NOTE: Python's `int(...)` raised ValueError on output that is
        // not a number (which `rev-list --count` never prints); 0 here.
        let count_text = py_strip(&count.stdout);
        let total: i64 = if count_text.is_empty() { 0 } else { count_text.parse().unwrap_or(0) };

        let pushed = self
            .git(
                args(&[&gd, "push", "--porcelain", "--no-verify", &repo.remote, &refspec]),
                &remote_config,
                self.idempotent,
                &format!("push to {}", repo.remote),
            )
            .await;
        let pushed = match pushed {
            Ok(pushed) => pushed,
            Err(Stop::Failed(failure)) => {
                let result = failure.result;
                let porcelain = result.stdout.clone();
                if porcelain.contains("[rejected]") || porcelain.contains("[remote rejected]") {
                    let line = splitlines(&porcelain).into_iter().find(|ln| ln.contains("rejected]")).unwrap_or("");
                    let reason = if line.is_empty() {
                        "rejected".to_string()
                    } else {
                        py_strip(line.rsplit('\t').next().unwrap_or("")).to_string()
                    };
                    return Err(Stop::Failed(Failed {
                        message: format!(
                            "The remote refused the push of {}: {reason}. Only fast-forward pushes are possible; \
                             integrate the remote branch in the repository first.",
                            repr_str(branch)
                        ),
                        result,
                    }));
                }
                if result.outcome == OUTCOME_UNKNOWN {
                    return Err(Stop::Failed(Failed {
                        message: "The outcome is UNKNOWN: the push may have reached the remote. Call again -- an \
                                  already-pushed branch comes back as up_to_date."
                            .to_string(),
                        result,
                    }));
                }
                return Err(Stop::Failed(Failed { message: failure.message, result }));
            }
            Err(other) => return Err(other),
        };
        let mut status = if old.is_none() { "created" } else { "updated" };
        for line in splitlines(&pushed.stdout) {
            if line.starts_with("=\t") {
                status = "up_to_date";
            }
        }
        let commits_truncated = total > commits.len() as i64;
        summary.insert("status".into(), json!(status));
        summary.insert("commits".into(), json!(commits));
        summary.insert("commits_total".into(), json!(total));
        summary.insert("commits_truncated".into(), json!(commits_truncated));
        Ok(Value::Object(summary))
    }
}

/// For /health/ready: git is there and runnable. Nothing is sent to the
/// remote -- a liveness question does not put the token on the wire.
pub async fn probe(toolkit: &Toolkit) -> bool {
    is_runnable(toolkit.git_binary.as_deref().filter(|g| !g.is_empty()).unwrap_or(DEFAULT_GIT_BINARY))
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;
