//! Tests for the `git` executor (port of `tests/test_execute_git.py`).
//!
//! Against real git on both ends: a worker checkout on disk, and a bare
//! repository served over git's smart HTTP protocol by `git http-backend`
//! behind a loopback HTTP server that insists on the token -- not a mocked
//! subprocess. What matters is what reaches the remote (only fast-forwards
//! of `feat/*`, nothing forced, nothing deleted), that the worker's own
//! hooks and config never run or redirect anything, and that the token is
//! nowhere but the Authorization header.
//!
//! The tests that need git skip (return early, with a note on stderr) when
//! git or `git-http-backend` is missing, as the Python module does.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::credentials::tests::env;
use crate::errors::ConfigResult;
use crate::tier1::{load_tier1, Tier1};

const TOKEN: &str = "ghp_test-push-token-0123456789";

fn encoded() -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{TOKEN}"))
}

/// `shutil.which("git")` and its `git-http-backend`, or `None` (skip).
fn tools() -> Option<(String, String)> {
    let path = std::env::var("PATH").unwrap_or_default();
    let git = path.split(':').map(|d| format!("{d}/git")).find(|p| is_runnable(p))?;
    let out = std::process::Command::new(&git).arg("--exec-path").output().ok()?;
    let backend = format!("{}/git-http-backend", String::from_utf8_lossy(&out.stdout).trim());
    Path::new(&backend).exists().then_some((git, backend))
}

macro_rules! need_git {
    () => {
        match tools() {
            Some(t) => t,
            None => {
                eprintln!("skipped: needs git and git-http-backend");
                return;
            }
        }
    };
}

/// The git binary for a toolkit, whether or not one exists here (Tier 1
/// checks the shape of the path only).
fn git_binary() -> String {
    tools().map(|(g, _)| g).unwrap_or_else(|| DEFAULT_GIT_BINARY.to_string())
}

/// `_git`: a setup command, with no system/global config and a fixed
/// author.
fn sh_git(args: &[&str], cwd: Option<&Path>, check: bool) -> String {
    let mut command = std::process::Command::new(git_binary());
    command
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "w")
        .env("GIT_AUTHOR_EMAIL", "w@x")
        .env("GIT_COMMITTER_NAME", "w")
        .env("GIT_COMMITTER_EMAIL", "w@x");
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let out = command.output().unwrap();
    if check {
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[derive(Default)]
struct ServerState {
    expected_auth: Option<String>,
    requests: Vec<(String, String, Option<String>)>,
}

/// Smart HTTP in front of a directory of bare repositories, via
/// `git http-backend` as a CGI. Every request is recorded; one without the
/// expected Authorization header gets a 401.
struct GitServer {
    root: PathBuf,
    port: u16,
    state: Arc<Mutex<ServerState>>,
}

impl GitServer {
    async fn start(root: &Path, backend: &str, expected_auth: Option<String>) -> GitServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(ServerState { expected_auth, requests: Vec::new() }));
        let (s2, root2, backend) = (state.clone(), root.to_path_buf(), backend.to_string());
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                tokio::spawn(serve(stream, s2.clone(), root2.clone(), backend.clone()));
            }
        });
        GitServer { root: root.to_path_buf(), port, state }
    }

    fn url(&self, name: &str) -> String {
        format!("http://127.0.0.1:{}/{name}.git", self.port)
    }

    fn requests(&self) -> Vec<(String, String, Option<String>)> {
        self.state.lock().requests.clone()
    }

    fn set_expected_auth(&self, auth: &str) {
        self.state.lock().expected_auth = Some(auth.to_string());
    }

    fn reference(&self, name: &str, reference: &str) -> Option<String> {
        let dir = self.root.join(format!("{name}.git"));
        let out =
            sh_git(&["--git-dir", dir.to_str().unwrap(), "rev-parse", "--verify", "--quiet", reference], None, false);
        (!out.is_empty()).then_some(out)
    }
}

/// One HTTP/1.0 exchange (as Python's `BaseHTTPRequestHandler`).
async fn serve(mut stream: tokio::net::TcpStream, state: Arc<Mutex<ServerState>>, root: PathBuf, backend: String) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut body = buf[head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let length: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    while body.len() < length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length);

    let auth = header("authorization");
    let expected = {
        let mut s = state.lock();
        s.requests.push((method.clone(), target.clone(), auth.clone()));
        s.expected_auth.clone()
    };
    if expected.is_some() && auth != expected {
        let _ = stream
            .write_all(b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        return;
    }
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let mut command = tokio::process::Command::new(&backend);
    command
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()))
        .env("GIT_PROJECT_ROOT", &root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("PATH_INFO", path)
        .env("QUERY_STRING", query)
        .env("REQUEST_METHOD", &method)
        .env("CONTENT_TYPE", header("content-type").unwrap_or_default())
        .env("CONTENT_LENGTH", body.len().to_string())
        .env("REMOTE_USER", "x-access-token")
        .env("REMOTE_ADDR", "127.0.0.1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    if let Some(enc) = header("content-encoding") {
        command.env("HTTP_CONTENT_ENCODING", enc);
    }
    if let Some(proto) = header("git-protocol") {
        command.env("GIT_PROTOCOL", proto);
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&body).await;
    });
    let out = child.wait_with_output().await.unwrap().stdout;
    let _ = writer.await;
    let split = out.windows(4).position(|w| w == b"\r\n\r\n");
    let (cgi_head, payload) = match split {
        Some(i) => (String::from_utf8_lossy(&out[..i]).into_owned(), out[i + 4..].to_vec()),
        None => (String::from_utf8_lossy(&out).into_owned(), Vec::new()),
    };
    let mut status = 200;
    let mut response_headers = Vec::new();
    for line in cgi_head.split("\r\n") {
        let (key, value) = line.split_once(':').unwrap_or((line, ""));
        if key.eq_ignore_ascii_case("status") {
            status = value.trim().split(' ').next().unwrap_or("200").parse().unwrap_or(200);
        } else if !key.is_empty() {
            response_headers.push((key.to_string(), value.trim().to_string()));
        }
    }
    let mut response = format!("HTTP/1.0 {status} X\r\n");
    for (k, v) in response_headers {
        response.push_str(&format!("{k}: {v}\r\n"));
    }
    response.push_str(&format!("Content-Length: {}\r\n\r\n", payload.len()));
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(&payload).await;
    let _ = stream.shutdown().await;
}

/// The `remote` fixture: a bare `proj.git` that accepts pushes, behind a
/// server that wants the token.
async fn remote(dir: &Path, backend: &str) -> GitServer {
    let root = dir.join("remote");
    std::fs::create_dir_all(&root).unwrap();
    let bare = root.join("proj.git");
    sh_git(&["init", "--bare", "--quiet", "-b", "main", bare.to_str().unwrap()], None, true);
    sh_git(&["--git-dir", bare.to_str().unwrap(), "config", "http.receivepack", "true"], None, true);
    GitServer::start(&root, backend, Some(format!("Basic {}", encoded()))).await
}

/// The `worker` fixture: the checkout a worker commits into, with `main`
/// already on the remote.
fn worker(dir: &Path, remote: &GitServer) -> PathBuf {
    let path = dir.join("work").join("proj");
    std::fs::create_dir_all(&path).unwrap();
    sh_git(&["init", "--quiet", "-b", "main"], Some(&path), true);
    std::fs::write(path.join("README"), "hello\n").unwrap();
    sh_git(&["add", "README"], Some(&path), true);
    sh_git(&["commit", "--quiet", "-m", "initial"], Some(&path), true);
    let bare = remote.root.join("proj.git");
    sh_git(&["push", "--quiet", bare.to_str().unwrap(), "main:refs/heads/main"], Some(&path), true);
    path
}

fn commit(path: &Path, name: &str) -> String {
    std::fs::write(path.join(name), "x").unwrap();
    sh_git(&["add", name], Some(path), true);
    sh_git(&["commit", "--quiet", "-m", &format!("add {name}")], Some(path), true);
    sh_git(&["rev-parse", "HEAD"], Some(path), true)
}

fn try_tier1(dir: &Path, repos: Value, overrides: Value) -> ConfigResult<Tier1> {
    let mut spec = json!({
        "executor": "git", "credential": "github", "allowed_git_operations": ["push"],
        "git_binary": git_binary(), "repos": repos, "max_timeout_seconds": 60,
    });
    for (k, v) in overrides.as_object().unwrap() {
        if v.is_null() {
            spec.as_object_mut().unwrap().remove(k);
        } else {
            spec[k] = v.clone();
        }
    }
    let doc = json!({"toolkits": {"gkrepo": spec}, "audit": {"dir": dir.join("logs").to_str().unwrap()}});
    let path = dir.join("toolkits.yaml");
    std::fs::write(&path, crate::yaml::dump(&doc)).unwrap();
    load_tier1(path.to_str().unwrap())
}

fn toolkit(dir: &Path, worker: &Path, remote: &GitServer, overrides: Value) -> Toolkit {
    let repos = json!({"proj": {"path": worker.to_str().unwrap(), "remote": remote.url("proj")}});
    try_tier1(dir, repos, overrides).unwrap().toolkit("gkrepo").unwrap().clone()
}

fn create_token(store: &CredentialStore) {
    store.create("github", "bearer", TOKEN, None, None, None, "test", "").unwrap();
}

fn vals(repo: &str, branch: &str) -> Values {
    [("repo".to_string(), repo.to_string()), ("branch".to_string(), branch.to_string())].into_iter().collect()
}

async fn push(toolkit: &Toolkit, store: &CredentialStore, branch: &str, repo: &str) -> ExecResult {
    run("push", &vals(repo, branch), toolkit, Some(store), 30, 65536, true, None).await.unwrap()
}

fn payload(result: &ExecResult) -> Value {
    serde_json::from_str(&result.stdout).unwrap_or_else(|e| panic!("{e}: {} / {}", result.stdout, result.stderr))
}

// -- Pushing ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn new_branch_is_created_with_its_commits() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    sh_git(&["checkout", "--quiet", "-b", "feat/one"], Some(&worker), true);
    commit(&worker, "a.txt");
    let head = commit(&worker, "b.txt");
    let result = push(&toolkit(dir, &worker, &remote, json!({})), &e.store, "feat/one", "proj").await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    assert!(result.external_untrusted);
    let p = payload(&result);
    let keys: Vec<&String> = p.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["repo", "branch", "remote", "old", "new", "status", "commits", "commits_total", "commits_truncated"]);
    assert_eq!(p["status"], "created");
    assert!(p["old"].is_null());
    assert_eq!(p["new"], head.as_str());
    assert_eq!(p["commits_total"], 2);
    assert_eq!(p["commits_truncated"], false);
    let subjects: Vec<&str> =
        p["commits"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().split_once(' ').unwrap().1).collect();
    assert_eq!(subjects, ["add b.txt", "add a.txt"]);
    assert_eq!(remote.reference("proj", "refs/heads/feat/one"), Some(head));
    assert!(!result.stdout.contains(TOKEN) && !result.stdout.contains(&encoded()));
    // Every request to the remote carried the token, and only as the header.
    let requests = remote.requests();
    let want = format!("Basic {}", encoded());
    assert!(!requests.is_empty() && requests.iter().all(|(_, _, auth)| auth.as_deref() == Some(want.as_str())));
    assert!(requests.iter().all(|(_, path, _)| !path.contains(TOKEN)));
}

#[tokio::test(flavor = "multi_thread")]
async fn update_is_a_fast_forward_listing_only_new_commits() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let tk = toolkit(dir, &worker, &remote, json!({}));
    sh_git(&["checkout", "--quiet", "-b", "feat/two"], Some(&worker), true);
    let first = commit(&worker, "a.txt");
    assert_eq!(push(&tk, &e.store, "feat/two", "proj").await.outcome, OUTCOME_OK);
    let second = commit(&worker, "b.txt");
    let p = payload(&push(&tk, &e.store, "feat/two", "proj").await);
    assert_eq!(p["status"], "updated");
    assert_eq!((p["old"].as_str().unwrap(), p["new"].as_str().unwrap()), (first.as_str(), second.as_str()));
    assert_eq!(p["commits_total"], 1);
    assert!(p["commits"][0].as_str().unwrap().ends_with("add b.txt"));
    let again = payload(&push(&tk, &e.store, "feat/two", "proj").await);
    assert_eq!(again["status"], "up_to_date");
    assert_eq!(again["commits"], json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn non_fast_forward_is_rejected_not_forced() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let tk = toolkit(dir, &worker, &remote, json!({}));
    sh_git(&["checkout", "--quiet", "-b", "feat/three"], Some(&worker), true);
    commit(&worker, "a.txt");
    commit(&worker, "b.txt");
    assert_eq!(push(&tk, &e.store, "feat/three", "proj").await.outcome, OUTCOME_OK);
    let on_remote = remote.reference("proj", "refs/heads/feat/three");
    sh_git(&["reset", "--quiet", "--hard", "HEAD~1"], Some(&worker), true);
    commit(&worker, "c.txt");
    let result = push(&tk, &e.store, "feat/three", "proj").await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert!(result.stderr.contains("fast-forward"), "{}", result.stderr);
    assert!(result.stderr.starts_with("The remote refused the push of 'feat/three': "), "{}", result.stderr);
    assert!(result.external_untrusted);
    assert_eq!(remote.reference("proj", "refs/heads/feat/three"), on_remote);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_plain_feat_branches_are_accepted() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let tk = toolkit(dir, &worker, &remote, json!({}));
    let long = format!("feat/{}", "a".repeat(200));
    for branch in [
        "main",
        "feat",
        "feat/",
        "feature/x",
        "refs/heads/feat/x",
        "feat/../main",
        "feat/x.lock",
        "feat/-x",
        "feat/.x",
        "feat//x",
        "feat/x/",
        "feat/x y",
        "feat/x:main",
        "+feat/x",
        "feat/x~1",
        long.as_str(),
        // PORT NOTE: refused here, passed Python's `$` (see is_branch_component).
        "feat/x\n",
    ] {
        let result = push(&tk, &e.store, branch, "proj").await;
        assert_eq!(result.outcome, OUTCOME_FAILED, "{branch:?}");
        assert_eq!(result.denial_reason.as_deref(), Some("param_invalid"), "{branch:?}");
    }
    assert!(remote.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_repo_is_refused_before_git_runs() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let result = push(&toolkit(dir, &worker, &remote, json!({})), &e.store, "feat/x", "other").await;
    assert_eq!(result.denial_reason.as_deref(), Some("tier1_violation"));
    assert_eq!(result.stderr, "Repository 'other' is not one this toolkit may push from (allowed: ['proj']).");
    assert!(remote.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_branch_is_a_denial_without_touching_the_remote() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let result = push(&toolkit(dir, &worker, &remote, json!({})), &e.store, "feat/nope", "proj").await;
    assert_eq!(result.denial_reason.as_deref(), Some("param_invalid"));
    assert_eq!(result.stderr, "Branch 'feat/nope' does not exist in repository 'proj'.");
    assert!(remote.requests().is_empty());
}

/// Whoever writes the checkout writes its .git/config and hooks too.
#[tokio::test(flavor = "multi_thread")]
async fn the_worker_repository_config_and_hooks_never_run() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let marker = dir.join("pwned");
    let script = dir.join("evil.sh");
    let text = format!("#!/bin/sh\ntouch {}\ncat >/dev/null\nexit 0\n", marker.display());
    let executable = |p: &Path| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    std::fs::write(&script, &text).unwrap();
    executable(&script);
    let evil = GitServer::start(&dir.join("remote"), &backend, None).await;
    let hooks = worker.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    for hook in ["pre-push", "reference-transaction", "post-checkout"] {
        std::fs::write(hooks.join(hook), &text).unwrap();
        executable(&hooks.join(hook));
    }
    let script_s = script.to_str().unwrap();
    let w = Some(worker.as_path());
    sh_git(
        &[
            "config",
            &format!("url.http://127.0.0.1:{}/.insteadOf", evil.port),
            &format!("http://127.0.0.1:{}/", remote.port),
        ],
        w,
        true,
    );
    sh_git(&["config", "credential.helper", &format!("!{script_s}")], w, true);
    sh_git(&["config", "core.fsmonitor", script_s], w, true);
    sh_git(&["config", "core.sshCommand", script_s], w, true);
    sh_git(&["config", "http.proxy", &format!("http://127.0.0.1:{}", evil.port)], w, true);
    sh_git(&["checkout", "--quiet", "-b", "feat/evil"], w, true);
    let head = commit(&worker, "a.txt");
    let _ = std::fs::remove_file(&marker); // the commit above ran the worker's hooks itself

    let result = push(&toolkit(dir, &worker, &remote, json!({})), &e.store, "feat/evil", "proj").await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    assert_eq!(remote.reference("proj", "refs/heads/feat/evil"), Some(head));
    assert!(evil.requests().is_empty());
    assert!(!marker.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_token_is_never_in_argv() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    sh_git(&["checkout", "--quiet", "-b", "feat/argv"], Some(&worker), true);
    commit(&worker, "a.txt");
    let tk = toolkit(dir, &worker, &remote, json!({}));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let result = SPY.scope(seen.clone(), push(&tk, &e.store, "feat/argv", "proj")).await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    let seen = seen.lock().clone();
    let joined: String = seen.iter().map(|(argv, _)| argv.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(!joined.contains(TOKEN) && !joined.contains(&encoded()));
    assert!(!joined.contains("--force") && !joined.contains("--delete") && !joined.contains(":refs/heads/main"));
    assert!(!joined.contains("+refs/"));
    let mut with_token: Vec<&str> = seen
        .iter()
        .filter(|(_, env)| env.values().any(|v| v.contains(&encoded())))
        .map(|(argv, _)| argv[2].as_str())
        .collect();
    with_token.sort();
    with_token.dedup();
    // Only the two steps that talk to the remote get the header.
    assert_eq!(with_token, ["ls-remote", "push"]);
    // Every git child gets a fresh environment and the hardening config.
    for (argv, env) in &seen {
        assert_eq!(env.get("GIT_CONFIG_NOSYSTEM").map(String::as_str), Some("1"), "{argv:?}");
        assert_eq!(env.get("GIT_CONFIG_GLOBAL").map(String::as_str), Some("/dev/null"));
        assert_eq!(env.get("GIT_TERMINAL_PROMPT").map(String::as_str), Some("0"));
        assert!(!env.contains_key("HTTPS_PROXY") && !env.contains_key("https_proxy"));
        assert_eq!(env.get("GIT_CONFIG_KEY_0").map(String::as_str), Some("core.hooksPath"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_token_fails_without_echoing_it() {
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    remote.set_expected_auth("Basic something-else");
    sh_git(&["checkout", "--quiet", "-b", "feat/auth"], Some(&worker), true);
    commit(&worker, "a.txt");
    let result = push(&toolkit(dir, &worker, &remote, json!({})), &e.store, "feat/auth", "proj").await;
    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert!(!result.stderr.contains(TOKEN) && !result.stderr.contains(&encoded()));
    assert!(result.stderr.starts_with("git ls-remote against "), "{}", result.stderr);
    assert_eq!(remote.reference("proj", "refs/heads/feat/auth"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_basic_credential_pushes_as_user_and_token() {
    let (_, backend) = need_git!();
    let e = env();
    e.store.create("github", "basic", &format!("bot:{TOKEN}"), None, None, None, "test", "").unwrap();
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("bot:{TOKEN}"));
    remote.set_expected_auth(&format!("Basic {basic}"));
    sh_git(&["checkout", "--quiet", "-b", "feat/basic"], Some(&worker), true);
    let head = commit(&worker, "a.txt");
    let result = push(&toolkit(dir, &worker, &remote, json!({})), &e.store, "feat/basic", "proj").await;
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    assert_eq!(remote.reference("proj", "refs/heads/feat/basic"), Some(head));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_token_credential_is_refused() {
    let (_, backend) = need_git!();
    let e = env();
    e.store.create("github", "api_key_header", TOKEN, Some("X-Key"), None, None, "t", "").unwrap();
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let result = push(&toolkit(dir, &worker, &remote, json!({})), &e.store, "feat/x", "proj").await;
    assert_eq!(result.denial_reason.as_deref(), Some("credential_unavailable"));
    assert_eq!(result.stderr, "Credential 'github' must be kind 'bearer' (a token) or 'basic' (user:token).");
    assert!(remote.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_credential_and_missing_path_are_refused() {
    let (_, backend) = need_git!();
    let e = env();
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let tk = toolkit(dir, &worker, &remote, json!({}));
    let result = push(&tk, &e.store, "feat/x", "proj").await;
    assert_eq!(result.denial_reason.as_deref(), Some("credential_unavailable"));
    assert_eq!(result.stderr, "Credential 'github' is not configured yet.");
    let result = run("push", &vals("proj", "feat/x"), &tk, None, 30, 65536, true, None).await.unwrap();
    assert_eq!(result.stderr, "This toolkit needs a push token in the credential store.");
    create_token(&e.store);
    let gone = Toolkit {
        git_repos: vec![GitRepo {
            name: "proj".into(),
            path: dir.join("nope").to_str().unwrap().into(),
            remote: remote.url("proj"),
        }],
        ..tk.clone()
    };
    let result = push(&gone, &e.store, "feat/x", "proj").await;
    assert_eq!(result.denial_reason.as_deref(), Some("executor_unavailable"));
    assert_eq!(result.stderr, "Repository 'proj' does not exist at its configured path.");
    let other = run("force_push", &vals("proj", "feat/x"), &tk, Some(&e.store), 30, 65536, true, None).await.unwrap();
    assert_eq!(other.denial_reason.as_deref(), Some("tier1_violation"));
    assert_eq!(other.stderr, "Git operation 'force_push' is not allowed for this toolkit.");
    assert!(remote.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_checks_the_binary_only() {
    let (_, backend) = need_git!();
    let e = env();
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    assert!(probe(&toolkit(dir, &worker, &remote, json!({}))).await);
    assert!(!probe(&toolkit(dir, &worker, &remote, json!({"git_binary": "/nonexistent/git"}))).await);
    assert!(remote.requests().is_empty());
}

// -- The executor's own floor ------------------------------------------------

#[test]
fn check_values_messages_match_python() {
    let tk = Toolkit {
        git_repos: vec![
            GitRepo { name: "a".into(), path: "/srv/a".into(), remote: "https://x.org/a.git".into() },
            GitRepo { name: "b".into(), path: "/srv/b".into(), remote: "https://x.org/b.git".into() },
        ],
        ..Toolkit::default()
    };
    let err = |repo: &str, branch: &str| check_values(&tk, &vals(repo, branch)).unwrap_err();
    let d = err("c", "feat/x");
    assert_eq!(d.reason, DenialReason::Tier1Violation);
    assert_eq!(d.detail, "Repository 'c' is not one this toolkit may push from (allowed: ['a', 'b']).");
    let d = err("a", "main");
    assert_eq!(d.reason, DenialReason::ParamInvalid);
    assert_eq!(d.detail, "Parameter 'branch' must start with 'feat/'; nothing else can be pushed.");
    assert_eq!(
        err("a", "feat/x..y").detail,
        "Parameter 'branch' must be feat/<name>, with letters, digits, '.', '_', '-' and '/' between parts, at \
         most 200 characters."
    );
    assert!(check_values(&tk, &vals("a", "feat/x")).is_ok());
    assert!(check_values(&tk, &vals("b", "feat/a_b/c-d.e/9")).is_ok());
    assert!(check_values(&tk, &vals("b", &format!("feat/{}", "a".repeat(195)))).is_ok());
    assert!(check_values(&tk, &vals("b", "feat/x.")).is_err());
    assert!(check_values(&tk, &vals("b", "feat/x.lock/y")).is_err());
    assert!(check_values(&tk, &vals("b", "feat/\u{e9}")).is_err());
    assert!(check_values(&tk, &IndexMap::new()).is_err());
}

#[test]
fn auth_header_and_secrets() {
    let cred = |kind: &str, value: &str| ResolvedCredential {
        name: "github".into(),
        kind: kind.into(),
        header: None,
        value: value.into(),
        previous_value: None,
        header_format: None,
    };
    let (header, secrets) = auth_header(&cred("bearer", TOKEN)).unwrap();
    assert_eq!(header, format!("Authorization: Basic {}", encoded()));
    assert_eq!(secrets, [TOKEN.to_string(), TOKEN.to_string(), format!("x-access-token:{TOKEN}"), encoded()]);
    let (_, secrets) = auth_header(&cred("basic", "u:t:x")).unwrap();
    assert_eq!(secrets[1], "t:x");
    assert!(auth_header(&cred("basic", "no-colon")).is_err());
    assert!(auth_header(&cred("api_key_header", TOKEN)).is_err());
    assert!(is_sha(&"a".repeat(40)) && is_sha(&"0".repeat(64)) && !is_sha(&"A".repeat(40)) && !is_sha("abc"));
}

// -- Tier 1 -------------------------------------------------------------------

fn plain_repos() -> Value {
    json!({"p": {"path": "/srv/p", "remote": "https://github.com/a/b.git"}})
}

#[test]
fn tier1_refuses_an_incomplete_git_toolkit() {
    let repo = |path: &str, remote: &str| json!({"p": {"path": path, "remote": remote}});
    let cases = [
        (plain_repos(), json!({"credential": null}), "needs 'credential'"),
        (plain_repos(), json!({"allowed_git_operations": ["force_push"]}), "unknown: ['force_push']"),
        (plain_repos(), json!({"allowed_git_operations": []}), "non-empty subset"),
        (plain_repos(), json!({"git_binary": "git"}), "absolute path"),
        (json!({}), json!({}), "non-empty mapping"),
        (repo("relative", "https://github.com/a/b.git"), json!({}), "absolute"),
        (repo("/srv/../etc", "https://github.com/a/b.git"), json!({}), "'..'"),
        (repo("/srv/p", "http://github.com/a/b.git"), json!({}), "https"),
        (repo("/srv/p", "ssh://git@github.com/a/b.git"), json!({}), "https"),
        (repo("/srv/p", "file:///srv/x"), json!({}), "https"),
        (repo("/srv/p", "https://u:t@github.com/a/b.git"), json!({}), "no user"),
        (repo("/srv/p", "https://github.com/a/b.git?x=1"), json!({}), "query"),
        (
            json!({"p": {"path": "/srv/p", "remote": "https://github.com/a/b.git", "push": "x"}}),
            json!({}),
            "unknown fields",
        ),
        (json!({"bad name": {"path": "/srv/p", "remote": "https://github.com/a/b.git"}}), json!({}), "repo name"),
        // PORT NOTE: Python's `$` let a trailing newline through here.
        (json!({"p\n": {"path": "/srv/p", "remote": "https://github.com/a/b.git"}}), json!({}), "repo name"),
    ];
    let e = env();
    for (repos, overrides, fragment) in cases {
        let err = try_tier1(e.dir.path(), repos.clone(), overrides).unwrap_err();
        assert!(err.message.contains(fragment), "{repos}: {fragment}: {}", err.message);
    }
    let err = try_tier1(e.dir.path(), plain_repos(), json!({"allowed_git_operations": ["force_push"]})).unwrap_err();
    assert_eq!(
        err.message,
        "toolkit 'gkrepo': allowed_git_operations must be a non-empty subset of ['push'] (unknown: ['force_push'])"
    );
}

#[test]
fn tier1_takes_https_and_loopback_http() {
    let e = env();
    let t = try_tier1(
        e.dir.path(),
        json!({
            "a": {"path": "/srv/a", "remote": "https://github.com/davidsteg/gatekeeper.git"},
            "b": {"path": "/srv/b", "remote": "http://127.0.0.1:9418/b.git"},
        }),
        json!({}),
    )
    .unwrap();
    let tk = t.toolkit("gkrepo").unwrap();
    let names: Vec<&str> = tk.git_repos.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(tk.git_repo("a").unwrap().remote, "https://github.com/davidsteg/gatekeeper.git");
    assert_eq!(tk.git_binary.as_deref(), Some(git_binary().as_str()));
    // Without `git_binary`, the default.
    let t = try_tier1(e.dir.path(), plain_repos(), json!({"git_binary": null})).unwrap();
    assert_eq!(t.toolkit("gkrepo").unwrap().git_binary.as_deref(), Some(DEFAULT_GIT_BINARY));
}

// -- Catalog ------------------------------------------------------------------

fn params() -> Value {
    json!({
        "repo": {"type": "enum", "required": true, "values": ["p"], "description": "repo"},
        "branch": {"type": "string", "required": true, "pattern": "^feat/[A-Za-z0-9._/-]{1,100}$",
                   "description": "branch"},
    })
}

fn tool_specs(change: Value) -> Vec<Value> {
    let mut spec = json!({"id": "gkrepo.push", "toolkit": "gkrepo", "version": 1, "enabled": true,
        "required_scopes": [], "timeout_seconds": 60, "max_output_bytes": 16384,
        "description": "push", "title": "Push", "category": "write", "idempotent": true,
        "git_operation": "push", "parameters": params()});
    for (k, v) in change.as_object().unwrap() {
        spec[k] = v.clone();
    }
    vec![spec]
}

fn make_catalog(dir: &Path, tier1: &Tier1, tools: &[Value]) -> ConfigResult<crate::catalog::Catalog> {
    let path = dir.join("tools.yaml");
    std::fs::write(&path, crate::yaml::dump(&json!({ "tools": tools }))).unwrap();
    crate::catalog::load_catalog(path.to_str().unwrap(), tier1, true)
}

#[test]
fn example_tool_loads() {
    let e = env();
    let t = try_tier1(e.dir.path(), plain_repos(), json!({})).unwrap();
    let catalog = make_catalog(e.dir.path(), &t, &tool_specs(json!({}))).unwrap();
    assert_eq!(catalog.tools["gkrepo.push"].git_operation.as_deref(), Some("push"));
}

#[test]
fn catalog_refuses_a_definition_wider_than_the_executor() {
    let mut force = params();
    force["force"] = json!({"type": "boolean", "description": "f"});
    let only_branch = json!({"branch": params()["branch"]});
    let mut int_branch = params();
    int_branch["branch"] = json!({"type": "integer", "required": true, "description": "b"});
    let mut wide_repo = params();
    wide_repo["repo"]["values"] = json!(["p", "q"]);
    let cases = [
        (json!({"category": "read"}), "must be 'write'"),
        (json!({"git_operation": "force_push"}), "unknown"),
        (json!({"parameters": force}), "does not read"),
        (json!({"parameters": only_branch}), "'repo'"),
        (json!({"parameters": int_branch}), "string or an enum"),
        (json!({"parameters": wide_repo}), "not in the 'repos'"),
    ];
    let e = env();
    let t = try_tier1(e.dir.path(), plain_repos(), json!({})).unwrap();
    for (change, fragment) in cases {
        let err = make_catalog(e.dir.path(), &t, &tool_specs(change)).unwrap_err();
        assert!(err.message.contains(fragment), "{fragment}: {}", err.message);
    }
    let mut wide_repo = params();
    wide_repo["repo"]["values"] = json!(["p", "z", "q"]);
    let err = crate::catalog::parse_tool_spec(&tool_specs(json!({"parameters": wide_repo}))[0], &t).unwrap_err();
    assert!(err.is_tier1_violation());
    assert_eq!(err.message, "tool 'gkrepo.push': repo values ['q', 'z'] are not in the 'repos' of toolkit 'gkrepo'");
    let err = crate::catalog::parse_tool_spec(&tool_specs(json!({"category": "read"}))[0], &t).unwrap_err();
    assert_eq!(
        err.message,
        "tool 'gkrepo.push': git operation 'push' changes a remote -- its category must be 'write', not 'read'"
    );
}

/// config/examples is what an operator copies from; its git part must load.
#[test]
fn shipped_example_toolkit_and_tool_load() {
    let e = env();
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/examples");
    let toolkits = crate::yaml::load(&std::fs::read_to_string(examples.join("toolkits.yaml")).unwrap()).unwrap();
    let all_tools = crate::yaml::load(&std::fs::read_to_string(examples.join("tools.yaml")).unwrap()).unwrap();
    let tools: Vec<Value> =
        all_tools["tools"].as_array().unwrap().iter().filter(|t| t["toolkit"] == "gkrepo").cloned().collect();
    let doc = json!({"toolkits": {"gkrepo": toolkits["toolkits"]["gkrepo"]},
                     "audit": {"dir": e.dir.path().join("logs").to_str().unwrap()}});
    let path = e.dir.path().join("toolkits.yaml");
    std::fs::write(&path, crate::yaml::dump(&doc)).unwrap();
    let t = load_tier1(path.to_str().unwrap()).unwrap();
    let catalog = make_catalog(e.dir.path(), &t, &tools).unwrap();
    let ids: Vec<&String> = catalog.tools.keys().collect();
    assert_eq!(ids, ["gkrepo.push"]);
}

// -- Through the service, with audit ------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn service_call_is_audited_without_the_token() {
    use crate::service::{CallError, Service, ServiceOptions};
    let (_, backend) = need_git!();
    let e = env();
    create_token(&e.store);
    let dir = e.dir.path();
    let remote = remote(dir, &backend).await;
    let worker = worker(dir, &remote);
    let repos = json!({"proj": {"path": worker.to_str().unwrap(), "remote": remote.url("proj")}});
    let t = try_tier1(dir, repos, json!({})).unwrap();
    let loose = json!({
        "repo": {"type": "string", "required": true, "pattern": "^\\S{1,64}$", "description": "r"},
        "branch": {"type": "string", "required": true, "pattern": "^\\S{1,200}$", "description": "b"},
    });
    let catalog = make_catalog(dir, &t, &tool_specs(json!({"parameters": loose}))).unwrap();
    let ipath = dir.join("identities.yaml");
    std::fs::write(
        &ipath,
        crate::yaml::dump(&json!({"identities": [{
            "id": "homelab", "role": "agent",
            "token_hash": crate::identity::hash_token(&crate::identity::generate_token()),
            "tools": ["gkrepo.push"], "scopes": [],
        }]})),
    )
    .unwrap();
    let identities = crate::identity::load_identities(ipath.to_str().unwrap()).unwrap();
    let homelab = identities.identities["homelab"].clone();
    let audit = Arc::new(crate::audit::AuditLog::new(dir.join("logs").to_str().unwrap()).unwrap());
    let store = Arc::new(CredentialStore::new(dir.join("credentials.yaml").to_str().unwrap(), audit.clone()));
    let service = Service::new(ServiceOptions {
        tier1: t,
        catalog,
        audit,
        credentials: Some(store),
        docker_host: None,
        identities: Some(Arc::new(parking_lot::RwLock::new(identities))),
    });

    sh_git(&["checkout", "--quiet", "-b", "feat/svc"], Some(&worker), true);
    let head = commit(&worker, "a.txt");
    let args = json!({"repo": "proj", "branch": "feat/svc"});
    let pushed = service.call(&homelab, "gkrepo.push", args.as_object().unwrap(), None).await.unwrap();
    assert_eq!(pushed.outcome, OUTCOME_OK, "{}", pushed.stderr);
    assert_eq!(payload(&pushed)["new"], head.as_str());
    // A loose schema does not widen the executor: main is still refused.
    let args = json!({"repo": "proj", "branch": "main"});
    match service.call(&homelab, "gkrepo.push", args.as_object().unwrap(), None).await {
        Err(CallError::Denied(denial)) => {
            assert!(denial.agent_message().contains("feat/"), "{}", denial.agent_message())
        }
        other => panic!("expected a denial, got {other:?}"),
    }
    assert_ne!(remote.reference("proj", "refs/heads/main"), Some(head));

    let mut log = String::new();
    for entry in walk(&dir.join("logs")) {
        log.push_str(&std::fs::read_to_string(entry).unwrap());
    }
    let records: Vec<Value> =
        log.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
    let calls: Vec<&str> =
        records.iter().filter(|r| r["kind"] == "call").map(|r| r["tool"].as_str().unwrap()).collect();
    assert_eq!(calls[calls.len() - 2..], ["gkrepo.push", "gkrepo.push"]);
    assert!(!log.contains(TOKEN) && !log.contains(&encoded()));
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
