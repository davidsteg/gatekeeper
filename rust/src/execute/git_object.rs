//! Byte-exact reader for `<commit>:<path>` out of a local git repository's
//! object database (FR body-source `from_git_object`, 1.31.0; see
//! `catalog.rs`'s load-time validation of the tool-side shape and
//! `pathutil::is_git_repo_dir`). This module is Part 1 of 3: the reader
//! itself and its unit tests. Wiring it into `validate.rs`/`http.rs`'s
//! body resolution and `audit.rs`/`service.rs`'s record of
//! `{repo, commit, path, bytes}` is a later card.
//!
//! **The repository is read, never trusted** (same stance as `git.rs`'s
//! push executor): nothing here checks the repository out, writes to it,
//! or runs a command *in* its working tree, so a worker-controlled
//! `.git/config`, `core.hooksPath` or `url.<x>.insteadOf` has nothing to
//! act on. Every `git` call here is `-C <repo> -c safe.directory=<repo>`
//! -- the ownership escape hatch applies to this one call only, never
//! written to any config file -- with a from-scratch, minimal
//! environment (`env_clear`): no inherited `GIT_*` variable, no system or
//! global config, no terminal prompt, no credential helper, `LC_ALL=C` so
//! git's own messages are not locale-dependent.
//!
//! `commit` and `path` are the only two values a caller supplies, and
//! both are checked against a hardcoded shape *before* either reaches
//! `git`'s argv: `commit` must look like `^[0-9a-f]{7,40}$`, `path` must
//! have no leading `/`, no `..` path segment and no control character.
//! `path` is additionally sent to `git` under the `:(literal)` pathspec
//! magic, so a path containing `*`, `?` or `[` is matched literally, never
//! expanded into more than the one entry it names.
//!
//! The lookup is three `git` calls, each gating the next:
//! `rev-parse --verify <commit>^{commit}` resolves `commit` to exactly one
//! full object id (ambiguous or unknown is refused here, before anything
//! about `path` is even looked at); `ls-tree -l <sha> -- :(literal)<path>`
//! names the one tree entry at that path -- a tree, a submodule (mode
//! `160000`, type `commit`) and a symlink (mode `120000`) are refused, and
//! so is a missing entry, all before a byte of content is touched, and the
//! entry's reported size is checked against `max_bytes` *before* reading
//! anything; `cat-file blob <objsha>` then reads the raw bytes, capped at
//! `max_bytes + 1` so a blob that grew between the two calls is still
//! caught. The content is read into a `Vec<u8>` directly from the child's
//! stdout pipe -- never through a lossy UTF-8 string, which is what
//! `execute::local::run` uses and why this module does not call it.

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use super::local::{kill_group, new_session, returncode};
use crate::errors::{DenialReason, Denied};
use crate::pyfmt::repr_str;

/// How long any single `git` call here may run before its process group is
/// killed and the call reported as refused. Local object-database reads
/// (`rev-parse`, `ls-tree`, `cat-file`) are not network operations; a
/// generous but bounded ceiling, not a caller-tunable timeout.
const GIT_TIMEOUT: Duration = Duration::from_secs(20);

/// `git` discovers nothing on disk beyond the object database itself: no
/// system config (`GIT_CONFIG_NOSYSTEM`), no `~/.gitconfig`
/// (`GIT_CONFIG_GLOBAL=/dev/null`), no credential/terminal prompt, no
/// locale-dependent message text.
const GIT_ENV: &[(&str, &str)] = &[
    ("PATH", "/usr/local/bin:/usr/bin:/bin"),
    ("HOME", "/nonexistent-gatekeeper-git-object"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("LC_ALL", "C"),
];

/// How much of a non-content `git` call's stderr/stdout a denial message
/// may quote. These calls never touch blob content, so there is nothing
/// to redact here beyond keeping a runaway message bounded.
const MAX_GIT_TEXT: usize = 4096;

/// `^[0-9a-f]{7,40}$`, hardcoded independently of any Tier 1 or catalog
/// check: the only shape `commit` may have before it reaches `git`'s argv.
fn is_commit_like(text: &str) -> bool {
    (7..=40).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// No leading `/`, no `..` path segment, no control character (`< 0x20`
/// or `0x7f`). This is independent of `pathutil`'s path-root checks --
/// `path` never touches the filesystem, it names a tree entry inside a
/// commit's object graph.
fn is_safe_object_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.bytes().any(|b| b < 0x20 || b == 0x7f)
        && path.split('/').all(|segment| segment != "..")
}

/// What a successful read reports for the audit log (FR-9.2, wired in a
/// later card): never the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitObjectMeta {
    pub repo: String,
    pub commit_full: String,
    pub path: String,
    pub bytes: u64,
}

fn invalid(detail: String) -> Denied {
    Denied::new(DenialReason::ParamInvalid, detail)
}

/// Reads up to `limit + 1` bytes from a child's stdout/stderr pipe
/// (byte-exact -- no UTF-8 decoding, unlike `execute::local`'s capped
/// reader, which this module cannot reuse for blob content).
async fn read_capped_bytes<R: AsyncRead + Unpin>(stream: &mut R, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        out.extend_from_slice(&chunk[..n]);
        if out.len() > limit {
            break;
        }
    }
    out
}

/// One `git` call against `repo`, with no shell, a from-scratch minimal
/// environment, and `-c safe.directory=<repo>` scoped to this call only.
/// `max_stdout` caps the stdout capture (`+1` so the caller can detect
/// truncation); stderr is always capped at [`MAX_GIT_TEXT`].
async fn run_git(repo: &str, args: &[&str], max_stdout: usize) -> Result<(Option<i64>, Vec<u8>, Vec<u8>), Denied> {
    let safe_directory = format!("safe.directory={repo}");
    let mut argv: Vec<&str> = vec!["-C", repo, "-c", &safe_directory];
    argv.extend_from_slice(args);

    let mut env: HashMap<String, String> = HashMap::new();
    for (key, value) in GIT_ENV {
        env.insert(key.to_string(), value.to_string());
    }

    let mut command = Command::new("git");
    command.args(&argv).env_clear().envs(&env).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    new_session(&mut command);

    let mut child = command.spawn().map_err(|e| match e.raw_os_error() {
        Some(libc::ENOENT) => Denied::new(DenialReason::ExecutorUnavailable, "Executable not found: git".to_string()),
        Some(libc::EACCES) | Some(libc::EPERM) => {
            Denied::new(DenialReason::ExecutorUnavailable, "No permission to execute git".to_string())
        }
        _ => Denied::new(DenialReason::ExecutorUnavailable, format!("Cannot run git: {e}")),
    })?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let gathered = tokio::time::timeout(GIT_TIMEOUT, async {
        let out = async {
            match stdout.as_mut() {
                Some(s) => read_capped_bytes(s, max_stdout).await,
                None => Vec::new(),
            }
        };
        let err = async {
            match stderr.as_mut() {
                Some(s) => read_capped_bytes(s, MAX_GIT_TEXT).await,
                None => Vec::new(),
            }
        };
        tokio::join!(out, err)
    })
    .await;

    let (out, err) = match gathered {
        Ok(pair) => pair,
        Err(_) => {
            kill_group(&mut child);
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            return Err(Denied::new(
                DenialReason::Timeout,
                format!("git {} timed out after {}s.", args.first().copied().unwrap_or(""), GIT_TIMEOUT.as_secs()),
            ));
        }
    };
    let code = child.wait().await.ok().map(returncode);
    Ok((code, out, err))
}

/// `rev-parse --verify <commit>^{commit}`: resolves `commit` to exactly
/// one full (40-hex-char) commit id, or refuses -- unknown, ambiguous, or
/// an object that is not a commit are all the same refusal from here.
async fn resolve_commit(repo: &str, commit: &str) -> Result<String, Denied> {
    let target = format!("{commit}^{{commit}}");
    let (code, out, err) = run_git(repo, &["rev-parse", "--verify", &target], 128).await?;
    let unresolved = || {
        let detail = String::from_utf8_lossy(&err).trim().to_string();
        invalid(format!(
            "commit {} does not resolve to exactly one commit in this repository{}.",
            repr_str(commit),
            if detail.is_empty() { String::new() } else { format!(": {detail}") }
        ))
    };
    if code != Some(0) {
        return Err(unresolved());
    }
    let text = String::from_utf8(out).map_err(|_| unresolved())?;
    let sha = text.trim();
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(unresolved());
    }
    Ok(sha.to_string())
}

/// One `ls-tree -l` entry: mode, type, object id, size.
struct TreeEntry {
    mode: String,
    kind: String,
    object: String,
    size: u64,
}

/// `ls-tree -l <sha> -- :(literal)<path>`: the one tree entry at `path`,
/// matched literally (no glob expansion of `*`, `?`, `[` in `path`).
/// Zero lines is a missing path; more than one is treated the same as
/// zero -- a literal pathspec against a single commit names at most one
/// entry, so more than one line is a shape this module does not trust
/// enough to pick from.
async fn ls_tree_entry(repo: &str, sha: &str, path: &str) -> Result<TreeEntry, Denied> {
    let pathspec = format!(":(literal){path}");
    let (code, out, err) = run_git(repo, &["ls-tree", "-l", sha, "--", &pathspec], 1 << 16).await?;
    if code != Some(0) {
        let detail = String::from_utf8_lossy(&err).trim().to_string();
        return Err(invalid(format!(
            "git ls-tree on {}:{} failed{}.",
            repr_str(sha),
            repr_str(path),
            if detail.is_empty() { String::new() } else { format!(": {detail}") }
        )));
    }
    let text = String::from_utf8(out)
        .map_err(|_| invalid(format!("git ls-tree on {}:{} returned non-UTF-8 output.", repr_str(sha), repr_str(path))))?;
    let lines: Vec<&str> = text.split('\n').filter(|l| !l.is_empty()).collect();
    let missing = || invalid(format!("{}:{} does not exist in this commit.", repr_str(sha), repr_str(path)));
    if lines.len() != 1 {
        return Err(missing());
    }
    let line = lines[0];
    let Some((meta, name)) = line.split_once('\t') else {
        return Err(missing());
    };
    if name != path {
        // A literal pathspec names exactly one entry; a reported name
        // that does not match what was asked for is not trusted.
        return Err(missing());
    }
    let fields: Vec<&str> = meta.split_whitespace().collect();
    let [mode, kind, object, size] = fields[..] else {
        return Err(missing());
    };
    // `-l`'s size column is `-` for a non-blob entry (a tree, or a
    // submodule's commit) -- there is no "object size" for those, and
    // this module rejects every non-blob kind right after this call
    // returns, so a 0 here never reaches the size-ceiling check.
    let size: u64 = size.parse().unwrap_or(0);
    Ok(TreeEntry { mode: mode.to_string(), kind: kind.to_string(), object: object.to_string(), size })
}

/// `cat-file blob <objsha>`: the raw bytes, capped at `max_bytes + 1` so a
/// blob that changed between `ls-tree` and this call is still caught, not
/// trusted on `ls-tree`'s reported size alone.
async fn cat_file_blob(repo: &str, object: &str, max_bytes: u64) -> Result<Vec<u8>, Denied> {
    let cap = (max_bytes as usize).saturating_add(1);
    let (code, out, err) = run_git(repo, &["cat-file", "blob", object], cap).await?;
    if code != Some(0) {
        let detail = String::from_utf8_lossy(&err).trim().to_string();
        return Err(invalid(format!(
            "git cat-file on blob {} failed{}.",
            repr_str(object),
            if detail.is_empty() { String::new() } else { format!(": {detail}") }
        )));
    }
    Ok(out)
}

/// Reads `<commit>:<path>` out of `repo`'s object database as raw bytes,
/// or refuses before a byte is read. `max_bytes` is the object-size
/// ceiling (checked against `ls-tree`'s reported size *and* against what
/// was actually read); `commit` and `path` are validated against their
/// hardcoded shapes before either reaches `git`.
pub async fn read_git_object(
    repo: &str,
    commit: &str,
    path: &str,
    max_bytes: u64,
) -> Result<(Vec<u8>, GitObjectMeta), Denied> {
    if !is_commit_like(commit) {
        return Err(invalid(format!(
            "commit {} must match ^[0-9a-f]{{7,40}}$ (lowercase hex, 7 to 40 characters).",
            repr_str(commit)
        )));
    }
    if !is_safe_object_path(path) {
        return Err(invalid(format!(
            "path {} must be relative, without a leading '/', a '..' segment or a control character.",
            repr_str(path)
        )));
    }

    let sha = resolve_commit(repo, commit).await?;
    let entry = ls_tree_entry(repo, &sha, path).await?;
    if entry.kind != "blob" || entry.mode == "120000" {
        return Err(invalid(format!(
            "{}:{} is not a plain file (mode {}, type {}); only regular-file blobs are read -- no tree, \
             submodule or symlink.",
            repr_str(commit),
            repr_str(path),
            entry.mode,
            entry.kind
        )));
    }
    if entry.size > max_bytes {
        return Err(invalid(format!(
            "{}:{} is {} bytes, over this call's limit of {max_bytes}. Nothing was read.",
            repr_str(commit),
            repr_str(path),
            entry.size
        )));
    }

    let content = cat_file_blob(repo, &entry.object, max_bytes).await?;
    if content.len() as u64 > max_bytes {
        return Err(invalid(format!(
            "{}:{} is larger than the limit of {max_bytes} bytes. Nothing was sent.",
            repr_str(commit),
            repr_str(path)
        )));
    }

    let bytes = content.len() as u64;
    Ok((content, GitObjectMeta { repo: repo.to_string(), commit_full: sha, path: path.to_string(), bytes }))
}

#[cfg(test)]
#[path = "git_object_tests.rs"]
mod tests;
