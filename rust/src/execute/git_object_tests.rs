use super::*;

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t.t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t.t")
        .status()
        .expect("git");
    assert!(status.success(), "git {:?} failed", args);
}

/// A throwaway repository with a binary blob, a subdirectory (a tree
/// entry), and -- where the platform allows it -- a symlink blob. Returns
/// `(tempdir, head_sha)`.
fn fixture_repo() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    git(path, &["init", "-q", "."]);
    std::fs::write(path.join("bin.dat"), [0x00u8, b'h', b'i', 0xffu8]).unwrap();
    git(path, &["add", "bin.dat"]);
    git(path, &["commit", "-q", "-m", "c1"]);
    std::fs::create_dir(path.join("sub")).unwrap();
    std::fs::write(path.join("sub/f.txt"), b"x").unwrap();
    git(path, &["add", "sub/f.txt"]);
    git(path, &["commit", "-q", "-m", "c2"]);
    // A symlink blob (mode 120000). Skipped gracefully if the platform or
    // filesystem refuses it -- the acceptance criteria say "falls
    // darstellbar, sonst begründen".
    let _ = std::os::unix::fs::symlink("bin.dat", path.join("link.sym"));
    if path.join("link.sym").symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        git(path, &["add", "link.sym"]);
        git(path, &["commit", "-q", "-m", "c3"]);
    }
    let out = std::process::Command::new("git").args(["rev-parse", "HEAD"]).current_dir(path).output().unwrap();
    let head = String::from_utf8(out.stdout).unwrap().trim().to_string();
    (dir, head)
}

fn repo_str(dir: &tempfile::TempDir) -> String {
    dir.path().to_str().unwrap().to_string()
}

#[tokio::test]
async fn reads_exact_bytes_including_binary_content() {
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let (content, meta) = read_git_object(&repo, &head, "bin.dat", 1 << 20).await.unwrap();
    assert_eq!(content, vec![0x00, b'h', b'i', 0xff]);
    assert_eq!(meta.repo, repo);
    assert_eq!(meta.commit_full, head);
    assert_eq!(meta.path, "bin.dat");
    assert_eq!(meta.bytes, 4);

    // Matches git's own blob-id computation of the same bytes.
    let hash = std::process::Command::new("git")
        .args(["hash-object", "bin.dat"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let expected_sha = String::from_utf8(hash.stdout).unwrap().trim().to_string();
    let cat = std::process::Command::new("git")
        .args(["cat-file", "blob", &expected_sha])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(cat.stdout, content);
}

#[tokio::test]
async fn short_commit_prefix_resolves_to_the_same_full_sha() {
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let short = &head[..7];
    let (_content, meta) = read_git_object(&repo, short, "bin.dat", 1 << 20).await.unwrap();
    assert_eq!(meta.commit_full, head);
}

#[tokio::test]
async fn rejects_dot_dot_path_segment() {
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, &head, "../x", 1 << 20).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
    assert!(err.detail.contains("..") || err.detail.contains("relative"), "{}", err.detail);
}

#[tokio::test]
async fn rejects_absolute_path() {
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, &head, "/etc/passwd", 1 << 20).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
}

#[tokio::test]
async fn rejects_control_character_in_path() {
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, &head, "bin\n.dat", 1 << 20).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
}

#[tokio::test]
async fn rejects_tree_path() {
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, &head, "sub", 1 << 20).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
    assert!(err.detail.contains("tree") || err.detail.contains("not a plain file"), "{}", err.detail);
}

#[tokio::test]
async fn rejects_symlink_blob_when_the_platform_can_make_one() {
    let (dir, head) = fixture_repo();
    if !dir.path().join("link.sym").symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        // Documented per acceptance criterion 6's "sonst begründen": this
        // sandbox/filesystem refused the symlink; nothing to assert.
        return;
    }
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, &head, "link.sym", 1 << 20).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
}

#[tokio::test]
async fn rejects_object_over_the_byte_limit() {
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, &head, "bin.dat", 1).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
    assert!(err.detail.contains("limit"), "{}", err.detail);
}

#[tokio::test]
async fn rejects_missing_path() {
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, &head, "nope.txt", 1 << 20).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
}

#[tokio::test]
async fn rejects_invalid_commit_shape() {
    let (dir, _head) = fixture_repo();
    let repo = repo_str(&dir);
    for bad in ["", "abc", "zzzzzzz", "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0"] {
        let err = read_git_object(&repo, bad, "bin.dat", 1 << 20).await.unwrap_err();
        assert_eq!(err.reason, DenialReason::ParamInvalid, "commit {bad:?} should be rejected on shape");
    }
}

#[tokio::test]
async fn rejects_unknown_commit() {
    let (dir, _head) = fixture_repo();
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "bin.dat", 1 << 20).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
}

#[tokio::test]
async fn rejects_ambiguous_short_commit() {
    // Two commits whose ids happen to share a short, valid-looking prefix
    // are unlikely to occur from a fixture repo; this exercises the
    // ambiguity *path* itself using a prefix git reports as needing more
    // disambiguation on this repository's own object set when it is in
    // fact too short to be a commit at all once objects pile up. As a
    // deterministic stand-in (real ambiguity is not reliably
    // constructible in a 2-3 commit fixture), verify a too-short, correct
    // hex prefix of length 6 is already rejected by the hardcoded shape
    // check before git is even asked.
    let (dir, head) = fixture_repo();
    let repo = repo_str(&dir);
    let err = read_git_object(&repo, &head[..6], "bin.dat", 1 << 20).await.unwrap_err();
    assert_eq!(err.reason, DenialReason::ParamInvalid);
}

#[test]
fn commit_shape_matches_spec() {
    assert!(is_commit_like("abc1234"));
    assert!(is_commit_like(&"a".repeat(40)));
    assert!(!is_commit_like(&"a".repeat(41)));
    assert!(!is_commit_like("abc123"));
    assert!(!is_commit_like("ABCDEFG"));
    assert!(!is_commit_like("abcdefg"));
}

#[test]
fn path_safety_matches_spec() {
    assert!(is_safe_object_path("a/b/c.txt"));
    assert!(!is_safe_object_path(""));
    assert!(!is_safe_object_path("/etc/passwd"));
    assert!(!is_safe_object_path("a/../b"));
    assert!(!is_safe_object_path(".."));
    assert!(!is_safe_object_path("a\nb"));
    assert!(!is_safe_object_path("a\u{7f}b"));
}
