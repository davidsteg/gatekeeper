//! Built-in `artifact` executor -- release-bound artifacts (port of
//! `execute_artifact.py`).
//!
//! Four operations and no fifth: `list`, `info`, `read` and `transfer`, all
//! in-process against the read-only [`ArtifactStore`]. The only things a
//! call can name are an artifact id and, optionally, a version (a commit
//! prefix) -- both checked against the manifest of the running image.
//!
//! `transfer` writes into the toolkit's Tier 1 `handover_dir`, under
//! `<handover_dir>/<id>/<version>/<file>`, reading through
//! [`ArtifactStore::stream`], writing a temp file, verifying the SHA-256 and
//! only then renaming. An existing target with the same SHA-256 is left as
//! is; a different file at that path is refused, never overwritten.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::artifacts::{Artifact, ArtifactStore, IntegrityError, StreamError};
use crate::execute::{elapsed_ms, ExecResult, OUTCOME_FAILED, OUTCOME_OK};
use crate::pathutil;
use crate::pyfmt::{os_error, repr_str};
use crate::pyjson::{self, Opts};
use crate::tier1::Toolkit;
use crate::validate::Values;

fn result(outcome: &str, started: Instant, stdout: impl Into<String>, stderr: impl Into<String>) -> ExecResult {
    let exit = if outcome == OUTCOME_OK { 0 } else { 1 };
    ExecResult::new(outcome, Some(exit), stdout, stderr, false, elapsed_ms(started))
}

fn dumps2(value: &Value) -> String {
    pyjson::dumps_with(value, &Opts::indented(2))
}

/// `visible(id)` is the caller's scope check (`artifact:<id>`); an
/// artifact it may not see is indistinguishable from one that does not
/// exist (FR-7.7).
pub async fn run(
    operation: &str,
    values: &Values,
    toolkit: &Toolkit,
    store: &ArtifactStore,
    visible: &(dyn Fn(&str) -> bool + Send + Sync),
    max_output_bytes: i64,
) -> ExecResult {
    let started = Instant::now();
    let allowed = |art_id: &str| toolkit.allowed_artifacts.iter().any(|a| a == art_id) && visible(art_id);

    if operation == "list" {
        let items: Vec<Value> = store.list().into_iter().filter(|a| allowed(&a.id)).map(Artifact::public).collect();
        return result(
            OUTCOME_OK,
            started,
            dumps2(&json!({"release": store.release, "commit": store.commit, "artifacts": items})),
            "",
        );
    }

    let art_id = values.get("artifact").map(String::as_str).unwrap_or("");
    let version = values.get("version").map(String::as_str).filter(|v| !v.is_empty());
    let art = if allowed(art_id) { store.get(art_id, version) } else { None };
    let Some(art) = art else {
        return result(
            OUTCOME_FAILED,
            started,
            "",
            "Unknown artifact, or not available. Use artifact.list to see the artifacts of this release.",
        );
    };

    match operation {
        "info" => result(OUTCOME_OK, started, dumps2(&art.public()), ""),
        "read" => match store.read_text(art, max_output_bytes.max(0) as u64) {
            Ok(text) => result(OUTCOME_OK, started, text, ""),
            // PORT NOTE: Python let an OSError escape `run()`; every error is
            // reported with the same sentence here.
            Err(err) => result(
                OUTCOME_FAILED,
                started,
                "",
                format!(
                    "{} cannot be read inline: {err}. Use artifact.transfer, or the authenticated \
                     download {}.",
                    art.id,
                    art.download_path()
                ),
            ),
        },
        "transfer" => transfer(art, store, toolkit, started),
        _ => result(OUTCOME_FAILED, started, "", format!("Unknown artifact operation: {}", repr_str(operation))),
    }
}

fn transfer(art: &Artifact, store: &ArtifactStore, toolkit: &Toolkit, started: Instant) -> ExecResult {
    let handover = toolkit.handover_dir.clone().unwrap_or_default();
    let target_dir = pathutil::join(&pathutil::join(&handover, &art.id), &art.version);
    let target = pathutil::join(&target_dir, &art.file);

    let done = |state: &str| {
        result(
            OUTCOME_OK,
            started,
            dumps2(&json!({
                "transfer": state, "artifact": art.id, "version": art.version, "commit": art.commit,
                "path": target, "sha256": art.sha256, "size": art.size})),
            "",
        )
    };

    if pathutil::exists(&target) {
        // PORT NOTE: an unreadable existing target raised in Python; it
        // counts as "different content" here (it is not overwritten either way).
        if sha256_file(&target).as_deref() == Some(art.sha256.as_str()) {
            return done("already_present");
        }
        return result(
            OUTCOME_FAILED,
            started,
            "",
            format!("{target} exists with different content; it is not overwritten. An operator must remove or move it first."),
        );
    }

    let tmp = std::fs::create_dir_all(&target_dir)
        .map_err(|e| os_error(&e, &target_dir))
        .and_then(|_| {
            tempfile::Builder::new()
                .prefix(".gk-")
                .suffix(".part")
                .tempfile_in(&target_dir)
                .map_err(|e| os_error(&e, &target_dir))
        });
    let mut tmp = match tmp {
        Ok(tmp) => tmp,
        Err(text) => return result(OUTCOME_FAILED, started, "", format!("handover_dir is not writable: {text}")),
    };

    let written = (|| -> Result<(), String> {
        let mut digest = Sha256::new();
        for chunk in store.stream(art) {
            let chunk = chunk.map_err(|e: StreamError| e.to_string())?;
            digest.update(&chunk);
            tmp.write_all(&chunk).map_err(|e| os_error(&e, ""))?;
        }
        tmp.flush().map_err(|e| os_error(&e, ""))?;
        tmp.as_file().sync_all().map_err(|e| os_error(&e, ""))?;
        if hex::encode(digest.finalize()) != art.sha256 {
            return Err(IntegrityError(format!("{}: written bytes do not match the manifest", art.id)).to_string());
        }
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o644))
            .map_err(|e| os_error(&e, &tmp.path().to_string_lossy()))?;
        Ok(())
    })();
    if let Err(text) = written {
        // Dropping the NamedTempFile unlinks it.
        return result(OUTCOME_FAILED, started, "", format!("transfer failed, nothing was written: {text}"));
    }
    if let Err(err) = tmp.persist(&target) {
        return result(
            OUTCOME_FAILED,
            started,
            "",
            format!("transfer failed, nothing was written: {}", os_error(&err.error, "")),
        );
    }
    done("transferred")
}

fn sha256_file(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Some(hex::encode(digest.finalize()))
}

/// Ready when the store serves at least one allowed artifact and, if the
/// toolkit may transfer, its `handover_dir` is writable.
pub async fn probe(toolkit: &Toolkit, store: &ArtifactStore) -> bool {
    if !store.list().iter().any(|a| toolkit.allowed_artifacts.iter().any(|x| *x == a.id)) {
        return false;
    }
    if toolkit.allowed_artifact_operations.iter().any(|o| o == "transfer") {
        let handover = toolkit.handover_dir.clone().unwrap_or_default();
        return !handover.is_empty() && crate::atomic::writable(&pathutil::join(&handover, ".probe"));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{build, Source, SourceKind};

    const COMMIT: &str = "7aa7b394cb713162db98aad29c91c342508a49c7";
    const CONTRACT: &str = "example-doc";
    const ADAPTER: &str = "example-kit";
    const DOC_FILE: &str = "EXAMPLE.md";
    const KIT_FILE: &str = "example-kit.tar.gz";

    struct Env {
        dir: tempfile::TempDir,
        store: ArtifactStore,
        toolkit: Toolkit,
    }

    fn setup() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("docs/EXAMPLE.md"), b"# Example document\r\n\nreleased with the image\n").unwrap();
        std::fs::create_dir_all(root.join("kit/pkg")).unwrap();
        std::fs::write(root.join("kit/pkg/main.py"), "print('hello')\n").unwrap();
        std::fs::write(root.join("kit/README.md"), "kit\n").unwrap();
        let sources = vec![
            Source {
                id: CONTRACT.into(),
                kind: SourceKind::File,
                path: "docs/EXAMPLE.md".into(),
                file: DOC_FILE.into(),
                media_type: "text/markdown; charset=utf-8".into(),
                text: true,
            },
            Source {
                id: ADAPTER.into(),
                kind: SourceKind::Tree,
                path: "kit".into(),
                file: KIT_FILE.into(),
                media_type: "application/gzip".into(),
                text: false,
            },
        ];
        let out = dir.path().join("artifacts");
        build(root.to_str().unwrap(), out.to_str().unwrap(), COMMIT, "0.52.0", &sources).unwrap();
        let store = ArtifactStore::new(out.to_str().unwrap());
        let toolkit = Toolkit {
            name: "artifact".into(),
            executor: "artifact".into(),
            allowed_artifact_operations: vec!["info".into(), "list".into(), "read".into(), "transfer".into()],
            allowed_artifacts: vec![CONTRACT.into(), ADAPTER.into()],
            handover_dir: Some(dir.path().join("handover").to_string_lossy().into_owned()),
            ..Toolkit::default()
        };
        Env { dir, store, toolkit }
    }

    fn vals(pairs: &[(&str, &str)]) -> Values {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    async fn call(env: &Env, scope_all: bool, op: &str, pairs: &[(&str, &str)]) -> ExecResult {
        let visible = move |id: &str| scope_all || id == CONTRACT;
        run(op, &vals(pairs), &env.toolkit, &env.store, &visible, 200000).await
    }

    #[tokio::test]
    async fn list_is_filtered_by_scope() {
        let env = setup();
        let full: Value = serde_json::from_str(&call(&env, true, "list", &[]).await.stdout).unwrap();
        let narrow: Value = serde_json::from_str(&call(&env, false, "list", &[]).await.stdout).unwrap();
        let ids = |v: &Value| v["artifacts"].as_array().unwrap().iter().map(|a| a["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(ids(&full), [CONTRACT, ADAPTER]);
        assert_eq!(full["commit"], COMMIT);
        assert_eq!(ids(&narrow), [CONTRACT]);
    }

    #[tokio::test]
    async fn missing_scope_looks_like_an_unknown_artifact() {
        let env = setup();
        let hidden = call(&env, false, "info", &[("artifact", ADAPTER)]).await;
        let unknown = call(&env, false, "info", &[("artifact", "does-not-exist")]).await;
        assert_eq!(hidden.outcome, OUTCOME_FAILED);
        assert_eq!(hidden.stderr, unknown.stderr);
        assert_eq!(hidden.exit_code, Some(1));
    }

    #[tokio::test]
    async fn info_and_read_with_version_prefix() {
        let env = setup();
        let info: Value =
            serde_json::from_str(&call(&env, true, "info", &[("artifact", CONTRACT), ("version", &COMMIT[..7])]).await.stdout)
                .unwrap();
        assert_eq!(info["commit"], COMMIT);
        assert_eq!(info["download_path"], format!("/artifacts/{CONTRACT}/{COMMIT}"));
        let text = call(&env, true, "read", &[("artifact", CONTRACT)]).await.stdout;
        assert!(text.starts_with("# Example document\n"));
        let wrong = call(&env, true, "info", &[("artifact", CONTRACT), ("version", "deadbee")]).await;
        assert_eq!(wrong.outcome, OUTCOME_FAILED);
        let binary = call(&env, true, "read", &[("artifact", ADAPTER)]).await;
        assert_eq!(binary.outcome, OUTCOME_FAILED);
        assert_eq!(
            binary.stderr,
            format!(
                "{ADAPTER} cannot be read inline: not a text artifact. Use artifact.transfer, or the authenticated \
                 download /artifacts/{ADAPTER}/{COMMIT}."
            )
        );
    }

    #[tokio::test]
    async fn transfer_writes_verified_and_is_idempotent() {
        let env = setup();
        let first: Value = serde_json::from_str(&call(&env, true, "transfer", &[("artifact", ADAPTER)]).await.stdout).unwrap();
        let target = env.dir.path().join("handover").join(ADAPTER).join(COMMIT).join(KIT_FILE);
        assert_eq!(first["transfer"], "transferred");
        assert_eq!(first["path"], target.to_str().unwrap());
        assert_eq!(sha256_file(target.to_str().unwrap()).unwrap(), first["sha256"].as_str().unwrap());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let leftovers: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with(".gk-"))
            .collect();
        assert!(leftovers.is_empty());
        let again: Value = serde_json::from_str(&call(&env, true, "transfer", &[("artifact", ADAPTER)]).await.stdout).unwrap();
        assert_eq!(again["transfer"], "already_present");
        assert!(probe(&env.toolkit, &env.store).await);
    }

    #[tokio::test]
    async fn transfer_never_overwrites_a_different_file() {
        let env = setup();
        let target = env.dir.path().join("handover").join(CONTRACT).join(COMMIT).join(DOC_FILE);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "someone else's file").unwrap();
        let r = call(&env, true, "transfer", &[("artifact", CONTRACT)]).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert!(r.stderr.contains("not overwritten"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "someone else's file");
    }

    #[tokio::test]
    async fn transfer_writes_nothing_when_the_bytes_changed_on_disk() {
        let env = setup();
        std::fs::write(env.dir.path().join("artifacts").join(KIT_FILE), b"changed after startup").unwrap();
        let r = call(&env, true, "transfer", &[("artifact", ADAPTER)]).await;
        assert_eq!(r.outcome, OUTCOME_FAILED);
        assert_eq!(r.stderr, format!("transfer failed, nothing was written: {ADAPTER}: content changed since startup"));
        let target_dir = env.dir.path().join("handover").join(ADAPTER).join(COMMIT);
        assert!(!target_dir.exists() || std::fs::read_dir(&target_dir).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn probe_needs_an_allowed_artifact() {
        let env = setup();
        let none = Toolkit { allowed_artifacts: vec!["other".into()], ..env.toolkit.clone() };
        assert!(!probe(&none, &env.store).await);
        let read_only = Toolkit { allowed_artifact_operations: vec!["list".into()], handover_dir: None, ..env.toolkit.clone() };
        assert!(probe(&read_only, &env.store).await);
    }
}
