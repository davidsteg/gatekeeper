//! Where gatekeeper is allowed to change a process's identity, and nowhere
//! else (port of the source-scanning half of the Python suite's
//! `test_no_internal_drop.py`; the Dockerfile/compose checks there test
//! files, not code, and are in `tests/test_image_files.py`).
//!
//! Two modules may change identity: `runas.rs` (in the short-lived helper
//! child, one file operation per process, one-way) and `privdrop.rs` (once
//! at startup, downward, plus the `__unpriv` wrapper clearing capabilities
//! before it execs). No executor, no service, no server module.

use std::path::{Path, PathBuf};

/// Everything in libc that changes who the process is. `setgroups` and
/// `initgroups` are the other half of a privilege drop.
const IDENTITY_CALLS: &[&str] = &[
    "setuid", "seteuid", "setreuid", "setresuid", "setgid", "setegid", "setregid", "setresgid", "setgroups",
    "initgroups",
];

const ALLOWED: &[&str] = &["runas.rs", "privdrop.rs"];

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn modules() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&src(), &mut out);
    out.sort();
    out
}

/// The code lines of a file: comments stripped, and everything from the
/// first `#[cfg(test)]` on dropped -- tests may *call* identity functions
/// to set up a scenario, the guarantee is about the shipped code.
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        let code = match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        };
        out.push((i + 1, code.to_string()));
    }
    out
}

/// Every `libc::<identity call>(` in `path`, as (name, line).
fn identity_calls(path: &Path) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    for (lineno, code) in code_lines(path) {
        for name in IDENTITY_CALLS {
            if code.contains(&format!("libc::{name}(")) {
                found.push((name.to_string(), lineno));
            }
        }
    }
    found
}

fn name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

#[test]
fn there_are_modules_to_check() {
    let names: Vec<String> = modules().iter().map(|p| name(p)).collect();
    assert!(names.len() > 10);
    for expected in ["main.rs", "local.rs", "file.rs", "runas.rs", "privdrop.rs"] {
        assert!(names.iter().any(|n| n == expected), "{expected} missing");
    }
}

#[test]
fn only_the_two_sanctioned_modules_change_process_identity() {
    for module in modules() {
        if ALLOWED.contains(&name(&module).as_str()) {
            continue;
        }
        let calls = identity_calls(&module);
        assert!(
            calls.is_empty(),
            "{} changes the process identity: {} -- only {ALLOWED:?} may.",
            name(&module),
            calls.iter().map(|(n, l)| format!("{n}() at line {l}")).collect::<Vec<_>>().join(", ")
        );
    }
}

#[test]
fn each_allowance_is_actually_used() {
    for allowed in ALLOWED {
        let calls: Vec<String> = identity_calls(&src().join(allowed)).into_iter().map(|(n, _)| n).collect();
        for needed in ["setresuid", "setresgid"] {
            assert!(calls.iter().any(|c| c == needed), "{allowed} does not call {needed}");
        }
    }
}

#[test]
fn the_startup_drop_is_only_reachable_from_the_cli() {
    // `drop_privileges` may be called from the entry point (main.rs / the
    // CLI module) and nowhere else in the shipped code.
    for module in modules() {
        let n = name(&module);
        if n == "main.rs" || n == "cli.rs" || module.components().any(|c| c.as_os_str() == "cli") {
            continue;
        }
        for (lineno, code) in code_lines(&module) {
            if code.contains("drop_privileges(") && !code.contains("fn drop_privileges(") {
                panic!("{n}:{lineno} calls drop_privileges");
            }
        }
    }
}

#[test]
fn the_helper_only_drops_from_its_own_entry_point() {
    // `become_user` is reachable from the child's entry and nowhere else.
    for module in modules() {
        let n = name(&module);
        for (lineno, code) in code_lines(&module) {
            if code.contains("become_user(") && !code.contains("fn become_user(") {
                assert_eq!(n, "runas.rs", "{n}:{lineno} calls become_user");
            }
        }
    }
}

#[test]
fn no_runtime_message_hardcodes_a_uid() {
    let mut offenders = Vec::new();
    for module in modules() {
        for (lineno, code) in code_lines(&module) {
            if code.contains('"') && code.contains("568") && code.contains("runs as") {
                offenders.push(format!("{}:{lineno}", name(&module)));
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:?}");
}
