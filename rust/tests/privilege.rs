//! Process execution and privilege handling that needs real processes:
//! ports of `tests/test_unpriv.py`, `tests/test_selfdrop.py` and the
//! executor/privilege halves of `tests/test_runas.py`.
//!
//! A custom harness (`harness = false`) rather than libtest, for one
//! reason: capabilities and `prctl` flags are per *thread*, and libtest
//! runs every test on a spawned thread, so a probe that changes them there
//! would not change what `/proc/self/status` (the thread-group leader)
//! reports. Each identity-changing scenario therefore runs in a fresh copy
//! of this executable (`GK_PROBE=<name>`), on its main thread, exactly as
//! the Python tests ran each in a fresh interpreter. Tests that need
//! privilege skip cleanly when the suite does not run as root.
//!
//! The `__unpriv` and `__runas` hidden entries are reached through the real
//! `gatekeeper` binary (`CARGO_BIN_EXE_gatekeeper`).

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, Output, Stdio};

use gatekeeper::execute::file::{self, FileCall};
use gatekeeper::execute::local;
use gatekeeper::privdrop::{self, EXIT_NOT_EXECUTABLE, EXIT_NOT_FOUND, MARKER};
use gatekeeper::runas::{self, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_SETGID, CAP_SETUID};

const GATEKEEPER: &str = env!("CARGO_BIN_EXE_gatekeeper");

/// A capability set with exactly the two `run_as` needs.
const SETID: u64 = (1 << CAP_SETUID) | (1 << CAP_SETGID);
const DAC_CAPS: u64 = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_DAC_READ_SEARCH);

/// A uid that exists in no image's passwd file.
const DROP_UID: u32 = 568;

// -- harness ----------------------------------------------------------------

struct Skip(&'static str);

fn skip(reason: &'static str) -> ! {
    std::panic::panic_any(Skip(reason))
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn needs_root() {
    if !is_root() {
        skip("a real privilege drop needs a privileged process");
    }
}

type Case = (&'static str, fn());

fn main() {
    privdrop::set_self_exe(GATEKEEPER);
    if let Ok(name) = std::env::var("GK_PROBE") {
        let code = run_probe(&name);
        let _ = std::io::stdout().flush();
        std::process::exit(code);
    }

    let mut filters = Vec::new();
    let mut list = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--list" => list = true,
            "--test-threads" | "--skip" | "--format" | "--color" | "-Z" | "--logfile" => {
                args.next();
            }
            a if a.starts_with('-') => {}
            a => filters.push(a.to_string()),
        }
    }
    let cases: Vec<&Case> =
        CASES.iter().filter(|(name, _)| filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str()))).collect();
    if list {
        for (name, _) in &cases {
            println!("{name}: test");
        }
        return;
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.payload().downcast_ref::<Skip>().is_none() {
            default_hook(info);
        }
    }));

    println!("\nrunning {} tests", cases.len());
    let (mut passed, mut skipped, mut failed) = (0, 0, Vec::new());
    for (name, case) in cases {
        match std::panic::catch_unwind(case) {
            Ok(()) => {
                passed += 1;
                println!("test {name} ... ok");
            }
            Err(payload) => {
                if let Some(Skip(reason)) = payload.downcast_ref::<Skip>() {
                    skipped += 1;
                    println!("test {name} ... skipped ({reason})");
                } else {
                    failed.push(*name);
                    println!("test {name} ... FAILED");
                }
            }
        }
    }
    println!(
        "\ntest result: {}. {passed} passed; {} failed; {skipped} skipped",
        if failed.is_empty() { "ok" } else { "FAILED" },
        failed.len()
    );
    if !failed.is_empty() {
        println!("failures: {failed:?}");
        std::process::exit(101);
    }
}

/// Runs `name` in a fresh copy of this executable.
fn probe(name: &str, env: &[(&str, String)]) -> Output {
    probe_with_input(name, env, None)
}

fn probe_with_input(name: &str, env: &[(&str, String)], input: Option<&str>) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.env("GK_PROBE", name).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    command.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = command.spawn().unwrap();
    if let Some(text) = input {
        child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[track_caller]
fn assert_ok(out: &Output) {
    assert!(out.status.success(), "probe failed: {:?}\nstdout: {}\nstderr: {}", out.status, text(&out.stdout), text(&out.stderr));
}

fn arg(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

fn nobody() -> (u32, u32) {
    match runas::resolve_run_as("nobody") {
        Ok((uid, gid, _)) => (uid, gid),
        Err(_) => skip("no 'nobody' account in this environment"),
    }
}

fn me() -> String {
    unsafe { format!("{}:{}", libc::geteuid(), libc::getegid()) }
}

/// A temp dir whose ancestors up to /tmp are traversable (`_traversable`).
fn tmp_root() -> (tempfile::TempDir, String) {
    let dir = tempfile::Builder::new().prefix("gk-priv").tempdir_in("/tmp").unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap().to_string_lossy().into_owned();
    let mut current = std::path::PathBuf::from(&root);
    while current != std::path::Path::new("/") && current != std::path::Path::new("/tmp") {
        let mode = std::fs::metadata(&current).unwrap().permissions().mode();
        let _ = std::fs::set_permissions(&current, std::fs::Permissions::from_mode(mode | 0o111));
        current.pop();
    }
    (dir, root)
}

fn chmod(path: &str, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn chown(path: &str, uid: u32, gid: u32) {
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).unwrap();
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
}

fn file_call(operation: &str, path: &str, root: &str, run_as: Option<&str>) -> FileCall {
    FileCall {
        operation: operation.into(),
        path: path.into(),
        path_roots: vec![root.into()],
        timeout_seconds: 30,
        max_output_bytes: 65536,
        run_as: run_as.map(str::to_string),
        ..Default::default()
    }
}

fn status_field(status: &str, field: &str) -> String {
    status
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{field}:")))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

fn status_hex(status: &str, field: &str) -> u64 {
    u64::from_str_radix(&status_field(status, field), 16).unwrap()
}

/// `sorted(capability_sets().items())` as the probes print it.
fn caps_line() -> String {
    runas::capability_sets()
        .unwrap()
        .iter()
        .map(|(k, v)| format!("{k}={v:x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_caps(line: &str) -> HashMap<String, u64> {
    line.trim()
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), u64::from_str_radix(v, 16).unwrap()))
        .collect()
}

// -- probe-side building blocks --------------------------------------------

fn setres(uid: u32, gid: u32) {
    unsafe {
        assert_eq!(libc::setresgid(gid, gid, gid), 0);
        assert_eq!(libc::setresuid(uid, uid, uid), 0);
    }
}

fn setgroups(groups: &[u32]) {
    assert_eq!(unsafe { libc::setgroups(groups.len(), groups.as_ptr()) }, 0);
}

fn getgroups() -> Vec<u32> {
    let mut groups = vec![0u32; 256];
    let n = unsafe { libc::getgroups(256, groups.as_mut_ptr()) };
    groups.truncate(n as usize);
    groups.sort_unstable();
    groups
}

fn ids_line() -> String {
    format!("{} {}", runas::fmt_ids(runas::getresuid()), runas::fmt_ids(runas::getresgid()))
}

/// `no-new-privileges: true`, as the container sets it.
fn under_nnp() {
    runas::prctl(38, 1, 0, 0, 0).unwrap();
}

/// Unprivileged but capable: KEEPCAPS across a drop to uid 1, the two
/// capabilities re-raised into effective (`_KEEP_CAPS_AND_DROP_TO`).
fn keep_caps_and_drop_to_one() {
    runas::capset(SETID, SETID, SETID).unwrap();
    runas::prctl(8, 1, 0, 0, 0).unwrap();
    setres(1, 1);
    runas::capset(SETID, SETID, SETID).unwrap();
}

/// ...and raised into the ambient set, which survives an execve
/// (`_AMBIENT_PREAMBLE`).
fn ambient_preamble() {
    keep_caps_and_drop_to_one();
    for cap in [CAP_SETUID, CAP_SETGID] {
        runas::prctl(47, 2, cap as u64, 0, 0).unwrap();
    }
}

/// `cap_drop: ALL` + `cap_add: [SETUID, SETGID]`: everything else out of
/// the bounding set, then the two in effective and permitted.
fn cap_drop_all() {
    for cap in 0..41u64 {
        if cap != CAP_SETGID as u64 && cap != CAP_SETUID as u64 {
            let _ = runas::prctl(24, cap, 0, 0, 0);
        }
    }
    runas::capset(SETID, SETID, 0).unwrap();
}

fn execv(argv: &[&str]) -> ! {
    let c: Vec<std::ffi::CString> = argv.iter().map(|a| std::ffi::CString::new(*a).unwrap()).collect();
    let mut ptrs: Vec<*const libc::c_char> = c.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let _ = std::io::stdout().flush();
    unsafe { libc::execv(ptrs[0], ptrs.as_ptr()) };
    panic!("execv failed: {}", std::io::Error::last_os_error());
}

fn run_probe(name: &str) -> i32 {
    match name {
        // -- _unpriv
        "ambient_then_cat" => {
            ambient_preamble();
            execv(&["/bin/cat", "/proc/self/status"]);
        }
        "ambient_then_wrapper_cat" => {
            ambient_preamble();
            execv(&[GATEKEEPER, "__unpriv", "/bin/cat", "/proc/self/status"]);
        }
        "ambient_wrapper_drop_fails" => {
            ambient_preamble();
            let argv = vec!["/bin/echo".to_string(), "should not run".to_string()];
            let code = privdrop::unpriv_main_with(&argv, || Ok(()));
            println!("exit {code}");
        }
        // -- _selfdrop
        "target_unset" => {
            let before = ids_line();
            assert_eq!(privdrop::configured_target(), None);
            assert_eq!(ids_line(), before);
            println!("unchanged");
        }
        "drop_to_root" => match privdrop::drop_privileges("0:0") {
            Err(e) => println!("{e}"),
            Ok(_) => println!("dropped?!"),
        },
        "already_unprivileged" => {
            if is_root() {
                setres(65534, 65534);
            }
            match privdrop::drop_privileges(&format!("{DROP_UID}:{DROP_UID}")) {
                Err(e) => println!("refused: {e}"),
                Ok(_) => println!("dropped?!"),
            }
        }
        "drop_and_report" => {
            if arg("GK_NNP") == "1" {
                under_nnp();
            }
            privdrop::drop_privileges(&format!("{DROP_UID}:{DROP_UID}")).unwrap();
            println!("{}", ids_line());
            println!("{}", caps_line());
        }
        "drop_then_cat" => {
            under_nnp();
            privdrop::drop_privileges(&format!("{DROP_UID}:{DROP_UID}")).unwrap();
            execv(&["/bin/cat", "/proc/self/status"]);
        }
        "capless_root_drop" => {
            runas::clear_capabilities().unwrap();
            assert!(is_root());
            match privdrop::drop_privileges(&format!("{DROP_UID}:{DROP_UID}")) {
                Err(e) => println!("refused: {e}"),
                Ok(_) => println!("dropped?!"),
            }
            println!("still root: {}", is_root());
        }
        "drop_then_discard" => {
            privdrop::drop_privileges(&format!("{DROP_UID}:{DROP_UID}")).unwrap();
            privdrop::discard_capabilities().unwrap();
            println!("{}", caps_line());
            println!("{}", ids_line());
        }
        "drop_then_file" => {
            under_nnp();
            privdrop::drop_privileges(&format!("{DROP_UID}:{DROP_UID}")).unwrap();
            assert_eq!(unsafe { libc::geteuid() }, DROP_UID);
            let run_as = arg("GK_RUN_AS");
            let mut call = file_call(&arg("GK_OP"), &arg("GK_PATH"), &arg("GK_ROOT"), (!run_as.is_empty()).then_some(run_as.as_str()));
            call.content = Some("written".into());
            call.idempotent = true;
            let result = block_on(file::run(&call));
            println!("outcome {} {:?} {}", result.outcome, result.stdout, result.stderr.replace('\n', " "));
        }
        "groups_across_drop" => {
            let groups: Vec<u32> = arg("GK_GROUPS").split(',').filter(|s| !s.is_empty()).map(|s| s.parse().unwrap()).collect();
            setgroups(&groups);
            privdrop::drop_privileges(&format!("{DROP_UID}:{DROP_UID}")).unwrap();
            println!("{:?}", getgroups());
        }
        "drop_with_thread" => {
            let handle = std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_millis(300)));
            match privdrop::drop_privileges(&format!("{DROP_UID}:{DROP_UID}")) {
                Err(e) => println!("refused: {e}"),
                Ok(_) => println!("dropped?!"),
            }
            handle.join().unwrap();
            println!("still root: {}", is_root());
            match privdrop::discard_capabilities() {
                Err(e) => println!("discard refused: {e}"),
                Ok(()) => println!("discarded?!"),
            }
        }
        "extra_caps" => match privdrop::configured_extra_caps() {
            Ok(bits) => println!("{bits:x}"),
            Err(e) => println!("refused: {e}"),
        },
        // -- _runas
        "become_then_setuid0" => {
            let (uid, gid) = (arg("GK_UID").parse().unwrap(), arg("GK_GID").parse().unwrap());
            if arg("GK_NNP") == "1" {
                assert!(runas::set_no_new_privs());
            }
            runas::become_user(uid, gid, None).unwrap();
            let regained = unsafe { libc::setuid(0) } == 0;
            println!("{} {}", !regained, ids_line());
            println!("{}", runas::effective_capabilities().unwrap());
        }
        "capless_root_can_change_user" => {
            assert!(is_root());
            assert!(runas::can_change_user());
            runas::clear_capabilities().unwrap();
            println!("{} {}", unsafe { libc::geteuid() }, runas::can_change_user());
        }
        "capless_root_become" => {
            runas::clear_capabilities().unwrap();
            match runas::become_user(3001, 3001, None) {
                Err(e) => println!("{e}"),
                Ok(()) => println!("became?!"),
            }
        }
        "non_root_become" => {
            setres(arg("GK_UID").parse().unwrap(), arg("GK_GID").parse().unwrap());
            match runas::become_user(3001, 3001, None) {
                Err(e) => println!("{e}"),
                Ok(()) => println!("became?!"),
            }
        }
        "ambient_become" => {
            let (uid, gid): (u32, u32) = (arg("GK_UID").parse().unwrap(), arg("GK_GID").parse().unwrap());
            if arg("GK_AMBIENT") == "1" {
                ambient_preamble();
                assert_eq!(runas::capability_sets().unwrap()["CapAmb"], SETID);
            } else {
                keep_caps_and_drop_to_one();
            }
            assert_ne!(unsafe { libc::geteuid() }, 0, "probe must be unprivileged");
            assert!(runas::can_change_user(), "ambient CAP_SETUID must count");
            runas::become_user(uid, gid, None).unwrap();
            println!("{}", ids_line());
            println!("{}", caps_line());
        }
        "child_main_nnp" => {
            let code = runas::child_main();
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            eprintln!("{}", status_field(&status, "NoNewPrivs"));
            return code;
        }
        "unprivileged_run_as_root" => {
            let (uid, gid) = (arg("GK_UID").parse().unwrap(), arg("GK_GID").parse().unwrap());
            if is_root() {
                setgroups(&[]);
                setres(uid, gid);
            }
            let call = file_call("read", &arg("GK_PATH"), &arg("GK_ROOT"), Some("0:0"));
            let result = block_on(file::run(&call));
            println!("{} {:?}", result.outcome, result.stdout);
            println!("{}", result.stderr.replace('\n', " "));
        }
        "cap_drop_all_reads" => {
            cap_drop_all();
            for target in arg("GK_TARGETS").split(',') {
                let mut call = file_call("read", &arg("GK_PATH"), &arg("GK_ROOT"), Some(target));
                call.max_output_bytes = 4096;
                call.idempotent = true;
                let result = block_on(file::run(&call));
                println!("{target} {} {}", result.outcome, result.stderr.replace('\n', " "));
            }
        }
        other => {
            eprintln!("unknown probe {other}");
            return 99;
        }
    }
    0
}

// == 1. _unpriv: whether the wrapper is in the way, and that it is transparent

fn wrapper_passes_output_and_exit_code_through() {
    let out = Command::new(GATEKEEPER).args(["__unpriv", "/bin/sh", "-c", "echo out; exit 3"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(text(&out.stdout).trim(), "out");
}

fn binary_keeps_the_pid_the_caller_is_holding() {
    let child = Command::new(GATEKEEPER)
        .args(["__unpriv", "/bin/sh", "-c", "echo $$"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let out = child.wait_with_output().unwrap();
    assert_eq!(text(&out.stdout).trim().parse::<u32>().unwrap(), pid);
}

fn missing_binary_reports_itself_with_the_marker() {
    let out = Command::new(GATEKEEPER).args(["__unpriv", "/nonexistent/binary"]).output().unwrap();
    assert_eq!(out.status.code(), Some(EXIT_NOT_FOUND));
    let err = text(&out.stderr);
    assert!(err.starts_with(MARKER), "{err}");
    assert_eq!(err[MARKER.len()..].trim(), "not found");

    let out = Command::new(GATEKEEPER).arg("__unpriv").output().unwrap();
    assert_eq!(out.status.code(), Some(EXIT_NOT_FOUND));
    assert_eq!(text(&out.stderr), format!("{MARKER}no command given\n"));
}

fn run_local(argv: &[&str], ambient: u64) -> Result<gatekeeper::execute::ExecResult, gatekeeper::errors::Denied> {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    block_on(local::run_with_ambient(&argv, 30, 65536, true, None, None, ambient))
}

fn missing_binary_is_denied_identically() {
    for ambient in [0, SETID] {
        let err = run_local(&["/nonexistent/binary", "arg"], ambient).unwrap_err();
        assert_eq!(err.detail, "Executable not found: /nonexistent/binary", "ambient={ambient}");
    }
}

fn non_executable_file_is_denied_identically() {
    let (_d, root) = tmp_root();
    let target = format!("{root}/not-executable");
    std::fs::write(&target, "#!/bin/sh\necho nope\n").unwrap();
    chmod(&target, 0o644);
    for ambient in [0, SETID] {
        let err = run_local(&[&target], ambient).unwrap_err();
        assert_eq!(err.detail, format!("No permission to execute {target}"), "ambient={ambient}");
    }
}

fn wrapped_run_passes_results_through() {
    let r = run_local(&["/bin/sh", "-c", "echo out; echo err >&2; exit 4"], SETID).unwrap();
    assert_eq!(r.exit_code, Some(4));
    assert_eq!(r.stdout, "out\n");
    assert_eq!(r.stderr, "err\n");
}

// == 1b. _unpriv: that it actually drops

fn without_the_wrapper_a_binary_really_does_inherit_them() {
    needs_root();
    let out = probe("ambient_then_cat", &[]);
    assert_ok(&out);
    assert_eq!(status_hex(&text(&out.stdout), "CapAmb"), SETID);
}

fn the_wrapper_strips_them_before_the_binary_starts() {
    needs_root();
    let out = probe("ambient_then_wrapper_cat", &[]);
    assert_ok(&out);
    let status = text(&out.stdout);
    for field in ["CapAmb", "CapEff", "CapPrm", "CapInh"] {
        assert_eq!(status_hex(&status, field), 0, "{field} survived");
    }
}

fn it_refuses_to_run_the_binary_when_the_drop_did_not_take() {
    needs_root();
    let out = probe("ambient_wrapper_drop_fails", &[]);
    assert_ok(&out);
    let stdout = text(&out.stdout);
    assert!(stdout.contains(&format!("exit {EXIT_NOT_EXECUTABLE}")), "{stdout}");
    assert!(!stdout.contains("should not run"));
    let stderr = text(&out.stderr);
    assert!(stderr.contains(MARKER) && stderr.contains("survived the drop"), "{stderr}");
}

// == 2. _selfdrop

fn nothing_happens_without_the_setting() {
    let out = probe("target_unset", &[("GATEKEEPER_DROP_TO", String::new())]);
    assert_ok(&out);
    assert!(text(&out.stdout).starts_with("unchanged"));
}

fn dropping_to_root_is_refused() {
    let out = probe("drop_to_root", &[]);
    assert_ok(&out);
    assert_eq!(
        text(&out.stdout).trim(),
        "GATEKEEPER_DROP_TO='0:0' resolves to uid 0. This setting exists to give up root, so root is the one value it cannot take."
    );
}

fn an_unprivileged_process_says_so_instead_of_pretending() {
    let out = probe("already_unprivileged", &[]);
    assert_ok(&out);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("refused:") && stdout.contains("already running unprivileged"), "{stdout}");
}

fn drop_report(env: &[(&str, String)]) -> (String, HashMap<String, u64>) {
    let out = probe("drop_and_report", env);
    assert_ok(&out);
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines();
    let ids = lines.next().unwrap().to_string();
    (ids, parse_caps(lines.next().unwrap()))
}

fn the_drop_keeps_exactly_the_two_capabilities() {
    needs_root();
    let (ids, held) = drop_report(&[("GK_NNP", "1".into())]);
    assert_eq!(ids, format!("({0}, {0}, {0}) ({0}, {0}, {0})", DROP_UID));
    for field in ["CapEff", "CapPrm", "CapInh", "CapAmb"] {
        assert_eq!(held[field], SETID, "{field}");
    }
}

fn the_capabilities_survive_an_exec_under_no_new_privs() {
    needs_root();
    let out = probe("drop_then_cat", &[]);
    assert_ok(&out);
    let status = text(&out.stdout);
    assert_eq!(status_field(&status, "NoNewPrivs"), "1");
    assert_eq!(status_hex(&status, "CapEff"), SETID);
    assert_eq!(status_hex(&status, "CapPrm"), SETID);
}

fn root_without_the_capabilities_cannot_drop_and_says_why() {
    needs_root();
    let out = probe("capless_root_drop", &[]);
    assert_ok(&out);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("refused:") && stdout.contains("cap_add: [SETUID, SETGID]"), "{stdout}");
    assert!(stdout.contains("still root: true"));
}

fn discarding_hands_everything_back() {
    needs_root();
    let out = probe("drop_then_discard", &[]);
    assert_ok(&out);
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines();
    let held = parse_caps(lines.next().unwrap());
    assert!(held.values().all(|v| *v == 0), "{held:?}");
    assert!(lines.next().unwrap().starts_with(&format!("({0}, {0}, {0})", DROP_UID)));
}

fn file_after_drop(op: &str, path: &str, root: &str, run_as: &str, env: &[(&str, String)]) -> String {
    let mut all = vec![
        ("GK_OP", op.to_string()),
        ("GK_PATH", path.to_string()),
        ("GK_ROOT", root.to_string()),
        ("GK_RUN_AS", run_as.to_string()),
    ];
    all.extend(env.iter().cloned());
    let out = probe("drop_then_file", &all);
    assert_ok(&out);
    text(&out.stdout)
}

fn run_as_root_writes_as_root_from_a_dropped_server() {
    needs_root();
    let (_d, root) = tmp_root();
    chmod(&root, 0o777);
    let target = format!("{root}/as-root.txt");
    let stdout = file_after_drop("write", &target, &root, "0:0", &[]);
    assert!(stdout.starts_with("outcome ok"), "{stdout}");
    assert_eq!(std::fs::metadata(&target).unwrap().uid(), 0);
}

fn without_run_as_the_server_user_still_writes() {
    needs_root();
    let (_d, root) = tmp_root();
    chmod(&root, 0o777);
    let target = format!("{root}/plain.txt");
    let stdout = file_after_drop("write", &target, &root, "", &[]);
    assert!(stdout.starts_with("outcome ok"), "{stdout}");
    assert_eq!(std::fs::metadata(&target).unwrap().uid(), DROP_UID);
}

fn group_add_survives_the_drop() {
    needs_root();
    let out = probe("groups_across_drop", &[("GK_GROUPS", "0,999".into())]);
    assert_ok(&out);
    assert_eq!(text(&out.stdout).trim(), "[999]");
}

fn root_own_group_is_not_carried_across() {
    needs_root();
    let out = probe("groups_across_drop", &[("GK_GROUPS", "0".into())]);
    assert_ok(&out);
    assert_eq!(text(&out.stdout).trim(), "[]");
}

fn keep_caps_parsing() {
    let run = |value: Option<&str>| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.env("GK_PROBE", "extra_caps").env_remove("GATEKEEPER_KEEP_CAPS");
        if let Some(v) = value {
            command.env("GATEKEEPER_KEEP_CAPS", v);
        }
        text(&command.output().unwrap().stdout).trim().to_string()
    };
    assert_eq!(run(None), "0");
    assert_eq!(run(Some("")), "0");
    let refused = run(Some("NONSENSE"));
    assert!(refused.starts_with("refused:") && refused.contains("NONSENSE"), "{refused}");
    assert_eq!(u64::from_str_radix(&run(Some("CAP_DAC_OVERRIDE,DAC_READ_SEARCH")), 16).unwrap(), DAC_CAPS);
    assert_eq!(u64::from_str_radix(&run(Some(" chown , ,kill ")), 16).unwrap(), 0b100001);
}

fn keep_caps_preserves_extras_in_permitted_inheritable_ambient() {
    needs_root();
    let (ids, held) = drop_report(&[("GK_NNP", "1".into()), ("GATEKEEPER_KEEP_CAPS", "DAC_OVERRIDE,DAC_READ_SEARCH".into())]);
    assert!(ids.starts_with(&format!("({0}, {0}, {0})", DROP_UID)));
    assert_eq!(held["CapEff"], SETID);
    for field in ["CapPrm", "CapInh", "CapAmb"] {
        assert_eq!(held[field], SETID | DAC_CAPS, "{field}");
    }
}

fn keep_caps_extras_survive_exec_into_child() {
    needs_root();
    let out = probe("drop_then_cat", &[("GATEKEEPER_KEEP_CAPS", "DAC_OVERRIDE,DAC_READ_SEARCH".into())]);
    assert_ok(&out);
    let status = text(&out.stdout);
    assert_eq!(status_field(&status, "NoNewPrivs"), "1");
    assert_eq!(status_hex(&status, "CapEff"), SETID | DAC_CAPS);
    assert_eq!(status_hex(&status, "CapPrm"), SETID | DAC_CAPS);
}

fn foreign_file() -> (tempfile::TempDir, String, String) {
    let (dir, root) = tmp_root();
    chmod(&root, 0o777);
    let foreign = format!("{root}/foreign-0600.txt");
    std::fs::write(&foreign, "secret").unwrap();
    chown(&foreign, DROP_UID, DROP_UID);
    chmod(&foreign, 0o600);
    (dir, root, foreign)
}

fn keep_caps_run_as_root_reads_foreign_file() {
    needs_root();
    let (_d, root, foreign) = foreign_file();
    let stdout = file_after_drop("read", &foreign, &root, "0:0", &[("GATEKEEPER_KEEP_CAPS", "DAC_OVERRIDE,DAC_READ_SEARCH".into())]);
    assert!(stdout.contains("outcome ok") && stdout.contains("secret"), "{stdout}");
}

fn without_keep_caps_run_as_root_cannot_read_foreign_file() {
    needs_root();
    let (_d, root, foreign) = foreign_file();
    let stdout = file_after_drop("read", &foreign, &root, "0:0", &[]);
    assert!(stdout.contains("outcome failed") && stdout.contains("Permission denied"), "{stdout}");
}

fn drop_refuses_once_threads_exist() {
    needs_root();
    let out = probe("drop_with_thread", &[]);
    assert_ok(&out);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("before any other thread is started"), "{stdout}");
    assert!(stdout.contains("still root: true"), "{stdout}");
}

// == 3. run_as: the executor path

fn run_file(call: &FileCall) -> gatekeeper::execute::ExecResult {
    block_on(file::run(call))
}

fn run_as_self_round_trips_every_operation() {
    let (_d, root) = tmp_root();
    let me = me();
    let target = format!("{root}/sub/config.yaml");

    let mut c = file_call("write", &target, &root, Some(&me));
    c.content = Some("version: 1\n".into());
    let written = run_file(&c);
    assert_eq!(written.outcome, "ok", "{}", written.stderr);
    assert_eq!(written.stdout, format!("Written 11 bytes to {target}"));
    assert_eq!(written.exit_code, Some(0));

    let mut c = file_call("patch", &target, &root, Some(&me));
    c.old_string = Some("version: 1".into());
    c.new_string = Some("version: 2".into());
    assert_eq!(run_file(&c).outcome, "ok");

    let read = run_file(&file_call("read", &target, &root, Some(&me)));
    assert_eq!(read.outcome, "ok");
    assert!(read.stdout.contains("version: 2"));

    let listed = run_file(&file_call("list", &format!("{root}/sub"), &root, Some(&me)));
    assert_eq!(listed.outcome, "ok");
    assert!(listed.stdout.contains("f config.yaml"));
}

fn run_as_reports_an_ordinary_failure_as_failed() {
    let (_d, root) = tmp_root();
    let r = run_file(&file_call("read", &format!("{root}/missing.txt"), &root, Some(&me())));
    assert_eq!(r.outcome, "failed");
    assert_eq!(r.exit_code, Some(1));
    assert!(r.stderr.to_lowercase().contains("not found"));
}

fn run_as_still_honours_max_output_bytes() {
    let (_d, root) = tmp_root();
    let path = format!("{root}/big.txt");
    std::fs::write(&path, "A".repeat(400)).unwrap();
    let mut c = file_call("read", &path, &root, Some(&me()));
    c.max_output_bytes = 100;
    let r = run_file(&c);
    assert_eq!(r.outcome, "ok");
    assert!(r.truncated);
    assert!(r.stdout.len() <= 100 + "\n... [truncated]".len());
}

fn run_as_does_not_widen_path_roots_or_protected() {
    let (_d, root) = tmp_root();
    let r = run_file(&file_call("read", "/etc/passwd", &root, Some(&me())));
    assert_eq!(r.outcome, "failed");
    assert!(r.stderr.to_lowercase().contains("outside allowed roots"));

    std::fs::create_dir(format!("{root}/gatekeeper")).unwrap();
    let mut c = file_call("read", &format!("{root}/gatekeeper/x.yaml"), &root, Some(&me()));
    c.protected = vec!["gatekeeper".into()];
    let r = run_file(&c);
    assert_eq!(r.outcome, "failed");
    assert!(r.stderr.to_lowercase().contains("protected resource"));
}

fn runas_child(request: &serde_json::Value) -> serde_json::Value {
    let mut child = Command::new(GATEKEEPER)
        .arg("__runas")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(request.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    serde_json::from_slice(&out.stdout).unwrap()
}

fn helper_revalidates_tier1_itself() {
    let (_d, root) = tmp_root();
    let payload = runas_child(&serde_json::json!({
        "run_as": me(), "operation": "read", "path": "/etc/passwd",
        "path_roots": [root], "protected": [], "max_output_bytes": 4096,
    }));
    assert_eq!(payload["outcome"], "failed");
    assert!(payload["stderr"].as_str().unwrap().to_lowercase().contains("outside allowed roots"));
    assert!(!payload["stdout"].as_str().unwrap().contains("root:"));
}

fn helper_reports_malformed_requests() {
    let mut child = Command::new(GATEKEEPER).arg("__runas").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"[1, 2]").unwrap();
    let out = child.wait_with_output().unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["stderr"], "malformed run_as request: request must be a JSON object");
    assert_eq!(payload["exit_code"], 1);

    let payload = runas_child(&serde_json::json!({"operation": "read"}));
    assert_eq!(payload["stderr"], "'run_as'");
    let payload = runas_child(&serde_json::json!({"run_as": me(), "path": "/tmp", "path_roots": ["/tmp"]}));
    assert_eq!(payload["stderr"], "'operation'");
}

fn helper_result_is_python_json() {
    let (_d, root) = tmp_root();
    std::fs::write(format!("{root}/x.txt"), "d\u{e4}ta").unwrap();
    let mut child = Command::new(GATEKEEPER).arg("__runas").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let request = serde_json::json!({
        "run_as": me(), "operation": "read", "path": format!("{root}/x.txt"),
        "path_roots": [root], "protected": [], "max_output_bytes": 4096,
    });
    child.stdin.take().unwrap().write_all(request.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        text(&out.stdout),
        "{\"outcome\": \"ok\", \"exit_code\": 0, \"stdout\": \"d\\u00e4ta\", \"stderr\": \"\", \"truncated\": false}"
    );
}

fn run_as_timeouts() {
    let (_d, root) = tmp_root();
    let mut c = file_call("write", &format!("{root}/x.txt"), &root, Some(&me()));
    c.content = Some("hi".into());
    c.timeout_seconds = 0;
    c.idempotent = false;
    let r = run_file(&c);
    assert_eq!(r.outcome, "unknown");
    assert_eq!(
        r.stderr,
        "Timeout of 0s exceeded, run_as helper killed. The outcome is UNKNOWN: the operation may have \
         completed. Do not retry without checking the state first."
    );

    let mut c = file_call("read", &format!("{root}/x.txt"), &root, Some(&me()));
    c.timeout_seconds = 0;
    c.idempotent = true;
    let r = run_file(&c);
    assert_eq!(r.outcome, "failed");
    assert_eq!(r.stderr, "Timeout of 0s exceeded, run_as helper killed.");
}

// == 4. run_as: the privilege boundary

fn unprivileged_process_refuses_rather_than_pretends() {
    // Python skipped this on root; here a root suite drops to `nobody`
    // first, so it runs either way.
    let (uid, gid) = nobody();
    let (_d, root) = tmp_root();
    chmod(&root, 0o755);
    let path = format!("{root}/x.txt");
    std::fs::write(&path, "data").unwrap();
    chmod(&path, 0o644);
    let out = probe(
        "unprivileged_run_as_root",
        &[("GK_UID", uid.to_string()), ("GK_GID", gid.to_string()), ("GK_PATH", path), ("GK_ROOT", root)],
    );
    assert_ok(&out);
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("failed \"\""), "{stdout}");
    assert!(stdout.contains("no privilege to change user"), "{stdout}");
    assert!(stdout.contains("not running as root"), "{stdout}");
}

fn the_written_file_belongs_to_the_run_as_user() {
    needs_root();
    let (uid, gid) = nobody();
    let (_d, root) = tmp_root();
    chmod(&root, 0o777);
    let target = format!("{root}/owned.txt");
    let mut c = file_call("write", &target, &root, Some(&format!("{uid}:{gid}")));
    c.content = Some("written by nobody".into());
    let r = run_file(&c);
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
    let meta = std::fs::metadata(&target).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (uid, gid));
}

fn the_drop_actually_removes_authority() {
    needs_root();
    let (uid, gid) = nobody();
    let (_d, root) = tmp_root();
    let locked = format!("{root}/root-only");
    std::fs::create_dir(&locked).unwrap();
    chmod(&root, 0o755);
    chmod(&locked, 0o700);
    let target = format!("{locked}/x.txt");

    let mut c = file_call("write", &target, &root, None);
    c.content = Some("root wrote this".into());
    assert_eq!(run_file(&c).outcome, "ok");

    let r = run_file(&file_call("read", &target, &root, Some(&format!("{uid}:{gid}"))));
    assert_eq!(r.outcome, "failed");
    assert!(r.stderr.to_lowercase().contains("permission denied"));
    assert!(!r.stdout.contains("root wrote this"));
    // A denial for a non-root target stays an ordinary one.
    assert!(r.stderr.contains(&format!("ran as uid={uid} gid={gid}")), "{}", r.stderr);
    assert!(r.stderr.contains("traversable"));
    assert!(!r.stderr.contains("NOT above file permissions"));
}

fn run_as_reaches_a_directory_the_container_user_cannot() {
    needs_root();
    let (uid, gid) = nobody();
    let (_d, root) = tmp_root();
    let theirs = format!("{root}/theirs");
    std::fs::create_dir(&theirs).unwrap();
    let secret = format!("{theirs}/agent.yaml");
    std::fs::write(&secret, "model: hermes\n").unwrap();
    chown(&secret, uid, gid);
    chown(&theirs, uid, gid);
    chmod(&theirs, 0o700);
    let r = run_file(&file_call("read", &secret, &root, Some(&format!("{uid}:{gid}"))));
    assert_eq!(r.outcome, "ok", "{}", r.stderr);
    assert!(r.stdout.contains("model: hermes"));
}

fn root_is_not_regainable_after_the_drop() {
    needs_root();
    let (uid, gid) = nobody();
    for nnp in ["0", "1"] {
        let out = probe("become_then_setuid0", &[("GK_UID", uid.to_string()), ("GK_GID", gid.to_string()), ("GK_NNP", nnp.into())]);
        assert_ok(&out);
        let stdout = text(&out.stdout);
        let mut lines = stdout.lines();
        assert_eq!(lines.next().unwrap(), format!("true ({0}, {0}, {0}) ({1}, {1}, {1})", uid, gid));
        // The drop leaves no capabilities behind.
        assert_eq!(lines.next().unwrap(), "0");
    }
}

fn an_unknown_run_as_user_fails_the_call_and_reads_nothing() {
    needs_root();
    let (_d, root) = tmp_root();
    let path = format!("{root}/x.txt");
    std::fs::write(&path, "data").unwrap();
    let r = run_file(&file_call("read", &path, &root, Some("nosuchuser-cbc1f7")));
    assert_eq!(r.outcome, "failed");
    assert_eq!(
        r.stderr,
        "'run_as' user 'nosuchuser-cbc1f7' does not exist in this container's passwd database. \
         Host accounts are not visible inside the image -- use the numeric 'uid:gid' form for those."
    );
    assert!(!r.stdout.contains("data"));
}

// == 5. run_as: what the privilege actually is

fn the_effective_capability_set_is_read_from_procfs() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    assert_eq!(runas::effective_capabilities(), Some(status_hex(&status, "CapEff")));
    assert_eq!(runas::bounding_capabilities(), Some(status_hex(&status, "CapBnd")));
    let expected = status_hex(&status, "CapEff") & DAC_CAPS != 0;
    assert_eq!(runas::bypasses_file_permissions(), Some(expected));
    assert_eq!(runas::child_bypasses_file_permissions(), Some(status_hex(&status, "CapAmb") & DAC_CAPS != 0));
}

fn a_capable_root_process_can_change_user() {
    needs_root();
    assert!(runas::can_change_user());
}

fn root_without_the_capabilities_cannot_change_user() {
    needs_root();
    let out = probe("capless_root_can_change_user", &[]);
    assert_ok(&out);
    assert_eq!(text(&out.stdout).trim(), "0 false");
}

fn the_message_for_a_capability_less_root_names_cap_drop() {
    needs_root();
    let out = probe("capless_root_become", &[]);
    assert_ok(&out);
    let message = text(&out.stdout);
    assert!(message.contains("no privilege to change user"), "{message}");
    assert!(message.contains("cap_drop: ALL"));
    assert!(message.contains("runs as root"));
    assert!(message.contains(
        "  docker inspect -f '{{.Config.User}} {{.HostConfig.CapAdd}}' gatekeeper\n  docker exec gatekeeper grep -E '^(Uid|CapEff):' /proc/self/status\nSee docs/DEPLOYMENT.md."
    ));
    assert!(message.starts_with(
        "cannot run this file operation as uid=3001 gid=3001: gatekeeper runs as uid=0 gid=0 with CapEff=0000000000000000 and holds no privilege to change user."
    ));
}

fn the_message_for_a_non_root_container_names_the_user_directive() {
    needs_root();
    let (uid, gid) = nobody();
    let out = probe("non_root_become", &[("GK_UID", uid.to_string()), ("GK_GID", gid.to_string())]);
    assert_ok(&out);
    let message = text(&out.stdout);
    assert!(message.contains("no privilege to change user"), "{message}");
    assert!(message.contains("user: \"0:0\""));
    assert!(message.contains("not running as root"));
    assert!(message.contains("not 'cap_add'"));
}

fn ambient_capabilities_are_enough_without_being_root() {
    needs_root();
    let (uid, gid) = nobody();
    for ambient in ["0", "1"] {
        let out = probe("ambient_become", &[("GK_UID", uid.to_string()), ("GK_GID", gid.to_string()), ("GK_AMBIENT", ambient.into())]);
        assert_ok(&out);
        let stdout = text(&out.stdout);
        let mut lines = stdout.lines();
        assert_eq!(lines.next().unwrap(), format!("({0}, {0}, {0}) ({1}, {1}, {1})", uid, gid));
        // Every set emptied, not only the effective one.
        let after = parse_caps(lines.next().unwrap());
        assert!(after.len() >= 4 && after.values().all(|v| *v == 0), "{after:?}");
    }
}

fn the_helper_child_forbids_gaining_privilege_through_exec() {
    let (_d, root) = tmp_root();
    let path = format!("{root}/x.txt");
    std::fs::write(&path, "data").unwrap();
    let request = serde_json::json!({
        "run_as": me(), "operation": "read", "path": path,
        "path_roots": [root], "protected": [], "max_output_bytes": 4096,
    });
    let out = probe_with_input("child_main_nnp", &[], Some(&request.to_string()));
    assert_ok(&out);
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["outcome"], "ok");
    assert!(text(&out.stderr).trim().ends_with('1'), "NoNewPrivs must be 1");
}

// == 7. When root is not above file permissions

fn private_compose(uid: u32, gid: u32) -> (tempfile::TempDir, String, String) {
    let (dir, root) = tmp_root();
    chmod(&root, 0o755);
    let secret = format!("{root}/compose.yaml");
    std::fs::write(&secret, "services: {}\n").unwrap();
    chown(&secret, uid, gid);
    chmod(&secret, 0o600);
    (dir, root, secret)
}

fn run_as_root_cannot_read_another_users_private_file() {
    needs_root();
    let (uid, gid) = nobody();
    let (_d, root, secret) = private_compose(uid, gid);
    let out = probe("cap_drop_all_reads", &[("GK_PATH", secret), ("GK_ROOT", root), ("GK_TARGETS", format!("root,{uid}:{gid}"))]);
    assert_ok(&out);
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines();
    let as_root = lines.next().unwrap();
    let as_owner = lines.next().unwrap();
    assert!(as_root.starts_with("root failed") && as_root.contains("Permission denied"), "{as_root}");
    assert!(as_owner.starts_with(&format!("{uid}:{gid} ok")), "{as_owner}");
    // The denial names the uid and the missing capability.
    assert!(as_root.contains("ran as uid=0 gid=0"));
    assert!(as_root.contains("run_as: 'root'"));
    assert!(as_root.contains("NOT above file permissions"));
    assert!(as_root.contains("CAP_DAC_OVERRIDE"));
    assert!(as_root.contains("'cap_drop: ALL' removed it from the bounding set"), "{as_root}");
}

fn explain_permission_denied_texts() {
    assert_eq!(
        runas::explain_permission_denied(65534, 65534, "65534:65534"),
        " The operation ran as uid=65534 gid=65534 (run_as: '65534:65534'). That is the user the toolkit \
         asked for, so this is an ordinary permission problem: check the file's mode and owner, and that \
         every parent directory is traversable (+x) by that uid -- a denial naming the file is often a \
         directory above it."
    );
    let as_root = runas::explain_permission_denied(0, 0, "root");
    if runas::bypasses_file_permissions() == Some(true) {
        assert!(as_root.contains("It holds CAP_DAC_OVERRIDE, so this is not a file-mode problem"));
    } else {
        assert!(as_root.contains("NOT above file permissions"));
    }
}

const CASES: &[Case] = &[
    ("unpriv::wrapper_passes_output_and_exit_code_through", wrapper_passes_output_and_exit_code_through),
    ("unpriv::binary_keeps_the_pid_the_caller_is_holding", binary_keeps_the_pid_the_caller_is_holding),
    ("unpriv::missing_binary_reports_itself_with_the_marker", missing_binary_reports_itself_with_the_marker),
    ("unpriv::missing_binary_is_denied_identically", missing_binary_is_denied_identically),
    ("unpriv::non_executable_file_is_denied_identically", non_executable_file_is_denied_identically),
    ("unpriv::wrapped_run_passes_results_through", wrapped_run_passes_results_through),
    ("unpriv::without_the_wrapper_a_binary_really_does_inherit_them", without_the_wrapper_a_binary_really_does_inherit_them),
    ("unpriv::the_wrapper_strips_them_before_the_binary_starts", the_wrapper_strips_them_before_the_binary_starts),
    ("unpriv::it_refuses_to_run_the_binary_when_the_drop_did_not_take", it_refuses_to_run_the_binary_when_the_drop_did_not_take),
    ("selfdrop::nothing_happens_without_the_setting", nothing_happens_without_the_setting),
    ("selfdrop::dropping_to_root_is_refused", dropping_to_root_is_refused),
    ("selfdrop::an_unprivileged_process_says_so_instead_of_pretending", an_unprivileged_process_says_so_instead_of_pretending),
    ("selfdrop::the_drop_keeps_exactly_the_two_capabilities", the_drop_keeps_exactly_the_two_capabilities),
    ("selfdrop::the_capabilities_survive_an_exec_under_no_new_privs", the_capabilities_survive_an_exec_under_no_new_privs),
    ("selfdrop::root_without_the_capabilities_cannot_drop_and_says_why", root_without_the_capabilities_cannot_drop_and_says_why),
    ("selfdrop::discarding_hands_everything_back", discarding_hands_everything_back),
    ("selfdrop::run_as_root_writes_as_root_from_a_dropped_server", run_as_root_writes_as_root_from_a_dropped_server),
    ("selfdrop::without_run_as_the_server_user_still_writes", without_run_as_the_server_user_still_writes),
    ("selfdrop::group_add_survives_the_drop", group_add_survives_the_drop),
    ("selfdrop::root_own_group_is_not_carried_across", root_own_group_is_not_carried_across),
    ("selfdrop::keep_caps_parsing", keep_caps_parsing),
    ("selfdrop::keep_caps_preserves_extras_in_permitted_inheritable_ambient", keep_caps_preserves_extras_in_permitted_inheritable_ambient),
    ("selfdrop::keep_caps_extras_survive_exec_into_child", keep_caps_extras_survive_exec_into_child),
    ("selfdrop::keep_caps_run_as_root_reads_foreign_file", keep_caps_run_as_root_reads_foreign_file),
    ("selfdrop::without_keep_caps_run_as_root_cannot_read_foreign_file", without_keep_caps_run_as_root_cannot_read_foreign_file),
    ("selfdrop::drop_refuses_once_threads_exist", drop_refuses_once_threads_exist),
    ("runas::run_as_self_round_trips_every_operation", run_as_self_round_trips_every_operation),
    ("runas::run_as_reports_an_ordinary_failure_as_failed", run_as_reports_an_ordinary_failure_as_failed),
    ("runas::run_as_still_honours_max_output_bytes", run_as_still_honours_max_output_bytes),
    ("runas::run_as_does_not_widen_path_roots_or_protected", run_as_does_not_widen_path_roots_or_protected),
    ("runas::helper_revalidates_tier1_itself", helper_revalidates_tier1_itself),
    ("runas::helper_reports_malformed_requests", helper_reports_malformed_requests),
    ("runas::helper_result_is_python_json", helper_result_is_python_json),
    ("runas::run_as_timeouts", run_as_timeouts),
    ("runas::unprivileged_process_refuses_rather_than_pretends", unprivileged_process_refuses_rather_than_pretends),
    ("runas::the_written_file_belongs_to_the_run_as_user", the_written_file_belongs_to_the_run_as_user),
    ("runas::the_drop_actually_removes_authority", the_drop_actually_removes_authority),
    ("runas::run_as_reaches_a_directory_the_container_user_cannot", run_as_reaches_a_directory_the_container_user_cannot),
    ("runas::root_is_not_regainable_after_the_drop", root_is_not_regainable_after_the_drop),
    ("runas::an_unknown_run_as_user_fails_the_call_and_reads_nothing", an_unknown_run_as_user_fails_the_call_and_reads_nothing),
    ("runas::the_effective_capability_set_is_read_from_procfs", the_effective_capability_set_is_read_from_procfs),
    ("runas::a_capable_root_process_can_change_user", a_capable_root_process_can_change_user),
    ("runas::root_without_the_capabilities_cannot_change_user", root_without_the_capabilities_cannot_change_user),
    ("runas::the_message_for_a_capability_less_root_names_cap_drop", the_message_for_a_capability_less_root_names_cap_drop),
    ("runas::the_message_for_a_non_root_container_names_the_user_directive", the_message_for_a_non_root_container_names_the_user_directive),
    ("runas::ambient_capabilities_are_enough_without_being_root", ambient_capabilities_are_enough_without_being_root),
    ("runas::the_helper_child_forbids_gaining_privilege_through_exec", the_helper_child_forbids_gaining_privilege_through_exec),
    ("runas::run_as_root_cannot_read_another_users_private_file", run_as_root_cannot_read_another_users_private_file),
    ("runas::explain_permission_denied_texts", explain_permission_denied_texts),
];
