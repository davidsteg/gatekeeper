//! Privilege handling outside the `run_as` child (port of `_unpriv.py` and
//! `_selfdrop.py`), plus the hidden entry points this binary re-executes
//! itself through.
//!
//! Three shapes of the same trade live in this crate:
//!
//! - [`crate::runas`] raises one `file` operation's authority, in a child
//!   (`__runas`);
//! - [`unpriv_main`] lowers a spawned `local` binary's, by clearing the
//!   ambient capabilities this process may hold before `execv`ing it
//!   (`__unpriv`, Python's `python -m gatekeeper._unpriv`);
//! - [`drop_privileges`] decides what the *server itself* is for its whole
//!   life: started as root with `cap_add: [SETUID, SETGID]`, it becomes an
//!   unprivileged uid while keeping exactly those two capabilities.
//!
//! ## `__unpriv`: why a separate process, and why `execv`
//!
//! A `preexec_fn`-style hook would run between `fork` and `exec` in a
//! process that runs an async runtime and threads -- the window `run_as`
//! uses `fork`+`exec` to stay out of. The wrapper is past that window: an
//! ordinary process that empties its own capability sets and then `execv`s
//! the real binary over itself, keeping the pid `execute::local::run` is
//! holding, so timeout, process-group kill and output streaming behave as
//! without it. It never runs the binary anyway when the drop fails: a
//! `docker` that silently kept CAP_SETUID looks identical to a successful
//! call from the outside.
//!
//! ## `drop_privileges`: the steps, and why each is not optional
//!
//! 1. `PR_SET_KEEPCAPS(1)` -- without it the kernel empties the permitted
//!    set the moment euid leaves 0.
//! 2. Supplementary groups, then `setresgid`, then `setresuid`.
//! 3. `capset` back to the kept set -- the uid change preserves *permitted*
//!    under KEEPCAPS but clears *effective*. Inheritable is set at the same
//!    time, which makes step 4 legal.
//! 4. `PR_CAP_AMBIENT_RAISE` for each kept capability -- the ambient set is
//!    the only one that survives the `run_as` helper's `execve`.
//!
//! **What this costs.** A process holding `CAP_SETUID` can call
//! `setuid(0)` whenever it likes; this is not a privilege boundary against
//! a compromised gatekeeper. What it buys is file ownership, a smaller
//! blast radius for ordinary bugs, and a capability set of exactly two
//! entries instead of root's full complement.
//!
//! **`GATEKEEPER_KEEP_CAPS`** names extra capabilities (Docker `cap_add`
//! notation, `CAP_` prefix optional) to carry through the drop in the
//! permitted, inheritable and ambient sets but *not* the effective set: the
//! server cannot use them, the `run_as` child inherits them.
//!
//! Off unless `GATEKEEPER_DROP_TO` is set.
//!
//! PORT NOTE: capabilities and `prctl` flags are per *thread*, while glibc
//! applies `setres[ug]id` to every thread. [`drop_privileges`] and
//! [`discard_capabilities`] must therefore run while the process is still
//! single-threaded -- before the tokio runtime starts -- and refuse
//! otherwise. Python had one thread at that point and no such check.

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::pyfmt::repr_str;
use crate::runas::{
    capability_bit, capability_sets, capset, clear_capabilities, fmt_ids, getresgid, getresuid,
    prctl, resolve_run_as, CAPABILITY_NAMES, CAP_SETGID, CAP_SETUID,
};

// -- Hidden entry points ----------------------------------------------------

/// First argument that turns this binary into the capability-clearing
/// wrapper for a `local` binary (Python: `python -m gatekeeper._unpriv`).
pub const UNPRIV_ENTRY: &str = "__unpriv";

/// First argument that turns this binary into the `run_as` helper child
/// (Python: `python -m gatekeeper._runas`).
pub const RUNAS_ENTRY: &str = "__runas";

/// Called first thing in `main` with the full argv. Returns the exit code
/// when `argv[1]` is one of the hidden entries, `None` otherwise (the CLI
/// proper then runs).
pub fn hidden_entry(args: &[String]) -> Option<i32> {
    match args.get(1).map(String::as_str) {
        Some(UNPRIV_ENTRY) => Some(unpriv_main(&args[2..])),
        Some(RUNAS_ENTRY) => Some(crate::runas::child_main()),
        _ => None,
    }
}

static SELF_EXE: OnceLock<PathBuf> = OnceLock::new();

/// The executable the hidden entries are reached through: this binary
/// (`std::env::current_exe()`), where Python used `sys.executable -m`.
pub fn self_exe() -> std::io::Result<PathBuf> {
    match SELF_EXE.get() {
        Some(path) => Ok(path.clone()),
        None => std::env::current_exe(),
    }
}

/// Points [`self_exe`] at another gatekeeper binary. For tests, whose own
/// executable is the test harness rather than `gatekeeper`; first call
/// wins.
#[doc(hidden)]
pub fn set_self_exe(path: impl Into<PathBuf>) {
    let _ = SELF_EXE.set(path.into());
}

// -- __unpriv ----------------------------------------------------------------

/// Prefix for anything the wrapper reports on stderr. Only reachable when
/// `execv` did not happen, which is what lets `execute::local::run` treat a
/// line starting with this as its own.
pub const MARKER: &str = "gatekeeper._unpriv: ";

/// Shell convention, reserved here for the same two meanings.
pub const EXIT_NOT_EXECUTABLE: i32 = 126;
pub const EXIT_NOT_FOUND: i32 = 127;

fn report(message: &str) {
    use std::io::Write;
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(format!("{MARKER}{message}\n").as_bytes());
    let _ = err.flush();
}

/// Clears the inherited capabilities, then becomes `argv` (`_unpriv._main`).
pub fn unpriv_main(argv: &[String]) -> i32 {
    unpriv_main_with(argv, clear_capabilities)
}

/// [`unpriv_main`] with the clearing step injectable, so a test can make
/// the drop silently fail and watch the wrapper refuse.
#[doc(hidden)]
pub fn unpriv_main_with(argv: &[String], clear: impl FnOnce() -> Result<(), String>) -> i32 {
    if argv.is_empty() {
        report("no command given");
        return EXIT_NOT_FOUND;
    }

    if let Err(exc) = clear() {
        report(&format!("cannot drop inherited capabilities: {exc}"));
        return EXIT_NOT_EXECUTABLE;
    }

    // Verify rather than assume.
    let remaining: Vec<(String, u64)> =
        capability_sets().unwrap_or_default().into_iter().filter(|(_, v)| *v != 0).collect();
    if !remaining.is_empty() {
        let listed: Vec<String> = remaining.iter().map(|(f, v)| format!("{f}={v:016x}")).collect();
        report(&format!("capabilities survived the drop ({})", listed.join(", ")));
        return EXIT_NOT_EXECUTABLE;
    }

    // execv, not execvp: no binary is resolved through PATH (FR-4.1).
    let c_args: Result<Vec<std::ffi::CString>, _> =
        argv.iter().map(|a| std::ffi::CString::new(a.as_bytes())).collect();
    let Ok(c_args) = c_args else {
        report("cannot execute: embedded null byte");
        return EXIT_NOT_EXECUTABLE;
    };
    let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: NUL-terminated strings and a NULL-terminated pointer array,
    // all alive for the call; on success it does not return.
    unsafe { libc::execv(ptrs[0], ptrs.as_ptr()) };
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOENT) => {
            report("not found");
            EXIT_NOT_FOUND
        }
        Some(libc::EACCES) | Some(libc::EPERM) => {
            report("no permission");
            EXIT_NOT_EXECUTABLE
        }
        _ => {
            report(&format!("cannot execute: {}", crate::pyfmt::os_error(&err, "")));
            EXIT_NOT_EXECUTABLE
        }
    }
}

// -- Startup self-drop (`_selfdrop.py`) ---------------------------------------

/// The environment variable that turns the drop on, and the whole
/// interface. Same notation as `run_as`: a passwd name or `uid:gid`.
pub const DROP_TO_ENV: &str = "GATEKEEPER_DROP_TO";

/// Extra capabilities to keep across the drop, beyond the mandatory two.
pub const KEEP_CAPS_ENV: &str = "GATEKEEPER_KEEP_CAPS";

/// `linux/prctl.h`.
const PR_SET_KEEPCAPS: i32 = 8;
const PR_CAP_AMBIENT: i32 = 47;
const PR_CAP_AMBIENT_RAISE: u64 = 2;

/// The two capabilities the drop always keeps.
pub const BASE_KEPT: u64 = (1 << CAP_SETUID) | (1 << CAP_SETGID);

/// The configured drop could not be performed, so startup must not
/// continue. `Display` is the bare message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfDropError(pub String);

impl std::fmt::Display for SelfDropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SelfDropError {}

/// `os.environ.get(name, "").strip()`.
fn env_trimmed(name: &str) -> String {
    std::env::var(name).map(|v| v.trim().to_string()).unwrap_or_default()
}

/// The `GATEKEEPER_DROP_TO` value, or `None` when unset or blank.
pub fn configured_target() -> Option<String> {
    let value = env_trimmed(DROP_TO_ENV);
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// One token from `GATEKEEPER_KEEP_CAPS` -> capability bit number. An
/// unknown name is a configuration error, not a silent skip.
fn parse_capability_name(token: &str) -> Result<u32, SelfDropError> {
    let upper = token.trim().to_uppercase();
    let name = upper.strip_prefix("CAP_").unwrap_or(&upper);
    capability_bit(name).ok_or_else(|| {
        let known: Vec<&str> = CAPABILITY_NAMES.iter().map(|(n, _)| *n).collect();
        SelfDropError(format!(
            "{KEEP_CAPS_ENV}={}: unknown capability {}. \
             Known: {} (with or without the 'CAP_' prefix).",
            repr_str(token),
            repr_str(name),
            known.join(", ")
        ))
    })
}

/// The extra capability bitmask from `GATEKEEPER_KEEP_CAPS`, or 0.
pub fn configured_extra_caps() -> Result<u64, SelfDropError> {
    let raw = env_trimmed(KEEP_CAPS_ENV);
    if raw.is_empty() {
        return Ok(0);
    }
    let mut bits = 0u64;
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        bits |= 1 << parse_capability_name(token)?;
    }
    Ok(bits)
}

/// `os.getgroups()`.
fn getgroups() -> Vec<u32> {
    // SAFETY: a zero-size query returns the count only.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n <= 0 {
        return Vec::new();
    }
    let mut groups = vec![0 as libc::gid_t; n as usize];
    // SAFETY: the buffer holds `n` entries.
    let got = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    groups.truncate(got.max(0) as usize);
    groups
}

/// The supplementary groups to carry across the drop: whatever the
/// container was started with (`group_add:`, e.g. the docker socket's
/// group), minus root's own group 0.
fn kept_groups() -> Vec<u32> {
    let mut groups: Vec<u32> = getgroups().into_iter().filter(|g| *g != 0).collect();
    groups.sort_unstable();
    groups.dedup();
    groups
}

/// Threads in this process, from `/proc/self/status`.
fn thread_count() -> Option<usize> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
}

/// PORT NOTE: see the module docs -- capability changes are per thread.
fn require_single_thread(what: &str) -> Result<(), SelfDropError> {
    match thread_count() {
        Some(n) if n > 1 => Err(SelfDropError(format!(
            "{what} must happen before any other thread is started, but this \
             process already has {n} threads; capabilities are per thread, so \
             the others would keep what this one gives up."
        ))),
        _ => Ok(()),
    }
}

fn os_err() -> String {
    crate::pyfmt::os_error(&std::io::Error::last_os_error(), "")
}

fn euid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() }
}

fn egid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::getegid() }
}

/// Becomes `value`, keeping `CAP_SETUID`/`CAP_SETGID` plus any extras.
///
/// Returns `(uid, gid)`. Fails rather than returning a process that is
/// still root; the caller aborts startup.
pub fn drop_privileges(value: &str) -> Result<(u32, u32), SelfDropError> {
    let (uid, gid, _) = resolve_run_as(value).map_err(|exc| SelfDropError(format!("{DROP_TO_ENV}: {exc}")))?;

    if uid == 0 {
        return Err(SelfDropError(format!(
            "{DROP_TO_ENV}={} resolves to uid 0. This setting exists to \
             give up root, so root is the one value it cannot take.",
            repr_str(value)
        )));
    }

    let extra = configured_extra_caps()?;

    if euid() != 0 {
        // Already unprivileged: nothing to give up, and nothing to keep.
        if (euid(), egid()) != (uid, gid) {
            return Err(SelfDropError(format!(
                "{DROP_TO_ENV}={} asks this process to become \
                 uid={uid} gid={gid}, but it is already running unprivileged \
                 as uid={} gid={} and cannot change \
                 user. Start the container as root ('user: \"0:0\"' with \
                 'cap_add: [SETUID, SETGID]') for this setting to mean \
                 anything -- see docs/DEPLOYMENT.md.",
                repr_str(value),
                euid(),
                egid()
            )));
        }
        return Ok((uid, gid));
    }

    require_single_thread(&format!("drop to uid={uid} gid={gid}"))?;

    let kept = BASE_KEPT | extra;

    let steps = (|| -> Result<(), String> {
        // 1. Without this the capabilities are gone the instant euid != 0.
        prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)?;

        // 2. Groups before ids: setting them needs what setresuid gives away.
        let groups = kept_groups();
        // SAFETY: the buffer holds `groups.len()` entries.
        if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } != 0 {
            return Err(os_err());
        }
        // SAFETY: plain id arguments; glibc applies them to every thread.
        if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
            return Err(os_err());
        }
        // SAFETY: as above.
        if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
            return Err(os_err());
        }

        // 3. Effective is the base two only; permitted and inheritable are
        //    the whole kept set (inheritable makes the ambient raise legal).
        capset(BASE_KEPT, kept, kept)?;

        // 4. The only set that survives the helper's execve.
        for bit in 0..64u64 {
            if kept & (1 << bit) != 0 {
                prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, bit, 0, 0)?;
            }
        }

        // Tidy: leaving it on would keep capabilities across any further
        // uid change, which nothing here intends to make.
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0)?;
        Ok(())
    })();
    if let Err(exc) = steps {
        return Err(SelfDropError(format!(
            "cannot drop to uid={uid} gid={gid}: {exc}. The container must \
             start as root with CAP_SETUID and CAP_SETGID for this \
             ('user: \"0:0\"' plus 'cap_add: [SETUID, SETGID]'); root alone \
             is not enough, because 'cap_drop: ALL' without a matching \
             'cap_add' leaves even root unable to change user. See \
             docs/DEPLOYMENT.md."
        )));
    }

    verify(uid, gid, extra)?;
    Ok((uid, gid))
}

fn hex_or_none(value: Option<u64>) -> String {
    match value {
        Some(v) => format!("{v:016x}"),
        None => "None".to_string(),
    }
}

/// Confirms the drop landed, in both directions.
fn verify(uid: u32, gid: u32, extra: u64) -> Result<(), SelfDropError> {
    if getresuid() != (uid, uid, uid) || getresgid() != (gid, gid, gid) {
        return Err(SelfDropError(format!(
            "drop to uid={uid} gid={gid} did not take effect \
             (now uid={} gid={})",
            fmt_ids(getresuid()),
            fmt_ids(getresgid())
        )));
    }

    let Some(held) = capability_sets() else {
        // No procfs to check against; the ids are right and every call
        // returned success.
        return Ok(());
    };

    let kept = BASE_KEPT | extra;

    let cap_eff = held.get("CapEff").copied();
    if cap_eff != Some(BASE_KEPT) {
        return Err(SelfDropError(format!(
            "drop to uid={uid} kept the wrong effective capabilities: \
             CapEff={}, expected {BASE_KEPT:016x} (CAP_SETUID + CAP_SETGID only). \
             The server itself must not hold extra capabilities -- only the \
             run_as child should, via the ambient set. See \
             docs/DEPLOYMENT.md.",
            hex_or_none(cap_eff)
        )));
    }

    for field in ["CapPrm", "CapInh", "CapAmb"] {
        let value = held.get(field).copied();
        if value != Some(kept) {
            return Err(SelfDropError(format!(
                "drop to uid={uid} kept the wrong capabilities: \
                 {field}={}, expected {kept:016x} (CAP_SETUID + CAP_SETGID{}). \
                 'run_as' would not work, and the process is no longer \
                 root either -- refusing to start in that state.",
                hex_or_none(value),
                if extra != 0 { format!(" + {KEEP_CAPS_ENV}") } else { String::new() }
            )));
        }
    }
    Ok(())
}

/// Gives up all capabilities after all, for a config that declares no
/// `run_as` anywhere. The error is Python's `str(OSError)` from `capset`.
///
/// PORT NOTE: refused (with the single-thread message) once other threads
/// exist, since `capset` would only empty the calling thread's sets.
pub fn discard_capabilities() -> Result<(), String> {
    require_single_thread("discarding capabilities").map_err(|e| e.0)?;
    capset(0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_entry_ignores_ordinary_argv() {
        assert_eq!(hidden_entry(&["gatekeeper".into(), "serve".into()]), None);
        assert_eq!(hidden_entry(&["gatekeeper".into()]), None);
    }

    #[test]
    fn capability_names_parse_with_and_without_prefix() {
        assert_eq!(parse_capability_name("DAC_OVERRIDE").unwrap(), 1);
        assert_eq!(parse_capability_name("cap_dac_read_search").unwrap(), 2);
        let err = parse_capability_name("NONSENSE").unwrap_err().0;
        assert_eq!(
            err,
            "GATEKEEPER_KEEP_CAPS='NONSENSE': unknown capability 'NONSENSE'. Known: CHOWN, \
             DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER, FSETID, KILL, SETGID, SETUID (with or \
             without the 'CAP_' prefix)."
        );
    }
}
