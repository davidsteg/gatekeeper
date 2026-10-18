//! Running one `file` operation as a different OS user (`run_as`) --
//! port of `_runas.py`.
//!
//! Two halves: the shape check Tier 1 and the catalog run at load time
//! ([`parse_run_as`], [`RunAsError`], [`RunAs`]), and the privilege
//! dropping child process ([`resolve_run_as`], [`become_user`], the
//! capability helpers, [`explain_permission_denied`] and the child entry
//! point [`child_main`], reached through the hidden `__runas` argument).
//!
//! `run_as` is a Tier 1 field on the toolkit (deploy time,
//! `toolkits.yaml`) plus a narrowing per-tool override; there is no
//! parameter through which a call can pick a user (FR-8.3i).

use std::fmt;
use std::sync::OnceLock;

use regex::Regex;

use crate::pyfmt::repr_str;

/// A `run_as` given as a name, resolved through the container's own passwd
/// database at call time. Deliberately narrow: a name with a slash or a
/// newline in it is a configuration mistake, never a real account.
pub const NAME_PATTERN: &str = r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?$";

/// A `run_as` given numerically, as `uid:gid`. Both halves are required.
///
/// PORT NOTE: Python's `\d` also matched non-ASCII Unicode digits (which
/// `int()` then accepted); only ASCII digits are accepted here.
pub const IDS_PATTERN: &str = r"^([0-9]{1,10}):([0-9]{1,10})$";

fn name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(NAME_PATTERN).expect("static regex"))
}

fn ids_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(IDS_PATTERN).expect("static regex"))
}

/// A `run_as` value that cannot be parsed, resolved, or assumed. `Display`
/// is the bare message (Python's `str(exc)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunAsError(pub String);

impl RunAsError {
    pub fn new(message: impl Into<String>) -> Self {
        RunAsError(message.into())
    }
}

impl fmt::Display for RunAsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RunAsError {}

/// A parsed `run_as`: exactly one of the two forms. Python returned the
/// tuple `(name, uid, gid)` with the other half `None`; [`RunAs::as_tuple`]
/// gives that shape back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunAs {
    /// A user name, resolved later against passwd.
    Name(String),
    /// A numeric `uid:gid` pair, taken as given.
    Ids { uid: u32, gid: u32 },
}

impl RunAs {
    /// `(name, uid, gid)` as `parse_run_as` returned it in Python.
    pub fn as_tuple(&self) -> (Option<&str>, Option<u32>, Option<u32>) {
        match self {
            RunAs::Name(n) => (Some(n.as_str()), None, None),
            RunAs::Ids { uid, gid } => (None, Some(*uid), Some(*gid)),
        }
    }
}

/// Splits a `run_as` value into its form (`parse_run_as`).
///
/// Called at Tier 1 load time for the shape check and again in the child
/// for the real resolution, so a malformed value fails at startup rather
/// than on the first agent call.
pub fn parse_run_as(value: &str) -> Result<RunAs, RunAsError> {
    let text = value.trim();
    if text.is_empty() {
        return Err(RunAsError::new("'run_as' must not be empty"));
    }

    if let Some(caps) = ids_re().captures(text) {
        let uid: u64 = caps[1].parse().unwrap_or(u64::MAX);
        let gid: u64 = caps[2].parse().unwrap_or(u64::MAX);
        if uid > 0xFFFF_FFFF || gid > 0xFFFF_FFFF {
            return Err(RunAsError::new(format!(
                "'run_as' {}: uid/gid out of range",
                repr_str(text)
            )));
        }
        return Ok(RunAs::Ids { uid: uid as u32, gid: gid as u32 });
    }

    if name_re().is_match(text) {
        return Ok(RunAs::Name(text.to_string()));
    }

    Err(RunAsError::new(format!(
        "'run_as' {} is neither a user name nor a 'uid:gid' pair \
         (e.g. 'hermes' or '3001:3001'). A bare numeric uid is rejected on \
         purpose -- the group would then depend on a passwd entry that a \
         host uid does not have inside this image.",
        repr_str(text)
    )))
}

// ===========================================================================
// EXECUTION HALF -- the privilege-dropping child (`_runas.py`, from
// `resolve_run_as` down).
//
// Three properties this half exists to guarantee:
//
// 1. **The privilege drop is one-way.** Real and saved ids are set together
//    (`setresuid`/`setresgid`), supplementary groups are replaced, every
//    capability set is emptied, and all of it is verified -- including an
//    explicit attempt to regain root that must fail. The bounding set
//    cannot be lowered without `CAP_SETPCAP`, so the child sets
//    `no_new_privs` instead.
// 2. **It never silently falls back.** A process that cannot become the
//    requested user fails the call with a message saying so.
// 3. **Tier 1 is checked on the privileged side too.** `path_roots` and
//    `protected_resources` are re-validated inside the child, after the
//    drop.
//
// The child is this same binary, re-executed with the hidden first
// argument `__runas` (see `crate::privdrop::hidden_entry`), where Python ran
// `python -m gatekeeper._runas`. The request travels over stdin, never
// argv: argv is world-readable through `/proc/<pid>/cmdline`, and a
// `file.write` request carries the file's whole content.
// ===========================================================================

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::{Read, Write};

use serde_json::{json, Value};

use crate::pyfmt::{os_error, str_value};

/// Turns a `run_as` value into the concrete `(uid, gid, name)` to assume.
///
/// A name is looked up in the container's passwd database; the numeric
/// form is taken as given. `name` comes back only for the passwd form,
/// because it is what `initgroups` needs to find the account's
/// supplementary groups -- there is no equivalent for a bare uid.
pub fn resolve_run_as(value: &str) -> Result<(u32, u32, Option<String>), RunAsError> {
    match parse_run_as(value)? {
        RunAs::Ids { uid, gid } => Ok((uid, gid, None)),
        RunAs::Name(name) => match getpwnam(&name) {
            Some((uid, gid)) => Ok((uid, gid, Some(name))),
            None => Err(RunAsError::new(format!(
                "'run_as' user {} does not exist in this container's \
                 passwd database. Host accounts are not visible inside the \
                 image -- use the numeric 'uid:gid' form for those.",
                repr_str(&name)
            ))),
        },
    }
}

/// `pwd.getpwnam(name)` -> `(pw_uid, pw_gid)`, or `None` for no entry.
fn getpwnam(name: &str) -> Option<(u32, u32)> {
    let c_name = CString::new(name).ok()?;
    let mut buf: Vec<libc::c_char> = vec![0; 16384];
    loop {
        // SAFETY: an all-zero `passwd` is a valid out-parameter.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the duration of the call and
        // `buf.len()` is the buffer's real size.
        let rc = unsafe {
            libc::getpwnam_r(c_name.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
        };
        if rc == libc::ERANGE && buf.len() < (1 << 22) {
            buf.resize(buf.len() * 4, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        return Some((pwd.pw_uid, pwd.pw_gid));
    }
}

/// Capability bit numbers from `linux/capability.h`. The two the drop
/// needs, plus the two that decide whether root is actually above file
/// permissions. The rest (CHOWN, FOWNER, FSETID, KILL) are included for
/// `GATEKEEPER_KEEP_CAPS`.
pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;

/// Names for `GATEKEEPER_KEEP_CAPS`, matching Docker's `cap_add` notation
/// (without the `CAP_` prefix). Sorted by name, which is the order the
/// "Known: ..." message lists them in.
pub const CAPABILITY_NAMES: &[(&str, u32)] = &[
    ("CHOWN", CAP_CHOWN),
    ("DAC_OVERRIDE", CAP_DAC_OVERRIDE),
    ("DAC_READ_SEARCH", CAP_DAC_READ_SEARCH),
    ("FOWNER", CAP_FOWNER),
    ("FSETID", CAP_FSETID),
    ("KILL", CAP_KILL),
    ("SETGID", CAP_SETGID),
    ("SETUID", CAP_SETUID),
];

/// `CAPABILITY_NAMES[name]`.
pub fn capability_bit(name: &str) -> Option<u32> {
    CAPABILITY_NAMES.iter().find(|(n, _)| *n == name).map(|(_, bit)| *bit)
}

/// `_LINUX_CAPABILITY_VERSION_3`, the 64-bit capability ABI: a
/// version+pid header and *two* 32-bit data words.
pub const CAP_VERSION_3: u32 = 0x2008_0522;

/// The per-process capability sets, as `/proc/self/status` names them.
/// `CapBnd` is deliberately absent (see [`bounding_capabilities`]).
const CAP_SETS: [&str; 4] = ["CapEff", "CapPrm", "CapInh", "CapAmb"];

/// Every per-process capability set as a bitmask, keyed by its
/// `/proc/self/status` name, or `None` when procfs cannot be read.
pub type CapSets = BTreeMap<String, u64>;

/// Every per-process capability set as a bitmask, or `None`.
///
/// Read out of `/proc/self/status`: a machine without procfs answers
/// "unknown" instead of failing -- which is a different thing from "holds
/// nothing", and callers treat it as such. All four sets rather than just
/// the effective one: a capability in the permitted set can be made
/// effective again at will, and one in the ambient set survives the next
/// `execve`.
///
/// PORT NOTE: `/proc/self/status` describes the thread-group leader. In
/// Python every caller ran on the main thread; here the capability-changing
/// callers (`privdrop::drop_privileges`, the hidden child entries) run while
/// the process is single-threaded, so the leader's sets are the process's.
pub fn capability_sets() -> Option<CapSets> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut found = CapSets::new();
    for line in text.lines() {
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v),
            None => (line, ""),
        };
        if CAP_SETS.contains(&field) {
            found.insert(field.to_string(), u64::from_str_radix(value.trim(), 16).ok()?);
        }
    }
    if found.is_empty() {
        None
    } else {
        Some(found)
    }
}

/// Just the effective set -- what a process can use *right now*.
pub fn effective_capabilities() -> Option<u64> {
    capability_sets().and_then(|sets| sets.get("CapEff").copied())
}

/// The bounding set -- the ceiling on what any `execve` from here can hold.
///
/// Deliberately not part of [`capability_sets`]: callers there check that
/// every set is empty after a drop, and the bounding set never is.
pub fn bounding_capabilities() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("CapBnd:") {
            return u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    None
}

fn geteuid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() }
}

fn getegid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::getegid() }
}

/// `os.getresuid()`.
pub fn getresuid() -> (u32, u32, u32) {
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: three valid out-pointers.
    unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
    (r, e, s)
}

/// `os.getresgid()`.
pub fn getresgid() -> (u32, u32, u32) {
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: three valid out-pointers.
    unsafe { libc::getresgid(&mut r, &mut e, &mut s) };
    (r, e, s)
}

/// A Python tuple of three ints, `(1, 2, 3)`.
pub fn fmt_ids(ids: (u32, u32, u32)) -> String {
    format!("({}, {}, {})", ids.0, ids.1, ids.2)
}

/// Whether this process can actually assume another uid/gid.
///
/// `CAP_SETUID`/`CAP_SETGID` in the *effective* set, not uid 0. Only where
/// the capability set cannot be read at all does uid 0 remain the best
/// available proxy.
pub fn can_change_user() -> bool {
    match effective_capabilities() {
        None => geteuid() == 0,
        Some(caps) => caps & (1 << CAP_SETUID) != 0 && caps & (1 << CAP_SETGID) != 0,
    }
}

/// `str(OSError(errno, strerror, filename))` for the last OS error.
fn last_os_error(filename: &str) -> String {
    os_error(&std::io::Error::last_os_error(), filename)
}

/// Writes this process's three capability sets, as bitmasks.
///
/// Only the low 32 bits: every capability this codebase names lives there,
/// and the second data word stays zero, which clears the high half. The
/// error is Python's `str(OSError)`, `[Errno 1] Operation not permitted:
/// 'capset'`.
///
/// Per thread, as the syscall is: callers run it while single-threaded.
pub fn capset(effective: u64, permitted: u64, inheritable: u64) -> Result<(), String> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header { version: CAP_VERSION_3, pid: 0 };
    let mut data = [Data::default(); 2];
    data[0].effective = (effective & 0xFFFF_FFFF) as u32;
    data[0].permitted = (permitted & 0xFFFF_FFFF) as u32;
    data[0].inheritable = (inheritable & 0xFFFF_FFFF) as u32;
    // SAFETY: header and data have the kernel's `_LINUX_CAPABILITY_VERSION_3`
    // layout and outlive the call.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) };
    if rc != 0 {
        return Err(last_os_error("capset"));
    }
    Ok(())
}

/// `prctl(option, a2, a3, a4, a5)`; the error is Python's
/// `str(OSError(errno, strerror, f"prctl{args}"))`.
pub fn prctl(option: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<(), String> {
    // SAFETY: plain integer arguments; the options used here take no pointers.
    let rc = unsafe {
        libc::prctl(
            option,
            a2 as libc::c_ulong,
            a3 as libc::c_ulong,
            a4 as libc::c_ulong,
            a5 as libc::c_ulong,
        )
    };
    if rc != 0 {
        return Err(last_os_error(&format!("prctl({option}, {a2}, {a3}, {a4}, {a5})")));
    }
    Ok(())
}

/// Empties the effective, permitted and inheritable capability sets (the
/// ambient set follows, the kernel keeps it a subset of both).
///
/// Needed on the path where the process was *not* uid 0 to begin with: a
/// change between two non-root uids does not clear capabilities by itself.
pub fn clear_capabilities() -> Result<(), String> {
    capset(0, 0, 0)
}

/// `PR_SET_NO_NEW_PRIVS` (`linux/prctl.h`).
pub const PR_SET_NO_NEW_PRIVS: i32 = 38;

/// Forbids this process ever gaining privilege through `execve`.
///
/// The half [`clear_capabilities`] cannot reach: the bounding set stays
/// full, and while it is, a setuid-root binary remains a way back up.
/// Defence in depth, so a kernel that does not know the option is
/// reported (`false`), not fatal.
pub fn set_no_new_privs() -> bool {
    // SAFETY: integer-only prctl.
    unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) == 0 }
}

/// The message for a process that cannot become `uid`/`gid`: names which
/// of the two halves (`user: "0:0"` or `cap_add`) is actually missing.
fn privilege_diagnosis(uid: u32, gid: u32) -> String {
    let caps = effective_capabilities();
    let mut where_ = format!("gatekeeper runs as uid={} gid={}", geteuid(), getegid());
    if let Some(c) = caps {
        where_.push_str(&format!(" with CapEff={c:016x}"));
    }

    let cause = if caps.is_none() {
        "This process is not uid 0 and its capability set cannot be read \
         here, so it has no way to assume another user."
    } else if geteuid() != 0 {
        "The container is not running as root, so the two capabilities \
         cannot take effect even when 'cap_add' lists them -- Docker \
         grants them in uid 0's permitted set only. The half missing \
         here is 'user: \"0:0\"', not 'cap_add'."
    } else {
        "The container runs as root but holds neither capability, so \
         'cap_drop: ALL' took effect and a matching \
         'cap_add: [SETUID, SETGID]' did not."
    };

    format!(
        "cannot run this file operation as uid={uid} gid={gid}: {where_} \
         and holds no privilege to change user. {cause} Both halves are \
         needed together; check what the container actually got with:\n  \
         docker inspect -f '{{{{.Config.User}}}} {{{{.HostConfig.CapAdd}}}}' gatekeeper\n  \
         docker exec gatekeeper grep -E '^(Uid|CapEff):' /proc/self/status\n\
         See docs/DEPLOYMENT.md."
    )
}

/// Whether root is still reachable after the drop: with the saved
/// set-user-id left at 0, `setuid(0)` would succeed.
fn can_regain_root() -> bool {
    // SAFETY: no preconditions; glibc applies it to every thread.
    unsafe { libc::setuid(0) == 0 }
}

/// Irreversibly assumes `uid`/`gid`, or fails (Python's `become`; renamed
/// because `become` is a reserved word in Rust).
///
/// Never returns having assumed something *other* than what was asked for.
pub fn become_user(uid: u32, gid: u32, name: Option<&str>) -> Result<(), RunAsError> {
    if !can_change_user() {
        // No privilege to become anybody. The only user this process can
        // be is the one it already is.
        if (geteuid(), getegid()) != (uid, gid) {
            return Err(RunAsError::new(privilege_diagnosis(uid, gid)));
        }
        return Ok(());
    }

    let switched = (|| -> Result<(), String> {
        // Supplementary groups first: both calls need the privilege that
        // setresuid below gives away. `initgroups` for a real account; an
        // explicit empty set for the numeric form.
        match name {
            Some(n) => {
                let c_name = CString::new(n).map_err(|_| "embedded null byte".to_string())?;
                // SAFETY: valid NUL-terminated name.
                if unsafe { libc::initgroups(c_name.as_ptr(), gid) } != 0 {
                    return Err(last_os_error(""));
                }
            }
            None => {
                // SAFETY: a zero-length list needs no buffer.
                if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
                    return Err(last_os_error(""));
                }
            }
        }
        // SAFETY: plain id arguments; glibc applies them to every thread.
        if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
            return Err(last_os_error(""));
        }
        // SAFETY: as above.
        if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
            return Err(last_os_error(""));
        }
        Ok(())
    })();
    if let Err(exc) = switched {
        return Err(RunAsError::new(format!(
            "cannot run this file operation as uid={uid} gid={gid}: {exc}. \
             The process holds CAP_SETUID and CAP_SETGID, so check the \
             toolkit's 'run_as' value itself -- see docs/DEPLOYMENT.md."
        )));
    }

    // Verify rather than assume.
    if getresuid() != (uid, uid, uid) || getresgid() != (gid, gid, gid) {
        return Err(RunAsError::new(format!(
            "privilege drop to uid={uid} gid={gid} did not take effect \
             (now uid={} gid={})",
            fmt_ids(getresuid()),
            fmt_ids(getresgid())
        )));
    }
    if uid != 0 {
        // A non-root-to-non-root change keeps ambient capabilities, so
        // clear them outright.
        if let Err(exc) = clear_capabilities() {
            if capability_sets().unwrap_or_default().values().any(|v| *v != 0) {
                return Err(RunAsError::new(format!(
                    "privilege drop to uid={uid} could not clear the \
                     capability sets ({exc}) -- refusing to run the operation"
                )));
            }
        }
        let remaining: Vec<(String, u64)> = capability_sets()
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, v)| *v != 0)
            .collect();
        if !remaining.is_empty() {
            let listed: Vec<String> =
                remaining.iter().map(|(f, v)| format!("{f}={v:016x}")).collect();
            return Err(RunAsError::new(format!(
                "privilege drop to uid={uid} left capabilities behind \
                 ({}) -- refusing to run the operation",
                listed.join(", ")
            )));
        }
        if can_regain_root() {
            return Err(RunAsError::new(format!(
                "privilege drop to uid={uid} left root regainable -- refusing \
                 to run the operation"
            )));
        }
    }
    Ok(())
}

const DAC_BITS: u64 = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_DAC_READ_SEARCH);

/// Whether this process is above ordinary DAC checks, or `None` if unknown.
pub fn bypasses_file_permissions() -> Option<bool> {
    effective_capabilities().map(|caps| caps & DAC_BITS != 0)
}

/// Whether a `run_as` child would inherit DAC-bypass capabilities (the
/// *ambient* set, which is what survives the child's `execve`).
pub fn child_bypasses_file_permissions() -> Option<bool> {
    let sets = capability_sets()?;
    let amb = sets.get("CapAmb").copied().unwrap_or(0);
    Some(amb & DAC_BITS != 0)
}

/// The context a bare "Permission denied" leaves out: which uid ran the
/// operation, and whether uid 0 here is above file permissions at all.
pub fn explain_permission_denied(uid: u32, gid: u32, run_as: &str) -> String {
    let where_ = format!(
        "The operation ran as uid={uid} gid={gid} (run_as: {}).",
        repr_str(run_as)
    );
    if uid != 0 {
        return format!(
            " {where_} That is the user the toolkit asked for, so this is an \
             ordinary permission problem: check the file's mode and owner, \
             and that every parent directory is traversable (+x) by that \
             uid -- a denial naming the file is often a directory above it."
        );
    }

    if bypasses_file_permissions() == Some(true) {
        return format!(
            " {where_} It holds CAP_DAC_OVERRIDE, so this is not a file-mode \
             problem -- check for a read-only mount, or a path that is not \
             mounted into the container at all."
        );
    }

    let reachable = bounding_capabilities().is_some_and(|b| b & (1 << CAP_DAC_OVERRIDE) != 0);
    let middle = if reachable {
        "The capability is in the bounding set, so 'cap_add: DAC_OVERRIDE' \
         would grant it -- but it reads every file on every mount, and \
         the better answer is almost always to name the owning uid: "
    } else {
        "'cap_drop: ALL' removed it from the bounding set, so it \
         cannot be granted back without changing that. Name the owning \
         uid instead: "
    };
    format!(
        " {where_} Note that uid 0 here is NOT above file permissions: this \
         container holds neither CAP_DAC_OVERRIDE nor CAP_DAC_READ_SEARCH, \
         so root is checked against the file's mode like any other user, and \
         a file owned by somebody else with mode 0600 is unreadable to it. \
         {middle}run_as: \"<uid>:<gid>\" of whoever owns the file. See \
         docs/DEPLOYMENT.md."
    )
}

fn fail(message: &str) -> Value {
    json!({
        "outcome": "failed",
        "exit_code": 1,
        "stdout": "",
        "stderr": message,
        "truncated": false,
    })
}

fn emit(value: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(crate::pyjson::dumps(value).as_bytes());
    let _ = out.flush();
}

/// `request[key]`, or Python's `str(KeyError(key))` -- the key's repr.
fn require<'a>(request: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a Value, String> {
    request.get(key).ok_or_else(|| repr_str(key))
}

/// `list(request.get(key) or [])` of strings.
fn str_list(request: &serde_json::Map<String, Value>, key: &str) -> Vec<String> {
    match request.get(key) {
        Some(Value::Array(items)) => items.iter().map(str_value).collect(),
        _ => Vec::new(),
    }
}

/// `request.get(key)` as an optional string.
fn opt_str(request: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    match request.get(key) {
        None | Some(Value::Null) => None,
        Some(v) => Some(str_value(v)),
    }
}

/// Child entry point (`_runas._main`): one request on stdin, one result on
/// stdout. Reached through the hidden `__runas` argument.
///
/// Always exits 0 with a JSON result, including on failure: a non-zero
/// exit means something genuinely unexpected (a crash before this ran).
pub fn child_main() -> i32 {
    // Before anything else, the request included: from here on this
    // process cannot gain privilege through `execve`.
    set_no_new_privs();

    let mut raw = Vec::new();
    let parsed: Result<serde_json::Map<String, Value>, String> =
        match std::io::stdin().lock().read_to_end(&mut raw) {
            Err(exc) => Err(exc.to_string()),
            Ok(_) => match String::from_utf8(raw) {
                Err(exc) => Err(exc.to_string()),
                Ok(text) => match serde_json::from_str::<Value>(&text) {
                    // PORT NOTE: the parse error text is serde_json's, not
                    // Python's `json` module's; the parent never sends a
                    // malformed request.
                    Err(exc) => Err(exc.to_string()),
                    Ok(Value::Object(map)) => Ok(map),
                    Ok(_) => Err("request must be a JSON object".to_string()),
                },
            },
        };
    let request = match parsed {
        Ok(map) => map,
        Err(exc) => {
            emit(&fail(&format!("malformed run_as request: {exc}")));
            return 0;
        }
    };

    let run_as_value = match require(&request, "run_as") {
        Ok(v) => str_value(v),
        Err(key) => {
            emit(&fail(&key));
            return 0;
        }
    };
    let (uid, gid) = match resolve_run_as(&run_as_value)
        .and_then(|(uid, gid, name)| become_user(uid, gid, name.as_deref()).map(|_| (uid, gid)))
    {
        Ok(ids) => ids,
        Err(exc) => {
            emit(&fail(&exc.0));
            return 0;
        }
    };

    // Every line below runs as the dropped-to user.

    // A proposed path root, stat-ed as the user its operations will run as
    // (`execute::file::check_root_dir_as`). Nothing is opened or changed.
    if let Some(root) = request.get("check_root") {
        let reply = match crate::execute::file::check_root_dir(&str_value(root)) {
            Ok(()) => json!({"outcome": crate::execute::OUTCOME_OK, "stderr": ""}),
            Err(why) => json!({"outcome": "failed", "checked": true, "stderr": why}),
        };
        emit(&reply);
        return 0;
    }
    let outcome = (|| -> Result<crate::execute::file::Op, String> {
        let path = crate::execute::file::validate_path(
            &str_value(require(&request, "path")?),
            &str_list(&request, "path_roots"),
            &str_list(&request, "protected"),
        )?;
        let operation = str_value(require(&request, "operation")?);
        let content = opt_str(&request, "content");
        let old_string = opt_str(&request, "old_string");
        let new_string = opt_str(&request, "new_string");
        let max_output_bytes = py_int(require(&request, "max_output_bytes")?)?;
        crate::execute::file::perform(
            &operation,
            &path,
            content.as_deref(),
            old_string.as_deref(),
            new_string.as_deref(),
            max_output_bytes,
        )
    })();
    let mut op = match outcome {
        Ok(op) => op,
        Err(exc) => {
            emit(&fail(&exc));
            return 0;
        }
    };

    // A denial is the one result where "which user was this?" decides what
    // to do next. Answer it here, where the uid is known for certain.
    if op.stderr.starts_with("Permission denied") {
        op.stderr.push_str(&explain_permission_denied(uid, gid, &run_as_value));
    }

    emit(&json!({
        "outcome": op.outcome,
        "exit_code": op.exit_code,
        "stdout": op.stdout,
        "stderr": op.stderr,
        "truncated": op.truncated,
    }));
    0
}

/// `int(value)` for the request's `max_output_bytes`.
fn py_int(value: &Value) -> Result<i64, String> {
    match value {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .ok_or_else(|| "int too large".to_string()),
        Value::Bool(b) => Ok(*b as i64),
        Value::String(s) => s.trim().parse::<i64>().map_err(|_| {
            format!("invalid literal for int() with base 10: {}", repr_str(s))
        }),
        other => Err(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            crate::pyfmt::type_name(other)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_forms() {
        assert_eq!(parse_run_as("hermes").unwrap(), RunAs::Name("hermes".into()));
        assert_eq!(parse_run_as(" 3001:3001 ").unwrap(), RunAs::Ids { uid: 3001, gid: 3001 });
        assert_eq!(parse_run_as("svc$").unwrap(), RunAs::Name("svc$".into()));
        assert_eq!(parse_run_as("0:0").unwrap().as_tuple(), (None, Some(0), Some(0)));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse_run_as("  ").unwrap_err().0, "'run_as' must not be empty");
        assert_eq!(
            parse_run_as("4294967296:1").unwrap_err().0,
            "'run_as' '4294967296:1': uid/gid out of range"
        );
        for bad in ["3001", "a/b", "1:2:3", "-x", "hermes\nroot", "a".repeat(33).as_str()] {
            let err = parse_run_as(bad).unwrap_err().0;
            assert!(err.contains("is neither a user name nor a 'uid:gid' pair"), "{bad}: {err}");
        }
    }
}
