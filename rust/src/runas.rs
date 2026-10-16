//! Running one `file` operation as a different OS user (`run_as`) --
//! port of `_runas.py`.
//!
//! This file currently holds the **parsing half** only: the shape check
//! Tier 1 and the catalog run at load time ([`parse_run_as`]), its error
//! type ([`RunAsError`]) and the parsed value ([`RunAs`]). The privilege
//! dropping child process (`resolve_run_as`, `become`, the capability
//! helpers, `explain_permission_denied`, the `_main` child entry point) is
//! ported separately into this same file -- see the marked section at the
//! bottom.
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
// EXECUTION HALF -- not ported yet.
//
// The privilege-dropping part of `_runas.py` goes below this line, in this
// same file: `resolve_run_as`, the capability constants (`CAP_*`,
// `CAPABILITY_NAMES`), `capability_sets`, `effective_capabilities`,
// `bounding_capabilities`, `can_change_user`, `capset`,
// `_clear_capabilities`, `_set_no_new_privs`, `_privilege_diagnosis`,
// `_can_regain_root`, `become`, `bypasses_file_permissions`,
// `child_bypasses_file_permissions`, `explain_permission_denied`, `_fail`
// and the child entry point `_main`. They reuse `parse_run_as` and
// `RunAsError` above.
// ===========================================================================

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
