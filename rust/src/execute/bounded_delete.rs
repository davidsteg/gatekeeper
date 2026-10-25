//! Bounded, symlink-safe `file_operation: delete` (1.28.0; port of the
//! Python FR's `execute_file._delete`).
//!
//! The 1.25.0 delete called `remove_dir_all` on a resolved path. This one
//! lists first and deletes only what it listed:
//!
//! 1. The path is taken *as sent*, not resolved: a `.`/`..` segment, a
//!    protected name, a path root itself or a path not literally under a
//!    root is refused.
//! 2. No path strings from there on. The matching root is opened (by its
//!    realpath: a root may itself be a symlink by admin config), every
//!    component below it `O_NOFOLLOW` relative to its parent's fd. A
//!    symlink in any component, the target included, is refused.
//! 3. The tree is listed through those fds, symlinks not followed (a link
//!    is one `l` entry). More than `max_entries` entries, a directory more
//!    than [`MAX_DELETE_DEPTH`] levels below the target, a sub-directory
//!    with `files_only`, an entry named in `protected_resources`, or any
//!    listing error aborts *before anything is removed*.
//! 4. The root -> parent chain is re-walked and must still be the same
//!    directories. Then exactly the listed entries go, bottom-up, each
//!    re-checked by `(st_dev, st_ino, type)` right before its
//!    `unlinkat`; the first extra, missing or replaced entry stops it and
//!    the report says what was removed by then.
//! 5. Proof: the target's name no longer exists in its parent.
//!
//! What a race can still do is remove a *name* inside the listed tree,
//! never anything outside it: every removal is by name through a directory
//! fd held since the listing, and no symlink is ever followed.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::file::Op;
use super::{OUTCOME_FAILED, OUTCOME_OK};
use crate::pathutil;
use crate::pyfmt::repr_str;

/// How many directory levels below the target a delete descends (the
/// target is level 0, its sub-directories level 1). Each level holds one
/// directory fd while listing and while deleting; 64 stays far under any
/// usual `RLIMIT_NOFILE` and stack, and real cleanup trees are shallower.
pub const MAX_DELETE_DEPTH: usize = 64;

/// Upper bound for a delete tool's `delete.max_entries`, and the bound a
/// delete tool without a `delete:` block gets. The listing is held in
/// memory and every entry is stat'ed twice within one request; bulk
/// deletes beyond this do not belong in one agent call.
pub const MAX_DELETE_ENTRIES: i64 = 100_000;

const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
const NOFOLLOW_DIR_FLAGS: libc::c_int = DIR_FLAGS | libc::O_NOFOLLOW;

/// `(st_dev, st_ino, file type)`: what an entry must still be when it goes.
type Ident = (u64, u64, u32);

struct Entry {
    name: CString,
    /// Path relative to the target, for messages (`""` for the target).
    rel: String,
    is_dir: bool,
    ident: Ident,
    children: Vec<Entry>,
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

fn strerror(err: i32) -> String {
    let text = std::io::Error::from_raw_os_error(err).to_string();
    // "No such file or directory (os error 2)" -> the part Python prints.
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

fn is_permission(err: i32) -> bool {
    err == libc::EACCES || err == libc::EPERM
}

fn open_at(dir: Option<RawFd>, name: &CStr, flags: libc::c_int) -> Result<OwnedFd, i32> {
    // SAFETY: `name` is a valid NUL-terminated string; the fd, if any, is
    // owned by the caller and outlives the call.
    let fd = unsafe { libc::openat(dir.unwrap_or(libc::AT_FDCWD), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ident_of(st: &libc::stat) -> Ident {
    (st.st_dev as u64, st.st_ino as u64, (st.st_mode & libc::S_IFMT) as u32)
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`.
fn stat_at(dir: RawFd, name: &CStr) -> Result<libc::stat, i32> {
    // SAFETY: zeroed `stat` is a valid out-buffer; `name` is NUL-terminated.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc < 0 {
        Err(last_errno())
    } else {
        Ok(st)
    }
}

fn fstat(fd: RawFd) -> Result<libc::stat, i32> {
    // SAFETY: as in `stat_at`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        Err(last_errno())
    } else {
        Ok(st)
    }
}

fn unlink_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> Result<(), i32> {
    // SAFETY: `name` is NUL-terminated, `dir` an open directory fd.
    if unsafe { libc::unlinkat(dir, name.as_ptr(), flags) } < 0 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

fn is_dir_mode(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn is_link_mode(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// The names in the directory open as `fd` (without `.`/`..`), sorted.
fn list_names(fd: RawFd) -> Result<Vec<CString>, i32> {
    // fdopendir takes ownership of its fd: give it a duplicate.
    // SAFETY: plain fd syscalls; every path below closes what it opened.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(last_errno());
    }
    let dir = unsafe { libc::fdopendir(dup) };
    if dir.is_null() {
        let err = last_errno();
        unsafe { libc::close(dup) };
        return Err(err);
    }
    // The duplicate shares the file offset: start from the beginning.
    unsafe { libc::rewinddir(dir) };
    let mut names = Vec::new();
    let result = loop {
        // readdir signals an error only through errno.
        unsafe { *libc::__errno_location() = 0 };
        let ent = unsafe { libc::readdir(dir) };
        if ent.is_null() {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            break if err == 0 { Ok(()) } else { Err(err) };
        }
        // SAFETY: `d_name` is NUL-terminated and valid until the next readdir.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(name.to_owned());
        }
    };
    unsafe { libc::closedir(dir) };
    result?;
    names.sort();
    Ok(names)
}

fn display(name: &CStr) -> String {
    String::from_utf8_lossy(name.to_bytes()).into_owned()
}

fn rel_of(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// Caps `text` at `limit` UTF-8 bytes; `true` if it had to.
fn cap(text: &str, limit: i64) -> (String, bool) {
    let limit = limit.max(0) as usize;
    if text.len() <= limit {
        return (text.to_string(), false);
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}\n... [truncated]", &text[..end]), true)
}

fn op(outcome: &'static str, stdout: String, stderr: String, truncated: bool) -> Op {
    let exit_code = Some(if outcome == OUTCOME_OK { 0 } else { 1 });
    Op { outcome, exit_code, stdout, stderr, truncated }
}

struct Limits<'a> {
    target: &'a str,
    protected: &'a [String],
    max_entries: usize,
    files_only: bool,
}

/// Opens the listed directory `entry` under `parent` without following a
/// symlink; it must still be the directory that was listed.
fn open_dir_checked(parent: RawFd, entry: &Entry, target: &str) -> Result<OwnedFd, String> {
    let at = if entry.rel.is_empty() { target.to_string() } else { entry.rel.clone() };
    let fd = open_at(Some(parent), &entry.name, NOFOLLOW_DIR_FLAGS).map_err(|err| match err {
        libc::ELOOP | libc::ENOTDIR => {
            format!("cannot open directory {} without following symlinks ({})", repr_str(&at), strerror(err))
        }
        _ => format!("cannot open directory {} ({})", repr_str(&at), strerror(err)),
    })?;
    match fstat(fd.as_raw_fd()) {
        Ok(st) if ident_of(&st) == entry.ident => Ok(fd),
        Ok(_) => Err(format!("directory {} changed since it was listed", repr_str(&at))),
        Err(err) => Err(format!("cannot stat directory {} ({})", repr_str(&at), strerror(err))),
    }
}

/// Lists `node` (open as `fd`) recursively into `node.children` and
/// `lines`. `depth` is `node`'s level below the target.
fn list_tree(fd: RawFd, node: &mut Entry, limits: &Limits, lines: &mut Vec<String>, depth: usize) -> Result<(), String> {
    let at = |rel: &str| if rel.is_empty() { limits.target.to_string() } else { rel.to_string() };
    let names = list_names(fd).map_err(|err| format!("cannot list {} ({})", repr_str(&at(&node.rel)), strerror(err)))?;
    for name in names {
        let shown = display(&name);
        let rel = rel_of(&node.rel, &shown);
        if limits.protected.contains(&shown) {
            return Err(format!("{} contains the protected resource {}", limits.target, repr_str(&rel)));
        }
        let st = stat_at(fd, &name).map_err(|err| format!("cannot stat {} ({})", repr_str(&rel), strerror(err)))?;
        let (kind, is_dir) = if is_link_mode(&st) {
            ('l', false)
        } else if is_dir_mode(&st) {
            ('d', true)
        } else {
            ('f', false)
        };
        if is_dir && limits.files_only {
            return Err(format!("{} contains the sub-directory {} (files_only)", limits.target, repr_str(&rel)));
        }
        lines.push(format!("{kind} {rel}"));
        if lines.len() > limits.max_entries {
            return Err(format!("{} has more than {} entries (max_entries)", limits.target, limits.max_entries));
        }
        let mut child = Entry { name, rel, is_dir, ident: ident_of(&st), children: Vec::new() };
        if is_dir {
            if depth + 1 > MAX_DELETE_DEPTH {
                return Err(format!(
                    "{} is nested deeper than {MAX_DELETE_DEPTH} levels (MAX_DELETE_DEPTH)",
                    limits.target
                ));
            }
            let child_fd = open_dir_checked(fd, &child, limits.target)?;
            list_tree(child_fd.as_raw_fd(), &mut child, limits, lines, depth + 1)?;
        }
        node.children.push(child);
    }
    Ok(())
}

/// `entry` must still exist under `dir` with its listed identity.
fn check_entry(dir: RawFd, entry: &Entry, target: &str) -> Result<(), String> {
    let at = if entry.rel.is_empty() { target.to_string() } else { entry.rel.clone() };
    match stat_at(dir, &entry.name) {
        Ok(st) if ident_of(&st) == entry.ident => Ok(()),
        Ok(_) => Err(format!("{} was replaced since it was listed", repr_str(&at))),
        Err(libc::ENOENT) => Err(format!("{} vanished since it was listed", repr_str(&at))),
        Err(err) => Err(format!("cannot stat {} ({})", repr_str(&at), strerror(err))),
    }
}

/// Removes exactly `node`'s listed entries, bottom-up, then `node`.
fn delete_dir(parent: RawFd, node: &Entry, target: &str, deleted: &mut Vec<String>) -> Result<(), String> {
    let at = if node.rel.is_empty() { target.to_string() } else { node.rel.clone() };
    {
        let fd = open_dir_checked(parent, node, target)?;
        let fd = fd.as_raw_fd();
        let current: BTreeSet<CString> = list_names(fd)
            .map_err(|err| format!("cannot list {} ({})", repr_str(&at), strerror(err)))?
            .into_iter()
            .collect();
        let expected: BTreeSet<CString> = node.children.iter().map(|c| c.name.clone()).collect();
        if current != expected {
            let few = |set: Vec<&CString>| set.into_iter().take(5).map(|n| repr_str(&display(n))).collect::<Vec<_>>().join(", ");
            return Err(format!(
                "{} no longer matches the listing (unexpected: [{}], missing: [{}])",
                repr_str(&at),
                few(current.difference(&expected).collect()),
                few(expected.difference(&current).collect()),
            ));
        }
        for child in &node.children {
            if child.is_dir {
                delete_dir(fd, child, target, deleted)?;
            } else {
                check_entry(fd, child, target)?;
                unlink_at(fd, &child.name, 0)
                    .map_err(|err| format!("cannot remove {} ({})", repr_str(&child.rel), strerror(err)))?;
                deleted.push(child.rel.clone());
            }
        }
    }
    check_entry(parent, node, target)?;
    // A directory that gained an entry since its check fails here (ENOTEMPTY).
    unlink_at(parent, &node.name, libc::AT_REMOVEDIR)
        .map_err(|err| format!("cannot remove directory {} ({})", repr_str(&at), strerror(err)))?;
    deleted.push(if node.rel.is_empty() { target.to_string() } else { node.rel.clone() });
    Ok(())
}

/// Picks the path root `comps` lies under, literally (by the root's
/// abspath or realpath, compared by components). `Ok(None)`: `comps` *is*
/// a root.
fn match_root(comps: &[&str], path_roots: &[String]) -> Result<Option<(String, usize)>, String> {
    let mut best: Option<(String, usize)> = None;
    for root in path_roots {
        if root.contains('\0') {
            continue;
        }
        let real = pathutil::realpath(root)?;
        for cand in [pathutil::abspath(root), real.clone()] {
            let rc: Vec<&str> = cand.split('/').filter(|c| !c.is_empty()).collect();
            if comps == rc.as_slice() {
                return Ok(None);
            }
            if comps.len() > rc.len() && comps[..rc.len()] == rc[..] && best.as_ref().is_none_or(|b| rc.len() > b.1) {
                best = Some((real.clone(), rc.len()));
            }
        }
    }
    best.map(Some).ok_or_else(|| "the path contains a symlink or is outside the path roots.".to_string())
}

/// Opens `root_real` and every directory in `comps` below it, no symlinks.
fn open_chain(root_real: &str, comps: &[CString]) -> Result<Vec<OwnedFd>, i32> {
    let root = CString::new(root_real).map_err(|_| libc::EINVAL)?;
    let mut fds = vec![open_at(None, &root, DIR_FLAGS)?];
    for name in comps {
        let next = open_at(Some(fds.last().expect("root opened").as_raw_fd()), name, NOFOLLOW_DIR_FLAGS)?;
        fds.push(next);
    }
    Ok(fds)
}

fn chain_idents(fds: &[OwnedFd]) -> Result<Vec<Ident>, i32> {
    fds.iter().map(|fd| fstat(fd.as_raw_fd()).map(|st| ident_of(&st))).collect()
}

/// The bounded delete; see the module docs. `path` is the path as the
/// agent sent it (already scope-checked by `validate_path`), never a
/// resolved one: resolving would turn a symlink in it into its target.
pub fn delete(
    path: &str,
    path_roots: &[String],
    protected: &[String],
    max_entries: i64,
    files_only: bool,
    max_output_bytes: i64,
) -> Result<Op, String> {
    delete_with(path, path_roots, protected, max_entries, files_only, max_output_bytes, &|| {})
}

/// [`delete`] with a seam between listing and deleting, for race tests.
#[allow(clippy::too_many_arguments)]
pub(crate) fn delete_with(
    path: &str,
    path_roots: &[String],
    protected: &[String],
    max_entries: i64,
    files_only: bool,
    max_output_bytes: i64,
    after_listing: &dyn Fn(),
) -> Result<Op, String> {
    let refuse = |why: &str| Ok(op(OUTCOME_FAILED, String::new(), format!("Refusing to delete {path}: {why} Nothing was deleted."), false));
    if !(1..=MAX_DELETE_ENTRIES).contains(&max_entries) {
        return Err(format!(
            "'max_entries' must be between 1 and {MAX_DELETE_ENTRIES} (MAX_DELETE_ENTRIES), not {max_entries}"
        ));
    }
    if !path.starts_with('/') {
        return refuse("the path must be absolute.");
    }
    if path.contains('\0') {
        return refuse("the path contains a NUL character.");
    }
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if comps.iter().any(|c| *c == "." || *c == "..") {
        return refuse("the path contains a '.' or '..' segment.");
    }
    if let Some(prot) = protected.iter().find(|p| comps.contains(&p.as_str())) {
        return refuse(&format!("it touches the protected resource {}.", repr_str(prot)));
    }
    let (root_real, below) = match match_root(&comps, path_roots) {
        Ok(Some(found)) => found,
        Ok(None) => return Ok(op(OUTCOME_FAILED, String::new(), format!("Refusing to delete the path root {path}"), false)),
        Err(why) => return refuse(&why),
    };
    let rest: Vec<CString> =
        comps[below..].iter().map(|c| CString::new(*c).expect("NUL refused above")).collect();
    let (final_name, parents) = rest.split_last().expect("a path below a root has a last component");

    let nothing = || Ok(op(OUTCOME_OK, format!("Nothing to delete at {path}"), String::new(), false));
    let open_failed = |err: i32| -> Result<Op, String> {
        match err {
            libc::ENOENT => nothing(),
            e if is_permission(e) => Ok(op(OUTCOME_FAILED, String::new(), format!("Permission denied: {path}"), false)),
            libc::ELOOP | libc::ENOTDIR => {
                refuse(&format!("the path contains a symlink or a non-directory ({}).", strerror(err)))
            }
            e => refuse(&format!("cannot open the path ({}).", strerror(e))),
        }
    };
    let fds = match open_chain(&root_real, parents) {
        Ok(fds) => fds,
        Err(err) => return open_failed(err),
    };
    let chain = match chain_idents(&fds) {
        Ok(chain) => chain,
        Err(err) => return open_failed(err),
    };
    let parent = fds.last().expect("root opened").as_raw_fd();
    let top_st = match stat_at(parent, final_name) {
        Ok(st) => st,
        Err(err) => return open_failed(err),
    };
    if is_link_mode(&top_st) {
        return refuse("the path is a symlink.");
    }

    // Phase 1: list everything, delete nothing.
    let is_dir = is_dir_mode(&top_st);
    let mut top = Entry { name: final_name.clone(), rel: String::new(), is_dir, ident: ident_of(&top_st), children: Vec::new() };
    let mut lines: Vec<String> = Vec::new();
    if is_dir {
        let limits = Limits { target: path, protected, max_entries: max_entries as usize, files_only };
        let listed = open_dir_checked(parent, &top, path)
            .and_then(|fd| list_tree(fd.as_raw_fd(), &mut top, &limits, &mut lines, 0));
        if let Err(why) = listed {
            return Ok(op(OUTCOME_FAILED, String::new(), format!("Aborted, nothing deleted: {why}"), false));
        }
    }
    lines.sort();

    after_listing();

    // Phase 2: the path must still lead to the listed tree; then remove
    // exactly what was listed.
    let mut deleted: Vec<String> = Vec::new();
    let removed = (|| -> Result<(), String> {
        let again = open_chain(&root_real, parents)
            .and_then(|fds| chain_idents(&fds))
            .map_err(|err| format!("the path changed since it was listed ({})", strerror(err)))?;
        if again != chain {
            return Err("the path changed since it was listed".to_string());
        }
        if is_dir {
            delete_dir(parent, &top, path, &mut deleted)
        } else {
            check_entry(parent, &top, path)?;
            unlink_at(parent, final_name, 0).map_err(|err| format!("cannot remove {path} ({})", strerror(err)))?;
            deleted.push(path.to_string());
            Ok(())
        }
    })();
    if let Err(why) = removed {
        let done = if deleted.is_empty() { "(nothing)".to_string() } else { deleted.join("\n") };
        let (stdout, truncated) = cap(&format!("deleted before abort:\n{done}"), max_output_bytes);
        let stderr = if deleted.is_empty() {
            format!("Aborted, nothing deleted: {why}.")
        } else {
            format!("{why}. Aborted after deleting {} entries (see stdout).", deleted.len())
        };
        return Ok(op(OUTCOME_FAILED, stdout, stderr, truncated));
    }

    // Phase 3: proof, not assumption.
    match stat_at(parent, final_name) {
        Err(libc::ENOENT) => {}
        _ => return Ok(op(OUTCOME_FAILED, String::new(), format!("Delete reported success but {path} still exists."), false)),
    }
    if !is_dir {
        return Ok(op(OUTCOME_OK, format!("Deleted {path}"), String::new(), false));
    }
    let header = format!("Deleted {path} (directory, {} entries below it):", lines.len());
    let (stdout, truncated) = cap(&format!("{header}\n{}", lines.join("\n")).trim_end().to_string(), max_output_bytes);
    Ok(op(OUTCOME_OK, stdout, String::new(), truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn tmp() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap().to_string_lossy().into_owned();
        (dir, root)
    }

    fn run(path: &str, root: &str, max_entries: i64, files_only: bool) -> Op {
        delete(path, &[root.to_string()], &["gatekeeper".to_string()], max_entries, files_only, 65536).unwrap()
    }

    fn tree(root: &str) -> String {
        let t = format!("{root}/t");
        std::fs::create_dir_all(format!("{t}/sub/deeper")).unwrap();
        std::fs::write(format!("{t}/a"), "a").unwrap();
        std::fs::write(format!("{t}/sub/b"), "b").unwrap();
        std::fs::write(format!("{t}/sub/deeper/c"), "c").unwrap();
        t
    }

    fn exists(p: &str) -> bool {
        std::fs::symlink_metadata(p).is_ok()
    }

    #[test]
    fn a_tree_goes_and_the_listing_says_what_went() {
        let (_d, root) = tmp();
        let t = tree(&root);
        let r = run(&t, &root, 10, false);
        assert_eq!(r.outcome, "ok", "{}", r.stderr);
        assert_eq!(
            r.stdout,
            format!("Deleted {t} (directory, 5 entries below it):\nd sub\nd sub/deeper\nf a\nf sub/b\nf sub/deeper/c")
        );
        assert!(!exists(&t));
        assert!(exists(&root));
    }

    #[test]
    fn a_file_goes_and_a_missing_path_is_nothing_to_delete() {
        let (_d, root) = tmp();
        let f = format!("{root}/f");
        std::fs::write(&f, "x").unwrap();
        let r = run(&f, &root, 1, true);
        assert_eq!((r.outcome, r.stdout.as_str()), ("ok", format!("Deleted {f}").as_str()));
        assert!(!exists(&f));
        let r = run(&f, &root, 1, true);
        assert_eq!((r.outcome, r.stdout), ("ok", format!("Nothing to delete at {f}")));
        let r = run(&format!("{root}/no/such/dir"), &root, 1, true);
        assert_eq!(r.outcome, "ok", "{}", r.stderr);
    }

    #[test]
    fn more_than_max_entries_deletes_nothing() {
        let (_d, root) = tmp();
        let t = tree(&root);
        let r = run(&t, &root, 4, false);
        assert_eq!(r.outcome, "failed");
        assert_eq!(r.stderr, format!("Aborted, nothing deleted: {t} has more than 4 entries (max_entries)"));
        assert!(exists(&format!("{t}/a")) && exists(&format!("{t}/sub/deeper/c")));
        // Exactly at the bound is fine.
        assert_eq!(run(&t, &root, 5, false).outcome, "ok");
    }

    #[test]
    fn files_only_refuses_any_sub_directory_and_deletes_nothing() {
        let (_d, root) = tmp();
        let t = tree(&root);
        let r = run(&t, &root, 100, true);
        assert_eq!(r.outcome, "failed");
        assert_eq!(r.stderr, format!("Aborted, nothing deleted: {t} contains the sub-directory 'sub' (files_only)"));
        assert!(exists(&format!("{t}/a")) && exists(&format!("{t}/sub/b")));

        let flat = format!("{root}/flat");
        std::fs::create_dir(&flat).unwrap();
        std::fs::write(format!("{flat}/x"), "x").unwrap();
        std::os::unix::fs::symlink("/", format!("{flat}/l")).unwrap();
        let r = run(&flat, &root, 100, true);
        assert_eq!(r.outcome, "ok", "{}", r.stderr);
        assert!(!exists(&flat));
    }

    fn nest(base: &str, levels: usize) -> String {
        let mut p = base.to_string();
        for _ in 0..levels {
            p.push_str("/d");
        }
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(format!("{p}/leaf"), "x").unwrap();
        p
    }

    #[test]
    fn deeper_than_64_levels_deletes_nothing() {
        let (_d, root) = tmp();
        let ok_tree = format!("{root}/ok");
        nest(&ok_tree, MAX_DELETE_DEPTH);
        let r = run(&ok_tree, &root, 1000, false);
        assert_eq!(r.outcome, "ok", "{}", r.stderr);
        assert!(!exists(&ok_tree));

        let deep = format!("{root}/deep");
        let leaf_dir = nest(&deep, MAX_DELETE_DEPTH + 1);
        let r = run(&deep, &root, 1000, false);
        assert_eq!(r.outcome, "failed");
        assert_eq!(r.stderr, format!("Aborted, nothing deleted: {deep} is nested deeper than 64 levels (MAX_DELETE_DEPTH)"));
        assert!(exists(&format!("{leaf_dir}/leaf")));
    }

    #[test]
    fn symlinks_are_removed_as_links_never_followed() {
        let (_d, root) = tmp();
        let (_o, outside) = tmp();
        std::fs::write(format!("{outside}/keep"), "x").unwrap();
        let t = format!("{root}/t");
        std::fs::create_dir(&t).unwrap();
        std::os::unix::fs::symlink(&outside, format!("{t}/link")).unwrap();
        let r = run(&t, &root, 10, false);
        assert_eq!(r.outcome, "ok", "{}", r.stderr);
        assert!(r.stdout.contains("\nl link"), "{}", r.stdout);
        assert!(exists(&format!("{outside}/keep")));

        // The target itself, or a directory on the way to it, a symlink: refused.
        std::fs::create_dir(format!("{root}/real")).unwrap();
        std::fs::write(format!("{root}/real/f"), "x").unwrap();
        std::os::unix::fs::symlink(format!("{root}/real"), format!("{root}/alias")).unwrap();
        let r = run(&format!("{root}/alias"), &root, 10, false);
        assert_eq!(r.stderr, format!("Refusing to delete {root}/alias: the path is a symlink. Nothing was deleted."));
        let r = run(&format!("{root}/alias/f"), &root, 10, false);
        assert!(r.stderr.starts_with(&format!("Refusing to delete {root}/alias/f: the path contains a symlink")), "{}", r.stderr);
        assert!(exists(&format!("{root}/real/f")));
    }

    #[test]
    fn roots_protected_names_and_dot_segments_are_refused() {
        let (_d, root) = tmp();
        let r = run(&root, &root, 10, false);
        assert_eq!(r.stderr, format!("Refusing to delete the path root {root}"));
        assert!(exists(&root));

        let t = format!("{root}/t");
        std::fs::create_dir_all(format!("{t}/x/gatekeeper")).unwrap();
        std::fs::write(format!("{t}/x/gatekeeper/cfg"), "x").unwrap();
        std::fs::write(format!("{t}/first"), "x").unwrap();
        let r = run(&t, &root, 10, false);
        assert_eq!(r.stderr, format!("Aborted, nothing deleted: {t} contains the protected resource 'x/gatekeeper'"));
        assert!(exists(&format!("{t}/first")));
        let r = run(&format!("{t}/x/gatekeeper/cfg"), &root, 10, false);
        assert!(r.stderr.contains("touches the protected resource 'gatekeeper'"), "{}", r.stderr);

        let r = run(&format!("{t}/x/../first"), &root, 10, false);
        assert!(r.stderr.contains("'.' or '..' segment"), "{}", r.stderr);
        let (_o, other) = tmp();
        let r = run(&format!("{other}/x"), &root, 10, false);
        assert!(r.stderr.contains("outside the path roots"), "{}", r.stderr);
        assert!(delete(&t, &[root.clone()], &[], 0, false, 100).is_err());
        assert!(delete(&t, &[root.clone()], &[], MAX_DELETE_ENTRIES + 1, false, 100).is_err());
    }

    fn race(path: &str, root: &str, swap: &dyn Fn()) -> Op {
        delete_with(path, &[root.to_string()], &[], 100, false, 65536, swap).unwrap()
    }

    #[test]
    fn a_directory_swapped_for_a_symlink_after_listing_is_not_followed() {
        let (_d, root) = tmp();
        let (_o, outside) = tmp();
        std::fs::write(format!("{outside}/b"), "keep").unwrap();
        let t = tree(&root);
        let sub = format!("{t}/sub");
        let r = race(&t, &root, &|| {
            std::fs::rename(&sub, format!("{root}/moved")).unwrap();
            std::os::unix::fs::symlink(&outside, &sub).unwrap();
        });
        assert_eq!(r.outcome, "failed");
        assert!(r.stdout.starts_with("deleted before abort:"), "{}", r.stdout);
        assert!(exists(&format!("{outside}/b")), "the symlink target was entered");
        assert!(exists(&format!("{root}/moved/deeper/c")), "the moved-away tree was touched");
    }

    #[test]
    fn a_parent_swapped_for_a_symlink_after_listing_aborts_before_anything_goes() {
        let (_d, root) = tmp();
        std::fs::create_dir(format!("{root}/p")).unwrap();
        let t = tree(&format!("{root}/p"));
        let (_o, outside) = tmp();
        std::fs::create_dir_all(format!("{outside}/t")).unwrap();
        std::fs::write(format!("{outside}/t/a"), "keep").unwrap();
        let r = race(&t, &root, &|| {
            std::fs::rename(format!("{root}/p"), format!("{root}/p.old")).unwrap();
            std::os::unix::fs::symlink(&outside, format!("{root}/p")).unwrap();
        });
        assert_eq!(r.outcome, "failed");
        assert!(r.stderr.starts_with("Aborted, nothing deleted: the path changed since it was listed"), "{}", r.stderr);
        assert!(exists(&format!("{outside}/t/a")));
        assert!(exists(&format!("{root}/p.old/t/sub/deeper/c")));
    }

    #[test]
    fn an_entry_added_or_replaced_after_listing_stops_the_delete() {
        let (_d, root) = tmp();
        let t = tree(&root);
        let r = race(&t, &root, &|| std::fs::write(format!("{t}/sub/new"), "x").unwrap());
        assert_eq!(r.outcome, "failed");
        assert!(r.stderr.contains("'sub' no longer matches the listing (unexpected: ['new'], missing: [])"), "{}", r.stderr);
        assert!(exists(&format!("{t}/sub/new")));

        let (_d2, root2) = tmp();
        let t2 = tree(&root2);
        let a = format!("{t2}/a");
        let r = race(&t2, &root2, &|| {
            std::fs::remove_file(&a).unwrap();
            std::fs::write(&a, "replaced").unwrap();
        });
        assert_eq!(r.outcome, "failed");
        assert!(r.stderr.contains("'a' was replaced since it was listed"), "{}", r.stderr);
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "replaced");
    }

    #[test]
    fn a_root_that_is_itself_a_symlink_still_works() {
        let (_d, base) = tmp();
        std::fs::create_dir(format!("{base}/real")).unwrap();
        std::os::unix::fs::symlink(format!("{base}/real"), format!("{base}/root")).unwrap();
        std::fs::write(format!("{base}/real/f"), "x").unwrap();
        let root = format!("{base}/root");
        let r = run(&format!("{root}/f"), &root, 1, false);
        assert_eq!(r.outcome, "ok", "{}", r.stderr);
        assert!(!Path::new(&format!("{base}/real/f")).exists());
    }
}
