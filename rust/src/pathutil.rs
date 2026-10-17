//! `os.path` semantics for POSIX paths.
//!
//! Path-root checks (`must_resolve_under`, the file executor's roots) were
//! written against `os.path.realpath`, `normpath` and `commonpath`. The
//! standard library's `canonicalize` is strict (it fails on a missing
//! component), which would turn "write a new file under the root" into an
//! error, so these are reimplemented with Python's exact behavior.

use std::path::Path;

/// `os.path.normpath`.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    // POSIX allows exactly two leading slashes to be special; Python keeps
    // them, three or more collapse to one.
    let initial = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else if path.starts_with('/') {
        1
    } else {
        0
    };
    let mut parts: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".." || (initial == 0 && parts.is_empty()) || parts.last() == Some(&"..") {
            parts.push(comp);
        } else if !parts.is_empty() {
            parts.pop();
        }
    }
    let mut out = "/".repeat(initial);
    out.push_str(&parts.join("/"));
    if out.is_empty() {
        ".".into()
    } else {
        out
    }
}

/// `os.path.abspath`.
pub fn abspath(path: &str) -> String {
    if path.starts_with('/') {
        normpath(path)
    } else {
        let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "/".into());
        normpath(&format!("{cwd}/{path}"))
    }
}

/// `os.path.join` for two components.
pub fn join(a: &str, b: &str) -> String {
    if b.starts_with('/') || a.is_empty() {
        b.to_string()
    } else if a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `os.path.basename`.
pub fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// `os.path.dirname`.
pub fn dirname(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => {
            let head = &path[..i + 1];
            let trimmed = head.trim_end_matches('/');
            if trimmed.is_empty() {
                head.to_string()
            } else {
                trimmed.to_string()
            }
        }
        None => String::new(),
    }
}

/// `os.path.realpath(path)` (non-strict): symlinks are resolved as far as
/// the path exists; the missing remainder is appended lexically.
pub fn realpath(path: &str) -> String {
    let abs = if path.starts_with('/') {
        path.to_string()
    } else {
        let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "/".into());
        format!("{cwd}/{path}")
    };
    let mut resolved = String::from("/");
    let mut pending: Vec<String> = abs.split('/').filter(|c| !c.is_empty()).map(|c| c.to_string()).collect();
    pending.reverse();
    let mut hops = 0usize;
    while let Some(comp) = pending.pop() {
        if comp == "." {
            continue;
        }
        if comp == ".." {
            resolved = dirname(&resolved);
            if resolved.is_empty() {
                resolved = "/".into();
            }
            continue;
        }
        let candidate = join(&resolved, &comp);
        match std::fs::symlink_metadata(&candidate) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > 40 {
                    // A loop: Python returns the path as-is from here on.
                    resolved = candidate;
                    continue;
                }
                match std::fs::read_link(&candidate) {
                    Ok(target) => {
                        let target = target.to_string_lossy().into_owned();
                        if target.starts_with('/') {
                            resolved = "/".into();
                        }
                        let mut parts: Vec<String> =
                            target.split('/').filter(|c| !c.is_empty()).map(|c| c.to_string()).collect();
                        parts.reverse();
                        pending.extend(parts);
                    }
                    Err(_) => resolved = candidate,
                }
            }
            _ => resolved = candidate,
        }
    }
    resolved
}

/// `os.path.commonpath` for absolute paths; `None` when they mix absolute
/// and relative (Python raises `ValueError`).
pub fn commonpath(paths: &[&str]) -> Option<String> {
    let first = paths.first()?;
    let absolute = first.starts_with('/');
    if paths.iter().any(|p| p.starts_with('/') != absolute) {
        return None;
    }
    let split: Vec<Vec<&str>> = paths
        .iter()
        .map(|p| p.split('/').filter(|c| !c.is_empty() && *c != ".").collect())
        .collect();
    let min = split.iter().map(|s| s.len()).min().unwrap_or(0);
    let mut common = Vec::new();
    for i in 0..min {
        let c = split[0][i];
        if split.iter().all(|s| s[i] == c) {
            common.push(c);
        } else {
            break;
        }
    }
    let prefix = if absolute { "/" } else { "" };
    Some(format!("{prefix}{}", common.join("/")))
}

/// True when `path` (already resolved) equals `root` or lies beneath it --
/// `os.path.commonpath([root, path]) == root`.
pub fn is_under(path: &str, root: &str) -> bool {
    commonpath(&[root, path]).is_some_and(|c| c == normpath(root))
}

pub fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_matches_python() {
        assert_eq!(normpath("/a/./b/../c/"), "/a/c");
        assert_eq!(normpath("a/../../b"), "../b");
        assert_eq!(normpath("/../x"), "/x");
        assert_eq!(normpath("//x"), "//x");
        assert_eq!(normpath("///x"), "/x");
        assert_eq!(normpath(""), ".");
    }

    #[test]
    fn realpath_resolves_links_and_missing_tails() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let base = base.to_str().unwrap();
        std::fs::create_dir(format!("{base}/real")).unwrap();
        std::os::unix::fs::symlink(format!("{base}/real"), format!("{base}/link")).unwrap();
        assert_eq!(realpath(&format!("{base}/link/new/file")), format!("{base}/real/new/file"));
        assert_eq!(realpath(&format!("{base}/link/../x")), format!("{base}/x"));
    }

    #[test]
    fn commonpath_and_under() {
        assert_eq!(commonpath(&["/srv/data", "/srv/data/x"]).unwrap(), "/srv/data");
        assert!(is_under("/srv/data/x", "/srv/data"));
        assert!(is_under("/srv/data", "/srv/data"));
        assert!(!is_under("/srv/database", "/srv/data"));
        assert_eq!(dirname("/a/b"), "/a");
        assert_eq!(dirname("/a"), "/");
        assert_eq!(basename("/a/b"), "b");
    }
}
