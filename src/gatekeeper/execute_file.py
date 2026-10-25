"""Built-in file executor (REQUIREMENTS.md §8, FR-4).

Unlike the ``local`` executor (which runs external binaries via argv),
the ``file`` executor performs read/write/patch/list operations directly
in Python — no shell, no process spawn, no argv chaining. This is the
safe way to give an agent file read/write access: every operation is
constrained by ``path_roots`` and ``protected_resources`` in Tier 1, and
the operation type is fixed per tool (``read``/``write``/``patch``/``list``),
not a free-form command.

One exception to "no process spawn": a toolkit that sets ``run_as``
(Tier 1, ``file`` toolkits only) runs its operations as a different OS
user, which an in-process executor structurally cannot do -- see
``_runas.py`` for why that means a child process and what it guarantees.
A toolkit *without* ``run_as`` -- the default, and every toolkit that
existed before the field did -- takes exactly the same in-process path as
before, unchanged.
"""

from __future__ import annotations

import asyncio
import errno
import json
import os
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result

#: The 5-tuple every operation below returns:
#: ``(outcome, exit_code, stdout, stderr, truncated)``.
_Op = tuple[str, int | None, str, str, bool]


def validate_path(
    path: str, path_roots: list[str], protected: list[str]
) -> Path:
    """Resolves ``path`` and checks it against ``path_roots``.

    Rejects ``..`` traversal, symlinks that escape the root, and any
    path that touches a protected resource directory.

    Public (rather than ``_``-prefixed) because ``_runas.py`` re-runs it
    inside the privileged child: the parent's check is the real gate, the
    child's is there so the half that may hold elevated rights never
    trusts a path it did not itself check against Tier 1.
    """
    raw = Path(path)
    if not raw.is_absolute():
        raise ValueError(f"Path must be absolute: {path!r}")

    # Normalise and resolve — but don't follow symlinks yet.
    # realpath resolves symlinks (FR-4.3).
    resolved = Path(os.path.realpath(raw))

    # Check path_roots
    if not path_roots:
        raise ValueError("No path_roots configured for this toolkit")

    allowed = False
    for root in path_roots:
        root_resolved = Path(os.path.realpath(root))
        try:
            resolved.relative_to(root_resolved)
            allowed = True
            break
        except ValueError:
            continue

    if not allowed:
        raise ValueError(
            f"Path {path!r} (resolved to {resolved}) is outside allowed roots: {path_roots}"
        )

    # Check protected_resources — reject if any segment matches
    parts = resolved.parts
    for prot in protected:
        if prot in parts:
            raise ValueError(f"Path {path!r} touches protected resource {prot!r}")

    return resolved


def perform(
    *,
    operation: str,
    path: Path | str,
    content: str | None = None,
    old_string: str | None = None,
    new_string: str | None = None,
    max_output_bytes: int,
    max_entries: int | None = None,
    files_only: bool = False,
    path_roots: list[str] | None = None,
    protected: list[str] | None = None,
) -> _Op:
    """Dispatches to the one operation, on an already-validated path.

    Split out from ``run`` so the in-process path and the ``run_as`` child
    execute literally the same code: there is one implementation of read,
    write, patch and list, not a privileged copy that could drift from the
    unprivileged one.

    ``delete`` is the exception to "already-validated": it takes the
    *original* path string, not ``validate_path``'s resolved one (resolving
    would silently turn a symlink in the path into its target), plus
    ``path_roots`` and ``protected``, and does its own authoritative checks
    -- so the ``run_as`` child gets them too, not just the parent.
    """
    if operation == "read":
        return _read(path, max_output_bytes)
    if operation == "write":
        if content is None:
            raise ValueError("'content' parameter is required for write")
        return _write(path, content)
    if operation == "patch":
        if old_string is None or new_string is None:
            raise ValueError("'old_string' and 'new_string' are required for patch")
        return _patch(path, old_string, new_string)
    if operation == "list":
        return _list(path, max_output_bytes)
    if operation == "delete":
        if max_entries is None:
            raise ValueError("'max_entries' is required for delete")
        if not 1 <= max_entries <= MAX_DELETE_ENTRIES:
            raise ValueError(
                f"'max_entries' must be between 1 and {MAX_DELETE_ENTRIES} "
                f"(MAX_DELETE_ENTRIES), not {max_entries}"
            )
        if not path_roots:
            raise ValueError("'path_roots' is required for delete")
        return _delete(
            str(path), list(path_roots), list(protected or []),
            max_entries, files_only, max_output_bytes,
        )
    raise ValueError(f"Unknown file operation: {operation!r}")


async def run(
    *,
    operation: str,
    path: str,
    content: str | None = None,
    old_string: str | None = None,
    new_string: str | None = None,
    path_roots: list[str],
    protected: list[str],
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool = False,
    run_as: str | None = None,
    max_entries: int | None = None,
    files_only: bool = False,
) -> Result:
    """Executes a file operation directly in Python."""
    started = time.monotonic()

    try:
        validated = validate_path(path, path_roots, protected)
    except ValueError as exc:
        duration = int((time.monotonic() - started) * 1000)
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=1,
            stdout="",
            stderr=str(exc),
            truncated=False,
            duration_ms=duration,
        )

    # `validate_path` resolves symlinks before its scope check -- right for
    # reading, wrong for deleting: a symlink in the path would make the
    # delete act on its target. So delete gets the path as the agent sent it,
    # and `_delete` (in this process or in the run_as child) walks it itself
    # without following symlinks.
    target: Path | str = path if operation == "delete" else validated

    if run_as is not None:
        # Path already checked above against this toolkit's Tier 1 roots --
        # the child re-checks it anyway (see `validate_path`).
        return await _run_as_user(
            run_as=run_as,
            operation=operation,
            path=str(target),
            content=content,
            old_string=old_string,
            new_string=new_string,
            path_roots=path_roots,
            protected=protected,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            idempotent=idempotent,
            started=started,
            max_entries=max_entries,
            files_only=files_only,
        )

    try:
        result = perform(
            operation=operation,
            path=target,
            content=content,
            old_string=old_string,
            new_string=new_string,
            max_output_bytes=max_output_bytes,
            max_entries=max_entries,
            files_only=files_only,
            path_roots=path_roots,
            protected=protected,
        )
    except Exception as exc:
        duration = int((time.monotonic() - started) * 1000)
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=1,
            stdout="",
            stderr=str(exc),
            truncated=False,
            duration_ms=duration,
        )

    duration = int((time.monotonic() - started) * 1000)
    return Result(
        outcome=result[0],
        exit_code=result[1],
        stdout=result[2],
        stderr=result[3],
        truncated=result[4],
        duration_ms=duration,
    )


async def _run_as_user(
    *,
    run_as: str,
    operation: str,
    path: str,
    content: str | None,
    old_string: str | None,
    new_string: str | None,
    path_roots: list[str],
    protected: list[str],
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    started: float,
    max_entries: int | None = None,
    files_only: bool = False,
) -> Result:
    """Runs one operation in a child process that first becomes ``run_as``.

    argv is fixed -- interpreter, ``-m``, module name, nothing else. No
    agent-supplied value reaches it (the request goes over stdin, see
    ``_runas._main``), so there is no argv to validate here in the sense
    FR-5.4 means: there are no template elements to fill.
    """
    request = json.dumps(
        {
            "run_as": run_as,
            "operation": operation,
            "path": path,
            "content": content,
            "old_string": old_string,
            "new_string": new_string,
            "path_roots": list(path_roots),
            "protected": list(protected),
            "max_output_bytes": max_output_bytes,
            "max_entries": max_entries,
            "files_only": files_only,
        }
    ).encode("utf-8")

    def done(outcome: str, exit_code: int | None, out: str, err: str, trunc: bool) -> Result:
        return Result(
            outcome=outcome,
            exit_code=exit_code,
            stdout=out,
            stderr=err,
            truncated=trunc,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "gatekeeper._runas",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=sys.platform != "win32",
        )
    except OSError as exc:
        return done(OUTCOME_FAILED, 1, "", f"Cannot start the run_as helper: {exc}", False)

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(request), timeout=timeout_seconds
        )
    except TimeoutError:
        _kill(process)
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            pass
        # Same honesty rule as `execute.run` (FR-6.9): a killed `write` may
        # or may not have hit the disk, and reporting that as `failed`
        # invites the retry that truncates a file twice.
        return done(
            OUTCOME_FAILED if idempotent else OUTCOME_UNKNOWN,
            None,
            "",
            (
                f"Timeout of {timeout_seconds}s exceeded, run_as helper killed."
                if idempotent
                else (
                    f"Timeout of {timeout_seconds}s exceeded, run_as helper killed. "
                    "The outcome is UNKNOWN: the operation may have completed. "
                    "Do not retry without checking the state first."
                )
            ),
            False,
        )

    try:
        payload = json.loads(stdout_bytes.decode("utf-8"))
        outcome = str(payload["outcome"])
        out = str(payload.get("stdout", ""))
        err = str(payload.get("stderr", ""))
        truncated = bool(payload.get("truncated", False))
        exit_code = payload.get("exit_code")
    except (ValueError, KeyError, UnicodeDecodeError):
        # The helper writes a JSON result even when the operation fails, so
        # getting here means it died before it could -- an import error, an
        # OOM kill. Its stderr is the only useful thing left; capped,
        # because a traceback is not a reason to hand the agent an
        # unbounded string.
        detail = stderr_bytes.decode("utf-8", errors="replace")[:2000].strip()
        return done(
            OUTCOME_FAILED,
            process.returncode,
            "",
            f"run_as helper failed (exit {process.returncode}): {detail or 'no output'}",
            False,
        )

    # The child caps its own output; re-capping here means a helper that
    # ever stopped doing so cannot widen this toolkit's `max_output_bytes`.
    if len(out.encode("utf-8")) > max_output_bytes:
        out = out.encode("utf-8")[:max_output_bytes].decode("utf-8", errors="ignore")
        truncated = True
    return done(
        outcome,
        exit_code if isinstance(exit_code, int) else None,
        out,
        err,
        truncated,
    )


def _kill(process: asyncio.subprocess.Process) -> None:
    """Kills the helper's whole session, mirroring `execute._terminate`."""
    if process.returncode is not None:
        return
    if sys.platform != "win32":
        try:
            os.killpg(os.getpgid(process.pid), 9)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        process.kill()
    except ProcessLookupError:
        pass


def _read(path: Path, max_output_bytes: int) -> _Op:
    """Reads a file, capped at ``max_output_bytes``."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return (OUTCOME_FAILED, 1, "", f"File not found: {path}", False)
    except IsADirectoryError:
        return (OUTCOME_FAILED, 1, "", f"Is a directory: {path}", False)
    except PermissionError:
        return (OUTCOME_FAILED, 1, "", f"Permission denied: {path}", False)

    truncated = False
    if len(data) > max_output_bytes:
        data = data[:max_output_bytes]
        truncated = True

    text = data.decode("utf-8", errors="replace")
    suffix = "\n... [truncated]" if truncated else ""
    return (OUTCOME_OK, 0, text + suffix, "", truncated)


def _write(path: Path, content: str) -> _Op:
    """Writes content to a file, creating parent directories."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except PermissionError:
        return (OUTCOME_FAILED, 1, "", f"Permission denied: {path}", False)
    except OSError as exc:
        return (OUTCOME_FAILED, 1, "", f"Write error: {exc}", False)

    return (OUTCOME_OK, 0, f"Written {len(content)} bytes to {path}", "", False)


def _patch(path: Path, old_string: str, new_string: str) -> _Op:
    """Replaces ``old_string`` with ``new_string`` in a file."""
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return (OUTCOME_FAILED, 1, "", f"File not found: {path}", False)
    except PermissionError:
        return (OUTCOME_FAILED, 1, "", f"Permission denied: {path}", False)

    count = content.count(old_string)
    if count == 0:
        return (OUTCOME_FAILED, 1, "", f"old_string not found in {path}", False)
    if count > 1:
        return (
            OUTCOME_FAILED,
            1,
            "",
            f"old_string found {count} times in {path} — must be unique",
            False,
        )

    new_content = content.replace(old_string, new_string)
    try:
        path.write_text(new_content, encoding="utf-8")
    except PermissionError:
        return (OUTCOME_FAILED, 1, "", f"Permission denied: {path}", False)

    return (OUTCOME_OK, 0, f"Patched 1 occurrence in {path}", "", False)


def _list(path: Path, max_output_bytes: int) -> _Op:
    """Lists directory entries (one per line)."""
    try:
        entries = sorted(path.iterdir(), key=lambda p: p.name)
    except FileNotFoundError:
        return (OUTCOME_FAILED, 1, "", f"Directory not found: {path}", False)
    except NotADirectoryError:
        return (OUTCOME_FAILED, 1, "", f"Not a directory: {path}", False)
    except PermissionError:
        return (OUTCOME_FAILED, 1, "", f"Permission denied: {path}", False)

    lines: list[str] = []
    total = 0
    truncated = False
    for entry in entries:
        prefix = "d " if entry.is_dir() else "f "
        line = prefix + entry.name
        total += len(line) + 1
        if total > max_output_bytes:
            truncated = True
            break
        lines.append(line)

    text = "\n".join(lines)
    if truncated:
        text += "\n... [truncated]"
    return (OUTCOME_OK, 0, text, "", truncated)


#: Flags for walking a delete target. Every component below the root is
#: opened ``O_NOFOLLOW`` relative to its parent's fd, so a symlink anywhere
#: in the path -- present before the call or swapped in during it -- fails
#: the open instead of being followed. ``getattr``: neither flag exists on
#: Windows, where ``dir_fd`` is unsupported anyway (see ``_delete``).
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW_DIR_FLAGS = _DIR_FLAGS | getattr(os, "O_NOFOLLOW", 0)

#: How many directory levels below the target a delete descends (the target
#: is level 0, its sub-directories level 1). Each level holds one directory
#: fd open while listing and while deleting, and costs ~2 Python stack
#: frames: 64 keeps a call at <= 64 + path-component fds, far under a
#: typical RLIMIT_NOFILE (1024/4096), and far under the interpreter's
#: recursion limit (~1000) with headroom for the caller's frames. Real
#: cleanup trees (caches, build and download dirs) are far shallower.
MAX_DELETE_DEPTH = 64

#: Same value as `catalog.MAX_DELETE_ENTRIES` (see there for why); repeated
#: so the `run_as` child need not import the catalog. A test keeps them equal.
MAX_DELETE_ENTRIES = 100_000


class _DeleteAbort(Exception):
    """An anomaly during a delete: stop at once, report what was removed."""


@dataclass
class _Entry:
    """One listed entry, with the identity it must still have when deleted."""

    name: str
    rel: str
    kind: str  # "f" | "d" | "l"
    ident: tuple[int, int, int]  # (st_dev, st_ino, file type)
    children: list[_Entry] = field(default_factory=list)


def _ident(st: os.stat_result) -> tuple[int, int, int]:
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode))


def _open_into(fds: list[int], name: str, flags: int, dir_fd: int | None = None) -> None:
    """Opens ``name`` and appends the fd to ``fds`` -- or closes it again."""
    fd = os.open(name, flags, dir_fd=dir_fd)
    try:
        fds.append(fd)
    except BaseException:
        os.close(fd)
        raise


def _after_listing(path: str) -> None:
    """No-op seam between listing and deleting; tests patch it to race."""


def _delete(
    path: str,
    path_roots: list[str],
    protected: list[str],
    max_entries: int,
    files_only: bool,
    max_output_bytes: int,
) -> _Op:
    """Lists the tree under ``path``, then deletes exactly that -- or aborts.

    ``path`` is the caller's original string, not a resolved one. Nothing
    here touches the filesystem by path string: the matching path root is
    opened (via its realpath -- a root may be a symlink by admin config),
    every component below it is opened ``O_NOFOLLOW`` relative to its
    parent's fd, and listing and deleting work on those fds only. A symlink
    in any component, including the target itself, is refused.

    The listing decides: more than ``max_entries`` entries, any
    sub-directory (``files_only``), or any entry named in ``protected``
    aborts before a single entry is removed. The delete then removes the
    listed entries -- and only those -- bottom-up, re-checking each one's
    ``(st_dev, st_ino, type)`` right before it goes; an extra, missing or
    changed entry stops it at the first anomaly, and the report says what
    was removed by then. Symlinks inside the tree are listed (``l``) and
    removed as links, never followed. The proof comes last: the target's
    name no longer exists in its parent, checked, not assumed.
    """
    def refuse(why: str) -> _Op:
        return (OUTCOME_FAILED, 1, "", f"Refusing to delete {path!r}: {why} Nothing was deleted.",
                False)

    if not {os.open, os.stat, os.unlink, os.rmdir} <= os.supports_dir_fd:
        return refuse("this platform cannot delete without following symlinks.")
    if not path.startswith("/"):
        return refuse("the path must be absolute.")
    comps = [c for c in path.split("/") if c]
    if any(c in (".", "..") for c in comps):
        return refuse("the path contains a '.' or '..' segment.")
    for prot in protected:
        if prot in comps:
            return refuse(f"it touches the protected resource {prot!r}.")

    root_real, rest, problem = _match_root(comps, path_roots)
    if problem:
        return refuse(problem)
    final = rest[-1]

    # Open root + every directory down to the target's parent, no symlinks.
    fds: list[int] = []
    deleted: list[str] = []
    try:
        try:
            _open_into(fds, root_real, _DIR_FLAGS)
            for name in rest[:-1]:
                _open_into(fds, name, _NOFOLLOW_DIR_FLAGS, dir_fd=fds[-1])
            top_st = os.stat(final, dir_fd=fds[-1], follow_symlinks=False)
            chain = [_ident(os.fstat(fd)) for fd in fds]
        except FileNotFoundError:
            return (OUTCOME_FAILED, 1, "", f"Not found: {path}", False)
        except PermissionError:
            return (OUTCOME_FAILED, 1, "", f"Permission denied: {path}", False)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                # O_NOFOLLOW hit a symlink, or a component is not a directory.
                return refuse(
                    f"the path contains a symlink or a non-directory ({exc.strerror})."
                )
            return refuse(f"cannot open the path ({exc.strerror}).")
        if stat.S_ISLNK(top_st.st_mode):
            return refuse("the path is a symlink.")
        parent_fd = fds[-1]

        is_dir = stat.S_ISDIR(top_st.st_mode)
        top = _Entry(final, "", "d" if is_dir else "f", _ident(top_st))
        entries: list[str] = []
        try:
            if is_dir:
                fd = _open_dir_checked(parent_fd, top)
                try:
                    _list_tree(fd, top, path, protected, files_only, max_entries, entries, 0)
                finally:
                    os.close(fd)
        except _DeleteAbort as exc:
            return (OUTCOME_FAILED, 1, "", f"Aborted, nothing deleted: {exc}", False)
        except PermissionError as exc:
            return (OUTCOME_FAILED, 1, "", f"Permission denied: {exc}. Nothing was deleted.",
                    False)
        except (OSError, RecursionError, MemoryError) as exc:
            return (OUTCOME_FAILED, 1, "",
                    f"Aborted, nothing deleted: listing failed ({type(exc).__name__}: {exc})",
                    False)
        listing = _cap("\n".join(sorted(entries)), max_output_bytes)

        _after_listing(path)

        try:
            _check_chain(root_real, rest[:-1], chain)
            if is_dir:
                _delete_dir(parent_fd, top, path, deleted)
            else:
                _check_entry(parent_fd, top)
                os.unlink(final, dir_fd=parent_fd)
                deleted.append(path)
        except (_DeleteAbort, OSError, RecursionError, MemoryError) as exc:
            done = "\n".join(deleted) if deleted else "(nothing)"
            if isinstance(exc, PermissionError):
                msg = f"Permission denied: {exc}."
            else:
                msg = f"{exc}." if isinstance(exc, _DeleteAbort) else f"Delete error: {exc}."
            if deleted:
                msg += f" Aborted after deleting {len(deleted)} entries (see stdout)."
            else:
                msg = f"Aborted, nothing deleted: {msg}"
            return (OUTCOME_FAILED, 1, _cap(f"deleted before abort:\n{done}", max_output_bytes),
                    msg, False)

        kind = "directory" if is_dir else "file"
        header = f"listed {len(entries)} entries under {kind} {path}:"
        try:
            os.stat(final, dir_fd=parent_fd, follow_symlinks=False)
            still_there = True
        except FileNotFoundError:
            still_there = False
        if still_there:
            return (
                OUTCOME_FAILED, 1, f"{header}\n{listing}",
                f"Delete reported success but {path} still exists.", False,
            )
        return (
            OUTCOME_OK, 0,
            f"{header}\n{listing}\nremoved: {path} (path no longer exists)".replace(":\n\n", ":\n"),
            "", False,
        )
    finally:
        for fd in fds:
            os.close(fd)


def _match_root(
    comps: list[str], path_roots: list[str]
) -> tuple[str, list[str], str | None]:
    """Picks the path root ``comps`` lies under, literally (no resolving).

    A root matches by its abspath or its realpath, compared by components.
    Returns ``(root realpath, components below it, problem)``.
    """
    best: tuple[str, list[str]] | None = None
    for root in path_roots:
        real = os.path.realpath(root)
        for cand in (os.path.abspath(root), real):
            rc = [c for c in cand.split("/") if c]
            if comps == rc:
                return ("", [], "it is a configured path root.")
            if comps[: len(rc)] == rc and (best is None or len(rc) > len(best[1])):
                best = (real, rc)
    if best is None:
        return ("", [], "the path contains a symlink or is outside the path roots.")
    return (best[0], comps[len(best[1]):], None)


def _open_dir_checked(parent_fd: int, entry: _Entry) -> int:
    """Opens ``entry`` under ``parent_fd`` without following symlinks.

    The opened directory must still be the one that was listed. The fd is
    closed again on any exception, so a failed call never leaks one.
    """
    where = entry.rel or entry.name
    try:
        fd = os.open(entry.name, _NOFOLLOW_DIR_FLAGS, dir_fd=parent_fd)
    except PermissionError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise _DeleteAbort(
                f"cannot open directory {where!r} without following symlinks ({exc.strerror})"
            ) from exc
        raise _DeleteAbort(f"cannot open directory {where!r} ({exc.strerror})") from exc
    try:
        if _ident(os.fstat(fd)) != entry.ident:
            raise _DeleteAbort(f"directory {where!r} changed since it was listed")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _list_tree(
    dir_fd: int,
    node: _Entry,
    target: str,
    protected: list[str],
    files_only: bool,
    max_entries: int,
    entries: list[str],
    depth: int,
) -> None:
    """Lists ``node``'s directory (open as ``dir_fd``), recursively, by fd.

    ``depth`` is ``node``'s level below the target (the target is 0); a
    sub-directory deeper than ``MAX_DELETE_DEPTH`` aborts before it is opened.
    """
    for name in sorted(os.listdir(dir_fd)):
        rel = f"{node.rel}/{name}" if node.rel else name
        if name in protected:
            raise _DeleteAbort(f"{target} contains the protected resource {rel!r}")
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            kind = "l"
        elif stat.S_ISDIR(st.st_mode):
            if files_only:
                raise _DeleteAbort(f"{target} contains the sub-directory {rel!r} (files_only).")
            kind = "d"
        else:
            kind = "f"
        child = _Entry(name, rel, kind, _ident(st))
        node.children.append(child)
        entries.append(f"{kind} {rel}")
        if len(entries) > max_entries:
            raise _DeleteAbort(
                f"{target} has more than {max_entries} entries (max_entries)."
            )
        if kind == "d":
            if depth + 1 > MAX_DELETE_DEPTH:
                raise _DeleteAbort(
                    f"{target} is nested deeper than {MAX_DELETE_DEPTH} levels "
                    "(MAX_DELETE_DEPTH)"
                )
            fd = _open_dir_checked(dir_fd, child)
            try:
                _list_tree(fd, child, target, protected, files_only, max_entries, entries,
                           depth + 1)
            finally:
                os.close(fd)


def _check_entry(dir_fd: int, entry: _Entry) -> None:
    """``entry`` must still exist under ``dir_fd`` with its listed identity."""
    try:
        st = os.stat(entry.name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise _DeleteAbort(f"{entry.rel or entry.name!r} vanished since it was listed") from exc
    if _ident(st) != entry.ident:
        raise _DeleteAbort(f"{entry.rel or entry.name!r} was replaced since it was listed")


def _check_chain(root_real: str, comps: list[str], chain: list[tuple[int, int, int]]) -> None:
    """Re-walks root -> target's parent; every directory must be the listed one.

    This makes a path that was changed under the delete fail loudly instead
    of deleting a tree that is no longer at the requested path. It cannot
    pin the path: right after this check the tree may still be renamed
    elsewhere. What holds regardless is that only listed entries with a
    matching ``(st_dev, st_ino, type)`` are removed, through the fds held
    since the listing, never following a symlink.
    """
    fds: list[int] = []
    try:
        try:
            _open_into(fds, root_real, _DIR_FLAGS)
            for name in comps:
                _open_into(fds, name, _NOFOLLOW_DIR_FLAGS, dir_fd=fds[-1])
        except OSError as exc:
            raise _DeleteAbort(
                f"the path changed since it was listed ({exc.strerror})"
            ) from exc
        if [_ident(os.fstat(fd)) for fd in fds] != chain:
            raise _DeleteAbort("the path changed since it was listed")
    finally:
        for fd in fds:
            os.close(fd)


def _delete_dir(parent_fd: int, node: _Entry, target: str, deleted: list[str]) -> None:
    """Removes exactly ``node``'s listed entries, bottom-up, then ``node``."""
    fd = _open_dir_checked(parent_fd, node)
    try:
        expected = {child.name for child in node.children}
        current = set(os.listdir(fd))
        if current != expected:
            extra = sorted(current - expected)
            missing = sorted(expected - current)
            where = node.rel or target
            raise _DeleteAbort(
                f"{where!r} no longer matches the listing (unexpected: {extra[:5]}, "
                f"missing: {missing[:5]})"
            )
        for child in node.children:
            if child.kind == "d":
                _delete_dir(fd, child, target, deleted)
            else:
                _check_entry(fd, child)
                os.unlink(child.name, dir_fd=fd)
                deleted.append(child.rel)
    finally:
        os.close(fd)
    _check_entry(parent_fd, node)
    # A directory that gained an entry since the check fails here (ENOTEMPTY).
    os.rmdir(node.name, dir_fd=parent_fd)
    deleted.append(node.rel or target)


def _cap(text: str, max_output_bytes: int) -> str:
    """Caps ``text`` at ``max_output_bytes`` UTF-8 bytes."""
    data = text.encode("utf-8")
    if len(data) <= max_output_bytes:
        return text
    return data[:max_output_bytes].decode("utf-8", errors="ignore") + "\n... [truncated]"
