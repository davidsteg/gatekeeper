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
import json
import os
import sys
import time
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
    path: Path,
    content: str | None = None,
    old_string: str | None = None,
    new_string: str | None = None,
    max_output_bytes: int,
) -> _Op:
    """Dispatches to the one operation, on an already-validated path.

    Split out from ``run`` so the in-process path and the ``run_as`` child
    execute literally the same code: there is one implementation of read,
    write, patch and list, not a privileged copy that could drift from the
    unprivileged one.
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

    if run_as is not None:
        # Path already checked above against this toolkit's Tier 1 roots --
        # the child re-checks it anyway (see `validate_path`).
        return await _run_as_user(
            run_as=run_as,
            operation=operation,
            path=str(validated),
            content=content,
            old_string=old_string,
            new_string=new_string,
            path_roots=path_roots,
            protected=protected,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            idempotent=idempotent,
            started=started,
        )

    try:
        result = perform(
            operation=operation,
            path=validated,
            content=content,
            old_string=old_string,
            new_string=new_string,
            max_output_bytes=max_output_bytes,
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
