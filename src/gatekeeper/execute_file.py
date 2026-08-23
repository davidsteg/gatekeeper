"""Built-in file executor (REQUIREMENTS.md §8, FR-4).

Unlike the ``local`` executor (which runs external binaries via argv),
the ``file`` executor performs read/write/patch/list operations directly
in Python — no shell, no process spawn, no argv chaining. This is the
safe way to give an agent file read/write access: every operation is
constrained by ``path_roots`` and ``protected_resources`` in Tier 1, and
the operation type is fixed per tool (``read``/``write``/``patch``/``list``),
not a free-form command.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .execute import OUTCOME_FAILED, OUTCOME_OK, Result


def _validate_path(
    path: str, path_roots: list[str], protected: list[str]
) -> Path:
    """Resolves ``path`` and checks it against ``path_roots``.

    Rejects ``..`` traversal, symlinks that escape the root, and any
    path that touches a protected resource directory.
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
) -> Result:
    """Executes a file operation directly in Python."""
    started = time.monotonic()

    try:
        validated = _validate_path(path, path_roots, protected)
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

    try:
        if operation == "read":
            result = await _read(validated, max_output_bytes)
        elif operation == "write":
            if content is None:
                raise ValueError("'content' parameter is required for write")
            result = await _write(validated, content)
        elif operation == "patch":
            if old_string is None or new_string is None:
                raise ValueError("'old_string' and 'new_string' are required for patch")
            result = await _patch(validated, old_string, new_string)
        elif operation == "list":
            result = await _list(validated, max_output_bytes)
        else:
            raise ValueError(f"Unknown file operation: {operation!r}")
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


async def _read(path: Path, max_output_bytes: int) -> tuple[str, int | None, str, str, bool]:
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


async def _write(path: Path, content: str) -> tuple[str, int | None, str, str, bool]:
    """Writes content to a file, creating parent directories."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except PermissionError:
        return (OUTCOME_FAILED, 1, "", f"Permission denied: {path}", False)
    except OSError as exc:
        return (OUTCOME_FAILED, 1, "", f"Write error: {exc}", False)

    return (OUTCOME_OK, 0, f"Written {len(content)} bytes to {path}", "", False)


async def _patch(
    path: Path, old_string: str, new_string: str
) -> tuple[str, int | None, str, str, bool]:
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


async def _list(path: Path, max_output_bytes: int) -> tuple[str, int | None, str, str, bool]:
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