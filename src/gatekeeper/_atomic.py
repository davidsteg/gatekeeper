"""Shared atomic-write / optimistic-concurrency helpers for Tier 2 files.

Extracted from `store.py` so `credentials.py` can reuse the exact same
write discipline (fsync + os.replace, revision fingerprint, writability
check) without importing `store.py` -- which pulls in `Service` and would
create a circular import.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from typing import Any

import yaml

#: Header of every written file. Anyone who later opens it by hand should
#: immediately see that a console is co-writing here.
HEADER = (
    "# Managed by gatekeeper. The admin console writes this file;\n"
    "# manual changes are possible but will be lost on the next write\n"
    "# from the UI unless they have been reloaded beforehand.\n"
)


def revision(path: str) -> str:
    """Short fingerprint of the file content for the concurrency check."""
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()[:16]
    except OSError:
        return ""


def atomic_write(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, prefix=".gk-", suffix=".tmp", delete=False
    )
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def dump(payload: dict[str, Any]) -> str:
    return HEADER + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def writable(path: str) -> bool:
    """Can anything be written here at all?

    The directory is checked, not just the file: `os.replace` creates a
    new file. A mount with `:ro` is thus caught before an admin fills
    out a form and only discovers on submission that nothing arrives.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    return os.access(directory, os.W_OK) and (
        not os.path.exists(path) or os.access(path, os.W_OK)
    )
