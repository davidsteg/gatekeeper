"""Shared atomic-write / optimistic-concurrency helpers for Tier 2 files.

Extracted from `store.py` so `credentials.py` can reuse the exact same
write discipline (fsync + os.replace, revision fingerprint, writability
check) without importing `store.py` -- which pulls in `Service` and would
create a circular import.
"""

from __future__ import annotations

import copy
import hashlib
import os
import tempfile
import threading
from typing import Any

import yaml

#: libyaml when the PyYAML build has it (the manylinux wheels do) -- about
#: 8x faster than the pure-Python loader, and just as safe.
_SafeLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
#: Same for writing: the pure-Python emitter was the larger half of an
#: approval's cost, since one rewrites pending.yaml with all its history.
_SafeDumper = getattr(yaml, "CSafeDumper", yaml.SafeDumper)

_cache: dict[str, tuple[str, Any]] = {}
_cache_lock = threading.Lock()

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


def safe_load(text: str | bytes) -> Any:
    """`yaml.safe_load`, through libyaml when available.

    For whole config files. `yaml.safe_load` itself always takes the
    pure-Python loader, which costs seconds per approval once tools.yaml
    and pending.yaml hold a few hundred entries.
    """
    return yaml.load(text, Loader=_SafeLoader)


def load_cached(path: str) -> Any:
    """`yaml.safe_load` of `path`, parsed once per distinct file content.

    Every console page counts the pending queues for the sidebar badge,
    and those files only grow -- decided entries are kept as history. On a
    deployment with a few hundred of them, re-parsing on every request
    cost over a second per page. Keyed by content hash, not mtime: hashing
    is under a millisecond for a megabyte, and it cannot miss a rewrite
    that lands within the filesystem's mtime granularity.

    Returns a deep copy, because the stores' write paths mutate what they
    load before writing it back. Missing file -> None.
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except FileNotFoundError:
        return None
    digest = hashlib.sha256(data).hexdigest()
    key = os.path.abspath(path)
    with _cache_lock:
        hit = _cache.get(key)
    if hit is None or hit[0] != digest:
        hit = (digest, safe_load(data.decode("utf-8")))
        with _cache_lock:
            _cache[key] = hit
    return copy.deepcopy(hit[1])


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
    return HEADER + yaml.dump(
        payload, Dumper=_SafeDumper, sort_keys=False, allow_unicode=True
    )


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
