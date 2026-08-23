"""Tests for the built-in file executor (read/write/patch/list).

The ``file`` executor performs operations directly in Python — no shell,
no argv. Path validation enforces ``path_roots`` and ``protected_resources``
from Tier 1.
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from gatekeeper.execute_file import run as file_run


@pytest.fixture
def tmp_root(tmp_path: str) -> str:
    """A temp directory that acts as path_root."""
    return str(tmp_path)


@pytest.fixture
def protected_names() -> list[str]:
    return ["gatekeeper", "dockhand", "ix-dockhand", "traefik"]


async def _run(*args, **kwargs):
    return await file_run(**kwargs)


def test_read_file(tmp_root, protected_names, tmp_path):
    f = os.path.join(tmp_root, "test.txt")
    with open(f, "w") as fh:
        fh.write("hello world")

    result = asyncio.run(_run(
        operation="read", path=f, path_roots=[tmp_root],
        protected=protected_names, timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "ok"
    assert "hello world" in result.stdout


def test_read_nonexistent(tmp_root, protected_names):
    result = asyncio.run(_run(
        operation="read", path=os.path.join(tmp_root, "missing.txt"),
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "failed"
    assert "not found" in result.stderr.lower()


def test_write_file(tmp_root, protected_names):
    path = os.path.join(tmp_root, "subdir", "output.txt")
    result = asyncio.run(_run(
        operation="write", path=path, content="new content",
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "ok"
    assert os.path.exists(path)
    with open(path) as f:
        assert f.read() == "new content"


def test_write_creates_parent_dirs(tmp_root, protected_names):
    path = os.path.join(tmp_root, "deep", "nested", "dir", "file.yaml")
    result = asyncio.run(_run(
        operation="write", path=path, content="key: value",
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "ok"
    assert os.path.exists(path)


def test_patch_file(tmp_root, protected_names):
    path = os.path.join(tmp_root, "config.yaml")
    with open(path, "w") as f:
        f.write("version: 1\nname: test\n")

    result = asyncio.run(_run(
        operation="patch", path=path,
        old_string="version: 1", new_string="version: 2",
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "ok"
    with open(path) as f:
        assert "version: 2" in f.read()


def test_patch_not_found(tmp_root, protected_names):
    path = os.path.join(tmp_root, "config.txt")
    with open(path, "w") as f:
        f.write("nothing relevant here")

    result = asyncio.run(_run(
        operation="patch", path=path,
        old_string="missing", new_string="found",
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "failed"
    assert "not found" in result.stderr.lower()


def test_patch_multiple_matches_rejected(tmp_root, protected_names):
    path = os.path.join(tmp_root, "dupes.txt")
    with open(path, "w") as f:
        f.write("x=1\nx=1\n")

    result = asyncio.run(_run(
        operation="patch", path=path,
        old_string="x=1", new_string="x=2",
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "failed"
    assert "unique" in result.stderr.lower()


def test_list_dir(tmp_root, protected_names):
    os.makedirs(os.path.join(tmp_root, "mydir"))
    with open(os.path.join(tmp_root, "file1.txt"), "w") as f:
        f.write("a")
    with open(os.path.join(tmp_root, "file2.yaml"), "w") as f:
        f.write("b")

    result = asyncio.run(_run(
        operation="list", path=tmp_root,
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "ok"
    assert "f file1.txt" in result.stdout
    assert "f file2.yaml" in result.stdout
    assert "d mydir" in result.stdout


def test_path_traversal_rejected(tmp_root, protected_names):
    # Try to read /etc/passwd via ..
    evil_path = os.path.join(tmp_root, "..", "..", "etc", "passwd")
    result = asyncio.run(_run(
        operation="read", path=evil_path,
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "failed"
    assert "outside allowed roots" in result.stderr.lower()


def test_protected_resource_rejected(tmp_root):
    # Create a path that contains a protected resource name
    evil_path = os.path.join(tmp_root, "gatekeeper", "config.yaml")
    os.makedirs(os.path.dirname(evil_path), exist_ok=True)
    with open(evil_path, "w") as f:
        f.write("secret")

    result = asyncio.run(_run(
        operation="read", path=evil_path,
        path_roots=[tmp_root], protected=["gatekeeper"],
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "failed"
    assert "protected resource" in result.stderr.lower()


def test_write_to_protected_rejected(tmp_root):
    evil_path = os.path.join(tmp_root, "dockhand", "compose.yaml")
    os.makedirs(os.path.dirname(evil_path), exist_ok=True)

    result = asyncio.run(_run(
        operation="write", path=evil_path, content="malicious",
        path_roots=[tmp_root], protected=["dockhand"],
        timeout_seconds=5, max_output_bytes=65536,
    ))
    assert result.outcome == "failed"
    assert "protected resource" in result.stderr.lower()


def test_read_truncation(tmp_root, protected_names):
    path = os.path.join(tmp_root, "big.txt")
    with open(path, "w") as f:
        f.write("A" * 200)

    result = asyncio.run(_run(
        operation="read", path=path,
        path_roots=[tmp_root], protected=protected_names,
        timeout_seconds=5, max_output_bytes=100,
    ))
    assert result.outcome == "ok"
    assert result.truncated is True
    assert "truncated" in result.stdout