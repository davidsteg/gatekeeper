"""Ruff lint guard — catches import-ordering and style issues locally
before they reach CI.

CI runs `ruff check src/` as a dedicated step; this test mirrors that
gate inside `pytest` so a developer who runs `pytest -q` (but not
`ruff check`) still sees the failure. It is a thin wrapper: ruff owns
the rules, this test only fails the suite when ruff does.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def _ruff_available() -> bool:
    try:
        subprocess.run(
            ["ruff", "--version"],
            capture_output=True,
            check=True,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def _venv_ruff() -> str | None:
    """Find ruff in the project venv (CI installs it via pip install -e .[dev])."""
    candidates = [
        Path(sys.prefix) / "bin" / "ruff",
        Path(__file__).resolve().parent.parent / ".venv" / "bin" / "ruff",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


@pytest.mark.skipif(
    not _ruff_available() and _venv_ruff() is None,
    reason="ruff not installed — run `pip install ruff` to enable this guard",
)
def test_src_passes_ruff_check() -> None:
    """Every file under src/ must pass `ruff check` with the project config."""
    ruff = _venv_ruff() or "ruff"
    src_dir = Path(__file__).resolve().parent.parent / "src"
    result = subprocess.run(
        [ruff, "check", str(src_dir)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(
            f"ruff check src/ failed — fix with `ruff check --fix src/`:\n\n"
            f"{result.stdout}\n{result.stderr}"
        )