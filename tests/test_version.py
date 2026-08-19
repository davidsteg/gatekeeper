"""`__version__` must always match `pyproject.toml`.

There used to be a second, hand-maintained `__version__ = "..."` string in
`__init__.py` that had to be bumped alongside `pyproject.toml` on every
release -- and once wasn't, so the console kept showing a stale version
after a real release shipped. `__init__.py` now derives the version instead
of hardcoding it (see its own docstring); this test is the backstop in case
that derivation ever regresses back into a second source of truth.
"""

from __future__ import annotations

import os
import tomllib

import gatekeeper


def test_version_matches_pyproject():
    pyproject_path = os.path.join(
        os.path.dirname(__file__), "..", "pyproject.toml"
    )
    with open(pyproject_path, "rb") as handle:
        data = tomllib.load(handle)
    assert gatekeeper.__version__ == data["project"]["version"]


def test_version_is_not_a_hardcoded_placeholder():
    assert gatekeeper.__version__ != "0.0.0+unknown"
