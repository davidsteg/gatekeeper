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


def test_server_reports_real_version_not_hardcoded():
    """The MCP `Server` object must report the real package version,
    not a hardcoded ``"0.1.0"`` placeholder.

    Regression test for the bug where ``serverInfo.version`` always
    reported ``0.1.0`` regardless of the installed release, because
    the version string was hardcoded in ``build_mcp_server`` instead of
    reading ``gatekeeper.__version__``.
    """
    import inspect

    from gatekeeper.server import build_mcp_server

    source = inspect.getsource(build_mcp_server)
    assert '"0.1.0"' not in source, (
        "build_mcp_server still hardcodes version=\"0.1.0\" — "
        "use gatekeeper.__version__ instead"
    )
    assert "__version__" in source, (
        "build_mcp_server must use __version__ for the Server version"
    )
