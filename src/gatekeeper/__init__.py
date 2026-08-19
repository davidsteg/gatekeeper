"""gatekeeper - controlled MCP server for host operations."""

from __future__ import annotations

from pathlib import Path


def _from_pyproject() -> str | None:
    """Reads the version straight out of `pyproject.toml`, if reachable.

    This is the live source of truth for a dev checkout or an editable
    install (`pip install -e .`): `__file__` resolves to the real file
    under `src/gatekeeper/`, so walking up finds the repo's own
    `pyproject.toml` -- always current, no reinstall needed after a
    version bump. This branch is what used to be a second hardcoded
    `__version__ = "..."` string here that had to be bumped by hand
    alongside `pyproject.toml`, and once wasn't: the console kept showing
    a stale version after a real release. There is nothing left here to
    forget to bump.
    """
    import tomllib

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "pyproject.toml"
        if candidate.is_file():
            try:
                data = tomllib.loads(candidate.read_text(encoding="utf-8"))
                return str(data["project"]["version"])
            except (OSError, KeyError, tomllib.TOMLDecodeError):
                return None
    return None


def _from_installed_metadata() -> str | None:
    """Falls back to the installed package's own metadata.

    Covers a non-editable install (`pip install .`, what the container
    image does): there `pyproject.toml` is not shipped inside
    site-packages, so the parent-walk above finds nothing -- but the
    image is rebuilt fresh from that exact `pyproject.toml` on every
    release, so the installed metadata is correct by construction.
    """
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as installed_version

    try:
        return installed_version("gatekeeper")
    except PackageNotFoundError:
        return None


__version__ = _from_pyproject() or _from_installed_metadata() or "0.0.0+unknown"
