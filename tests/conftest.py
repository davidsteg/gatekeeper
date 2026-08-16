"""Test configuration.

The fixtures build a real Tier 1 and catalog configuration from YAML,
instead of constructing objects directly -- this way the loaders run
through the tests and an error in the configuration check surfaces here.
"""

from __future__ import annotations

import os
import sys
import textwrap

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from gatekeeper.catalog import load_catalog  # noqa: E402
from gatekeeper.identity import (  # noqa: E402
    IdentityStore,
    generate_token,
    hash_token,
    load_identities,
)
from gatekeeper.tier1 import load_tier1  # noqa: E402

#: A guaranteed-present, harmless program - the Python interpreter.
PYTHON = os.path.realpath(sys.executable)


def _write(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


@pytest.fixture
def sandbox(tmp_path):
    """Directory that serves as the path root."""
    root = tmp_path / "raid"
    root.mkdir()
    (root / "media-jellyfin").mkdir()
    _write(str(root / "media-jellyfin" / "compose.yaml"), "services: {}\n")
    (root / "gatekeeper").mkdir()
    _write(str(root / "gatekeeper" / "compose.yaml"), "services: {}\n")
    return root


@pytest.fixture
def tier1(tmp_path, sandbox):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "demo": {
                        "executor": "local",
                        "binaries": [PYTHON],
                        "denied_args": ["--dangerous", "rm"],
                        "path_roots": [str(sandbox)],
                        "protected_resources": ["gatekeeper", "dockhand"],
                        "max_timeout_seconds": 30,
                        "max_output_bytes": 8192,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    return load_tier1(str(path))


def make_catalog(tmp_path, tier1, tools, *, strict=True):
    path = tmp_path / "tools.yaml"
    path.write_text(yaml.safe_dump({"tools": tools}), encoding="utf-8")
    return load_catalog(str(path), tier1, strict=strict)


@pytest.fixture
def tool_specs(sandbox):
    """A read tool with path derivation and scope, plus a free-form tool."""
    return [
        {
            "id": "demo.show",
            "toolkit": "demo",
            "binary": PYTHON,
            "version": 1,
            "title": "Show compose file",
            "description": "Outputs the path of the compose file.",
            "category": "read",
            "idempotent": True,
            "enabled": True,
            "argv": ["-c", "import sys; print(sys.argv[1])", "{compose_path}"],
            "parameters": {
                "stack": {
                    "type": "string",
                    "required": True,
                    "pattern": "^[a-z0-9][a-z0-9_-]{0,62}$",
                    "description": "Stack name",
                },
                "compose_path": {
                    "type": "path",
                    "derived": os.path.join(str(sandbox), "{stack}", "compose.yaml"),
                    "must_resolve_under": str(sandbox),
                    "description": "derived",
                },
            },
            "required_scopes": ["stack:{stack}"],
            "timeout_seconds": 10,
            "max_output_bytes": 4096,
        },
        {
            # Deliberately permissive pattern: serves to prove that
            # security does NOT depend on the pattern, but on the structure
            # of the argv construction (FR-5.4).
            "id": "demo.echo",
            "toolkit": "demo",
            "binary": PYTHON,
            "version": 1,
            "title": "Echo",
            "description": "Outputs the given text.",
            "category": "read",
            "idempotent": True,
            "enabled": True,
            "argv": ["-c", "import sys; print(sys.argv[1])", "{text}"],
            "parameters": {
                "text": {
                    "type": "string",
                    "required": True,
                    "pattern": "^.+$",
                    "description": "arbitrary text",
                }
            },
            "required_scopes": [],
            "timeout_seconds": 10,
            "max_output_bytes": 4096,
        },
    ]


@pytest.fixture
def catalog(tmp_path, tier1, tool_specs):
    return make_catalog(tmp_path, tier1, tool_specs)


@pytest.fixture
def identities(tmp_path):
    """Two identities: one with permissions, one without."""
    tokens = {"full": generate_token(), "narrow": generate_token()}
    path = tmp_path / "identities.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "full",
                        "role": "agent",
                        "token_hash": hash_token(tokens["full"]),
                        "tools": ["demo.show", "demo.echo"],
                        "scopes": ["stack:*"],
                    },
                    {
                        "id": "narrow",
                        "role": "agent",
                        "token_hash": hash_token(tokens["narrow"]),
                        "tools": ["demo.show"],
                        "scopes": ["stack:media-*"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    store: IdentityStore = load_identities(str(path))
    return store, tokens


@pytest.fixture
def service(tier1, catalog, tmp_path):
    from gatekeeper.audit import AuditLog
    from gatekeeper.service import Service

    audit = AuditLog(str(tmp_path / "logs"))
    return Service(tier1=tier1, catalog=catalog, audit=audit)


@pytest.fixture
def repo_config_dir():
    """The example configuration.

    gatekeeper no longer ships an active configuration -- `config/` contains
    only `examples/`. The examples must still load: they are what
    someone copies from, and a typo in them would otherwise only surface
    on the foreign host.
    """
    return os.path.join(os.path.dirname(__file__), "..", "config", "examples")


__all__ = ["make_catalog", "textwrap", "PYTHON"]