"""Testkonfiguration.

Die Fixtures bauen eine echte Ebene-1- und Katalogkonfiguration aus YAML auf,
statt Objekte direkt zu konstruieren -- so laufen die Loader mit durch die
Tests und ein Fehler in der Konfigurationspruefung faellt hier auf.
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

#: Ein garantiert vorhandenes, harmloses Programm - der Python-Interpreter.
PYTHON = os.path.realpath(sys.executable)


def _write(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


@pytest.fixture
def sandbox(tmp_path):
    """Verzeichnis, das als Pfad-Wurzel dient."""
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
    """Ein lesendes Tool mit Pfadableitung und Scope, plus ein freies Tool."""
    return [
        {
            "id": "demo.show",
            "toolkit": "demo",
            "binary": PYTHON,
            "version": 1,
            "title": "Compose-Datei anzeigen",
            "description": "Gibt den Pfad der Compose-Datei aus.",
            "category": "read",
            "idempotent": True,
            "enabled": True,
            "argv": ["-c", "import sys; print(sys.argv[1])", "{compose_path}"],
            "parameters": {
                "stack": {
                    "type": "string",
                    "required": True,
                    "pattern": "^[a-z0-9][a-z0-9_-]{0,62}$",
                    "description": "Stack-Name",
                },
                "compose_path": {
                    "type": "path",
                    "derived": os.path.join(str(sandbox), "{stack}", "compose.yaml"),
                    "must_resolve_under": str(sandbox),
                    "description": "abgeleitet",
                },
            },
            "required_scopes": ["stack:{stack}"],
            "timeout_seconds": 10,
            "max_output_bytes": 4096,
        },
        {
            # Bewusst freizuegiges Pattern: dient dem Nachweis, dass die
            # Sicherheit NICHT vom Pattern abhaengt, sondern von der Struktur
            # des argv-Baus (FR-5.4).
            "id": "demo.echo",
            "toolkit": "demo",
            "binary": PYTHON,
            "version": 1,
            "title": "Echo",
            "description": "Gibt den uebergebenen Text aus.",
            "category": "read",
            "idempotent": True,
            "enabled": True,
            "argv": ["-c", "import sys; print(sys.argv[1])", "{text}"],
            "parameters": {
                "text": {
                    "type": "string",
                    "required": True,
                    "pattern": "^.+$",
                    "description": "beliebiger Text",
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
    """Zwei Identitaeten: eine mit Rechten, eine ohne."""
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
    """Die Beispielkonfiguration.

    gatekeeper liefert keine aktive Konfiguration mehr mit -- `config/` enthaelt
    nur noch `examples/`. Die Beispiele muessen trotzdem laden: sie sind das,
    wovon jemand abschreibt, und ein Tippfehler darin faellt sonst erst auf dem
    fremden Host auf.
    """
    return os.path.join(os.path.dirname(__file__), "..", "config", "examples")


__all__ = ["make_catalog", "textwrap", "PYTHON"]
