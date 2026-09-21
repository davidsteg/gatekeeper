"""The pattern `/mcp` publishes is the pattern the definition spells.

Reported as: `admin.tool_get` shows `file.write`'s `file` parameter with a
slash-joined, multi-segment pattern that `sub/file.yaml` matches in Python
`re`, while the `tools/list` `inputSchema` was said to drop the separator
between the repetition groups -- so a schema-validating client refuses a
value the server would have accepted, and because the call never reaches
gatekeeper there is no denial and no audit entry to look at.

These tests pin the property the report is about, on both sides of the
transport: `ToolDef.input_schema()` publishes the definition's own string
character for character, and the same string survives a real `/mcp`
session over the MCP client. They cover every parameter the report names
(`file.read/write/patch`'s `file`, `selfdeploy2.mv`'s `src`/`dst`,
`envwrite`'s `relpath`, `upenv`'s `envpath`) -- all of them the same
shape: up to six `/`-separated path segments.
"""

from __future__ import annotations

import re

import pytest
import yaml
from conftest import PYTHON, make_catalog
from test_mcp_live_catalog import connected

from gatekeeper.audit import AuditLog
from gatekeeper.errors import ConfigError
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

#: The reported definition's pattern: one segment plus up to five more,
#: each separated by a literal `/`. The separator inside the repetition
#: group is the whole point -- drop it and `sub/file.yaml` no longer
#: matches, while `subfile.yaml` still does.
SIX_SEGMENT_PATTERN = r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,5}$"

#: Every parameter the report names, as (tool id, parameter name).
REPORTED_PARAMS = [
    ("file.read", "file"),
    ("file.write", "file"),
    ("file.patch", "file"),
    ("selfdeploy2.mv", "src"),
    ("selfdeploy2.mv", "dst"),
    ("selfdeploy2.envwrite", "relpath"),
    ("selfdeploy2.upenv", "envpath"),
]


@pytest.fixture
def path_tier1(tmp_path, sandbox):
    """A `file` toolkit and a `local` one, for the two reported toolkits."""
    path = tmp_path / "toolkits-paths.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "file": {
                        "executor": "file",
                        "binaries": [],
                        "path_roots": [str(sandbox)],
                        "max_timeout_seconds": 30,
                        "max_output_bytes": 131072,
                    },
                    "selfdeploy2": {
                        "executor": "local",
                        "binaries": [PYTHON],
                        "path_roots": [str(sandbox)],
                        "max_timeout_seconds": 30,
                        "max_output_bytes": 131072,
                    },
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    return load_tier1(str(path))


def _file_write_spec() -> dict:
    """The reported `file.write` definition, trimmed to what matters."""
    return {
        "id": "file.write",
        "toolkit": "file",
        "executor": "file",
        "file_operation": "write",
        "title": "Write file",
        "description": "Write a file below the toolkit's root.",
        "category": "write",
        "idempotent": False,
        "enabled": True,
        "parameters": {
            "file": {
                "type": "string",
                "required": True,
                "pattern": SIX_SEGMENT_PATTERN,
                "description": "Path relative to the root, up to six segments",
            },
            "content": {
                "type": "string",
                "required": True,
                "pattern": r"[\s\S]*",
                "allow_control_characters": True,
                "description": "File content",
            },
        },
        "required_scopes": [],
        "timeout_seconds": 10,
        "max_output_bytes": 65536,
    }


def _reported_specs() -> list[dict]:
    """One definition per reported tool, each carrying its own params."""
    by_tool: dict[str, list[str]] = {}
    for tool_id, param in REPORTED_PARAMS:
        by_tool.setdefault(tool_id, []).append(param)

    specs = []
    for tool_id, params in by_tool.items():
        toolkit = tool_id.split(".", 1)[0]
        spec: dict = {
            "id": tool_id,
            "toolkit": toolkit,
            "title": tool_id,
            "description": tool_id,
            "category": "write",
            "idempotent": False,
            "enabled": True,
            "parameters": {
                name: {
                    "type": "string",
                    "required": True,
                    "pattern": SIX_SEGMENT_PATTERN,
                    "description": f"{name}, up to six path segments",
                }
                for name in params
            },
            "required_scopes": [],
            "timeout_seconds": 10,
            "max_output_bytes": 65536,
        }
        if toolkit == "file":
            spec["executor"] = "file"
            spec["file_operation"] = "write" if tool_id != "file.read" else "read"
            if tool_id == "file.patch":
                spec["file_operation"] = "patch"
        else:
            spec["binary"] = PYTHON
            spec["argv"] = ["-c", "print(1)", *(f"{{{name}}}" for name in params)]
        specs.append(spec)
    return specs


def test_published_pattern_equals_the_def_pattern(tmp_path, path_tier1):
    """The regression the report asks for, at its narrowest.

    A `file.write` definition with the six-segment pattern must publish
    that exact string, and that exact string must match `sub/file.yaml`
    in Python `re` -- the value the reported client validation refused.
    """
    catalog = make_catalog(tmp_path, path_tier1, [_file_write_spec()])
    tool = catalog.get("file.write")

    published = tool.input_schema()["properties"]["file"]["pattern"]
    assert published == SIX_SEGMENT_PATTERN
    # ... and the same string the ToolDef itself carries, not a copy that
    # merely looks similar.
    assert published == tool.parameters["file"].pattern.pattern
    assert re.fullmatch(published, "sub/file.yaml")
    # The separator is doing work: a pattern that lost it would accept
    # this instead.
    assert re.fullmatch(published, "a/b/c/d/e/f")
    assert not re.fullmatch(published, "a/b/c/d/e/f/g")


def test_every_reported_parameter_publishes_its_def_pattern(tmp_path, path_tier1):
    """All seven parameters the report names, in one pass."""
    catalog = make_catalog(tmp_path, path_tier1, _reported_specs())
    for tool_id, param in REPORTED_PARAMS:
        tool = catalog.get(tool_id)
        published = tool.input_schema()["properties"][param]["pattern"]
        assert published == tool.parameters[param].pattern.pattern, f"{tool_id}.{param}"
        assert published == SIX_SEGMENT_PATTERN, f"{tool_id}.{param}"
        assert re.fullmatch(published, "sub/file.yaml"), f"{tool_id}.{param}"


async def test_pattern_survives_a_real_mcp_session(tmp_path, path_tier1):
    """The published half of the claim, over the wire rather than in-process.

    `input_schema()` being right is not the same statement as `/mcp`
    serving it unchanged: the schema still passes through `ToolView`, the
    MCP `Tool` model and JSON on the way out. This asserts the string a
    client actually receives.
    """
    catalog = make_catalog(tmp_path, path_tier1, [_file_write_spec()])
    token = generate_token()
    identities_path = tmp_path / "identities-schema.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "full",
                        "role": "agent",
                        "token_hash": hash_token(token),
                        "tools": ["file.write"],
                        "scopes": [],
                    },
                    {
                        "id": "boss",
                        "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "tools": [],
                        "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identity_store = load_identities(str(identities_path))
    audit = AuditLog(str(tmp_path / "logs-schema"))
    service = Service(tier1=path_tier1, catalog=catalog, audit=audit)
    app = build_app(service=service, identities=identity_store, audit=audit)

    async with connected(app, token) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        published = tools["file.write"].input_schema["properties"]["file"]["pattern"]

    assert published == SIX_SEGMENT_PATTERN
    assert re.fullmatch(published, "sub/file.yaml")


def test_a_non_string_pattern_is_refused_at_load(tmp_path, path_tier1):
    """There is no "make it a string" step that could change the text.

    A pattern that is not written as a string is a YAML accident, and
    coercing it would publish gatekeeper's guess at what was meant.
    """
    spec = _file_write_spec()
    spec["parameters"]["file"]["pattern"] = ["^a$", "^b$"]
    with pytest.raises(ConfigError) as exc:
        make_catalog(tmp_path, path_tier1, [spec])
    assert "non-string" in str(exc.value)
