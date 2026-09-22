"""`/ui/tools` must survive a template field that is not a mapping.

`ToolDef.body_template` is typed `dict | list | str | None` -- an API that
wants a raw JSON string body is a supported `http` tool shape, and the
tool card rendered `{**query_template, **body_template}`, which a `str`
cannot be spread into. The whole list page answered 500 because of one
such tool, hiding every other tool with it.
"""

from __future__ import annotations

import dataclasses

import httpx2
import pytest
import yaml

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1
from gatekeeper.ui import UI_PREFIX

BASE = "http://gatekeeper.test"
ROOT_PASSWORD = "correct-horse-battery"


@pytest.fixture
def http_tier1(tmp_path):
    path = tmp_path / "toolkits-http.yaml"
    path.write_text(
        f"""
toolkits:
  demo_http:
    executor: http
    base_url: "http://127.0.0.1:9"
    allowed_methods: ["GET", "POST"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["127.0.0.1/32"]
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    return load_tier1(str(path))


@pytest.fixture
def http_catalog(tmp_path, http_tier1):
    """One ordinary http tool, one whose templates are plain strings.

    The string `body:` comes through the loader as written; the string
    `query_template` is set on the loaded `ToolDef` afterwards, since
    `_str_str_map` rejects it in YAML -- but nothing stops a `ToolDef`
    from carrying one, and the console must not depend on it.
    """
    path = tmp_path / "tools-http.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "tools": [
                    {
                        "id": "demo_http.normal",
                        "toolkit": "demo_http",
                        "version": 1,
                        "title": "Normal",
                        "description": "Mapping templates, as usual.",
                        "category": "read",
                        "idempotent": True,
                        "enabled": True,
                        "method": "GET",
                        "path": "/api/items",
                        "query": {"name": "{name}"},
                        "parameters": {
                            "name": {
                                "type": "string",
                                "required": True,
                                "pattern": "^[a-z]+$",
                                "description": "item name",
                            }
                        },
                        "required_scopes": [],
                    },
                    {
                        "id": "demo_http.raw_body",
                        "toolkit": "demo_http",
                        "version": 1,
                        "title": "Raw body",
                        "description": "Sends a raw string body.",
                        "category": "write",
                        "idempotent": False,
                        "enabled": True,
                        "method": "POST",
                        "path": "/api/items",
                        "body": "{name}",
                        "parameters": {
                            "name": {
                                "type": "string",
                                "required": True,
                                "pattern": "^[a-z]+$",
                                "description": "item name",
                            }
                        },
                        "required_scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    catalog = load_catalog(str(path), http_tier1)
    raw = catalog.tools["demo_http.raw_body"]
    assert isinstance(raw.body_template, str)
    catalog.tools["demo_http.raw_body"] = dataclasses.replace(
        raw, query_template="name={name}"
    )
    return catalog


@pytest.fixture
def tools_app(http_tier1, http_catalog, tmp_path):
    path = tmp_path / "identities-tpl.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "password_hash": hash_token(ROOT_PASSWORD),
                        "tools": [],
                        "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(path))
    audit = AuditLog(http_tier1.audit_dir)
    service = Service(tier1=http_tier1, catalog=http_catalog, audit=audit)
    return build_app(service=service, identities=identities, audit=audit, ui=True)


async def test_tools_page_survives_non_mapping_templates(tools_app):
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=tools_app), base_url=BASE, timeout=30.0
    ) as client:
        await client.post(
            f"{UI_PREFIX}/login", data={"identity": "root", "password": ROOT_PASSWORD}
        )
        response = await client.get(f"{UI_PREFIX}/tools")

    assert response.status_code == 200
    # Both tools are listed -- the bad one did not take the page down,
    # and the good one still shows its rendered query template.
    assert "demo_http.normal" in response.text
    assert "demo_http.raw_body" in response.text
    assert "name={name}" in response.text
