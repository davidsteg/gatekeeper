"""The credentials admin pages (REQUIREMENTS.md §11, UI layer).

Same concern as `test_ui_admin.py`, narrowed to one property that matters
more here than anywhere else in the console: a value must never come back
out through any response body, however it got in.
"""

from __future__ import annotations

import httpx2
import pytest

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.ui import UI_PREFIX
import yaml

BASE = "http://gatekeeper.test"
PASSWORDS = {"root": "admin-console-password", "eye": "viewer-console-password"}
SECRET_VALUE = "super-secret-sonarr-key-xyz"


@pytest.fixture
def credentials_env(tmp_path, tier1, tool_specs, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())

    tools_path = tmp_path / "tools-rw.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")

    tokens = {"root": generate_token(), "eye": generate_token()}
    identities_path = tmp_path / "identities-rw.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root", "role": "admin",
                        "token_hash": hash_token(tokens["root"]),
                        "password_hash": hash_token(PASSWORDS["root"]),
                        "tools": [], "scopes": [],
                    },
                    {
                        "id": "eye", "role": "viewer",
                        "token_hash": hash_token(tokens["eye"]),
                        "password_hash": hash_token(PASSWORDS["eye"]),
                        "tools": [], "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    identities = load_identities(str(identities_path))
    audit = AuditLog(tier1.audit_dir)
    service = Service(
        tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit
    )
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    credentials = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    app = build_app(
        service=service, identities=identities, audit=audit, ui=True, store=store,
        credentials=credentials,
    )
    return {"app": app, "credentials": credentials, "tier1": tier1}


def _client(app) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, timeout=30.0
    )


async def _login(client, identity: str = "root"):
    return await client.post(
        f"{UI_PREFIX}/login", data={"identity": identity, "password": PASSWORDS[identity]}
    )


async def _signed_in(client, identity: str = "root") -> str:
    await _login(client, identity)
    page = await client.get(f"{UI_PREFIX}/credentials")
    marker = 'name="_csrf" value="'
    start = page.text.index(marker) + len(marker)
    return page.text[start : page.text.index('"', start)]


async def test_credentials_page_requires_login(credentials_env):
    async with _client(credentials_env["app"]) as client:
        response = await client.get(f"{UI_PREFIX}/credentials")
        assert response.status_code in (302, 303, 307)


async def test_create_credential_never_echoes_value(credentials_env):
    async with _client(credentials_env["app"]) as client:
        csrf = await _signed_in(client)
        response = await client.post(
            f"{UI_PREFIX}/credentials/new",
            data={
                "_csrf": csrf, "rev": "", "name": "sonarr", "kind": "api_key_header",
                "header": "X-Api-Key", "value": SECRET_VALUE,
            },
        )
        assert response.status_code in (302, 303)

        page = await client.get(f"{UI_PREFIX}/credentials")
        assert SECRET_VALUE not in page.text
        assert "sonarr" in page.text
        assert "api_key_header" in page.text


async def test_viewer_cannot_create_credential(credentials_env):
    async with _client(credentials_env["app"]) as client:
        csrf = await _signed_in(client, "eye")
        response = await client.post(
            f"{UI_PREFIX}/credentials/new",
            data={
                "_csrf": csrf, "rev": "", "name": "sonarr", "kind": "api_key_header",
                "header": "X-Api-Key", "value": SECRET_VALUE,
            },
        )
        assert response.status_code == 403
        assert credentials_env["credentials"].names() == []


async def test_write_without_csrf_token_is_refused(credentials_env):
    async with _client(credentials_env["app"]) as client:
        await _signed_in(client)
        response = await client.post(
            f"{UI_PREFIX}/credentials/new",
            data={
                "rev": "", "name": "sonarr", "kind": "api_key_header",
                "header": "X-Api-Key", "value": SECRET_VALUE,
            },
        )
        assert response.status_code == 403
        assert credentials_env["credentials"].names() == []


async def test_rotate_and_delete_round_trip(credentials_env):
    async with _client(credentials_env["app"]) as client:
        csrf = await _signed_in(client)
        await client.post(
            f"{UI_PREFIX}/credentials/new",
            data={
                "_csrf": csrf, "rev": "", "name": "sonarr", "kind": "api_key_header",
                "header": "X-Api-Key", "value": SECRET_VALUE,
            },
        )
        rev = credentials_env["credentials"].revision()
        rotate = await client.post(
            f"{UI_PREFIX}/credentials/rotate",
            data={
                "_csrf": csrf, "rev": rev, "name": "sonarr", "value": "new-value-xyz",
                "overlap_seconds": "0",
            },
        )
        assert rotate.status_code in (302, 303)
        assert "new-value-xyz" not in rotate.text

        rev = credentials_env["credentials"].revision()
        delete = await client.post(
            f"{UI_PREFIX}/credentials/delete",
            data={"_csrf": csrf, "rev": rev, "name": "sonarr"},
        )
        assert delete.status_code in (302, 303)
        assert credentials_env["credentials"].names() == []


async def test_used_by_toolkit_shown(tmp_path, tool_specs, tier1, monkeypatch):
    """A toolkit's `credential:` field cross-references into the list."""
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.tier1 import load_tier1
    import os

    toolkits_path = tmp_path / "toolkits-cred.yaml"
    toolkits_path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "demo": {
                        "executor": "local",
                        "binaries": [tier1.toolkits["demo"].binaries[0]],
                        "credential": "sonarr",
                    }
                },
                "audit": {"dir": str(tmp_path / "logs2")},
            }
        ),
        encoding="utf-8",
    )
    tier1b = load_tier1(str(toolkits_path))

    tools_path = tmp_path / "tools-rw2.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")

    tokens = {"root": generate_token()}
    identities_path = tmp_path / "identities-rw2.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root", "role": "admin",
                        "token_hash": hash_token(tokens["root"]),
                        "password_hash": hash_token(PASSWORDS["root"]),
                        "tools": [], "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(identities_path))
    audit = AuditLog(tier1b.audit_dir)
    service = Service(tier1=tier1b, catalog=load_catalog(str(tools_path), tier1b), audit=audit)
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    credentials = CredentialStore(path=str(tmp_path / "credentials2.yaml"), audit=audit)
    credentials.create(
        "sonarr", kind="api_key_header", header="X-Api-Key", value=SECRET_VALUE,
        actor="test", rev="",
    )
    app = build_app(
        service=service, identities=identities, audit=audit, ui=True, store=store,
        credentials=credentials,
    )
    async with _client(app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/credentials")
        assert "demo" in page.text
        assert SECRET_VALUE not in page.text
