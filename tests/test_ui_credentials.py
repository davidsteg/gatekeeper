"""The credentials admin pages (REQUIREMENTS.md §11, UI layer).

Same concern as `test_ui_admin.py`, narrowed to one property that matters
more here than anywhere else in the console: a value must never come back
out through any response body, however it got in.
"""

from __future__ import annotations

import httpx2
import pytest
import yaml

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.pending import PendingStore
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.toolkit_proposals import ToolkitProposalStore
from gatekeeper.ui import UI_PREFIX

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
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit-proposals.yaml"),
        audit=audit,
        service=service,
        toolkits_path=str(tmp_path / "toolkits.yaml"),
        tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    app = build_app(
        service=service, identities=identities, audit=audit, ui=True, store=store,
        credentials=credentials, pending=pending, toolkit_proposals=toolkit_proposals,
    )
    return {
        "app": app, "credentials": credentials, "tier1": tier1,
        "pending": pending, "pending_path": tmp_path / "pending.yaml",
    }


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


# -- The other half of admin.cred_propose: filling in the value -----------


async def test_credential_fill_approves_proposal_and_creates_credential(credentials_env):
    pending = credentials_env["pending"]
    credentials = credentials_env["credentials"]
    item = pending.propose(
        action="cred_propose", actor="hermes",
        payload={"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"},
        base_rev=credentials.revision(),
    )
    async with _client(credentials_env["app"]) as client:
        csrf = await _signed_in(client)

        form_page = await client.get(f"{UI_PREFIX}/pending/credential-fill?id={item.id}")
        assert form_page.status_code == 200
        assert "sonarr" in form_page.text
        assert "api_key_header" in form_page.text
        assert "X-Api-Key" in form_page.text

        response = await client.post(
            f"{UI_PREFIX}/pending/credential-fill",
            data={"_csrf": csrf, "id": item.id, "value": SECRET_VALUE},
        )
        assert response.status_code in (302, 303)

    metas = {m.name: m for m in credentials.names()}
    assert metas["sonarr"].kind == "api_key_header"
    assert metas["sonarr"].header == "X-Api-Key"
    approved = pending.get(item.id)
    assert approved.status == "approved"
    # The value never touched the pending queue's own file, at any point.
    pending_raw = credentials_env["pending_path"].read_text(encoding="utf-8")
    assert SECRET_VALUE not in pending_raw


async def test_credential_fill_never_echoes_the_value(credentials_env):
    pending = credentials_env["pending"]
    credentials = credentials_env["credentials"]
    item = pending.propose(
        action="cred_propose", actor="hermes",
        payload={"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"},
        base_rev=credentials.revision(),
    )
    async with _client(credentials_env["app"]) as client:
        csrf = await _signed_in(client)
        response = await client.post(
            f"{UI_PREFIX}/pending/credential-fill",
            data={"_csrf": csrf, "id": item.id, "value": SECRET_VALUE},
            follow_redirects=True,
        )
        assert SECRET_VALUE not in response.text


async def test_credential_fill_route_is_writer_gated(credentials_env):
    pending = credentials_env["pending"]
    credentials = credentials_env["credentials"]
    item = pending.propose(
        action="cred_propose", actor="hermes",
        payload={"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"},
        base_rev=credentials.revision(),
    )
    async with _client(credentials_env["app"]) as client:
        csrf = await _signed_in(client, "eye")
        response = await client.post(
            f"{UI_PREFIX}/pending/credential-fill",
            data={"_csrf": csrf, "id": item.id, "value": SECRET_VALUE},
        )
        assert response.status_code == 403
        assert credentials.names() == []


async def test_credential_fill_requires_csrf(credentials_env):
    pending = credentials_env["pending"]
    credentials = credentials_env["credentials"]
    item = pending.propose(
        action="cred_propose", actor="hermes",
        payload={"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"},
        base_rev=credentials.revision(),
    )
    async with _client(credentials_env["app"]) as client:
        await _signed_in(client)
        response = await client.post(
            f"{UI_PREFIX}/pending/credential-fill",
            data={"id": item.id, "value": SECRET_VALUE},
        )
        assert response.status_code == 403
        assert credentials.names() == []


async def test_credential_fill_stale_when_name_taken_meanwhile(credentials_env):
    """Between propose and fill, someone else creates a credential of the

    same name directly (e.g. a second admin, in the normal /ui form) --
    the fill must not silently create a second, orphaned entry or clobber
    the one that already exists.
    """
    pending = credentials_env["pending"]
    credentials = credentials_env["credentials"]
    item = pending.propose(
        action="cred_propose", actor="hermes",
        payload={"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"},
        base_rev=credentials.revision(),
    )
    credentials.create(
        "sonarr", kind="bearer", value="typed-directly-in-the-meantime",
        actor="root", rev="",
    )
    async with _client(credentials_env["app"]) as client:
        csrf = await _signed_in(client)
        response = await client.post(
            f"{UI_PREFIX}/pending/credential-fill",
            data={"_csrf": csrf, "id": item.id, "value": SECRET_VALUE},
        )
        assert response.status_code == 400
        assert SECRET_VALUE not in response.text
    # The directly-created credential is untouched -- still 'bearer', not
    # silently overwritten by the stale proposal's 'api_key_header'.
    metas = {m.name: m for m in credentials.names()}
    assert metas["sonarr"].kind == "bearer"


async def test_approve_all_excludes_credential_proposals(credentials_env):
    pending = credentials_env["pending"]
    credentials = credentials_env["credentials"]
    pending.propose(
        action="cred_propose", actor="hermes",
        payload={"name": "sonarr", "kind": "api_key_header", "header": "X-Api-Key"},
        base_rev=credentials.revision(),
    )
    pending.propose(
        action="cred_propose", actor="hermes",
        payload={"name": "radarr", "kind": "api_key_header", "header": "X-Api-Key"},
        base_rev=credentials.revision(),
    )
    async with _client(credentials_env["app"]) as client:
        await _signed_in(client)
        page = await client.get(f"{UI_PREFIX}/requests?tab=change")
        # Two items are live, but neither is batchable -- the "Approve all"
        # link itself must not appear (checked by href, not by the phrase
        # "Approve all" alone -- that also shows up in this page's own
        # static help text describing the feature in general).
        assert f'href="{UI_PREFIX}/pending/approve-all"' not in page.text

        redirect = await client.get(
            f"{UI_PREFIX}/pending/approve-all", follow_redirects=False
        )
        assert redirect.status_code in (302, 303)


def _app_with_binding(tmp_path, tier1, monkeypatch, *, create_credential: bool):
    """A console wired to one toolkit carrying `credential: sonarr`.

    Shared by the two halves of the same question -- the credential exists,
    or it does not -- so the wiring cannot drift between them.
    """
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.tier1 import load_tier1

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

    identities_path = tmp_path / "identities-rw2.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root", "role": "admin",
                        "token_hash": hash_token(generate_token()),
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
    if create_credential:
        credentials.create(
            "sonarr", kind="api_key_header", header="X-Api-Key", value=SECRET_VALUE,
            actor="test", rev="",
        )
    pending = PendingStore(path=str(tmp_path / "pending2.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit-proposals2.yaml"),
        audit=audit,
        service=service,
        toolkits_path=str(toolkits_path),
        tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    return build_app(
        service=service, identities=identities, audit=audit, ui=True, store=store,
        credentials=credentials, pending=pending, toolkit_proposals=toolkit_proposals,
    )


async def test_used_by_toolkit_shown(tmp_path, tool_specs, tier1, monkeypatch):
    """A toolkit's `credential:` field cross-references into the list."""
    app = _app_with_binding(tmp_path, tier1, monkeypatch, create_credential=True)
    async with _client(app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/credentials")
        assert "demo" in page.text
        assert SECRET_VALUE not in page.text
        assert "do not exist yet" not in page.text


async def test_dangling_binding_named_on_the_page(tmp_path, tool_specs, tier1, monkeypatch):
    """A binding with no credential behind it has no card to appear in.

    Without a note of its own it is invisible here -- which is what made
    "No credentials yet." look like the whole story while every call
    through the toolkit was being refused.
    """
    app = _app_with_binding(tmp_path, tier1, monkeypatch, create_credential=False)
    async with _client(app) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/credentials")
        assert "do not exist yet" in page.text
        # Names the credential and what refers to it, so the reader knows
        # both what to create and why it matters.
        assert "sonarr" in page.text
        assert "demo" in page.text
        assert "No credentials yet." in page.text
