"""The integration picker UI (`/ui/tools/integrations`).

The property that matters: an integration only ever pre-fills the same textarea
an admin would otherwise type into by hand, and the save still goes
through the full `parse_tool_spec`/Tier 1 path -- proven here by making a
integration's own spec briefly invalid and checking it is still rejected.
"""

from __future__ import annotations

import httpx2
import pytest
import yaml

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.integrations import INTEGRATIONS
from gatekeeper.pending import PendingStore
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_proposals import ToolkitProposalStore
from gatekeeper.ui import UI_PREFIX

BASE = "http://gatekeeper.test"
PASSWORDS = {"root": "admin-console-password", "eye": "viewer-console-password"}


@pytest.fixture
def integrations_env(tmp_path):
    """A toolkit matching the 'sonarr' integration, so it becomes actionable."""
    toolkits_path = tmp_path / "toolkits-integration.yaml"
    toolkits_path.write_text(
        "toolkits:\n" + INTEGRATIONS["sonarr"].toolkit_yaml
        + f"\naudit:\n  dir: {tmp_path / 'logs'}\n",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(toolkits_path))

    tools_path = tmp_path / "tools-rw.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")

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
    service = Service(tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit)
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
    toolkit_proposals = ToolkitProposalStore(
        path=str(tmp_path / "toolkit-proposals.yaml"),
        audit=audit,
        service=service,
        toolkits_path=str(toolkits_path),
        tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    app = build_app(
        service=service, identities=identities, audit=audit, ui=True,
        store=store, pending=pending, toolkit_proposals=toolkit_proposals,
    )
    return {"app": app, "store": store, "service": service}


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
    page = await client.get(f"{UI_PREFIX}/tools")
    marker = 'name="_csrf" value="'
    start = page.text.index(marker) + len(marker)
    return page.text[start : page.text.index('"', start)]


async def test_gallery_shows_all_integrations(integrations_env):
    async with _client(integrations_env["app"]) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/tools/integrations")
        for integration in INTEGRATIONS.values():
            assert integration.display_name in page.text


async def test_only_configured_toolkit_offers_create_action(integrations_env):
    async with _client(integrations_env["app"]) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/tools/integrations")
        assert f"{UI_PREFIX}/tools/integrations/pick?key=sonarr" in page.text
        assert f"{UI_PREFIX}/tools/integrations/pick?key=radarr" not in page.text


async def test_pick_lists_starter_tools(integrations_env):
    async with _client(integrations_env["app"]) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/tools/integrations/pick?key=sonarr")
        assert "sonarr.list_series" in page.text
        assert "sonarr.add_series" in page.text


async def test_pick_unknown_integration_redirects(integrations_env):
    async with _client(integrations_env["app"]) as client:
        await _login(client)
        page = await client.get(
            f"{UI_PREFIX}/tools/integrations/pick?key=nonexistent", follow_redirects=False
        )
        assert page.status_code in (302, 303)


async def test_new_from_integration_prefills_editor_and_saves(integrations_env):
    async with _client(integrations_env["app"]) as client:
        csrf = await _signed_in(client)
        page = await client.get(
            f"{UI_PREFIX}/tools/integrations/new?key=sonarr&tool=sonarr.list_series"
        )
        assert "sonarr.list_series" in page.text
        assert "<textarea" in page.text

        marker = 'name="yaml" spellcheck="false">'
        start = page.text.index(marker) + len(marker)
        end = page.text.index("</textarea>", start)
        yaml_text = page.text[start:end]
        import html as _html

        yaml_text = _html.unescape(yaml_text)

        response = await client.post(
            f"{UI_PREFIX}/tools/new",
            data={"_csrf": csrf, "rev": "", "yaml": yaml_text},
            follow_redirects=False,
        )
        assert response.status_code in (302, 303)

        tools_page = await client.get(f"{UI_PREFIX}/tools")
        assert "sonarr.list_series" in tools_page.text


async def test_toolkit_not_configured_blocks_integration_creation(integrations_env):
    async with _client(integrations_env["app"]) as client:
        await _signed_in(client)
        page = await client.get(
            f"{UI_PREFIX}/tools/integrations/new?key=radarr&tool=radarr.list_movies"
        )
        assert "not configured" in page.text.lower()


async def test_a_broken_integration_spec_is_still_rejected(integrations_env, monkeypatch):
    """Proves integrations do not bypass Tier 1 -- only pre-fill the textarea."""
    import gatekeeper.ui as ui_module

    broken_spec = dict(INTEGRATIONS["sonarr"].tool_specs[0])
    broken_spec["method"] = "DELETE"  # not in sonarr's allowed_methods

    real_integrations = ui_module.INTEGRATIONS
    tampered = dict(real_integrations)
    from dataclasses import replace

    tampered["sonarr"] = replace(
        real_integrations["sonarr"],
        tool_specs=(broken_spec, *real_integrations["sonarr"].tool_specs[1:]),
    )
    monkeypatch.setattr(ui_module, "INTEGRATIONS", tampered)

    async with _client(integrations_env["app"]) as client:
        csrf = await _signed_in(client)
        page = await client.get(
            f"{UI_PREFIX}/tools/integrations/new?key=sonarr&tool=sonarr.list_series"
        )
        marker = 'name="yaml" spellcheck="false">'
        start = page.text.index(marker) + len(marker)
        end = page.text.index("</textarea>", start)
        import html as _html

        yaml_text = _html.unescape(page.text[start:end])

        response = await client.post(
            f"{UI_PREFIX}/tools/new",
            data={"_csrf": csrf, "rev": "", "yaml": yaml_text},
        )
        assert response.status_code == 400
        assert "Rejected" in response.text


async def test_viewer_cannot_create_from_integration(integrations_env):
    async with _client(integrations_env["app"]) as client:
        await _signed_in(client, "eye")
        page = await client.get(
            f"{UI_PREFIX}/tools/integrations/new?key=sonarr&tool=sonarr.list_series",
            follow_redirects=False,
        )
        assert page.status_code in (302, 303)


async def test_reference_page_lists_all_toolkit_yaml_blocks(integrations_env):
    async with _client(integrations_env["app"]) as client:
        await _login(client)
        page = await client.get(f"{UI_PREFIX}/toolkits/reference")
        for integration in INTEGRATIONS.values():
            assert integration.key in page.text
        assert "executor: http" in page.text
        assert "executor: truenas" in page.text
