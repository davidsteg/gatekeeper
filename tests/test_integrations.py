"""The integration library (src/gatekeeper/integrations.py).

Every integration's `toolkit_yaml` and `tool_specs` must be real, valid
definitions -- not just plausible-looking strings. If an integration were wrong,
the UI's "pick an integration" flow would just relocate hand-editing YAML from
a blank textarea to a broken pre-filled one, which is worse.
"""

from __future__ import annotations

import pytest
import yaml

from gatekeeper.catalog import parse_tool_spec
from gatekeeper.errors import ConfigError
from gatekeeper.integrations import INTEGRATIONS
from gatekeeper.tier1 import load_tier1


def _tier1_from_toolkit_yaml(tmp_path, toolkit_yaml: str, name: str):
    path = tmp_path / f"toolkits-{name}.yaml"
    path.write_text(
        "toolkits:\n" + toolkit_yaml + f"\naudit:\n  dir: {tmp_path / 'logs'}\n",
        encoding="utf-8",
    )
    return load_tier1(str(path))


@pytest.mark.parametrize("key", sorted(INTEGRATIONS))
def test_toolkit_yaml_parses(tmp_path, key):
    integration = INTEGRATIONS[key]
    tier1 = _tier1_from_toolkit_yaml(tmp_path, integration.toolkit_yaml, key)
    assert key in tier1.toolkits


@pytest.mark.parametrize("key", sorted(INTEGRATIONS))
def test_tool_specs_parse_against_their_toolkit(tmp_path, key):
    integration = INTEGRATIONS[key]
    tier1 = _tier1_from_toolkit_yaml(tmp_path, integration.toolkit_yaml, key)
    assert integration.tool_specs, f"integration {key!r} has no starter tools"
    for spec in integration.tool_specs:
        tool = parse_tool_spec(dict(spec), tier1)
        assert tool.toolkit == key
        assert tool.id.startswith(f"{key}.")


@pytest.mark.parametrize("key", sorted(INTEGRATIONS))
def test_tool_ids_are_unique_within_a_integration(key):
    integration = INTEGRATIONS[key]
    ids = [spec["id"] for spec in integration.tool_specs]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("key", sorted(INTEGRATIONS))
def test_logo_is_inline_svg_with_no_external_reference(key):
    integration = INTEGRATIONS[key]
    svg = integration.logo_svg
    assert svg.strip().startswith("<svg")
    # The xmlns declaration is a namespace URI, never fetched -- only an
    # actual resource-loading attribute (href/src) would be a live
    # external reference, which is what's actually disallowed here.
    assert 'href="http' not in svg
    assert 'src="http' not in svg
    assert "<script" not in svg.lower()
    assert "<image" not in svg.lower()


@pytest.mark.parametrize("key", sorted(INTEGRATIONS))
def test_logo_has_no_csp_blocked_styling(key):
    """The console's CSP is `style-src 'nonce-...'`, which covers inline

    `style=""` attributes AND a bare `<style>` tag -- neither carries the
    page's nonce, so the browser silently drops them and every element
    that depended on one renders with default (black) fill instead of its
    real color. A fetched brand SVG must have every declaration converted
    to presentation attributes (`fill="#hex"`, not `style="fill:#hex"` or
    a CSS class resolved via a `<style>` block) before it ever reaches
    `integrations.py` -- this is what actually failed the first time these
    logos were added: several rendered as solid black circles.
    """
    svg = INTEGRATIONS[key].logo_svg
    assert 'style="' not in svg, f"{key}: inline style= is dropped by CSP"
    assert "<style" not in svg.lower(), f"{key}: <style> block is dropped by CSP"
    assert 'class="' not in svg, f"{key}: class= implies a (dropped) stylesheet"


def test_no_duplicate_svg_ids_or_gradient_targets_across_all_integrations():
    """The integration gallery renders every logo on one page at once -- an SVG

    `id` (and the `url(#id)`/`href="#id"` that reference it, e.g. a
    gradient or clip-path) is global to the whole document, not scoped per
    `<svg>`. Two integrations defining the same bare id (several of the source
    files used generic names like 'a'/'b' before namespacing) would make
    one logo silently borrow -- or corrupt -- another's gradient.
    """
    import re

    seen: dict[str, str] = {}
    for key, integration in INTEGRATIONS.items():
        for svg_id in re.findall(r'\bid="([^"]+)"', integration.logo_svg):
            owner = seen.get(svg_id)
            assert owner is None, f"id {svg_id!r} used by both {owner!r} and {key!r}"
            seen[svg_id] = key


@pytest.mark.parametrize("key", sorted(INTEGRATIONS))
def test_toolkit_yaml_is_a_mapping_under_the_integration_key(key):
    integration = INTEGRATIONS[key]
    parsed = yaml.safe_load(integration.toolkit_yaml)
    assert key in parsed
    assert parsed[key]["executor"] in ("http", "truenas", "docker", "ssh")


def test_credential_kind_is_known():
    from gatekeeper.credentials import KINDS

    for key, integration in INTEGRATIONS.items():
        assert integration.credential_kind in KINDS, key


def test_all_named_services_present():
    expected = {
        "sonarr", "radarr", "jellyfin", "bazarr", "tdarr", "prowlarr",
        "hass", "n8n", "uptimekuma", "immich", "telegram", "google_api",
        "truenas", "pfsense", "jellystat", "jellyseerr", "netdata", "sabnzbd",
        "paperless", "docker", "linux",
    }
    assert expected <= set(INTEGRATIONS)


def test_jellyseerr_auth_shape():
    """Jellyseerr and Jellystat are different services with different auth.

    They sit next to each other in the gallery and their names differ by
    three letters -- pinning the header and port here is what keeps a
    future edit from "fixing" one into the other.
    """
    integration = INTEGRATIONS["jellyseerr"]
    parsed = yaml.safe_load(integration.toolkit_yaml)["jellyseerr"]
    assert parsed["base_url"].endswith(":5055")
    assert integration.credential_kind == "api_key_header"
    assert "X-Api-Key" in integration.toolkit_yaml
    # Read-only starter set: no tool here may write.
    assert {spec["method"] for spec in integration.tool_specs} == {"GET"}
    assert parsed["allowed_methods"] == ["GET"]


def test_docker_and_linux_use_argv_shaped_tools_not_http():
    """The two non-http/truenas integrations reuse the `docker`/`local`

    binary+argv tool shape (FR-5.3/5.4) -- proven by checking their
    starter tools carry `binary`/`argv`, not `method`/`path`.
    """
    for key in ("docker", "linux"):
        for spec in INTEGRATIONS[key].tool_specs:
            assert "binary" in spec and "argv" in spec
            assert "method" not in spec and "path" not in spec


def test_unedited_toolkit_yaml_fails_closed_not_open(tmp_path):
    """A CHANGEME placeholder CIDR must not accidentally allow a real host."""
    integration = INTEGRATIONS["sonarr"]
    tier1 = _tier1_from_toolkit_yaml(tmp_path, integration.toolkit_yaml, "sonarr")
    toolkit = tier1.toolkits["sonarr"]
    import ipaddress

    # The placeholder network must not cover any private LAN range one
    # might actually run Sonarr on.
    assert not toolkit.in_allowed_cidrs(ipaddress.ip_address("192.168.1.1"))
    assert not toolkit.in_allowed_cidrs(ipaddress.ip_address("10.0.0.1"))
