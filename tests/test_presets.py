"""The preset library (src/gatekeeper/presets.py).

Every preset's `toolkit_yaml` and `tool_specs` must be real, valid
definitions -- not just plausible-looking strings. If a preset were wrong,
the UI's "pick a preset" flow would just relocate hand-editing YAML from
a blank textarea to a broken pre-filled one, which is worse.
"""

from __future__ import annotations

import pytest
import yaml

from gatekeeper.catalog import parse_tool_spec
from gatekeeper.errors import ConfigError
from gatekeeper.presets import PRESETS
from gatekeeper.tier1 import load_tier1


def _tier1_from_toolkit_yaml(tmp_path, toolkit_yaml: str, name: str):
    path = tmp_path / f"toolkits-{name}.yaml"
    path.write_text(
        "toolkits:\n" + toolkit_yaml + f"\naudit:\n  dir: {tmp_path / 'logs'}\n",
        encoding="utf-8",
    )
    return load_tier1(str(path))


@pytest.mark.parametrize("key", sorted(PRESETS))
def test_toolkit_yaml_parses(tmp_path, key):
    preset = PRESETS[key]
    tier1 = _tier1_from_toolkit_yaml(tmp_path, preset.toolkit_yaml, key)
    assert key in tier1.toolkits


@pytest.mark.parametrize("key", sorted(PRESETS))
def test_tool_specs_parse_against_their_toolkit(tmp_path, key):
    preset = PRESETS[key]
    tier1 = _tier1_from_toolkit_yaml(tmp_path, preset.toolkit_yaml, key)
    assert preset.tool_specs, f"preset {key!r} has no starter tools"
    for spec in preset.tool_specs:
        tool = parse_tool_spec(dict(spec), tier1)
        assert tool.toolkit == key
        assert tool.id.startswith(f"{key}.")


@pytest.mark.parametrize("key", sorted(PRESETS))
def test_tool_ids_are_unique_within_a_preset(key):
    preset = PRESETS[key]
    ids = [spec["id"] for spec in preset.tool_specs]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("key", sorted(PRESETS))
def test_logo_is_inline_svg_with_no_external_reference(key):
    preset = PRESETS[key]
    svg = preset.logo_svg
    assert svg.strip().startswith("<svg")
    # The xmlns declaration is a namespace URI, never fetched -- only an
    # actual resource-loading attribute (href/src) would be a live
    # external reference, which is what's actually disallowed here.
    assert 'href="http' not in svg
    assert 'src="http' not in svg
    assert "<script" not in svg.lower()
    assert "<image" not in svg.lower()


@pytest.mark.parametrize("key", sorted(PRESETS))
def test_toolkit_yaml_is_a_mapping_under_the_preset_key(key):
    preset = PRESETS[key]
    parsed = yaml.safe_load(preset.toolkit_yaml)
    assert key in parsed
    assert parsed[key]["executor"] in ("http", "truenas")


def test_credential_kind_is_known():
    from gatekeeper.credentials import KINDS

    for key, preset in PRESETS.items():
        assert preset.credential_kind in KINDS, key


def test_all_twelve_named_services_present():
    expected = {
        "sonarr", "radarr", "jellyfin", "bazarr", "tdarr", "prowlarr",
        "hass", "n8n", "uptimekuma", "immich", "telegram", "google_api",
    }
    assert expected <= set(PRESETS)


def test_unedited_toolkit_yaml_fails_closed_not_open(tmp_path):
    """A CHANGEME placeholder CIDR must not accidentally allow a real host."""
    preset = PRESETS["sonarr"]
    tier1 = _tier1_from_toolkit_yaml(tmp_path, preset.toolkit_yaml, "sonarr")
    toolkit = tier1.toolkits["sonarr"]
    import ipaddress

    # The placeholder network must not cover any private LAN range one
    # might actually run Sonarr on.
    assert not toolkit.in_allowed_cidrs(ipaddress.ip_address("192.168.1.1"))
    assert not toolkit.in_allowed_cidrs(ipaddress.ip_address("10.0.0.1"))
