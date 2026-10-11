"""The toolkit reference (src/gatekeeper/toolkit_reference.py).

Each block is what an operator pastes into toolkits.yaml, so it has to be a
real Tier 1 toolkit, not a plausible-looking string -- and an unedited one
has to fail closed.
"""

from __future__ import annotations

import ipaddress

import pytest
import yaml

from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_reference import REFERENCES


def _tier1(tmp_path, toolkit_yaml: str):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        "toolkits:\n" + toolkit_yaml + f"\naudit:\n  dir: {tmp_path / 'logs'}\n",
        encoding="utf-8",
    )
    return load_tier1(str(path))


@pytest.mark.parametrize("key", sorted(REFERENCES))
def test_each_block_is_one_valid_toolkit_of_its_executor(tmp_path, key):
    ref = REFERENCES[key]
    parsed = yaml.safe_load(ref.toolkit_yaml)
    assert isinstance(parsed, dict) and len(parsed) == 1
    (name, body), = parsed.items()
    assert body["executor"] == key
    assert name in _tier1(tmp_path, ref.toolkit_yaml).toolkits


def test_every_executor_with_a_toolkit_shape_has_a_reference():
    assert set(REFERENCES) == {
        "local", "docker", "http", "ssh", "truenas", "file",
        "google", "microsoft", "opencode", "agent",
    }


@pytest.mark.parametrize("key", ["http", "opencode"])
def test_unedited_cidr_fails_closed(tmp_path, key):
    """A CHANGEME placeholder CIDR must not accidentally allow a real host."""
    (name,) = yaml.safe_load(REFERENCES[key].toolkit_yaml)
    toolkit = _tier1(tmp_path, REFERENCES[key].toolkit_yaml).toolkits[name]
    for host in ("192.168.1.1", "10.0.0.1", "172.16.0.1"):
        assert not toolkit.in_allowed_cidrs(ipaddress.ip_address(host))
