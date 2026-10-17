"""`admin.toolkit_update` for an http toolkit's methods, path prefixes and
limits, and the network policy on proposed `allowed_cidrs` (1.11.0).

- `allowed_methods`, `allowed_path_prefixes`, `max_timeout_seconds` and
  `max_output_bytes` are proposable, pending until a human deploys, then
  live without a restart; methods/prefixes only on an http toolkit.
- A CIDR wider than /16 (IPv4) or /48 (IPv6) needs `confirm_broad_cidrs`.
- A private range is refused on a toolkit whose target is public.
- Toolkits written by hand load unchanged: the policy is for proposals.
"""

from __future__ import annotations

import ipaddress

import pytest
import yaml

from gatekeeper import toolkit_proposals
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_proposals import ToolkitProposalStore, ToolkitProposalWriteRefused


def _github(**extra):
    spec = {
        "executor": "http",
        "base_url": "https://api.github.com",
        "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/repos/"],
        "allowed_cidrs": ["140.82.112.0/20"],
    }
    spec.update(extra)
    return spec


def _sonarr():
    return {
        "executor": "http",
        "base_url": "http://sonarr.lan:8989",
        "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/api/"],
        "allowed_cidrs": ["192.168.1.42/32"],
    }


@pytest.fixture
def dns(monkeypatch):
    table = {
        "api.github.com": ["20.250.119.72"],
        "sonarr.lan": ["192.168.1.42"],
    }

    def resolve(host):
        return [ipaddress.ip_address(a) for a in table.get(host, [])]

    monkeypatch.setattr(toolkit_proposals, "_resolve_addresses", resolve)
    return table


@pytest.fixture
def env(tmp_path, dns):
    toolkits_path = tmp_path / "toolkits.yaml"
    toolkits_path.write_text(yaml.safe_dump({
        "toolkits": {"github": _github(), "sonarr": _sonarr(), "box": {
            "executor": "local", "binaries": ["/bin/true"],
        }},
        "audit": {"dir": str(tmp_path / "logs")},
    }), encoding="utf-8")
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(yaml.safe_dump({"identities": [{
        "id": "root", "role": "admin", "token_hash": hash_token(generate_token()),
        "password_hash": hash_token("x" * 20), "tools": [], "scopes": [],
    }]}), encoding="utf-8")
    tier1 = load_tier1(str(toolkits_path))
    service = Service(
        tier1=tier1, catalog=load_catalog(str(tools_path), tier1),
        audit=AuditLog(str(tmp_path / "audit")),
    )
    store = ToolkitProposalStore(
        path=str(tmp_path / "toolkit_proposals.yaml"), audit=service.audit, service=service,
        toolkits_path=str(toolkits_path), tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    return store, service, toolkits_path


def _update(store, name, spec, **kw):
    return store.propose(name=name, spec=spec, actor="hermes", kind="update", **kw)


# -- New writable fields --------------------------------------------------------


def test_methods_prefixes_and_limits_are_live_after_deploy(env):
    store, service, toolkits_path = env
    item = _update(store, "github", {
        "allowed_methods": ["GET", "POST"],
        "allowed_path_prefixes": ["/repos/davidsteg/", "/user/repos"],
        "max_timeout_seconds": 30,
        "max_output_bytes": 262144,
    })
    # Pending changes nothing.
    assert service.tier1.toolkit("github").allowed_methods == ("GET",)

    store.deploy(item.id, decided_by="root")

    live = service.tier1.toolkit("github")
    assert live.allowed_methods == ("GET", "POST")
    assert live.allowed_path_prefixes == ("/repos/davidsteg/", "/user/repos")
    assert live.max_timeout_seconds == 30
    assert live.max_output_bytes == 262144
    on_disk = yaml.safe_load(toolkits_path.read_text(encoding="utf-8"))["toolkits"]["github"]
    assert on_disk["allowed_methods"] == ["GET", "POST"]


def test_deploy_audits_before_and_after(env, tmp_path):
    import json

    store, _service, _tp = env
    item = _update(store, "github", {"allowed_methods": ["GET", "POST"]})
    store.deploy(item.id, decided_by="root")
    records = [json.loads(line) for line in
               (tmp_path / "audit" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    [deploy] = [r for r in records if r.get("action") == "toolkit_update_deploy"]
    assert deploy["before_fields"] == {"allowed_methods": ["GET"]}
    assert deploy["after_fields"] == {"allowed_methods": ["GET", "POST"]}


@pytest.mark.parametrize("value", [0, -1, "30", True, 1.5])
def test_limits_must_be_positive_integers(env, value):
    store, _service, _tp = env
    with pytest.raises(ToolkitProposalWriteRefused, match="positive integer"):
        _update(store, "github", {"max_timeout_seconds": value})


def test_unknown_method_is_refused_at_deploy(env):
    store, service, toolkits_path = env
    before = toolkits_path.read_text(encoding="utf-8")
    item = _update(store, "github", {"allowed_methods": ["GET", "FETCH"]})
    with pytest.raises(ToolkitProposalWriteRefused, match="not HTTP"):
        store.deploy(item.id, decided_by="root")
    assert toolkits_path.read_text(encoding="utf-8") == before


@pytest.mark.parametrize(
    "spec", [{"allowed_methods": ["GET"]}, {"allowed_path_prefixes": ["/x/"]}]
)
def test_http_fields_refused_on_another_executor(env, spec):
    store, _service, _tp = env
    item = _update(store, "box", spec)
    with pytest.raises(ToolkitProposalWriteRefused, match="does not use it"):
        store.deploy(item.id, decided_by="root")


def test_path_roots_and_protected_resources_stay_redeploy_only(env):
    store, _service, _tp = env
    for field in ("path_roots", "protected_resources"):
        with pytest.raises(ToolkitProposalWriteRefused, match=field):
            _update(store, "box", {field: ["/"]})


# -- Broad CIDRs ------------------------------------------------------------------


@pytest.mark.parametrize("cidr", ["140.0.0.0/8", "0.0.0.0/0", "2001:db8::/32"])
def test_broad_cidr_needs_confirmation(env, cidr):
    store, _service, _tp = env
    with pytest.raises(ToolkitProposalWriteRefused, match="confirm_broad_cidrs"):
        _update(store, "github", {"allowed_cidrs": [cidr]})
    assert store.list() == []


def test_confirmed_broad_cidr_is_queued_flagged_and_deploys(env):
    store, service, _tp = env
    item = _update(store, "github", {"allowed_cidrs": ["20.0.0.0/8"]}, confirm_broad_cidrs=True)
    assert item.confirm_broad_cidrs is True
    assert store.get(item.id).confirm_broad_cidrs is True
    store.deploy(item.id, decided_by="root")
    assert service.tier1.toolkit("github").allowed_cidrs == ("20.0.0.0/8",)


def test_slash_16_is_not_broad(env):
    store, _service, _tp = env
    item = _update(store, "github", {"allowed_cidrs": ["20.250.0.0/16"]})
    assert item.confirm_broad_cidrs is False


def test_deploy_rechecks_a_broad_cidr_without_confirmation(env):
    """A proposal file edited by hand after submit gains nothing."""
    store, _service, _tp = env
    item = _update(store, "github", {"allowed_cidrs": ["20.250.0.0/16"]})
    raw = yaml.safe_load(open(store.path, encoding="utf-8"))
    raw["proposals"][0]["spec"]["allowed_cidrs"] = ["20.0.0.0/8"]
    with open(store.path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(raw, handle)
    with pytest.raises(ToolkitProposalWriteRefused, match="confirm_broad_cidrs"):
        store.deploy(item.id, decided_by="root")


# -- Private ranges on an external target ---------------------------------------


@pytest.mark.parametrize("cidr", ["10.0.0.0/24", "192.168.1.0/24", "127.0.0.1/32", "fc00::/64"])
def test_private_cidr_refused_for_public_target(env, cidr):
    store, _service, _tp = env
    with pytest.raises(ToolkitProposalWriteRefused, match="public address"):
        _update(store, "github", {"allowed_cidrs": ["140.82.112.0/20", cidr]})


def test_private_cidr_allowed_for_lan_target(env):
    store, service, _tp = env
    item = _update(store, "sonarr", {"allowed_cidrs": ["192.168.1.40/29"]})
    store.deploy(item.id, decided_by="root")
    assert service.tier1.toolkit("sonarr").allowed_cidrs == ("192.168.1.40/29",)


def test_deploy_rechecks_resolution(env, dns):
    """The name moved to a public address while the proposal waited."""
    store, _service, _tp = env
    item = _update(store, "sonarr", {"allowed_cidrs": ["192.168.1.40/29"]})
    dns["sonarr.lan"] = ["93.184.216.34"]
    with pytest.raises(ToolkitProposalWriteRefused, match="public address"):
        store.deploy(item.id, decided_by="root")


def test_create_proposal_gets_the_same_policy(env):
    store, _service, _tp = env
    with pytest.raises(ToolkitProposalWriteRefused, match="public address"):
        store.propose(
            name="gh2", actor="hermes",
            spec=_github(allowed_cidrs=["10.0.0.0/8"]),
            confirm_broad_cidrs=True,
        )


def test_hand_written_toolkit_is_not_judged(tmp_path):
    """The policy is for proposals; an existing toolkits.yaml loads as before."""
    path = tmp_path / "toolkits.yaml"
    path.write_text(yaml.safe_dump({
        "toolkits": {"github": _github(allowed_cidrs=["10.0.0.0/8", "0.0.0.0/0"])},
        "audit": {"dir": str(tmp_path / "logs")},
    }), encoding="utf-8")
    assert load_tier1(str(path)).toolkit("github").allowed_cidrs == ("10.0.0.0/8", "0.0.0.0/0")
