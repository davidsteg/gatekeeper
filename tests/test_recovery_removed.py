"""The recovery supervisor is gone (1.0.0), and what an existing deployment
still carries of it must not look as if it did anything.

- A `recovery:` block that enables anything is refused at load, with the
  migration hint; an inert one loads and is warned about.
- An `artifact` toolkit naming the removed adapter artifacts loads, warns,
  and its tools answer "unknown artifact".
- `/recovery/*` does not exist, and the former reserved argument
  `_hermes_recovery` is an ordinary unknown argument again.
"""

from __future__ import annotations

import importlib.util
import logging

import httpx2
import pytest
import yaml
from conftest import make_catalog

from gatekeeper.audit import AuditLog
from gatekeeper.errors import ConfigError, DenialReason, Denied
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

REMOVED = ["hermes-adapter-contract", "hermes-recovery-adapter"]


def _load(tmp_path, **extra):
    path = tmp_path / "toolkits.yaml"
    path.write_text(yaml.safe_dump({"toolkits": {}, "audit": {"dir": str(tmp_path / "logs")}, **extra}),
                    encoding="utf-8")
    return load_tier1(str(path))


def test_the_module_is_gone():
    assert importlib.util.find_spec("gatekeeper.recovery") is None


@pytest.mark.parametrize("block", [
    {"enabled": True},
    {"enabled": True, "installations": {"homelab": {"identities": ["hermes-homelab"]}}},
    {"enabled": False, "rescue": {"enabled": True}},
    {"decision": {"enabled": True}},
])
def test_an_enabled_recovery_block_is_refused_with_the_migration_hint(tmp_path, block):
    with pytest.raises(ConfigError, match="no longer exists") as exc:
        _load(tmp_path, recovery=block)
    assert "Delete the 'recovery:' block" in str(exc.value)


@pytest.mark.parametrize("block", [None, {}, {"enabled": False, "rescue": {"enabled": False}}])
def test_an_inert_recovery_block_loads_with_a_warning(tmp_path, caplog, block):
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        tier1 = _load(tmp_path, recovery=block)
    assert tier1.toolkits == {}
    assert "'recovery:' block is ignored" in caplog.text
    assert not hasattr(tier1, "recovery")


def test_no_recovery_block_no_warning(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        _load(tmp_path)
    assert "recovery" not in caplog.text


@pytest.fixture
def env(tmp_path, caplog):
    toolkit = {"executor": "artifact", "allowed_artifact_operations": ["list", "info"],
               "allowed_artifacts": REMOVED}
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        tier1 = _load(tmp_path, toolkits={"artifact": toolkit})
    tools = [
        {"id": "artifact.list", "toolkit": "artifact", "version": 1, "enabled": True, "title": "List",
         "description": "artifact list", "category": "read", "idempotent": True,
         "artifact_operation": "list", "parameters": {}, "required_scopes": [],
         "timeout_seconds": 30, "max_output_bytes": 65536},
        {"id": "artifact.info", "toolkit": "artifact", "version": 1, "enabled": True, "title": "Info",
         "description": "artifact info", "category": "read", "idempotent": True,
         "artifact_operation": "info", "required_scopes": [], "timeout_seconds": 30,
         "max_output_bytes": 65536,
         "parameters": {"artifact": {"type": "string", "required": True, "pattern": "^[a-z0-9-]+$",
                                     "description": "artifact id"}}},
    ]
    catalog = make_catalog(tmp_path, tier1, tools)
    token = generate_token()
    ipath = tmp_path / "identities.yaml"
    ipath.write_text(yaml.safe_dump({"identities": [
        {"id": "hermes-homelab", "role": "agent", "token_hash": hash_token(token),
         "tools": [t["id"] for t in tools], "scopes": ["artifact:hermes-recovery-adapter"]},
    ]}), encoding="utf-8")
    identities = load_identities(str(ipath))
    service = Service(tier1=tier1, catalog=catalog, audit=AuditLog(str(tmp_path / "logs")),
                      identities=identities)
    # What the 1.0.0 image carries: a manifest without artifacts.
    from gatekeeper.artifacts import ArtifactStore, build
    build(str(tmp_path), str(tmp_path / "artifacts"), commit="a" * 40, release="1.0.0")
    service.artifact_store = ArtifactStore(str(tmp_path / "artifacts"))
    return service, identities, token


def test_removed_artifacts_in_a_toolkit_warn_and_serve_nothing(env, caplog):
    service, identities, _ = env
    setup = " ".join(r.getMessage() for r in caplog.get_records("setup"))
    assert "no longer builds" in setup and "hermes-recovery-adapter" in setup


async def test_removed_artifacts_are_unknown_to_the_tools(env):
    service, identities, _ = env
    who = identities.identities["hermes-homelab"]
    listed = await service.call(who, "artifact.list", {})
    assert '"artifacts": []' in listed.stdout
    info = await service.call(who, "artifact.info", {"artifact": "hermes-recovery-adapter"})
    assert info.outcome == "failed" and "Unknown artifact" in info.stderr
    assert (await service.probe_executors()) == {"artifact": False}


async def test_the_former_reserved_argument_is_an_ordinary_unknown_argument(env):
    service, identities, _ = env
    who = identities.identities["hermes-homelab"]
    with pytest.raises(Denied) as exc:
        await service.call(who, "artifact.list", {"_hermes_recovery": {"task_id": "t1"}})
    assert exc.value.reason is DenialReason.PARAM_UNKNOWN


async def test_recovery_routes_do_not_exist(env):
    service, identities, token = env
    app = build_app(service=service, identities=identities, audit=service.audit)
    assert not [r for r in app.routes if "recovery" in getattr(r, "path", "")]
    transport = httpx2.ASGITransport(app=app)
    auth = {"Authorization": f"Bearer {token}"}
    async with httpx2.AsyncClient(transport=transport, base_url="http://gk.test") as http:
        events = await http.post("/recovery/events", headers=auth, json={"event": "turn_stopped"})
        incidents = await http.get("/recovery/incidents", headers=auth)
    assert events.status_code == incidents.status_code == 404
