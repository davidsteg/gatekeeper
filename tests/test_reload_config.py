"""`Service.reload_config` -- reload Tier 1 + Tier 2 without a process
restart.

Nothing exercised this directly before: the existing SIGHUP handler
(`__main__.py`'s `_on_sighup`) calls it, and so does
`ToolkitProposalStore.deploy` after writing a newly-approved toolkit
(`toolkit_proposals.py`) -- both rely on the same guarantee tested here:
success swaps `tier1`/`catalog`/`limiter` together, and any failure leaves
the old state completely untouched.
"""

from __future__ import annotations

import yaml

from conftest import PYTHON
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.identity import generate_token, hash_token
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1


def _toolkit_spec(sandbox, *, max_timeout=30, max_output=8192):
    return {
        "executor": "local",
        "binaries": [PYTHON],
        "denied_args": [],
        "path_roots": [str(sandbox)],
        "protected_resources": [],
        "max_timeout_seconds": max_timeout,
        "max_output_bytes": max_output,
    }


def _env(tmp_path, sandbox):
    toolkits_path = tmp_path / "toolkits.yaml"
    toolkits_path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {"demo": _toolkit_spec(sandbox)},
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": []}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "password_hash": hash_token("x" * 20),
                        "tools": [],
                        "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    tier1 = load_tier1(str(toolkits_path))
    catalog = load_catalog(str(tools_path), tier1)
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    return service, str(toolkits_path), str(tools_path), str(identities_path)


def test_reload_success_swaps_tier1_and_catalog(tmp_path, sandbox):
    service, toolkits_path, tools_path, identities_path = _env(tmp_path, sandbox)
    assert "extra" not in service.tier1.toolkits
    old_limiter = service.limiter

    raw = yaml.safe_load(open(toolkits_path, encoding="utf-8").read())
    raw["toolkits"]["extra"] = _toolkit_spec(sandbox, max_timeout=10, max_output=4096)
    with open(toolkits_path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(raw, handle)

    error = service.reload_config(
        toolkits_path=toolkits_path, tools_path=tools_path, identities_path=identities_path,
    )
    assert error is None
    assert "extra" in service.tier1.toolkits
    assert set(service.tier1.toolkits) == {"demo", "extra"}
    # The limiter is reinitialized on every successful reload (fresh
    # windows), not merely reused.
    assert service.limiter is not old_limiter


def test_reload_invalid_toolkits_leaves_old_state_untouched(tmp_path, sandbox):
    service, toolkits_path, tools_path, identities_path = _env(tmp_path, sandbox)
    old_tier1 = service.tier1
    old_catalog = service.catalog
    old_limiter = service.limiter

    with open(toolkits_path, "w", encoding="utf-8") as handle:
        handle.write("toolkits: [not, a, mapping]\n")

    error = service.reload_config(
        toolkits_path=toolkits_path, tools_path=tools_path, identities_path=identities_path,
    )
    assert error is not None
    assert "toolkits.yaml" in error
    assert service.tier1 is old_tier1
    assert service.catalog is old_catalog
    assert service.limiter is old_limiter


def test_reload_invalid_tools_leaves_old_state_untouched(tmp_path, sandbox):
    service, toolkits_path, tools_path, identities_path = _env(tmp_path, sandbox)
    old_tier1 = service.tier1
    old_catalog = service.catalog

    with open(tools_path, "w", encoding="utf-8") as handle:
        handle.write("tools: not-a-list\n")

    error = service.reload_config(
        toolkits_path=toolkits_path, tools_path=tools_path, identities_path=identities_path,
    )
    assert error is not None
    assert "tools.yaml" in error
    assert service.tier1 is old_tier1
    assert service.catalog is old_catalog


def test_reload_invalid_identities_leaves_old_state_untouched(tmp_path, sandbox):
    service, toolkits_path, tools_path, identities_path = _env(tmp_path, sandbox)
    old_tier1 = service.tier1
    old_catalog = service.catalog

    with open(identities_path, "w", encoding="utf-8") as handle:
        handle.write("identities: not-a-list\n")

    error = service.reload_config(
        toolkits_path=toolkits_path, tools_path=tools_path, identities_path=identities_path,
    )
    assert error is not None
    assert "identities.yaml" in error
    assert service.tier1 is old_tier1
    assert service.catalog is old_catalog


def test_reload_missing_toolkits_file_reports_and_leaves_state(tmp_path, sandbox):
    service, toolkits_path, tools_path, identities_path = _env(tmp_path, sandbox)
    old_tier1 = service.tier1

    import os

    os.remove(toolkits_path)

    error = service.reload_config(
        toolkits_path=toolkits_path, tools_path=tools_path, identities_path=identities_path,
    )
    assert error is not None
    assert "toolkits.yaml" in error
    assert service.tier1 is old_tier1
