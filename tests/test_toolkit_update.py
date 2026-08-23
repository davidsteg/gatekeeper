"""Tests for `ConfigStore.save_toolkit` — the narrowly-scoped Tier 1 write path.

Since v0.23.0, an admin can change a toolkit's ``executor``, ``binaries``,
and ``denied_args`` at runtime — but never the security-critical fields
(``path_roots``, ``protected_resources``, ``limits``). This test pins the
rejection half of that contract (the illegal-field check fires before the
``toolkits_path`` guard, so it needs no real toolkits.yaml on disk).
"""

from __future__ import annotations

import pytest

from gatekeeper.store import ConfigStore, WriteRefused


@pytest.fixture
def store(tier1, tool_specs, tmp_path):
    """A ConfigStore with no toolkits_path — enough for the rejection tests,
    which fail on the illegal-field check before ever touching the file."""
    from gatekeeper.audit import AuditLog
    from gatekeeper.catalog import load_catalog
    from gatekeeper.identity import load_identities
    from gatekeeper.service import Service

    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(
        __import__("yaml").safe_dump({"tools": tool_specs}), encoding="utf-8"
    )
    from gatekeeper.identity import hash_token

    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        __import__("yaml").safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token("tk-root"),
                        "password_hash": hash_token("pw-root"),
                        "tools": [],
                        "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    audit = AuditLog(tier1.audit_dir)
    service = Service(
        tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit
    )
    return ConfigStore(
        service=service,
        identities=load_identities(str(identities_path)),
        audit=audit,
        tools_path=str(tools_path),
        identities_path=str(identities_path),
    )


def _rev(store):
    return store.tools_revision()


def test_rejects_path_roots(store):
    with pytest.raises(WriteRefused):
        store.save_toolkit("demo", {"path_roots": ["/etc"]}, actor="root", rev=_rev(store))


def test_rejects_protected_resources(store):
    with pytest.raises(WriteRefused):
        store.save_toolkit("demo", {"protected_resources": []}, actor="root", rev=_rev(store))


def test_rejects_limits(store):
    with pytest.raises(WriteRefused):
        store.save_toolkit(
            "demo", {"limits": {"timeout_seconds": 999}}, actor="root", rev=_rev(store)
        )


def test_rejects_unknown_field(store):
    with pytest.raises(WriteRefused):
        store.save_toolkit("demo", {"base_url": "http://evil"}, actor="root", rev=_rev(store))


def test_accepts_executor_binaries_denied_args(store):
    """executor/binaries/denied_args are the three writable fields — the
    call passes the field check and then fails on the missing-toolkits_path
    guard (which is correct behaviour in a store without a toolkits file)."""
    with pytest.raises(WriteRefused) as exc:
        store.save_toolkit(
            "demo",
            {"executor": "file", "binaries": [], "denied_args": []},
            actor="root",
            rev=_rev(store),
        )
    assert "toolkits_path" in str(exc.value)


def test_toolkit_update_switches_executor_and_reloads(tmp_path, tier1, tool_specs):
    """Full path: a real toolkits.yaml on disk, save_toolkit switches the
    executor, and the running Service reflects the change immediately."""
    import yaml as _yaml

    from gatekeeper.audit import AuditLog
    from gatekeeper.catalog import load_catalog
    from gatekeeper.identity import hash_token, load_identities
    from gatekeeper.service import Service

    toolkits_path = tmp_path / "toolkits.yaml"
    toolkits_path.write_text(
        _yaml.safe_dump(
            {
                "toolkits": {
                    "demo": {
                        "executor": "local",
                        "binaries": ["/usr/bin/true"],
                        "denied_args": [],
                        "path_roots": [str(tmp_path)],
                        "protected_resources": ["gatekeeper"],
                        "max_timeout_seconds": 30,
                        "max_output_bytes": 8192,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(_yaml.safe_dump({"tools": []}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        _yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token("tk"),
                        "password_hash": hash_token("pw"),
                        "tools": [],
                        "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    from gatekeeper.tier1 import load_tier1

    tier1_loaded = load_tier1(str(toolkits_path))
    audit = AuditLog(tier1_loaded.audit_dir)
    service = Service(
        tier1=tier1_loaded, catalog=load_catalog(str(tools_path), tier1_loaded), audit=audit
    )
    store = ConfigStore(
        service=service,
        identities=load_identities(str(identities_path)),
        audit=audit,
        tools_path=str(tools_path),
        identities_path=str(identities_path),
        toolkits_path=str(toolkits_path),
    )

    assert service.tier1.toolkit("demo").executor == "local"

    store.save_toolkit(
        "demo",
        {"executor": "file", "binaries": [], "denied_args": []},
        actor="root",
        rev=store.toolkits_revision(),
    )

    # Executor switched and the running Service reflects it
    assert service.tier1.toolkit("demo").executor == "file"
    assert service.tier1.toolkit("demo").binaries == ()
    assert service.tier1.toolkit("demo").denied_args == ()