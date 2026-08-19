"""Append-only tool versioning (FR-3.1/3.3).

`tools.yaml` entries can be either today's flat shape (an implicit,
single version 1) or the nested `versions:`/`current_version` shape --
`load_catalog` must resolve both identically, and `store.py`'s writers
must only ever append a version, never overwrite one.
"""

from __future__ import annotations

import yaml

from conftest import PYTHON, make_catalog
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import (
    append_tool_version,
    load_catalog,
    new_tool_entry,
    normalize_tool_entry,
    now_iso,
    soft_delete_entry,
)
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore, WriteRefused


def _store(tmp_path, tier1, tool_specs):
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root", "role": "admin",
                        "token_hash": hash_token(generate_token()),
                        "password_hash": hash_token("x" * 20),
                        "tools": [], "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(identities_path))
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit)
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    return store, tools_path


# -- Legacy flat files still load ------------------------------------------


def test_legacy_flat_tools_yaml_still_loads(tmp_path, tier1, tool_specs):
    """No migration step -- today's file shape is an implicit version 1."""
    catalog = make_catalog(tmp_path, tier1, tool_specs)
    assert set(catalog.tools) == {"demo.show", "demo.echo"}
    assert catalog.tools["demo.show"].version == 1


def test_flat_spec_of_returns_editable_flat_shape_for_legacy_entry(tmp_path, tier1, tool_specs):
    catalog = make_catalog(tmp_path, tier1, tool_specs)
    flat = catalog.flat_spec_of("demo.show")
    assert flat is not None
    assert flat["id"] == "demo.show"
    assert flat["toolkit"] == "demo"
    assert flat["enabled"] is True


# -- Versioned shape resolves identically -----------------------------------


def _versioned_entry(tool_id: str, toolkit: str, binary: str, *, enabled: bool = True) -> dict:
    return {
        "id": tool_id,
        "enabled": enabled,
        "current_version": 1,
        "deleted": False,
        "versions": [
            {
                "version": 1,
                "spec": {
                    "toolkit": toolkit,
                    "binary": binary,
                    "title": "Show",
                    "description": "d",
                    "category": "read",
                    "idempotent": True,
                    "argv": ["-c", "print(1)"],
                    "parameters": {},
                    "required_scopes": [],
                    "timeout_seconds": 5,
                    "max_output_bytes": 4096,
                },
                "created_at": now_iso(),
                "created_by": "root",
                "superseded": False,
            }
        ],
    }


def test_versioned_entry_loads_like_a_flat_one(tmp_path, tier1):
    entry = _versioned_entry("demo.v1", "demo", PYTHON)
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": [entry]}), encoding="utf-8")
    catalog = load_catalog(str(tools_path), tier1, strict=True)
    assert "demo.v1" in catalog.tools
    assert catalog.tools["demo.v1"].version == 1
    assert catalog.tools["demo.v1"].category == "read"


def test_deleted_versioned_entry_excluded_from_catalog_but_kept_in_raw(tmp_path, tier1):
    entry = _versioned_entry("demo.v1", "demo", PYTHON)
    entry["deleted"] = True
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": [entry]}), encoding="utf-8")
    catalog = load_catalog(str(tools_path), tier1, strict=True)
    assert "demo.v1" not in catalog.tools
    assert catalog.raw_of("demo.v1") is not None
    assert catalog.raw_of("demo.v1")["deleted"] is True


def test_current_version_mismatch_is_a_config_error(tmp_path, tier1):
    entry = _versioned_entry("demo.v1", "demo", PYTHON)
    entry["current_version"] = 99
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": [entry]}), encoding="utf-8")
    try:
        load_catalog(str(tools_path), tier1, strict=True)
        assert False, "expected ConfigError"
    except Exception as exc:  # ConfigError
        assert "current_version" in str(exc)


# -- append_tool_version / new_tool_entry / soft_delete_entry (pure) --------


def test_new_tool_entry_is_version_1():
    spec = {"id": "x.y", "toolkit": "x", "enabled": True, "category": "read"}
    entry = new_tool_entry("x.y", spec, actor="root", created_at="2020-01-01T00:00:00")
    assert entry["current_version"] == 1
    assert entry["deleted"] is False
    assert len(entry["versions"]) == 1
    assert entry["versions"][0]["superseded"] is False
    assert "id" not in entry["versions"][0]["spec"]
    assert "enabled" not in entry["versions"][0]["spec"]


def test_append_tool_version_on_legacy_flat_entry_creates_v1_and_v2():
    legacy = {
        "id": "x.y", "toolkit": "x", "enabled": True, "category": "read",
        "title": "old",
    }
    new_spec = {"id": "x.y", "toolkit": "x", "enabled": True, "category": "read", "title": "new"}
    entry = append_tool_version(legacy, "x.y", new_spec, actor="root", created_at="t2")
    assert entry["current_version"] == 2
    assert len(entry["versions"]) == 2
    v1, v2 = entry["versions"]
    assert v1["version"] == 1 and v1["superseded"] is True
    assert v1["spec"]["title"] == "old"
    assert v2["version"] == 2 and v2["superseded"] is False
    assert v2["spec"]["title"] == "new"


def test_append_tool_version_never_overwrites_old_versions():
    entry = new_tool_entry("x.y", {"id": "x.y", "title": "v1"}, actor="a", created_at="t1")
    entry = append_tool_version(entry, "x.y", {"id": "x.y", "title": "v2"}, actor="a", created_at="t2")
    entry = append_tool_version(entry, "x.y", {"id": "x.y", "title": "v3"}, actor="a", created_at="t3")
    assert entry["current_version"] == 3
    titles = [v["spec"]["title"] for v in entry["versions"]]
    assert titles == ["v1", "v2", "v3"]
    superseded = [v["superseded"] for v in entry["versions"]]
    assert superseded == [True, True, False]


def test_soft_delete_entry_retains_history():
    entry = new_tool_entry("x.y", {"id": "x.y", "title": "v1"}, actor="a", created_at="t1")
    deleted = soft_delete_entry(entry)
    assert deleted["deleted"] is True
    assert deleted["versions"][0]["spec"]["title"] == "v1"


def test_normalize_tool_entry_reports_category_for_both_shapes():
    flat = {"id": "x.y", "toolkit": "x", "enabled": True, "category": "write"}
    versioned = new_tool_entry("x.z", {"id": "x.z", "category": "read"}, actor="a", created_at="t1")
    assert normalize_tool_entry(flat)["category"] == "write"
    assert normalize_tool_entry(versioned)["category"] == "read"
    assert normalize_tool_entry(versioned)["current_version"] == 1


# -- store.py: save_tool appends, never overwrites ---------------------------


def test_store_update_appends_a_version_old_ones_still_fetchable(tmp_path, tier1, tool_specs):
    store, tools_path = _store(tmp_path, tier1, tool_specs)
    original = store.service.catalog.flat_spec_of("demo.show")
    assert store.service.catalog.tools["demo.show"].version == 1

    updated_spec = dict(original)
    updated_spec["title"] = "Show compose file (v2)"
    store.save_tool(
        updated_spec, actor="root", rev=store.tools_revision(), replaces="demo.show"
    )

    tool = store.service.catalog.tools["demo.show"]
    assert tool.version == 2
    assert tool.title == "Show compose file (v2)"

    raw = store.service.catalog.raw_of("demo.show")
    assert raw["current_version"] == 2
    assert len(raw["versions"]) == 2
    assert raw["versions"][0]["spec"]["title"] != "Show compose file (v2)"
    assert raw["versions"][0]["superseded"] is True
    assert raw["versions"][1]["superseded"] is False

    # Reloading from disk (what a restart would produce) agrees.
    reloaded = load_catalog(str(tools_path), tier1, strict=True)
    assert reloaded.tools["demo.show"].version == 2


def test_store_create_starts_at_version_1(tmp_path, tier1, tool_specs):
    store, _tp = _store(tmp_path, tier1, tool_specs)
    spec = {
        "id": "demo.newtool", "toolkit": "demo", "binary": PYTHON,
        "title": "New", "description": "d", "category": "read",
        "idempotent": True, "enabled": True,
        "argv": ["-c", "print(1)"], "parameters": {},
        "required_scopes": [], "timeout_seconds": 5, "max_output_bytes": 4096,
    }
    store.save_tool(spec, actor="root", rev=store.tools_revision())
    assert store.service.catalog.tools["demo.newtool"].version == 1
    raw = store.service.catalog.raw_of("demo.newtool")
    assert raw["current_version"] == 1
    assert len(raw["versions"]) == 1


def test_store_delete_is_soft_and_history_survives(tmp_path, tier1, tool_specs):
    store, tools_path = _store(tmp_path, tier1, tool_specs)
    store.delete_tool("demo.show", actor="root", rev=store.tools_revision())

    assert "demo.show" not in store.service.catalog.tools
    raw = store.service.catalog.raw_of("demo.show")
    assert raw is not None
    assert raw["deleted"] is True
    assert raw["versions"][0]["spec"]["toolkit"] == "demo"

    # Deleting again is refused, not a silent no-op.
    try:
        store.delete_tool("demo.show", actor="root", rev=store.tools_revision())
        assert False, "expected WriteRefused"
    except WriteRefused:
        pass

    reloaded = load_catalog(str(tools_path), tier1, strict=True)
    assert "demo.show" not in reloaded.tools
    assert reloaded.raw_of("demo.show")["deleted"] is True
