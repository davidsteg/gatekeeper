"""Nested HTTP body templates — APIs like Tdarr that expect
``{"data":{"collection":"…","mode":"…"}}`` need the body template to
support nested dicts, not just flat string→string maps.
"""

from __future__ import annotations

import pytest

from gatekeeper.catalog import (
    ToolDef,
    _collect_template_strings,
    _nested_body_map,
)
from gatekeeper.errors import Denied
from gatekeeper.validate import _resolve_body_template


def test_nested_body_map_accepts_dict():
    body = {"data": {"collection": "{collection}", "mode": "{mode}"}}
    result = _nested_body_map(body, "test", "body")
    assert result == body


def test_nested_body_map_accepts_list():
    body = ["{a}", "{b}", 42, None]
    result = _nested_body_map(body, "test", "body")
    assert result == ["{a}", "{b}", 42, None]


def test_nested_body_map_accepts_scalar():
    assert _nested_body_map(42, "test", "body") == 42
    assert _nested_body_map(True, "test", "body") is True
    assert _nested_body_map(None, "test", "body") is None
    assert _nested_body_map("literal", "test", "body") == "literal"


def test_collect_template_strings_nested():
    body = {"data": {"collection": "{collection}", "mode": "{mode}", "docID": ""}}
    strings = _collect_template_strings(body)
    assert "{collection}" in strings
    assert "{mode}" in strings
    assert "" in strings  # literal empty string


def test_collect_template_strings_flat():
    body = {"collection": "{collection}", "mode": "{mode}"}
    strings = _collect_template_strings(body)
    assert "{collection}" in strings
    assert "{mode}" in strings


def test_collect_template_strings_none():
    assert _collect_template_strings(None) == []


def test_resolve_body_template_nested():
    template = {"data": {"collection": "{collection}", "mode": "{mode}", "docID": ""}}
    values = {"collection": "StatisticsJSONDB", "mode": "getAll"}
    result = _resolve_body_template(template, values)
    assert result == {
        "data": {
            "collection": "StatisticsJSONDB",
            "mode": "getAll",
            "docID": "",
        }
    }


def test_resolve_body_template_flat_still_works():
    template = {"collection": "{collection}", "mode": "{mode}"}
    values = {"collection": "LibrarySettingsJSONDB", "mode": "getAll"}
    result = _resolve_body_template(template, values)
    assert result == {"collection": "LibrarySettingsJSONDB", "mode": "getAll"}


def test_resolve_body_template_missing_param():
    template = {"data": {"collection": "{collection}", "mode": "{mode}"}}
    values = {"collection": "StatisticsJSONDB"}  # mode missing
    with pytest.raises(Denied):
        _resolve_body_template(template, values)


def test_resolve_body_template_passthrough_scalars():
    template = {"count": 42, "active": True, "tag": None, "name": "{name}"}
    values = {"name": "test"}
    result = _resolve_body_template(template, values)
    assert result == {"count": 42, "active": True, "tag": None, "name": "test"}