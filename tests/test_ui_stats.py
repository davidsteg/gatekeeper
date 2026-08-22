"""Tests for the Stats page and its aggregation helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx2
import pytest
import yaml

from gatekeeper.audit import AuditLog
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.ui import (
    UI_PREFIX,
    _admin_action_stats,
    _bucket_calls_by_day,
    _call_stats,
    _duration_stats,
    _outcome_totals,
)

BASE = "http://gatekeeper.test"
ROOT_PASSWORD = "correct-horse-battery"


@pytest.fixture
def ui_identities(tmp_path):
    tokens = {"root": generate_token(), "bot": generate_token()}
    path = tmp_path / "identities-stats.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root",
                        "role": "admin",
                        "token_hash": hash_token(tokens["root"]),
                        "password_hash": hash_token(ROOT_PASSWORD),
                        "tools": [],
                        "scopes": [],
                    },
                    {
                        "id": "bot",
                        "role": "agent",
                        "token_hash": hash_token(tokens["bot"]),
                        "tools": ["demo.show"],
                        "scopes": ["stack:*"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    return load_identities(str(path)), tokens


@pytest.fixture
def stats_app(tier1, catalog, ui_identities, tmp_path):
    store, _ = ui_identities
    audit = AuditLog(tier1.audit_dir)
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    return build_app(service=service, identities=store, audit=audit, ui=True)


def _client(app, **kwargs) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, timeout=30.0, **kwargs
    )


async def _login(client: httpx2.AsyncClient, identity: str = "root", password: str = ROOT_PASSWORD):
    return await client.post(
        f"{UI_PREFIX}/login", data={"identity": identity, "password": password}
    )


def _ts(hours_ago: float = 0) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours_ago)).strftime(
        "%Y-%m-%dT%H:%M:%S+0000"
    )


def _seed_calls(audit: AuditLog, n_ok: int = 0, n_denied: int = 0, n_failed: int = 0):
    for _ in range(n_ok):
        audit.write({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok",
                     "exit_code": 0, "duration_ms": 42, "ts": _ts(1)})
    for _ in range(n_denied):
        audit.write({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "denied",
                     "exit_code": 0, "duration_ms": 5, "ts": _ts(1),
                     "denial_reason": "PERMISSION_DENIED"})
    for _ in range(n_failed):
        audit.write({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "failed",
                     "exit_code": 1, "duration_ms": 100, "ts": _ts(1)})


# -- Unit tests ---------------------------------------------------------------


def test_outcome_totals_counts_all_outcomes():
    records = [
        {"kind": "call", "outcome": "ok"},
        {"kind": "call", "outcome": "ok"},
        {"kind": "call", "outcome": "denied"},
        {"kind": "call", "outcome": "failed"},
        {"kind": "startup"},
        {"kind": "call", "outcome": "unknown"},
    ]
    totals = _outcome_totals(records)
    assert totals["ok"] == 2
    assert totals["denied"] == 1
    assert totals["failed"] == 1
    assert totals["total"] == 4
    assert totals["error_rate"] == 50


def test_outcome_totals_zero_when_no_calls():
    assert _outcome_totals([]) == {"ok": 0, "denied": 0, "failed": 0, "total": 0, "error_rate": 0}


def test_admin_action_stats_counts_by_label():
    records = [
        {"kind": "admin_change", "action": "tool_create"},
        {"kind": "admin_change", "action": "tool_create"},
        {"kind": "admin_change", "action": "token_rotate"},
        {"kind": "call", "outcome": "ok"},
    ]
    stats = _admin_action_stats(records)
    assert stats["created tool"] == 2
    assert stats["rotated the API token of"] == 1


def test_admin_action_stats_sorted_by_count_desc():
    records = [
        {"kind": "admin_change", "action": "tool_create"},
        {"kind": "admin_change", "action": "tool_delete"},
        {"kind": "admin_change", "action": "tool_create"},
        {"kind": "admin_change", "action": "tool_create"},
    ]
    items = list(_admin_action_stats(records).items())
    assert items[0] == ("created tool", 3)
    assert items[1] == ("deleted tool", 1)


def test_duration_stats_per_toolkit_and_overall():
    tools_by_kit = {"demo": {"demo.show", "demo.echo"}}
    records = [
        {"kind": "call", "tool": "demo.show", "duration_ms": 10},
        {"kind": "call", "tool": "demo.show", "duration_ms": 20},
        {"kind": "call", "tool": "demo.show", "duration_ms": 30},
        {"kind": "call", "tool": "demo.show", "duration_ms": 40},
        {"kind": "call", "tool": "demo.show", "duration_ms": 1000},
        {"kind": "call", "tool": "unknown.tool", "duration_ms": 5},
    ]
    result = _duration_stats(records, tools_by_kit)
    assert result["demo"]["count"] == 5
    assert result["demo"]["avg"] == (10 + 20 + 30 + 40 + 1000) / 5
    assert result["_overall"]["count"] == 6


def test_duration_stats_handles_missing_durations():
    records = [
        {"kind": "call", "tool": "x", "duration_ms": None},
        {"kind": "call", "tool": "x"},
        {"kind": "call", "tool": "x", "duration_ms": "bad"},
    ]
    assert _duration_stats(records, None)["_overall"]["count"] == 0


def test_bucket_calls_by_day_buckets_correctly():
    now = datetime(2026, 8, 19, 14, 30, tzinfo=UTC)
    records = [
        {"kind": "call", "outcome": "ok", "ts": "2026-08-19T10:00:00+0000"},
        {"kind": "call", "outcome": "denied", "ts": "2026-08-18T22:00:00+0000"},
        {"kind": "call", "outcome": "ok", "ts": "2026-08-13T08:00:00+0000"},
        {"kind": "startup", "ts": "2026-08-19T10:00:00+0000"},
        {"kind": "call", "outcome": "ok", "ts": "2026-08-01T08:00:00+0000"},
    ]
    buckets = _bucket_calls_by_day(records, days=7, now=now)
    assert len(buckets) == 7
    assert buckets[6] == (1, 0)
    assert buckets[5] == (0, 1)
    assert buckets[0] == (1, 0)


def test_bucket_calls_by_day_empty():
    buckets = _bucket_calls_by_day([], days=7)
    assert len(buckets) == 7
    assert all(b == (0, 0) for b in buckets)


def test_call_stats_isolates_identities():
    records = [
        {"kind": "call", "identity": "bot", "outcome": "ok"},
        {"kind": "call", "identity": "bot", "outcome": "denied"},
        {"kind": "call", "identity": "media", "outcome": "ok"},
    ]
    stats = _call_stats(records)
    assert stats["bot"]["total"] == 2
    assert stats["media"]["total"] == 1


# -- HTTP tests ---------------------------------------------------------------


async def test_stats_requires_session(stats_app):
    async with _client(stats_app) as client:
        r = await client.get(f"{UI_PREFIX}/stats", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].endswith("/login")


async def test_stats_renders_with_seeded_data(stats_app, tier1):
    audit = AuditLog(tier1.audit_dir)
    _seed_calls(audit, n_ok=3, n_denied=1, n_failed=1)
    audit.write({"kind": "admin_change", "actor": "root", "action": "tool_create",
                 "target": "demo.test", "ts": _ts(0)})

    async with _client(stats_app) as client:
        await _login(client)
        r = await client.get(f"{UI_PREFIX}/stats")
        assert r.status_code == 200
        body = r.text
        assert "Total calls" in body
        assert "5" in body
        assert "Success rate" in body
        assert "60%" in body
        assert "Admin actions" in body
        assert "Toolkit usage" in body
        assert "Identity activity" in body
        assert "Latency" in body


async def test_stats_window_7d_renders(stats_app, tier1):
    audit = AuditLog(tier1.audit_dir)
    _seed_calls(audit, n_ok=2)

    async with _client(stats_app) as client:
        await _login(client)
        r = await client.get(f"{UI_PREFIX}/stats?window=7d")
        assert r.status_code == 200
        assert "Last 7 days" in r.text


async def test_stats_window_30d_renders(stats_app, tier1):
    audit = AuditLog(tier1.audit_dir)
    _seed_calls(audit, n_ok=1)

    async with _client(stats_app) as client:
        await _login(client)
        r = await client.get(f"{UI_PREFIX}/stats?window=30d")
        assert r.status_code == 200
        assert "Last 30 days" in r.text


async def test_stats_error_rate_shows_when_denied(stats_app, tier1):
    audit = AuditLog(tier1.audit_dir)
    _seed_calls(audit, n_ok=1, n_denied=2)

    async with _client(stats_app) as client:
        await _login(client)
        r = await client.get(f"{UI_PREFIX}/stats")
        assert r.status_code == 200
        assert "Error rate" in r.text
        assert "66%" in r.text


async def test_stats_empty_state(stats_app):
    async with _client(stats_app) as client:
        await _login(client)
        r = await client.get(f"{UI_PREFIX}/stats")
        assert r.status_code == 200
        assert "Total calls" in r.text


# -- Overview page highlight tiles --------------------------------------------


async def test_overview_shows_call_tiles(stats_app, tier1):
    audit = AuditLog(tier1.audit_dir)
    _seed_calls(audit, n_ok=4, n_denied=1)

    async with _client(stats_app) as client:
        await _login(client)
        r = await client.get(f"{UI_PREFIX}/")
        assert r.status_code == 200
        assert "Calls (12h)" in r.text
        assert "Success rate" in r.text
        assert "Full stats" in r.text
        assert f"{UI_PREFIX}/stats" in r.text


async def test_overview_call_tiles_zero_when_empty(stats_app):
    async with _client(stats_app) as client:
        await _login(client)
        r = await client.get(f"{UI_PREFIX}/")
        assert r.status_code == 200
        assert "Calls (12h)" in r.text