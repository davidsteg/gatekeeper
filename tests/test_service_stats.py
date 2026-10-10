"""The Stats/overview aggregation helpers in `gatekeeper.api.service`
(moved from `test_ui_stats.py`), plus the numbers `/api/v1/stats` and
`/api/v1/overview` derive from them."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from api_env import API, client, login, make_env

from gatekeeper.api.service import (
    _admin_action_stats,
    _bucket_calls_by_day,
    _call_stats,
    _duration_stats,
    _outcome_totals,
)


@pytest.fixture
def env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs)


def _ts(hours_ago: float = 0) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours_ago)).strftime(
        "%Y-%m-%dT%H:%M:%S+0000"
    )


def _seed_calls(audit, n_ok: int = 0, n_denied: int = 0, n_failed: int = 0):
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




# -- Over the API: the numbers the Stats page and the overview tiles show -----


async def test_stats_rates_and_tables_with_seeded_data(env):
    """`test_ui_stats`'s "Total calls 5 / Success rate 60% / Admin actions
    / Toolkit usage / Identity activity / Latency" page, as data."""
    _seed_calls(env["audit"], n_ok=3, n_denied=1, n_failed=1)
    env["audit"].write({"kind": "admin_change", "actor": "root", "action": "tool_create",
                        "target": "demo.test", "ts": _ts(0)})
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/stats")).json()
    assert body["totals"] == {"ok": 3, "denied": 1, "failed": 1, "total": 5, "error_rate": 40}
    assert body["success_rate"] == 60
    assert body["admin_total"] == 1
    assert body["admin"] == [{"action": "created tool", "count": 1}]
    assert body["toolkits"] == [{"name": "demo", "total": 5, "ok": 3, "denied": 1, "failed": 1}]
    assert body["identities"][0] == {"name": "bot", "total": 5, "ok": 3, "denied": 1, "failed": 1}
    latency = {row["toolkit"]: row["count"] for row in body["latency"]}
    assert latency["demo"] == 5 and latency["_overall"] == 5


async def test_stats_window_labels_and_error_rate(env):
    _seed_calls(env["audit"], n_ok=1, n_denied=2)
    async with client(env["app"]) as c:
        await login(c, "eye")
        for window, label in (("7d", "Last 7 days"), ("30d", "Last 30 days")):
            body = (await c.get(f"{API}/stats", params={"window": window})).json()
            assert body["label"] == label
            assert body["totals"]["total"] == 3
        day = (await c.get(f"{API}/stats")).json()
    assert day["window"] == "24h"
    assert day["totals"]["error_rate"] == 66


async def test_stats_empty_state(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/stats")).json()
    assert body["totals"]["total"] == 0
    assert body["success_rate"] == 0
    assert body["toolkits"] == [] and body["identities"] == [] and body["latency"] == []


async def test_overview_call_tiles(env):
    """The overview's "Calls (12h)" and "Success rate" tiles."""
    _seed_calls(env["audit"], n_ok=4, n_denied=1)
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/overview")).json()
    assert body["outcomes"]["total"] == 5
    assert body["outcomes"]["success_pct"] == 80
    assert sum(b["ok"] + b["not_ok"] for b in body["activity"]) == 5


async def test_overview_call_tiles_zero_when_empty(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/overview")).json()
    assert body["outcomes"]["total"] == 0
    assert body["outcomes"]["success_pct"] == 0
    assert len(body["activity"]) == 12
    assert all(b["ok"] == 0 and b["not_ok"] == 0 for b in body["activity"])
