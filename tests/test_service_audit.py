"""Audit reading and hourly bucketing behind `/api/v1/audit`, the
Overview chart and Stats (`api/service.py`). Moved from `test_ui.py`
when the HTML console was removed in 1.0.0."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from gatekeeper.api.service import _bucket_calls, read_audit


def test_read_audit_filters_and_orders(tmp_path):
    path = tmp_path / "audit.jsonl"
    with open(path, "w", encoding="utf-8") as handle:
        for index in range(5):
            handle.write(
                json.dumps(
                    {
                        "ts": f"t{index}",
                        "kind": "call",
                        "identity": "a" if index % 2 else "b",
                        "tool": "demo.show",
                        "outcome": "ok",
                    }
                )
                + "\n"
            )
    records, truncated = read_audit(str(path), identity="a")
    assert not truncated
    assert [r["ts"] for r in records] == ["t3", "t1"]  # most recent first


def test_read_audit_survives_broken_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"kind": "call"}\nnot json\n\n', encoding="utf-8")
    records, _ = read_audit(str(path))
    assert len(records) == 1


def test_read_audit_missing_file():
    assert read_audit("/does/not/exist/audit.jsonl") == ([], False)


def test_calls_in_the_current_hour_reach_the_chart():
    """Regression: the chart stayed empty even though calls were present.

    The present is rounded down to the full hour. If the timestamp
    of the entry was not treated the same way, a call from the current
    hour lay *after* this present -- negative age, no bucket, empty chart.
    Exactly the case one rarely reproduces by hand.
    """
    now = datetime(2026, 8, 12, 19, 0, tzinfo=UTC)
    records = [
        {"kind": "call", "ts": "2026-08-12T19:57:00+0000", "outcome": "ok"},
        {"kind": "call", "ts": "2026-08-12T19:58:00+0000", "outcome": "denied"},
        # Different timezone, same hour in UTC.
        {"kind": "call", "ts": "2026-08-12T21:59:00+0200", "outcome": "ok"},
        # Non-calls do not count.
        {"kind": "ui_login", "ts": "2026-08-12T19:30:00+0000"},
    ]
    buckets = _bucket_calls(records, 12, now=now)
    assert buckets[-1] == (2, 1)
    assert sum(o + d for o, d in buckets[:-1]) == 0


def test_bucket_calls_spreads_over_hours():
    now = datetime(2026, 8, 12, 19, 0, tzinfo=UTC)
    records = [
        {"kind": "call", "ts": "2026-08-12T17:10:00+0000", "outcome": "ok"},
        {"kind": "call", "ts": "2026-08-12T18:10:00+0000", "outcome": "ok"},
        # Too old for the window.
        {"kind": "call", "ts": "2026-08-11T19:10:00+0000", "outcome": "ok"},
        # An unreadable timestamp must not cause a crash.
        {"kind": "call", "ts": "broken", "outcome": "ok"},
    ]
    buckets = _bucket_calls(records, 12, now=now)
    assert buckets[-3] == (1, 0)
    assert buckets[-2] == (1, 0)
    assert sum(o + d for o, d in buckets) == 2
