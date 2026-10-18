//! The Stats/overview aggregation helpers in `api::service`, plus the
//! numbers `/api/v1/stats` and `/api/v1/overview` derive from them (port
//! of `tests/test_service_stats.py` and the stats/documents half of
//! `tests/test_api_extras.py`).

mod api_env;
mod app_env;

use std::collections::{BTreeSet, HashSet};

use api_env::{api, make_env, ApiEnv};
use chrono::{Duration, TimeZone, Utc};
use gatekeeper::api::service::{
    admin_action_stats, bucket_calls_by_day, call_stats, duration_stats, outcome_totals, Totals,
};
use indexmap::IndexMap;
use serde_json::{json, Value};

fn ts(hours_ago: f64) -> String {
    (Utc::now() - Duration::milliseconds((hours_ago * 3_600_000.0) as i64)).format("%Y-%m-%dT%H:%M:%S+0000").to_string()
}

fn seed_calls(env: &ApiEnv, n_ok: usize, n_denied: usize, n_failed: usize) {
    let audit = &env.env.audit;
    for _ in 0..n_ok {
        audit
            .write(json!({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok",
                          "exit_code": 0, "duration_ms": 42, "ts": ts(1.0)}))
            .unwrap();
    }
    for _ in 0..n_denied {
        audit
            .write(json!({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "denied",
                          "exit_code": 0, "duration_ms": 5, "ts": ts(1.0), "denial_reason": "PERMISSION_DENIED"}))
            .unwrap();
    }
    for _ in 0..n_failed {
        audit
            .write(json!({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "failed",
                          "exit_code": 1, "duration_ms": 100, "ts": ts(1.0)}))
            .unwrap();
    }
}

// -- Unit tests ---------------------------------------------------------------------

#[test]
fn outcome_totals_counts_all_outcomes() {
    let records = [
        json!({"kind": "call", "outcome": "ok"}),
        json!({"kind": "call", "outcome": "ok"}),
        json!({"kind": "call", "outcome": "denied"}),
        json!({"kind": "call", "outcome": "failed"}),
        json!({"kind": "startup"}),
        json!({"kind": "call", "outcome": "unknown"}),
    ];
    let totals = outcome_totals(&records);
    assert_eq!((totals.ok, totals.denied, totals.failed, totals.total, totals.error_rate), (2, 1, 1, 4, 50));
}

#[test]
fn outcome_totals_zero_when_no_calls() {
    assert_eq!(outcome_totals(&[]), Totals { ok: 0, denied: 0, failed: 0, total: 0, error_rate: 0 });
}

#[test]
fn admin_action_stats_counts_by_label() {
    let records = [
        json!({"kind": "admin_change", "action": "tool_create"}),
        json!({"kind": "admin_change", "action": "tool_create"}),
        json!({"kind": "admin_change", "action": "token_rotate"}),
        json!({"kind": "call", "outcome": "ok"}),
    ];
    let stats = admin_action_stats(&records);
    let get = |label: &str| stats.iter().find(|(l, _)| l == label).map(|(_, n)| *n);
    assert_eq!(get("created tool"), Some(2));
    assert_eq!(get("rotated the API token of"), Some(1));
}

#[test]
fn admin_action_stats_sorted_by_count_desc() {
    let records = [
        json!({"kind": "admin_change", "action": "tool_create"}),
        json!({"kind": "admin_change", "action": "tool_delete"}),
        json!({"kind": "admin_change", "action": "tool_create"}),
        json!({"kind": "admin_change", "action": "tool_create"}),
    ];
    let items = admin_action_stats(&records);
    assert_eq!(items[0], ("created tool".to_string(), 3));
    assert_eq!(items[1], ("deleted tool".to_string(), 1));
}

#[test]
fn duration_stats_per_toolkit_and_overall() {
    let mut tools_by_kit: IndexMap<String, BTreeSet<String>> = IndexMap::new();
    tools_by_kit.insert("demo".into(), ["demo.show", "demo.echo"].iter().map(|s| s.to_string()).collect());
    let mut records: Vec<Value> =
        [10, 20, 30, 40, 1000].iter().map(|d| json!({"kind": "call", "tool": "demo.show", "duration_ms": d})).collect();
    records.push(json!({"kind": "call", "tool": "unknown.tool", "duration_ms": 5}));
    let result = duration_stats(&records, Some(&tools_by_kit));
    assert_eq!(result["demo"].count, 5.0);
    assert_eq!(result["demo"].avg, (10.0 + 20.0 + 30.0 + 40.0 + 1000.0) / 5.0);
    assert_eq!(result["_overall"].count, 6.0);
}

#[test]
fn duration_stats_handles_missing_durations() {
    let records = [
        json!({"kind": "call", "tool": "x", "duration_ms": null}),
        json!({"kind": "call", "tool": "x"}),
        json!({"kind": "call", "tool": "x", "duration_ms": "bad"}),
    ];
    assert_eq!(duration_stats(&records, None)["_overall"].count, 0.0);
}

#[test]
fn bucket_calls_by_day_buckets_correctly() {
    let now = Utc.with_ymd_and_hms(2026, 8, 19, 14, 30, 0).unwrap().fixed_offset();
    let records = [
        json!({"kind": "call", "outcome": "ok", "ts": "2026-08-19T10:00:00+0000"}),
        json!({"kind": "call", "outcome": "denied", "ts": "2026-08-18T22:00:00+0000"}),
        json!({"kind": "call", "outcome": "ok", "ts": "2026-08-13T08:00:00+0000"}),
        json!({"kind": "startup", "ts": "2026-08-19T10:00:00+0000"}),
        json!({"kind": "call", "outcome": "ok", "ts": "2026-08-01T08:00:00+0000"}),
    ];
    let buckets = bucket_calls_by_day(&records, 7, Some(now));
    assert_eq!(buckets.len(), 7);
    assert_eq!(buckets[6], (1, 0));
    assert_eq!(buckets[5], (0, 1));
    assert_eq!(buckets[0], (1, 0));
}

#[test]
fn bucket_calls_by_day_empty() {
    let buckets = bucket_calls_by_day(&[], 7, None);
    assert_eq!(buckets.len(), 7);
    assert!(buckets.iter().all(|b| *b == (0, 0)));
}

#[test]
fn call_stats_isolates_identities() {
    let records = [
        json!({"kind": "call", "identity": "bot", "outcome": "ok"}),
        json!({"kind": "call", "identity": "bot", "outcome": "denied"}),
        json!({"kind": "call", "identity": "media", "outcome": "ok"}),
    ];
    let stats = call_stats(&records);
    assert_eq!(stats["bot"].total, 2);
    assert_eq!(stats["media"].total, 1);
}

// -- Over the API ---------------------------------------------------------------------

#[tokio::test]
async fn stats_rates_and_tables_with_seeded_data() {
    let env = make_env();
    seed_calls(&env, 3, 1, 1);
    env.env
        .audit
        .write(json!({"kind": "admin_change", "actor": "root", "action": "tool_create", "target": "demo.test", "ts": ts(0.0)}))
        .unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/stats")).await.json();
    assert_eq!(body["totals"], json!({"ok": 3, "denied": 1, "failed": 1, "total": 5, "error_rate": 40}));
    assert_eq!(body["success_rate"], 60);
    assert_eq!(body["admin_total"], 1);
    assert_eq!(body["admin"], json!([{"action": "created tool", "count": 1}]));
    assert_eq!(body["toolkits"], json!([{"name": "demo", "total": 5, "ok": 3, "denied": 1, "failed": 1}]));
    assert_eq!(body["identities"][0], json!({"name": "bot", "total": 5, "ok": 3, "denied": 1, "failed": 1}));
    assert_eq!(body["tools"], json!([{"name": "demo.show", "toolkit": "demo", "total": 5, "ok": 3, "denied": 1, "failed": 1}]));
    let latency = body["latency"].as_array().unwrap();
    let count = |kit: &str| latency.iter().find(|r| r["toolkit"] == kit).unwrap()["count"].clone();
    assert_eq!(count("demo"), 5);
    assert_eq!(count("_overall"), 5);
}

#[tokio::test]
async fn stats_top_tools_carry_their_toolkit() {
    // Port of test_api_extras.py::test_stats_top_tools_carry_their_toolkit.
    let env = make_env();
    for outcome in ["ok", "ok", "failed"] {
        env.env.audit.write(json!({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": outcome})).unwrap();
    }
    env.env.audit.write(json!({"kind": "call", "identity": "bot", "tool": "gone.tool", "outcome": "denied"})).unwrap();
    env.env
        .audit
        .write(json!({"kind": "admin_change", "actor": "root", "action": "tool_create", "target": "demo.show"}))
        .unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/stats")).await.json();
    assert_eq!(
        body["tools"],
        json!([
            {"name": "demo.show", "toolkit": "demo", "total": 3, "ok": 2, "denied": 0, "failed": 1},
            {"name": "gone.tool", "toolkit": "_unknown", "total": 1, "ok": 0, "denied": 1, "failed": 0},
        ])
    );
}

#[tokio::test]
async fn stats_window_labels_and_error_rate() {
    let env = make_env();
    seed_calls(&env, 1, 2, 0);
    let mut c = env.client();
    c.login("eye").await;
    for (window, label) in [("7d", "Last 7 days"), ("30d", "Last 30 days")] {
        let body = c.get(&api(&format!("/stats?window={window}"))).await.json();
        assert_eq!(body["label"], label);
        assert_eq!(body["totals"]["total"], 3);
    }
    let day = c.get(&api("/stats")).await.json();
    assert_eq!(day["window"], "24h");
    assert_eq!(day["totals"]["error_rate"], 66);
}

#[tokio::test]
async fn stats_empty_state() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/stats")).await.json();
    assert_eq!(body["totals"]["total"], 0);
    assert_eq!(body["success_rate"], 0);
    assert_eq!(body["toolkits"], json!([]));
    assert_eq!(body["identities"], json!([]));
    assert_eq!(body["latency"], json!([]));
}

/// The overview's "Calls (12h)" and "Success rate" tiles.
#[tokio::test]
async fn overview_call_tiles() {
    let env = make_env();
    seed_calls(&env, 4, 1, 0);
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/overview")).await.json();
    assert_eq!(body["outcomes"]["total"], 5);
    assert_eq!(body["outcomes"]["success_pct"], 80);
    let sum: i64 =
        body["activity"].as_array().unwrap().iter().map(|b| b["ok"].as_i64().unwrap() + b["not_ok"].as_i64().unwrap()).sum();
    assert_eq!(sum, 5);
}

#[tokio::test]
async fn overview_call_tiles_zero_when_empty() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/overview")).await.json();
    assert_eq!(body["outcomes"]["total"], 0);
    assert_eq!(body["outcomes"]["success_pct"], 0);
    let activity = body["activity"].as_array().unwrap();
    assert_eq!(activity.len(), 12);
    assert!(activity.iter().all(|b| b["ok"] == 0 && b["not_ok"] == 0));
}

// -- From test_api_extras: stats windows, documents ---------------------------------

#[tokio::test]
async fn stats_for_each_window() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    for (window, buckets) in [("24h", 24), ("7d", 7), ("30d", 30)] {
        let body = c.get(&api(&format!("/stats?window={window}"))).await.json();
        assert_eq!(body["window"], window);
        assert_eq!(body["series"].as_array().unwrap().len(), buckets);
        let keys: Vec<&str> = body["windows"].as_array().unwrap().iter().map(|w| w["key"].as_str().unwrap()).collect();
        assert_eq!(keys, ["24h", "7d", "30d"]);
    }
    assert_eq!(c.get(&api("/stats?window=1y")).await.status, 422);
}

#[tokio::test]
async fn stats_count_tool_calls() {
    let env = make_env();
    env.env.audit.write(json!({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok", "duration_ms": 5})).unwrap();
    env.env.audit.write(json!({"kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "denied"})).unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/stats")).await.json();
    assert_eq!(body["totals"]["total"], 2);
    assert_eq!(body["totals"]["ok"], 1);
    assert_eq!(body["identities"][0]["name"], "bot");
}

/// 250 calls inside the last hour, then one from two days ago appended
/// before them: the 24 h window counts every one of the 250 and not the
/// old one, and the 7 d window counts all 251.
#[tokio::test]
async fn stats_read_their_whole_window_and_nothing_older() {
    let env = make_env();
    let now = chrono::Local::now();
    let old = (now - Duration::days(2)).format("%Y-%m-%dT%H:%M:%S%z").to_string();
    let recent = now.format("%Y-%m-%dT%H:%M:%S%z").to_string();
    let mut records = vec![json!({"ts": old, "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok"})];
    for _ in 0..250 {
        records.push(json!({"ts": recent, "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok"}));
    }
    api_env::write_audit(&env, &records);
    let mut c = env.client();
    c.login("eye").await;
    let day = c.get(&api("/stats")).await.json();
    let week = c.get(&api("/stats?window=7d")).await.json();
    assert_eq!(day["totals"]["total"], 250);
    assert_eq!(day["truncated"], false);
    assert_eq!(day["series"].as_array().unwrap().iter().map(|b| b["ok"].as_i64().unwrap()).sum::<i64>(), 250);
    assert_eq!(week["totals"]["total"], 251);
}

/// Found next to the package (not through the working directory); no path
/// from the request reaches the filesystem.
#[tokio::test]
async fn documents_are_a_fixed_list() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let index = c.get(&api("/documents")).await.json();
    let slugs: HashSet<&str> = index.as_array().unwrap().iter().map(|d| d["slug"].as_str().unwrap()).collect();
    assert_eq!(slugs, HashSet::from(["readme", "requirements", "agents", "release"]));
    let readme = c.get(&api("/documents/readme")).await.json();
    assert!(readme["text"].as_str().unwrap().contains("gatekeeper"));
    for slug in ["../pyproject.toml", "README.md", "%2e%2e%2fpyproject.toml"] {
        assert_eq!(c.get(&api(&format!("/documents/{slug}"))).await.status, 404, "{slug}");
    }
}
