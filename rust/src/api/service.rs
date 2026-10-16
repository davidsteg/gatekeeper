//! Console read model behind the JSON API (port of `api/service.py`).
//!
//! The functions here turn the live stores into plain, JSON-serialisable
//! structures -- no HTML, no request objects. The routes in `app.rs` answer
//! them as the console's response models, field by field in the models'
//! order. `admin_service` reuses some of them for the `admin.*` read
//! actions, so the console and `/admin/mcp` compute the same numbers.
//!
//! Nothing in this module writes, with one deliberate exception:
//! `pending_view` sweeps vanished pending items before listing, exactly
//! like `admin.pending_list` does.

use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, FixedOffset, Local, TimeDelta, Timelike};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use crate::catalog::{normalize_tool_entry, Catalog, Parameter, ToolDef};
use crate::credentials::CredentialStore;
use crate::errors::{ConfigError, ConfigResult};
use crate::identity::{Identity, IdentityStore, UI_ROLES};
use crate::pending::{PendingAction, PendingStore, STALE_TAKEN_REASON, STALE_VANISHED_REASON};
use crate::pyfmt::str_value;
use crate::service::Service;
use crate::store::{tool_to_yaml, ConfigStore};
use crate::tier1::{Destination, Tier1, Toolkit};
use crate::toolkit_proposals::ToolkitProposalStore;

use super::session::SessionStore;

/// Read at most this many bytes from the end of the log file.
pub const AUDIT_READ_BYTES: u64 = 2 * 1024 * 1024;
pub const AUDIT_DEFAULT_LIMIT: usize = 200;

/// `read_audit` walks the log backwards in chunks of this size and stops
/// as soon as it has enough records.
pub const AUDIT_CHUNK_BYTES: u64 = 256 * 1024;

/// Filters for [`read_audit`] (Python's keyword arguments); empty strings
/// mean "no filter".
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub identity: String,
    pub tool: String,
    pub outcome: String,
    pub since: Option<DateTime<FixedOffset>>,
}

/// `_parse_ts`: `datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S%z")`.
pub fn parse_ts(value: Option<&Value>) -> Option<DateTime<FixedOffset>> {
    let text = crate::pyfmt::str_value(value.unwrap_or(&Value::Null));
    DateTime::parse_from_str(&text, "%Y-%m-%dT%H:%M:%S%z").ok()
}

fn strip_ascii(line: &[u8]) -> &[u8] {
    let start = line.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(line.len());
    let end = line.iter().rposition(|b| !b.is_ascii_whitespace()).map(|p| p + 1).unwrap_or(start);
    &line[start..end.max(start)]
}

fn matches_field(record: &Value, key: &str, wanted: &str) -> bool {
    wanted.is_empty() || record.get(key).and_then(Value::as_str) == Some(wanted)
}

/// Reads the most recent entries of the current log file, newest first.
///
/// Returns `(entries, truncated)`. `truncated` indicates that older
/// material exists that is not visible here -- the file is longer than
/// `AUDIT_READ_BYTES`, or more matching entries exist than `limit`.
///
/// The file is walked backwards from EOF in `AUDIT_CHUNK_BYTES` chunks; the
/// first line of every chunk is held back and prepended to the chunk read
/// next, so a record cut by a chunk boundary is not lost.
pub fn read_audit(path: &str, limit: usize, filter: &AuditFilter) -> (Vec<Value>, bool) {
    let Ok(meta) = std::fs::metadata(path) else {
        return (Vec::new(), false);
    };
    let Ok(mut handle) = std::fs::File::open(path) else {
        return (Vec::new(), false);
    };
    let size = meta.len();
    let floor = size.saturating_sub(AUDIT_READ_BYTES);
    let wanted = limit.max(1) + 1;
    let mut records: Vec<Value> = Vec::new();
    let mut carry: Vec<u8> = Vec::new();
    let mut pos = size;
    let mut reached_since = false;

    while pos > floor && records.len() < wanted && !reached_since {
        let chunk_start = floor.max(pos.saturating_sub(AUDIT_CHUNK_BYTES));
        let mut blob = vec![0u8; (pos - chunk_start) as usize];
        if handle.seek(SeekFrom::Start(chunk_start)).is_err() {
            break;
        }
        // A short read (file truncated underneath) leaves what was read.
        let mut filled = 0;
        while filled < blob.len() {
            match handle.read(&mut blob[filled..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => filled += n,
            }
        }
        blob.truncate(filled);
        blob.extend_from_slice(&carry);
        pos = chunk_start;
        let mut lines: Vec<&[u8]> = blob.split(|b| *b == b'\n').collect();
        if pos > floor {
            // Incomplete: it continues into the chunk not yet read.
            carry = lines.remove(0).to_vec();
        } else if floor > 0 {
            // At the window floor mid-file: the first line was cut by the
            // window itself. Drop it.
            carry = Vec::new();
            lines.remove(0);
        } else {
            carry = Vec::new();
        }
        for line in lines.iter().rev() {
            let line = strip_ascii(line);
            if line.is_empty() {
                continue;
            }
            let Ok(record) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            if !record.is_object() {
                continue;
            }
            if let Some(since) = filter.since {
                if let Some(stamp) = parse_ts(record.get("ts")) {
                    if stamp < since {
                        reached_since = true;
                        break;
                    }
                }
            }
            if !matches_field(&record, "identity", &filter.identity)
                || !matches_field(&record, "tool", &filter.tool)
                || !matches_field(&record, "outcome", &filter.outcome)
            {
                continue;
            }
            records.push(record);
            if records.len() >= wanted {
                break;
            }
        }
    }

    let truncated = (floor > 0 && !reached_since) || records.len() > limit;
    records.truncate(limit);
    (records, truncated)
}

/// The one target field that is set on a Toolkit or a Destination.
pub trait Target {
    fn target(&self) -> String;
}

fn first_set(fields: [&Option<String>; 3]) -> String {
    fields.into_iter().flatten().find(|s| !s.is_empty()).cloned().unwrap_or_default()
}

impl Target for Toolkit {
    fn target(&self) -> String {
        first_set([&self.docker_host, &self.base_url, &self.ws_url])
    }
}

impl Target for Destination {
    fn target(&self) -> String {
        first_set([&self.docker_host, &self.base_url, &self.ws_url])
    }
}

/// One live Tier 1 toolkit as plain data -- `admin.toolkit_list` and
/// `GET /api/v1/toolkits` both report exactly this shape. Names only: a
/// toolkit's `credential` is the credential's name, never its value.
pub fn toolkit_summary(name: &str, tk: &Toolkit) -> Value {
    json!({
        "name": name,
        "executor": tk.executor,
        "binaries": tk.binaries,
        "denied_args": tk.denied_args,
        "path_roots": tk.path_roots,
        "protected_resources": tk.protected_resources,
        "max_timeout_seconds": tk.max_timeout_seconds,
        "max_output_bytes": tk.max_output_bytes,
        "destinations": tk.destinations,
        "target": tk.target(),
        "credential": tk.credential,
        "run_as": tk.run_as,
        "mailbox_path": tk.mailbox_path,
        "allowed_agent_operations": tk.allowed_agent_operations,
    })
}

pub fn toolkit_summaries(tier1: &Tier1) -> Vec<Value> {
    let mut names: Vec<&String> = tier1.toolkits.keys().collect();
    names.sort();
    names.into_iter().map(|name| toolkit_summary(name, &tier1.toolkits[name])).collect()
}

/// Credential metadata, never a value (FR-10.2). `used_by` comes from
/// `Tier1::credential_references`, the one walk over toolkits *and*
/// destinations.
pub fn credential_summaries(credentials: &CredentialStore, tier1: &Tier1) -> ConfigResult<Vec<Value>> {
    let used_by: HashMap<String, Vec<String>> = tier1.credential_references().into_iter().collect();
    Ok(credentials
        .names(Some(&used_by))?
        .into_iter()
        .map(|meta| {
            json!({
                "name": meta.name,
                "kind": meta.kind,
                "header": meta.header,
                "header_format": meta.header_format,
                "created_at": meta.created_at,
                "rotated_at": meta.rotated_at,
                "in_overlap": meta.in_overlap,
                "used_by": meta.used_by,
                "probe_url": meta.probe_url,
                "probe_status": meta.probe_status,
                "probe_checked_at": meta.probe_checked_at,
                "suspect_status": meta.suspect_status,
                "suspect_at": meta.suspect_at,
            })
        })
        .collect())
}

// -- Timestamps and bucketing ------------------------------------------------

/// Current time in the container's local timezone, as a fixed offset (what
/// Python's `datetime.now().astimezone()` holds).
pub fn local_now() -> DateTime<FixedOffset> {
    Local::now().fixed_offset()
}

/// A parsed timestamp converted to local time for display.
fn to_local(stamp: DateTime<FixedOffset>) -> DateTime<FixedOffset> {
    stamp.with_timezone(&Local).fixed_offset()
}

fn floor_hour(t: DateTime<FixedOffset>) -> DateTime<FixedOffset> {
    t.with_minute(0).and_then(|t| t.with_second(0)).and_then(|t| t.with_nanosecond(0)).unwrap_or(t)
}

fn floor_day(t: DateTime<FixedOffset>) -> DateTime<FixedOffset> {
    floor_hour(t).with_hour(0).unwrap_or(t)
}

/// `datetime.isoformat()` of a whole-second aware datetime.
pub fn isoformat(t: DateTime<FixedOffset>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%:z").to_string()
}

fn is_call(record: &Value) -> bool {
    record.get("kind").and_then(Value::as_str) == Some("call")
}

fn outcome_is_ok(record: &Value) -> bool {
    record.get("outcome").and_then(Value::as_str) == Some("ok")
}

fn bucket_by(
    records: &[Value],
    slots: usize,
    current: DateTime<FixedOffset>,
    floor: fn(DateTime<FixedOffset>) -> DateTime<FixedOffset>,
    span_seconds: i64,
) -> Vec<(i64, i64)> {
    let mut buckets = vec![(0i64, 0i64); slots];
    for record in records {
        if !is_call(record) {
            continue;
        }
        let Some(stamp) = parse_ts(record.get("ts")) else {
            continue;
        };
        let slot_start = floor(to_local(stamp));
        let age = (current - slot_start).num_seconds().div_euclid(span_seconds);
        if age >= 0 && (age as usize) < slots {
            let slot = slots - 1 - age as usize;
            if outcome_is_ok(record) {
                buckets[slot].0 += 1;
            } else {
                buckets[slot].1 += 1;
            }
        }
    }
    buckets
}

/// Calls per hour slot as `(succeeded, not succeeded)`. Both sides are
/// rounded down to the full hour before computing, so an entry from the
/// current hour lands in the last slot.
pub fn bucket_calls(records: &[Value], hours: usize, now: Option<DateTime<FixedOffset>>) -> Vec<(i64, i64)> {
    bucket_by(records, hours, floor_hour(now.unwrap_or_else(local_now)), floor_hour, 3600)
}

/// Calls per day slot, for the 7d/30d chart.
pub fn bucket_calls_by_day(records: &[Value], days: usize, now: Option<DateTime<FixedOffset>>) -> Vec<(i64, i64)> {
    bucket_by(records, days, floor_day(now.unwrap_or_else(local_now)), floor_day, 86400)
}

// -- Call counting -------------------------------------------------------------

/// `{ok, denied, failed, total}`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub ok: i64,
    pub denied: i64,
    pub failed: i64,
    pub total: i64,
}

impl Counts {
    fn add(&mut self, record: &Value) {
        match record.get("outcome").and_then(Value::as_str) {
            Some("ok") => self.ok += 1,
            Some("denied") => self.denied += 1,
            Some("failed") => self.failed += 1,
            _ => {}
        }
        self.total += 1;
    }

    pub fn to_value(self) -> Value {
        json!({"ok": self.ok, "denied": self.denied, "failed": self.failed, "total": self.total})
    }
}

/// Python truthiness of a JSON value.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
    }
}

/// `record.get(key) or ""` as a string key.
fn key_or_empty(record: &Value, key: &str) -> String {
    let v = record.get(key);
    if truthy(v) {
        str_value(v.unwrap())
    } else {
        String::new()
    }
}

/// Counts calls per identity: `{id: Counts}`.
pub fn call_stats(records: &[Value]) -> IndexMap<String, Counts> {
    let mut stats: IndexMap<String, Counts> = IndexMap::new();
    for record in records.iter().filter(|r| is_call(r)) {
        let ident = key_or_empty(record, "identity");
        if ident.is_empty() {
            continue;
        }
        stats.entry(ident).or_default().add(record);
    }
    stats
}

fn tool_to_kit(tools_by_kit: &IndexMap<String, BTreeSet<String>>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (kit, ids) in tools_by_kit {
        for tid in ids {
            map.insert(tid.clone(), kit.clone());
        }
    }
    map
}

/// Counts calls per toolkit by resolving the tool ID; a call whose tool is
/// in no known toolkit is grouped under `_unknown`.
pub fn tool_call_stats(records: &[Value], tools_by_kit: &IndexMap<String, BTreeSet<String>>) -> IndexMap<String, Counts> {
    let lookup = tool_to_kit(tools_by_kit);
    let mut stats: IndexMap<String, Counts> = IndexMap::new();
    for record in records.iter().filter(|r| is_call(r)) {
        let kit = lookup.get(&key_or_empty(record, "tool")).cloned().unwrap_or_else(|| "_unknown".into());
        stats.entry(kit).or_default().add(record);
    }
    stats
}

/// Counts calls per (identity, toolkit) pair -- the access map's edges.
pub fn pair_call_stats(
    records: &[Value],
    tools_by_kit: &IndexMap<String, BTreeSet<String>>,
) -> HashMap<(String, String), Counts> {
    let lookup = tool_to_kit(tools_by_kit);
    let mut stats: HashMap<(String, String), Counts> = HashMap::new();
    for record in records.iter().filter(|r| is_call(r)) {
        let ident = key_or_empty(record, "identity");
        let Some(kit) = lookup.get(&key_or_empty(record, "tool")) else {
            continue;
        };
        if ident.is_empty() {
            continue;
        }
        stats.entry((ident, kit.clone())).or_default().add(record);
    }
    stats
}

/// Flat outcome totals and error rate across all call records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    pub ok: i64,
    pub denied: i64,
    pub failed: i64,
    pub total: i64,
    pub error_rate: i64,
}

pub fn outcome_totals(records: &[Value]) -> Totals {
    let (mut ok, mut denied, mut failed) = (0, 0, 0);
    for record in records.iter().filter(|r| is_call(r)) {
        match record.get("outcome").and_then(Value::as_str) {
            Some("ok") => ok += 1,
            Some("denied") => denied += 1,
            Some("failed") => failed += 1,
            _ => {}
        }
    }
    let total = ok + denied + failed;
    let error_rate = if total > 0 { ((denied + failed) as f64 / total as f64 * 100.0) as i64 } else { 0 };
    Totals { ok, denied, failed, total, error_rate }
}

fn pct(part: i64, whole: i64) -> i64 {
    if whole > 0 {
        (part as f64 / whole as f64 * 100.0) as i64
    } else {
        0
    }
}

fn request_pending_counts(
    pending: Option<&PendingStore>,
    proposals: Option<&ToolkitProposalStore>,
) -> ConfigResult<(usize, usize)> {
    let change = match pending {
        Some(p) => p.list(None)?.iter().filter(|i| i.status == "pending").count(),
        None => 0,
    };
    let toolkit = match proposals {
        Some(p) => p.list(None)?.iter().filter(|i| i.status == "pending").count(),
        None => 0,
    };
    Ok((change, toolkit))
}

pub fn audit_path(service: &Service) -> String {
    format!("{}/audit.jsonl", service.tier1().audit_dir)
}

fn tools_by_kit(service: &Service) -> IndexMap<String, BTreeSet<String>> {
    let tier1 = service.tier1();
    let catalog = service.catalog();
    let mut names: Vec<&String> = tier1.toolkits.keys().collect();
    names.sort();
    let mut map: IndexMap<String, BTreeSet<String>> = names.into_iter().map(|n| (n.clone(), BTreeSet::new())).collect();
    for tool in catalog.tools.values() {
        map.entry(tool.toolkit.clone()).or_default().insert(tool.id.clone());
    }
    map
}

fn sorted_toolkits(tier1: &Tier1) -> Vec<(&String, &Toolkit)> {
    let mut kits: Vec<(&String, &Toolkit)> = tier1.toolkits.iter().collect();
    kits.sort_by(|a, b| a.0.cmp(b.0));
    kits
}

/// The rows of the access map: agents, plus console identities that hold
/// a grant -- and, with nothing but console identities, all of them.
fn matrix_identities(identities: &IdentityStore) -> Vec<&Identity> {
    let mut rows: Vec<&Identity> = identities
        .identities
        .values()
        .filter(|i| !UI_ROLES.contains(&i.role.as_str()) || !i.tools.is_empty())
        .collect();
    if rows.is_empty() {
        rows = identities.identities.values().collect();
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows
}

/// Identity x toolkit grants with per-pair call counts. `hot_threshold` is
/// the heat-map cut-off (75th percentile of pair totals, at least 3).
pub fn access_matrix(service: &Service, identities: &IdentityStore, records: &[Value]) -> Value {
    let tier1 = service.tier1();
    let toolkits = sorted_toolkits(&tier1);
    let by_kit = tools_by_kit(service);
    let pairs = pair_call_stats(records, &by_kit);
    let mut totals: Vec<i64> = pairs.values().map(|c| c.total).collect();
    totals.sort();
    let hot = if totals.is_empty() { 0 } else { totals[(totals.len() as f64 * 0.75) as usize] };
    let empty = BTreeSet::new();
    let rows: Vec<Value> = matrix_identities(identities)
        .into_iter()
        .map(|ident| {
            let cells: Vec<Value> = toolkits
                .iter()
                .map(|(name, _)| {
                    let kit_tools = by_kit.get(*name).unwrap_or(&empty);
                    let granted: Vec<&String> = ident.tools.intersection(kit_tools).collect();
                    let calls = if granted.is_empty() {
                        Counts::default()
                    } else {
                        pairs.get(&(ident.id.clone(), (*name).clone())).copied().unwrap_or_default()
                    };
                    json!({"toolkit": name, "granted": granted, "calls": calls.to_value()})
                })
                .collect();
            json!({"identity": ident.id, "role": ident.role, "tool_count": ident.tools.len(), "cells": cells})
        })
        .collect();
    json!({
        "toolkits": toolkits.iter().map(|(n, tk)| json!({"name": n, "executor": tk.executor})).collect::<Vec<_>>(),
        "rows": rows,
        "hot_threshold": hot.max(3),
    })
}

/// Everything the console's overview page shows, as data.
pub fn overview_view(
    service: &Service,
    identities: &IdentityStore,
    store: Option<&ConfigStore>,
    pending: Option<&PendingStore>,
    proposals: Option<&ToolkitProposalStore>,
    now: Option<DateTime<FixedOffset>>,
) -> ConfigResult<Value> {
    let catalog = service.catalog();
    let tier1 = service.tier1();
    let (records, _) = read_audit(&audit_path(service), 400, &AuditFilter::default());
    let (change_n, toolkit_n) = request_pending_counts(pending, proposals)?;
    let totals = outcome_totals(&records);
    let current = floor_hour(now.unwrap_or_else(local_now));
    let buckets = bucket_calls(&records, 12, now);
    let n = buckets.len() as i64;
    let activity: Vec<Value> = buckets
        .iter()
        .enumerate()
        .map(|(i, (ok, bad))| {
            json!({"hour": isoformat(current - TimeDelta::hours(n - 1 - i as i64)), "ok": ok, "not_ok": bad})
        })
        .collect();
    let unwritable: Vec<String> = match store {
        Some(store) => {
            let mut names: Vec<String> =
                store.writability().into_iter().filter(|(_, ok)| !truthy(Some(ok))).map(|(name, _)| name).collect();
            names.sort();
            names
        }
        None => Vec::new(),
    };
    let protected: BTreeSet<&String> = tier1.toolkits.values().flat_map(|tk| tk.protected_resources.iter()).collect();
    let recent: Vec<Value> = records.iter().take(20).cloned().collect();
    Ok(json!({
        "stats": {
            "tools_active": catalog.tools.values().filter(|t| t.enabled).count(),
            "identities": identities.identities.len(),
            "protected_resources": protected.len(),
            "tools_disabled": catalog.disabled_by_tier1.len(),
        },
        "outcomes": {
            "ok": totals.ok, "denied": totals.denied, "failed": totals.failed,
            "total": totals.total, "error_rate": totals.error_rate,
            "success_pct": pct(totals.ok, totals.total),
        },
        "events_logged": records.len(),
        "activity": activity,
        "recent": recent,
        "notices": {
            "unwritable": unwritable,
            "disabled_by_tier1": catalog.disabled_by_tier1,
            "pending_changes": change_n,
            "pending_toolkits": toolkit_n,
            "no_toolkits": tier1.toolkits.is_empty(),
            "empty_catalog": !tier1.toolkits.is_empty() && catalog.tools.is_empty(),
        },
        "access": access_matrix(service, identities, &records),
    }))
}

// -- Tools and identities ----------------------------------------------------------

/// `int | None` as Pydantic serialises it: integral numbers as ints.
fn opt_int(v: &Option<Value>) -> Value {
    match v {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Number(n)) if n.is_f64() => match n.as_f64() {
            Some(f) if f.fract() == 0.0 => Value::from(f as i64),
            _ => Value::Number(n.clone()),
        },
        Some(other) => other.clone(),
    }
}

fn parameter(p: &Parameter) -> Value {
    json!({
        "name": p.name,
        "type": p.ptype,
        "description": p.description,
        "required": p.required,
        "derived": p.derived,
        "pattern": p.pattern_source,
        "values": p.values,
        "minimum": opt_int(&p.minimum),
        "maximum": opt_int(&p.maximum),
    })
}

pub fn tool_summary(tool: &ToolDef, identities: &IdentityStore) -> Value {
    let mut params: Vec<(&String, &Parameter)> = tool.parameters.iter().collect();
    params.sort_by(|a, b| a.0.cmp(b.0));
    let mut grantees: Vec<&String> =
        identities.identities.values().filter(|i| i.tools.contains(&tool.id)).map(|i| &i.id).collect();
    grantees.sort();
    json!({
        "id": tool.id,
        "toolkit": tool.toolkit,
        "destination": tool.destination,
        "version": tool.version,
        "title": tool.title,
        "description": tool.description,
        "category": tool.category,
        "idempotent": tool.idempotent,
        "enabled": tool.enabled,
        "required_scopes": tool.required_scopes,
        "timeout_seconds": tool.timeout_seconds,
        "max_output_bytes": tool.max_output_bytes,
        "parameters": params.into_iter().map(|(_, p)| parameter(p)).collect::<Vec<_>>(),
        "grantees": grantees,
    })
}

fn sorted_tools(catalog: &Catalog) -> Vec<&ToolDef> {
    let mut tools: Vec<&ToolDef> = catalog.tools.values().collect();
    tools.sort_by(|a, b| a.id.cmp(&b.id));
    tools
}

pub fn tools_view(service: &Service, identities: &IdentityStore) -> Value {
    let catalog = service.catalog();
    let tier1 = service.tier1();
    json!({
        "tools": sorted_tools(&catalog).into_iter().map(|t| tool_summary(t, identities)).collect::<Vec<_>>(),
        "rejected": catalog.rejected.iter().map(|(spec, reason)| json!({
            "id": spec.get("id").map(str_value).unwrap_or_else(|| "?".into()),
            "reason": reason,
        })).collect::<Vec<_>>(),
        "disabled_by_tier1": catalog.disabled_by_tier1,
        "toolkits": sorted_toolkits(&tier1).iter().map(|(n, tk)| json!({"name": n, "executor": tk.executor})).collect::<Vec<_>>(),
    })
}

/// One definition as the editor shows it: the flat spec and its YAML.
/// `tool_id` is the definition's own ID (the base ID for a
/// multi-destination toolkit).
pub fn tool_detail(service: &Service, identities: &IdentityStore, tool_id: &str) -> Option<Value> {
    let catalog = service.catalog();
    let spec = catalog.flat_spec_of(tool_id)?;
    let raw = catalog.raw_of(tool_id)?;
    let entry = normalize_tool_entry(raw);
    let prefix = format!("{tool_id}@");
    let expanded: Vec<Value> = sorted_tools(&catalog)
        .into_iter()
        .filter(|t| t.id == tool_id || t.id.starts_with(&prefix))
        .map(|t| tool_summary(t, identities))
        .collect();
    let versions: Vec<Value> = entry
        .get("versions")
        .and_then(Value::as_array)
        .map(|vs| {
            vs.iter()
                .map(|v| {
                    let mut out = Map::new();
                    for k in ["version", "created_at", "created_by", "superseded"] {
                        out.insert(k.into(), v.get(k).cloned().unwrap_or(Value::Null));
                    }
                    Value::Object(out)
                })
                .collect()
        })
        .unwrap_or_default();
    Some(json!({
        "id": tool_id,
        "enabled": entry.get("enabled").cloned().unwrap_or(Value::Null),
        "current_version": entry.get("current_version").cloned().unwrap_or(Value::Null),
        "versions": versions,
        "yaml": tool_to_yaml(&spec),
        "spec": Value::Object(spec),
        "tools": expanded,
    }))
    .map(reorder_detail)
}

/// `ToolDetail`'s field order (spec before yaml).
fn reorder_detail(v: Value) -> Value {
    project(&v, &["id", "enabled", "current_version", "versions", "spec", "yaml", "tools"])
}

/// The named fields of an object, in this order (a response model).
pub fn project(v: &Value, fields: &[&str]) -> Value {
    let mut out = Map::new();
    for f in fields {
        out.insert((*f).to_string(), v.get(*f).cloned().unwrap_or(Value::Null));
    }
    Value::Object(out)
}

/// Identities without a single hash: role, grants, scopes, and which of the
/// two credentials it can use.
pub fn identities_view(service: &Service, identities: &IdentityStore) -> Vec<Value> {
    let catalog = service.catalog();
    let mut all: Vec<&Identity> = identities.identities.values().collect();
    all.sort_by(|a, b| a.id.cmp(&b.id));
    all.into_iter()
        .map(|ident| {
            let console = if UI_ROLES.contains(&ident.role.as_str()) {
                if ident.can_sign_in() {
                    "access"
                } else {
                    "no_password"
                }
            } else {
                "api_only"
            };
            let unknown: Vec<&String> = ident.tools.iter().filter(|t| !catalog.tools.contains_key(*t)).collect();
            json!({
                "id": ident.id,
                "role": ident.role,
                "tools": ident.tools,
                "scopes": ident.scopes,
                "console": console,
                "unknown_tools": unknown,
            })
        })
        .collect()
}

// -- Requests ------------------------------------------------------------------------

fn sweep(store: Option<&ConfigStore>, pending: &PendingStore, credentials: Option<&CredentialStore>) -> ConfigResult<()> {
    if let Some(store) = store {
        crate::admin_service::sweep_vanished_pendings(store, pending, credentials, "system")?;
    }
    Ok(())
}

const PENDING_ITEM_FIELDS: [&str; 11] =
    ["id", "action", "actor", "payload", "base_rev", "status", "created_at", "decided_by", "decided_at", "reason", "review"];

fn pending_spec(item: &PendingAction, store: Option<&ConfigStore>) -> Value {
    let mut spec = item.to_spec();
    spec["review"] = pending_review(item, store);
    project(&spec, &PENDING_ITEM_FIELDS)
}

pub fn pending_view(
    store: Option<&ConfigStore>,
    pending: Option<&PendingStore>,
    status: Option<&str>,
    credentials: Option<&CredentialStore>,
) -> ConfigResult<Vec<Value>> {
    let Some(pending) = pending else {
        return Ok(Vec::new());
    };
    sweep(store, pending, credentials)?;
    Ok(pending.list(status)?.iter().map(|item| pending_spec(item, store)).collect())
}

fn b64_nopad(text: &str) -> String {
    base64::engine::general_purpose::URL_SAFE.encode(text.as_bytes()).trim_end_matches('=').to_string()
}

fn b64_padded_decode(cursor: &str) -> Option<Vec<u8>> {
    let pad = (4 - cursor.chars().count() % 4) % 4;
    crate::identity::py_b64decode(&format!("{cursor}{}", "=".repeat(pad)), true)
}

fn encode_decided_cursor(key: &(String, usize)) -> String {
    b64_nopad(&crate::pyjson::dumps(&json!([key.0, key.1])))
}

/// `None` for anything this module did not write.
fn decode_decided_cursor(cursor: &str) -> Option<(String, i64)> {
    let raw = b64_padded_decode(cursor)?;
    let key: Value = serde_json::from_slice(&raw).ok()?;
    match key.as_array().map(Vec::as_slice) {
        Some([Value::String(s), Value::Number(n)]) if n.is_i64() || n.is_u64() => Some((s.clone(), n.as_i64()?)),
        _ => None,
    }
}

/// Decided proposals, newest decision first, `limit` at a time. `Err(None)`
/// for a bad cursor (a 400); `Err(Some(e))` for a store failure.
pub fn decided_pending_page(
    store: Option<&ConfigStore>,
    pending: Option<&PendingStore>,
    limit: usize,
    cursor: Option<&str>,
    credentials: Option<&CredentialStore>,
) -> Result<Value, Option<ConfigError>> {
    let Some(pending) = pending else {
        return Ok(json!({"entries": [], "next_cursor": null, "total": 0}));
    };
    sweep(store, pending, credentials).map_err(Some)?;
    let items = pending.list(None).map_err(Some)?;
    let mut decided: Vec<((String, usize), &PendingAction)> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| item.status != "pending")
        .map(|(pos, item)| ((item.decided_at.clone().filter(|d| !d.is_empty()).unwrap_or_else(|| item.created_at.clone()), pos), item))
        .collect();
    decided.sort_by(|a, b| b.0.cmp(&a.0));
    let total = decided.len();
    if let Some(cursor) = cursor.filter(|c| !c.is_empty()) {
        let after = decode_decided_cursor(cursor).ok_or(None)?;
        decided.retain(|((stamp, pos), _)| (stamp.as_str(), *pos as i64) < (after.0.as_str(), after.1));
    }
    let more = decided.len() > limit;
    let page: Vec<&((String, usize), &PendingAction)> = decided.iter().take(limit).collect();
    let next = match page.last() {
        Some((key, _)) if more => Value::String(encode_decided_cursor(key)),
        _ => Value::Null,
    };
    Ok(json!({
        "entries": page.iter().map(|(_, item)| pending_spec(item, store)).collect::<Vec<_>>(),
        "next_cursor": next,
        "total": total,
    }))
}

/// One tool a proposal names, resolved against the live catalog.
fn review_tool(store: Option<&ConfigStore>, tool_id: &str, marker: &str) -> Value {
    let flat = store.and_then(|s| s.service.catalog().flat_spec_of(tool_id));
    let Some(flat) = flat else {
        return json!({"id": tool_id, "marker": marker, "state": "missing", "title": "", "category": ""});
    };
    let title = if truthy(flat.get("title")) { str_value(&flat["title"]) } else { tool_id.to_string() };
    json!({
        "id": tool_id, "marker": marker,
        "state": if truthy(flat.get("enabled")) { "enabled" } else { "disabled" },
        "title": title,
        "category": flat.get("category").map(str_value).unwrap_or_default(),
    })
}

/// `payload.get(key, default)` rendered with Python's `str()`.
fn pstr(map: &Map<String, Value>, key: &str, default: &str) -> String {
    map.get(key).map(str_value).unwrap_or_else(|| default.to_string())
}

/// `payload.get(key) or default`, as a value.
fn or_value<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key).filter(|v| truthy(Some(v)))
}

fn id_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(items)) => items.iter().map(str_value).collect(),
        _ => Vec::new(),
    }
}

/// What a reviewer needs to judge one proposal, as plain data.
pub fn pending_review(item: &PendingAction, store: Option<&ConfigStore>) -> Value {
    let payload = &item.payload;
    let mut tools: Vec<Value> = Vec::new();
    let mut unchanged = 0usize;
    let action = item.action.as_str();
    let empty = Map::new();
    let headline = match action {
        "tool_enable" | "tool_disable" | "tool_delete" => {
            tools.push(review_tool(store, &pstr(payload, "id", ""), ""));
            format!("{} tool {}", action.replace("tool_", ""), pstr(payload, "id", ""))
        }
        "tool_create" | "tool_update" => {
            let spec = or_value(payload, "spec").and_then(Value::as_object).unwrap_or(&empty);
            let target = match or_value(payload, "replaces") {
                Some(v) => str_value(v),
                None => pstr(spec, "id", ""),
            };
            format!(
                "tool {target}: category {}, enabled={}",
                pstr(spec, "category", ""),
                spec.get("enabled").map(str_value).unwrap_or_else(|| "False".into())
            )
        }
        "grant_set" => {
            let identity_id = pstr(payload, "identity_id", "");
            let proposed_ids = id_list(or_value(payload, "tools"));
            match payload.get("prev_tools").filter(|v| !v.is_null()) {
                None => {
                    let mut sorted = proposed_ids.clone();
                    sorted.sort();
                    tools = sorted.iter().map(|t| review_tool(store, t, "")).collect();
                    format!("identity {identity_id}: {} tool grant(s)", proposed_ids.len())
                }
                Some(prev) => {
                    let catalog = store.map(|s| s.service.catalog());
                    let normalize = |ids: &[String]| -> BTreeSet<String> {
                        let mut found = BTreeSet::new();
                        for tid in ids {
                            let resolved = catalog.as_ref().map(|c| c.grantable_ids(tid)).unwrap_or_default();
                            if resolved.is_empty() {
                                found.insert(tid.clone());
                            } else {
                                found.extend(resolved);
                            }
                        }
                        found
                    };
                    let proposed = normalize(&proposed_ids);
                    let previous = normalize(&id_list(Some(prev)));
                    let added: Vec<&String> = proposed.difference(&previous).collect();
                    let removed: Vec<&String> = previous.difference(&proposed).collect();
                    let kept: Vec<&String> = proposed.intersection(&previous).collect();
                    unchanged = kept.len();
                    tools.extend(added.iter().map(|t| review_tool(store, t, "+")));
                    tools.extend(removed.iter().map(|t| review_tool(store, t, "-")));
                    tools.extend(
                        kept.iter().map(|t| review_tool(store, t, "")).filter(|r| r["state"] != json!("enabled")),
                    );
                    format!("identity {identity_id}: +{} -{}, {unchanged} unchanged", added.len(), removed.len())
                }
            }
        }
        "cred_propose" => {
            let mut text = format!("credential {}: kind {}", pstr(payload, "name", ""), pstr(payload, "kind", ""));
            if let Some(header) = or_value(payload, "header") {
                text.push_str(&format!(", header {}", str_value(header)));
            }
            if let Some(format_) = or_value(payload, "header_format") {
                text.push_str(&format!(", value format {}", str_value(format_)));
            }
            text.push_str(" (no value: typed by a human on approval)");
            text
        }
        "cred_update" => {
            let prev = or_value(payload, "prev").and_then(Value::as_object).unwrap_or(&empty);
            let mut changes: Vec<String> = Vec::new();
            if let Some(new_name) = or_value(payload, "new_name") {
                changes.push(format!("rename to {}", str_value(new_name)));
            }
            for field in ["kind", "header", "header_format", "probe_url"] {
                let before = prev.get(field).unwrap_or(&Value::Null);
                let after = payload.get(field).unwrap_or(&Value::Null);
                if before != after {
                    let show = |v: &Value| if truthy(Some(v)) { str_value(v) } else { "none".to_string() };
                    changes.push(format!("{} {} -> {}", field.replace('_', " "), show(before), show(after)));
                }
            }
            let joined = if changes.is_empty() { "no change".to_string() } else { changes.join(", ") };
            format!("credential {}: {joined} (stored value kept)", pstr(payload, "name", ""))
        }
        "role_set" => {
            let identity_id = pstr(payload, "identity_id", "");
            let new_role = pstr(payload, "role", "");
            let current = store.and_then(|s| s.identities.read().identities.get(&identity_id).map(|i| i.role.clone()));
            match current {
                Some(role) if role != new_role => format!("identity {identity_id}: role {role} -> {new_role}"),
                _ => format!("identity {identity_id}: role {new_role}"),
            }
        }
        _ => crate::pyjson::dumps(&Value::Object(payload.clone())),
    };
    let stale = if item.status == "stale" {
        let reason = item.reason.as_deref();
        Value::String(if reason == Some(STALE_VANISHED_REASON) {
            "What this proposal targeted no longer exists, so there is nothing to apply it to.".to_string()
        } else if reason == Some(STALE_TAKEN_REASON) {
            let name = match or_value(payload, "new_name") {
                Some(v) => str_value(v),
                None => pstr(payload, "name", ""),
            };
            format!(
                "A credential named {name} was created after this was proposed. Ask the agent for a new \
                 name, or rotate the existing credential."
            )
        } else {
            "The configuration it referred to changed after it was proposed; ask the agent to \
             re-propose from the current state."
                .to_string()
        })
    } else {
        Value::Null
    };
    json!({"headline": headline, "tools": tools, "unchanged": unchanged, "stale": stale})
}

const PROPOSAL_FIELDS: [&str; 12] =
    ["id", "name", "spec", "actor", "kind", "status", "created_at", "decided_by", "decided_at", "reason", "current", "spec_yaml"];

/// Each proposal plus the live toolkit it would replace or extend.
pub fn toolkit_proposals_view(
    service: &Service,
    proposals: Option<&ToolkitProposalStore>,
    status: Option<&str>,
) -> ConfigResult<Vec<Value>> {
    let Some(proposals) = proposals else {
        return Ok(Vec::new());
    };
    let tier1 = service.tier1();
    Ok(proposals
        .list(status)?
        .iter()
        .map(|item| {
            let mut spec = item.to_spec();
            spec["current"] = match tier1.toolkits.get(&item.name) {
                Some(live) => toolkit_summary(&item.name, live),
                None => Value::Null,
            };
            spec["spec_yaml"] = Value::String(match item.kind.as_str() {
                "delete" | "bind" => String::new(),
                "update" => crate::yaml::dump(&Value::Object(item.spec.clone())),
                _ => {
                    let mut wrapped = Map::new();
                    wrapped.insert(item.name.clone(), Value::Object(item.spec.clone()));
                    crate::yaml::dump(&Value::Object(wrapped))
                }
            });
            project(&spec, &PROPOSAL_FIELDS)
        })
        .collect())
}

// -- Audit ------------------------------------------------------------------------------

pub fn encode_cursor(offset: usize) -> String {
    b64_nopad(&crate::pyjson::dumps(&json!({ "o": offset })))
}

/// Opaque to clients; `None` on anything this did not issue.
pub fn decode_cursor(cursor: Option<&str>) -> Option<usize> {
    let Some(cursor) = cursor.filter(|c| !c.is_empty()) else {
        return Some(0);
    };
    let raw = b64_padded_decode(cursor)?;
    let text = String::from_utf8(raw).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    match data.get("o")? {
        Value::Number(n) if n.is_u64() => usize::try_from(n.as_u64()?).ok(),
        _ => None,
    }
}

/// A page of the audit log, newest first, filtered. `None` for a bad
/// cursor (a 400).
pub fn audit_page(service: &Service, limit: usize, cursor: Option<&str>, filter: &AuditFilter) -> Option<Value> {
    let offset = decode_cursor(cursor)?;
    let (records, truncated) = read_audit(&audit_path(service), offset.saturating_add(limit).saturating_add(1), filter);
    let page: Vec<Value> = records.iter().skip(offset).take(limit).cloned().collect();
    let more = records.len() > offset + limit;
    Some(json!({
        "entries": page,
        "next_cursor": if more { Value::String(encode_cursor(offset + limit)) } else { Value::Null },
        "window_truncated": truncated && !more,
    }))
}

/// Copy-pasteable Tier 1 YAML per executor (FR-4.11: nothing writes it).
pub fn toolkit_reference_view() -> Vec<Value> {
    crate::toolkit_reference::view()
}

// -- Shared by the write paths --------------------------------------------------------

/// Scaffold for a new definition, built from the first configured toolkit.
/// Callers check that a toolkit exists.
pub fn tool_scaffold(service: &Service) -> String {
    let tier1 = service.tier1();
    let (name, toolkit) = sorted_toolkits(&tier1)[0];
    let binary = toolkit.binaries.first().cloned().unwrap_or_default();
    let mut lines: Vec<String> = vec![
        format!("id: {name}.CHANGEME"),
        format!("toolkit: {name}"),
        format!("binary: {binary}"),
        "version: 1".into(),
        "title: CHANGEME".into(),
        "description: What this does, in one sentence for the agent.".into(),
        "category: read            # read | write | write_external".into(),
        "idempotent: true".into(),
        "enabled: true".into(),
        String::new(),
        "# Every element becomes exactly one argument. A parameter value can".into(),
        "# never produce a second one (FR-5.4).".into(),
        "argv: [\"--help\"]".into(),
        String::new(),
        "# Every string parameter needs a pattern -- unvalidated free text is".into(),
        "# not permitted (FR-5.7). Paths are derived by the server, never".into(),
        "# supplied by the agent.".into(),
        "parameters: {}".into(),
        String::new(),
        "required_scopes: []".into(),
        format!("timeout_seconds: {}", toolkit.max_timeout_seconds.min(30)),
        format!("max_output_bytes: {}", toolkit.max_output_bytes.min(65536)),
    ];
    if !toolkit.path_roots.is_empty() {
        let at = lines.len() - 3;
        lines.insert(at, format!("# This toolkit allows derived paths under: {}", toolkit.path_roots.join(", ")));
    }
    format!("{}\n", lines.join("\n"))
}

/// Runs the credential's probe in the background. Detection only: a
/// failure never rolls back the write that triggered it.
pub fn schedule_credential_probe(credentials: Arc<CredentialStore>, name: String) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = credentials.probe_credential(&name).await;
        });
    }
}

/// Which console sessions survive an identity edit. Renamed, or moved to a
/// role without console access: every session of the old identity ends. A
/// new password ends them too -- except the editor's own session when they
/// set their own password.
pub fn drop_sessions_after_identity_update(
    sessions: &SessionStore,
    replaces: &str,
    new_id: &str,
    role: &str,
    password_set: bool,
    actor: &str,
    current_sid: Option<&str>,
) {
    let locked_out = new_id != replaces || !UI_ROLES.contains(&role);
    if locked_out || password_set {
        let keep = if !locked_out && replaces == actor { current_sid } else { None };
        sessions.drop_identity(replaces, keep);
    }
}

// -- Stats and docs ------------------------------------------------------------------

const ADMIN_VERBS: [(&str, &str); 10] = [
    ("tool_create", "created tool"),
    ("tool_update", "updated tool"),
    ("tool_delete", "deleted tool"),
    ("tool_enable", "enabled tool"),
    ("tool_disable", "disabled tool"),
    ("identity_create", "created identity"),
    ("identity_update", "updated identity"),
    ("identity_delete", "deleted identity"),
    ("token_rotate", "rotated the API token of"),
    ("password_set", "set the console password of"),
];

/// Counts `admin_change` records by action label, most frequent first.
pub fn admin_action_stats(records: &[Value]) -> Vec<(String, i64)> {
    let mut stats: IndexMap<String, i64> = IndexMap::new();
    for record in records {
        if record.get("kind").and_then(Value::as_str) != Some("admin_change") {
            continue;
        }
        let action = record.get("action").map(str_value).unwrap_or_default();
        let label = match ADMIN_VERBS.iter().find(|(k, _)| *k == action) {
            Some((_, verb)) => verb.to_string(),
            None if !action.is_empty() => action,
            None => "admin_change".to_string(),
        };
        *stats.entry(label).or_default() += 1;
    }
    let mut out: Vec<(String, i64)> = stats.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// Average and p95 duration of one group of calls.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Durations {
    pub avg: f64,
    pub p95: f64,
    pub count: f64,
}

/// `int(dur)` for a logged duration; `None` where Python's `int()` fails.
fn py_int(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i64)),
        Value::String(s) => parse_py_int_text(s),
        _ => None,
    }
}

fn parse_py_int_text(s: &str) -> Option<i64> {
    let t = s.trim().replace('_', "");
    let digits = t.strip_prefix(['+', '-']).unwrap_or(&t);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

fn pct_of(values: &[i64], pct: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut s = values.to_vec();
    s.sort();
    let idx = ((s.len() as f64 * pct) as i64 - 1).clamp(0, s.len() as i64 - 1);
    s[idx as usize] as f64
}

/// Average and p95 duration per toolkit, plus `_overall`.
pub fn duration_stats(
    records: &[Value],
    tools_by_kit: Option<&IndexMap<String, BTreeSet<String>>>,
) -> IndexMap<String, Durations> {
    let lookup = tools_by_kit.map(tool_to_kit).unwrap_or_default();
    let mut per_kit: IndexMap<String, Vec<i64>> = IndexMap::new();
    let mut all: Vec<i64> = Vec::new();
    for record in records.iter().filter(|r| is_call(r)) {
        let Some(dur) = record.get("duration_ms").filter(|v| !v.is_null()).and_then(py_int) else {
            continue;
        };
        all.push(dur);
        let kit = lookup.get(&key_or_empty(record, "tool")).cloned().unwrap_or_else(|| "_unknown".into());
        per_kit.entry(kit).or_default().push(dur);
    }
    let summarize = |values: &[i64]| Durations {
        avg: if values.is_empty() { 0.0 } else { values.iter().sum::<i64>() as f64 / values.len() as f64 },
        p95: pct_of(values, 0.95),
        count: values.len() as f64,
    };
    let mut result: IndexMap<String, Durations> = per_kit.iter().map(|(k, v)| (k.clone(), summarize(v))).collect();
    result.insert("_overall".into(), summarize(&all));
    result
}

const STATS_WINDOWS: [(&str, &str, i64); 3] =
    [("24h", "Last 24 hours", 24), ("7d", "Last 7 days", 7), ("30d", "Last 30 days", 30)];

/// Not a sample size: stats read their whole time window.
const STATS_MAX_RECORDS: usize = 1_000_000;

fn stats_row(name: &str, c: &Counts) -> Value {
    json!({"ok": c.ok, "denied": c.denied, "failed": c.failed, "total": c.total, "name": name})
}

fn stats_rows(stats: &IndexMap<String, Counts>) -> Vec<Value> {
    let mut rows: Vec<(&String, &Counts)> = stats.iter().filter(|(_, c)| c.total > 0).collect();
    rows.sort_by(|a, b| b.1.total.cmp(&a.1.total).then_with(|| a.0.cmp(b.0)));
    rows.into_iter().map(|(n, c)| stats_row(n, c)).collect()
}

/// The Stats page as data: tiles, an activity series (hourly for 24 h,
/// daily otherwise), and per-toolkit, per-identity, latency and admin
/// tables.
pub fn stats_view(service: &Service, window: &str) -> Value {
    let (key, label, span) = STATS_WINDOWS.iter().copied().find(|w| w.0 == window).unwrap_or(STATS_WINDOWS[0]);
    let now = local_now();
    let start = if key == "24h" {
        floor_hour(now) - TimeDelta::hours(span - 1)
    } else {
        floor_day(now) - TimeDelta::days(span - 1)
    };
    let filter = AuditFilter { since: Some(start), ..Default::default() };
    let (records, truncated) = read_audit(&audit_path(service), STATS_MAX_RECORDS, &filter);
    let by_kit = tools_by_kit(service);
    let totals = outcome_totals(&records);
    let idents = call_stats(&records);
    let kits = tool_call_stats(&records, &by_kit);
    let admin = admin_action_stats(&records);
    let durations = duration_stats(&records, Some(&by_kit));
    let series: Vec<Value> = if key == "24h" {
        let hour = floor_hour(local_now());
        bucket_calls(&records, span as usize, None)
            .iter()
            .enumerate()
            .map(|(i, (ok, bad))| {
                json!({"start": isoformat(hour - TimeDelta::hours(span - 1 - i as i64)), "ok": ok, "not_ok": bad})
            })
            .collect()
    } else {
        let today = floor_day(local_now());
        bucket_calls_by_day(&records, span as usize, None)
            .iter()
            .enumerate()
            .map(|(i, (ok, bad))| {
                json!({"start": isoformat(today - TimeDelta::days(span - 1 - i as i64)), "ok": ok, "not_ok": bad})
            })
            .collect()
    };
    let mut latency: Vec<(&String, &Durations)> = durations.iter().filter(|(_, d)| d.count > 0.0).collect();
    latency.sort_by(|a, b| b.1.count.partial_cmp(&a.1.count).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.0.cmp(b.0)));
    json!({
        "window": key,
        "label": label,
        "windows": STATS_WINDOWS.iter().map(|w| json!({"key": w.0, "label": w.1})).collect::<Vec<_>>(),
        "truncated": truncated,
        "totals": {
            "ok": totals.ok, "denied": totals.denied, "failed": totals.failed,
            "total": totals.total, "error_rate": totals.error_rate,
        },
        "success_rate": pct(totals.ok, totals.total),
        "active_identities": idents.len(),
        "active_toolkits": kits.iter().filter(|(k, v)| v.total > 0 && k.as_str() != "_unknown").count(),
        "admin_total": admin.iter().map(|(_, n)| n).sum::<i64>(),
        "series": series,
        "toolkits": stats_rows(&kits),
        "identities": stats_rows(&idents),
        "admin": admin.iter().map(|(a, n)| json!({"action": a, "count": n})).collect::<Vec<_>>(),
        "latency": latency.iter().map(|(kit, d)| json!({
            "toolkit": kit, "avg_ms": d.avg as i64, "p95_ms": d.p95 as i64, "count": d.count as i64,
        })).collect::<Vec<_>>(),
    })
}

/// Where the bundled documents are looked for, in order.
///
/// PORT NOTE: Python's second candidate was the repository root relative
/// to the package directory; the Rust binary records the checkout it was
/// built from (`CARGO_MANIFEST_DIR/..`) instead.
fn docs_dir_candidates() -> [&'static str; 4] {
    ["/opt/gatekeeper-docs", concat!(env!("CARGO_MANIFEST_DIR"), "/.."), "/opt/data/gatekeeper", "."]
}

/// A doc file from the first candidate directory that has it; "" if none.
fn read_doc_file(name: &str) -> String {
    for base in docs_dir_candidates() {
        if let Ok(text) = std::fs::read_to_string(format!("{base}/{name}")) {
            return text;
        }
    }
    String::new()
}

const DOC_FILES: [(&str, &str, &str); 4] = [
    ("readme", "README", "README.md"),
    ("requirements", "Requirements", "REQUIREMENTS.md"),
    ("agents", "AGENTS", "AGENTS.md"),
    ("release", "Release Notes", "RELEASE.md"),
];

pub fn docs_index() -> Vec<Value> {
    DOC_FILES
        .iter()
        .map(|(slug, label, file)| json!({"slug": slug, "label": label, "available": !read_doc_file(file).is_empty()}))
        .collect()
}

/// One bundled document as Markdown source. The slug picks from a fixed
/// list, so no path from a request ever reaches the filesystem.
pub fn doc_text(slug: &str) -> Option<Value> {
    DOC_FILES
        .iter()
        .find(|(known, _, _)| *known == slug)
        .map(|(slug, label, file)| json!({"slug": slug, "label": label, "text": read_doc_file(file)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_lines(path: &std::path::Path, lines: &[Value]) {
        let text: String = lines.iter().map(|l| format!("{}\n", crate::pyjson::dumps(l))).collect();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn read_audit_filters_and_orders() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let lines: Vec<Value> = (0..5)
            .map(|i| {
                json!({"ts": format!("t{i}"), "kind": "call", "identity": if i % 2 == 1 { "a" } else { "b" },
                       "tool": "demo.show", "outcome": "ok"})
            })
            .collect();
        write_lines(&path, &lines);
        let filter = AuditFilter { identity: "a".into(), ..Default::default() };
        let (records, truncated) = read_audit(path.to_str().unwrap(), AUDIT_DEFAULT_LIMIT, &filter);
        assert!(!truncated);
        let ts: Vec<&str> = records.iter().map(|r| r["ts"].as_str().unwrap()).collect();
        assert_eq!(ts, ["t3", "t1"]); // most recent first
    }

    #[test]
    fn read_audit_survives_broken_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "{\"kind\": \"call\"}\nnot json\n\n").unwrap();
        let (records, _) = read_audit(path.to_str().unwrap(), AUDIT_DEFAULT_LIMIT, &AuditFilter::default());
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn read_audit_missing_file() {
        assert_eq!(
            read_audit("/does/not/exist/audit.jsonl", AUDIT_DEFAULT_LIMIT, &AuditFilter::default()),
            (Vec::new(), false)
        );
    }

    #[test]
    fn read_audit_limit_sets_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let lines: Vec<Value> = (0..5).map(|i| json!({"ts": format!("t{i}")})).collect();
        write_lines(&path, &lines);
        let (records, truncated) = read_audit(path.to_str().unwrap(), 2, &AuditFilter::default());
        assert!(truncated);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["ts"], "t4");
    }

    #[test]
    fn read_audit_keeps_records_across_chunk_boundaries() {
        // Enough bytes for several chunks: no record may vanish at a seam.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let pad = "x".repeat(200);
        let lines: Vec<Value> = (0..3000).map(|i| json!({"n": i, "pad": pad})).collect();
        write_lines(&path, &lines);
        let (records, truncated) = read_audit(path.to_str().unwrap(), 3000, &AuditFilter::default());
        assert!(!truncated);
        assert_eq!(records.len(), 3000);
        for (k, r) in records.iter().enumerate() {
            assert_eq!(r["n"], json!(2999 - k));
        }
    }

    #[test]
    fn read_audit_since_stops_the_walk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_lines(
            &path,
            &[
                json!({"ts": "2026-01-01T00:00:00+0000", "n": 1}),
                json!({"ts": "2026-01-03T00:00:00+0000", "n": 2}),
                json!({"ts": "2026-01-05T00:00:00+0000", "n": 3}),
            ],
        );
        let since = DateTime::parse_from_str("2026-01-02T00:00:00+0000", "%Y-%m-%dT%H:%M:%S%z").unwrap();
        let filter = AuditFilter { since: Some(since), ..Default::default() };
        let (records, truncated) = read_audit(path.to_str().unwrap(), 10, &filter);
        assert!(!truncated);
        assert_eq!(records.iter().map(|r| r["n"].as_i64().unwrap()).collect::<Vec<_>>(), [3, 2]);
    }
}
