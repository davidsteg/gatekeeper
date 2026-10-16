//! Console read model behind the JSON API (port of `api/service.py`).
//!
//! The functions here turn the live stores into plain, JSON-serialisable
//! structures. `admin_service` reuses some of them for the `admin.*` read
//! actions, so the console and `/admin/mcp` compute the same numbers.
//!
//! PORT NOTE: only what `admin_service` needs is ported so far
//! (`read_audit`, `toolkit_summaries`, `credential_summaries` and their
//! helpers); the rest of the read model lands with the console API.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use chrono::{DateTime, FixedOffset};
use serde_json::{json, Value};

use crate::credentials::CredentialStore;
use crate::errors::ConfigResult;
use crate::tier1::{Destination, Tier1, Toolkit};

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
