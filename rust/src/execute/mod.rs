//! Executors (port of `execute.py` and the `execute_*.py` modules).
//!
//! Each executor is one submodule exposing `pub async fn run(...)` with the
//! parameters of its Python counterpart and, where Python has one,
//! `pub async fn probe(toolkit: &Toolkit) -> bool` for `/health/ready`.
//! This file holds what they share: the result type, the outcome states
//! and the per-resource locks.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

pub mod agent;
pub mod artifact;
pub mod file;
pub mod git;
pub mod google;
pub mod http;
pub mod kuma;
pub mod local;
pub mod microsoft;
pub mod opencode;
pub mod ssh;
pub mod truenas;

/// Outcome states. `unknown` is the important one: on timeout it is
/// undecided whether the operation completed on the other side (FR-6.9).
pub const OUTCOME_OK: &str = "ok";
pub const OUTCOME_FAILED: &str = "failed";
pub const OUTCOME_UNKNOWN: &str = "unknown";

/// What an executor reports back (Python's `execute.Result`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub outcome: String,
    pub exit_code: Option<i64>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub duration_ms: i64,
    /// FR-8.12: set by the `http`/`truenas` executors. Marks `stdout` as
    /// data from outside gatekeeper's own logs -- it can contain prompt
    /// injection, and the agent-facing rendering must say so.
    pub external_untrusted: bool,
    /// Set when an executor refused the call itself, after
    /// `Service::call` had already validated it -- an SSRF block, a
    /// missing credential. The `DenialReason` value and its detail go into
    /// the audit record's `denial_reason`/`detail`, so a refused target
    /// says why there rather than only as a "failed" outcome. Never a
    /// credential value: details name hosts, addresses and credential
    /// names only.
    pub denial_reason: Option<String>,
    pub denial_detail: Option<String>,
    /// The files an `http` body read (1.21.0): path and size, for the
    /// audit record. Never their content.
    pub body_files: Vec<(String, u64)>,
    /// Set from the toolkit's `structured_content` (1.25.0): the MCP
    /// result also carries the outcome as `structuredContent`.
    pub structured: bool,
}

impl ExecResult {
    pub fn new(
        outcome: &str,
        exit_code: Option<i64>,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
        truncated: bool,
        duration_ms: i64,
    ) -> Self {
        ExecResult {
            outcome: outcome.to_string(),
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
            truncated,
            duration_ms,
            external_untrusted: false,
            denial_reason: None,
            denial_detail: None,
            body_files: Vec::new(),
            structured: false,
        }
    }

    /// A refusal by the executor itself (Python's `_denied` helpers): the
    /// agent sees the denial's message, the audit record its reason and
    /// detail.
    pub fn denied(denial: &crate::errors::Denied, duration_ms: i64) -> Self {
        let mut result = ExecResult::new(OUTCOME_FAILED, None, "", denial.agent_message(), false, duration_ms);
        result.denial_reason = Some(denial.reason.as_str().to_string());
        result.denial_detail = Some(denial.detail.clone());
        result
    }

    pub fn untrusted(mut self, external_untrusted: bool) -> Self {
        self.external_untrusted = external_untrusted;
        self
    }

    pub fn read_files(mut self, body_files: Vec<(String, u64)>) -> Self {
        self.body_files = body_files;
        self
    }
}

/// `AuditLog.redact`, handed to executors so error text never carries a
/// credential value.
pub type Redact = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// A redactor that changes nothing (tests, callers without credentials).
pub fn no_redact() -> Redact {
    Arc::new(|s: &str| s.to_string())
}

/// Serializes calls per resource (FR-6.7). Two concurrent `compose up -d`
/// on the same stack must not overlap.
#[derive(Default)]
pub struct ResourceLocks {
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl ResourceLocks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().entry(key.to_string()).or_default().clone()
    }
}

/// Milliseconds elapsed since `started`, as Python's
/// `int((time.monotonic() - started) * 1000)`.
pub fn elapsed_ms(started: std::time::Instant) -> i64 {
    started.elapsed().as_millis() as i64
}
