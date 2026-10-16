//! Placeholder: ported in a later step.
//!
//! PORT NOTE: stub signatures only, so `service` compiles in this
//! worktree. The lead replaces this file with the real port of
//! `execute_http.py` at merge and reconciles the signatures with the call
//! site in `service::Service::call`.

use indexmap::IndexMap;
use serde_json::Value;

use super::{ExecResult, Redact, OUTCOME_FAILED};
use crate::credentials::CredentialStore;
use crate::errors::ConfigError;
use crate::tier1::Toolkit;

/// `execute_http.run(method=, path=, query=, body=, raw_param=, toolkit=,
/// credentials=, timeout_seconds=, max_output_bytes=, idempotent=, redact=)`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    _method: &str,
    _path: &str,
    _query: &IndexMap<String, String>,
    _body: Option<&Value>,
    _raw_param: Option<&str>,
    _toolkit: &Toolkit,
    _credentials: Option<&CredentialStore>,
    _timeout_seconds: f64,
    _max_output_bytes: i64,
    _idempotent: bool,
    _redact: Option<&Redact>,
) -> Result<ExecResult, ConfigError> {
    Ok(ExecResult::new(OUTCOME_FAILED, None, "", "http executor not ported yet", false, 0))
}

/// `execute_http.probe(toolkit)`.
pub async fn probe(_toolkit: &Toolkit) -> bool {
    false
}
