//! Placeholder: ported in a later step.
//!
//! PORT NOTE: stub signatures only, so `service` compiles in this
//! worktree. The lead replaces this file with the real port of
//! `execute_truenas.py` at merge and reconciles the signatures with the
//! call site in `service::Service::call`.

use indexmap::IndexMap;

use super::{ExecResult, Redact, OUTCOME_FAILED};
use crate::credentials::CredentialStore;
use crate::errors::ConfigError;
use crate::tier1::Toolkit;

/// `execute_truenas.run(method=, params=, toolkit=, credentials=,
/// timeout_seconds=, max_output_bytes=, idempotent=, redact=)`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    _method: &str,
    _params: &IndexMap<String, String>,
    _toolkit: &Toolkit,
    _credentials: Option<&CredentialStore>,
    _timeout_seconds: f64,
    _max_output_bytes: i64,
    _idempotent: bool,
    _redact: Option<&Redact>,
) -> Result<ExecResult, ConfigError> {
    Ok(ExecResult::new(OUTCOME_FAILED, None, "", "truenas executor not ported yet", false, 0))
}

/// `execute_truenas.probe(toolkit)`.
pub async fn probe(_toolkit: &Toolkit) -> bool {
    false
}
