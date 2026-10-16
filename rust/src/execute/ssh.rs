//! Placeholder: ported in a later step.
//!
//! PORT NOTE: stub signatures only, so `service` compiles in this
//! worktree. The lead replaces this file with the real port of
//! `execute_ssh.py` at merge and reconciles the signatures with the call
//! site in `service::Service::call`.

use super::{ExecResult, Redact, OUTCOME_FAILED};
use crate::catalog::ToolDef;
use crate::credentials::CredentialStore;
use crate::errors::ConfigError;
use crate::tier1::Toolkit;

/// `execute_ssh.run(argv, toolkit=, credentials=, timeout_seconds=,
/// max_output_bytes=, idempotent=, redact=, tool=)`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    _argv: &[String],
    _toolkit: &Toolkit,
    _credentials: Option<&CredentialStore>,
    _timeout_seconds: f64,
    _max_output_bytes: i64,
    _idempotent: bool,
    _redact: Option<&Redact>,
    _tool: Option<&ToolDef>,
) -> Result<ExecResult, ConfigError> {
    Ok(ExecResult::new(OUTCOME_FAILED, None, "", "ssh executor not ported yet", false, 0))
}

/// `execute_ssh.probe(toolkit)`.
pub async fn probe(_toolkit: &Toolkit) -> bool {
    false
}
