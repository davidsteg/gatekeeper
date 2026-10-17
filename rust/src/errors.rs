//! Error types (port of `errors.py`).
//!
//! The separation is deliberate: [`DenialReason`] is what goes into the
//! audit log (FR-9.2), [`Denied::agent_message`] is what the agent sees. Per
//! FR-7.7 a missing permission and a non-existent tool must be
//! indistinguishable to the agent, otherwise `tools/call` becomes a catalog
//! oracle.

use std::fmt;
use std::path::Path;

/// Internal denial reason -- complete, for the audit log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenialReason {
    UnknownToken,
    UnknownTool,
    ToolDisabled,
    NotGranted,
    ScopeMismatch,
    ProtectedResource,
    ParamInvalid,
    ParamUnknown,
    ParamMissing,
    ParamDerivedSupplied,
    ControlCharacter,
    PathEscape,
    Tier1Violation,
    RateLimited,
    Timeout,
    ExecutorUnavailable,
    SsrfBlocked,
    /// The three ways an http/opencode target can be refused (1.10.0; kuma
    /// since 1.12.0) --
    /// one reason each, so the audit log says which rule stopped a call.
    HostNotAllowed,
    AddressNotPublic,
    CidrNotAllowed,
    RpcMethodDenied,
    CredentialUnavailable,
}

impl DenialReason {
    pub const ALL: [DenialReason; 22] = [
        DenialReason::UnknownToken,
        DenialReason::UnknownTool,
        DenialReason::ToolDisabled,
        DenialReason::NotGranted,
        DenialReason::ScopeMismatch,
        DenialReason::ProtectedResource,
        DenialReason::ParamInvalid,
        DenialReason::ParamUnknown,
        DenialReason::ParamMissing,
        DenialReason::ParamDerivedSupplied,
        DenialReason::ControlCharacter,
        DenialReason::PathEscape,
        DenialReason::Tier1Violation,
        DenialReason::RateLimited,
        DenialReason::Timeout,
        DenialReason::ExecutorUnavailable,
        DenialReason::SsrfBlocked,
        DenialReason::HostNotAllowed,
        DenialReason::AddressNotPublic,
        DenialReason::CidrNotAllowed,
        DenialReason::RpcMethodDenied,
        DenialReason::CredentialUnavailable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DenialReason::UnknownToken => "unknown_token",
            DenialReason::UnknownTool => "unknown_tool",
            DenialReason::ToolDisabled => "tool_disabled",
            DenialReason::NotGranted => "not_granted",
            DenialReason::ScopeMismatch => "scope_mismatch",
            DenialReason::ProtectedResource => "protected_resource",
            DenialReason::ParamInvalid => "param_invalid",
            DenialReason::ParamUnknown => "param_unknown",
            DenialReason::ParamMissing => "param_missing",
            DenialReason::ParamDerivedSupplied => "param_derived_supplied",
            DenialReason::ControlCharacter => "control_character",
            DenialReason::PathEscape => "path_escape",
            DenialReason::Tier1Violation => "tier1_violation",
            DenialReason::RateLimited => "rate_limited",
            DenialReason::Timeout => "timeout",
            DenialReason::ExecutorUnavailable => "executor_unavailable",
            DenialReason::SsrfBlocked => "ssrf_blocked",
            DenialReason::HostNotAllowed => "host_not_allowed",
            DenialReason::AddressNotPublic => "address_not_public",
            DenialReason::CidrNotAllowed => "cidr_not_allowed",
            DenialReason::RpcMethodDenied => "rpc_method_denied",
            DenialReason::CredentialUnavailable => "credential_unavailable",
        }
    }

    pub fn parse(value: &str) -> Option<DenialReason> {
        DenialReason::ALL.iter().copied().find(|r| r.as_str() == value)
    }

    fn is_opaque(self) -> bool {
        matches!(
            self,
            DenialReason::UnknownTool
                | DenialReason::ToolDisabled
                | DenialReason::NotGranted
                | DenialReason::ScopeMismatch
                | DenialReason::ProtectedResource
        )
    }
}

impl fmt::Display for DenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Uniform response for everything the agent should not know (FR-7.7).
/// Unknown tool and missing permission yield exactly this text.
pub const OPAQUE_DENIAL: &str = "Unknown tool, or not available.";

/// A call was denied. `reason` and `detail` go into the audit log,
/// [`Denied::agent_message`] to the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    pub reason: DenialReason,
    pub detail: String,
}

impl Denied {
    pub fn new(reason: DenialReason, detail: impl Into<String>) -> Self {
        Denied { reason, detail: detail.into() }
    }

    pub fn bare(reason: DenialReason) -> Self {
        Denied { reason, detail: String::new() }
    }

    /// What the agent sees -- deliberately uninformative for catalog
    /// information.
    pub fn agent_message(&self) -> String {
        if self.reason.is_opaque() {
            return OPAQUE_DENIAL.to_string();
        }
        if self.reason == DenialReason::RateLimited {
            return "Rate limit reached. Try again later.".to_string();
        }
        if self.reason == DenialReason::Timeout {
            return if self.detail.is_empty() { "Timed out.".into() } else { self.detail.clone() };
        }
        // Validation errors may be specific: they reveal nothing about the
        // catalog, only about the values sent by the agent itself.
        if self.detail.is_empty() {
            "Call denied.".into()
        } else {
            self.detail.clone()
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            f.write_str(self.reason.as_str())
        } else {
            write!(f, "{}: {}", self.reason.as_str(), self.detail)
        }
    }
}

impl std::error::Error for Denied {}

/// Which subclass of Python's `ConfigError` an error corresponds to. Code
/// that caught `ConfigError` catches every kind; code that caught a
/// subclass checks the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorKind {
    /// Plain `ConfigError`: configuration is invalid.
    Config,
    /// `Tier1Violation`: a tool definition violates the deploy-time limits.
    Tier1Violation,
    /// `store.WriteRefused` (and `pending`/`toolkit_proposals` refusals).
    WriteRefused,
    /// `credentials.WriteRefused`.
    CredentialWriteRefused,
    /// `admin_service.AdminActionError`.
    AdminAction,
}

/// Configuration is invalid, or a write was refused -- always with a
/// human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub kind: ConfigErrorKind,
    pub message: String,
}

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        ConfigError { kind: ConfigErrorKind::Config, message: message.into() }
    }
    pub fn tier1(message: impl Into<String>) -> Self {
        ConfigError { kind: ConfigErrorKind::Tier1Violation, message: message.into() }
    }
    pub fn refused(message: impl Into<String>) -> Self {
        ConfigError { kind: ConfigErrorKind::WriteRefused, message: message.into() }
    }
    pub fn credential_refused(message: impl Into<String>) -> Self {
        ConfigError { kind: ConfigErrorKind::CredentialWriteRefused, message: message.into() }
    }
    pub fn admin(message: impl Into<String>) -> Self {
        ConfigError { kind: ConfigErrorKind::AdminAction, message: message.into() }
    }
    pub fn is_tier1_violation(&self) -> bool {
        self.kind == ConfigErrorKind::Tier1Violation
    }
    pub fn is_write_refused(&self) -> bool {
        matches!(self.kind, ConfigErrorKind::WriteRefused | ConfigErrorKind::CredentialWriteRefused)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

pub type ConfigResult<T> = Result<T, ConfigError>;

/// Shorthand: `Err(ConfigError::new(format!(...)))`.
#[macro_export]
macro_rules! config_err {
    ($($arg:tt)*) => { $crate::errors::ConfigError::new(format!($($arg)*)) };
}

/// Shorthand for a store-level `WriteRefused`.
#[macro_export]
macro_rules! refused {
    ($($arg:tt)*) => { $crate::errors::ConfigError::refused(format!($($arg)*)) };
}

/// uid:gid of this process, for a chown recommendation that is correct.
pub fn whoami() -> String {
    // SAFETY: geteuid/getegid have no preconditions.
    unsafe { format!("{}:{}", libc::geteuid(), libc::getegid()) }
}

/// Reads a configuration file and translates OS errors into plain text
/// (port of `read_config_file`).
pub fn read_config_file(path: &str, hint: &str) -> ConfigResult<String> {
    if Path::new(path).is_dir() {
        return Err(ConfigError::new(format!(
            "{path} is a directory, not a file. Docker creates a directory \
             when a bind-mounted file does not exist on the host. Remove it \
             on the host, mount the containing directory instead of the \
             single file, and create the file before starting.{}",
            if hint.is_empty() { String::new() } else { format!(" {hint}") }
        )));
    }
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|exc| ConfigError::new(format!("{path} cannot be read: {exc}"))),
        Err(exc) if exc.kind() == std::io::ErrorKind::PermissionDenied => {
            let parent = Path::new(path)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| path.to_string());
            Err(ConfigError::new(format!(
                "{path} cannot be read by this process ({who}). \
                 Check the owner and mode of the file and of every directory \
                 above it -- a denial naming the file is often a parent \
                 directory without +x for that uid. Files created while the \
                 container ran as root stay root-owned, so this is the usual \
                 first failure after switching a deployment to a lesser user \
                 (GATEKEEPER_DROP_TO, or 'user:'). On the host:\n  chown -R {who} <the directory mounted at {parent}>{hint}",
                who = whoami(),
                hint = if hint.is_empty() { String::new() } else { format!("\n{hint}") }
            )))
        }
        Err(exc) => Err(ConfigError::new(format!("{path} cannot be read: {}", crate::pyfmt::os_error(&exc, path)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_reasons_share_one_message() {
        for reason in [
            DenialReason::UnknownTool,
            DenialReason::ToolDisabled,
            DenialReason::NotGranted,
            DenialReason::ScopeMismatch,
            DenialReason::ProtectedResource,
        ] {
            assert_eq!(Denied::new(reason, "secret detail").agent_message(), OPAQUE_DENIAL);
        }
        assert_eq!(
            Denied::new(DenialReason::RateLimited, "x").agent_message(),
            "Rate limit reached. Try again later."
        );
        assert_eq!(Denied::bare(DenialReason::Timeout).agent_message(), "Timed out.");
        assert_eq!(Denied::bare(DenialReason::ParamInvalid).agent_message(), "Call denied.");
        assert_eq!(Denied::new(DenialReason::ParamInvalid, "bad").agent_message(), "bad");
    }

    #[test]
    fn directory_is_reported_plainly() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_config_file(dir.path().to_str().unwrap(), "").unwrap_err();
        assert!(err.message.contains("is a directory, not a file"));
    }
}
