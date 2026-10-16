//! Tier 1 -- the immutable-at-runtime limits (port of `tier1.py`,
//! REQUIREMENTS.md §6).
//!
//! Everything here is read from `toolkits.yaml` at startup and never
//! touched again. The admin API can create tools, but no toolkit --
//! otherwise Tier 1 would be mutable at runtime and the whole design would
//! have no foundation (FR-4.11).
//!
//! Public API (Python name -> Rust):
//!
//! | Python | Rust |
//! |---|---|
//! | `Toolkit`, `Destination`, `RateLimit`, `Tier1` | same-named structs |
//! | `load_tier1(path)` | [`load_tier1`] |
//! | `Tier1.toolkit/destination` | [`Tier1::toolkit`], [`Tier1::destination`] |
//! | `Tier1.credential_references()` | [`Tier1::credential_references`] |
//! | `Tier1.missing_local_binaries()` | [`Tier1::missing_local_binaries`] |
//! | `is_runnable(path)` | [`is_runnable`] |
//! | `_validate_http_base_url` | [`validate_http_base_url`] |
//! | `missing_agent_operations` / `missing_google_script` / `missing_microsoft_script` | same names |
//! | `KNOWN_EXECUTORS`, `HTTP_METHODS`, ... | same-named consts (sorted slices) |
//!
//! The Python `frozenset` constants are sorted `&[&str]` slices here, so
//! `sorted(KNOWN_EXECUTORS)` in a message is simply the slice itself.
//!
//! The small helpers that reproduce Python's built-in conversions on a
//! YAML/JSON value (`int(x)`, `str(x)`, `bool(x)`) live at the bottom of
//! this module ([`py_int`], [`py_str`], [`py_truthy`], [`py_eq`]); the
//! catalog uses them too.

use std::net::IpAddr;

use indexmap::IndexMap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde_json::{Map, Value};

use crate::errors::{read_config_file, ConfigError, ConfigResult};
use crate::pyfmt::{repr_list, repr_str, repr_value};
use crate::runas::parse_run_as;

/// Executor types implemented (sorted, as `sorted(KNOWN_EXECUTORS)` prints).
pub const KNOWN_EXECUTORS: &[&str] = &[
    "agent", "artifact", "docker", "file", "google", "http", "local", "microsoft", "opencode",
    "ssh", "truenas",
];

/// FR-8.6: methods an `http` toolkit may allow at all. A toolkit may
/// narrow this further; it may never widen it.
pub const HTTP_METHODS: &[&str] = &["DELETE", "GET", "PATCH", "POST", "PUT"];

/// The complete vocabulary of the `opencode` executor -- a toolkit picks a
/// subset of these, it can never name an operation outside the set.
pub const OPENCODE_OPERATIONS: &[&str] =
    &["abort", "ask", "check", "fire", "health", "providers", "review_changes", "run"];

/// Where the image itself carries `google_api.py` (since 0.40.1). Lives
/// here so the startup warning and the executor's runtime fallback name
/// the same path.
pub const GOOGLE_FALLBACK_SCRIPT: &str = "/opt/gatekeeper/google/google_api.py";

/// The same arrangement for the `microsoft` executor's vendored script.
pub const MICROSOFT_FALLBACK_SCRIPT: &str = "/opt/gatekeeper/microsoft/microsoft_api.py";

/// The complete vocabulary of the `agent` executor (the mailbox behind
/// `messages`). `mailbox_status` is the read-only poll of that mailbox.
pub const AGENT_OPERATIONS: &[&str] = &["mailbox_status", "read_messages", "send_message"];

/// The `artifact` executor's vocabulary. `transfer` is the only one that
/// writes, and only into the toolkit's `handover_dir`.
pub const ARTIFACT_OPERATIONS: &[&str] = &["info", "list", "read", "transfer"];

/// Artifacts this image no longer builds (RELEASE.md 0.52.0).
pub const REMOVED_ARTIFACTS: &[&str] = &["hermes-adapter-contract", "hermes-recovery-adapter"];

/// What an operator with a leftover `recovery:` block is told.
pub const RECOVERY_MIGRATION: &str = "The recovery supervisor was removed from Gatekeeper in 0.52.0; Hermes \
orchestrates and recovers its own tasks. Delete the 'recovery:' block \
from toolkits.yaml -- see docs/DEPLOYMENT.md, 'Removed: recovery \
supervisor'. recovery.yaml and the credentials it named are no longer \
read and can be archived.";

/// Default ceiling on one `agent` message's subject + body, in bytes.
pub const DEFAULT_MAX_MESSAGE_BYTES: i64 = 4096;
/// Default ceiling on how many messages one recipient's mailbox holds.
pub const DEFAULT_MAILBOX_LIMIT: i64 = 200;

/// Toolkit-level defaults applied by [`load_tier1`].
pub const DEFAULT_MAX_TIMEOUT_SECONDS: i64 = 60;
pub const DEFAULT_MAX_OUTPUT_BYTES: i64 = 65536;
pub const DEFAULT_SSH_PORT: i64 = 22;
/// Rate-limit defaults (`count`, `window_seconds`) and the categories that
/// always get one.
pub const DEFAULT_RATE_LIMIT_COUNT: i64 = 60;
pub const DEFAULT_RATE_LIMIT_WINDOW: i64 = 60;
pub const DEFAULT_RATE_LIMIT_CATEGORIES: &[&str] = &["read", "write", "write_external"];
/// Top-level defaults.
pub const DEFAULT_MAX_CONCURRENT: i64 = 4;
pub const DEFAULT_AUDIT_DIR: &str = "/mnt/raid/gatekeeper/logs";
pub const DEFAULT_AUDIT_MAX_BYTES: i64 = 32 * 1024 * 1024;
pub const DEFAULT_AUDIT_KEEP_FILES: i64 = 10;

fn contains(set: &[&str], s: &str) -> bool {
    set.iter().any(|x| *x == s)
}

/// `sorted(set(values) - set(known))` as owned strings.
fn sorted_difference(values: &[String], known: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = values.iter().filter(|v| !contains(known, v)).cloned().collect();
    out.sort();
    out.dedup();
    out
}

/// A leftover `recovery:` block: refused when it still enables anything, a
/// warning when it is inert.
fn check_removed_recovery(block: &Value, where_: &str) -> ConfigResult<()> {
    fn enables(node: &Value) -> bool {
        match node {
            Value::Object(map) => {
                map.get("enabled") == Some(&Value::Bool(true)) || map.values().any(enables)
            }
            _ => false,
        }
    }
    if enables(block) {
        return Err(ConfigError::new(format!(
            "{where_}: 'recovery' enables a feature that no longer exists. {RECOVERY_MIGRATION}"
        )));
    }
    tracing::warn!("{}: the 'recovery:' block is ignored. {}", where_, RECOVERY_MIGRATION);
    Ok(())
}

/// Operations in the `agent` vocabulary that `toolkit` does not allow
/// (sorted). Empty for a non-`agent` toolkit or when nothing is missing.
pub fn missing_agent_operations(toolkit: &Toolkit) -> Vec<String> {
    if toolkit.executor != "agent" {
        return Vec::new();
    }
    AGENT_OPERATIONS
        .iter()
        .filter(|op| !toolkit.allowed_agent_operations.iter().any(|a| a == *op))
        .map(|s| s.to_string())
        .collect()
}

/// The `google_script` a `google` toolkit names and this filesystem does
/// not have -- `None` when there is nothing to report. `google_container`
/// toolkits are skipped (the script lives on another filesystem).
pub fn missing_google_script(toolkit: &Toolkit) -> Option<String> {
    if toolkit.executor != "google" || toolkit.google_container.as_deref().is_some_and(|c| !c.is_empty())
    {
        return None;
    }
    let script = toolkit.google_script.as_deref().unwrap_or("");
    if script.is_empty() || std::path::Path::new(script).is_file() {
        return None;
    }
    Some(script.to_string())
}

/// `missing_google_script` for the `microsoft` executor.
pub fn missing_microsoft_script(toolkit: &Toolkit) -> Option<String> {
    if toolkit.executor != "microsoft"
        || toolkit.microsoft_container.as_deref().is_some_and(|c| !c.is_empty())
    {
        return None;
    }
    let script = toolkit.microsoft_script.as_deref().unwrap_or("");
    if script.is_empty() || std::path::Path::new(script).is_file() {
        return None;
    }
    Some(script.to_string())
}

/// Carrier of the Tier 1 limits (FR-4.8).
///
/// Limits are attached to the toolkit, not globally: `diag.uptime` needs no
/// path root, `docker.compose_up` does (FR-4.9). Fields mirror the Python
/// dataclass one to one; a Python `tuple[str, ...]` is a `Vec<String>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolkit {
    pub name: String,
    pub executor: String,
    pub binaries: Vec<String>,
    pub denied_args: Vec<String>,
    pub path_roots: Vec<String>,
    pub protected_resources: Vec<String>,
    pub max_timeout_seconds: i64,
    pub max_output_bytes: i64,
    /// Name of a credential in the credential store, never a value. The
    /// *binding* is Tier 1 (FR-10.4).
    pub credential: Option<String>,

    // -- `http` executor only (FR-8.5 to FR-8.15) --
    /// Scheme and host live exclusively here (FR-8.5). May contain a single
    /// `{credential}` placeholder (resolved server-side only).
    pub base_url: Option<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
    /// Post-DNS-resolution IP/CIDR allowlist (FR-8.9).
    pub allowed_cidrs: Vec<String>,
    /// Exact hostnames this toolkit may connect to (1.10.0), for public
    /// services whose addresses are not a stable, published range.
    /// Lower-case, no trailing dot, never a wildcard and never an IP
    /// literal (that is what `allowed_cidrs` is for). When set, three
    /// checks apply on every connect, all of them required
    /// (`execute::http::resolve_and_check`): the URL's hostname is in this
    /// list; every address it resolves to is public ([`is_public_address`]);
    /// and, if `allowed_cidrs` is set as well, every address is also inside
    /// it -- CIDRs can only narrow a hostname toolkit, never reopen a
    /// private range for it. Empty (the default) keeps the pre-1.10.0
    /// behaviour exactly: `allowed_cidrs` alone decides.
    pub allowed_hosts: Vec<String>,

    // -- `truenas` executor only (FR-8.3a-f) --
    /// JSON-RPC 2.0 endpoint, e.g. `wss://truenas.lan/api/current`.
    pub ws_url: Option<String>,
    pub allowed_rpc_methods: Vec<String>,

    // -- Multi-destination (FR-8.3g-j) --
    /// Names into [`Tier1::destinations`]. Empty = single implicit target.
    pub destinations: Vec<String>,
    /// The docker executor's own explicit target. `None` falls back to the
    /// process-wide `DOCKER_HOST`.
    pub docker_host: Option<String>,
    pub docker_tls: bool,

    // -- `ssh` executor only --
    pub ssh_host: Option<String>,
    pub ssh_port: i64,
    pub ssh_user: Option<String>,
    /// `known_hosts`-format text pinning the accepted host key(s). Required.
    pub ssh_known_hosts: Option<String>,

    // -- `file` executor only --
    /// The OS user the file operations run as (`"hermes"` or `"uid:gid"`).
    /// Tier 1 only; rejected on any other executor.
    pub run_as: Option<String>,

    // -- `google` executor only --
    pub google_script: Option<String>,
    pub google_container: Option<String>,
    pub allowed_google_actions: Vec<String>,
    /// OAuth scopes the toolkit's actions need (google/microsoft only).
    pub required_scopes: Vec<String>,

    // -- `microsoft` executor only --
    pub microsoft_script: Option<String>,
    pub microsoft_container: Option<String>,
    pub allowed_microsoft_actions: Vec<String>,

    // -- `opencode` executor only --
    /// Subset of [`OPENCODE_OPERATIONS`].
    pub allowed_opencode_operations: Vec<String>,

    // -- `agent` executor only --
    /// Absolute path of the mailbox file. Deploy-time only.
    pub mailbox_path: Option<String>,
    /// Subset of [`AGENT_OPERATIONS`].
    pub allowed_agent_operations: Vec<String>,
    // -- `artifact` executor only --
    pub allowed_artifact_operations: Vec<String>,
    pub allowed_artifacts: Vec<String>,
    pub handover_dir: Option<String>,
    /// Ceiling on one message's subject + body, in bytes.
    pub max_message_bytes: i64,
    /// Ceiling on how many messages one recipient's mailbox holds.
    pub max_mailbox_messages: i64,
}

impl Default for Toolkit {
    /// The dataclass defaults; `name`/`executor` empty and the two
    /// ceilings at the [`load_tier1`] defaults. For tests and stand-ins.
    fn default() -> Self {
        Toolkit {
            name: String::new(),
            executor: String::new(),
            binaries: Vec::new(),
            denied_args: Vec::new(),
            path_roots: Vec::new(),
            protected_resources: Vec::new(),
            max_timeout_seconds: DEFAULT_MAX_TIMEOUT_SECONDS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            credential: None,
            base_url: None,
            allowed_methods: Vec::new(),
            allowed_path_prefixes: Vec::new(),
            allowed_cidrs: Vec::new(),
            allowed_hosts: Vec::new(),
            ws_url: None,
            allowed_rpc_methods: Vec::new(),
            destinations: Vec::new(),
            docker_host: None,
            docker_tls: false,
            ssh_host: None,
            ssh_port: DEFAULT_SSH_PORT,
            ssh_user: None,
            ssh_known_hosts: None,
            run_as: None,
            google_script: None,
            google_container: None,
            allowed_google_actions: Vec::new(),
            required_scopes: Vec::new(),
            microsoft_script: None,
            microsoft_container: None,
            allowed_microsoft_actions: Vec::new(),
            allowed_opencode_operations: Vec::new(),
            mailbox_path: None,
            allowed_agent_operations: Vec::new(),
            allowed_artifact_operations: Vec::new(),
            allowed_artifacts: Vec::new(),
            handover_dir: None,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_mailbox_messages: DEFAULT_MAILBOX_LIMIT,
        }
    }
}

impl Toolkit {
    /// FR-4.1: the executable must be exactly in the allowlist.
    pub fn check_binary(&self, binary: &str) -> ConfigResult<()> {
        if !self.binaries.iter().any(|b| b == binary) {
            return Err(ConfigError::new(format!(
                "Toolkit {}: binary {} is not in the allowlist {}",
                repr_str(&self.name),
                repr_str(binary),
                repr_list(&self.binaries)
            )));
        }
        Ok(())
    }

    /// FR-4.2: blocked subcommands and flags, on the *resolved* argv.
    /// Returns the first denied element.
    pub fn check_args<S: AsRef<str>>(&self, argv: &[S]) -> Option<String> {
        argv.iter()
            .map(|a| a.as_ref())
            .find(|a| self.denied_args.iter().any(|d| d == a))
            .map(|a| a.to_string())
    }

    /// A `must_resolve_under` must lie within the toolkit roots (FR-4.10:
    /// a tool may tighten the limits of its toolkit, never widen them).
    /// Lexical, `PurePosixPath` semantics.
    pub fn check_path_root(&self, root: &str) -> ConfigResult<()> {
        if self.path_roots.is_empty() {
            return Err(ConfigError::new(format!(
                "Toolkit {} declares no path_roots, but a tool requires {}",
                repr_str(&self.name),
                repr_str(root)
            )));
        }
        if self.path_roots.iter().any(|allowed| pure_posix_within(root, allowed)) {
            return Ok(());
        }
        Err(ConfigError::new(format!(
            "Toolkit {}: {} lies outside the path_roots {}",
            repr_str(&self.name),
            repr_str(root),
            repr_list(&self.path_roots)
        )))
    }

    /// FR-4.12: protected resources, independent of permissions and scopes.
    pub fn is_protected(&self, resource: &str) -> bool {
        self.protected_resources.iter().any(|r| r == resource)
    }

    /// FR-8.6: only allowlisted HTTP methods.
    pub fn allows_method(&self, method: &str) -> bool {
        self.allowed_methods.iter().any(|m| m == method)
    }

    /// FR-8.6/FR-8.7: the path must start with an allowed prefix, at a
    /// segment boundary (`/api/v3/series` does not admit `/api/v3/seriesX`).
    pub fn allows_path(&self, path: &str) -> bool {
        for prefix in &self.allowed_path_prefixes {
            if !path.starts_with(prefix.as_str()) {
                continue;
            }
            if prefix.ends_with('/') || path == prefix || path[prefix.len()..].starts_with('/') {
                return true;
            }
        }
        false
    }

    /// FR-8.9: the *resolved* IP, checked immediately before connecting.
    /// An entry that does not parse matches nothing (load-time validation
    /// already refused it).
    pub fn in_allowed_cidrs(&self, address: IpAddr) -> bool {
        self.allowed_cidrs
            .iter()
            .any(|cidr| ip_network(cidr).is_ok_and(|net| net.contains(&address)))
    }

    /// `allowed_hosts`: an exact, case-insensitive name match. True for
    /// every host when the toolkit declares no `allowed_hosts` -- then
    /// `allowed_cidrs` alone decides, exactly as before 1.10.0.
    pub fn allows_host(&self, host: &str) -> bool {
        if self.allowed_hosts.is_empty() {
            return true;
        }
        let host = normalize_hostname(host);
        self.allowed_hosts.iter().any(|h| *h == host)
    }

    /// FR-8.3c: the whitelist acts on JSON-RPC method names.
    pub fn allows_rpc_method(&self, method: &str) -> bool {
        self.allowed_rpc_methods.iter().any(|m| m == method)
    }

    /// The whitelist acts on google_api.py action strings.
    pub fn allows_google_action(&self, action: &str) -> bool {
        self.allowed_google_actions.iter().any(|a| a == action)
    }

    /// The whitelist acts on microsoft_api.py action strings.
    pub fn allows_microsoft_action(&self, action: &str) -> bool {
        self.allowed_microsoft_actions.iter().any(|a| a == action)
    }

    /// The whitelist acts on opencode operation names.
    pub fn allows_opencode_operation(&self, operation: &str) -> bool {
        self.allowed_opencode_operations.iter().any(|o| o == operation)
    }

    /// The whitelist acts on agent (mailbox) operation names.
    pub fn allows_agent_operation(&self, operation: &str) -> bool {
        self.allowed_agent_operations.iter().any(|o| o == operation)
    }

    /// The whitelist acts on artifact operation names.
    pub fn allows_artifact_operation(&self, operation: &str) -> bool {
        self.allowed_artifact_operations.iter().any(|o| o == operation)
    }
}

/// A concrete place a toolkit's actions may run (FR-8.3g, deploy-time).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Destination {
    pub name: String,
    pub docker_host: Option<String>,
    /// `None` (not declared) inherits the toolkit's `docker_tls`; an
    /// explicit `false` overrides a toolkit-level `true`.
    pub docker_tls: Option<bool>,
    pub base_url: Option<String>,
    pub ws_url: Option<String>,
    /// Overrides the toolkit's own `credential` for this destination only.
    pub credential: Option<String>,
}

/// Per-category sliding-window limit (FR-6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub count: i64,
    pub window_seconds: i64,
}

/// The complete deploy-time configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier1 {
    pub toolkits: IndexMap<String, Toolkit>,
    pub destinations: IndexMap<String, Destination>,
    pub rate_limits: IndexMap<String, RateLimit>,
    pub max_concurrent: i64,
    pub audit_dir: String,
    pub audit_max_bytes: i64,
    pub audit_keep_files: i64,
}

impl Tier1 {
    pub fn toolkit(&self, name: &str) -> ConfigResult<&Toolkit> {
        self.toolkits
            .get(name)
            .ok_or_else(|| ConfigError::new(format!("Unknown toolkit {}", repr_str(name))))
    }

    pub fn destination(&self, name: &str) -> ConfigResult<&Destination> {
        self.destinations
            .get(name)
            .ok_or_else(|| ConfigError::new(format!("Unknown destination {}", repr_str(name))))
    }

    /// Credential name -> the labels of everything that refers to it:
    /// toolkit names, then `"<dest> (destination)"`. The single walk both
    /// the startup check and the console's "Used by" row use. Names only.
    pub fn credential_references(&self) -> IndexMap<String, Vec<String>> {
        let mut refs: IndexMap<String, Vec<String>> = IndexMap::new();
        for toolkit in self.toolkits.values() {
            if let Some(cred) = toolkit.credential.as_deref().filter(|c| !c.is_empty()) {
                refs.entry(cred.to_string()).or_default().push(toolkit.name.clone());
            }
        }
        for dest in self.destinations.values() {
            if let Some(cred) = dest.credential.as_deref().filter(|c| !c.is_empty()) {
                refs.entry(cred.to_string()).or_default().push(format!("{} (destination)", dest.name));
            }
        }
        refs
    }

    /// The union of every `google` toolkit's `required_scopes`, in first-seen order.
    pub fn google_oauth_scopes(&self) -> Vec<String> {
        self.oauth_scopes_for("google")
    }

    /// The union of every `microsoft` toolkit's `required_scopes`.
    pub fn microsoft_oauth_scopes(&self) -> Vec<String> {
        self.oauth_scopes_for("microsoft")
    }

    fn oauth_scopes_for(&self, executor: &str) -> Vec<String> {
        let mut scopes: Vec<String> = Vec::new();
        for toolkit in self.toolkits.values() {
            if toolkit.executor != executor {
                continue;
            }
            for scope in &toolkit.required_scopes {
                if !scopes.contains(scope) {
                    scopes.push(scope.clone());
                }
            }
        }
        scopes
    }

    /// `local` toolkit name -> the binaries it declares that this container
    /// does not have. `local` only: an `ssh` toolkit's binaries are on
    /// another filesystem.
    pub fn missing_local_binaries(&self) -> IndexMap<String, Vec<String>> {
        let mut missing = IndexMap::new();
        for toolkit in self.toolkits.values() {
            if toolkit.executor != "local" {
                continue;
            }
            let absent: Vec<String> =
                toolkit.binaries.iter().filter(|b| !is_runnable(b)).cloned().collect();
            if !absent.is_empty() {
                missing.insert(toolkit.name.clone(), absent);
            }
        }
        missing
    }
}

/// Exists, is a regular file, and is executable by this process. One
/// definition for the startup warning and the readiness probe.
pub fn is_runnable(path: &str) -> bool {
    if !std::path::Path::new(path).is_file() {
        return false;
    }
    let Ok(c_path) = std::ffi::CString::new(path) else {
        return false;
    };
    // SAFETY: `c_path` is a valid NUL-terminated string.
    unsafe { libc::access(c_path.as_ptr(), libc::X_OK) == 0 }
}

/// Absolute by POSIX convention (the paths describe the container
/// filesystem). What matters is that no bare program name remains.
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

// -- PurePosixPath ---------------------------------------------------------

/// `PurePosixPath(path).parts`: the root (`/`, or `//` for exactly two
/// leading slashes) followed by the non-empty, non-`.` components. `..` is
/// kept (pure paths never resolve it).
pub fn pure_posix_parts(path: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let stripped = path.trim_start_matches('/');
    let leading = path.len() - stripped.len();
    if leading == 2 {
        parts.push("//".to_string());
    } else if leading > 0 {
        parts.push("/".to_string());
    }
    for comp in stripped.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        parts.push(comp.to_string());
    }
    parts
}

/// `candidate == root or root in candidate.parents`, with `PurePosixPath`.
pub fn pure_posix_within(candidate: &str, root: &str) -> bool {
    let c = pure_posix_parts(candidate);
    let r = pure_posix_parts(root);
    // `PurePosixPath("")` / `"."` has no parts and is a parent of every
    // relative path; parts comparison covers that too.
    c.len() >= r.len() && c[..r.len()] == r[..]
}

// -- ipaddress.ip_network(strict=False) -------------------------------------

/// `ipaddress.ip_network(value, strict=False)`: an address with an optional
/// `/prefix` (IPv4 also accepts a netmask or hostmask), host bits masked
/// off. The error text is Python's `ValueError` message.
pub fn ip_network(value: &str) -> Result<IpNet, String> {
    let err = || format!("{} does not appear to be an IPv4 or IPv6 network", repr_str(value));
    let (addr_part, prefix_part) = match value.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (value, None),
    };
    if prefix_part.is_some_and(|p| p.contains('/')) {
        return Err(err());
    }
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    if let Ok(v4) = addr_part.parse::<std::net::Ipv4Addr>() {
        let prefix: u8 = match prefix_part {
            None => 32,
            Some(p) if digits(p) => match p.parse::<u32>() {
                Ok(n) if n <= 32 => n as u8,
                _ => return Err(err()),
            },
            Some(p) => match p.parse::<std::net::Ipv4Addr>() {
                Ok(mask) => {
                    let bits = u32::from(mask);
                    if bits.leading_ones() + bits.trailing_zeros() == 32 {
                        bits.leading_ones() as u8
                    } else {
                        let inv = !bits;
                        if inv.leading_ones() + inv.trailing_zeros() == 32 {
                            inv.leading_ones() as u8
                        } else {
                            return Err(err());
                        }
                    }
                }
                Err(_) => return Err(err()),
            },
        };
        return Ipv4Net::new(v4, prefix).map(|n| IpNet::V4(n.trunc())).map_err(|_| err());
    }
    // IPv6, optionally with a `%scope` id (ignored for containment).
    let bare = addr_part.split_once('%').map(|(a, _)| a).unwrap_or(addr_part);
    if let Ok(v6) = bare.parse::<std::net::Ipv6Addr>() {
        let prefix: u8 = match prefix_part {
            None => 128,
            Some(p) if digits(p) => match p.parse::<u32>() {
                Ok(n) if n <= 128 => n as u8,
                _ => return Err(err()),
            },
            Some(_) => return Err(err()),
        };
        return Ipv6Net::new(v6, prefix).map(|n| IpNet::V6(n.trunc())).map_err(|_| err());
    }
    Err(err())
}

// -- Field helpers ----------------------------------------------------------

fn require<'a>(data: &'a Map<String, Value>, key: &str, where_: &str) -> ConfigResult<&'a Value> {
    data.get(key).ok_or_else(|| {
        ConfigError::new(format!("{where_}: required field {} is missing", repr_str(key)))
    })
}

/// `_str_tuple`: `None` -> empty; otherwise a list of strings.
fn str_tuple(value: Option<&Value>, where_: &str) -> ConfigResult<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => Ok(s.clone()),
                _ => Err(ConfigError::new(format!("{where_}: expects a list of strings"))),
            })
            .collect(),
        Some(_) => Err(ConfigError::new(format!("{where_}: expects a list of strings"))),
    }
}

/// `spec.get(key, default)` then `int(...)`: absent -> `default`.
fn int_or(spec: &Map<String, Value>, key: &str, default: i64) -> ConfigResult<i64> {
    match spec.get(key) {
        None => Ok(default),
        Some(v) => py_int(v),
    }
}

/// Shared shape check behind the docker/http/ws URL validators: split it,
/// check the scheme, check there is an address to connect to.
fn validate_url(
    value: &str,
    where_: &str,
    field: &str,
    schemes: &[&str],
    example: &str,
    allow_path: bool,
) -> ConfigResult<String> {
    let parsed = urlsplit(value);
    let has_address = !parsed.netloc.is_empty() || (allow_path && !parsed.path.is_empty());
    if !schemes.contains(&parsed.scheme.as_str()) || !has_address {
        return Err(ConfigError::new(format!(
            "{where_}: {field} {} must be {example}",
            repr_str(value)
        )));
    }
    Ok(value.to_string())
}

/// `docker_host`: a `tcp://host:port` or `unix:///path/to/socket` URL.
pub fn validate_docker_host(value: &str, where_: &str) -> ConfigResult<String> {
    validate_url(
        value,
        where_,
        "docker_host",
        &["tcp", "unix"],
        "a 'tcp://host:port' or 'unix:///path/to/socket' URL",
        true,
    )
}

/// `_validate_http_base_url`: an absolute http(s) URL. `field` names the
/// field in the message (Python's default is `"base_url"`).
pub fn validate_http_base_url(value: &str, where_: &str, field: &str) -> ConfigResult<String> {
    validate_url(
        value,
        where_,
        field,
        &["http", "https"],
        "an absolute http(s) URL, e.g. 'http://sonarr.lan:8989'",
        false,
    )
}

/// `_validate_ws_url`: an absolute ws(s) URL.
pub fn validate_ws_url(value: &str, where_: &str, field: &str) -> ConfigResult<String> {
    validate_url(
        value,
        where_,
        field,
        &["ws", "wss"],
        "an absolute ws(s) URL, e.g. 'wss://truenas.lan/api/current'",
        false,
    )
}

/// The parts of `urllib.parse.urlsplit` the URL checks read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SplitUrl {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

/// `urllib.parse.urlsplit` (scheme lower-cased, `//netloc` only after a
/// scheme or at the start, query/fragment split off).
pub fn urlsplit(url: &str) -> SplitUrl {
    // Python strips leading C0 control/space and removes tab/CR/LF.
    let cleaned: String = url
        .trim_start_matches(|c: char| (c as u32) <= 0x20)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = cleaned.as_str();
    let mut scheme = String::new();
    if let Some(i) = rest.find(':') {
        let cand = &rest[..i];
        let valid = !cand.is_empty()
            && cand.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && cand.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if valid {
            scheme = cand.to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
    }
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..end].to_string();
        rest = &after[end..];
    }
    let (rest, fragment) = match rest.split_once('#') {
        Some((a, f)) => (a, f.to_string()),
        None => (rest, String::new()),
    };
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (rest.to_string(), String::new()),
    };
    SplitUrl { scheme, netloc, path, query, fragment }
}

/// Parses the top-level `destinations:` section (FR-8.3g).
fn parse_destinations(raw: &Map<String, Value>) -> ConfigResult<IndexMap<String, Destination>> {
    let empty = Map::new();
    let section = match raw.get("destinations") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(m)) => m,
        Some(_) => {
            return Err(ConfigError::new("toolkits.yaml: section 'destinations' must be a mapping"))
        }
    };
    let mut destinations = IndexMap::new();
    for (name, spec) in section {
        let where_ = format!("destination {}", repr_str(name));
        let Value::Object(spec) = spec else {
            return Err(ConfigError::new(format!("{where_}: expects a mapping")));
        };
        let opt_str = |key: &str| spec.get(key).filter(|v| !v.is_null()).map(py_str);
        let docker_host = opt_str("docker_host")
            .map(|v| validate_docker_host(&v, &where_))
            .transpose()?;
        let base_url = opt_str("base_url")
            .map(|v| validate_http_base_url(&v, &where_, "base_url"))
            .transpose()?;
        let ws_url = opt_str("ws_url").map(|v| validate_ws_url(&v, &where_, "ws_url")).transpose()?;
        let credential = match spec.get("credential") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                return Err(ConfigError::new(format!(
                    "{where_}: 'credential' must be a string name"
                )))
            }
        };
        let docker_tls = match spec.get("docker_tls") {
            None | Some(Value::Null) => None,
            Some(v) => Some(py_truthy(v)),
        };
        destinations.insert(
            name.clone(),
            Destination { name: name.clone(), docker_host, docker_tls, base_url, ws_url, credential },
        );
    }
    Ok(destinations)
}

/// A toolkit's destinations must carry the target field its executor reads.
fn check_destination_shape(dest: &Destination, executor: &str, toolkit_where: &str) -> ConfigResult<()> {
    let where_ = format!("{toolkit_where}: destination {}", repr_str(&dest.name));
    if executor == "docker" && dest.docker_host.is_none() {
        return Err(ConfigError::new(format!(
            "{where_} has no 'docker_host', required for a docker toolkit"
        )));
    }
    if executor == "http" && dest.base_url.is_none() {
        return Err(ConfigError::new(format!(
            "{where_} has no 'base_url', required for an http toolkit"
        )));
    }
    if executor == "opencode" && dest.base_url.is_none() {
        return Err(ConfigError::new(format!(
            "{where_} has no 'base_url', required for an opencode toolkit"
        )));
    }
    if executor == "truenas" && dest.ws_url.is_none() {
        return Err(ConfigError::new(format!(
            "{where_} has no 'ws_url', required for a truenas toolkit"
        )));
    }
    Ok(())
}

/// Resolves and validates one toolkit's `destinations:` list (FR-8.3g).
fn toolkit_destinations(
    spec: &Map<String, Value>,
    executor: &str,
    where_: &str,
    destinations: &IndexMap<String, Destination>,
) -> ConfigResult<Vec<String>> {
    let dest_names = str_tuple(spec.get("destinations"), where_)?;
    if !dest_names.is_empty() {
        let refusal = match executor {
            "local" => Some(
                "'local' toolkits cannot declare destinations -- there is nothing remote to connect to",
            ),
            "ssh" => Some(
                "'ssh' toolkits cannot declare destinations yet -- one toolkit, one host (use a separate toolkit per host)",
            ),
            "artifact" => Some(
                "'artifact' toolkits cannot declare destinations -- artifacts come from this image, not from a target to connect to",
            ),
            "agent" => Some(
                "'agent' toolkits cannot declare destinations -- the mailbox is a local file (mailbox_path), not a target to connect to",
            ),
            _ => None,
        };
        if let Some(text) = refusal {
            return Err(ConfigError::new(format!("{where_}: {text}")));
        }
    }
    for dest_name in &dest_names {
        let Some(dest) = destinations.get(dest_name) else {
            return Err(ConfigError::new(format!(
                "{where_}: destination {} is not declared in the top-level 'destinations' section",
                repr_str(dest_name)
            )));
        };
        check_destination_shape(dest, executor, where_)?;
    }
    Ok(dest_names)
}

fn check_cidrs(cidrs: &[String], where_: &str) -> ConfigResult<()> {
    for cidr in cidrs {
        if let Err(exc) = ip_network(cidr) {
            return Err(ConfigError::new(format!(
                "{where_}: allowed_cidrs entry {} is not a valid IP network: {exc}",
                repr_str(cidr)
            )));
        }
    }
    Ok(())
}

// -- Network targets by hostname (1.10.0) ---------------------------------------

/// The executors that connect to a URL and so know what a host is.
pub const NETWORK_EXECUTORS: &[&str] = &["http", "opencode"];

/// Lower-case, without a trailing root dot -- the one spelling both the
/// allowlist and the URL's hostname are compared in.
pub fn normalize_hostname(host: &str) -> String {
    host.trim().to_lowercase().trim_end_matches('.').to_string()
}

/// `urlsplit(url).hostname or ""`: lower-cased, brackets stripped.
pub fn url_hostname(url: &str) -> String {
    crate::execute::http::host_info(&urlsplit(url).netloc).hostname
}

/// `ipaddress.ip_address(text)`: a plain IPv4 dotted quad or an IPv6
/// address (with an optional `%scope`, ignored), `None` otherwise.
pub fn py_ip_address(text: &str) -> Option<IpAddr> {
    if let Ok(v4) = text.parse::<std::net::Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    let bare = match text.split_once('%') {
        Some((addr, scope)) if !scope.is_empty() && !scope.contains('%') => addr,
        Some(_) => return None,
        None => text,
    };
    bare.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
}

/// `address in any(nets)`, for an address and networks of `bits` width.
fn in_nets(address: u128, bits: u32, nets: &[(u128, u32)]) -> bool {
    nets.iter().any(|&(net, prefix)| {
        let shift = bits - prefix;
        prefix == 0 || (address >> shift) == (net >> shift)
    })
}

fn v4net(a: u8, b: u8, c: u8, d: u8, prefix: u32) -> (u128, u32) {
    (u32::from_be_bytes([a, b, c, d]) as u128, prefix)
}

fn v6net(text: &str, prefix: u32) -> (u128, u32) {
    (u128::from(text.parse::<std::net::Ipv6Addr>().expect("constant network")), prefix)
}

/// Python 3.13's `ipaddress` classification of one address, in the order
/// `is_public_address` reads them: `[is_global, is_multicast,
/// is_reserved, is_loopback, is_link_local, is_unspecified, is_private]`.
fn v4_flags(address: std::net::Ipv4Addr) -> [bool; 7] {
    let ip = u32::from(address) as u128;
    let private = [
        v4net(0, 0, 0, 0, 8),
        v4net(10, 0, 0, 0, 8),
        v4net(127, 0, 0, 0, 8),
        v4net(169, 254, 0, 0, 16),
        v4net(172, 16, 0, 0, 12),
        v4net(192, 0, 0, 0, 24),
        v4net(192, 0, 0, 170, 31),
        v4net(192, 0, 2, 0, 24),
        v4net(192, 168, 0, 0, 16),
        v4net(198, 18, 0, 0, 15),
        v4net(198, 51, 100, 0, 24),
        v4net(203, 0, 113, 0, 24),
        v4net(240, 0, 0, 0, 4),
        v4net(255, 255, 255, 255, 32),
    ];
    let exceptions = [v4net(192, 0, 0, 9, 32), v4net(192, 0, 0, 10, 32)];
    let is_private = in_nets(ip, 32, &private) && !in_nets(ip, 32, &exceptions);
    let is_global = !in_nets(ip, 32, &[v4net(100, 64, 0, 0, 10)]) && !is_private;
    [
        is_global,
        in_nets(ip, 32, &[v4net(224, 0, 0, 0, 4)]),
        in_nets(ip, 32, &[v4net(240, 0, 0, 0, 4)]),
        in_nets(ip, 32, &[v4net(127, 0, 0, 0, 8)]),
        in_nets(ip, 32, &[v4net(169, 254, 0, 0, 16)]),
        ip == 0,
        is_private,
    ]
}

/// The same flags for an IPv6 address; an IPv4-mapped one
/// (`::ffff:a.b.c.d`) is judged by its IPv4 address alone, as Python's
/// properties do.
fn v6_flags(address: std::net::Ipv6Addr) -> [bool; 7] {
    let ip = u128::from(address);
    if (ip >> 32) == 0xFFFF {
        return v4_flags(std::net::Ipv4Addr::from((ip & 0xFFFF_FFFF) as u32));
    }
    let private = [
        v6net("::1", 128),
        v6net("::", 128),
        v6net("::ffff:0:0", 96),
        v6net("64:ff9b:1::", 48),
        v6net("100::", 64),
        v6net("2001::", 23),
        v6net("2001:db8::", 32),
        v6net("2002::", 16),
        v6net("3fff::", 20),
        v6net("fc00::", 7),
        v6net("fe80::", 10),
    ];
    let exceptions = [
        v6net("2001:1::1", 128),
        v6net("2001:1::2", 128),
        v6net("2001:3::", 32),
        v6net("2001:4:112::", 48),
        v6net("2001:20::", 28),
        v6net("2001:30::", 28),
    ];
    let reserved = [
        v6net("::", 8),
        v6net("100::", 8),
        v6net("200::", 7),
        v6net("400::", 6),
        v6net("800::", 5),
        v6net("1000::", 4),
        v6net("4000::", 3),
        v6net("6000::", 3),
        v6net("8000::", 3),
        v6net("a000::", 3),
        v6net("c000::", 3),
        v6net("e000::", 4),
        v6net("f000::", 5),
        v6net("f800::", 6),
        v6net("fe00::", 9),
    ];
    let is_private = in_nets(ip, 128, &private) && !in_nets(ip, 128, &exceptions);
    [
        !is_private,
        in_nets(ip, 128, &[v6net("ff00::", 8)]),
        in_nets(ip, 128, &reserved),
        ip == 1,
        in_nets(ip, 128, &[v6net("fe80::", 10)]),
        ip == 0,
        is_private,
    ]
}

/// True only for a globally routable unicast address.
///
/// The SSRF floor of a hostname toolkit (`Toolkit::allowed_hosts`): no
/// private, loopback, link-local, carrier-grade NAT, multicast, reserved,
/// documentation or unspecified address, in IPv4 or IPv6. An IPv6 address
/// that embeds an IPv4 one (IPv4-mapped `::ffff:a.b.c.d`, NAT64
/// `64:ff9b::/96`, 6to4 `2002::/16`) is judged by the embedded address as
/// well, so `::ffff:127.0.0.1` cannot pass as an IPv6 literal. The
/// classification is Python 3.13's `ipaddress` one.
pub fn is_public_address(address: IpAddr) -> bool {
    let [global, multicast, reserved, loopback, link_local, unspecified, private] = match address {
        IpAddr::V4(a) => v4_flags(a),
        IpAddr::V6(a) => v6_flags(a),
    };
    if !global || multicast || reserved || loopback || link_local || unspecified || private {
        return false;
    }
    if let IpAddr::V6(a) = address {
        let ip = u128::from(a);
        let embedded: Option<u32> = if (ip >> 32) == 0xFFFF {
            // ipv4_mapped
            Some((ip & 0xFFFF_FFFF) as u32)
        } else if (ip >> 112) == 0x2002 {
            // sixtofour
            Some(((ip >> 80) & 0xFFFF_FFFF) as u32)
        } else if in_nets(ip, 128, &[v6net("64:ff9b::", 96)]) {
            // NAT64
            Some((ip & 0xFFFF_FFFF) as u32)
        } else {
            None
        };
        if let Some(v4) = embedded {
            if !is_public_address(IpAddr::V4(std::net::Ipv4Addr::from(v4))) {
                return false;
            }
        }
    }
    true
}

/// One DNS label: letters, digits and inner hyphens, 1-63 characters
/// (Python's `^(?!-)[a-z0-9-]{1,63}(?<!-)$`).
// PORT NOTE: Python's `$` also matched before a trailing newline, so a
// label with a newline at its end passed the regex there; it is refused
// here.
fn is_host_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Validates `allowed_hosts` entries: exact DNS names, nothing else.
///
/// No wildcard in any form -- `*.github.com` would hand the choice of host
/// to whoever controls that zone's subdomains, which is the decision this
/// field exists to keep in toolkits.yaml. No IP literal either: an address
/// belongs in `allowed_cidrs`, where it is not subject to the
/// public-address floor a name gets.
fn parse_allowed_hosts(value: Option<&Value>, where_: &str) -> ConfigResult<Vec<String>> {
    let hosts = str_tuple(value, where_)?;
    let mut out: Vec<String> = Vec::new();
    for raw in &hosts {
        let host = normalize_hostname(raw);
        if host.contains('*') || host.contains('?') {
            return Err(ConfigError::new(format!(
                "{where_}: allowed_hosts entry {} is a wildcard -- only exact hostnames are accepted (e.g. 'api.github.com')",
                repr_str(raw)
            )));
        }
        if py_ip_address(host.trim_matches(|c| c == '[' || c == ']')).is_some() {
            return Err(ConfigError::new(format!(
                "{where_}: allowed_hosts entry {} is an IP address -- put addresses in allowed_cidrs (e.g. '{host}/32')",
                repr_str(raw)
            )));
        }
        let labels: Vec<&str> = host.split('.').collect();
        if host.is_empty()
            || host.chars().count() > 253
            || labels.len() < 2
            || !labels.iter().all(|label| is_host_label(label))
        {
            return Err(ConfigError::new(format!(
                "{where_}: allowed_hosts entry {} is not a valid fully qualified hostname (e.g. 'api.github.com')",
                repr_str(raw)
            )));
        }
        if !out.contains(&host) {
            out.push(host);
        }
    }
    Ok(out)
}

/// `allowed_cidrs` and `allowed_hosts` of an http/opencode toolkit
/// (`_parse_network_allowlist`). At least one must be non-empty: a toolkit
/// with neither would have no target restriction at all. Either may stand
/// alone -- `allowed_cidrs` alone is every toolkit written before 1.10.0,
/// unchanged.
pub fn parse_network_allowlist(
    spec: &Map<String, Value>,
    where_: &str,
) -> ConfigResult<(Vec<String>, Vec<String>)> {
    let allowed_cidrs = str_tuple(spec.get("allowed_cidrs"), where_)?;
    check_cidrs(&allowed_cidrs, where_)?;
    let allowed_hosts = parse_allowed_hosts(spec.get("allowed_hosts"), where_)?;
    if allowed_cidrs.is_empty() && allowed_hosts.is_empty() {
        return Err(ConfigError::new(format!(
            "{where_}: 'allowed_cidrs' must not be empty (or set 'allowed_hosts' to exact hostnames instead)"
        )));
    }
    Ok((allowed_cidrs, allowed_hosts))
}

/// Load-time half of the hostname check (`_check_url_host_allowed`): a
/// toolkit whose own target is not in its `allowed_hosts` could never make
/// a call, so it is refused here rather than on its first one. The
/// connect-time check in `execute::http` stays the authoritative one.
fn check_url_host_allowed(url: &str, allowed_hosts: &[String], where_: &str, field: &str) -> ConfigResult<()> {
    if allowed_hosts.is_empty() {
        return Ok(());
    }
    let host = normalize_hostname(&url_hostname(url));
    if !allowed_hosts.contains(&host) {
        return Err(ConfigError::new(format!(
            "{where_}: {field} host {} is not in allowed_hosts {}",
            repr_str(&host),
            repr_list(allowed_hosts)
        )));
    }
    Ok(())
}

/// The part both network executors share in `load_tier1`: the allowlist,
/// then the toolkit's own and every destination's `base_url` against it.
fn parse_network_targets(
    tk: &mut Toolkit,
    spec: &Map<String, Value>,
    where_: &str,
    base_url: &str,
    destinations: &IndexMap<String, Destination>,
) -> ConfigResult<()> {
    let (allowed_cidrs, allowed_hosts) = parse_network_allowlist(spec, where_)?;
    check_url_host_allowed(base_url, &allowed_hosts, where_, "base_url")?;
    for dest_name in &tk.destinations {
        if let Some(dest_url) = destinations.get(dest_name).and_then(|d| d.base_url.as_deref()) {
            check_url_host_allowed(
                dest_url,
                &allowed_hosts,
                &format!("{where_}: destination {}", repr_str(dest_name)),
                "base_url",
            )?;
        }
    }
    tk.allowed_cidrs = allowed_cidrs;
    tk.allowed_hosts = allowed_hosts;
    Ok(())
}

fn has_dotdot(path: &str) -> bool {
    pure_posix_parts(path).iter().any(|p| p == "..")
}

/// Loads and validates `toolkits.yaml`. Errors here abort startup.
///
/// Unlike the catalog, Tier 1 has no meaningful empty state: if the file
/// is missing, it is undecided what would be allowed.
pub fn load_tier1(path: &str) -> ConfigResult<Tier1> {
    if !std::path::Path::new(path).exists() {
        return Err(ConfigError::new(format!(
            "{path} not found. Tier 1 defines what is possible at all and has \
             no safe default -- create it before starting. A starting point \
             sits in config/examples/toolkits.yaml, or run 'gatekeeper init'."
        )));
    }
    let text = read_config_file(path, "A starting point sits in config/examples/toolkits.yaml.")?;
    // PORT NOTE: a YAML syntax error was an uncaught `yaml.YAMLError` in
    // Python; here it is a ConfigError naming the file.
    let raw = crate::atomic::safe_load(&text).map_err(|e| ConfigError::new(format!("{path}: {e}")))?;
    parse_tier1(&raw, path)
}

/// [`load_tier1`] on an already-parsed document (`path` only labels the
/// `recovery` message). Used by tests and by callers that hold the YAML.
pub fn parse_tier1(raw: &Value, path: &str) -> ConfigResult<Tier1> {
    let empty = Map::new();
    let raw: &Map<String, Value> = match raw {
        Value::Object(m) => m,
        v if !py_truthy(v) => &empty,
        // PORT NOTE: Python crashed with AttributeError on a non-mapping
        // document; reported plainly here.
        _ => return Err(ConfigError::new("toolkits.yaml: the document must be a mapping")),
    };

    // An empty section is valid and the state after `init`: then nothing
    // is possible.
    let toolkit_section = match raw.get("toolkits") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(m)) => m,
        Some(_) => return Err(ConfigError::new("toolkits.yaml: section 'toolkits' must be a mapping")),
    };

    let destinations = parse_destinations(raw)?;

    let mut toolkits: IndexMap<String, Toolkit> = IndexMap::new();
    for (name, spec) in toolkit_section {
        let toolkit = parse_toolkit(name, spec, &destinations)?;
        warn_toolkit(&toolkit);
        toolkits.insert(name.clone(), toolkit);
    }

    let mut rate_limits: IndexMap<String, RateLimit> = IndexMap::new();
    match raw.get("rate_limits") {
        Some(Value::Object(limits)) => {
            for (category, spec) in limits {
                let spec = match spec {
                    Value::Object(m) => m,
                    // PORT NOTE: Python crashed with AttributeError.
                    _ => {
                        return Err(ConfigError::new(format!(
                            "toolkits.yaml: rate_limits.{category} must be a mapping"
                        )))
                    }
                };
                rate_limits.insert(
                    category.clone(),
                    RateLimit {
                        count: int_or(spec, "count", DEFAULT_RATE_LIMIT_COUNT)?,
                        window_seconds: int_or(spec, "window_seconds", DEFAULT_RATE_LIMIT_WINDOW)?,
                    },
                );
            }
        }
        Some(v) if py_truthy(v) => {
            return Err(ConfigError::new("toolkits.yaml: section 'rate_limits' must be a mapping"))
        }
        _ => {}
    }
    for category in DEFAULT_RATE_LIMIT_CATEGORIES {
        rate_limits.entry(category.to_string()).or_insert(RateLimit {
            count: DEFAULT_RATE_LIMIT_COUNT,
            window_seconds: DEFAULT_RATE_LIMIT_WINDOW,
        });
    }

    if let Some(block) = raw.get("recovery") {
        check_removed_recovery(block, &format!("{path}: recovery"))?;
    }

    let audit = match raw.get("audit") {
        Some(Value::Object(m)) => m,
        Some(v) if py_truthy(v) => {
            return Err(ConfigError::new("toolkits.yaml: section 'audit' must be a mapping"))
        }
        _ => &empty,
    };
    Ok(Tier1 {
        toolkits,
        destinations,
        rate_limits,
        max_concurrent: int_or(raw, "max_concurrent", DEFAULT_MAX_CONCURRENT)?,
        audit_dir: audit.get("dir").map(py_str).unwrap_or_else(|| DEFAULT_AUDIT_DIR.to_string()),
        audit_max_bytes: int_or(audit, "max_bytes", DEFAULT_AUDIT_MAX_BYTES)?,
        audit_keep_files: int_or(audit, "keep_files", DEFAULT_AUDIT_KEEP_FILES)?,
    })
}

/// One `toolkits:` entry -- the body of the Python loop in `load_tier1`.
fn parse_toolkit(
    name: &str,
    spec: &Value,
    destinations: &IndexMap<String, Destination>,
) -> ConfigResult<Toolkit> {
    let where_ = format!("toolkit {}", repr_str(name));
    let Value::Object(spec) = spec else {
        return Err(ConfigError::new(format!("{where_}: expects a mapping")));
    };
    let where_ = where_.as_str();

    let executor_value = require(spec, "executor", where_)?;
    let executor = match executor_value {
        Value::String(s) if contains(KNOWN_EXECUTORS, s) => s.clone(),
        other => {
            return Err(ConfigError::new(format!(
                "{where_}: executor {} is not enabled at this stage (available: {})",
                repr_value(other),
                repr_list(KNOWN_EXECUTORS)
            )))
        }
    };
    let executor = executor.as_str();

    let max_timeout = int_or(spec, "max_timeout_seconds", DEFAULT_MAX_TIMEOUT_SECONDS)?;
    let max_output = int_or(spec, "max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES)?;
    if max_timeout <= 0 || max_output <= 0 {
        return Err(ConfigError::new(format!("{where_}: ceilings must be positive")));
    }

    let credential = match spec.get("credential") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            return Err(ConfigError::new(format!("{where_}: 'credential' must be a string name")))
        }
    };

    let mut tk = Toolkit {
        name: name.to_string(),
        executor: executor.to_string(),
        max_timeout_seconds: max_timeout,
        max_output_bytes: max_output,
        credential,
        ..Toolkit::default()
    };

    // `run_as` (file executor only), parsed for every executor so a
    // `run_as` elsewhere aborts startup instead of being silently ignored.
    if let Some(run_as) = spec.get("run_as").filter(|v| !v.is_null()) {
        if executor != "file" {
            return Err(ConfigError::new(format!(
                "{where_}: 'run_as' is only supported on a 'file' toolkit, \
                 not on {}. The other executors reach their \
                 target as a remote user (ssh_user), through a socket, or \
                 with a credential -- none of them runs local file \
                 operations there is a user to choose for.",
                repr_str(executor)
            )));
        }
        let run_as = py_str(run_as).trim().to_string();
        if let Err(exc) = parse_run_as(&run_as) {
            return Err(ConfigError::new(format!("{where_}: {exc}")));
        }
        tk.run_as = Some(run_as);
    }

    // `required_scopes` (the two OAuth executors only), same reasoning.
    if spec.get("required_scopes").is_some_and(|v| !v.is_null()) {
        if executor != "google" && executor != "microsoft" {
            return Err(ConfigError::new(format!(
                "{where_}: 'required_scopes' is only supported on a 'google' \
                 or 'microsoft' toolkit, not on {}. The other \
                 executors authenticate with a header, a key, or a socket -- \
                 none of them has an OAuth consent screen to ask a scope for.",
                repr_str(executor)
            )));
        }
        tk.required_scopes = str_tuple(spec.get("required_scopes"), where_)?;
    }

    // `allowed_hosts` on an executor that never reads it would read as a
    // network restriction that does not exist -- refused like `run_as`
    // above rather than silently ignored.
    if spec.get("allowed_hosts").is_some_and(|v| !v.is_null()) && !contains(NETWORK_EXECUTORS, executor) {
        return Err(ConfigError::new(format!(
            "{where_}: 'allowed_hosts' is only supported on an 'http' or 'opencode' toolkit, not on {}",
            repr_str(executor)
        )));
    }

    tk.destinations = toolkit_destinations(spec, executor, where_, destinations)?;

    let req_str = |key: &str| -> ConfigResult<String> { Ok(py_str(require(spec, key, where_)?)) };
    let req_list = |key: &str| -> ConfigResult<Vec<String>> {
        str_tuple(Some(require(spec, key, where_)?), where_)
    };
    let nonempty = |v: &[String], key: &str| -> ConfigResult<()> {
        if v.is_empty() {
            Err(ConfigError::new(format!("{where_}: {} must not be empty", repr_str(key))))
        } else {
            Ok(())
        }
    };

    match executor {
        "docker" | "local" | "ssh" => {
            tk.binaries = req_list("binaries")?;
            nonempty(&tk.binaries, "binaries")?;
            for binary in &tk.binaries {
                if !is_absolute(binary) {
                    return Err(ConfigError::new(format!(
                        "{where_}: binary {} must be an absolute path -- \
                         otherwise PATH decides what gets executed",
                        repr_str(binary)
                    )));
                }
            }
            if executor == "docker" {
                if let Some(raw_host) = spec.get("docker_host").filter(|v| !v.is_null()) {
                    tk.docker_host = Some(validate_docker_host(&py_str(raw_host), where_)?);
                }
                tk.docker_tls = spec.get("docker_tls").is_some_and(py_truthy);
            } else if executor == "ssh" {
                tk.ssh_host = Some(req_str("ssh_host")?);
                tk.ssh_port = int_or(spec, "ssh_port", DEFAULT_SSH_PORT)?;
                if !(1..=65535).contains(&tk.ssh_port) {
                    return Err(ConfigError::new(format!(
                        "{where_}: ssh_port {} is out of range",
                        tk.ssh_port
                    )));
                }
                tk.ssh_user = Some(req_str("ssh_user")?);
                let known = req_str("ssh_known_hosts")?.trim().to_string();
                if known.is_empty() {
                    return Err(ConfigError::new(format!(
                        "{where_}: 'ssh_known_hosts' must not be empty -- run \
                         'ssh-keyscan -t ed25519 <host>' and paste its output here. \
                         Host-key checking is not optional (FR-8.9's DNS-rebinding \
                         check exists for the same reason: verify the target, not \
                         just the name)."
                    )));
                }
                tk.ssh_known_hosts = Some(known);
            }
        }
        "http" => {
            tk.base_url = Some(validate_http_base_url(&req_str("base_url")?, where_, "base_url")?);
            tk.allowed_methods = req_list("allowed_methods")?;
            nonempty(&tk.allowed_methods, "allowed_methods")?;
            let unknown = sorted_difference(&tk.allowed_methods, HTTP_METHODS);
            if !unknown.is_empty() {
                return Err(ConfigError::new(format!(
                    "{where_}: allowed_methods {} are not HTTP methods (known: {})",
                    repr_list(&unknown),
                    repr_list(HTTP_METHODS)
                )));
            }
            tk.allowed_path_prefixes = req_list("allowed_path_prefixes")?;
            nonempty(&tk.allowed_path_prefixes, "allowed_path_prefixes")?;
            for prefix in &tk.allowed_path_prefixes {
                if !prefix.starts_with('/') {
                    return Err(ConfigError::new(format!(
                        "{where_}: allowed_path_prefixes entry {} must start with '/'",
                        repr_str(prefix)
                    )));
                }
            }
            let base_url = tk.base_url.clone().unwrap_or_default();
            parse_network_targets(&mut tk, spec, where_, &base_url, destinations)?;
            // FR-8.8 is not a configurable knob.
            if spec.get("follow_redirects").is_some_and(py_truthy) {
                return Err(ConfigError::new(format!(
                    "{where_}: 'follow_redirects' must be false -- gatekeeper \
                     never follows redirects on an http toolkit (FR-8.8)"
                )));
            }
        }
        "truenas" => {
            tk.ws_url = Some(validate_ws_url(&req_str("ws_url")?, where_, "ws_url")?);
            tk.allowed_rpc_methods = req_list("allowed_rpc_methods")?;
            nonempty(&tk.allowed_rpc_methods, "allowed_rpc_methods")?;
        }
        "google" => {
            let script = req_str("google_script")?;
            if !is_absolute(&script) {
                return Err(ConfigError::new(format!(
                    "{where_}: 'google_script' must be an absolute path -- \
                     otherwise PATH decides what gets executed"
                )));
            }
            tk.google_script = Some(script);
            if let Some(raw) = spec.get("google_container").filter(|v| !v.is_null()) {
                let container = py_str(raw);
                if container.is_empty() {
                    return Err(ConfigError::new(format!(
                        "{where_}: 'google_container' must not be empty"
                    )));
                }
                tk.google_container = Some(container);
            }
            tk.allowed_google_actions = req_list("allowed_google_actions")?;
            nonempty(&tk.allowed_google_actions, "allowed_google_actions")?;
        }
        "microsoft" => {
            let script = req_str("microsoft_script")?;
            if !is_absolute(&script) {
                return Err(ConfigError::new(format!(
                    "{where_}: 'microsoft_script' must be an absolute path -- \
                     otherwise PATH decides what gets executed"
                )));
            }
            tk.microsoft_script = Some(script);
            if let Some(raw) = spec.get("microsoft_container").filter(|v| !v.is_null()) {
                let container = py_str(raw);
                if container.is_empty() {
                    return Err(ConfigError::new(format!(
                        "{where_}: 'microsoft_container' must not be empty"
                    )));
                }
                tk.microsoft_container = Some(container);
            }
            tk.allowed_microsoft_actions = req_list("allowed_microsoft_actions")?;
            nonempty(&tk.allowed_microsoft_actions, "allowed_microsoft_actions")?;
        }
        "opencode" => {
            let base_url = validate_http_base_url(&req_str("base_url")?, where_, "base_url")?;
            if base_url.contains("{credential}") {
                return Err(ConfigError::new(format!(
                    "{where_}: base_url must not contain a '{{credential}}' \
                     placeholder -- the opencode executor sends its credential \
                     as a header, and would send this literally."
                )));
            }
            parse_network_targets(&mut tk, spec, where_, &base_url, destinations)?;
            tk.base_url = Some(base_url);
            tk.allowed_opencode_operations = req_list("allowed_opencode_operations")?;
            nonempty(&tk.allowed_opencode_operations, "allowed_opencode_operations")?;
            let unknown = sorted_difference(&tk.allowed_opencode_operations, OPENCODE_OPERATIONS);
            if !unknown.is_empty() {
                return Err(ConfigError::new(format!(
                    "{where_}: allowed_opencode_operations {} are not opencode operations (known: {})",
                    repr_list(&unknown),
                    repr_list(OPENCODE_OPERATIONS)
                )));
            }
        }
        "agent" => {
            let mailbox = req_str("mailbox_path")?;
            if !is_absolute(&mailbox) {
                return Err(ConfigError::new(format!(
                    "{where_}: 'mailbox_path' must be an absolute path -- \
                     otherwise the working directory would decide where \
                     messages are stored"
                )));
            }
            if has_dotdot(&mailbox) {
                return Err(ConfigError::new(format!(
                    "{where_}: 'mailbox_path' must not contain '..' -- state \
                     the path it actually resolves to"
                )));
            }
            tk.mailbox_path = Some(mailbox);
            tk.allowed_agent_operations = req_list("allowed_agent_operations")?;
            nonempty(&tk.allowed_agent_operations, "allowed_agent_operations")?;
            let unknown = sorted_difference(&tk.allowed_agent_operations, AGENT_OPERATIONS);
            if !unknown.is_empty() {
                return Err(ConfigError::new(format!(
                    "{where_}: allowed_agent_operations {} are not agent operations (known: {})",
                    repr_list(&unknown),
                    repr_list(AGENT_OPERATIONS)
                )));
            }
            tk.max_message_bytes = int_or(spec, "max_message_bytes", DEFAULT_MAX_MESSAGE_BYTES)?;
            tk.max_mailbox_messages = int_or(spec, "max_mailbox_messages", DEFAULT_MAILBOX_LIMIT)?;
            if tk.max_message_bytes <= 0 || tk.max_mailbox_messages <= 0 {
                return Err(ConfigError::new(format!("{where_}: mailbox ceilings must be positive")));
            }
        }
        "artifact" => {
            tk.allowed_artifact_operations = req_list("allowed_artifact_operations")?;
            let unknown = sorted_difference(&tk.allowed_artifact_operations, ARTIFACT_OPERATIONS);
            if tk.allowed_artifact_operations.is_empty() || !unknown.is_empty() {
                let tail = if unknown.is_empty() {
                    String::new()
                } else {
                    format!(" (unknown: {})", repr_list(&unknown))
                };
                return Err(ConfigError::new(format!(
                    "{where_}: allowed_artifact_operations must be a non-empty subset of {}{tail}",
                    repr_list(ARTIFACT_OPERATIONS)
                )));
            }
            tk.allowed_artifacts = req_list("allowed_artifacts")?;
            nonempty(&tk.allowed_artifacts, "allowed_artifacts")?;
            let mut removed: Vec<String> = tk
                .allowed_artifacts
                .iter()
                .filter(|a| contains(REMOVED_ARTIFACTS, a))
                .cloned()
                .collect();
            removed.sort();
            removed.dedup();
            if !removed.is_empty() {
                // Not an error: the toolkit still loads.
                tracing::warn!(
                    "{}: allowed_artifacts names {}, which this image no longer \
                     builds (the Hermes recovery adapter was removed in 0.52.0). \
                     Remove them; drop the toolkit, its tools and the matching \
                     'artifact:' scopes if nothing else is left.",
                    where_,
                    repr_list(&removed)
                );
            }
            if tk.allowed_artifact_operations.iter().any(|o| o == "transfer") {
                let dir = req_str("handover_dir")?;
                if !is_absolute(&dir) || has_dotdot(&dir) {
                    return Err(ConfigError::new(format!(
                        "{where_}: 'handover_dir' must be an absolute path without '..'"
                    )));
                }
                tk.handover_dir = Some(dir);
            } else if spec.get("handover_dir").is_some_and(|v| !v.is_null()) {
                return Err(ConfigError::new(format!(
                    "{where_}: 'handover_dir' is only meaningful with the 'transfer' operation"
                )));
            }
        }
        _ => {} // "file": no executor-specific fields beyond run_as.
    }

    tk.denied_args = str_tuple(spec.get("denied_args"), where_)?;
    tk.path_roots = str_tuple(spec.get("path_roots"), where_)?;
    tk.protected_resources = str_tuple(spec.get("protected_resources"), where_)?;
    Ok(tk)
}

/// The startup warnings `load_tier1` logs per toolkit (missing agent
/// operations, missing vendored scripts).
fn warn_toolkit(tk: &Toolkit) {
    let unavailable = missing_agent_operations(tk);
    if !unavailable.is_empty() {
        tracing::warn!(
            "Toolkit {} does not allow the agent operation(s) {}. A \
             toolkit's allowed_agent_operations is set in toolkits.yaml \
             and cannot be changed by a proposal -- add the operation \
             there (a Tier-1 file: host-side edit, then SIGHUP or \
             redeploy to reload) if identities on this toolkit should \
             have it. The operations this toolkit allows stay: {}.",
            repr_str(&tk.name),
            unavailable.join(", "),
            tk.allowed_agent_operations.join(", ")
        );
    }
    for (absent, fallback, field) in [
        (missing_google_script(tk), GOOGLE_FALLBACK_SCRIPT, "google_script"),
        (missing_microsoft_script(tk), MICROSOFT_FALLBACK_SCRIPT, "microsoft_script"),
    ] {
        let Some(absent) = absent else { continue };
        if std::path::Path::new(fallback).is_file() {
            let since = if field == "google_script" { " (baked in since 0.40.1)" } else { "" };
            tracing::warn!(
                "Toolkit {} names {} {}, which does not exist \
                 in this container -- calls fall back to the image's own \
                 copy at {}{}. Point {} at that path in \
                 toolkits.yaml to make the configuration say what actually runs.",
                repr_str(&tk.name),
                field,
                absent,
                fallback,
                since,
                field
            );
        } else {
            tracing::warn!(
                "Toolkit {} names {} {}, which does not exist \
                 in this container, and the image's own copy at {} is \
                 missing too -- every call on this toolkit will fail \
                 until one of the two paths exists.",
                repr_str(&tk.name),
                field,
                absent,
                fallback
            );
        }
    }
}

// -- Python built-in conversions on YAML/JSON values -------------------------

/// Python's `bool(x)` (truthiness).
pub fn py_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// Python's `str(x)`.
pub fn py_str(v: &Value) -> String {
    crate::pyfmt::str_value(v)
}

/// Python's `int(x)`: ints as-is, floats truncated, `bool` as 0/1, strings
/// parsed base 10 (surrounding whitespace and `_` separators allowed).
///
/// PORT NOTE: Python raised `ValueError`/`TypeError` (an uncaught crash at
/// startup); here it is a `ConfigError` carrying the same text.
pub fn py_int(v: &Value) -> ConfigResult<i64> {
    match v {
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else if let Some(u) = n.as_u64() {
                i64::try_from(u).map_err(|_| ConfigError::new(format!("int too large: {u}")))
            } else {
                let f = n.as_f64().unwrap_or(0.0);
                if f.is_nan() {
                    Err(ConfigError::new("cannot convert float NaN to integer"))
                } else if f.is_infinite() {
                    Err(ConfigError::new("cannot convert float infinity to integer"))
                } else {
                    Ok(f.trunc() as i64)
                }
            }
        }
        Value::String(s) => {
            let t = s.trim();
            let (sign, digits) = match t.strip_prefix('-') {
                Some(d) => (-1i64, d),
                None => (1i64, t.strip_prefix('+').unwrap_or(t)),
            };
            let valid = !digits.is_empty()
                && !digits.starts_with('_')
                && !digits.ends_with('_')
                && !digits.contains("__")
                && digits.chars().all(|c| c.is_ascii_digit() || c == '_');
            let parsed = if valid { digits.replace('_', "").parse::<i64>().ok() } else { None };
            parsed.map(|n| sign * n).ok_or_else(|| {
                ConfigError::new(format!(
                    "invalid literal for int() with base 10: {}",
                    repr_str(s)
                ))
            })
        }
        other => Err(ConfigError::new(format!(
            "int() argument must be a string, a bytes-like object or a real number, not {}",
            repr_str(crate::pyfmt::type_name(other))
        ))),
    }
}

/// Python's `==` between two JSON-shaped values: numbers compare by value
/// (`1 == 1.0`), and `True == 1` / `False == 0`.
pub fn py_eq(a: &Value, b: &Value) -> bool {
    fn num(v: &Value) -> Option<f64> {
        match v {
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    }
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            if let (Some(i), Some(j)) = (x.as_i64(), y.as_i64()) {
                i == j
            } else {
                num(a) == num(b)
            }
        }
        (Value::Bool(_), Value::Number(_)) | (Value::Number(_), Value::Bool(_)) => num(a) == num(b),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| py_eq(v, w)))
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ip_network_matches_python() {
        assert_eq!(ip_network("10.0.0.1/24").unwrap().to_string(), "10.0.0.0/24");
        assert_eq!(ip_network("10.0.0.0/255.0.0.0").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(ip_network("10.0.0.0/0.255.255.255").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(ip_network("10.0.0.0/08").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(ip_network("fe80::1%eth0/64").unwrap().to_string(), "fe80::/64");
        assert_eq!(ip_network("10.0.0.5").unwrap().to_string(), "10.0.0.5/32");
        for bad in ["foo", "10.0.0.0/33", "010.0.0.1", "::1/129", "1.2.3", "", " 10.0.0.0/8"] {
            assert_eq!(
                ip_network(bad).unwrap_err(),
                format!("{} does not appear to be an IPv4 or IPv6 network", repr_str(bad))
            );
        }
    }

    #[test]
    fn urlsplit_basics() {
        let p = urlsplit("http://sonarr.lan:8989/api?x=1#f");
        assert_eq!((p.scheme.as_str(), p.netloc.as_str(), p.path.as_str()), ("http", "sonarr.lan:8989", "/api"));
        let u = urlsplit("unix:///var/run/docker.sock");
        assert_eq!((u.scheme.as_str(), u.netloc.as_str(), u.path.as_str()), ("unix", "", "/var/run/docker.sock"));
        let n = urlsplit("sonarr.lan:8989");
        assert_eq!(n.scheme, "sonarr.lan");
        assert_eq!(urlsplit("HTTP://x").scheme, "http");
    }

    #[test]
    fn pure_posix() {
        assert_eq!(pure_posix_parts("/a//b/./c/"), vec!["/", "a", "b", "c"]);
        assert_eq!(pure_posix_parts("//a"), vec!["//", "a"]);
        assert_eq!(pure_posix_parts("///a"), vec!["/", "a"]);
        assert!(pure_posix_within("/mnt/raid/x", "/mnt/raid"));
        assert!(pure_posix_within("/mnt/raid", "/mnt/raid/"));
        assert!(!pure_posix_within("/mnt/raid-evil", "/mnt/raid"));
        assert!(!pure_posix_within("/mnt", "/mnt/raid"));
    }

    #[test]
    fn py_int_matches_python() {
        assert_eq!(py_int(&json!(" 60 ")).unwrap(), 60);
        assert_eq!(py_int(&json!("6_0")).unwrap(), 60);
        assert_eq!(py_int(&json!(60.9)).unwrap(), 60);
        assert_eq!(py_int(&json!(true)).unwrap(), 1);
        assert_eq!(
            py_int(&json!("x")).unwrap_err().message,
            "invalid literal for int() with base 10: 'x'"
        );
        assert_eq!(
            py_int(&Value::Null).unwrap_err().message,
            "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'"
        );
        assert!(py_int(&json!("1.5")).is_err());
    }

    #[test]
    fn allows_path_segment_boundary() {
        let tk = Toolkit {
            allowed_path_prefixes: vec!["/api/v3/series".into(), "/api/v1/".into()],
            ..Toolkit::default()
        };
        assert!(tk.allows_path("/api/v3/series"));
        assert!(tk.allows_path("/api/v3/series/1"));
        assert!(!tk.allows_path("/api/v3/seriesXYZ"));
        assert!(tk.allows_path("/api/v1/anything"));
        assert!(!tk.allows_path("/api/v2"));
    }
}
