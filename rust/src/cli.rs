//! The command line (port of `__main__.py`): `serve`, `check`, `init`,
//! `token`, `password`, `credential-key`, plus the two module entry points
//! Python reached with `python -m` (`build-artifacts`, `openapi`).
//!
//! `serve` runs in two phases. Everything up to the application is
//! synchronous and runs before the tokio runtime exists: the privilege drop
//! (in [`main`]) and the capability hand-back in `serve` change per-thread
//! state and must happen while the process has one thread. Only then is
//! the runtime started, the app built inside it and the socket bound --
//! uvicorn's part, including its log lines, its proxy-header handling and
//! its graceful shutdown.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use clap::{Arg, ArgAction, ArgMatches, Command};
use parking_lot::RwLock;

use crate::audit::{AuditLog, Redactor};
use crate::catalog::load_catalog;
use crate::credentials::{generate_master_key, CredentialStore, KEY_ENV};
use crate::errors::ConfigError;
use crate::identity::{
    generate_password, generate_token, hash_token, hash_token_lookup, load_identities, UI_ROLES,
};
use crate::pathutil;
use crate::pending::PendingStore;
use crate::privdrop::{configured_target, discard_capabilities, drop_privileges};
use crate::pyfmt::{os_error, repr_list, repr_str};
use crate::runas::{
    bypasses_file_permissions, can_change_user, capability_sets, child_bypasses_file_permissions,
    effective_capabilities, resolve_run_as,
};
use crate::server::{self, build_app, client_addr, log_startup, AppOptions};
use crate::service::{Service, ServiceOptions, SharedIdentities};
use crate::store::{set_password_in_file, ConfigStore};
use crate::tier1::load_tier1;
use crate::toolkit_proposals::ToolkitProposalStore;
use crate::ui::has_ui_identity;

/// How long `serve` lets open requests finish on shutdown.
pub const SHUTDOWN_GRACE_SECONDS: u64 = 5;

/// Where a freshly bootstrapped `toolkits.yaml` points its audit log when
/// neither `--audit-dir` nor this says otherwise.
pub const AUDIT_DIR_ENV: &str = "GATEKEEPER_AUDIT_DIR";

// -- Paths ------------------------------------------------------------------------

/// Tier 1. May be mounted read-only.
pub fn config_dir() -> String {
    match std::env::var_os("GATEKEEPER_CONFIG_DIR") {
        Some(v) => v.to_string_lossy().into_owned(),
        None => "/etc/gatekeeper".into(),
    }
}

/// Tier 2. Must be writable if the console is to write. Falls back to the
/// configuration directory when the variable is not set (or empty).
pub fn state_dir() -> String {
    match std::env::var("GATEKEEPER_STATE_DIR") {
        Ok(v) if !v.is_empty() => v,
        _ => config_dir(),
    }
}

/// `_config_path`: the explicit option, or the file in its tier's directory.
pub fn config_path(name: &str, args_value: Option<&str>) -> String {
    if let Some(v) = args_value.filter(|v| !v.is_empty()) {
        return v.to_string();
    }
    let base = if matches!(
        name,
        "tools.yaml" | "identities.yaml" | "credentials.yaml" | "pending.yaml" | "toolkit_proposals.yaml"
    ) {
        state_dir()
    } else {
        config_dir()
    };
    pathutil::join(&base, name)
}

/// uid:gid of the running process, for a usable chown recommendation.
pub fn whoami() -> String {
    // SAFETY: getuid/getgid have no preconditions.
    unsafe { format!("{}:{}", libc::getuid(), libc::getgid()) }
}

/// `_require_run_as`: whether an unusable `run_as` aborts startup rather
/// than only logging. Off by default.
pub fn require_run_as() -> bool {
    let value = std::env::var("GATEKEEPER_REQUIRE_RUN_AS").unwrap_or_default();
    matches!(value.trim().to_lowercase().as_str(), "1" | "true" | "yes")
}

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).unwrap_or_default().as_str(), "1" | "true" | "yes")
}

// -- Bootstrap ----------------------------------------------------------------------

/// Tier 1, empty. gatekeeper makes no assumption about what an agent should
/// be able to reach; after `init`, nothing is possible.
const INIT_TOOLKITS: &str = "\
# Tier 1 - deploy-time, immutable at runtime (REQUIREMENTS.md §6).
#
# Created empty by 'gatekeeper init'. As long as no toolkit is defined here,
# gatekeeper cannot execute anything - no administrator can change this,
# because the console creates tools but never a toolkit
# (FR-4.11). Extending means: edit this file and redeploy.
#
# A toolkit looks like this. The values are examples and must match
# the host - a complete set is in config/examples/toolkits.yaml:
#
# toolkits:
#   diag:
#     executor: local          # local | docker
#     binaries:                # absolute paths, exact allowlist (FR-4.1)
#       - /usr/bin/uptime
#     denied_args: []          # blocked subcommands and flags (FR-4.2)
#     path_roots: []           # roots for derived paths (FR-4.3)
#     protected_resources: []  # reachable by no tool (FR-4.12)
#     max_timeout_seconds: 10
#     max_output_bytes: 16384

toolkits: {}

# FR-6.8
rate_limits:
  read:
    count: 120
    window_seconds: 60
  write:
    count: 20
    window_seconds: 60
  write_external:
    count: 5
    window_seconds: 60

max_concurrent: 4

# FR-9.4/9.5 - append-only with rotation. Without rotation, the log fills the dataset.
audit:
  dir: @AUDIT_DIR@
  max_bytes: 33554432
  keep_files: 10
";

const INIT_TOOLS: &str = "\
# Catalog (REQUIREMENTS.md §7). Created empty - this is by design.
#
# Tools are created in the console at /app; it writes this file.
# Examples to learn from are in config/examples/tools.yaml.

tools: []
";

/// `_paths`: toolkits.yaml in the config dir, the other two in the state dir.
pub fn init_paths(config_dir: &str, state_dir: &str) -> [(&'static str, String); 3] {
    [
        ("toolkits", pathutil::join(config_dir, "toolkits.yaml")),
        ("tools", pathutil::join(state_dir, "tools.yaml")),
        ("identities", pathutil::join(state_dir, "identities.yaml")),
    ]
}

/// An `OSError` with the path it names, for Python's `str(exc)`.
#[derive(Debug)]
pub struct PathError {
    pub error: std::io::Error,
    pub path: String,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&os_error(&self.error, &self.path))
    }
}

/// `os.makedirs(path, exist_ok=True)`, reporting the level that failed.
fn makedirs(path: &str) -> Result<(), PathError> {
    let p = std::path::Path::new(path);
    if p.is_dir() {
        return Ok(());
    }
    if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        makedirs(&parent.to_string_lossy())?;
    }
    match std::fs::create_dir(p) {
        Ok(()) => Ok(()),
        Err(_) if p.is_dir() => Ok(()),
        Err(error) => Err(PathError { error, path: path.to_string() }),
    }
}

/// Writes the empty state, returns token and console password -- the shared
/// core of `init` and the first start.
pub fn bootstrap(config_dir: &str, state_dir: &str, audit_dir: Option<&str>) -> Result<(String, String), PathError> {
    makedirs(config_dir)?;
    if state_dir != config_dir {
        makedirs(state_dir)?;
    }
    let paths = init_paths(config_dir, state_dir);
    let token = generate_token();
    let password = generate_password();
    let env_audit = std::env::var(AUDIT_DIR_ENV).map(|v| v.trim().to_string()).unwrap_or_default();
    let audit = match audit_dir.filter(|a| !a.is_empty()) {
        Some(a) => a.to_string(),
        None if !env_audit.is_empty() => env_audit,
        None => pathutil::join(state_dir, "logs"),
    };
    let identities = format!(
        "# Identities and permissions (REQUIREMENTS.md §4 and §9).\n\
         #\n\
         # Contains only hashes. The console creates further identities.\n\
         #\n\
         # Two separate credentials: 'token_hash' belongs to the API (/mcp),\n\
         # 'password_hash' for signing in to the console (/app). Losing one\n\
         # does not mean losing both.\n\n\
         identities:\n  \
         - id: admin\n    \
         role: admin\n    \
         token_hash: \"{}\"\n    \
         token_lookup: \"{}\"\n    \
         password_hash: \"{}\"\n    \
         # An administrator needs no tool rights: the console\n    \
         # calls nothing.\n    \
         tools: []\n    \
         scopes: []\n",
        hash_token(&token),
        hash_token_lookup(&token),
        hash_token(&password)
    );
    let files = [
        (&paths[0].1, INIT_TOOLKITS.replace("@AUDIT_DIR@", &audit)),
        (&paths[1].1, INIT_TOOLS.to_string()),
        (&paths[2].1, identities),
    ];
    for (path, content) in files {
        std::fs::write(path, content).map_err(|error| PathError { error, path: path.clone() })?;
    }
    Ok((token, password))
}

/// First start: if all three files are missing, everything is created; if
/// any one exists, nothing is (an existing installation with a problem must
/// fail loudly, not be overwritten). `None` on success or nothing to do.
pub fn bootstrap_on_first_start(config_dir: &str, state_dir: &str) -> Option<String> {
    let paths = init_paths(config_dir, state_dir);
    if paths.iter().any(|(_, p)| std::path::Path::new(p).exists()) {
        return None;
    }
    let (token, password) = match bootstrap(config_dir, state_dir, None) {
        Ok(pair) => pair,
        Err(exc) => {
            return Some(format!(
                "Cannot create the configuration in {config_dir}: {exc}\n\
                 This process runs as {who}. Docker creates a missing \
                 bind-mount source as root, which that user cannot write to.\n\
                 On the host, give the directory to the container user, then \
                 start again:\n  \
                 chown -R {who} <the directory mounted at {config_dir}>",
                who = whoami()
            ))
        }
    };
    tracing::warn!(
        "First start: created an empty configuration in {}. No toolkits, no \
         tools, no agents -- gatekeeper can do nothing until you say what it \
         may do.",
        config_dir
    );
    // Both secrets are now in the container log: the price of a first start
    // without a second command.
    tracing::warn!(
        "Administrator console password (shown once, and only here): {} -- \
         sign in at /app as 'admin', then change it there so it no longer \
         lives in this log.",
        password
    );
    tracing::warn!(
        "Administrator API token (shown once, and only here): {} -- for \
         /mcp only; it does not sign in to /app. Rotate it in the console.",
        token
    );
    None
}

/// `_ensure_console_passwords`: gives console accounts without a password
/// one -- once, into the log. `None` on success or nothing to do.
pub fn ensure_console_passwords(path: &str, identities: &SharedIdentities) -> Option<String> {
    let missing: Vec<(String, String)> = identities
        .read()
        .identities
        .values()
        .filter(|i| UI_ROLES.contains(&i.role.as_str()) && i.password_hash.is_empty())
        .map(|i| (i.id.clone(), i.role.clone()))
        .collect();
    if missing.is_empty() {
        return None;
    }
    for (identity_id, role) in missing {
        let password = generate_password();
        // PORT NOTE: `set_password_in_file` reports an OSError as a
        // ConfigError with the same text; both land here, as in Python.
        if let Err(exc) = set_password_in_file(path, &identity_id, &password) {
            return Some(format!(
                "Configuration error: {} has role {} but no console \
                 password, and one cannot be written: {exc}\n\
                 Signing in to /app needs a password since 0.3.0 -- the API \
                 token no longer opens the console. Set one on a writable \
                 copy of the file with:\n  \
                 gatekeeper password --identity {identity_id}",
                repr_str(&identity_id),
                repr_str(&role)
            ));
        }
        tracing::warn!(
            "Console password for {} (shown once, and only here): {} -- this \
             identity had none; signing in to /app needs one since 0.3.0. \
             Change it under /app/account so it no longer lives in this log.",
            repr_str(&identity_id),
            password
        );
    }
    // Reload from the file, not patched in memory: only this proves that the
    // running state matches what a restart would produce.
    match load_identities(path) {
        Ok(store) => {
            identities.write().identities = store.identities;
            None
        }
        // PORT NOTE: Python let this ConfigError escape as a traceback.
        Err(exc) => Some(format!("Configuration error: {exc}")),
    }
}

// -- Logging ------------------------------------------------------------------------

/// Python's logger name for a tracing target.
fn logger_name(target: &str) -> &str {
    if target.starts_with("gatekeeper::mcp") {
        "mcp"
    } else if target.starts_with("gatekeeper") {
        "gatekeeper"
    } else {
        target
    }
}

fn level_name(level: &tracing::Level) -> &'static str {
    match *level {
        tracing::Level::ERROR => "ERROR",
        tracing::Level::WARN => "WARNING",
        tracing::Level::INFO => "INFO",
        _ => "DEBUG",
    }
}

/// `logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s
/// %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z")`.
struct BasicFormat;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for BasicFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();
        let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%z");
        write!(writer, "{ts} {} {} ", level_name(meta.level()), logger_name(meta.target()))?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// logging's `lastResort` handler: WARNING and above, the bare message.
struct LastResort;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for LastResort
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// `GATEKEEPER_LOG_LEVEL` as `logging` reads a level name (case-sensitive).
fn parse_level(name: &str) -> Result<tracing_subscriber::filter::LevelFilter, String> {
    use tracing_subscriber::filter::LevelFilter;
    Ok(match name {
        "CRITICAL" | "FATAL" => LevelFilter::OFF,
        "ERROR" => LevelFilter::ERROR,
        "WARN" | "WARNING" => LevelFilter::WARN,
        "INFO" => LevelFilter::INFO,
        "DEBUG" | "NOTSET" => LevelFilter::DEBUG,
        other => return Err(format!("ValueError: Unknown level: {}", repr_str(other))),
    })
}

fn init_basic_logging() -> Result<(), String> {
    let level = parse_level(&std::env::var("GATEKEEPER_LOG_LEVEL").unwrap_or_else(|_| "INFO".into()))?;
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .event_format(BasicFormat)
        .try_init();
    Ok(())
}

fn init_last_resort_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(std::io::stderr)
        .event_format(LastResort)
        .try_init();
}

/// uvicorn's default formatter: `"%(levelprefix)s %(message)s"`.
fn uvicorn_log(level: &str, message: &str) {
    let prefix = format!("{level}:");
    eprintln!("{prefix:<9} {message}");
}

// -- Commands -----------------------------------------------------------------------

/// The parsed top-level options shared by every command.
#[derive(Debug, Clone, Default)]
pub struct FileArgs {
    pub toolkits: Option<String>,
    pub tools: Option<String>,
    pub identities: Option<String>,
    pub credentials: Option<String>,
    pub pending: Option<String>,
    pub toolkit_proposals: Option<String>,
}

impl FileArgs {
    fn from(m: &ArgMatches) -> Self {
        let get = |k: &str| m.get_one::<String>(k).cloned();
        FileArgs {
            toolkits: get("toolkits"),
            tools: get("tools"),
            identities: get("identities"),
            credentials: get("credentials"),
            pending: get("pending"),
            toolkit_proposals: get("toolkit_proposals"),
        }
    }

    fn path(&self, name: &str) -> String {
        let value = match name {
            "toolkits.yaml" => &self.toolkits,
            "tools.yaml" => &self.tools,
            "identities.yaml" => &self.identities,
            "credentials.yaml" => &self.credentials,
            "pending.yaml" => &self.pending,
            "toolkit_proposals.yaml" => &self.toolkit_proposals,
            _ => &None,
        };
        config_path(name, value.as_deref())
    }
}

/// `serve`'s own options.
#[derive(Debug, Clone)]
pub struct ServeArgs {
    pub host: String,
    pub port: i64,
    pub strict: bool,
    pub ui: bool,
    pub ui_read_only: bool,
    pub no_bootstrap: bool,
    /// `--headless` / `GATEKEEPER_HEADLESS` (1.26.0): no console and no
    /// `/admin/mcp`, enforced rather than merely not configured.
    pub headless: bool,
    pub trusted_proxies: Option<String>,
}

/// `cmd_check`: validate the configuration strictly, without starting.
pub fn cmd_check(files: &FileArgs) -> i32 {
    let loaded = (|| -> Result<_, ConfigError> {
        let tier1 = load_tier1(&files.path("toolkits.yaml"))?;
        let catalog = load_catalog(&files.path("tools.yaml"), &tier1, true)?;
        let identities = load_identities(&files.path("identities.yaml"))?;
        Ok((tier1, catalog, identities))
    })();
    let (tier1, catalog, identities) = match loaded {
        Ok(t) => t,
        Err(exc) => {
            eprintln!("ERROR: {exc}");
            return 1;
        }
    };
    println!(
        "OK: {} toolkits, {} tools, {} identities",
        tier1.toolkits.len(),
        catalog.tools.len(),
        identities.identities.len()
    );
    for identity in identities.identities.values() {
        let unknown: Vec<&String> = identity.tools.iter().filter(|t| !catalog.tools.contains_key(*t)).collect();
        if !unknown.is_empty() {
            eprintln!("WARNING: {} has rights on unknown tools: {}", repr_str(&identity.id), repr_list(&unknown));
        }
    }
    0
}

/// `cmd_init`: a runnable empty state -- no tools, one administrator.
pub fn cmd_init(config_dir_arg: Option<&str>, state_dir_arg: Option<&str>, audit_dir: Option<&str>, force: bool) -> i32 {
    let config_arg = config_dir_arg.filter(|v| !v.is_empty());
    let base = config_arg.map(str::to_string).unwrap_or_else(config_dir);
    let state = match state_dir_arg.filter(|v| !v.is_empty()) {
        Some(s) => s.to_string(),
        None if config_arg.is_none() => state_dir(),
        None => base.clone(),
    };
    let paths = init_paths(&base, &state);
    let existing: Vec<&str> =
        paths.iter().filter(|(_, p)| std::path::Path::new(p).exists()).map(|(_, p)| p.as_str()).collect();
    if !existing.is_empty() && !force {
        eprintln!(
            "Refusing to overwrite:\n  {}\nPass --force to replace them. Note that this discards the \
             current catalog and every identity, including their tokens.",
            existing.join("\n  ")
        );
        return 1;
    }
    let (token, password) = match bootstrap(&base, &state, audit_dir) {
        Ok(pair) => pair,
        Err(exc) => {
            eprintln!("Cannot write the configuration: {exc}");
            return 2;
        }
    };
    println!("Created:");
    for (_, path) in &paths {
        println!("  {path}");
    }
    println!(
        "\nNo tools, no agents. Start with --ui and create what you need;\n\
         every capability from here on is a deliberate, audited decision."
    );
    // Two lines, because there are two credentials.
    println!(
        "\nAdministrator console password for /app (shown once):\n  {password}\
         \n\nAdministrator API token for /mcp (shown once):\n  {token}"
    );
    0
}

/// `cmd_credential_key`: the credential store's master key, shown once.
pub fn cmd_credential_key() -> i32 {
    let key = generate_master_key();
    println!("Credential master key (shown once):\n  {key}");
    println!(
        "\nSet it before starting gatekeeper, as {KEY_ENV} or in a file \
         referenced by GATEKEEPER_CREDENTIAL_KEY_FILE. Losing it makes every \
         stored credential unrecoverable -- back it up separately from \
         credentials.yaml, never next to it."
    );
    0
}

/// `cmd_token`: plaintext plus hash; the plaintext appears exactly once.
pub fn cmd_token(token: Option<&str>) -> i32 {
    let token = token.filter(|t| !t.is_empty()).map(str::to_string).unwrap_or_else(generate_token);
    println!("Token (shown once, goes into the agent config.yaml):\n  {token}\n");
    println!("token_hash (goes into identities.yaml):\n  {}", hash_token(&token));
    println!(
        "token_lookup (goes into identities.yaml too -- lets authenticate() \
         avoid a per-identity scrypt scan on every /mcp request):\n  {}",
        hash_token_lookup(&token)
    );
    0
}

/// `cmd_password`: sets the console password of an identity.
pub fn cmd_password(files: &FileArgs, identity: &str, password: Option<&str>) -> i32 {
    let path = files.path("identities.yaml");
    let given = password.filter(|p| !p.is_empty());
    let password = given.map(str::to_string).unwrap_or_else(generate_password);
    // PORT NOTE: a failed write surfaces as a ConfigError (exit 1) here;
    // Python reported a raw OSError with exit 2 -- the writability check
    // before the write makes that path practically unreachable.
    if let Err(exc) = set_password_in_file(&path, identity, &password) {
        eprintln!("ERROR: {exc}");
        return 1;
    }
    println!("Console password for {} in {path} set.", repr_str(identity));
    if given.is_none() {
        println!("\nPassword (shown once):\n  {password}");
    }
    println!(
        "\nThis opens /app only. The API token of this identity is unchanged \
         and still authenticates /mcp."
    );
    0
}

/// `gatekeeper credential-set` (1.26.0): stores a credential from stdin,
/// for an instance without a console (`serve --headless`). Creates the
/// slot, or replaces the value of an existing slot of the same kind with
/// no overlap. The value is read from stdin only -- never an argument, so
/// it stays out of the shell history and the process list -- and the
/// audit record names the slot and kind, never the value.
pub fn cmd_credential_set(files: &FileArgs, name: &str, kind: &str, header: Option<&str>, header_format: Option<&str>) -> i32 {
    use std::io::Read as _;
    let tier1 = match load_tier1(&files.path("toolkits.yaml")) {
        Ok(t) => t,
        Err(exc) => {
            eprintln!("Configuration error: {exc}");
            return 2;
        }
    };
    let audit = match AuditLog::new(&tier1.audit_dir) {
        Ok(a) => Arc::new(a),
        Err(exc) => {
            eprintln!("Configuration error: cannot use the audit directory {}: {}", repr_str(&tier1.audit_dir), os_error(&exc, &tier1.audit_dir));
            return 2;
        }
    };
    let mut value = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut value) {
        eprintln!("ERROR: cannot read the value from stdin: {e}");
        return 1;
    }
    // One trailing newline is what `echo` or a heredoc adds, not part of it.
    let value = value.strip_suffix('\n').map(|v| v.strip_suffix('\r').unwrap_or(v)).unwrap_or(&value);
    if value.is_empty() {
        eprintln!("ERROR: no value on stdin. Pipe it in: gatekeeper credential-set --name {name} --kind {kind} < file");
        return 1;
    }
    let store = CredentialStore::new(&files.path("credentials.yaml"), audit);
    let existing = match store.raw() {
        Ok(section) => section.get(name).and_then(|s| s.get("kind")).and_then(serde_json::Value::as_str).map(str::to_string),
        Err(exc) => {
            eprintln!("ERROR: {exc}");
            return 1;
        }
    };
    let rev = store.revision();
    let outcome = match existing.as_deref() {
        None => store.create(name, kind, value, header, None, header_format, "cli", &rev).map(|_| "created"),
        Some(k) if k == kind => store.rotate(name, value, 0, "cli", &rev).map(|_| "replaced the value of"),
        Some(k) => {
            eprintln!(
                "ERROR: credential {} exists with kind {}, not {}. Delete it first to change its kind.",
                repr_str(name),
                repr_str(k),
                repr_str(kind)
            );
            return 1;
        }
    };
    match outcome {
        Ok(verb) => {
            println!("Credential {}: {verb} it in {}.", repr_str(name), files.path("credentials.yaml"));
            println!("Send the running server SIGHUP (or restart it) so its output masking includes the new value.");
            0
        }
        Err(exc) => {
            eprintln!("ERROR: {exc}");
            1
        }
    }
}

/// `gatekeeper openapi` (Python's `python -m gatekeeper.api`): prints the
/// console's OpenAPI schema, the committed `frontend/openapi.json`.
pub fn cmd_openapi() -> i32 {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    if out.write_all(crate::api::openapi_json().as_bytes()).and_then(|_| out.flush()).is_err() {
        return 1;
    }
    0
}

// -- serve ---------------------------------------------------------------------------

/// The configuration paths SIGHUP reloads.
#[derive(Debug, Clone)]
struct ReloadPaths {
    toolkits: String,
    tools: String,
    identities: String,
}

/// Everything the synchronous phase hands to the runtime.
struct Prepared {
    options: AppOptions,
    reload: ReloadPaths,
    trusted_proxies: Option<Vec<String>>,
    credentials: Arc<CredentialStore>,
}

/// `cmd_serve`. Returns the exit code.
pub fn cmd_serve(files: &FileArgs, args: &ServeArgs) -> i32 {
    if let Err(message) = init_basic_logging() {
        eprintln!("{message}");
        return 1;
    }
    let prepared = match prepare_serve(files, args) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let code = runtime.block_on(run_server(prepared, args.host.clone(), args.port));
    // Whatever is still running (a stream past the grace period) is
    // cancelled with the runtime.
    runtime.shutdown_timeout(Duration::from_millis(100));
    code
}

/// The synchronous startup sequence, in Python's order. `Err` carries the
/// exit code after the reason was printed.
fn prepare_serve(files: &FileArgs, args: &ServeArgs) -> Result<Prepared, i32> {
    // Headless: the configuration is what the deployment mounted, and
    // nothing at runtime -- no console, no agent proposal -- can change it.
    // A console flag next to it is a contradiction, refused rather than
    // resolved either way.
    let headless = args.headless || env_flag("GATEKEEPER_HEADLESS");
    if headless {
        let console: Vec<&str> = [
            (args.ui, "--ui"),
            (env_flag("GATEKEEPER_UI"), "GATEKEEPER_UI"),
            (args.ui_read_only, "--ui-read-only"),
            (env_flag("GATEKEEPER_UI_READ_ONLY"), "GATEKEEPER_UI_READ_ONLY"),
        ]
        .into_iter()
        .filter_map(|(set, name)| set.then_some(name))
        .collect();
        if !console.is_empty() {
            eprintln!(
                "Configuration error: headless mode serves no console, but {} is set. \
                 Remove it, or drop --headless / GATEKEEPER_HEADLESS.",
                console.join(" and ")
            );
            return Err(2);
        }
    }
    let args = &ServeArgs {
        // A headless instance never invents a configuration of its own, and
        // a tool its Tier 1 refuses is a broken deployment, not one to run
        // with that tool quietly disabled.
        strict: args.strict || headless,
        no_bootstrap: args.no_bootstrap || headless,
        ..args.clone()
    };

    // First start: a mounted, empty directory suffices.
    if !(args.no_bootstrap || env_flag("GATEKEEPER_NO_BOOTSTRAP")) {
        if let Some(problem) = bootstrap_on_first_start(&config_dir(), &state_dir()) {
            // Do not continue: the loader would report "not found" and name
            // the wrong cause.
            eprintln!("{problem}");
            return Err(2);
        }
    }

    let loaded = (|| -> Result<_, ConfigError> {
        let tier1 = load_tier1(&files.path("toolkits.yaml"))?;
        let catalog = load_catalog(&files.path("tools.yaml"), &tier1, args.strict)?;
        let identities = load_identities(&files.path("identities.yaml"))?;
        Ok((tier1, catalog, identities))
    })();
    let (tier1, catalog, identities) = match loaded {
        Ok(t) => t,
        Err(exc) => {
            eprintln!("Configuration error: {exc}");
            return Err(2);
        }
    };

    // A `file` toolkit with `run_as` performs its operations as somebody
    // other than this process: deliberate and deploy-time, but never
    // invisible.
    let mut run_as_toolkits: Vec<String> = tier1
        .toolkits
        .iter()
        .filter(|(_, t)| t.run_as.as_deref().is_some_and(|r| !r.is_empty()))
        .map(|(n, _)| n.clone())
        .collect();
    run_as_toolkits.sort();
    let run_as_of = |name: &str| tier1.toolkits[name].run_as.clone().unwrap_or_default();
    if configured_target().is_some() && run_as_toolkits.is_empty() {
        // The drop ran before the configuration was read and kept the two
        // capabilities on the chance a toolkit wants them. None does.
        if let Err(e) = discard_capabilities() {
            eprintln!("{e}");
            return Err(1);
        }
        tracing::info!(
            "No toolkit declares 'run_as', so the capabilities kept across \
             the startup drop were handed back. This process ({}) now holds \
             none.",
            whoami()
        );
    }
    for name in &run_as_toolkits {
        tracing::warn!(
            "Toolkit {}: file operations run as {}, not as this process ({}).",
            repr_str(name),
            repr_str(&run_as_of(name)),
            whoami()
        );
    }
    if !run_as_toolkits.is_empty() {
        // Checked, not declared: whether the container can actually do it.
        let caps = effective_capabilities();
        let state = match caps {
            None => "unreadable".to_string(),
            Some(c) => format!("CapEff={c:016x}"),
        };
        if can_change_user() {
            tracing::info!(
                "run_as is usable: this process ({}, {}) holds CAP_SETUID and CAP_SETGID.",
                whoami(),
                state
            );
            // Usable is not useful: uid 0 without CAP_DAC_OVERRIDE is checked
            // against file modes like anyone else.
            let server_bypasses = bypasses_file_permissions();
            let child_bypasses = child_bypasses_file_permissions();
            if server_bypasses == Some(false) && child_bypasses == Some(false) {
                for name in &run_as_toolkits {
                    let Ok((target, _, _)) = resolve_run_as(&run_as_of(name)) else { continue };
                    if target != 0 {
                        continue;
                    }
                    tracing::warn!(
                        "Toolkit {} uses 'run_as: {}', but neither this \
                         process nor a run_as child holds CAP_DAC_OVERRIDE \
                         or CAP_DAC_READ_SEARCH -- so uid 0 is checked \
                         against file permissions like any other user and \
                         cannot read a file owned by somebody else with \
                         mode 0600. To let the child read such files, add \
                         'DAC_OVERRIDE,DAC_READ_SEARCH' to cap_add AND to \
                         GATEKEEPER_KEEP_CAPS (so they survive the startup \
                         drop into the child's ambient set). Alternatively, \
                         name the owning uid: 'run_as: \"<uid>:<gid>\"'. \
                         See docs/DEPLOYMENT.md.",
                        repr_str(name),
                        run_as_of(name)
                    );
                }
            }
        } else {
            // SAFETY: geteuid has no preconditions.
            let is_root = unsafe { libc::geteuid() } == 0;
            let explanation = if !is_root {
                // A process at 568 was *started* at 568: gatekeeper never
                // changes its own uid outside the opt-in drop.
                "This process is not root. gatekeeper never changes its \
                 own uid, so it was started this way: the image default \
                 is 'USER 568:568' and the compose 'user:' did not reach \
                 this container. Check for a second 'user:' key in the \
                 service (compose keeps only one), a container that was \
                 restarted rather than recreated, or a compose file at a \
                 different path than the one edited. What the container \
                 actually got: docker inspect -f \
                 '{{.Config.User}} {{.HostConfig.CapAdd}}' <container>."
            } else {
                "This process is root, so 'user:' is in effect and the \
                 capabilities are what is missing: 'cap_drop: ALL' took \
                 effect and a matching 'cap_add: [SETUID, SETGID]' did \
                 not."
            };
            tracing::error!(
                "run_as is NOT usable: this process ({}, {}) holds no privilege \
                 to change user, so every call on {} will fail rather than fall \
                 back. Both halves are needed -- 'user: \"0:0\"' AND \
                 'cap_add: [SETUID, SETGID]'. {} See docs/DEPLOYMENT.md.",
                whoami(),
                state,
                run_as_toolkits.iter().map(|n| repr_str(n)).collect::<Vec<_>>().join(", "),
                explanation
            );
            if require_run_as() {
                // Opt-in: removes the healthy-looking-but-broken state.
                eprintln!(
                    "Configuration error: GATEKEEPER_REQUIRE_RUN_AS is set and \
                     this process ({}, {state}) cannot assume another \
                     user. Refusing to start with a run_as toolkit that could \
                     not work. See docs/DEPLOYMENT.md.",
                    whoami()
                );
                return Err(2);
            }
        }
    }

    // Ambient capabilities are stripped per spawn (`__unpriv`); one line at
    // startup says so.
    let ambient = capability_sets().and_then(|s| s.get("CapAmb").copied()).unwrap_or(0);
    if ambient != 0 {
        tracing::info!(
            "This process holds ambient capabilities (CapAmb={:016x}), so it \
             was started unprivileged but kept them across its own drop. \
             'local' toolkit binaries are run through a wrapper that clears \
             them first, and refuses to run the binary if that fails -- only \
             the run_as helper keeps them. See docs/DEPLOYMENT.md.",
            ambient
        );
    }

    // Without an audit log, startup is refused.
    let audit = match AuditLog::with_options(
        &tier1.audit_dir,
        u64::try_from(tier1.audit_max_bytes).unwrap_or(0),
        usize::try_from(tier1.audit_keep_files).unwrap_or(0),
        Some(Arc::new(Redactor::new())),
    ) {
        Ok(a) => Arc::new(a),
        Err(exc) => {
            // PORT NOTE: the path in the OSError text is the audit directory
            // itself; Python named whichever level `os.makedirs` failed on.
            let who = whoami();
            eprintln!(
                "Configuration error: cannot use the audit directory {}: {}\n\
                 This process runs as {who}. Either mount a directory it \
                 owns there, or point 'audit.dir' in toolkits.yaml at one:\n  \
                 chown -R {who} <the directory mounted at {}>",
                repr_str(&tier1.audit_dir),
                os_error(&exc, &tier1.audit_dir),
                tier1.audit_dir
            );
            return Err(2);
        }
    };

    let credentials_path = files.path("credentials.yaml");
    let credentials = Arc::new(CredentialStore::new(&credentials_path, audit.clone()));
    // Forces a load and, if any credential exists, a decrypt: a wrong master
    // key or a corrupt file fails startup here, not on the first call.
    match credentials.plaintext_values_for_masking() {
        Ok(values) => audit.set_secrets(values),
        Err(exc) => {
            eprintln!("Configuration error: {credentials_path}: {exc}");
            return Err(2);
        }
    }

    // A `credential:` naming a credential the store does not have: a
    // warning, not an abort.
    let references = tier1.credential_references();
    let known: std::collections::HashSet<String> =
        credentials.names(None).unwrap_or_default().into_iter().map(|m| m.name).collect();
    let mut dangling: Vec<&String> = references.keys().filter(|n| !known.contains(*n)).collect();
    dangling.sort();
    if !dangling.is_empty() {
        let detail: Vec<String> = dangling
            .iter()
            .map(|name| {
                let mut users = references[*name].clone();
                users.sort();
                format!("{name} (used by {})", users.join(", "))
            })
            .collect();
        tracing::warn!(
            "{} credential(s) referenced by toolkits.yaml are missing from {}: \
             {}. Calls through them will be refused with 'is not configured \
             yet' until a value is entered -- in the console at /app/credentials, \
             or by approving the matching request in /app/requests.",
            dangling.len(),
            credentials_path,
            detail.join("; ")
        );
    }

    // The same failure shape one field over: a `local` toolkit naming a
    // binary this image does not contain.
    let unrunnable = tier1.missing_local_binaries();
    if !unrunnable.is_empty() {
        let mut entries: Vec<(&String, &Vec<String>)> = unrunnable.iter().collect();
        entries.sort();
        tracing::warn!(
            "{} local toolkit(s) declare binaries this container does not \
             have: {}. Their tools stay listed but fail on call. Either \
             install the binary in the image, or -- for anything that is \
             host state rather than a program (ZFS, pools, host processes) \
             -- move the toolkit to the 'truenas' or 'ssh' executor, which \
             is where it is reachable from (REQUIREMENTS.md FR-8.4).",
            unrunnable.len(),
            entries.iter().map(|(n, p)| format!("{n} ({})", p.join(", "))).collect::<Vec<_>>().join("; ")
        );
    }

    let identities: SharedIdentities = Arc::new(RwLock::new(identities));
    let service = Arc::new(Service::new(ServiceOptions {
        tier1,
        catalog,
        audit: audit.clone(),
        credentials: Some(credentials.clone()),
        docker_host: std::env::var("DOCKER_HOST").ok(),
        // The same store the auth middleware holds -- the config store
        // mutates it in place.
        identities: Some(identities.clone()),
    }));

    {
        let audit = audit.clone();
        let store = Arc::downgrade(&credentials);
        let service = Arc::downgrade(&service);
        credentials.set_on_change(Some(Arc::new(move || {
            if let Some(store) = store.upgrade() {
                if let Ok(values) = store.plaintext_values_for_masking() {
                    audit.set_secrets(values);
                }
            }
            if let Some(service) = service.upgrade() {
                // A rotated credential must not keep serving stale material
                // from any executor cache.
                service.invalidate_docker_tls_cache();
                service.invalidate_google_token_cache();
                service.invalidate_microsoft_token_cache();
            }
        })));
    }

    log_startup(&service, &identities);

    let reload = ReloadPaths {
        toolkits: files.path("toolkits.yaml"),
        tools: files.path("tools.yaml"),
        identities: files.path("identities.yaml"),
    };

    let ui_enabled = !headless && (args.ui || env_flag("GATEKEEPER_UI"));
    if headless {
        tracing::info!(
            "Headless: no console at /app and no admin MCP endpoint at /admin/mcp; \
             the configuration changes only through its files (SIGHUP reloads them)"
        );
    }
    if ui_enabled {
        let identities_path = files.path("identities.yaml");
        if !identities.read().identities.values().any(|i| UI_ROLES.contains(&i.role.as_str())) {
            // Fail closed: a console nobody can sign in to is an open
            // surface with no use.
            eprintln!(
                "Configuration error: --ui requires at least one identity with \
                 role: viewer or role: admin in identities.yaml."
            );
            return Err(2);
        }
        if let Some(problem) = ensure_console_passwords(&identities_path, &identities) {
            eprintln!("{problem}");
            return Err(2);
        }
        assert!(has_ui_identity(&identities.read()));
    }

    let mut store = None;
    let mut pending = None;
    let mut toolkit_proposals = None;
    if ui_enabled {
        let read_only = args.ui_read_only || env_flag("GATEKEEPER_UI_READ_ONLY");
        if read_only {
            tracing::info!("Console enabled at /app (read-only, writes disabled by flag)");
        } else {
            let config_store = Arc::new(ConfigStore::new(
                service.clone(),
                identities.clone(),
                audit.clone(),
                &files.path("tools.yaml"),
                &files.path("identities.yaml"),
            ));
            // Proposals from /admin/mcp a human has not yet decided.
            pending = Some(Arc::new(PendingStore::new(&files.path("pending.yaml"), audit.clone())));
            // Toolkit proposals touch Tier 1: their own store and review tab.
            toolkit_proposals = Some(Arc::new(ToolkitProposalStore::new(
                &files.path("toolkit_proposals.yaml"),
                audit.clone(),
                service.clone(),
                &files.path("toolkits.yaml"),
                &files.path("tools.yaml"),
                &files.path("identities.yaml"),
            )));
            let mut stuck: Vec<String> = config_store
                .writability()
                .iter()
                .filter(|(_, ok)| !ok.as_bool().unwrap_or(false))
                .map(|(n, _)| n.clone())
                .collect();
            stuck.sort();
            if !stuck.is_empty() {
                // No abort: reading remains useful. But it must be in the log.
                tracing::warn!(
                    "Console writes will be refused: {} not writable (read-only mount?)",
                    stuck.iter().map(|n| format!("{n}.yaml")).collect::<Vec<_>>().join(", ")
                );
            }
            tracing::info!(
                "Console enabled at /app (admins may write; {} admin(s) configured); \
                 admin MCP endpoint enabled at /admin/mcp",
                identities.read().identities.values().filter(|i| i.role == "admin").count()
            );
            if !credentials.writable() {
                tracing::warn!(
                    "Credential writes will be refused: credentials.yaml not \
                     writable (read-only mount?)"
                );
            }
            store = Some(config_store);
        }
    }

    // `forwarded_allow_ips`: uvicorn's own default (127.0.0.1) when unset.
    let trusted_proxies = args
        .trusted_proxies
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|v| v.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect());

    let sighup_credentials = credentials.clone();
    let credentials_for_app = store.as_ref().map(|_| credentials.clone());
    let options = AppOptions {
        service,
        identities,
        audit,
        host: args.host.clone(),
        ui: ui_enabled,
        store,
        credentials: credentials_for_app,
        pending,
        toolkit_proposals,
    };
    Ok(Prepared { options, reload, trusted_proxies, credentials: sighup_credentials })
}

/// uvicorn's access log line, at response start.
fn access_log(in_flight: Arc<AtomicUsize>) -> impl Fn(Request, Next) -> futures::future::BoxFuture<'static, Response> + Clone {
    move |request: Request, next: Next| {
        let in_flight = in_flight.clone();
        Box::pin(async move {
            let client = client_addr(request.extensions()).map(|c| format!("{}:{}", c.host, c.port)).unwrap_or_default();
            let method = request.method().to_string();
            let target = request.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
            let version = match request.version() {
                http::Version::HTTP_09 => "0.9",
                http::Version::HTTP_10 => "1.0",
                http::Version::HTTP_2 => "2",
                http::Version::HTTP_3 => "3",
                _ => "1.1",
            };
            in_flight.fetch_add(1, Ordering::SeqCst);
            let response = next.run(request).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            let status = response.status();
            let phrase = status.canonical_reason().unwrap_or("");
            println!("INFO:     {client} - \"{method} {target} HTTP/{version}\" {} {phrase}", status.as_u16());
            response
        })
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

/// uvicorn's `host:port` display: brackets around an IPv6 address.
fn display_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn run_server(prepared: Prepared, host: String, port: i64) -> i32 {
    let Prepared { options, reload, trusted_proxies, credentials } = prepared;
    let service = options.service.clone();
    let app = match build_app(options) {
        Ok(app) => app,
        Err(message) => {
            eprintln!("{message}");
            return 1;
        }
    };

    // SIGHUP reloads all three configuration files without a restart, and
    // picks up credentials another process wrote (`credential-set`).
    {
        let service = service.clone();
        if let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            tokio::spawn(async move {
                while hup.recv().await.is_some() {
                    let service = service.clone();
                    let paths = reload.clone();
                    let error = tokio::task::spawn_blocking(move || {
                        service.reload_config(&paths.toolkits, &paths.tools, &paths.identities)
                    })
                    .await
                    .unwrap_or_else(|e| Some(e.to_string()));
                    if let Some(error) = error {
                        tracing::error!("SIGHUP reload failed: {}", error);
                    }
                    let credentials = credentials.clone();
                    let _ = tokio::task::spawn_blocking(move || credentials.notify_changed()).await;
                    // On success, reload_config has already logged.
                }
            });
        }
    }

    // uvicorn's composition: its proxy headers outermost, its access log
    // on the rewritten scope, then X-Real-IP, then the app.
    let in_flight = Arc::new(AtomicUsize::new(0));
    let app: Router = server::real_ip(app, trusted_proxies.clone());
    let app = app.layer(middleware::from_fn(access_log(in_flight.clone())));
    let app = server::uvicorn_proxy_headers(app, trusted_proxies);

    let pid = std::process::id();
    uvicorn_log("INFO", &format!("Started server process [{pid}]"));
    uvicorn_log("INFO", "Waiting for application startup.");
    uvicorn_log("INFO", "Application startup complete.");

    let bind = match u16::try_from(port) {
        Ok(p) => tokio::net::TcpListener::bind((host.as_str(), p)).await.map_err(|e| (e, p)),
        Err(_) => Err((std::io::Error::other("port must be 0-65535."), 0)),
    };
    let listener = match bind {
        Ok(l) => l,
        Err((e, p)) => {
            let message = match e.raw_os_error() {
                Some(code) => format!(
                    "[Errno {code}] error while attempting to bind on address ({}, {p}): {}",
                    repr_str(&host),
                    os_error(&e, "").splitn(2, "] ").nth(1).unwrap_or("").to_lowercase()
                ),
                None => e.to_string(),
            };
            uvicorn_log("ERROR", &message);
            uvicorn_log("INFO", "Waiting for application shutdown.");
            uvicorn_log("INFO", "Application shutdown complete.");
            return 1;
        }
    };
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    uvicorn_log("INFO", &format!("Uvicorn running on http://{} (Press CTRL+C to quit)", display_addr(&host, bound)));

    let stopping = Arc::new(tokio::sync::Notify::new());
    let notify = stopping.clone();
    let serving = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            uvicorn_log("INFO", "Shutting down");
            notify.notify_one();
        });
    let grace = async {
        stopping.notified().await;
        tokio::time::sleep(Duration::from_secs(SHUTDOWN_GRACE_SECONDS)).await;
    };
    tokio::select! {
        result = serving => {
            if let Err(e) = result {
                uvicorn_log("ERROR", &e.to_string());
            }
        }
        _ = grace => {
            // PORT NOTE: uvicorn counts its request tasks; this counts the
            // requests whose handler had not yet produced a response.
            uvicorn_log(
                "ERROR",
                &format!(
                    "Cancel {} running task(s), timeout graceful shutdown exceeded",
                    in_flight.load(Ordering::SeqCst)
                ),
            );
        }
    }
    // Long-lived listen streams end with the runtime.
    service.catalog_notifier.close_listen_streams();
    uvicorn_log("INFO", "Waiting for application shutdown.");
    uvicorn_log("INFO", "Application shutdown complete.");
    uvicorn_log("INFO", &format!("Finished server process [{pid}]"));
    0
}

// -- Argument parsing ----------------------------------------------------------------

/// A default computed at startup, for clap's `&'static str` defaults (the
/// parser is built once per process).
fn leak(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

/// The parser. Defaults that Python read from the environment while
/// building its parser are read here too, so `--help` shows them alike.
pub fn command() -> Result<Command, String> {
    let host_default = std::env::var("GATEKEEPER_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port_raw = std::env::var("GATEKEEPER_PORT").unwrap_or_else(|_| "8080".into());
    let Some(port_default) = crate::release_notes::py_int(&port_raw) else {
        return Err(format!("ValueError: invalid literal for int() with base 10: {}", repr_str(&port_raw)));
    };
    let trusted_default = std::env::var("GATEKEEPER_TRUSTED_PROXIES").ok();

    let opt = |name: &'static str, id: &'static str| Arg::new(id).long(name).num_args(1).value_name(leak(id.to_uppercase()));
    let flag = |name: &'static str, help: &'static str| Arg::new(name).long(name).action(ArgAction::SetTrue).help(help);

    let mut trusted = Arg::new("trusted_proxies").long("trusted-proxies").num_args(1).value_name("TRUSTED_PROXIES").hide_default_value(true).help(
        "Comma-separated IPs/CIDRs of reverse proxies allowed to set \
         X-Forwarded-For/X-Forwarded-Proto, or X-Real-IP when no \
         X-Forwarded-For is sent (or '*' to trust any peer -- \
         only inside a network gatekeeper does not share with anything \
         untrusted). Unset means uvicorn's own default: only a proxy \
         on 127.0.0.1 is trusted, which a container's own reverse-proxy \
         sidecar is not -- see docs/DEPLOYMENT.md. Without this, the \
         console's per-client login throttle keys on the proxy's \
         address for every visitor, the audit log records the proxy \
         as the actor of every UI action, and the session cookie's \
         Secure flag never activates behind TLS termination.",
    );
    if let Some(d) = trusted_default {
        trusted = trusted.default_value(leak(d));
    }

    let serve = Command::new("serve")
        .about("Start the server")
        .arg(Arg::new("host").long("host").num_args(1).value_name("HOST").hide_default_value(true).default_value(leak(host_default)))
        .arg(
            Arg::new("port").value_name("PORT").hide_default_value(true)
                .long("port")
                .num_args(1)
                .value_parser(clap::value_parser!(i64))
                .default_value(leak(port_default.to_string())),
        )
        .arg(flag("strict", "Abort on a Tier 1 violation instead of disabling the tool"))
        .arg(flag("ui", "Serve the operations console at /app (needs role: viewer or admin)"))
        .arg(
            Arg::new("ui_read_only")
                .long("ui-read-only")
                .action(ArgAction::SetTrue)
                .help("Serve the console without any write functions, whatever the roles say"),
        )
        .arg(
            Arg::new("headless")
                .long("headless")
                .action(ArgAction::SetTrue)
                .help(
                    "No console and no /admin/mcp, refusing --ui; implies --strict and --no-bootstrap \
                     (also GATEKEEPER_HEADLESS)",
                ),
        )
        .arg(
            Arg::new("no_bootstrap")
                .long("no-bootstrap")
                .action(ArgAction::SetTrue)
                .help("Never create configuration on start; fail if it is missing"),
        )
        .arg(trusted);

    let init = Command::new("init")
        .about("Create an empty, runnable configuration and one administrator")
        .arg(opt("config-dir", "config_dir").help("Where toolkits.yaml goes (default: GATEKEEPER_CONFIG_DIR)"))
        .arg(opt("state-dir", "state_dir").help(
            "Where tools.yaml and identities.yaml go, must be writable \
             (default: GATEKEEPER_STATE_DIR, else the config directory)",
        ))
        .arg(
            opt("audit-dir", "audit_dir")
                .help(format!("Where the audit log goes (default: ${AUDIT_DIR_ENV}, else <state-dir>/logs)")),
        )
        .arg(flag("force", "Overwrite existing files"));

    let token = Command::new("token")
        .about("Generate an API token")
        .arg(opt("token", "token").help("Hash an existing token instead of generating one"));

    let password = Command::new("password")
        .about("Set the console password of an identity (/app sign-in)")
        .arg(opt("identity", "identity").required(true).help("Which identity gets the password"))
        .arg(opt("password", "password").help(
            "Use this password instead of generating one. Beware the shell \
             history -- omit it and gatekeeper generates one.",
        ));

    let credential_set = Command::new("credential-set")
        .about("Store a credential read from stdin (for a server without the console)")
        .arg(opt("name", "name").required(true).help("The slot name a toolkit's 'credential:' refers to"))
        .arg(opt("kind", "kind").required(true).help("Credential kind, e.g. ws_api_key, bearer, api_key_header"))
        .arg(opt("header", "header").help("Header or query parameter name, for api_key_header/url_query"))
        .arg(opt("header-format", "header_format").help("Header value format, e.g. 'Bearer {value}'"));

    Ok(Command::new("gatekeeper")
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .arg(opt("toolkits", "toolkits"))
        .arg(opt("tools", "tools"))
        .arg(opt("identities", "identities"))
        .arg(opt("credentials", "credentials"))
        .arg(opt("pending", "pending"))
        .arg(opt("toolkit-proposals", "toolkit_proposals"))
        .subcommand(serve)
        .subcommand(Command::new("check").about("Validate the configuration"))
        .subcommand(init)
        .subcommand(credential_set)
        .subcommand(Command::new("credential-key").about("Generate the credential store's master key"))
        .subcommand(token)
        .subcommand(password)
        // Python's `python -m gatekeeper.artifacts` and `-m gatekeeper.api`:
        // build-time tools, not part of the operator's CLI.
        .subcommand(
            Command::new("build-artifacts")
                .hide(true)
                .disable_help_flag(true)
                .arg(Arg::new("args").num_args(0..).allow_hyphen_values(true).trailing_var_arg(true)),
        )
        .subcommand(Command::new("openapi").hide(true)))
}

/// Runs the CLI on `argv` (program name first). Returns the exit code.
pub fn run(argv: Vec<String>) -> i32 {
    // Before argument parsing, before logging, before any file is touched:
    // a `gatekeeper init` that ran as root would leave root-owned config
    // behind that the dropped-to user cannot rewrite.
    if let Some(target) = configured_target() {
        if let Err(exc) = drop_privileges(&target) {
            // Never continue as root having been told to give it up.
            eprintln!("Configuration error: {exc}");
            return 2;
        }
    }

    let command = match command() {
        Ok(c) => c,
        Err(message) => {
            eprintln!("{message}");
            return 1;
        }
    };
    let matches = match command.try_get_matches_from(&argv) {
        Ok(m) => m,
        Err(e) => {
            let _ = e.print();
            return e.exit_code();
        }
    };
    let files = FileArgs::from(&matches);
    let Some((name, sub)) = matches.subcommand() else { return 2 };
    if name != "serve" {
        init_last_resort_logging();
    }
    let get = |k: &str| sub.get_one::<String>(k).map(String::as_str);
    match name {
        "serve" => {
            let args = ServeArgs {
                host: get("host").unwrap_or("0.0.0.0").to_string(),
                port: sub.get_one::<i64>("port").copied().unwrap_or(8080),
                strict: sub.get_flag("strict"),
                ui: sub.get_flag("ui"),
                ui_read_only: sub.get_flag("ui_read_only"),
                no_bootstrap: sub.get_flag("no_bootstrap"),
                headless: sub.get_flag("headless"),
                trusted_proxies: get("trusted_proxies").map(str::to_string),
            };
            cmd_serve(&files, &args)
        }
        "check" => cmd_check(&files),
        "init" => cmd_init(get("config_dir"), get("state_dir"), get("audit_dir"), sub.get_flag("force")),
        "credential-key" => cmd_credential_key(),
        "token" => cmd_token(get("token")),
        "credential-set" => cmd_credential_set(
            &files,
            get("name").unwrap_or_default(),
            get("kind").unwrap_or_default(),
            get("header"),
            get("header_format"),
        ),
        "password" => cmd_password(&files, get("identity").unwrap_or_default(), get("password")),
        "build-artifacts" => {
            let rest: Vec<String> = sub.get_many::<String>("args").map(|v| v.cloned().collect()).unwrap_or_default();
            crate::artifacts::main("gatekeeper build-artifacts", &rest)
        }
        "openapi" => cmd_openapi(),
        _ => 2,
    }
}

/// The binary's entry point after the hidden entries.
pub fn main() -> i32 {
    let argv: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    run(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_follow_logging_names() {
        assert!(parse_level("INFO").is_ok());
        assert!(parse_level("WARNING").is_ok());
        assert_eq!(parse_level("info").unwrap_err(), "ValueError: Unknown level: 'info'");
    }

    #[test]
    fn uvicorn_prefix_is_padded() {
        assert_eq!(format!("{:<9} x", "INFO:"), "INFO:     x");
        assert_eq!(format!("{:<9} x", "ERROR:"), "ERROR:    x");
    }

    #[test]
    fn ipv6_addresses_are_bracketed() {
        assert_eq!(display_addr("::", 80), "[::]:80");
        assert_eq!(display_addr("0.0.0.0", 80), "0.0.0.0:80");
    }

    #[test]
    fn the_parser_is_well_formed() {
        command().unwrap().debug_assert();
    }
}
