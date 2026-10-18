//! The call path (port of `service.py`, REQUIREMENTS.md §2).
//!
//! Every call passes through the same layers in the same order:
//! authentication, authorization, registry, validation, argv construction,
//! executor, audit. Nothing bypasses this chain -- there is exactly one way
//! to execution.
//!
//! Shared state: a [`Service`] lives behind an `Arc` and is used from many
//! tokio tasks at once. What the stores swap at runtime (Tier 1, the
//! catalog, the rate limiter) sits in `RwLock<Arc<_>>` cells: a call takes
//! a snapshot at its start and is never torn by a concurrent swap.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde_json::{Map, Value};

use crate::artifacts::ArtifactStore;
use crate::audit::{AuditLog, CallRecord};
use crate::catalog::{load_catalog, Catalog, ToolDef};
use crate::credentials::CredentialStore;
use crate::errors::{ConfigError, DenialReason, Denied};
use crate::execute::{self, ExecResult, Redact, ResourceLocks, OUTCOME_OK};
use crate::identity::{load_identities, Identity, IdentityStore};
use crate::mcp::CatalogNotifier;
use crate::messages::MessageStore;
use crate::oauth::{google_token_env, microsoft_token_env, TokenDirCache};
use crate::pyfmt::repr_str;
use crate::ratelimit::RateLimiter;
use crate::tier1::{is_runnable, load_tier1, Tier1, Toolkit};
use crate::validate;

/// The live identity store, shared by reference: the config store replaces
/// its contents in place, and every holder sees the change on its next
/// read.
pub type SharedIdentities = Arc<RwLock<IdentityStore>>;

/// What an agent sees of a tool.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolView {
    pub name: String,
    pub title: String,
    pub description: String,
    pub input_schema: Value,
    pub read_only: bool,
    pub idempotent: bool,
}

/// Why [`Service::call`] did not return a result.
#[derive(Debug, Clone, PartialEq)]
pub enum CallError {
    /// A rejection. Denials raised before the executor runs are audited;
    /// one raised by the `docker`/`local` executor itself (binary missing)
    /// propagates unaudited, exactly as in Python.
    Denied(Denied),
    /// Anything Python would have raised as a non-`Denied` exception
    /// (an audit log that cannot be written, an executor the dispatch does
    /// not know).
    Internal(String),
    /// A `ConfigError` escaping an executor (`http`/`truenas`/`ssh`) --
    /// what escaped Python's `run()` as an exception.
    Config(ConfigError),
}

impl From<ConfigError> for CallError {
    fn from(e: ConfigError) -> Self {
        CallError::Config(e)
    }
}

impl From<Denied> for CallError {
    fn from(d: Denied) -> Self {
        CallError::Denied(d)
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Denied(d) => d.fmt(f),
            CallError::Internal(m) => f.write_str(m),
            CallError::Config(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for CallError {}

/// Constructor arguments (Python's keyword arguments).
/// The longest unknown tool name kept as sent (audit record, denial).
const MAX_UNKNOWN_TOOL_CHARS: usize = 200;

/// The metrics series every unknown tool name is counted under.
pub const UNKNOWN_TOOL_METRIC: &str = "<unknown>";

/// A Prometheus label value, escaped (`\\`, `\"`, `\n`).
fn label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

pub struct ServiceOptions {
    pub tier1: Tier1,
    pub catalog: Catalog,
    pub audit: Arc<AuditLog>,
    pub credentials: Option<Arc<CredentialStore>>,
    pub docker_host: Option<String>,
    pub identities: Option<SharedIdentities>,
}

/// Writes `content` to `path` with 0600 permissions from the start -- no
/// window where the file exists world-readable before a later chmod.
fn write_private_file(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file =
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    file.write_all(content.as_bytes())
}

fn unavailable(detail: impl Into<String>) -> Denied {
    Denied::new(DenialReason::CredentialUnavailable, detail)
}

pub struct Service {
    tier1: RwLock<Arc<Tier1>>,
    catalog: RwLock<Arc<Catalog>>,
    limiter: RwLock<Arc<RateLimiter>>,
    pub audit: Arc<AuditLog>,
    /// The live identity store, when the caller has one. Used for exactly
    /// one thing: checking that a message's recipient is a configured
    /// identity (`validate::build_agent_call`). `None` (a bare `Service` in
    /// a test, or `gatekeeper check`) means the recipient is checked for
    /// shape only.
    pub identities: Option<SharedIdentities>,
    /// Announces `notifications/tools/list_changed` to already-connected
    /// agents. Owned here because the writes that change the catalog
    /// (`store::ConfigStore`, `reload_config`) reach the `Service`.
    pub catalog_notifier: CatalogNotifier,
    pub credentials: Option<Arc<CredentialStore>>,
    pub docker_host: Option<String>,
    pub locks: ResourceLocks,
    metrics: Mutex<BTreeMap<(String, String, String), u64>>,
    executor_ready: Mutex<BTreeMap<String, bool>>,
    /// credential name -> private temp dir holding its materialized
    /// cert.pem/key.pem/ca.pem, for a TLS-secured docker destination
    /// (FR-8.3g). Cleared on credential rotation.
    docker_tls_dirs: Mutex<HashMap<String, PathBuf>>,
    google_token_dirs: TokenDirCache,
    microsoft_token_dirs: TokenDirCache,
    /// mailbox path -> the `MessageStore` that owns it. Keyed on the path,
    /// so two `agent` toolkits pointed at one file share one lock.
    mailboxes: Mutex<HashMap<String, Arc<MessageStore>>>,
    /// The image's release-bound artifacts, loaded on first use.
    artifact_store: RwLock<Option<Arc<ArtifactStore>>>,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service").field("docker_host", &self.docker_host).finish()
    }
}

impl Service {
    pub fn new(opts: ServiceOptions) -> Service {
        let limiter = RateLimiter::new(opts.tier1.rate_limits.clone());
        Service {
            tier1: RwLock::new(Arc::new(opts.tier1)),
            catalog: RwLock::new(Arc::new(opts.catalog)),
            limiter: RwLock::new(Arc::new(limiter)),
            audit: opts.audit,
            identities: opts.identities,
            catalog_notifier: CatalogNotifier::new(),
            credentials: opts.credentials,
            docker_host: opts.docker_host,
            locks: ResourceLocks::new(),
            metrics: Mutex::new(BTreeMap::new()),
            executor_ready: Mutex::new(BTreeMap::new()),
            docker_tls_dirs: Mutex::new(HashMap::new()),
            google_token_dirs: TokenDirCache::new(),
            microsoft_token_dirs: TokenDirCache::new(),
            mailboxes: Mutex::new(HashMap::new()),
            artifact_store: RwLock::new(None),
        }
    }

    /// A service with no credential store, no docker host and no identity
    /// handle (tests, `gatekeeper check`).
    pub fn basic(tier1: Tier1, catalog: Catalog, audit: Arc<AuditLog>) -> Service {
        Service::new(ServiceOptions {
            tier1,
            catalog,
            audit,
            credentials: None,
            docker_host: None,
            identities: None,
        })
    }

    // -- Swappable state -----------------------------------------------------

    /// The current Tier 1 (a snapshot).
    pub fn tier1(&self) -> Arc<Tier1> {
        self.tier1.read().clone()
    }

    /// The current catalog (a snapshot).
    pub fn catalog(&self) -> Arc<Catalog> {
        self.catalog.read().clone()
    }

    pub fn set_catalog(&self, catalog: Catalog) {
        *self.catalog.write() = Arc::new(catalog);
    }

    /// Replaces Tier 1 alone (tests; `reload_config` swaps everything).
    pub fn set_tier1(&self, tier1: Tier1) {
        *self.tier1.write() = Arc::new(tier1);
    }

    pub fn limiter(&self) -> Arc<RateLimiter> {
        self.limiter.read().clone()
    }

    /// `self.metrics`: (tool, identity, outcome) -> count.
    pub fn metrics(&self) -> BTreeMap<(String, String, String), u64> {
        self.metrics.lock().clone()
    }

    pub fn executor_ready(&self) -> BTreeMap<String, bool> {
        self.executor_ready.lock().clone()
    }

    fn count(&self, tool_id: &str, identity_id: &str, outcome: &str) {
        *self
            .metrics
            .lock()
            .entry((tool_id.to_string(), identity_id.to_string(), outcome.to_string()))
            .or_insert(0) += 1;
    }

    pub fn artifact_store(&self) -> Arc<ArtifactStore> {
        if let Some(store) = self.artifact_store.read().clone() {
            return store;
        }
        let mut slot = self.artifact_store.write();
        slot.get_or_insert_with(|| Arc::new(ArtifactStore::from_env())).clone()
    }

    pub fn set_artifact_store(&self, store: ArtifactStore) {
        *self.artifact_store.write() = Some(Arc::new(store));
    }

    fn redact(&self) -> Redact {
        let redactor = self.audit.redactor().clone();
        Arc::new(move |s: &str| redactor.redact(s))
    }

    // -- Registry ------------------------------------------------------------

    /// FR-1.4: filtered per identity. An agent sees exclusively what it is
    /// allowed to call.
    pub fn visible_tools(&self, identity: &Identity) -> Vec<ToolView> {
        let catalog = self.catalog();
        let mut views: Vec<ToolView> = catalog
            .tools
            .values()
            .filter(|tool| tool.enabled && identity.may_call(&tool.id))
            .map(|tool| ToolView {
                name: tool.id.clone(),
                title: tool.title.clone(),
                description: tool.agent_description(),
                input_schema: tool.input_schema(),
                read_only: tool.category == "read",
                idempotent: tool.idempotent,
            })
            .collect();
        views.sort_by(|a, b| a.name.cmp(&b.name));
        views
    }

    // -- Call ----------------------------------------------------------------

    fn authorize(catalog: &Catalog, identity: &Identity, tool_id: &str) -> Result<ToolDef, Denied> {
        let Some(tool) = catalog.tools.get(tool_id) else {
            return Err(Denied::new(
                DenialReason::UnknownTool,
                format!("Tool {} does not exist", repr_str(tool_id)),
            ));
        };
        if !tool.enabled {
            return Err(Denied::new(
                DenialReason::ToolDisabled,
                format!("Tool {} is disabled", repr_str(tool_id)),
            ));
        }
        if !identity.may_call(&tool.id) {
            return Err(Denied::new(
                DenialReason::NotGranted,
                format!("Identity {} has no right to {}", repr_str(&identity.id), repr_str(tool_id)),
            ));
        }
        Ok(tool.clone())
    }

    /// `_resolve_toolkit`: applies a tool's destination override
    /// (FR-8.3g/h). `None` returns the toolkit unchanged.
    pub fn resolve_toolkit(tier1: &Tier1, toolkit: &Toolkit, destination: Option<&str>) -> Result<Toolkit, Denied> {
        let Some(destination) = destination else {
            return Ok(toolkit.clone());
        };
        // Unreachable in practice (Tier 1 and catalog load together), but
        // converted so the uniform "denied, logged" response holds.
        let dest = tier1
            .destination(destination)
            .map_err(|exc| Denied::new(DenialReason::Tier1Violation, exc.message))?;
        let or = |a: &Option<String>, b: &Option<String>| match a {
            Some(s) if !s.is_empty() => Some(s.clone()),
            _ => b.clone(),
        };
        let mut resolved = toolkit.clone();
        resolved.docker_host = or(&dest.docker_host, &toolkit.docker_host);
        // None (not declared on the destination) inherits the toolkit's
        // docker_tls; an explicit true/false on the destination wins.
        resolved.docker_tls = dest.docker_tls.unwrap_or(toolkit.docker_tls);
        resolved.base_url = or(&dest.base_url, &toolkit.base_url);
        resolved.ws_url = or(&dest.ws_url, &toolkit.ws_url);
        resolved.credential = or(&dest.credential, &toolkit.credential);
        Ok(resolved)
    }

    /// `_environment`: the minimal env of a `docker` toolkit's child
    /// process. The child does not inherit gatekeeper's environment, so
    /// secrets located there do not end up in foreign processes.
    pub fn environment(&self, toolkit: &Toolkit) -> Result<Option<HashMap<String, String>>, Denied> {
        if toolkit.executor != "docker" {
            return Ok(None);
        }
        let host = match toolkit.docker_host.as_deref().filter(|h| !h.is_empty()) {
            Some(h) => h.to_string(),
            None => match self.docker_host.as_deref().filter(|h| !h.is_empty()) {
                Some(h) => h.to_string(),
                None => return Ok(None),
            },
        };
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()));
        env.insert("DOCKER_HOST".to_string(), host);
        if toolkit.docker_tls {
            env.extend(self.docker_tls_env(toolkit.credential.as_deref())?);
        }
        Ok(Some(env))
    }

    /// Wired to `CredentialStore.on_change` (FR-8.3g): a rotated
    /// docker_tls credential is re-materialized on next use. Removes the
    /// discarded directories from disk too.
    pub fn invalidate_docker_tls_cache(&self) {
        let stale: Vec<PathBuf> = self.docker_tls_dirs.lock().drain().map(|(_, p)| p).collect();
        for dir in stale {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    pub fn invalidate_google_token_cache(&self) {
        self.google_token_dirs.invalidate();
    }

    pub fn invalidate_microsoft_token_cache(&self) {
        self.microsoft_token_dirs.invalidate();
    }

    /// `_google_token_env`.
    pub fn google_token_env(&self, cred_name: Option<&str>) -> Result<HashMap<String, String>, Denied> {
        google_token_env(self.credentials.as_deref(), cred_name, &self.google_token_dirs)
    }

    /// `_microsoft_token_env`.
    pub fn microsoft_token_env(&self, cred_name: Option<&str>) -> Result<HashMap<String, String>, Denied> {
        microsoft_token_env(self.credentials.as_deref(), cred_name, &self.microsoft_token_dirs)
    }

    /// `_docker_tls_env`: materializes a `docker_tls` credential to a
    /// private temp dir and returns the env vars the `docker` CLI needs.
    fn docker_tls_env(&self, cred_name: Option<&str>) -> Result<HashMap<String, String>, Denied> {
        let env = |dir: &std::path::Path| {
            HashMap::from([
                ("DOCKER_CERT_PATH".to_string(), dir.to_string_lossy().into_owned()),
                ("DOCKER_TLS_VERIFY".to_string(), "1".to_string()),
            ])
        };
        let Some(cred_name) = cred_name else {
            return Err(unavailable("This destination needs TLS but has no credential configured."));
        };
        let mut dirs = self.docker_tls_dirs.lock();
        if let Some(cached) = dirs.get(cred_name) {
            return Ok(env(cached));
        }
        let Some(credentials) = self.credentials.as_deref() else {
            return Err(unavailable("No credential store is configured, but this destination needs one."));
        };
        // PORT NOTE: Python let a store error (wrong master key, unreadable
        // file) escape `call()` as an exception; it is an audited denial here.
        let resolved = credentials.resolve(cred_name).map_err(|e| unavailable(e.message))?;
        let Some(resolved) = resolved else {
            return Err(unavailable(format!("Credential {} is not configured yet.", repr_str(cred_name))));
        };
        if resolved.kind != "docker_tls" {
            return Err(unavailable(format!(
                "Credential {} is not a docker_tls credential.",
                repr_str(cred_name)
            )));
        }
        let Ok(bundle) = serde_json::from_str::<Value>(&resolved.value) else {
            return Err(unavailable(format!(
                "Credential {} is not a valid docker_tls JSON bundle.",
                repr_str(cred_name)
            )));
        };
        // PORT NOTE: a JSON bundle that is not an object made Python raise
        // AttributeError; it reads as an empty bundle here (refused below).
        let empty = Map::new();
        let bundle = bundle.as_object().unwrap_or(&empty);
        let text = |key: &str| -> Option<String> {
            match bundle.get(key) {
                Some(v) if crate::tier1::py_truthy(v) => Some(crate::pyfmt::str_value(v)),
                _ => None,
            }
        };
        let (Some(cert), Some(key)) = (text("cert"), text("key")) else {
            return Err(unavailable(format!("Credential {} is missing 'cert' or 'key'.", repr_str(cred_name))));
        };
        let ca = text("ca");
        let materialize = || -> std::io::Result<PathBuf> {
            use std::os::unix::fs::PermissionsExt as _;
            let tmp_dir = tempfile::Builder::new().prefix("gatekeeper-docker-tls-").tempdir()?.keep();
            std::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o700))?;
            write_private_file(&tmp_dir.join("cert.pem"), &cert)?;
            write_private_file(&tmp_dir.join("key.pem"), &key)?;
            if let Some(ca) = &ca {
                write_private_file(&tmp_dir.join("ca.pem"), ca)?;
            }
            Ok(tmp_dir)
        };
        // PORT NOTE: Python let an OSError here escape; it is a denial here.
        let tmp_dir = materialize()
            .map_err(|e| unavailable(format!("The docker TLS material could not be written: {e}")))?;
        let result = env(&tmp_dir);
        dirs.insert(cred_name.to_string(), tmp_dir);
        Ok(result)
    }

    /// `_mailbox`: the `MessageStore` for an `agent` toolkit's mailbox
    /// file, cached per path so concurrent calls serialize on one lock.
    pub fn mailbox(&self, toolkit: &Toolkit) -> Arc<MessageStore> {
        let path = toolkit.mailbox_path.clone().unwrap_or_default();
        self.mailboxes.lock().entry(path.clone()).or_insert_with(|| Arc::new(MessageStore::new(path))).clone()
    }

    fn known_recipients(&self) -> Option<HashSet<String>> {
        self.identities.as_ref().map(|ids| ids.read().identities.keys().cloned().collect())
    }

    fn audit_call(&self, record: CallRecord) -> Result<(), CallError> {
        self.audit
            .call(record)
            .map_err(|e| CallError::Internal(format!("The audit log could not be written: {e}")))
    }

    /// The whole pipeline. `client` is the caller's network address,
    /// recorded in the audit log next to the identity; `None` when the
    /// caller is not over HTTP.
    pub async fn call(
        &self,
        identity: &Identity,
        tool_id: &str,
        arguments: &Map<String, Value>,
        client: Option<&str>,
    ) -> Result<ExecResult, CallError> {
        let tier1 = self.tier1();
        let catalog = self.catalog();

        // An unknown name is whatever the caller sent, and it goes into the
        // audit log and the denial: cut to a length no tool ID comes near,
        // so a megabyte-long name cannot rotate the audit history away.
        let clipped: String;
        let tool_id = if catalog.get(tool_id).is_some() || tool_id.chars().count() <= MAX_UNKNOWN_TOOL_CHARS {
            tool_id
        } else {
            clipped = format!("{}...", tool_id.chars().take(MAX_UNKNOWN_TOOL_CHARS).collect::<String>());
            &clipped
        };

        let mut tool: Option<ToolDef> = None;
        let mut scopes: Vec<String> = Vec::new();
        let mut values = validate::Values::new();
        // Which named credential this call ends up using (FR-10.7) -- the
        // *name*, never the value. Set once the toolkit is resolved.
        let mut credential_names: Vec<String> = Vec::new();

        let prepared: Result<(Toolkit, Request), Denied> = (|| {
            let t = Self::authorize(&catalog, identity, tool_id)?;
            tool = Some(t.clone());
            // PORT NOTE: Python let this ConfigError (a tool whose toolkit
            // vanished -- unreachable, the catalog is validated against
            // this Tier 1) escape unaudited; it is an audited denial here.
            let base = tier1
                .toolkit(&t.toolkit)
                .map_err(|exc| Denied::new(DenialReason::Tier1Violation, exc.message))?;
            let toolkit = Self::resolve_toolkit(&tier1, base, t.destination.as_deref())?;
            // After resolve_toolkit, so a destination's credential override
            // is already applied: the audited name is the one used.
            credential_names = toolkit.credential.iter().filter(|c| !c.is_empty()).cloned().collect();

            if !self.limiter().check(&identity.id, &t.category) {
                return Err(Denied::new(
                    DenialReason::RateLimited,
                    format!("Rate limit for category {} reached", repr_str(&t.category)),
                ));
            }

            values = validate::resolve_parameters(&t, arguments)?;
            scopes = validate::resolve_scopes(&t, &values)?;

            // FR-4.12 before the permission check: a protected resource
            // remains locked even if the permission profile would cover it.
            validate::check_protected(&scopes, &toolkit)?;

            for scope in &scopes {
                if !identity.covers_scope(scope) {
                    return Err(Denied::new(
                        DenialReason::ScopeMismatch,
                        format!("Scope {} is not covered by the profile", repr_str(scope)),
                    ));
                }
            }

            // The executor-specific request is built here, inside the same
            // error path as everything else -- a bad parameter surfaces as
            // a normal "denied" audit entry whatever the executor.
            let request = match toolkit.executor.as_str() {
                "docker" | "local" | "ssh" => Request::Argv {
                    argv: validate::build_argv(&t, &values, &toolkit)?,
                    env: self.environment(&toolkit)?,
                },
                "http" => Request::Http(validate::build_http_request(&t, &values, &toolkit)?),
                "truenas" => {
                    let (method, params) = validate::build_rpc_call(&t, &values, &toolkit)?;
                    Request::Rpc { method, params }
                }
                "google" => {
                    let args = validate::build_google_call(&t, &values, &toolkit)?;
                    let env = self.google_token_env(toolkit.credential.as_deref())?;
                    Request::Google { action: t.google_action.clone().unwrap_or_default(), args, env }
                }
                "microsoft" => {
                    let args = validate::build_microsoft_call(&t, &values, &toolkit)?;
                    let env = self.microsoft_token_env(toolkit.credential.as_deref())?;
                    Request::Microsoft { action: t.microsoft_action.clone().unwrap_or_default(), args, env }
                }
                "opencode" => Request::Opencode(validate::build_opencode_call(&t, &values, &toolkit)?),
                "agent" => {
                    let known = self.known_recipients();
                    Request::Agent(validate::build_agent_call(&t, &values, &toolkit, known.as_ref())?)
                }
                "artifact" => Request::Artifact(validate::build_artifact_call(&t, &values, &toolkit)?),
                "kuma" => Request::Kuma(validate::build_kuma_call(&t, &values, &toolkit)?),
                "git" => Request::Git(validate::build_git_call(&t, &values, &toolkit)?),
                "file" => Request::File,
                _ => Request::Unknown,
            };
            Ok((toolkit, request))
        })();

        let (mut toolkit, request) = match prepared {
            Ok(p) => p,
            Err(denial) => {
                // One series for every name that is not a tool: each
                // distinct name would otherwise be a counter kept forever.
                let metric_id = if catalog.get(tool_id).is_some() { tool_id } else { UNKNOWN_TOOL_METRIC };
                self.count(metric_id, &identity.id, "denied");
                self.audit_call(CallRecord {
                    identity: identity.id.clone(),
                    tool_id: tool_id.to_string(),
                    tool_version: tool.as_ref().map(|t| t.version),
                    parameters: Value::Object(arguments.clone()),
                    scopes,
                    outcome: "denied".into(),
                    denial_reason: Some(denial.reason.as_str().to_string()),
                    detail: Some(denial.detail.clone()),
                    credential_names,
                    client: client.map(str::to_string),
                    ..Default::default()
                })?;
                return Err(CallError::Denied(denial));
            }
        };
        let tool = tool.expect("authorized tool");
        let command = describe_request(&request, &values);

        let timeout_seconds = tool.timeout_seconds.min(toolkit.max_timeout_seconds);
        let max_output_bytes = tool.max_output_bytes.min(toolkit.max_output_bytes);
        let redact = self.redact();
        let credentials = self.credentials.as_deref();

        let lock_key = scopes.first().cloned().unwrap_or_else(|| tool.id.clone());
        let lock = self.locks.get(&lock_key);
        let result = {
            let _guard = lock.lock().await;
            match request {
                Request::Argv { argv, env } => {
                    if toolkit.executor == "ssh" {
                        execute::ssh::run(
                            &argv,
                            &toolkit,
                            credentials,
                            timeout_seconds as f64,
                            max_output_bytes,
                            tool.idempotent,
                            Some(&redact),
                            Some(&tool),
                        )
                        .await?
                    } else {
                        // A denial from the executor itself (binary missing)
                        // propagates unaudited, as Python's did.
                        execute::local::run(
                            &argv,
                            timeout_seconds,
                            max_output_bytes,
                            tool.idempotent,
                            None,
                            env.as_ref(),
                        )
                        .await?
                    }
                }
                Request::Http(req) => {
                    // Per-tool base_url override (0.45.5): the override wins
                    // when set, the toolkit value stands otherwise.
                    if let Some(base_url) = tool.base_url.as_deref().filter(|b| !b.is_empty()) {
                        if toolkit.base_url.as_deref() != Some(base_url) {
                            toolkit.base_url = Some(base_url.to_string());
                        }
                    }
                    execute::http::run(
                        &req.method,
                        &req.path,
                        &req.query,
                        req.body.as_ref(),
                        // Raw JSON body mode, when the tool declares one.
                        tool.body_raw_param.as_deref(),
                        &toolkit,
                        credentials,
                        timeout_seconds as f64,
                        max_output_bytes,
                        tool.idempotent,
                        Some(&redact),
                    )
                    .await?
                }
                Request::Agent(operation) => {
                    let store = self.mailbox(&toolkit);
                    execute::agent::run(
                        &operation,
                        // The authenticated identity, never a parameter.
                        &identity.id,
                        &values,
                        &toolkit,
                        &store,
                        max_output_bytes,
                        Some(&redact),
                    )
                    .await
                }
                Request::Artifact(operation) => {
                    let store = self.artifact_store();
                    // Per artifact, on top of the tool grant: an identity
                    // sees an artifact only with scope `artifact:<id>`.
                    let visible = |art_id: &str| identity.covers_scope(&format!("artifact:{art_id}"));
                    execute::artifact::run(&operation, &values, &toolkit, &store, &visible, max_output_bytes).await
                }
                Request::File => {
                    // Per-tool `run_as` wins over the toolkit's: None
                    // inherits, "" clears, anything else overrides.
                    let effective_run_as = match tool.run_as.as_deref() {
                        None => toolkit.run_as.clone(),
                        Some("") => None,
                        Some(r) => Some(r.to_string()),
                    };
                    let Some(operation) = tool.file_operation.clone() else {
                        return Err(CallError::Internal("file tool without a file operation".into()));
                    };
                    let call = execute::file::FileCall {
                        operation,
                        path: values.get("path").cloned().unwrap_or_default(),
                        content: values.get("content").cloned(),
                        old_string: values.get("old_string").cloned(),
                        new_string: values.get("new_string").cloned(),
                        path_roots: toolkit.path_roots.clone(),
                        protected: toolkit.protected_resources.clone(),
                        timeout_seconds,
                        max_output_bytes,
                        idempotent: tool.idempotent,
                        run_as: effective_run_as,
                    };
                    // A masked read written back would replace the real
                    // secret with the mask: refuse it before it touches disk.
                    let writes_mask = toolkit.redact_secrets
                        && [&call.content, &call.new_string]
                            .into_iter()
                            .flatten()
                            .any(|text| crate::secretmask::carries_mask(text));
                    if writes_mask {
                        let denial = Denied::new(
                            DenialReason::ParamInvalid,
                            format!(
                                "The text to write contains {}, which gatekeeper put in place of a \
                                 secret when the file was read. Writing it would replace the real \
                                 value. Change only the lines you mean to change (old_string/new_string), \
                                 leaving the masked lines out.",
                                repr_str(crate::secretmask::MASK)
                            ),
                        );
                        ExecResult::denied(&denial, 0)
                    } else {
                        execute::file::run(&call).await
                    }
                }
                Request::Kuma(operation) => {
                    execute::kuma::run(
                        &operation,
                        &values,
                        &toolkit,
                        credentials,
                        timeout_seconds as f64,
                        max_output_bytes,
                        tool.idempotent,
                        Some(&redact),
                    )
                    .await?
                }
                Request::Git(operation) => {
                    execute::git::run(
                        &operation,
                        &values,
                        &toolkit,
                        credentials,
                        timeout_seconds,
                        max_output_bytes,
                        tool.idempotent,
                        Some(&redact),
                    )
                    .await?
                }
                Request::Opencode(operation) => {
                    execute::opencode::run(
                        &operation,
                        &values,
                        &toolkit,
                        credentials,
                        timeout_seconds,
                        max_output_bytes,
                        tool.idempotent,
                        Some(&redact),
                    )
                    .await
                }
                Request::Google { action, args, env } => {
                    execute::google::run(
                        &action,
                        &args,
                        &toolkit,
                        timeout_seconds,
                        max_output_bytes,
                        tool.idempotent,
                        Some(&env),
                        Some(&redact),
                    )
                    .await
                }
                Request::Microsoft { action, args, env } => {
                    execute::microsoft::run(
                        &action,
                        &args,
                        &toolkit,
                        timeout_seconds,
                        max_output_bytes,
                        tool.idempotent,
                        Some(&env),
                        Some(&redact),
                    )
                    .await
                }
                Request::Rpc { method, params } => {
                    execute::truenas::run(
                        &method,
                        &params,
                        &toolkit,
                        credentials,
                        timeout_seconds as f64,
                        max_output_bytes,
                        tool.idempotent,
                        Some(&redact),
                    )
                    .await?
                }
                Request::Unknown => {
                    // Python: an AssertionError in the dispatch.
                    return Err(CallError::Internal(format!(
                        "No executor dispatch for {}",
                        repr_str(&toolkit.executor)
                    )));
                }
            }
        };

        // Output masking (FR-10.6), for every executor: the secrets
        // gatekeeper holds, then -- where the toolkit asks for it -- anything
        // secret-shaped, such as the tokens in a config file a tool prints.
        let mut result = result;
        for text in [&mut result.stdout, &mut result.stderr] {
            let mut masked = redact(text);
            if toolkit.redact_secrets {
                masked = crate::secretmask::mask_secrets(&masked);
            }
            *text = masked;
        }

        self.count(tool_id, &identity.id, &result.outcome);
        let parameters: Map<String, Value> =
            values.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
        self.audit_call(CallRecord {
            identity: identity.id.clone(),
            tool_id: tool.id.clone(),
            tool_version: Some(tool.version),
            parameters: Value::Object(parameters),
            scopes,
            outcome: result.outcome.clone(),
            exit_code: result.exit_code,
            duration_ms: Some(result.duration_ms),
            truncated: result.truncated,
            denial_reason: result.denial_reason.clone(),
            detail: result.denial_detail.clone(),
            credential_names,
            client: client.map(str::to_string),
            command,
        })?;
        Ok(result)
    }

    // -- Operation -----------------------------------------------------------

    /// Reachability per executor for /health/ready (NFR-9). A toolkit with
    /// declared destinations reports per destination
    /// (`executor@destination`), probed concurrently.
    pub async fn probe_executors(&self) -> BTreeMap<String, bool> {
        let tier1 = self.tier1();
        let mut seen: BTreeMap<String, bool> = BTreeMap::new();
        for toolkit in tier1.toolkits.values() {
            if !toolkit.destinations.is_empty() {
                let pending: Vec<&String> = toolkit
                    .destinations
                    .iter()
                    .filter(|d| !seen.contains_key(&format!("{}@{d}", toolkit.executor)))
                    .collect();
                if !pending.is_empty() {
                    let probes = pending.iter().map(|d| async {
                        match Self::resolve_toolkit(&tier1, toolkit, Some(d)) {
                            Ok(resolved) => self.probe_one(&resolved).await,
                            // PORT NOTE: Python let this Denied (an unknown
                            // destination, unreachable after load) escape.
                            Err(_) => false,
                        }
                    });
                    let results = futures::future::join_all(probes).await;
                    for (dest_name, ready) in pending.iter().zip(results) {
                        seen.insert(format!("{}@{dest_name}", toolkit.executor), ready);
                    }
                }
                continue;
            }
            if seen.contains_key(&toolkit.executor) {
                continue;
            }
            let ready = self.probe_one(toolkit).await;
            seen.insert(toolkit.executor.clone(), ready);
        }
        *self.executor_ready.lock() = seen.clone();
        seen
    }

    /// `_probe_one`.
    pub async fn probe_one(&self, toolkit: &Toolkit) -> bool {
        match toolkit.executor.as_str() {
            "local" => toolkit.binaries.iter().all(|b| is_runnable(b)),
            // In-process: the one configuration that cannot work is a
            // toolkit with no roots.
            "file" => !toolkit.path_roots.is_empty(),
            "docker" => {
                let Ok(env) = self.environment(toolkit) else {
                    return false;
                };
                let Some(binary) = toolkit.binaries.first() else {
                    return false;
                };
                let argv = vec![
                    binary.clone(),
                    "version".to_string(),
                    "--format".to_string(),
                    "{{.Server.Version}}".to_string(),
                ];
                match execute::local::run(&argv, 5, 4096, true, None, env.as_ref()).await {
                    Ok(result) => result.outcome == OUTCOME_OK,
                    Err(_) => false,
                }
            }
            // TCP-connect only, no HTTP request.
            "http" => execute::http::probe(toolkit).await,
            "truenas" => execute::truenas::probe(toolkit).await,
            "ssh" => execute::ssh::probe(toolkit).await,
            "google" => execute::google::probe(toolkit).await,
            "microsoft" => execute::microsoft::probe(toolkit).await,
            "opencode" => execute::opencode::probe(toolkit).await,
            "kuma" => execute::kuma::probe(toolkit).await,
            "git" => execute::git::probe(toolkit).await,
            "agent" => execute::agent::probe(toolkit).await,
            "artifact" => {
                let store = self.artifact_store();
                execute::artifact::probe(toolkit, &store).await
            }
            _ => false,
        }
    }

    /// Prometheus text format (NFR-3a).
    pub fn render_metrics(&self) -> String {
        let mut lines = vec![
            "# HELP gatekeeper_tool_calls_total Calls by tool, identity and outcome".to_string(),
            "# TYPE gatekeeper_tool_calls_total counter".to_string(),
        ];
        for ((tool_id, identity_id, outcome), count) in self.metrics.lock().iter() {
            let (tool_id, identity_id, outcome) = (label(tool_id), label(identity_id), label(outcome));
            lines.push(format!(
                "gatekeeper_tool_calls_total{{tool=\"{tool_id}\",identity=\"{identity_id}\",outcome=\"{outcome}\"}} {count}"
            ));
        }
        lines.push("# HELP gatekeeper_executor_ready Executor reachable (1/0)".to_string());
        lines.push("# TYPE gatekeeper_executor_ready gauge".to_string());
        for (executor, ready) in self.executor_ready.lock().iter() {
            lines.push(format!(
                "gatekeeper_executor_ready{{executor=\"{executor}\"}} {}",
                if *ready { 1 } else { 0 }
            ));
        }
        lines.join("\n") + "\n"
    }

    /// Test hook: records a probe result as `probe_executors` would.
    pub fn set_executor_ready(&self, ready: BTreeMap<String, bool>) {
        *self.executor_ready.lock() = ready;
    }

    // -- Reload --------------------------------------------------------------

    /// Reloads all three configuration files. `None` on success, otherwise
    /// an error message; the old state is preserved on errors.
    pub fn reload_config(&self, toolkits_path: &str, tools_path: &str, identities_path: &str) -> Option<String> {
        // Load everything before anything is swapped out.
        let tier1 = match load_tier1(toolkits_path) {
            Ok(t) => t,
            Err(exc) => return Some(format!("toolkits.yaml: {exc}")),
        };
        let catalog = match load_catalog(tools_path, &tier1, false) {
            Ok(c) => c,
            Err(exc) => return Some(format!("tools.yaml: {exc}")),
        };
        // PORT NOTE: as in Python, identities.yaml is loaded -- so a broken
        // file fails the reload -- but the result is *not* swapped into the
        // live identity store; only its count is logged. The console's
        // writes (`store::ConfigStore`) are what refresh identities.
        let identities = match load_identities(identities_path) {
            Ok(i) => i,
            Err(exc) => return Some(format!("identities.yaml: {exc}")),
        };

        // Swap. The limiter is reinitialized so changed rate limits take
        // effect immediately and old windows are not carried over.
        let toolkit_count = tier1.toolkits.len();
        let tool_count = catalog.tools.len();
        let violations = catalog.disabled_by_tier1.clone();
        {
            let mut t1 = self.tier1.write();
            let mut cat = self.catalog.write();
            let mut lim = self.limiter.write();
            *lim = Arc::new(RateLimiter::new(tier1.rate_limits.clone()));
            *t1 = Arc::new(tier1);
            *cat = Arc::new(catalog);
        }
        // A reload is a catalog change like any write.
        self.catalog_notifier.tool_catalog_changed();

        tracing::info!(
            "Configuration reloaded: {} toolkits, {} tools, {} identities",
            toolkit_count,
            tool_count,
            identities.identities.len()
        );
        for violation in violations {
            tracing::warn!("Definition disabled by Tier 1 violation: {}", violation);
        }
        None
    }
}

/// The audit log's `command` (1.20.0): what the executor is handed, as
/// one line. Never the environment, which is where credentials travel.
/// The value of a parameter whose name marks it secret (`token`,
/// `api_key`, ...) is masked wherever it lands, as it is in the logged
/// `parameters`; the audit log then masks the credentials it knows.
fn describe_request(request: &Request, values: &validate::Values) -> Option<String> {
    use crate::audit::{is_secret_key, scrub, Redactor};
    use crate::execute::ssh::shlex_quote;
    let quoted = |args: &[String]| args.iter().map(|a| shlex_quote(a)).collect::<Vec<_>>().join(" ");
    let masked_pairs = |pairs: &indexmap::IndexMap<String, String>| -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(if is_secret_key(k) { "***".into() } else { v.clone() })))
            .collect()
    };
    let line = match request {
        Request::Argv { argv, .. } => quoted(argv),
        Request::Http(req) => {
            let mut line = format!("{} {}", req.method, req.path);
            if !req.query.is_empty() {
                let query: Vec<String> = masked_pairs(&req.query)
                    .into_iter()
                    .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default()))
                    .collect();
                line = format!("{line}?{}", query.join("&"));
            }
            if let Some(body) = &req.body {
                line = format!("{line} {}", scrub(body.clone(), &Redactor::new()));
            }
            line
        }
        Request::Rpc { method, params } => format!("{method} {}", Value::Object(masked_pairs(params))),
        Request::Google { action, args, .. } | Request::Microsoft { action, args, .. } => {
            [action.clone(), quoted(args)].into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" ")
        }
        Request::Opencode(op) | Request::Agent(op) | Request::Artifact(op) | Request::Kuma(op) | Request::Git(op) => {
            op.clone()
        }
        Request::File | Request::Unknown => return None,
    };
    let mut line = line;
    for (name, value) in values {
        if is_secret_key(name) && !value.is_empty() {
            line = line.replace(value.as_str(), "***");
        }
    }
    Some(line)
}

/// The executor-specific request built inside the denial-audited block.
enum Request {
    Argv { argv: Vec<String>, env: Option<HashMap<String, String>> },
    Http(validate::HttpRequest),
    Rpc { method: String, params: indexmap::IndexMap<String, String> },
    Google { action: String, args: Vec<String>, env: HashMap<String, String> },
    Microsoft { action: String, args: Vec<String>, env: HashMap<String, String> },
    Opencode(String),
    Agent(String),
    Artifact(String),
    Kuma(String),
    Git(String),
    File,
    Unknown,
}
