//! Shared fixtures for the application-layer tests (service, store,
//! toolkit proposals, admin service). Like the Python fixtures they write
//! real files and run the real loaders.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use gatekeeper::admin_service::AdminService;
use gatekeeper::audit::AuditLog;
use gatekeeper::catalog::load_catalog;
use gatekeeper::credentials::{CredentialStore, KEY_ENV, KEY_FILE_ENV};
use gatekeeper::identity::{generate_token, hash_token, load_identities, Identity};
use gatekeeper::pending::PendingStore;
use gatekeeper::service::{Service, ServiceOptions, SharedIdentities};
use gatekeeper::store::ConfigStore;
use gatekeeper::tier1::load_tier1;
use gatekeeper::toolkit_proposals::ToolkitProposalStore;
use parking_lot::RwLock;
use serde_json::{json, Map, Value};

/// A harmless absolute program the toolkit allows.
pub const SH: &str = "/bin/sh";

/// Console passwords of the two humans in the test.
pub const ROOT_PASSWORD: &str = "admin-console-password";
pub const EYE_PASSWORD: &str = "viewer-console-password";

/// One process-wide credential master key (each test binary is its own
/// process, and no test changes it).
pub fn master_key() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        std::env::remove_var(KEY_FILE_ENV);
        std::env::set_var(KEY_ENV, gatekeeper::credentials::generate_master_key());
    });
}

pub fn write(path: &Path, text: &str) -> String {
    std::fs::write(path, text).unwrap();
    path.to_str().unwrap().to_string()
}

pub fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        other => panic!("not an object: {other}"),
    }
}

/// The conftest `tool_specs`, with `/bin/sh` in place of the interpreter:
/// `demo.show` prints its derived compose path, `demo.echo` its text.
pub fn sh_specs(sandbox: &Path) -> Vec<Value> {
    let sb = sandbox.to_str().unwrap();
    vec![
        json!({
            "id": "demo.show", "toolkit": "demo", "binary": SH, "version": 1,
            "title": "Show compose file", "description": "Outputs the path of the compose file.",
            "category": "read", "idempotent": true, "enabled": true,
            "argv": ["-c", "printf '%s\\n' \"$1\"", "sh", "{compose_path}"],
            "parameters": {
                "stack": {"type": "string", "required": true,
                          "pattern": "^[a-z0-9][a-z0-9_-]{0,62}$", "description": "Stack name"},
                "compose_path": {"type": "path", "derived": format!("{sb}/{{stack}}/compose.yaml"),
                                 "must_resolve_under": sb, "description": "derived"},
            },
            "required_scopes": ["stack:{stack}"],
            "timeout_seconds": 10, "max_output_bytes": 4096,
        }),
        json!({
            "id": "demo.echo", "toolkit": "demo", "binary": SH, "version": 1,
            "title": "Echo", "description": "Outputs the given text.",
            "category": "read", "idempotent": true, "enabled": true,
            "argv": ["-c", "printf '%s\\n' \"$1\"", "sh", "{text}"],
            "parameters": {"text": {"type": "string", "required": true, "pattern": "^.+$",
                                    "description": "arbitrary text"}},
            "required_scopes": [],
            "timeout_seconds": 10, "max_output_bytes": 4096,
        }),
    ]
}

/// The conftest `tier1` (one `local` toolkit "demo"), as a value.
pub fn demo_tier1_doc(tmp: &Path, sandbox: &Path) -> Value {
    json!({
        "toolkits": {
            "demo": {
                "executor": "local",
                "binaries": [SH],
                "denied_args": ["--dangerous", "rm"],
                "path_roots": [sandbox.to_str().unwrap()],
                "protected_resources": ["gatekeeper", "dockhand"],
                "max_timeout_seconds": 30,
                "max_output_bytes": 8192,
            }
        },
        "audit": {"dir": tmp.join("logs").to_str().unwrap()},
    })
}

pub fn sandbox(tmp: &Path) -> PathBuf {
    let root = tmp.join("raid");
    std::fs::create_dir_all(root.join("media-jellyfin")).unwrap();
    std::fs::create_dir_all(root.join("gatekeeper")).unwrap();
    std::fs::write(root.join("media-jellyfin/compose.yaml"), "services: {}\n").unwrap();
    std::fs::write(root.join("gatekeeper/compose.yaml"), "services: {}\n").unwrap();
    root
}

/// The default identities: root (admin, password), eye (viewer, password),
/// bot (agent, demo.show, stack:*).
pub fn default_identities() -> Vec<Value> {
    vec![
        json!({"id": "root", "role": "admin", "token_hash": hash_token(&generate_token()),
               "password_hash": hash_token(ROOT_PASSWORD), "tools": [], "scopes": []}),
        json!({"id": "eye", "role": "viewer", "token_hash": hash_token(&generate_token()),
               "password_hash": hash_token(EYE_PASSWORD), "tools": [], "scopes": []}),
        json!({"id": "bot", "role": "agent", "token_hash": hash_token(&generate_token()),
               "tools": ["demo.show"], "scopes": ["stack:*"]}),
    ]
}

pub struct AppEnv {
    pub dir: tempfile::TempDir,
    pub tmp: PathBuf,
    pub sandbox: PathBuf,
    pub toolkits_path: String,
    pub tools_path: String,
    pub identities_path: String,
    pub audit: Arc<AuditLog>,
    pub identities: SharedIdentities,
    pub service: Arc<Service>,
    pub store: Arc<ConfigStore>,
    pub pending: Arc<PendingStore>,
    pub proposals: Arc<ToolkitProposalStore>,
    pub credentials: Option<Arc<CredentialStore>>,
}

pub struct Builder {
    tier1: Option<Value>,
    tools: Option<Vec<Value>>,
    identities: Option<Vec<Value>>,
    credentials: bool,
}

pub fn builder() -> Builder {
    Builder { tier1: None, tools: None, identities: None, credentials: false }
}

impl Builder {
    /// Replaces the default Tier 1 document (an `audit.dir` is added).
    pub fn tier1(mut self, doc: Value) -> Self {
        self.tier1 = Some(doc);
        self
    }
    pub fn tools(mut self, tools: Vec<Value>) -> Self {
        self.tools = Some(tools);
        self
    }
    pub fn identities(mut self, ids: Vec<Value>) -> Self {
        self.identities = Some(ids);
        self
    }
    pub fn credentials(mut self) -> Self {
        self.credentials = true;
        self
    }

    pub fn build(self) -> AppEnv {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().to_path_buf();
        let sandbox = sandbox(&tmp);
        let mut doc = self.tier1.unwrap_or_else(|| demo_tier1_doc(&tmp, &sandbox));
        if doc.get("audit").is_none() {
            doc["audit"] = json!({"dir": tmp.join("logs").to_str().unwrap()});
        }
        let toolkits_path = write(&tmp.join("toolkits.yaml"), &gatekeeper::yaml::dump(&doc));
        let tools = self.tools.unwrap_or_else(|| sh_specs(&sandbox));
        let tools_path = write(&tmp.join("tools.yaml"), &gatekeeper::yaml::dump(&json!({ "tools": tools })));
        let ids = self.identities.unwrap_or_else(default_identities);
        let identities_path =
            write(&tmp.join("identities.yaml"), &gatekeeper::yaml::dump(&json!({ "identities": ids })));

        let tier1 = load_tier1(&toolkits_path).unwrap();
        let catalog = load_catalog(&tools_path, &tier1, false).unwrap();
        let audit = Arc::new(AuditLog::new(&tier1.audit_dir).unwrap());
        let identities: SharedIdentities = Arc::new(RwLock::new(load_identities(&identities_path).unwrap()));
        let credentials = if self.credentials {
            master_key();
            Some(Arc::new(CredentialStore::new(tmp.join("credentials.yaml").to_str().unwrap(), audit.clone())))
        } else {
            None
        };
        let service = Arc::new(Service::new(ServiceOptions {
            tier1,
            catalog,
            audit: audit.clone(),
            credentials: credentials.clone(),
            docker_host: None,
            identities: Some(identities.clone()),
        }));
        let store = Arc::new(ConfigStore::new(
            service.clone(),
            identities.clone(),
            audit.clone(),
            &tools_path,
            &identities_path,
        ));
        let pending = Arc::new(PendingStore::new(tmp.join("pending.yaml").to_str().unwrap(), audit.clone()));
        let proposals = Arc::new(ToolkitProposalStore::new(
            tmp.join("toolkit_proposals.yaml").to_str().unwrap(),
            audit.clone(),
            service.clone(),
            &toolkits_path,
            &tools_path,
            &identities_path,
        ));
        AppEnv {
            dir,
            tmp,
            sandbox,
            toolkits_path,
            tools_path,
            identities_path,
            audit,
            identities,
            service,
            store,
            pending,
            proposals,
            credentials,
        }
    }
}

impl AppEnv {
    pub fn new() -> AppEnv {
        builder().build()
    }

    pub fn admin(&self) -> AdminService {
        AdminService::new(self.store.clone(), self.pending.clone(), self.proposals.clone(), self.credentials.clone())
    }

    pub fn identity(&self, id: &str) -> Identity {
        self.identities.read().identities[id].clone()
    }

    pub fn audit_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.audit.path())
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    pub fn audit_text(&self) -> String {
        std::fs::read_to_string(self.audit.path()).unwrap_or_default()
    }

    pub fn read(&self, path: &str) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    pub fn load_yaml(&self, path: &str) -> Value {
        gatekeeper::yaml::load(&self.read(path)).unwrap()
    }

    pub fn tools_rev(&self) -> String {
        self.store.tools_revision()
    }

    pub fn ids_rev(&self) -> String {
        self.store.identities_revision()
    }
}

/// An identity built in memory (no file), for service-level call tests.
pub fn agent(id: &str, tools: &[&str], scopes: &[&str]) -> Identity {
    Identity {
        id: id.into(),
        role: "agent".into(),
        token_hash: String::new(),
        tools: tools.iter().map(|s| s.to_string()).collect(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        password_hash: String::new(),
        token_lookup: String::new(),
    }
}

pub fn args(v: Value) -> Map<String, Value> {
    obj(v)
}
