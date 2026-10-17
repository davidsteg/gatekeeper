//! Copy-pasteable Tier 1 starting points, one per executor (port of
//! `toolkit_reference.py`).
//!
//! What `/app/toolkits/reference` shows: a toolkit block for a human to
//! paste under `toolkits:` in toolkits.yaml, edit, and redeploy. Nothing
//! here writes that file (FR-4.11), and nothing here is specific to one
//! product -- the point is the shape of each executor's toolkit with its
//! safe defaults already in place (a header credential, a /32 CIDR, a
//! narrow whitelist). `config/examples/toolkits.yaml` is the long form with
//! the reasoning.
//!
//! Every placeholder is `CHANGEME`. An unedited block still parses, and
//! fails closed: the http/opencode/kuma CIDR is 203.0.113.1/32 (RFC 5737
//! TEST-NET-3, reserved for documentation), so it can never match a real
//! host.
//!
//! The table below is generated verbatim from the Python module.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolkitReference {
    pub key: &'static str,
    pub display_name: &'static str,
    pub notes: &'static str,
    pub toolkit_yaml: &'static str,
}

/// Every reference, in the Python dict's (insertion) order.
pub const REFERENCES: &[ToolkitReference] = &[
    ToolkitReference {
        key: "local",
        display_name: "Local binaries (local)",
        notes: "Programs inside the gatekeeper container, run without a shell. A binary is checked for shape at startup, not for existence: name only what the image actually has. Host state such as zfs or ps does not belong here (FR-8.4).",
        toolkit_yaml: r#"  diag:
    executor: local
    binaries: ["/usr/bin/uptime", "/usr/bin/free", "/usr/bin/df"]
    denied_args: []
    path_roots: []
    protected_resources: []
    max_timeout_seconds: 10
    max_output_bytes: 16384
"#,
    },
    ToolkitReference {
        key: "docker",
        display_name: "Docker (docker)",
        notes: "Uses the mounted Docker socket. For a remote daemon over TLS, declare a destination with docker_host, docker_tls: true and a docker_tls credential (FR-8.3g).",
        toolkit_yaml: r#"  docker:
    executor: docker
    binaries: ["/usr/bin/docker"]
    denied_args:
      - rm
      - kill
      - exec
      - build
      - push
      - login
      - system
      - prune
      - cp
      - --privileged
      - --force
      - -v
      - --volumes
      - --rmi
    path_roots:
      - "/mnt/CHANGEME"   # where your compose.yaml files live
    protected_resources:
      - "gatekeeper"      # stacks that must never be touched
    max_timeout_seconds: 300
    max_output_bytes: 262144
"#,
    },
    ToolkitReference {
        key: "http",
        display_name: "HTTP API (http)",
        notes: "One service's REST API. Scheme and host live only here; tools add a method and a path under allowed_path_prefixes. Keep allowed_cidrs to the /32 of that one host (FR-8.15), and send the credential as a header, never a query parameter (FR-8.14).",
        toolkit_yaml: r#"  myservice:
    executor: http
    base_url: "http://CHANGEME:8080"
    allowed_methods: ["GET", "POST"]
    allowed_path_prefixes:
      - "/api/"   # CHANGEME -- as narrow as the tools need
    allowed_cidrs:
      - "203.0.113.1/32"  # CHANGEME -- e.g. 192.168.1.42/32, this one host
    credential: myservice   # kind api_key_header or bearer, created in /app/credentials
    follow_redirects: false
    max_timeout_seconds: 20
    max_output_bytes: 131072
"#,
    },
    ToolkitReference {
        key: "ssh",
        display_name: "Remote host over SSH (ssh)",
        notes: "The same binary and argv model as local, run on another host. Use a dedicated ed25519 key and an unprivileged user; ssh_known_hosts pins the host key.",
        toolkit_yaml: r#"  linux:
    executor: ssh
    ssh_host: "CHANGEME"          # e.g. 192.168.1.50
    ssh_port: 22
    ssh_user: "CHANGEME"          # a dedicated, unprivileged user -- not root
    ssh_known_hosts: "CHANGEME"   # output of: ssh-keyscan -t ed25519 <host>
    binaries: ["/usr/bin/uptime", "/usr/bin/free", "/usr/bin/df"]
    denied_args: []
    path_roots: []
    credential: linux
    max_timeout_seconds: 15
    max_output_bytes: 16384
"#,
    },
    ToolkitReference {
        key: "truenas",
        display_name: "TrueNAS (truenas)",
        notes: "JSON-RPC 2.0 over WebSocket. The whitelist is method names: a method that is not listed cannot be called by any tool.",
        toolkit_yaml: r#"  truenas:
    executor: truenas
    ws_url: "wss://CHANGEME/api/current"
    allowed_rpc_methods:
      - pool.query
      - pool.dataset.query
      - zfs.snapshot.query
    credential: truenas
    max_timeout_seconds: 30
    max_output_bytes: 65536
"#,
    },
    ToolkitReference {
        key: "file",
        display_name: "Files (file)",
        notes: "Read, write, patch and list inside path_roots, with no binary and no argv. path_roots is the whole restriction, so keep it narrow.",
        toolkit_yaml: r#"  files:
    executor: file
    binaries: []
    path_roots:
      - "/mnt/CHANGEME"
    protected_resources: []
    max_timeout_seconds: 15
    max_output_bytes: 262144
"#,
    },
    ToolkitReference {
        key: "google",
        display_name: "Google Workspace (google)",
        notes: "OAuth2: create a credential named google (kind oauth2) in /app/credentials with client_id and client_secret, then Connect Google. Action IDs are the CLI's own spelling, hyphen included (drive create-folder). One toolkit per Google service.",
        toolkit_yaml: r#"  gmail:
    executor: google
    google_script: "/opt/gatekeeper/google/google_api.py"
    allowed_google_actions:
      - gmail search
      - gmail get
    required_scopes:
      - gmail.readonly
    credential: google
    max_timeout_seconds: 30
    max_output_bytes: 131072
"#,
    },
    ToolkitReference {
        key: "microsoft",
        display_name: "Microsoft 365 / Outlook (microsoft)",
        notes: "OAuth2 against Microsoft Graph: create a credential named microsoft (kind oauth2) with the app registration's client_id and client_secret, then Connect Microsoft. Keep offline_access, or the credential stops working after an hour.",
        toolkit_yaml: r#"  outlook:
    executor: microsoft
    microsoft_script: "/opt/gatekeeper/microsoft/microsoft_api.py"
    allowed_microsoft_actions:
      - mail list
      - mail get
    required_scopes:
      - Mail.Read
      - User.Read
      - offline_access
    credential: microsoft
    max_timeout_seconds: 30
    max_output_bytes: 131072
"#,
    },
    ToolkitReference {
        key: "opencode",
        display_name: "opencode server (opencode)",
        notes: "A headless opencode coding agent. 'run' lets another agent edit files under path_roots: list only ask/check/health for a read-only toolkit. No auth by default; set OPENCODE_SERVER_PASSWORD and a basic credential if it is reachable beyond gatekeeper.",
        toolkit_yaml: r#"  opencode:
    executor: opencode
    base_url: "http://CHANGEME:4096"
    allowed_cidrs:
      - "203.0.113.1/32"  # CHANGEME -- e.g. 192.168.1.42/32, this one host
    allowed_opencode_operations:
      - ask
      - check
      - health
    path_roots:
      - "/mnt/CHANGEME"   # the project roots opencode may be pointed at
    max_timeout_seconds: 900
    max_output_bytes: 131072
"#,
    },
    ToolkitReference {
        key: "git",
        display_name: "Push feat/* branches (git)",
        notes: "Pushes one feat/* branch of a listed repository to that repository's remote, fast-forward only: no force, no delete, no main. Create a credential named github (kind bearer, a token that may push to the remote) and mount the repository into the container, read-only is enough.",
        toolkit_yaml: r#"  gkrepo:
    executor: git
    repos:
      CHANGEME:
        path: "/repos/CHANGEME"   # the checkout, as mounted into this container
        remote: "https://github.com/CHANGEME/CHANGEME.git"
    allowed_git_operations:
      - push
    credential: github
    max_timeout_seconds: 120
    max_output_bytes: 16384
"#,
    },
    ToolkitReference {
        key: "kuma",
        display_name: "Uptime Kuma monitors (kuma)",
        notes: "Lists, adds, pauses and resumes HTTP monitors over Kuma's Socket.IO API. Create a credential named kuma (kind basic, value username:password) for a Kuma account without 2FA. Pause/resume only touch monitors gatekeeper created; there is no delete or edit.",
        toolkit_yaml: r#"  kuma:
    executor: kuma
    base_url: "http://CHANGEME:3001"
    allowed_cidrs:
      - "203.0.113.1/32"  # CHANGEME -- e.g. 192.168.1.42/32, this one host
    allowed_kuma_operations:
      - monitor_list
      - monitor_add_http
      - monitor_pause
      - monitor_resume
    credential: kuma
    max_timeout_seconds: 30
    max_output_bytes: 131072
"#,
    },
    ToolkitReference {
        key: "agent",
        display_name: "Agent mailbox (agent)",
        notes: "Messages between gatekeeper identities, delivered on the recipient's next read. mailbox_path must be on a writable, persistent volume. Stored in plaintext: coordination only, never secrets.",
        toolkit_yaml: r#"  agent:
    executor: agent
    mailbox_path: "/etc/gatekeeper/messages.yaml"
    allowed_agent_operations:
      - send_message
      - read_messages
    max_message_bytes: 4096
    max_mailbox_messages: 200
    max_timeout_seconds: 10
    max_output_bytes: 65536
"#,
    },
];

/// `REFERENCES[key]`.
pub fn get(key: &str) -> Option<&'static ToolkitReference> {
    REFERENCES.iter().find(|r| r.key == key)
}

/// `toolkit_reference_view()` of `api/service.py`: the references as
/// `{"key", "display_name", "notes", "toolkit_yaml"}` objects.
pub fn view() -> Vec<serde_json::Value> {
    REFERENCES
        .iter()
        .map(|r| {
            serde_json::json!({
                "key": r.key, "display_name": r.display_name,
                "notes": r.notes, "toolkit_yaml": r.toolkit_yaml,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn each_block_is_one_toolkit_of_its_executor() {
        for r in REFERENCES {
            let parsed = crate::yaml::load(r.toolkit_yaml).unwrap();
            let map = parsed.as_object().unwrap();
            assert_eq!(map.len(), 1, "{}", r.key);
            let (name, body) = map.iter().next().unwrap();
            assert_eq!(body["executor"], r.key);
            // ... and it loads as a real Tier 1 toolkit.
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("toolkits.yaml");
            let logs = dir.path().join("logs");
            std::fs::write(&path, format!("toolkits:\n{}\naudit:\n  dir: {}\n", r.toolkit_yaml, logs.display()))
                .unwrap();
            let tier1 = crate::tier1::load_tier1(path.to_str().unwrap()).unwrap();
            assert!(tier1.toolkits.contains_key(name), "{}", r.key);
        }
    }

    #[test]
    fn every_executor_with_a_toolkit_shape_has_a_reference() {
        let mut keys: Vec<&str> = REFERENCES.iter().map(|r| r.key).collect();
        keys.sort();
        let mut want = vec![
            "local", "docker", "http", "ssh", "truenas", "file", "google", "microsoft", "opencode", "kuma", "git",
            "agent",
        ];
        want.sort();
        assert_eq!(keys, want);
        assert_eq!(get("http").unwrap().display_name, "HTTP API (http)");
        assert!(get("nope").is_none());
    }

    #[test]
    fn unedited_cidr_is_the_documentation_range() {
        for key in ["http", "opencode", "kuma"] {
            let parsed = crate::yaml::load(get(key).unwrap().toolkit_yaml).unwrap();
            let body = parsed.as_object().unwrap().values().next().unwrap().clone();
            assert_eq!(body["allowed_cidrs"], serde_json::json!(["203.0.113.1/32"]));
        }
    }

    /// Verbatim against the Python module's `REFERENCES`, frozen in
    /// `tests/fixtures/toolkit_reference_golden.json` when the Python
    /// implementation was removed (1.16.0).
    #[test]
    fn text_matches_python_verbatim() {
        let theirs: Value =
            serde_json::from_str(include_str!("../tests/fixtures/toolkit_reference_golden.json")).unwrap();
        let ours: Vec<Value> = REFERENCES
            .iter()
            .map(|r| serde_json::json!([r.key, r.display_name, r.notes, r.toolkit_yaml]))
            .collect();
        assert_eq!(Value::Array(ours), theirs);
    }
}
