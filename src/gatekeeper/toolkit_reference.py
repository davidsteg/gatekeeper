"""Copy-pasteable Tier 1 starting points, one per executor.

What `/app/toolkits/reference` shows: a toolkit block for a human to paste
under `toolkits:` in toolkits.yaml, edit, and redeploy. Nothing here writes
that file (FR-4.11), and nothing here is specific to one product -- the
point is the shape of each executor's toolkit with its safe defaults
already in place (a header credential, a /32 CIDR, a narrow whitelist).
`config/examples/toolkits.yaml` is the long form with the reasoning.

Every placeholder is `CHANGEME`. An unedited block still parses, and fails
closed: the http/opencode CIDR is 203.0.113.1/32 (RFC 5737 TEST-NET-3,
reserved for documentation), so it can never match a real host.
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True, slots=True)
class ToolkitReference:
    key: str
    display_name: str
    notes: str
    toolkit_yaml: str


_REFERENCES = (
    ToolkitReference(
        "local", "Local binaries (local)",
        "Programs inside the gatekeeper container, run without a shell. A binary is "
        "checked for shape at startup, not for existence: name only what the image "
        "actually has. Host state such as zfs or ps does not belong here (FR-8.4).",
        """\
  diag:
    executor: local
    binaries: ["/usr/bin/uptime", "/usr/bin/free", "/usr/bin/df"]
    denied_args: []
    path_roots: []
    protected_resources: []
    max_timeout_seconds: 10
    max_output_bytes: 16384
""",
    ),
    ToolkitReference(
        "docker", "Docker (docker)",
        "Uses the mounted Docker socket. For a remote daemon over TLS, declare a "
        "destination with docker_host, docker_tls: true and a docker_tls credential "
        "(FR-8.3g).",
        """\
  docker:
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
""",
    ),
    ToolkitReference(
        "http", "HTTP API (http)",
        "One service's REST API. Scheme and host live only here; tools add a method "
        "and a path under allowed_path_prefixes. Keep allowed_cidrs to the /32 of that "
        "one host (FR-8.15), and send the credential as a header, never a query "
        "parameter (FR-8.14).",
        """\
  myservice:
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
""",
    ),
    ToolkitReference(
        "ssh", "Remote host over SSH (ssh)",
        "The same binary and argv model as local, run on another host. Use a dedicated "
        "ed25519 key and an unprivileged user; ssh_known_hosts pins the host key.",
        """\
  linux:
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
""",
    ),
    ToolkitReference(
        "truenas", "TrueNAS (truenas)",
        "JSON-RPC 2.0 over WebSocket. The whitelist is method names: a method that is "
        "not listed cannot be called by any tool.",
        """\
  truenas:
    executor: truenas
    ws_url: "wss://CHANGEME/api/current"
    allowed_rpc_methods:
      - pool.query
      - pool.dataset.query
      - zfs.snapshot.query
    credential: truenas
    max_timeout_seconds: 30
    max_output_bytes: 65536
""",
    ),
    ToolkitReference(
        "file", "Files (file)",
        "Read, write, patch and list inside path_roots, with no binary and no argv. "
        "path_roots is the whole restriction, so keep it narrow.",
        """\
  files:
    executor: file
    binaries: []
    path_roots:
      - "/mnt/CHANGEME"
    protected_resources: []
    max_timeout_seconds: 15
    max_output_bytes: 262144
""",
    ),
    ToolkitReference(
        "google", "Google Workspace (google)",
        "OAuth2: create a credential named google (kind oauth2) in /app/credentials with "
        "client_id and client_secret, then Connect Google. Action IDs are the CLI's own "
        "spelling, hyphen included (drive create-folder). One toolkit per Google service.",
        """\
  gmail:
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
""",
    ),
    ToolkitReference(
        "microsoft", "Microsoft 365 / Outlook (microsoft)",
        "OAuth2 against Microsoft Graph: create a credential named microsoft (kind oauth2) "
        "with the app registration's client_id and client_secret, then Connect Microsoft. "
        "Keep offline_access, or the credential stops working after an hour.",
        """\
  outlook:
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
""",
    ),
    ToolkitReference(
        "opencode", "opencode server (opencode)",
        "A headless opencode coding agent. 'run' lets another agent edit files under "
        "path_roots: list only ask/check/health for a read-only toolkit. No auth by "
        "default; set OPENCODE_SERVER_PASSWORD and a basic credential if it is reachable "
        "beyond gatekeeper.",
        """\
  opencode:
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
""",
    ),
    ToolkitReference(
        "agent", "Agent mailbox (agent)",
        "Messages between gatekeeper identities, delivered on the recipient's next "
        "read. mailbox_path must be on a writable, persistent volume. Stored in "
        "plaintext: coordination only, never secrets.",
        """\
  agent:
    executor: agent
    mailbox_path: "/etc/gatekeeper/messages.yaml"
    allowed_agent_operations:
      - send_message
      - read_messages
    max_message_bytes: 4096
    max_mailbox_messages: 200
    max_timeout_seconds: 10
    max_output_bytes: 65536
""",
    ),
)

REFERENCES: dict[str, ToolkitReference] = {ref.key: ref for ref in _REFERENCES}
