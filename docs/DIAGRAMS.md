# Diagrams

Visual companion to [ARCHITECTURE.md](ARCHITECTURE.md).

## System architecture

```mermaid
flowchart LR
    subgraph Clients
        Agent["Agent (MCP client)"]
        AdminAgent["Admin agent (MCP client)"]
        Human["Human (browser)"]
    end

    subgraph Gatekeeper["gatekeeper (one process)"]
        MCP["/mcp\nagent role only"]
        AdminMCP["/admin/mcp\nadmin role only\nfixed admin.* tool list"]
        UI["/ui console\nviewer + admin roles\nscript-free, server-rendered"]

        Service["service.py\ncall pipeline"]
        AdminService["admin_service.py\ndispatch"]

        Catalog["catalog.py\ntool catalog"]
        Tier1["tier1.py\ntoolkit boundaries"]
        Store["store.py\nTier 2 writes"]
        Pending["pending.py\npending.yaml queue"]
        ToolkitProp["toolkit_proposals.py\ntoolkit_proposals.yaml"]
        Creds["credentials.py\nwrite-only, encrypted"]
        Audit["audit.py\nJSON Lines log"]

        subgraph Executors
            Docker["execute.py (docker/local)"]
            Http["execute_http.py"]
            TrueNAS["execute_truenas.py"]
            Ssh["execute_ssh.py"]
        end
    end

    subgraph Config["config/ (files on disk)"]
        T1YAML["toolkits.yaml (Tier 1)"]
        T2YAML["tools.yaml, identities.yaml,\ncredentials.yaml, pending.yaml,\ntoolkit_proposals.yaml (Tier 2)"]
    end

    subgraph Targets["Reached systems"]
        DockerHost["Docker hosts"]
        LAN["LAN / SaaS APIs"]
        Nas["TrueNAS"]
        Ssh_Host["Remote Linux hosts (SSH)"]
    end

    Agent -->|API token| MCP --> Service
    AdminAgent -->|API token| AdminMCP --> AdminService
    Human -->|console password| UI

    Service --> Catalog --> Tier1
    Service --> Creds
    Service --> Audit
    Service --> Docker & Http & TrueNAS & Ssh

    AdminService -->|auto-apply| Store
    AdminService -->|higher risk| Pending
    AdminService -->|toolkit_propose| ToolkitProp
    UI -->|approve/reject| Pending
    UI -->|approve & deploy| ToolkitProp -->|reload_config, no restart| Tier1
    UI --> Store
    UI --> Audit

    Store --> T2YAML
    Pending --> T2YAML
    ToolkitProp --> T2YAML
    Tier1 --> T1YAML

    Docker --> DockerHost
    Http --> LAN
    TrueNAS --> Nas
    Ssh --> Ssh_Host
```

## Call pipeline (one `/mcp` tool call)

```mermaid
flowchart TD
    A["Agent calls a tool over /mcp"] --> B["auth: verify API token, resolve identity"]
    B -->|fail| Z1["auth_failure (audit)"]
    B -->|ok| C["authorize: identity's grants/scopes cover this tool?"]
    C -->|no| Z2["denied (audit, opaque DenialReason)"]
    C -->|yes| D["registry: look up tool + its toolkit (Tier 1)"]
    D --> E["validate: parameters against tool schema + Tier 1 boundaries\n(allowlisted binaries / path prefixes / CIDRs / RPC methods)"]
    E -->|invalid| Z2
    E -->|ok| F["build request: argv / HTTP request / RPC call\n(structured, never a shell string)"]
    F --> G["execute: dispatch to executor by toolkit.executor\n(docker / local / http / truenas / ssh)"]
    G --> H["credential resolved from credentials.py if toolkit needs one"]
    G --> I["call reaches target system"]
    I --> J["outcome: ok / failed / unknown (timeout)"]
    J --> K["audit.py: JSON Lines record\n(identity, tool, tool_version, scopes, outcome, duration)"]
    K --> L["response returned to agent (credential values, if any, masked)"]
```

## Tier 2 change approval (admin agent -> human)

```mermaid
flowchart TD
    A["admin agent calls admin.* on /admin/mcp"] --> B{"admin_service.py:\nwhich category?"}
    B -->|read-only| C1["answered immediately"]
    B -->|always-auto-apply| C2["applied immediately via store.py\n(admin_change, audit)"]
    B -->|always-pending| C3["queued to pending.yaml"]
    B -->|category-conditional\n(tool_enable, tool_update)| C3
    B -->|admin.cred_propose\n(name/kind/header, no value)| C3
    B -->|admin.toolkit_propose| C4["queued to toolkit_proposals.yaml\n(never pending.yaml)"]

    C3 --> D["Human reviews at /ui/requests, Change tab"]
    D -->|"approve (most actions)"| E1["store.py write + CSRF-protected action\n(admin_change, audit)"]
    D -->|"approve (cred_propose only) --\nhuman types the value here"| E3["credentials.py CredentialStore.create()\nvia /ui/pending/credential-fill, not apply_pending"]
    D -->|reject| E2["discarded (admin_denied, audit)"]

    C4 --> F["Human reviews at /ui/requests, Toolkit tab"]
    F -->|approve & deploy| G["merge + validate via load_tier1()\nwrite toolkits.yaml\nService.reload_config() -- no restart"]
    F -->|reject| E2
```

`approve`/`reject` (both tabs) are only reachable via `/ui/requests`, never
from `/admin/mcp` -- an agent can propose a change but can never approve its
own proposal.
