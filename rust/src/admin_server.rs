//! The second MCP server: the `admin.*` namespace (port of
//! `admin_server.py`, REQUIREMENTS.md FR-2.8/2.9).
//!
//! A fixed tool list wired straight to [`AdminService`] -- this handler
//! shares no `Catalog`/tool registry with the agent-facing one in
//! [`crate::server`], so admin tools cannot leak into `/mcp` (or vice
//! versa) by construction. The server mounts it at `/admin/mcp`, under the
//! same auth middleware that role-gates each mount.
//!
//! `approve` and `reject` are not on the list and have no handler here --
//! `admin_service::apply_pending` is called only from the console API's
//! request-decision routes. There is no code path from this file that
//! reaches it.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::admin_service::{AdminService, EXPOSED};
use crate::mcp::{CallToolResult, ListToolsResult, McpError, McpHandler, RequestContext, ServerInfo};
use crate::server::identity_from;

/// The admin server's `instructions`.
pub const INSTRUCTIONS: &str = "Self-service catalog and grant management for gatekeeper. \
Read-only queries and low-risk changes (creating a disabled \
tool, disabling a tool, enabling/updating a read-category \
tool) apply immediately. Anything that expands what an agent \
can do -- enabling/updating a write tool, deleting a tool, \
granting access, changing a credential -- is written to a pending queue and takes \
effect only once a human approves it at /app/requests (Change tab). There is \
no way to approve your own proposal from this endpoint.";

/// The fixed `admin.*` tool list (`admin_server._TOOLS`), as the SDK dumps
/// it (`model_dump(by_alias=True, exclude_none=True)`). Generated from the
/// Python module, not retyped; `tests/admin_mcp.rs` compares it against the
/// Python list whenever the reference interpreter is available.
const TOOLS_JSON: &str = r####"
[
 {
  "name": "admin.tool_list",
  "title": "List tool definitions",
  "description": "Lists every tool definition (id, enabled, deleted, current version, category, full version history). Read-only.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "include_deleted": {
     "type": "boolean"
    }
   },
   "additionalProperties": false
  }
 },
 {
  "name": "admin.tool_get",
  "title": "Get one tool definition",
  "description": "Returns one tool's full record, including its version history. Read-only.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "id": {
     "type": "string"
    }
   },
   "required": [
    "id"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.tool_create",
  "title": "Create a tool definition",
  "description": "Creates a new tool definition. Always applies immediately, but the tool is always created disabled (enabled: false) regardless of what 'spec' says -- enabling it is a separate, auditable step via admin.tool_enable.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "spec": {
     "type": "object",
     "additionalProperties": true
    }
   },
   "required": [
    "spec"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.tool_update",
  "title": "Update a tool definition",
  "description": "Appends a new version to an existing tool definition (never overwrites -- old versions remain fetchable via admin.tool_get). Applies immediately if the resulting category is 'read'; otherwise it is written to the pending queue for a human to approve at /app/requests (Change tab).",
  "inputSchema": {
   "type": "object",
   "properties": {
    "id": {
     "type": "string"
    },
    "spec": {
     "type": "object",
     "additionalProperties": true
    }
   },
   "required": [
    "id",
    "spec"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.tool_enable",
  "title": "Enable a tool",
  "description": "Enables a tool. Applies immediately if its category is 'read'; otherwise it is written to the pending queue for a human to approve at /app/requests (Change tab).",
  "inputSchema": {
   "type": "object",
   "properties": {
    "id": {
     "type": "string"
    }
   },
   "required": [
    "id"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.tool_disable",
  "title": "Disable a tool",
  "description": "Disables a tool. Always applies immediately -- disabling only narrows access.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "id": {
     "type": "string"
    }
   },
   "required": [
    "id"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.tool_delete",
  "title": "Delete a tool definition",
  "description": "Soft-deletes a tool definition (version history is retained). Always written to the pending queue for a human to approve.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "id": {
     "type": "string"
    }
   },
   "required": [
    "id"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.tool_validate",
  "title": "Validate a tool definition",
  "description": "Checks a tool definition against Tier 1 without storing anything -- the same validation path startup and every write use. Read-only.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "spec": {
     "type": "object",
     "additionalProperties": true
    }
   },
   "required": [
    "spec"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.grant_list",
  "title": "List grants",
  "description": "Lists identities and the tool IDs/scopes each holds. Read-only.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "tool_id": {
     "type": "string"
    },
    "identity_id": {
     "type": "string"
    }
   },
   "additionalProperties": false
  }
 },
 {
  "name": "admin.grant_set",
  "title": "Set an identity's tool grants",
  "description": "Replaces an existing identity's tool grants (and, if given, its scopes). Cannot create a new identity. Always written to the pending queue for a human to approve -- this is the only identity mutation exposed on /admin/mcp.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "identity_id": {
     "type": "string"
    },
    "tools": {
     "type": "array",
     "items": {
      "type": "string"
     }
    },
    "scopes": {
     "type": "array",
     "items": {
      "type": "string"
     }
    }
   },
   "required": [
    "identity_id",
    "tools"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.role_set",
  "title": "Change an identity's role",
  "description": "Changes an existing identity's role (agent/viewer/admin). Cannot create a new identity. Always written to the pending queue for a human to approve -- role changes go through the same review surface as grant changes.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "identity_id": {
     "type": "string"
    },
    "role": {
     "type": "string",
     "enum": [
      "agent",
      "viewer",
      "admin"
     ]
    }
   },
   "required": [
    "identity_id",
    "role"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.audit_query",
  "title": "Query the audit log",
  "description": "Reads recent audit log entries, optionally filtered. Read-only.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "identity": {
     "type": "string"
    },
    "tool": {
     "type": "string"
    },
    "outcome": {
     "type": "string"
    },
    "limit": {
     "type": "integer",
     "minimum": 1,
     "maximum": 1000
    }
   },
   "additionalProperties": false
  }
 },
 {
  "name": "admin.pending_list",
  "title": "List pending actions",
  "description": "Lists proposals in the pending queue, optionally filtered by status (pending/approved/rejected/stale). Read-only -- approving or rejecting a proposal is only possible through /app/requests (Change tab), never from here.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "status": {
     "type": "string"
    }
   },
   "additionalProperties": false
  }
 },
 {
  "name": "admin.proposal_list",
  "title": "List toolkit proposals",
  "description": "Lists the toolkit-proposal queue -- what admin.toolkit_propose, toolkit_update, toolkit_delete and credential_bind filed, which admin.pending_list does not show. Optionally filtered by kind (create/update/delete/bind) and status (pending/deployed/rejected/withdrawn). Read-only.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "kind": {
     "type": "string",
     "enum": [
      "bind",
      "create",
      "delete",
      "update"
     ]
    },
    "status": {
     "type": "string",
     "enum": [
      "deployed",
      "pending",
      "rejected",
      "withdrawn"
     ]
    }
   },
   "additionalProperties": false
  }
 },
 {
  "name": "admin.release_notes",
  "title": "Read this deployment's release notes",
  "description": "Returns RELEASE.md -- the notes for every version of the gatekeeper you are managing, newest first. `full: true` gives the whole file verbatim including the release rule, the procedure and the versioning scheme; otherwise it is version-by-version, narrowable with `version` (exact), `search` (case-insensitive, matched against heading and body) and `limit` (default 10). Read-only. Check here what a version actually changed before blaming a deployment for it.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "version": {
     "type": "string"
    },
    "search": {
     "type": "string"
    },
    "limit": {
     "type": "integer",
     "minimum": 1,
     "maximum": 200
    },
    "full": {
     "type": "boolean"
    }
   },
   "additionalProperties": false
  }
 },
 {
  "name": "admin.toolkit_list",
  "title": "List live toolkits",
  "description": "Lists every toolkit and destination defined in the running Tier 1 configuration (toolkits.yaml) -- executor, binaries, path roots, protected resources, ceilings. Read-only; check reality here before drafting a proposal instead of guessing.",
  "inputSchema": {
   "type": "object",
   "properties": {},
   "additionalProperties": false
  }
 },
 {
  "name": "admin.cred_list",
  "title": "List credential metadata",
  "description": "Lists credential slots and read-only detection metadata: kind, header/param name, used-by references, optional probe URL/status, and suspect auth-failure timestamps. Values, ciphertext, and rotation secret material are never returned.",
  "inputSchema": {
   "type": "object",
   "properties": {},
   "additionalProperties": false
  }
 },
 {
  "name": "admin.cred_delete",
  "title": "Delete a credential slot",
  "description": "Deletes a credential slot by name. Applies immediately -- it removes a credential, never creates or reveals one -- but is refused while any toolkit or destination still references the slot (admin.cred_list's 'used_by'), naming them, since deleting a bound slot would leave those refusing every call with 'credential is not configured yet'. An unknown name is refused the same way, by name. This is the way out of a wrong 'kind': a slot's kind is fixed at creation, so a token created as 'bearer' for a service that wants 'api_key_header' is deleted here and proposed again with the right kind via admin.cred_propose -- where a human still types the value. To fix a wrong kind or header while keeping the value, use admin.cred_update instead. Audited by name; no value is accepted or returned.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "name": {
     "type": "string",
     "description": "Name of the credential slot to delete (admin.cred_list) -- a name, never a value"
    }
   },
   "required": [
    "name"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.cred_propose",
  "title": "Propose a new credential slot",
  "description": "Proposes a new named credential -- name, kind, and (for api_key_header/url_query) the header/param name. There is no 'value' property, and one sent anyway is explicitly refused, never stored or ignored quietly: no operation on /admin/mcp ever carries a secret (FR-10.2/10.8), not even to create one. Always written to the pending queue and never auto-applies -- a human reviews the proposed name/kind/header at /app/requests and, if they approve, types the actual secret value there themselves; the value never exists anywhere an agent could have written it.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "name": {
     "type": "string"
    },
    "kind": {
     "type": "string",
     "enum": [
      "api_key_header",
      "basic",
      "bearer",
      "docker_tls",
      "oauth2",
      "ssh_password",
      "ssh_private_key",
      "url_path",
      "url_query",
      "ws_api_key"
     ]
    },
    "header": {
     "type": "string"
    },
    "header_format": {
     "type": "string",
     "description": "api_key_header only: the header value with {value} where the secret goes, for a service that wants more than the bare token -- e.g. MediaBrowser Token=\"{value}\" for Jellyfin's Authorization header. Empty clears it."
    },
    "probe_url": {
     "type": "string"
    }
   },
   "required": [
    "name",
    "kind"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.cred_update",
  "title": "Propose changing a credential slot, keeping its value",
  "description": "Proposes changing an existing credential slot's kind, header/param name, header value format, probe URL and/or name, while the stored secret stays exactly as it is -- the in-place repair for a slot whose header or kind is wrong (a token sent as X-Emby-Token to a server that wants Authorization), without deleting it or having a human paste the value again. Fields left out keep their current value. There is no 'value' property and anything value-shaped is explicitly refused (FR-10.2/10.8); a new value is a rotation in /app/credentials. Always written to the pending queue and never auto-applies: a human approves it at /app/requests (Change tab), where the before/after is shown. A kind can only change within the same value shape (the token kinds api_key_header, bearer, url_path, url_query and ws_api_key are interchangeable; a token never becomes a docker_tls or oauth2 bundle). 'new_name' is refused while any toolkit or destination still references the slot (admin.cred_list's 'used_by'), since the binding is Tier 1; kind and header changes are not, because the binding is by name.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "name": {
     "type": "string",
     "description": "Existing credential slot (admin.cred_list)"
    },
    "new_name": {
     "type": "string",
     "description": "Rename the slot; only while nothing references it"
    },
    "kind": {
     "type": "string",
     "enum": [
      "api_key_header",
      "basic",
      "bearer",
      "docker_tls",
      "oauth2",
      "ssh_password",
      "ssh_private_key",
      "url_path",
      "url_query",
      "ws_api_key"
     ]
    },
    "header": {
     "type": "string",
     "description": "Header name (api_key_header) or query parameter name (url_query)"
    },
    "header_format": {
     "type": "string",
     "description": "api_key_header only: the header value with {value} where the secret goes, for a service that wants more than the bare token -- e.g. MediaBrowser Token=\"{value}\" for Jellyfin's Authorization header. Empty clears it."
    },
    "probe_url": {
     "type": "string",
     "description": "http(s) URL, or an empty string to clear it"
    }
   },
   "required": [
    "name"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.credential_bind",
  "title": "Propose binding a toolkit to a credential",
  "description": "Proposes pointing an existing toolkit at an existing credential slot -- two names and nothing else. There is no 'value' property and anything value-shaped sent anyway (value, secret, token, password, api_key, ...) is explicitly refused rather than stored or ignored quietly: no operation on /admin/mcp ever carries secret material (FR-10.2/10.8). This is the half admin.cred_propose does not cover -- a credential nothing references is inert, and the binding itself is Tier 1 (FR-10.4), so it is always written to the toolkit-proposal queue and never applies on its own, not even when both names already exist. A human reviews it at /app/requests (Toolkit tab) and, if they approve, gatekeeper writes 'credential: <name>' under that toolkit in toolkits.yaml, re-validates it, and reloads it into the running process -- no redeploy needed, but also no way for this call to make it live by itself. Toolkit-level only: a destination's own credential override, path_roots, protected_resources and limits stay deploy-time only (FR-4.11) and are rejected here. Both names are checked against the running configuration (admin.toolkit_list, admin.cred_list), so an unknown one is refused immediately, by name.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "toolkit": {
     "type": "string",
     "description": "Name of an existing toolkit (admin.toolkit_list)"
    },
    "credential": {
     "type": "string",
     "description": "Name of an existing credential slot (admin.cred_list) -- a name, never a value"
    }
   },
   "required": [
    "toolkit",
    "credential"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.toolkit_propose",
  "title": "Propose a new toolkit",
  "description": "Proposes adding a brand-new toolkit to Tier 1. Always written to the toolkit-proposal queue -- never applies, not even for a read-only-looking toolkit -- since this changes what is possible at all (REQUIREMENTS.md §6), not just who can do what. A human reviews it at /app/requests (Toolkit tab) and, if they approve, gatekeeper validates, writes toolkits.yaml, and reloads it into the running process itself -- no redeploy needed, but also no way for this call to make it live on its own. Editing an existing toolkit is not supported here: a name that already exists is refused right away, with the way to change that toolkit instead (admin.toolkit_update, or toolkits.yaml and a reload for path_roots/protected_resources/limits).",
  "inputSchema": {
   "type": "object",
   "properties": {
    "name": {
     "type": "string"
    },
    "spec": {
     "type": "object",
     "additionalProperties": true
    },
    "confirm_broad_cidrs": {
     "type": "boolean",
     "description": "Set true only when an allowed_cidrs entry is deliberately wider than /16 (IPv4) or /48 (IPv6); without it such a proposal is refused. The reviewer sees the flag."
    }
   },
   "required": [
    "name",
    "spec"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.toolkit_update",
  "title": "Propose updating a toolkit's executor, binaries or network targets",
  "description": "Proposes changing an existing toolkit's executor type, binaries, denied_args, run_as (the OS user a 'file' toolkit's operations run as), and -- on an http, opencode or kuma toolkit -- allowed_hosts (exact hostnames such as 'api.github.com'; no wildcards, no IP addresses) and allowed_cidrs, plus an http toolkit's allowed_methods and allowed_path_prefixes, and max_timeout_seconds/max_output_bytes. Only these fields can be proposed — path_roots and protected_resources remain deploy-time only (FR-4.11) and are rejected. A CIDR wider than /16 (IPv4) or /48 (IPv6) needs confirm_broad_cidrs: true, and a private range is refused on a toolkit whose target is a public address. A hostname toolkit never reaches a private, loopback, link-local or multicast address, whatever its allowed_cidrs say. Like admin.toolkit_propose, this changes Tier 1 -- what is possible at all, not just who can do what -- so it is always written to the toolkit-proposal queue and never applies on its own. A human reviews it at /app/requests (Toolkit tab) and, if they approve, gatekeeper validates, writes toolkits.yaml, and reloads it into the running process itself -- no redeploy needed, but also no way for this call to make it live by itself. Example: propose switching executor from 'local' to 'file' by passing updates={\"executor\": \"file\", \"binaries\": [], \"denied_args\": []}, or pointing an existing 'file' toolkit at another user with updates={\"run_as\": \"3001:3001\"}, or moving the 'github' toolkit from fixed addresses to its hostname with updates={\"allowed_hosts\": [\"api.github.com\"], \"allowed_cidrs\": null}.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "name": {
     "type": "string",
     "description": "Toolkit name"
    },
    "updates": {
     "type": "object",
     "description": "Fields to propose changing (executor, binaries, denied_args, run_as, allowed_hosts, allowed_cidrs only)",
     "properties": {
      "executor": {
       "type": "string"
      },
      "binaries": {
       "type": "array",
       "items": {
        "type": "string"
       }
      },
      "denied_args": {
       "type": "array",
       "items": {
        "type": "string"
       }
      },
      "run_as": {
       "type": [
        "string",
        "null"
       ],
       "description": "'file' toolkits only: the OS user its file operations run as -- an account name in the container image ('hermes') or a numeric 'uid:gid' pair ('3001:3001'). A bare uid is rejected. null clears it, handing the toolkit back to the container user. Only takes effect where the container was started privileged enough to change user; elsewhere the calls fail."
      },
      "allowed_hosts": {
       "type": [
        "array",
        "null"
       ],
       "items": {
        "type": "string"
       },
       "description": "http/opencode/kuma toolkits only: exact hostnames the toolkit may connect to, e.g. ['api.github.com']. Every address a name resolves to must be public. null removes it."
      },
      "allowed_cidrs": {
       "type": [
        "array",
        "null"
       ],
       "items": {
        "type": "string"
       },
       "description": "http/opencode/kuma toolkits only: IP networks the resolved address must lie in. With allowed_hosts set it only narrows further. null removes it. Private ranges are refused when the target is a public address."
      },
      "allowed_methods": {
       "type": "array",
       "items": {
        "type": "string"
       },
       "description": "http toolkits only: HTTP methods its tools may use."
      },
      "allowed_path_prefixes": {
       "type": "array",
       "items": {
        "type": "string"
       },
       "description": "http toolkits only: path prefixes (each starting with '/') its tools' paths must lie under."
      },
      "max_timeout_seconds": {
       "type": "integer",
       "minimum": 1
      },
      "max_output_bytes": {
       "type": "integer",
       "minimum": 1
      }
     },
     "additionalProperties": false
    },
    "confirm_broad_cidrs": {
     "type": "boolean",
     "description": "Set true only when an allowed_cidrs entry is deliberately wider than /16 (IPv4) or /48 (IPv6); without it such a proposal is refused. The reviewer sees the flag."
    }
   },
   "required": [
    "name",
    "updates"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.toolkit_delete",
  "title": "Propose deleting a toolkit",
  "description": "Proposes removing an existing toolkit from Tier 1. Refused at deploy time if the toolkit no longer exists or any non-deleted tool still references it. Like admin.toolkit_propose/toolkit_update, this changes Tier 1 -- what is possible at all, not just who can do what -- so it is always written to the toolkit-proposal queue and never applies on its own. A human reviews it at /app/requests (Toolkit tab) and, if they approve, gatekeeper removes it from toolkits.yaml and reloads it into the running process itself -- no restart needed, but also no way for this call to make it take effect by itself.",
  "inputSchema": {
   "type": "object",
   "properties": {
    "name": {
     "type": "string",
     "description": "Toolkit name"
    }
   },
   "required": [
    "name"
   ],
   "additionalProperties": false
  }
 },
 {
  "name": "admin.proposal_withdraw",
  "title": "Withdraw your own toolkit proposal",
  "description": "Takes a still-pending toolkit proposal off the queue -- only one you filed yourself (proposal_id from admin.toolkit_propose/toolkit_update/toolkit_delete/credential_bind, or admin.proposal_list). Approves nothing and never touches toolkits.yaml; deploying or rejecting someone's proposal stays with a human at /app/requests (Toolkit tab).",
  "inputSchema": {
   "type": "object",
   "properties": {
    "proposal_id": {
     "type": "string"
    }
   },
   "required": [
    "proposal_id"
   ],
   "additionalProperties": false
  }
 }
]
"####;

/// The tool list. Every entry's bare name is in `admin_service::EXPOSED`
/// and nothing else is -- checked on first use, so a drift between the two
/// fails loudly instead of quietly exposing (or hiding) a tool.
pub fn admin_tools() -> &'static [Value] {
    static TOOLS: OnceLock<Vec<Value>> = OnceLock::new();
    TOOLS.get_or_init(|| {
        let tools: Vec<Value> = serde_json::from_str(TOOLS_JSON).expect("admin tool list is valid JSON");
        if let Err(message) = check_drift(&tools) {
            panic!("{message}");
        }
        tools
    })
}

/// `_names != set(EXPOSED_ACTIONS)`.
fn check_drift(tools: &[Value]) -> Result<(), String> {
    let names: BTreeSet<String> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .map(|n| n.strip_prefix("admin.").unwrap_or(n).to_string())
        .collect();
    let exposed: BTreeSet<String> = EXPOSED.iter().map(|s| s.to_string()).collect();
    if names != exposed {
        return Err(format!(
            "admin_server._TOOLS and admin_service.EXPOSED_ACTIONS have drifted apart: {} != {}",
            set_repr(&names),
            set_repr(&exposed)
        ));
    }
    Ok(())
}

fn set_repr(items: &BTreeSet<String>) -> String {
    let inner: Vec<String> = items.iter().map(|s| crate::pyfmt::repr_str(s)).collect();
    format!("{{{}}}", inner.join(", "))
}

/// `build_admin_mcp_server`.
pub struct AdminMcp {
    pub admin_service: Arc<AdminService>,
}

impl AdminMcp {
    pub fn new(admin_service: AdminService) -> Self {
        AdminMcp { admin_service: Arc::new(admin_service) }
    }
}

#[async_trait]
impl McpHandler for AdminMcp {
    /// The real version, not a hand-set constant: both servers describe
    /// the same process.
    fn server_info(&self) -> ServerInfo {
        ServerInfo::new("gatekeeper-admin", crate::VERSION).with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(&self, ctx: &RequestContext) -> Result<ListToolsResult, McpError> {
        // Requires a valid identity like the agent-facing server does, even
        // though the middleware has already role-gated this mount.
        identity_from(ctx).map_err(|d| McpError::internal(d.to_string()))?;
        Ok(ListToolsResult::new(admin_tools().to_vec()))
    }

    async fn call_tool(
        &self,
        ctx: &RequestContext,
        name: &str,
        args: Map<String, Value>,
    ) -> Result<CallToolResult, McpError> {
        let identity = identity_from(ctx).map_err(|d| McpError::internal(d.to_string()))?;
        let name = name.strip_prefix("admin.").unwrap_or(name).to_string();
        let admin = self.admin_service.clone();
        // The stores are synchronous (file I/O, scrypt): off the event loop.
        let outcome = tokio::task::spawn_blocking(move || admin.call(&identity.id, &name, &args))
            .await
            .map_err(|e| McpError::internal(e.to_string()))?;
        Ok(match outcome {
            // `json.dumps(result, default=str)`.
            Ok(result) => CallToolResult::text(crate::pyjson::dumps(&result), false),
            // AdminActionError, WriteRefused, ConfigError: all `ConfigError`.
            Err(exc) => CallToolResult::text(exc.to_string(), true),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_matches_the_exposed_actions() {
        let tools = admin_tools();
        assert_eq!(tools.len(), EXPOSED.len());
        assert!(tools.iter().all(|t| t["name"].as_str().unwrap().starts_with("admin.")));
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(!names.contains(&"admin.approve") && !names.contains(&"admin.reject"));
    }

    #[test]
    fn drift_is_reported() {
        let mut tools = admin_tools().to_vec();
        tools.pop();
        let message = check_drift(&tools).unwrap_err();
        assert!(message.starts_with("admin_server._TOOLS and admin_service.EXPOSED_ACTIONS have drifted apart: {'"));
    }
}
