//! A tiny MCP server on `gatekeeper::mcp`, the Rust twin of
//! `tests/interop/ref_server.py` (the Python SDK configured the way
//! gatekeeper configures it). The interop tests drive both with the same
//! raw-HTTP probe and with the real Python SDK client.
//!
//!     cargo run --example mcp_echo [-- PORT]    # prints "PORT <n>"
//!
//! Routes:
//!   /mcp           stateful, with a CatalogNotifier (sessions, listen)
//!   /admin/mcp     stateless, no notifier
//!   POST /_change  toggles `demo.extra` and calls tool_catalog_changed()
//!   GET  /_tracked {"tracked": notifier.tracked_sessions()}

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::routing::{get, post};
use axum::{Json, Router};
use gatekeeper::mcp::{
    self, CallToolResult, CatalogNotifier, ListToolsResult, McpConfig, McpError, McpHandler, RequestContext, ServerInfo,
};
use serde_json::{json, Map, Value};

struct Echo {
    name: &'static str,
    instructions: &'static str,
    extra_tool: Arc<AtomicBool>,
    notifier: Option<CatalogNotifier>,
    /// The admin mount advertises only the first tool.
    only_first: bool,
}

fn tools(extra: bool) -> Vec<Value> {
    let mut out = vec![
        json!({
            "name": "demo.echo",
            "title": "Echo",
            "description": "Echo the text back.",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                            "required": ["text"], "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "idempotentHint": true, "destructiveHint": false},
        }),
        json!({"name": "demo.fail", "description": "Raises inside the handler.",
               "inputSchema": {"type": "object", "properties": {}}}),
        json!({"name": "demo.slow", "description": "Sleeps.",
               "inputSchema": {"type": "object", "properties": {"seconds": {"type": "number"}}}}),
    ];
    if extra {
        out.push(json!({"name": "demo.extra", "inputSchema": {"type": "object"}}));
    }
    out
}

#[async_trait]
impl McpHandler for Echo {
    fn server_info(&self) -> ServerInfo {
        ServerInfo::new(self.name, "9.9.9").with_instructions(self.instructions)
    }

    async fn list_tools(&self, ctx: &RequestContext) -> Result<ListToolsResult, McpError> {
        if let Some(n) = &self.notifier {
            n.track(ctx);
        }
        let mut all = tools(self.extra_tool.load(Ordering::SeqCst));
        if self.only_first {
            all.truncate(1);
        }
        Ok(ListToolsResult::new(all))
    }

    async fn call_tool(&self, _ctx: &RequestContext, name: &str, args: Map<String, Value>) -> Result<CallToolResult, McpError> {
        match name {
            "demo.echo" => {
                let text = args.get("text").map(gatekeeper::pyfmt::str_value).unwrap_or_else(|| "None".into());
                Ok(CallToolResult::text(text, false))
            }
            "demo.fail" => Err(McpError::internal("boom from handler")),
            "demo.slow" => {
                let seconds = args.get("seconds").and_then(Value::as_f64).unwrap_or(1.0);
                tokio::time::sleep(Duration::from_secs_f64(seconds)).await;
                Ok(CallToolResult::text("slept", false))
            }
            "demo.extra" => Ok(CallToolResult::text("extra", false)),
            other => Ok(CallToolResult::text(format!("No tool {}.", gatekeeper::pyfmt::repr_str(other)), true)),
        }
    }

    async fn on_initialized(&self, ctx: &RequestContext) {
        if let Some(n) = &self.notifier {
            n.track(ctx);
        }
    }
}

/// The whole app: both mounts and the two control routes. Call inside the
/// runtime that serves it. (`tests/mcp_interop.rs` includes this file.)
pub fn build_app() -> Router {
    let extra = Arc::new(AtomicBool::new(false));
    let notifier = CatalogNotifier::new();

    let agent = Arc::new(Echo {
        name: "echo",
        instructions: "Echo server for interop tests.",
        extra_tool: extra.clone(),
        notifier: Some(notifier.clone()),
        only_first: false,
    });
    let admin = Arc::new(Echo {
        name: "echo-admin",
        instructions: "Admin echo.",
        extra_tool: extra.clone(),
        notifier: None,
        only_first: true,
    });

    let change = {
        let (extra, notifier) = (extra.clone(), notifier.clone());
        move || async move {
            extra.fetch_xor(true, Ordering::SeqCst);
            notifier.tool_catalog_changed();
            Json(json!({"ok": true}))
        }
    };
    let tracked = {
        let notifier = notifier.clone();
        move || async move { Json(json!({"tracked": notifier.tracked_sessions()})) }
    };

    Router::new()
        .merge(mcp::router(agent, McpConfig::stateful("/mcp").with_notifier(notifier.clone())))
        .merge(mcp::router(admin, McpConfig::stateless("/admin/mcp")))
        .route("/_change", post(change))
        .route("/_tracked", get(tracked))
}

#[allow(dead_code)]
#[tokio::main]
async fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    let app = build_app();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    println!("PORT {}", listener.local_addr().expect("addr").port());
    use std::io::Write;
    std::io::stdout().flush().ok();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.expect("serve");
}
