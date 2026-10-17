//! The console JSON API (`/api/v1`, port of `api/*`) and the browser
//! surface around it (`/app`, `/ui`).

use std::sync::Arc;

use crate::audit::AuditLog;
use crate::credentials::CredentialStore;
use crate::pending::PendingStore;
use crate::service::{Service, SharedIdentities};
use crate::store::ConfigStore;
use crate::toolkit_proposals::ToolkitProposalStore;

pub mod app;
pub mod deps;
pub mod events;
pub mod models;
pub mod service;
pub mod session;
pub mod web;

pub use app::ConsoleOptions;

/// Where the console API is mounted.
pub const API_PREFIX: &str = "/api/v1";

/// What the HTTP server knows about a request's origin after proxy
/// handling (`request.client.host`, `request.url.scheme`). The server
/// inserts it as a request extension; without it the console falls back to
/// the socket peer (`ConnectInfo`) and `http`.
#[derive(Debug, Clone, Default)]
pub struct RequestClient {
    pub host: Option<String>,
    pub scheme: Option<String>,
}

/// The committed OpenAPI document, served at `GET /api/v1/openapi.json`
/// (admins only).
pub fn openapi_json() -> String {
    app::OPENAPI_JSON.to_string()
}

/// Everything the console needs from the running server -- the arguments
/// Python's `server.build_app` hands to `ApiContext` and `build_ui_routes`.
/// `store` (and with it `pending` and `toolkit_proposals`) is `None` on a
/// read-only deployment.
#[derive(Clone)]
pub struct ConsoleDeps {
    pub service: Arc<Service>,
    pub identities: SharedIdentities,
    pub audit: Arc<AuditLog>,
    pub store: Option<Arc<ConfigStore>>,
    pub credentials: Option<Arc<CredentialStore>>,
    pub pending: Option<Arc<PendingStore>>,
    pub toolkit_proposals: Option<Arc<ToolkitProposalStore>>,
}

/// The routes `server.build_app` adds when the UI is enabled: the `/ui`
/// redirects and OAuth callbacks, the `/app` SPA, and `/api/v1`. They share
/// one session store, one login throttle and one OAuth-flow store, created
/// here. Authentication for these paths is the console's own (sessions),
/// not the bearer middleware, exactly as `AuthMiddleware` lets them through
/// in Python.
pub fn console_router(deps: ConsoleDeps) -> axum::Router {
    console_router_with(deps, ConsoleOptions::default())
}

/// [`console_router`] with non-default knobs (tests).
pub fn console_router_with(deps: ConsoleDeps, options: ConsoleOptions) -> axum::Router {
    use axum::routing::any;
    let ctx = deps::ApiContext {
        service: deps.service,
        identities: deps.identities,
        audit: deps.audit.clone(),
        sessions: Arc::new(session::SessionStore::default()),
        throttle: Arc::new(session::LoginThrottle::default()),
        store: deps.store,
        credentials: deps.credentials,
        pending: deps.pending,
        toolkit_proposals: deps.toolkit_proposals,
        oauth_states: Some(Arc::new(crate::oauth::OAuthStateStore::new())),
    };
    let hub = Arc::new(events::EventHub::new(options.max_subscribers, options.queue_limit));
    let listener_hub = hub.clone();
    deps.audit.add_listener(Box::new(move |record| listener_hub.publish(record)));
    let console = Arc::new(app::Console { ctx, hub, options });
    axum::Router::new()
        .route(API_PREFIX, any(app::api_entry))
        .route("/api/v1/", any(app::api_entry))
        .route("/api/v1/{*rest}", any(app::api_entry))
        .route(web::APP_PREFIX, any(app::web_entry))
        .route("/app/", any(app::web_entry))
        .route("/app/{*rest}", any(app::web_entry))
        .route("/ui", any(app::ui_entry))
        .route("/ui/", any(app::ui_entry))
        .route("/ui/{*rest}", any(app::ui_entry))
        .route("/", any(app::ui_entry))
        .route("/favicon.ico", any(app::ui_entry))
        .with_state(console)
}
