//! The console JSON API (`/api/v1`, port of `api/*`) and the browser
//! surface around it (`/app`, `/ui`).

use std::sync::Arc;

use crate::audit::AuditLog;
use crate::credentials::CredentialStore;
use crate::pending::PendingStore;
use crate::service::{Service, SharedIdentities};
use crate::store::ConfigStore;
use crate::toolkit_proposals::ToolkitProposalStore;

pub mod service;

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
/// here.
///
/// PORT NOTE: placeholder contract -- the console-API port replaces this
/// body. The HTTP server merges the returned router as-is; authentication
/// for these paths is the console's own (sessions), not the bearer
/// middleware, exactly as `AuthMiddleware` lets them through in Python.
pub fn console_router(_deps: ConsoleDeps) -> axum::Router {
    axum::Router::new()
}
