//! gatekeeper -- MCP server for controlled host operations.
//!
//! Agents do not get a shell, but a fixed set of validated actions -- each
//! with its own token, own permissions, and full audit. Module names follow
//! the Python modules of the implementation this crate replaced (removed
//! in 1.16.0): `tier1.py` -> [`tier1`], `execute_http.py` -> `execute::http`.

/// The release version: `version` in `rust/Cargo.toml`. Every change on
/// `main` is a release and bumps it (RELEASE.md, "The rule").
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Foundation: Python-compatible formats and file discipline.
pub mod atomic;
pub mod errors;
pub mod fnmatch;
pub mod pathutil;
pub mod pyfmt;
pub mod pyjson;
pub mod pyre;
pub mod timeutil;
pub mod yaml;

// Self-contained stores and helpers.
pub mod artifacts;
pub mod messages;
pub mod release_notes;
pub mod toolkit_reference;

// Identities, audit, credentials, proxies, the pending queue.
pub mod audit;
pub mod credentials;
pub mod identity;
pub mod pending;
pub mod realip;

// Configuration data model.
pub mod catalog;
pub mod ratelimit;
pub mod runas;
pub mod tier1;
pub mod validate;

// Executors.
pub mod execute;

// Protocol layer.
pub mod mcp;

// Console: OAuth sign-in and what is left of /ui.
pub mod oauth;
pub mod ui;

pub mod privdrop;

// Application layer.
pub mod admin_service;
pub mod api;
pub mod service;
pub mod store;
pub mod toolkit_proposals;

// HTTP server and CLI.
pub mod admin_server;
pub mod cli;
pub mod server;
