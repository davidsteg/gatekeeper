//! gatekeeper -- MCP server for controlled host operations.
//!
//! Agents do not get a shell, but a fixed set of validated actions -- each
//! with its own token, own permissions, and full audit. This crate is the
//! Rust implementation; module names follow the Python modules they
//! replace (`tier1.py` -> [`tier1`], `execute_http.py` -> `execute::http`).

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

// Identities, audit, credentials, proxies, the pending queue.
pub mod audit;
pub mod credentials;
pub mod identity;
pub mod pending;
pub mod realip;
