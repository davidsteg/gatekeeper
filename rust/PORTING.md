# Porting notes (Python -> Rust)

Working notes for the rewrite. The Python package under `src/gatekeeper/`
is the specification: the Rust crate must keep its behavior, its file
formats and its wire formats, so an existing deployment can switch binaries
without touching a config file.

## Rules

- **Port faithfully.** Same validation, same order of checks, same
  defaults. Every user-visible string (error messages, audit field names,
  JSON keys, agent-facing text) is copied verbatim. Where Python formats
  with `{x!r}`, use `pyfmt::repr_str` / `repr_list` / `repr_value`, so a
  message reads `No tool with ID 'x'.` exactly as before.
- **No new scope.** No features the Python code does not have. A Python
  quirk that is clearly a bug may be fixed, but note it in a comment
  starting with `PORT NOTE:`.
- **Dicts are `serde_json::Value`** (the crate enables `preserve_order`,
  so key order is insertion order like a Python dict). Typed structs are
  fine and preferred for parsed config, but keep the raw `Value` wherever
  Python keeps the raw dict (catalog `raw`, pending payloads, ...).
- **Formats.** YAML in/out goes through `crate::yaml` (PyYAML 1.1
  semantics) or `crate::atomic::{load_cached, dump, atomic_write}`. JSON
  text that Python produced with `json.dumps` goes through `crate::pyjson`
  (Python separators and escaping). Operator-written regexes
  (`pattern:` in tool specs) go through `crate::pyre::PyRegex`; internal
  fixed regexes use the `regex` crate. `fnmatch.fnmatchcase` is
  `crate::fnmatch::fnmatchcase`. `os.path` functions are in
  `crate::pathutil` (non-strict `realpath`, `commonpath`, `normpath`).
  Timestamps are in `crate::timeutil`.
- **Errors.** `ConfigError` (with `kind` for the Python subclasses
  `Tier1Violation`, `WriteRefused`, `AdminActionError`) and `Denied`
  (`DenialReason` + detail) live in `crate::errors`.
- **Sync core, async edges.** Config, catalog, identity, audit and the
  stores are synchronous (`std::sync`/`parking_lot` locks). Executors and
  servers are async on tokio.
- **Secrets.** Credential values are never logged, never returned by an API
  and never written to a plaintext file (FR-10.2).
- **Tests.** Port the Python tests that cover the module (grep `tests/` for
  its name) into `#[cfg(test)] mod tests` or `rust/tests/*.rs`. Run
  `cargo test` and `cargo build` with zero warnings before committing.
- The Python reference environment is `/tmp/claude-0/venv` (`mcp`,
  `pyyaml`, `pytest`, ... installed). Use it to check what Python actually
  does when the source leaves a doubt.

## Module map

| Python | Rust |
|---|---|
| `_atomic.py` | `atomic` |
| `errors.py` | `errors` |
| `tier1.py`, `catalog.py`, `validate.py` | `tier1`, `catalog`, `validate` |
| `_runas.py` | `runas` |
| `identity.py`, `audit.py`, `credentials.py`, `realip.py` | same names |
| `pending.py`, `toolkit_proposals.py`, `store.py` | same names |
| `messages.py`, `artifacts.py`, `release_notes.py`, `toolkit_reference.py` | same names |
| `ratelimit.py` | `ratelimit` |
| `notifications.py` + MCP SDK transport | `mcp` |
| `service.py` | `service` |
| `execute*.py` | `execute::{local, http, truenas, ssh, file, google, microsoft, opencode, agent, artifact, kuma, git}` |
| `_unpriv.py`, `_selfdrop.py` | `privdrop` |
| `server.py`, `admin_server.py`, `admin_service.py` | `server`, `admin_server`, `admin_service` |
| `api/*`, `oauth.py`, `ui.py` | `api::*`, `oauth`, `ui` |
| `__main__.py` | `main.rs` (+ `cli`) |
