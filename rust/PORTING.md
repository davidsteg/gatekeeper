# Porting history (Python -> Rust)

gatekeeper was first written in Python. This crate is a faithful port of
that package: same validation and order of checks, same defaults, every
user-visible string (error messages, audit field names, JSON keys,
agent-facing text) copied verbatim, and the same file and wire formats, so
an existing deployment switched binaries without touching a config file.

- **1.13.0** -- the image runs this crate instead of the Python package.
  The Python package stayed in the repository as the reference, and the
  parity tests compared against it live.
- **1.17.0** -- the Python package, its tests and `pyproject.toml` were
  removed. What it produced is frozen in `tests/fixtures/` (see below);
  the release version moved to `Cargo.toml`. Only the vendored Google and
  Microsoft CLI scripts (`../scripts/`) are still Python.

## What the port kept on purpose

- **Python formats.** YAML in/out goes through `crate::yaml` (PyYAML 1.1
  semantics) or `crate::atomic::{load_cached, dump, atomic_write}`. JSON
  text the Python version wrote with `json.dumps` goes through
  `crate::pyjson`. Operator-written regexes (`pattern:` in tool specs) go
  through `crate::pyre::PyRegex`; `fnmatch.fnmatchcase` is
  `crate::fnmatch::fnmatchcase`; `os.path` is `crate::pathutil`; messages
  that Python formatted with `{x!r}` use `pyfmt::repr_str` / `repr_list` /
  `repr_value`.
- **`PORT NOTE:` comments** mark the places where the port deliberately
  differs -- mostly where Python crashed on malformed input and the port
  returns the error a caller would expect.
- **Module names** follow the Python modules they replaced:

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

## Frozen fixtures

Generated from the Python implementation before it was removed and never
regenerated. A deliberate change to one of these outputs is edited into
the fixture by hand, in the same commit:

- `tests/fixtures/error_cases_golden.json` -- Tier 1 / tool-spec error texts.
- `tests/fixtures/examples_golden.json` -- `config/examples/` as loaded.
- `tests/fixtures/init_golden/` -- what `init --audit-dir /audit` wrote.
- `tests/fixtures/admin_tools_golden.json` -- the `admin.*` tool list.
- `tests/fixtures/toolkit_reference_golden.json` -- the reference blocks.
- `tests/fixtures/shipped_cli_argv_golden.json` -- the minimal argv of every
  shipped google/microsoft tool (also run against the real scripts by
  `../tests/test_cli_grammar.py`).
- `tests/fixtures/mcp_wire_python_transcript.txt` -- `tests/interop/probe.py`
  against the Python SDK server as the Python gatekeeper configured it.
- `tests/fixtures/python_written/` -- token hashes, a credential store and
  its key, as Python wrote them; `tests/python_compat.rs` reads them back.
- `tests/data/mcp_envelope_errors.json` -- pydantic's envelope validation
  texts (`tests/interop/envelope_errors.py`, needs only the MCP SDK).
