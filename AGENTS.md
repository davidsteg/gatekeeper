# AGENTS.md — gatekeeper

> **MCP server for controlled host operations.** Agents do not get a shell,
> but a fixed set of validated actions — each with its own token, own
> permissions, and full audit.

This file is for **agent behavior only** — what to do, in what order, and
what has bitten a previous session. For what the project *is* (architecture,
security model, executors, UI, audit format), see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). For deployment/environment
details, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). For what's built vs.
not, see [docs/ROADMAP.md](docs/ROADMAP.md).

## Quick facts

| | |
|---|---|
| **Repo** | `davidsteg/gatekeeper` |
| **Language** | Rust (`rust/`, the one implementation; the image runs it). Python 3.12+ only for the vendored CLI scripts the `google`/`microsoft` executors run (`scripts/`) |
| **Dependencies** | `rust/Cargo.toml`, locked in `rust/Cargo.lock`; the scripts' venv is installed by the Dockerfile (`constraints.txt`) |
| **Tests** | `cargo test` in `rust/`, plus `npm test`, `tsc` and lint in `frontend/`, plus `python -m pytest -q` for `scripts/` — all must pass before push |

Check the current version in `rust/Cargo.toml` (`version`), not here — it
changes every release and a hardcoded number in this file would just go
stale.

## Release workflow (mandatory)

**Every change on `main` is a release.** No batch releases — see
[RELEASE.md](RELEASE.md) for the full rule and rationale.

1. **Version bump** — `version` in `rust/Cargo.toml`, in the same commit as
   the change, and `rust/Cargo.lock` with it (any `cargo build` updates its
   `gatekeeper` entry; CI builds `--locked` and fails on a stale lock).
2. **`RELEASE.md`** — add a section `## <version>` (no `v` prefix), above
   the previous entry. **CI enforces this and fails the build if it's
   missing** — see "Known pitfalls" below; this is not optional housekeeping.
3. **Doc check** — before committing, check whether README.md,
   `docs/ARCHITECTURE.md`, and `docs/ROADMAP.md` still describe reality. Keep
   them updated *in the same commit* as the code change, not as a followup —
   a stale "not implemented yet" line is worse than none.
4. **Commit** — descriptive message, version in the subject if useful.
5. **Push** — `git push origin main`. Prefer the `gh` CLI's own auth when
   available. If it isn't and pushing needs a PAT, put it only in the
   remote URL, never in a file: `git remote set-url origin
   "https://<PAT>@github.com/davidsteg/gatekeeper.git"`.
6. **Verify** — check the run, don't assume: `gh run list --limit 3` /
   `gh run watch <id> --exit-status`. The GitHub Action runs tests first
   (this is where the `RELEASE.md` check lives — see "Known pitfalls"),
   then, if the version is new, builds the image, pushes to Docker Hub,
   tags `vX.Y.Z`, and cuts a GitHub Release from the `RELEASE.md` section.

### Versioning

- **MAJOR** — Tier 1 changes meaning, or an existing deployment does not
  start without adjustment.
- **MINOR** — new toolkits, executors, UI features, new runtime behavior.
- **PATCH** — bug fixes, including security-relevant ones.

## Testing

```bash
cd rust
RUSTFLAGS="-D warnings" cargo build --locked --all-targets
cargo test --locked
cd .. && python -m pytest -q      # scripts/ and the Dockerfile checks
```

All green before every push — no exceptions. If a test references a
loopback HTTP/WebSocket/SSH server (the `http`, `truenas`, `ssh`, `kuma`
executor tests), that's a real local listener the test starts itself —
not a mock; no network access outside localhost is needed. The privilege
tests skip themselves unless run as root; CI runs the suite a second time
under `sudo` for them.

A few tests drive the server with the official Python MCP SDK as the
client (`rust/tests/interop/*.py`). They need an interpreter with
`mcp==2.2.0`: `GATEKEEPER_INTEROP_PYTHON=/path/to/python` (CI sets it, and
then a missing SDK is a failure), otherwise `python3` on `PATH` is tried
and the tests skip with a note when it cannot import `mcp`. The Python
pytest suite needs the scripts' own dependencies:
`pip install -c constraints.txt "google-api-python-client>=2.100" "google-auth-oauthlib>=1.0" pytest`.

The Python implementation the crate was ported from is gone (1.17.0).
What it produced is kept as frozen fixtures in `rust/tests/fixtures/`
(error messages, the examples as loaded, `init` output, the admin tool
list, the MCP wire transcript, files it wrote). They are expectations, not
generated files: a deliberate change to one of those outputs is edited
into its fixture by hand, in the same commit.

## Known pitfalls

- **RELEASE.md is checked by CI before anything builds.** A version bump in
  `rust/Cargo.toml` with no matching `## <version>` section in `RELEASE.md`
  fails the `tests` job immediately with *"RELEASE.md has no '## X.Y.Z'
  section."* — no image gets built or pushed. Add both files in the same
  commit, always.
- **A push to `main` without a version bump now fails CI (since 0.46.9).**
  It used to pass: an already-tagged version meant "build a dev image
  only", the version step exited early, and both the `RELEASE.md` check and
  the whole `release` job were skipped — a green run that published
  nothing, which is how three UI commits sat unreleased on `main` behind
  0.46.8. On a push to `main` the `tests` job now errors if `v<version>` is
  already tagged, or if the version is unchanged from the previous `main`
  tip. Other branches, pull requests and `workflow_dispatch` are
  unaffected, so a feature branch still builds its dev image. Practical
  consequence: never push to `main` without the bump + notes — the fix is
  not "re-run CI", it is a new commit.
- **Linux only.** The crate uses Unix privilege dropping, `SIGHUP` reload
  and `/proc`; it does not build for Windows. Develop in WSL or a Linux
  container.
- **Credential-store tests/scripts need a master key.** Anything that
  touches `credentials.rs` beyond an empty store (creating, rotating,
  resolving a credential) needs `GATEKEEPER_CREDENTIAL_KEY` set — generate
  one with `gatekeeper credential-key`. A manual smoke test needs to set the
  env var itself.
- **A toolkit's `credential:` and the credential store are separate tiers,
  and can disagree.** The binding is Tier 1 (`toolkits.yaml`), the value is
  Tier 2 (`credentials.yaml`) — so a toolkit can name a credential that does
  not exist. `Tier1::credential_references()` is the single walk over toolkits
  *and* destinations that both the startup check and the console's "Used by"
  row use; do not hand-roll a second one, it will forget the
  destination-level `credential:` override (FR-8.3g). A dangling reference is
  a startup warning, not an abort, and shows as a note on `/app/credentials`.
- **Three names describe one `google`/`microsoft` operation, and they are
  not interchangeable.** The public **tool ID** is dotted and
  underscore-only (`outlook.list_messages`, `drive.create_folder`); the
  **action ID** is what a tool's `microsoft_action`/`google_action` and
  its toolkit's `allowed_microsoft_actions`/`allowed_google_actions` must
  share *verbatim* (`mail list`, `drive create-folder`); the **CLI argv**
  is what the bundled script's argparse accepts. Nothing derives one from
  another, and a tool ID is never matched against a whitelist.
  `execute::microsoft::MICROSOFT_ACTION_ALIASES` bridges the four
  tool-shaped Outlook action names (`list_messages` → `list`); `google`
  has no such table, so a `google_action` must be the CLI's own spelling,
  hyphen included (`drive create-folder`). Release notes name the dotted
  tool IDs, never a flat `outlook_list_messages`. See
  docs/ARCHITECTURE.md, "Three names for one operation".
- **`local` binaries are validated for shape, never for existence — and
  host state is not a binary problem.** Tier 1 checks that a binary path is
  absolute and traversal-free, then loads; it is parsed before anything
  runs, so a toolkit naming a binary the image lacks starts clean and fails
  on first call. `Tier1::missing_local_binaries()` is the startup warning and
  `Service::probe_one`'s readiness check sharing one `tier1::is_runnable()`; keep
  it `local`-only, since an `ssh` toolkit's binaries are on another
  filesystem entirely. Before "just apt-install it" in the Dockerfile, check
  FR-8.4: `zfs`/`zpool`/`ps aux`/`top` do not return host values from inside
  this container at any path, and belong on `truenas` or `ssh` — the
  Dockerfile carries the long form of why ZFS in particular is not
  installable out of this problem.
- **`/ui` is gone, except for what must not move (1.0.0).** The console is
  `/app` over `/api/v1`. `/ui` is now only redirects (`GET /ui/<x>` →
  `/app/<x>`, anything else 410) and the OAuth callbacks at
  `/ui/oauth/{google,microsoft}/callback`, which stay because they are the
  redirect URIs operators registered with Google and Microsoft. Do not add
  a page or a write under `/ui`; do not "tidy" the callback paths to
  `/app` or `/api`. Console security tests live in
  `rust/tests/api_security.rs`.
- **API output is built field by field.** Response models are assembled in
  `rust/src/api/service.rs` (reads) and `rust/src/api/app.rs` (routes and
  writes), request models are validated in `api/models.rs`; a new field is
  invisible until one of them names it, which is the point. The schema
  the console is typed against, `frontend/openapi.json`, is a committed
  file edited by hand with the API (see the frontend loop below);
  `rust/tests/api_web.rs` pins that the routes and the schema agree.
- **No `v` prefix in `RELEASE.md`** — section headers are `## 0.4.0`, not
  `## v0.4.0`.
- **`latest` tag moves** — pin a fixed version + digest for production
  deployments (NFR-5).
- **Toolkit creation is UI-unreachable, on purpose.** If a task seems to
  need a new/edited *toolkit* reachable from the console, stop — that's
  FR-4.11, not a bug. Toolkits are deploy-time only; only tools, identities,
  and credentials are console-writable. `/app/toolkits/reference` prints
  copy-pasteable YAML for a human to paste in by hand, it does not write
  the file.

## Frontend dev loop (`frontend/`, the console at `/app`)

```bash
cd frontend
npm ci --ignore-scripts        # never without --ignore-scripts
npm run dev                    # Vite on :5173, proxies /api to 127.0.0.1:8080
npm test && npx tsc --noEmit && npm run lint && npm run build
```

`npm run dev` needs a gatekeeper on `127.0.0.1:8080` (override with
`GATEKEEPER_DEV_BACKEND`). Start it with
`cargo run --manifest-path rust/Cargo.toml -- serve --ui`. Open
`http://localhost:5173/app/`. A built console (`npm run build`) is also
served by that gatekeeper itself at `/app`, because `api/web.rs` falls back
to `frontend/dist` in the checkout it was built from.

**After any API change, update the schema and regenerate the client
types.** `frontend/openapi.json` is the source of truth (the binary embeds
it and serves it at `/api/v1/openapi.json`); edit it in the same commit as
the route or model, then:

```bash
(cd frontend && npm run gen:api)
```

CI's `npm run check:api` fails if `src/api/schema.d.ts` does not match the
schema, and `rust/tests/api_web.rs` fails if the routes and the schema
disagree.

Console code must not use `dangerouslySetInnerHTML`, `innerHTML` or `eval`.
eslint refuses them, and the `/app` CSP enforces Trusted Types, so they
would fail in the browser anyway. Render agent-supplied data as text.

## CLI reference (agent-relevant subset)

```bash
gatekeeper check                       # validate config, no start
gatekeeper init                        # empty config + one admin
gatekeeper token                       # generate an API token
gatekeeper password --identity <id>    # set a console password
gatekeeper credential-key              # generate the credential-store master key
gatekeeper serve --ui                  # start the server with the admin console
```

## Working with the dispatching agent (Hermes)

The usual client is Hermes, an orchestrating agent that drives this repo
through opencode ask/fire. Session prompts come in two flavors; both are
legitimate; behave accordingly:

- Free task prompts (implement X, find out why Y fails): use your full
  abilities - explore the repo, run whatever commands you need, decide your
  own path, report a summary at the end. Do NOT ask permission for ordinary
  steps (branching, editing, running tests).
- Exact command prompts (Run this exact shell command and paste its raw
  stdout verbatim, nothing else): the client is verifying one precise
  mechanical step and parses the output literally. Execute exactly that
  command; do not substitute, extend, or improve it; do not wrap stdout in
  prose or fences beyond quoting it. A chatty answer instead of raw output
  is a failure mode here - it costs the client a whole retry round through
  a slow link.

When an exact-command prompt is one step of a release chain (commit, merge,
push), treat failure as data, not as an error to fix: if the command fails,
report the exact stderr verbatim and stop; the client decides next steps.

Client-side ask timeouts (59s) are transport noise, not task failures - work
the client dispatched continues server-side. Never restart work after a
timeout; finish and leave the tree in a consistent state (edits done, commit
only when the prompt says so).
