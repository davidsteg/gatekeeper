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
| **Language** | Python 3.12+ |
| **Runtime deps** | `mcp`, `pyyaml`, `uvicorn`, `httpx`, `websockets`, `cryptography`, `asyncssh` — see `pyproject.toml` |
| **Tests** | `python -m pytest -q` — all must pass before push |

Check the current version in `pyproject.toml`, not here — it changes every
release and a hardcoded number in this file would just go stale.

## Release workflow (mandatory)

**Every change on `main` is a release.** No batch releases — see
[RELEASE.md](RELEASE.md) for the full rule and rationale.

1. **Version bump** — `pyproject.toml`, in the same commit as the change.
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
python -m pytest -q
```

All green before every push — no exceptions. If a test file references a
loopback HTTP/WebSocket/SSH server (`test_execute_http.py`,
`test_execute_truenas.py`, `test_execute_ssh.py`), that's a real local
listener the test starts itself — the ssh one via
`asyncssh.create_server()` with an ephemeral host key — not a mock; no
network access outside localhost is needed.

## Known pitfalls

- **RELEASE.md is checked by CI before anything builds.** A version bump in
  `pyproject.toml` with no matching `## <version>` section in `RELEASE.md`
  fails the `tests` job immediately with *"RELEASE.md has no '## X.Y.Z'
  section."* — no image gets built or pushed. Add both files in the same
  commit, always.
- **Windows dev environment: `gatekeeper serve` crashes on Windows.**
  `cmd_serve` registers a `SIGHUP` handler unconditionally
  (`signal.signal(signal.SIGHUP, ...)`), and `SIGHUP` doesn't exist on
  Windows. Don't try to smoke-test the CLI's `serve` command directly on a
  Windows box — build the ASGI app yourself (`server.build_app(...)`) in a
  throwaway script and run it with `uvicorn.run(...)`, bypassing
  `cmd_serve`. See `docs/DEPLOYMENT.md` for the pattern.
- **New dependency, new install.** After pulling a change that touches
  `pyproject.toml`'s `dependencies`, re-run `pip install -e ".[dev]"` (or
  the `uv` equivalent) before running tests — a stale venv will import-error
  on `httpx`/`websockets`/`cryptography`/`asyncssh` instead of giving a
  useful test failure.
- **Credential-store tests/scripts need a master key.** Anything that
  touches `credentials.py` beyond an empty store (creating, rotating,
  resolving a credential) needs `GATEKEEPER_CREDENTIAL_KEY` set — generate
  one with `gatekeeper credential-key`. Tests set this via `monkeypatch`
  per-test; a manual smoke-test script needs to set the env var itself.
- **A toolkit's `credential:` and the credential store are separate tiers,
  and can disagree.** The binding is Tier 1 (`toolkits.yaml`), the value is
  Tier 2 (`credentials.yaml`) — so a toolkit can name a credential that does
  not exist. `Tier1.credential_references()` is the single walk over toolkits
  *and* destinations that both the startup check and the console's "Used by"
  row use; do not hand-roll a second one, it will forget the
  destination-level `credential:` override (FR-8.3g). A dangling reference is
  a startup warning, not an abort, and shows as a note on `/ui/credentials`.
- **`local` binaries are validated for shape, never for existence — and
  host state is not a binary problem.** Tier 1 checks that a binary path is
  absolute and traversal-free, then loads; it is parsed before anything
  runs, so a toolkit naming a binary the image lacks starts clean and fails
  on first call. `Tier1.missing_local_binaries()` is the startup warning and
  `service._probe_one`'s readiness check sharing one `is_runnable()`; keep
  it `local`-only, since an `ssh` toolkit's binaries are on another
  filesystem entirely. Before "just apt-install it" in the Dockerfile, check
  FR-8.4: `zfs`/`zpool`/`ps aux`/`top` do not return host values from inside
  this container at any path, and belong on `truenas` or `ssh` — the
  Dockerfile carries the long form of why ZFS in particular is not
  installable out of this problem.
- **`document.querySelector('form')` on an authenticated `/ui` page grabs
  the sidebar's logout form, not the page's content form** — the sidebar
  renders before `<main>` in the DOM. When scripting the console (browser
  automation, CDP, screenshots), scope to `document.querySelector('main
  form')` instead, or you'll silently log yourself out.
- **No `v` prefix in `RELEASE.md`** — section headers are `## 0.4.0`, not
  `## v0.4.0`.
- **`latest` tag moves** — pin a fixed version + digest for production
  deployments (NFR-5).
- **Toolkit creation is UI-unreachable, on purpose.** If a task seems to
  need a new/edited *toolkit* reachable from `/ui`, stop — that's FR-4.11,
  not a bug. Toolkits are deploy-time only; only tools, identities, and
  credentials are console-writable. `/ui/toolkits/reference` prints
  copy-pasteable YAML for a human to paste in by hand, it does not write
  the file.

## CLI reference (agent-relevant subset)

```bash
gatekeeper check                       # validate config, no start
gatekeeper init                        # empty config + one admin
gatekeeper token                       # generate an API token
gatekeeper password --identity <id>    # set a console password
gatekeeper credential-key              # generate the credential-store master key
gatekeeper integration list             # list available service integrations
gatekeeper integration show <key>       # print one integration's toolkit YAML + starter tools
gatekeeper serve --ui                  # start the server with the admin console
```
