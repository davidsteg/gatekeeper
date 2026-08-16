# Releases

The notes live here, not in a web form. They go through the same review as
the code, and the workflow reads them when tagging — what is published has
been read first.

## The rule: every change is a release

**What lands on `main` is published.** No accumulated, unreleased changes;
no "we'll catch it next time."

The reason is not tidiness. gatekeeper mediates root-equivalent access to
a host. If a build is running somewhere, you must be able to say *which one*
— and that only works if every state has a version with notes. A batch
release after five changes turns five traceable steps into an indivisible
 lump, and in an incident nobody knows which one it was.

**The tag is not set by hand.** The release is triggered by the version in
`pyproject.toml`: if there is a version with no corresponding tag yet, the
workflow publishes it. This means the version bump belongs in the same
commit as the change — and whoever forgets it notices because nothing
appears.

## Procedure

Two files in the same commit as the change:

**1. `pyproject.toml`** — bump the version.

**2. `RELEASE.md`** — add a section, heading exactly `## <version>`,
without `v`. If it is missing, the workflow aborts *before* any image
reaches the registry: a version without notes is not published.

Then `git push`. After that it runs automatically: tests → image to Docker
Hub (`0.2.0`, `0.2`, `latest`) → Git tag `v0.2.0` → GitHub release with the
section from here, the image digest, and a deploy bundle.

A push without a new version only builds `<version>-dev` and publishes
nothing. This is the path for intermediate states and for changes that do
not alter behavior — it is the exception, not the norm.

`latest` always points to the latest build. Since every change is a release
per the rule above, this is almost always also the latest release. For
**production** a fixed version remains correct (NFR-5): `latest` moves, and
a redeploy would otherwise pull a different build without anyone deciding
to.

## Versioning

`MAJOR.MINOR.PATCH`. For this project:

- **MAJOR** — Tier 1 changes its meaning, or an existing deployment does
  not start without adjustment.
- **MINOR** — new toolkits, executors, UI features, or new runtime
  behavior.
- **PATCH** — bug fixes, including security-relevant ones.

**Pin the digest after deploy.** A tag can be overwritten, a digest
cannot. It is in every release.

---

## 0.3.4

**Fully English + UI fixes.**

- **All German removed** — every docstring, comment, UI string, test,
  release note, requirement doc, Dockerfile, compose file, and config
  example is now English. 27 files changed.
- **Tool matrix rebuilt** — one cell per identity column (was all stuffed
  in a single `<td>`), aligned with headers. Zebra striping for
  readability. `✓` / `—` instead of raw text pills. Column widths
  optimized: tool name gets space, status/category/idempotent are
  narrow, identity columns are centered.
- **Zoom fixed** — viewport meta now explicitly allows user scaling.
  Previously the sticky sidebar captured zoom independently from the
  main content.

---

## 0.3.3

**Five UI issues fixed.**

- **Executors moved to the left column** — previously in the right sidebar
  below the activity feed, where it was cut off when space was tight. Now
  under the access map, visible without scrolling.
- **Blocked edges staggered** — all red dashed edges started from the same
  point on the hub's right side. Now the start points are distributed
  vertically along the hub edge, which preserves clarity with multiple
  protected resources.
- **Call flow pipeline enlarged** — nodes 120×52 → 130×58, subtitle
  9.5px → 10px. Container scrolls horizontally on narrow viewports. Each
  node now has a `<title>` tooltip with name + description.
- **Activity chart empty state** — instead of an empty grid, the chart now
  shows "No calls in the last 12 hours" when there are no `call`-type
  audit records.
- **Call flow CSS** — `.flow-scroll` class with `overflow-x: auto` and
  explicit font sizes for title (12.5px) and subtitle (10px).

---

## 0.3.2

**Version visible.** The sidebar and login page now show the running
version (`v0.3.2` etc.) next to the gatekeeper shield. Subtle muted grey
so it does not distract from the content.

---

## 0.3.1

**Access map with audit data.** The access map on the overview page now
shows call counts per identity and per toolkit. Each node has a tooltip
(SVG `<title>`, native browser support, no JavaScript) with the
breakdown of ok / denied / failed. High-traffic edges are drawn thicker
("hot"); they highlight on hover. The nodes themselves react with CSS
transitions on hover: border, fill, and text color change. The legend has
a third entry for "high traffic." Requires the audit log; without it the
map renders as before, only with tooltips.

---

## 0.3.0

**The console has its own login.** `/ui` now asks for identity and
password; the API token stays where it belongs — `/mcp`. Previously both
were the same secret: anyone wanting to open the UI typed the token into
a form, carrying it through clipboard, password manager, and history.
Separate credentials mean: a lost console password cannot invoke tools, a
lost token cannot open the UI, and each can be changed independently
(FR-11.5).

**After upgrade, nothing to do.** If `identities.yaml` has no passwords
yet, the first start with `--ui` generates one for each console account
and writes it to the log once — just as the first start does with the
token. If the file is not writable, the server does not start and tells
you the way: `gatekeeper password --identity <id>`.

### Added

- **`password_hash` per identity**, scrypt like the token, optional and
  only for `viewer` and `admin`. An agent does not get one — it never logs
  in anywhere, and a password on a role without login is rejected.
- **`IdentityStore.authenticate_console(id, password)`**. For each
  failure, scrypt is computed once even for unknown identities: otherwise
  response time would be a directory of all console accounts.
- **`/ui/account`** — self-service for your own password, with the old
  password required. Also for `viewer`, who otherwise cannot write: an
  account whose password only someone else can change will never be
  changed.
- **Password field in the identity editor.** Required when creating
  console roles, leave empty when editing = unchanged.
- **`gatekeeper password --identity <id>`** sets a password directly in
  `identities.yaml` — the way back when nobody can get in.
- **`gatekeeper init`** outputs console password and API token separately,
  both exactly once (FR-2.6).

### Changed

- **The login form no longer accepts a token.** Anyone who tries gets the
  same message as any other failed attempt; the hint below the form says
  so upfront.
- **Lockout protection counts accounts, not roles.** An `admin` without a
  password cannot log in and no longer holds the door open. The check only
  runs if there was previously a login-capable admin — a setup from an
  older version does not block itself.
- **A password change terminates other sessions** of the identity; the
  triggering one stays. If an admin sets someone else's password, that
  person's session is gone — usually exactly the reason for the change.
- **`--ui` starts only with a login-capable identity.** Previously the
  role alone was sufficient.
- **The identities page shows console access** per identity: `console
  access`, `no console password`, or `api only`.

---

## 0.2.6

**Scope wildcard boundary enforced by test.** The `-` in `stack:dev-*` is
literal, not a naive prefix — `devtools` or `dev_x` must not pass for a
`dev-*` identity. Two new tests enforce this so that a future switch to
prefix comparison does not silently open the boundary.

### Added

- **`test_scope_wildcard_requires_dash_boundary`**: checks `covers_scope`
  directly against `dev-argus` (allowed) and `devtools`/`dev_x`/`dev`
  (rejected).
- **`test_scope_mismatch_rejects_sibling_prefix`**: the negative case in
  the real call path — `mediatools` is rejected with `SCOPE_MISMATCH` for
  a `media-*` identity.

---

## 0.2.5

**Two new diagrams on the overview page.** The call flow pipeline shows
the 8 layers every request passes through; the tool matrix lists every
tool with status, category, idempotency, and the identities permitted to
call it.

### Added

- **Call flow pipeline** (`_call_flow_pipeline`): horizontal SVG with the
  8 layers MCP → Auth → Authorize → Registry → Validate → argv-build →
  Executor → Audit. Each layer with name and short description.
- **Tool matrix** (`_tool_matrix`): each tool as a table row with a status
  pill (enabled/disabled), category (read/write/write_external),
  idempotency (yes/no), and a column per identity showing who may call the
  tool.

---

## 0.2.4

**SIGHUP reloads the configuration.** `kill -HUP <pid>` or
`docker kill -s HUP gatekeeper` reloads all three files (`toolkits.yaml`,
`tools.yaml`, `identities.yaml`) atomically — no restart, no connection
drop.

### Added

- **`Service.reload_config()`** loads Tier 1, catalog, and identities in
  one pass. If a file fails, the previous state remains untouched.
- **SIGHUP handler** in `cmd_serve`. On success it logs the new count of
  toolkits/tools/identities; on failure the reason.

### Changed

- **Rate limiter** is rebuilt on reload so changed limits take effect
  immediately and old windows are not carried over.

---

## 0.2.3

A non-writable audit directory previously crashed the start with a raw
`OSError`. Now it gets the same treatment as the config directory: cause,
current user, and the command that fixes it.

Starting without an audit log is still not allowed. A service that
mediates host operations but cannot record them is worse than none — the
calls happen, but nobody knows which ones afterwards.

Mainly affects installations whose `audit.dir` points to a separate
volume: Docker creates it as root, and the unprivileged user cannot enter
it.

---

## 0.2.2

Fixes the first start from 0.2.0/0.2.1 silently doing nothing when the
mounted directory did not belong to the container — and the server then
reporting `toolkits.yaml not found` even though the directory existed.

The cause was a pre-check with `os.access`: if the write permission was
missing, the first start exited without saying anything. The loader's
message then named the wrong cause. Now it writes and evaluates the
error:

```
Cannot create the configuration in /etc/gatekeeper: [Errno 13] Permission denied
This process runs as 568:568. Docker creates a missing bind-mount source as
root, which that user cannot write to.
On the host, give the directory to the container user, then start again:
  chown -R 568:568 <the directory mounted at /etc/gatekeeper>
```

**Who this affects:** Docker creates a missing bind-mount source as
`root`. If `./gatekeeper/config` does not exist on the host, it is owned
by root afterwards, and the unprivileged user in the container cannot
enter it. A container without `CAP_CHOWN` cannot fix this itself — the
message names the one command that does.

`latest` now follows the latest build without exception, not just the
latest release. Since every change is a release per the rule above, both
almost always coincide; the difference only affected pushes without a
version bump, which now also move `latest`.

The image smoke test deliberately accesses `latest` instead of relying on
the order of generated tags.

For production the recommendation is unchanged: pin a fixed version or
digest. `latest` is for trying out, not for running.

---

## 0.2.0

Fixes a bug that sent every fresh install from 0.1.0 into a restart loop,
and makes the first start self-sufficient.

### Fixed

**The `compose.yaml` from 0.1.0 was broken.** It bind-mounted
`toolkits.yaml` as a single file to keep Tier 1 read-only. Docker creates
a **directory** in that case when the source file does not exist on the
host — which is always the case on a fresh install. The container then
restarted endlessly with `IsADirectoryError`, and a folder named
`toolkits.yaml` was left on the host.

Anyone who rolled out 0.1.0 cleans it up once:

```bash
rm -rf <config>/toolkits.yaml
```

Now a single **directory** mount suffices, which does not have this
problem. Tier 1 remains protected, but by code rather than by the mount:
nobody writes `toolkits.yaml`, and a test enforces this.

**Configuration errors name the cause, not the symptom.** A directory in
place of a file now explains that Docker created it and why. The check
happens before opening, not via the exception — Linux reports
`IsADirectoryError`, Windows `PermissionError`.

### New

- **The first start creates the configuration itself.** Mount an empty,
  writable directory and start; `init` by hand is no longer needed. The
  admin token appears once in the container log — rotate it after the
  first login in `/ui`.

  Writing only happens if **none** of the three files exist. A slipped
  mount would otherwise look like a fresh install, and a new
  configuration on top would hide the error.
  `GATEKEEPER_NO_BOOTSTRAP=1` disables this.

- **`GATEKEEPER_STATE_DIR`** separates Tier 1 and Tier 2 into separate
  directories. This allows the config mount to be `:ro` while the UI
  still writes — both are directory mounts, the trap above does not
  apply.

### Changed

`docker.compose_ps` in the example catalog returns JSON instead of a text
table. An agent that counts columns would misread the first long
container name. `--format json` is fixed in the template; a parameter
value cannot override it.

### Other

Releases are now driven by the version in `pyproject.toml`, not by a
hand-set tag. Every change on `main` gets a version and notes — see [The
rule](#the-rule-every-change-is-a-release) above.

### Test bench

127 tests on Linux.

---

## 0.1.0

First release. Implements stages 1 and 3 from
[REQUIREMENTS.md](REQUIREMENTS.md) §14.

### What it does

Controlled MCP server for host operations. Agents do not get a shell,
but a fixed set of validated actions — each with its own token, own
permissions, and full audit.

- **MCP over Streamable HTTP** at `/mcp`, bearer token per identity.
  `tools/list` is filtered per identity; ungranted tools do not exist for
  the agent.
- **Executors `local` and `docker`.** What is reachable with them is
  decided exclusively by the `toolkits.yaml` file.
- **Audit log** as JSON Lines with rotation. The true denial reason is
  there even when the agent only got a non-descriptive response.
- **Operations and admin console** at `/ui`, disabled by default. Access
  map, Tier 1 boundaries, catalog, identity profiles, audit log with
  filters — and for admins, write access to Tier 2.
- **Health probes** (`/health/live`, `/health/ready`,
  `/health/startup`) and Prometheus metrics at `/metrics`.

### Empty after installation

`gatekeeper init` creates an **empty** Tier 1 (`toolkits: {}`), an empty
catalog, and exactly one admin. Immediately afterwards, gatekeeper can do
nothing — not a single command.

This is intentional. A tool that mediates root-equivalent access to a
host should not bring capabilities nobody decided on: a pre-populated
catalog would have no author in the audit log. Which binaries an agent
should be able to reach is known only by someone who knows the system.

Ready-made templates to look at — a Docker toolkit and ten compose and
diagnostic tools — are in [config/examples/](config/examples/). Adopting
them means: read, adapt, deploy.

### What it guarantees

- **No shell interpreter.** Execution exclusively via argv list. A
  parameter expands structurally to exactly one argument — a value cannot
  produce a second one, regardless of its content. Injection is not
  escaped away but structurally impossible.
- **Two tiers.** Binary allowlist, denied arguments, path roots,
  protected resources, and ceilings live in `toolkits.yaml` and are
  immutable at runtime. The catalog moves within these boundaries, never
  beyond them — not even through the UI.
- **Rights on tool IDs, not on toolkits.** A newly created tool is not
  granted to anyone automatically.
- **Denials reveal nothing.** Missing permission and unknown tool produce
  the same response for the agent.
- **Protected resources.** What is in `protected_resources` is not
  reachable by any tool — otherwise an agent could shut down the channel
  it speaks through. The names are deployment-specific; gatekeeper does
  not guess them.
- **Timeout ≠ failure.** If a non-idempotent tool hits its timeout, the
  server reports "outcome unknown" instead of "failed." Reporting a
  timeout as failure provokes exactly the retry that creates a duplicate
  on an already-completed write.

### Roles

| Role | MCP | Console read | Tier 2 write |
|---|:--:|:--:|:--:|
| `agent` | ✓ | — | — |
| `viewer` | — | ✓ | — |
| `admin` | — | ✓ | ✓ |

### Known limitations

- **The Docker socket is root-equivalent on the host.** Deliberately
  accepted: gatekeeper is precisely the whitelist that constrains this
  access. But it means: a bug in gatekeeper is a root bug. Hence the
  negative test corpus and `read_only`, `cap_drop: ALL`,
  `no-new-privileges` in `compose.yaml`.
- **Container logs regularly contain environment variables.** An agent
  with `docker.compose_logs` on a stack potentially sees its secrets.
  Masking only works when gatekeeper knows the values itself — i.e., with
  the credential store in 0.2.
- **The UI speaks HTTP.** Without TLS, the session cookie runs without the
  `Secure` flag. Behind an HTTPS proxy, gatekeeper sets it automatically.
  The port does not belong on the open network.
- **Tier 1 is only changed by redeploy.** A toolkit grants access to real
  binaries; that remains a deploy-time decision (FR-4.11). The UI creates
  tools, but never a toolkit.
- **Not yet included:** ZFS and TrueNAS API (need the `truenas` executor),
  service APIs like Sonarr/Radarr/Jellyfin (need `http` and the credential
  store), `write_external`.

### Test bench

121 tests on Linux, 49 of them in the negative corpus (NFR-8):
metacharacters, control characters, argv expansion, path traversal,
symlink escape, sibling directory with same prefix, Tier 1 violations,
overridden derived parameters, protected resources, opacity of denials.
Plus 25 tests for UI write access.

Verified against a real Docker daemon, not just unit tests: stacks
started, queried, and stopped while protection mechanisms were triggered
individually.