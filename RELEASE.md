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

## 0.8.0

**Renamed "presets" to "integrations". New `ssh` executor. 7 new integrations: pfSense, Jellystat, Netdata, SABnzbd, Paperless-ngx, Docker, and Linux-over-SSH.**

- **"Presets" is now "Integrations" everywhere** -- `presets.py` ->
  `integrations.py`, `Preset`/`PRESETS` -> `Integration`/`INTEGRATIONS`,
  `/ui/tools/presets` -> `/ui/tools/integrations`, `gatekeeper preset
  list/show` -> `gatekeeper integration list/show`. No config format
  change -- `toolkits.yaml`/`tools.yaml` are untouched, only the admin
  route and CLI subcommand names moved.
- **New `ssh` executor** (`execute_ssh.py`) -- reuses the `docker`/`local`
  binary+argv tool shape exactly (REQUIREMENTS.md §17); the only
  difference is the transport, an SSH exec channel to a remote host
  instead of a local subprocess. Host-key verification is mandatory, not
  optional: a new `ssh_known_hosts` Tier 1 field pins the exact key
  (`ssh-keyscan` output), same posture as the DNS-rebinding check on the
  `http` executor. SSH's exec channel is unavoidably shell-interpreted on
  the server side, unlike every other executor here -- mitigated with
  `shlex.quote` on every argv element before it's joined into the command
  string, on top of (not instead of) each parameter's own regex allowlist.
  New credential kind `ssh_private_key`.
- **New `url_query` credential kind** -- FR-8.14's other documented
  exception to "a credential is always a header" (alongside Telegram's
  `url_path`), for a service with no header-auth option at all. Injected
  as a query parameter by `execute_http.py` directly, never through a
  tool's own `query_template`.
- **7 new integrations**, researched against each service's real API:
  - **pfSense** -- the community "pfSense REST API" package (pfrest.org),
    `X-API-Key` header, `/api/v2`.
  - **Jellystat** -- `x-api-token` header (confirmed from its own auth
    middleware source, not just docs).
  - **Netdata** -- unauthenticated by default; `bearer` only if you've
    turned on `bearer_protection`.
  - **SABnzbd** -- `url_query` (`?apikey=`), its classic API's only auth
    option.
  - **Paperless-ngx** -- `Authorization: Token <token>` (stored as the
    credential value verbatim, via the existing `api_key_header` kind).
  - **Docker** -- the `docker` executor's own toolkit shape (not `http`),
    mirroring `config/examples/toolkits.yaml`'s `docker` entry.
  - **Linux** -- the new `ssh` executor, three fixed read-only
    diagnostics (uptime, memory, disk) on one remote host -- deliberately
    not a general "Linux CLI" tool, which has no boundary to validate
    against.
  - Logos sourced the same way as before (homarr-labs/dashboard-icons,
    Apache-2.0); Jellystat's only available mark there turned out to be a
    raster PNG wrapped in an `<image>` tag and was rejected by the same
    rule that excludes external images, falling back to a monogram like
    Tdarr's.

## 0.7.0

**Real service logos on the preset gallery, instead of plain letter monograms.**

- **12 of the 13 presets now show their actual service mark** (Sonarr,
  Radarr, Jellyfin, Bazarr, Prowlarr, Home Assistant, n8n, Uptime Kuma,
  Immich, Telegram, Google, TrueNAS), sourced from
  [homarr-labs/dashboard-icons](https://github.com/homarr-labs/dashboard-icons)
  (Apache License 2.0, attributed in `presets.py`). Tdarr has no usable SVG
  available there and keeps its colored-circle-with-initials fallback.
- **Two rendering bugs found and fixed while adding these:**
  - Several logos initially rendered as solid black circles. Their source
    SVGs set color via `style="fill:#hex"` or a `<style>` block with CSS
    classes -- both are governed by the console's CSP
    (`style-src 'nonce-...'`), which the browser silently drops when
    nothing carries that nonce, leaving the shape with no fill at all.
    Every fetched logo is now stripped of `style=`/`<style>`/`class=` and
    rewritten with plain presentation attributes (`fill="#hex"`) before it
    ever reaches `presets.py` -- the same fix `_preset_logo()`'s own sizing
    already had to learn once before (see 0.4.0's CSS-only-modal work).
  - The logo badges briefly rendered oversized (filling most of the card)
    because their container was sized via an inline
    `style="width:28px;height:28px"` attribute -- also CSP-blocked. Sizing
    is now two named classes, `.preset-logo`/`.preset-logo-lg`.
- Added `test_logo_has_no_csp_blocked_styling` and
  `test_no_duplicate_svg_ids_or_gradient_targets_across_all_presets` to
  `test_presets.py` so both classes of bug fail a test run instead of only
  showing up as a black circle in a screenshot.

## 0.6.0

**New: a `docker`/`http`/`truenas` toolkit can now reach several named
destinations instead of exactly one host.**

Until now every toolkit was bound to a single target -- one Docker socket,
one `base_url`, one `ws_url` -- reaching a second host meant hand-duplicating
an entire toolkit definition (binaries, denied args, path roots, limits) just
to change *where* it connects. Destinations close that gap:

- **`destinations:` in `toolkits.yaml`** (Tier 1, FR-8.3g) -- a named target
  (`docker_host`/`docker_tls`, `base_url`, or `ws_url`) plus an optional
  credential override. Every other boundary stays on the toolkit, identical
  across all its destinations (FR-4.9: those answer "what," not "where").
- **Tools expand at catalog-load time** into one independently-grantable ID
  per destination -- `docker.compose_up` becomes `docker.compose_up@nas1`
  and `docker.compose_up@nas2` -- with no change to the grant model
  (FR-8.3h). The agent can never choose a destination: it's fixed in the
  tool ID itself, the same principle as `http`'s "scheme and host live
  exclusively in the toolkit" (FR-8.3i extends FR-8.7). A toolkit with no
  `destinations` behaves exactly as before this existed (FR-8.3j).
- **TLS-secured remote Docker hosts** -- a new `docker_tls` credential kind
  (a JSON `{cert, key, ca}` bundle) is materialized to a private, 0700 temp
  directory on first use and re-materialized on rotation; the previous
  directory is now actually removed from disk, not just forgotten.
- **Admin console**: destination pills on tool cards (grouped per
  destination within a toolkit), a destination column in the tool matrix,
  and a real third tier in the access map -- identity → toolkit →
  destination, with structural edges for what a toolkit *can* reach and
  grant edges for what an identity actually holds.
- 29 new tests (`tests/test_destinations.py`) covering Tier 1 validation,
  catalog expansion, grant isolation between destinations, the docker TLS
  credential path, per-destination health probing, and the admin-UI write
  path (edit/enable/disable/delete correctly target the one YAML definition
  behind every destination-qualified tool).

## 0.5.0

**Fix: the console showed a stale version after a release. New: a release-notes popup on the version badge.**

- **Version drift, fixed at the root.** `__init__.py` used to carry a
  second, hand-maintained `__version__ = "..."` string alongside
  `pyproject.toml`'s -- and after shipping 0.4.0, it wasn't bumped, so the
  console kept showing `v0.3.12`. `__init__.py` now derives `__version__`
  instead of hardcoding it: it reads `pyproject.toml` directly when one is
  reachable (dev checkouts, editable installs -- always current, no
  reinstall needed), falling back to the installed package's own metadata
  otherwise (the container image, rebuilt fresh every release). There is no
  second copy left anywhere to forget. `tests/test_version.py` asserts
  `gatekeeper.__version__` matches `pyproject.toml` on every run.
- **Release-notes popup.** The version badge (sidebar and login page) is now
  a link that opens a popup with the full `RELEASE.md` history -- newest
  first, headings, bold, and inline code rendered, everything else escaped.
  Pure CSS (`:target`), no JavaScript, consistent with the rest of the
  console. `RELEASE.md` ships inside the container image
  (`/usr/share/gatekeeper/RELEASE.md`, overridable via
  `GATEKEEPER_RELEASE_NOTES`) so this works in production, not only from a
  source checkout.

## 0.4.0

**New: `http` and `truenas` executors, a credential store, and starter presets for
13 common services.**

Until now gatekeeper could only run allowlisted local binaries or docker
commands -- there was no way to reach an HTTP API or TrueNAS at all, so
Sonarr, Radarr, Jellyfin, Bazarr, Tdarr, Prowlarr, Home Assistant, n8n,
Uptime Kuma, Immich, Telegram, Google APIs, and TrueNAS were simply
impossible to add as tools. This closes that gap end to end:

- **`http` executor** (`execute_http.py`) -- SSRF-safe: the resolved IP is
  checked against the toolkit's `allowed_cidrs` immediately before
  connecting, not just the hostname once, closing the DNS-rebinding gap.
  Redirects are reported, never followed. Credentials are injected as
  headers by the executor itself, never through a tool's own query/body
  template. Responses are capped in size and field count and marked as
  external, untrusted data for the agent.
- **`truenas` executor** (`execute_truenas.py`) -- JSON-RPC 2.0 over
  WebSocket, since TrueNAS's REST v2.0 is deprecated. The whitelist acts
  on RPC method names instead of paths: a method not listed structurally
  does not exist, there is no separate "permission" to deny it.
- **Credential store** (`credentials.py`) -- named, encrypted-at-rest
  secrets a toolkit references by name. Write-only: create, rotate,
  delete -- no operation, for no role, ever returns a value back out.
  Master key comes from `GATEKEEPER_CREDENTIAL_KEY`
  (`gatekeeper credential-key` generates one) or
  `GATEKEEPER_CREDENTIAL_KEY_FILE`, kept outside the encrypted dataset.
  New `/ui/credentials` admin pages.
- **Presets** (`presets.py`) -- a toolkit YAML block plus 2-3 starter
  tools and an inline-SVG logo for each of the 13 services above. New
  `/ui/tools/presets` gallery: pick a preset's starter tool and land on
  the *existing* tool editor pre-filled, instead of a blank textarea --
  the save still goes through the exact same Tier 1 validation as
  hand-written YAML, presets never bypass it. Toolkit creation stays a
  manual, deploy-time edit (unchanged, by design): `/ui/toolkits/reference`
  and `gatekeeper preset list`/`show` print the copy-pasteable YAML.
- Google/Telegram are covered only for their static-credential surface
  (Telegram bot API, Google APIs that accept a plain API key) -- no
  OAuth2 authorization-code flow is implemented.
- 293 tests added/updated, including a negative corpus for SSRF,
  DNS-rebinding, path-traversal, and disallowed-RPC-method attempts
  against the new executors.

## 0.3.12

**Access map: per-identity colors. Sidebar: dropped the read/write badge.**

- **Removed the "read & write" / "read-only" sidebar badge.** The same
  information (role, hence write capability) was already shown in the
  sidebar footer next to the signed-in identity's name -- the top badge
  was redundant, and it was also the thing that kept overflowing under
  the new tighter sidebar column. `.brand` is back to a single row now
  that there's no badge fighting it for space.
- **Access map: one color per identity.** Every granted edge used to be
  the same green regardless of which identity it belonged to, so a
  busier graph gave no way to trace "which lines are dev's" without
  hovering each one. Each identity that holds at least one grant now
  gets its own color (blue, violet, pink, indigo, fuchsia, sky --
  chosen to sit clearly apart from the accent/ok/deny/warn hues, cycling
  if there are more identities than colors), applied to both its node
  and every edge leaving it. An identity with no tool rights stays
  neutral -- there is nothing to color. The filter/dim interaction and
  hover states were extended to match so highlighting a match still
  works the same way against the new colors. All new color pairs
  checked against WCAG AA against the card surface in both themes
  (4.6-8.5:1, comfortable margin throughout).

## 0.3.11

**Fix: Account page (and both 403 pages) wrongly highlighted "Overview" in the sidebar nav.**

`_NAV`'s Overview entry uses `""` as its path (it maps to `/ui/`). Pages
with no nav entry of their own -- Account, and the CSRF-refused /
not-permitted 403 pages -- also passed `active=""` as a "nothing
selected" default, so `path == active` matched Overview by accident.
Pre-existing, not introduced by the 0.3.9/0.3.10 redesign, but far more
visible under the new bracket-and-solid-fill active state than the old
soft highlight. All three call sites now pass `active="none"`, a value
no real nav path can equal.

## 0.3.10

**Layout/alignment fixes + access map redesign + toolkit icons.**

Follow-up review of the 0.3.9 redesign caught real layout bugs that a
downscaled screenshot had hidden -- found this time with DOM-level box
measurements (`getBoundingClientRect`, `getBBox`) instead of eyeballing
images, since the Browser pane wasn't reliably rendering screenshots
mid-session.

- **Sidebar "read & write" badge fixed** -- squeezed onto one flex row
  with the logo and version, it had nowhere to shrink and wrapped its
  text across four lines instead of staying on one. Brand is now two
  rows (name+version, then the badge) so nothing has to shrink.
- **Stat grid touched the card below it** -- 0px gap, confirmed by
  measurement, not just impression. `.grid` and `.split` (bare grid
  containers, unlike `.card`) had no margin-bottom of their own.
- **Mobile sidebar padding didn't match the topbar/content column** --
  11.2px vs. 16px, so the bezel's left edge sat ~5px out of line with
  the page title beneath it. Aligned to the same 1rem.
- **Call-flow pipeline captions overflowed their boxes** -- the longest
  ("JSON-RPC 2.0, tools/list, tools/call") ran 14px past the left edge
  and 11px past the right of its 130px-wide node. A font-size override
  specific to that diagram was larger than everywhere else; brought back
  in line so every caption fits, longest included.
- **Long tool IDs overflowed their Tools-page cards** -- an identifier
  like `docker.compose_restart` is one unbroken run of characters (dots,
  not spaces), so with no break opportunity it ran past the card edge
  instead of wrapping. Added `overflow-wrap: anywhere`.
- **Access map redesigned: direct edges, no hub.** Every call already
  goes through gatekeeper by definition -- the hub node in the middle
  repeated that fact without adding one, and cost every edge an extra
  hop to trace. Identities now connect straight to the toolkits they
  hold at least one tool in; blocked resources sit isolated with no
  inbound edge, since nothing reaches them from any identity and an edge
  would have had to invent a source.
- **Toolkit/executor icons added** -- a shell glyph for `local`, a
  container glyph for `docker`, plus `git-branch` and `cloud` mapped for
  future toolkit types, all deliberately generic pictograms rather than
  reproductions of any vendor's trademarked logo. Also fixes a real
  pre-existing bug found along the way: the Tools page's per-toolkit
  header called `_icon("package", 14)`, but `"package"` was never
  defined in `_ICONS` -- every toolkit section had been rendering with a
  blank icon.

## 0.3.9

**Console visual redesign -- "checkpoint console."**

A full CSS-only reskin of the operations console, replacing the generic
SaaS-dashboard look with something that reads as a security checkpoint
instead. No HTML-generation logic changed, so it applies uniformly to
every page (Overview, Tools, Identities, Audit, editors, login) at once
and carries no risk to routing, forms, CSRF, or escaping.

- **Cyan/teal accent** (`#0e7490` / `#2dd4bf` in dark) replacing the
  generic blue, driven entirely by the `--accent` token.
- **Always-dark sidebar bezel**, independent of the light/dark theme --
  a fixed console panel regardless of which theme the content column is
  in. The active nav item gets a `›` bracket instead of a filled pill.
- **Sharper corners** -- a `--radius`/`--radius-sm` scale (6px/4px)
  replacing the previous 11px/8px/7px, everywhere except pills, which
  stay fully rounded.
- **Card headers** dropped their filled background bar for a plain
  bottom rule -- an instrument-panel label, not a button.
- **Stat tiles** got outlined (not filled) chips and monospace numerals.
- **Section headers** are monospace with a `//` prefix, terminal-comment
  style.
- **Subtle dot-grid background texture**, pure CSS `radial-gradient`,
  no image request.
- Every new color pair was checked against WCAG AA (4.5:1); all pass,
  most with wide margins (5.4-16.5:1). The one flagged during design --
  white text on the light-mode accent button -- was deliberately
  verified rather than assumed, since the *previous* dark-mode accent
  had failed exactly this kind of check before (RELEASE.md 0.3.7).
- Fixed a latent bug found while touching this file: every inline
  `style="..."` attribute (old and new) was silently non-functional --
  the CSP is `style-src 'nonce-...'` with no `unsafe-inline`, which does
  not cover inline style attributes at all. All 9 instances converted to
  named classes.

## 0.3.8

**Overview page: dashboard review fixes.**

- **Access map naming collision fixed** — the hub node (this running
  service) and a protected resource can both be literally named
  "gatekeeper" (typically the service's own container, guarded against
  the docker toolkit). The two boxes used to carry the exact same bold
  label in the same diagram; the protected one now reads "own container"
  and its tooltip spells out the distinction.
- **Dashboard stat tooltips** — "Protected resources" and "Tools
  disabled" (renamed from "Tools blocked") sit side by side with the
  same red styling but measure different things: whole toolkits blocked
  for everyone vs. individual tool definitions rejected by a Tier 1
  rule. Both now carry a `title` explaining which is which.
- **Tool matrix caption** — identities with a viewer/admin role and no
  per-tool grants are omitted from the grant columns (their access comes
  from the role, not a grant per tool); the table now says so instead of
  silently showing fewer columns than the identity count implies.
- **Activity feed collapses repeats** — consecutive identical events
  (e.g. three "Sign-in failed" rows in a row) now collapse into one row
  with a "×N" suffix, freeing the feed's limited slots for events that
  actually differ.
- **Executors card is actionable** — "not probed yet" used to be a dead
  end pointing at a raw API path; there is now a "Check now" button that
  probes `/health/ready` and reloads the card in place.
- **Read & write badge more prominent** — filled with the accent color
  instead of a muted outline, since whether the console can currently
  mutate config is one of the more consequential facts on the page.

---

## 0.3.7

**Console UI review fixes + access map filter.**

- **Entity escaping bug fixed** — the Tier 1 ceiling text in the tool
  editor was built with the literal string `&le;`, then passed through
  the same escaping helper as every other value, which printed the
  entity name (`&le;`) instead of `≤` on the page.
- **Layout overflow fixed** — a long path root, scope pattern, or other
  unbounded value in a `.row` card could widen the whole page past the
  viewport, dragging the sidebar and topbar sideways with it. Also fixed
  a 17px mobile overflow caused by the sidebar grid track not shrinking
  below its content width.
- **Audit table header actually sticks** — `position: sticky` had no
  effect because the scroll container's height was unbounded; the table
  wrapper is now height-bounded so the header stays visible while
  scrolling a long audit log.
- **Dark-mode button contrast fixed** — white text on the dark-mode
  accent color measured 2.5:1 on Save/Sign in/New tool/New identity.
  Ink now switches per theme via a `--on-solid` token (7.5–8:1 in both
  themes).
- **Access map tooltips list actual tool IDs** — hovering an identity or
  toolkit node used to show only a tool *count*; it now lists the tool
  IDs themselves (capped at 8, with a "+N more" tail).
- **Access map filter** — a GET-based search field above the map
  (`?q=`, same pattern as the audit page's own filters, no script
  required) dims every identity/toolkit/protected-resource node that
  doesn't match, keeping the map's shape legible instead of removing
  the context around a single hit.
- **Call flow diagram collapsed by default** — it's static documentation
  that looks the same on every visit; it's now a native `<details>`
  disclosure instead of always occupying the top of the page.
- **"Calls, last 12 h" no longer mislabels the feed below it** — that
  card also shows sign-ins and admin changes, not just calls. Split into
  two headed sections: "Calls, last 12 h" (the chart) and "Recent
  events" (the feed).

---

## 0.3.6

**Tools page redesigned — card grid grouped by toolkit.**

- Replaced the flat 7-column table with a responsive card grid.
  Tools are grouped by toolkit prefix (`diag`, `docker`, etc.),
  each group showing a summary header with read/write/disabled counts.
- Each tool is a compact card: tool ID, title, category/idempotent
  pills, binary, and granted-to identities at a glance. Params, scopes,
  and limits are in a collapsible `<details>` (no JS — CSP-safe).
- Disabled tools are dimmed. Cards highlight on hover.
- Grid is responsive: `repeat(auto-fill, minmax(280px, 1fr))` —
  adapts from 1 column on mobile to 3-4 on desktop.

---

## 0.3.5

**UI polish.**

- **Zoom fixed** — removed `position: sticky; height: 100vh` from the
  sidebar. Browser zoom now applies uniformly to the whole page instead
  of only the sidebar.
- **Activity card relabeled** — header now says "Activity" (not "Calls,
  last 12 h"), and the empty-state message reads "No tool calls in the
  last 12 hours" — clarifying that the chart tracks tool calls
  specifically, while the feed below shows all audit events (logins,
  startup, admin changes).
- **Feed spacing** — increased row padding from .55rem to .7rem for
  better readability.
- **Tool matrix** — zebra striping, one cell per identity column, ✓/—
  indicators (from v0.3.4, verified live).

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

## 0.3.1

Neu: [AGENTS.md](AGENTS.md) — was jemand wissen muss, der diesen Code ändert.

Enthält die Zusicherungen, die nicht brechen dürfen, die Konventionen, die
Release-Regel, die Architektur und eine Liste der Fallen, die dieses Projekt
bereits gekostet hat — damit künftige Arbeiten sie nicht erneut zahlen.

Außerdem: Passwort-Rotation für die Oberfläche über `/ui/account` (neben der
bisherigen Token-Rotation in der Identitätsverwaltung).

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