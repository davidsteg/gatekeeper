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

## 0.37.0

**All timestamps in the UI and container logs now use the container's local timezone instead of UTC.**

The audit log already stored timestamps with a local offset (`time.strftime("%Y-%m-%dT%H:%M:%S%z")`), but the UI displayed them in raw UTC — the activity chart axis said "14:32 UTC", the recent-activity feed showed UTC clock times, and the audit log table showed the raw `T`-partitioned string. The container log (`logging.basicConfig`) used the default `asctime` format without a timezone indicator.

Changed:
- **Activity chart** (`_activity_chart`, `_activity_chart_by_day`): `now` uses `datetime.now().astimezone()` (local) instead of `datetime.now(UTC)`; the "UTC" suffix on the axis label is removed. Bucketing (`_bucket_calls`, `_bucket_calls_by_day`) converts parsed timestamps to local before computing hour/day offsets.
- **Recent activity feed** (`_recent_activity`): the clock column now converts the parsed timestamp to local time via `_to_local(stamp).strftime("%H:%M")` instead of raw-string-partitioning the UTC `ts`.
- **Audit log table** (`_view_audit`): the date and clock columns now display local time via `_to_local(stamp).strftime(...)`.
- **Container logs** (`cmd_serve`): `logging.basicConfig` now uses `datefmt="%Y-%m-%dT%H:%M:%S%z"` so log lines carry the local timezone offset, making them consistent with the audit log format.
- Added `_local_now()` and `_to_local()` helpers to `ui.py`.

Stored timestamps (`catalog.now_iso`, `credentials._now`) remain UTC by design — they are compared lexicographically for credential overlap windows and tool version ordering, and a DST transition would break that monotonicity. Only the **display** layer converts to local.

## 0.36.6

**Fix: the access map showed broken image icons for toolkits whose CDN slug doesn't exist — `tdarr`, `diag` (→ `stethoscope`), `file` (→ `folder`), `http`/`webui` (→ `web`) all returned 404 from the dashboard-icons CDN, leaving a broken `<img>` with no `onerror` fallback (CSP forbids scripts).**

The `_DASHBOARD_ICON_SLUGS` map in `ui.py` had four entries pointing at CDN paths that don't exist: `tdarr`, `stethoscope`, `folder`, and `web`. Removed them — those toolkits now fall back to `_toolkit_badge`'s colored monogram (the same circle-plus-initials badge already used for unknown toolkits), which always renders. All remaining slugs verified with HTTP 200 against the CDN.

## 0.36.5

**Reported: new tools reach `admin.tool_list` but never the agent's `/mcp` catalog until the container is restarted. The running process is not the stale half — it serves the new tool on the very next request, and it is callable on the same connection. What is missing is anything telling a connected client to ask again.**

The suspicion was a startup snapshot with no reload hook in
`tool_create`/`tool_enable`/`grant_set`. There is one, and it has been there
all along: `ConfigStore._write_tools` reassigns `service.catalog` from the
file it just wrote, `_write_identities` swaps the identity contents in
place, and `tools/list` reads both on every request. Two tests now hold a
live MCP session open, perform the reported admin sequence against the same
process, and assert that the session sees the new tool on a re-fetch and can
call it — so this hypothesis does not need investigating a third time.

The real gap is the other half of the handshake. Most MCP clients fetch
`tools/list` once at session setup and keep it; MCP's way to invalidate that
is `notifications/tools/list_changed`, and gatekeeper sends none. It also
cannot today: `/mcp` runs with `stateless_http=True`, so every request gets
its own short-lived transport and there is no retained session to push a
notification into. Restarting the container works only because it forces
every client to reconnect.

Which makes the practical remedy a **client reconnect rather than a
container restart** — cheaper, and it leaves everything else the container
is doing alone. `docs/DEPLOYMENT.md` gains a section saying so, with the
evidence for why the server side can be ruled out.

**No behaviour changed in this release, deliberately.** Sending the
notification means holding sessions on `/mcp`, which is a wire-protocol
change for every connected agent — session ids, `Mcp-Session-Id` handling,
and reconnect semantics — not something to switch on as a side effect of a
bug report. It is the one open decision, and it belongs to whoever runs the
agents.
## 0.36.4

**Fix: the `files.write` test tool in `test_runas.py` was missing its `content` parameter — the service-call test passed `{"path": ..., "content": "x"}` but the tool spec only declared `path`, so `service.call` raised `param_unknown: Unknown parameter 'content'`. Added the `content` parameter with `pattern: "[\\s\\S]*"` and `allow_control_characters: true`, matching the real `file-tools.yaml` example.**

## 0.36.3

**Fix: one test helper in `test_runas.py` still had `"pattern": "^/"` (line 1187) — the `replaceAll` edit missed it because of a slightly different formatting. `re.fullmatch('^/', '/tmp/x.txt')` returns `None`, causing the service-call test to fail with `param_invalid`. Changed to `^/.*`.**

## 0.36.2

**Fix: the 0.36.1 test pattern `^/` failed `fullmatch` validation — `re.fullmatch('^/', '/tmp/x.txt')` returns `None` because `fullmatch` requires the entire string to match, not just a prefix. Changed to `^/.*` which matches any absolute path fully.**

## 0.36.1

**Fix: the 0.36.0 tests failed in CI — ruff flagged an unsorted import in `catalog.py` (the new `_runas` import was placed after `errors` instead of before it alphabetically), and the new `test_runas.py` tests created tool parameters without the `pattern` field that FR-5.7 requires for string parameters.**

Both are test-only fixes; no runtime behavior change. The import order is corrected (`._runas` before `.errors`), and all test helpers that create tool specs now include `"pattern": "^/"` on string parameters.

## 0.36.0

**Fix: per-tool `run_as` was silently ignored — `service.py:360` always used `toolkit.run_as`, so a tool spec that declared `run_as: root` while its toolkit declared `run_as: 568:568` would silently run write/patch as uid 568. Read worked only by coincidence of the toolkit also setting root; write/patch on a toolkit with a different default failed with "The operation ran as uid=568" instead of as the tool's requested user.**

The root cause: `ToolDef` (catalog.py) had no `run_as` field. A `run_as` in the tool spec YAML was parsed by neither `parse_tool_spec` nor validated — it sat in the raw YAML, visible in `admin.tool_get`, but never reached the executor. `service.py` hardcoded `run_as=toolkit.run_as` at the call site, so the tool-level value was invisible to every operation.

`ToolDef.run_as` now exists (file executor only). `parse_tool_spec` parses and validates it with the same `parse_run_as` the toolkit level uses — a bad value fails at startup, not on the first call. `None` (or unset) inherits the toolkit's `run_as`; an empty string explicitly clears it (run as the container user, regardless of what the toolkit says). `service.py` resolves the effective `run_as` as `tool.run_as if tool.run_as is not None else toolkit.run_as`, with the empty string mapped to `None` (no run_as — in-process).

The common case this enables: a `file` toolkit with `run_as: root` for write tools, and a read tool on the same toolkit that sets `run_as: ""` to run as the container user — the read tool does not need the privilege, and this avoids spawning the helper child for it. The field is `tools.yaml` (Tier 1, console-writable), not agent-supplied — it narrows the toolkit's authority, never widens it.

Tests: `test_runas.py` gains a catalog-parsing section (per-tool run_as parsed, empty string is explicit clear, null is none, malformed aborts) and a service-path section (tool run_as wins over toolkit, tool without run_as inherits toolkit, empty string clears toolkit). The service-path tests intercept `execute_file.run` to assert the `run_as` argument — they do not need root, because the bug is in the wiring, not the privilege.

## 0.35.1

**Fix: the `GATEKEEPER_KEEP_CAPS` tests from 0.35.0 failed in the CI root job because the test container lacked `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` in its bounding set, and the "without KEEP_CAPS" test created a file owned by root (which `run_as: root` could read as the owner).**

The CI `tests (root)` job runs in a `python:3.12-slim` container that only had `CAP_SETUID`/`CAP_SETGID`. The `GATEKEEPER_KEEP_CAPS` tests call `capset` to put `DAC_OVERRIDE`/`DAC_READ_SEARCH` into the permitted set — but `capset` can only add capabilities that are in the bounding set, so it failed with EPERM. The workflow now adds `--cap-add CAP_DAC_OVERRIDE --cap-add CAP_DAC_READ_SEARCH` to the container options, matching what a real deployment would grant.

The end-to-end test `test_without_keep_caps_run_as_root_cannot_read_foreign_file` created a 0600 file owned by root and expected `run_as: root` to fail — but root IS the owner, so it read fine. The file is now `chown`ed to uid 568 so root is genuinely foreign to it, making the "without KEEP_CAPS → Permission denied" assertion meaningful.

## 0.35.0

**Fix: explicitly `cap_add`-ed DAC capabilities (`CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`) were silently discarded by the startup privilege drop, so `run_as: root` could not read files owned by other users even when the container had been granted those capabilities.**

The startup drop (`_selfdrop.py`) hardcoded `_KEPT = CAP_SETUID | CAP_SETGID` and called `capset(_KEPT, _KEPT, _KEPT)`, discarding everything else in step 3 of the drop. A deployment that added `DAC_OVERRIDE` and `DAC_READ_SEARCH` to `cap_add` — the standard way to let `run_as: root` read foreign 0600 files — would see `docker inspect` report the caps in `CapAdd` but `/proc/1/status` show `CapEff=00000000000000c0` (only SETUID+SETGID), and every `run_as: root` read of a file it did not own would fail with `Permission denied`.

`GATEKEEPER_KEEP_CAPS` now names the extra capabilities to carry through the drop, in Docker `cap_add` notation (`DAC_OVERRIDE,DAC_READ_SEARCH`; a `CAP_` prefix is accepted too). The extras are kept in the **permitted**, **inheritable** and **ambient** sets but **not the effective set** — the server process itself cannot use them, only the `run_as` child can after inheriting them from the ambient set on `execve`. This is the narrowest split that lets a privileged child read foreign files without the server itself being able to. The base two (`SETUID`+`SETGID`) remain hardcoded and always kept; extras are opt-in.

An unknown capability name is a startup error, not a silent skip — the operator typed it for a reason, and carrying on without it would produce the exact "looks like a bug" failure this module exists to make legible. When no toolkit declares `run_as`, startup discards the extras along with the base two (`discard_capabilities`), so the common case still ends up holding nothing.

The startup warning for `run_as: root` in a container without DAC caps now checks both the server's effective set *and* the child's ambient set (via `child_bypasses_file_permissions`), so a deployment with `GATEKEEPER_KEEP_CAPS` no longer gets a false alarm. The warning message names the new env var as the fix.

Tests: `_selfdrop.py` gains a section for `GATEKEEPER_KEEP_CAPS` — off by default, empty string is zero, unknown name is refused, `CAP_` prefix accepted, extras in CapPrm/CapInh/CapAmb but not CapEff, extras survive exec into the child, and end-to-end `run_as: root` reads a 0600 foreign file with `KEEP_CAPS` and fails without it. The root-requiring tests run in the `tests (root)` CI job.

## 0.34.1

**Fix: the "cannot be read" startup error stated `568:568` as a fixed string instead of reading the process's actual uid — the one message where being told the wrong uid costs the most, because the reader chowns to it and the failure does not move.**

Reported from a crash loop: `Configuration error:
/etc/gatekeeper/toolkits.yaml cannot be read. Check the owner -- the
container runs as 568:568.` The cause was ordinary and expected — files
created while the container ran as root stay root-owned, so the first start
after switching a deployment to a lesser user cannot read its own config —
but the message was asserting an identity it had never looked up.
`errors.py` had `"568:568."` written out literally, the shipped image's
convention rather than this process's identity. Correct here by luck; wrong
for any deployment that names a different uid, and wrong on purpose since
0.32.0, where `GATEKEEPER_DROP_TO` makes the running uid a deploy-time
decision.

It now reads `os.geteuid()`/`os.getegid()`, and says what to do about it:
check the file *and every directory above it* (a denial naming the file is
often a parent without `+x`), that this is the usual first failure after
switching to a lesser user, and the `chown -R <uid>:<gid>` against the
mounted directory. A test scans every module for a runtime message that
names a uid it did not read; docstrings and comments may still say 568,
since they describe the image rather than the process. Counter-checked
against the previous wording, which it fails.

## 0.34.0

**Two things, both about `run_as` telling the truth: the startup drop no longer discards `group_add` (which silently cost the container its Docker socket), and `run_as: root` failing with a bare "Permission denied" now says which uid ran the operation and why uid 0 was not enough.**

**The group bug.** `_selfdrop` copied `_runas.become`'s `os.setgroups([])`,
where emptying the set is correct: there the drop *is* a privilege boundary
for one operation, and carrying the server's groups into it would widen
exactly what the boundary narrows. In the startup drop it is wrong. Those
groups came from `group_add:` in the deployment — deliberate configuration,
and specifically how the container reaches `/var/run/docker.sock`. Measured
before and after: `[0, 999]` went to `[]`, so switching `GATEKEEPER_DROP_TO`
on would have left every `docker` toolkit failing with EACCES and nothing
saying why. It is invisible until then, because with `user: "0:0"` root
never needed the group. The drop now keeps what it was given, minus group 0
— that one is present because the container started as `user: "0:0"`, not
because anyone asked for it, and a process that has just given up root
keeps no read access to root-group files on the way out.

**The denial.** Reported as `run_as: root` not working: container correct
(`Config.User=0:0`, `CapEff=00000000000000c0`), toolkit correct
(`run_as: root` live in `admin.toolkit_list`), and `file.read` answering
`Permission denied` on a file owned by 568 — which looked like the
operation running as some third user, or `run_as` being ignored.

It was neither. The operation ran as uid 0, exactly as configured, and the
kernel refused it correctly. "Root can read any file" is not a property of
uid 0; it is `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`, two ordinary
capabilities that `cap_drop: ALL` removes from root along with everything
else, and that `cap_add: [SETUID, SETGID]` does not give back. In the
recommended container uid 0 is therefore checked against file modes like
anybody else, so against `-rw------- 568 568 compose.yaml` it gets EACCES —
while `run_as: "568:568"` reads the same file holding no capability at all.
`run_as: root` reaches *less* than the owning uid, which is the opposite of
what the name suggests.

Reproducing it took one correction worth recording: restricting the
parent's permitted set is not enough, because on `execve` the kernel
re-derives a root child's permitted set from the **bounding** set, so the
helper got `CAP_DAC_OVERRIDE` straight back and the first attempt passed.
`cap_drop: ALL` is a bounding-set restriction; the test drops the bounding
set, and then the failure reproduces exactly.

So the message says it now. A denial from a `run_as` call reports the uid
and gid the operation actually ran as and the `run_as` value that asked for
them; for uid 0 without those capabilities it adds that root is not above
file permissions here, whether the capability is even reachable in this
container's bounding set, and that naming the owning uid is the answer. For
a non-root target it stays an ordinary permission problem and says to check
the mode and the traversability of the parent directories instead — no
capability lecture where none applies. Startup warns about the same thing
at deploy time rather than at first call, for any toolkit whose `run_as`
resolves to uid 0 in a container without those capabilities.

Nothing about the `run_as` mechanism changed: it was applying correctly the
whole time. What changed is that a correct refusal no longer reads like a
broken feature.

Seven tests: that `group_add` survives the drop and group 0 does not; the
reported failure reproduced end to end, including that the owning uid
succeeds where root fails; that the denial names the uid, the `run_as`
value and the missing capability; that a non-root denial stays plain; and
that `bypasses_file_permissions` matches the process's real effective set.

## 0.33.0

**A fresh install put its audit log in `/etc/gatekeeper/logs` — inside the configuration directory, which is what stops that mount from ever being `:ro`. The image now declares `/var/log/gatekeeper`, and `compose.yaml` stops mapping a host path onto itself.**

Three answers to "where does the audit log go" coexisted in the tree, which
is two too many. `gatekeeper init` wrote `<state-dir>/logs`, and since the
image sets no separate state dir that resolved to `/etc/gatekeeper/logs`.
The example config and the Tier 1 fallback said
`/mnt/raid/gatekeeper/logs`. The compose mount said the same — mapped onto
*itself*, `/mnt/raid/gatekeeper/logs:/mnt/raid/gatekeeper/logs`, so the
path inside the container was an artefact of one particular NAS layout.

The `init` default was the one that mattered, because it is what a real
first start produces, and it was the wrong one twice over. `/etc` is for
configuration; a file that rotates every few seconds by `max_bytes` and
`keep_files` is not configuration. And a configuration directory being
written to continuously cannot be mounted read-only — which rules out the
hardening `compose.yaml` documents two sections further down, where Tier 1
is made immutable at runtime. Keeping the log out of there is what makes
`- /path/config:/etc/gatekeeper:ro` possible at all.

`GATEKEEPER_AUDIT_DIR` fixes it without hardcoding a container path into a
library. The image declares `/var/log/gatekeeper`; a bare `pip install`
sets nothing and keeps the self-contained `<state-dir>/logs`, so a checkout
stays runnable from any directory without write access to `/var/log`; and
`gatekeeper init --audit-dir` still beats both. The compose mount now reads
`- /mnt/raid/gatekeeper/logs:/var/log/gatekeeper`: host layout on the left,
standard path on the right, which is the distinction that got lost.

**Nothing moves for an existing deployment.** The variable only seeds a
*new* `toolkits.yaml`. `audit.dir` in an existing one is Tier 1 and
authoritative — no upgrade rewrites it, so an installed instance keeps
writing exactly where it already does. Moving it stays a deliberate edit of
that line plus a repointed mount, and `docs/DEPLOYMENT.md` gains a section
saying so, along with the precedence order and why `/etc/gatekeeper` is the
wrong home.

One inconsistency is deliberately left standing: the Tier 1 fallback in
`tier1.py`, used only by a hand-written `toolkits.yaml` with no `audit:`
block at all, still reads `/mnt/raid/gatekeeper/logs`. Changing it would
move the audit log of any deployment in that shape, and a deployment that
does not start without adjustment is a MAJOR by this project's own rule —
worth doing on purpose, not as a side effect of tidying a default.

Eight tests: the three precedence levels, that the resulting path is not
inside the configuration directory, that the image, the example config and
the compose mount all agree on `/var/log/gatekeeper`, and that the compose
log mount does not map the host path onto itself.

## 0.32.0

**`run_as` no longer costs the container its unprivileged life. `GATEKEEPER_DROP_TO` starts gatekeeper as root, has it become 568 immediately, and keeps exactly `CAP_SETUID`/`CAP_SETGID` across the drop — so a `file` toolkit can still switch to another user per operation while the server itself spends its whole life unprivileged.**

Until now `run_as` left two deployments, both unattractive. `user:
"568:568"` is unprivileged and `run_as` cannot work at all, because Docker
grants capabilities to uid 0 alone. `user: "0:0"` with `cap_add` makes
`run_as` work and puts the process at uid 0 for its entire life: every file
it writes is root-owned, and the container that mediates root-equivalent
access to the host is itself root while doing it.

The third option does both. The container starts privileged; `_selfdrop.py`
runs before argparse and before any file is touched, and becomes the
configured uid while keeping the two capabilities. Startup then reports
`568:568` with `CapEff=00000000000000c0`, files land owned by 568 exactly as
in the unprivileged profile, and `run_as` still works — `_runas.py` has
asked the kernel for `CAP_SETUID` rather than for uid 0 since 0.30.0, so
nothing downstream needed changing.

The order matters and every step earns its place. `PR_SET_KEEPCAPS(1)`
first, or the kernel empties the permitted set the moment euid leaves 0.
Supplementary groups, then `setresgid`, then `setresuid` — groups first
because both need what `setresuid` gives away. Then `capset` back to exactly
`{CAP_SETUID, CAP_SETGID}`: the uid change preserves *permitted* under
KEEPCAPS but still clears *effective*, so without it the process holds the
capabilities and cannot use them. Then `PR_CAP_AMBIENT_RAISE` for both —
the step an implementation gets wrong silently. The `run_as` helper is a
separate process reached by `fork`+`exec`, and on `execve` of an ordinary
file the kernel derives the new permitted set from the file's own
capabilities, which are none. The ambient set is the only one that survives
an `execve`, and therefore the only way the helper ever sees the capability
its existence depends on.

`no-new-privileges: true` stays on and does not conflict: it governs what
`execve` may grant *from a file*, and the ambient set is not that. Asserted
rather than argued — a test sets `no_new_privs`, performs the drop, `exec`s
`/bin/cat` and reads the capabilities back out of the child's
`/proc/self/status`.

Three things keep the change from reaching anyone who did not ask for it:

- **Off unless configured.** Without `GATEKEEPER_DROP_TO` the module does
  nothing, which is also what stops `gatekeeper serve` on a bare host from
  trying to become a uid that does not exist there. Deliberately not baked
  into the image either: a container started as `user: "0:0"` with no
  `cap_add` would then refuse to boot, and that is somebody's working
  deployment today.
- **The capabilities are handed back when unused.** The drop has to precede
  reading the configuration, so the two are kept on the chance a toolkit
  wants them; if none declares `run_as`, startup discards them and logs it.
  The common case ends up holding nothing.
- **A failed drop aborts startup** with exit 2. A server told to give up
  root that could not must not go on to serve requests while its log says
  568.

Stated plainly, because the profile is easy to over-read: a process holding
`CAP_SETUID` can call `setuid(0)` at will, so this is **not** a boundary
against a compromised gatekeeper. Against an attacker with code execution
inside the process it is worth about what `user: "0:0"` is worth. What it
buys is narrower and real: file ownership, a smaller blast radius for the
ordinary bugs that are not code execution, and a capability set of two
entries rather than root's full complement. `docs/DEPLOYMENT.md` says so at
the point of choosing.

This reverses an invariant 0.31.0 had just finished pinning. That release
added `test_no_internal_drop.py` to settle, after three reports, that
gatekeeper never changes its own uid — and this one gives that up on
purpose. The test file is rewritten rather than deleted: it now pins the
narrower guarantee (only two modules may change identity, the startup one
only behind its setting, `drop_privileges` called from `main()` alone) and
keeps the diagnostic that made it worth having. With `GATEKEEPER_DROP_TO`
unset, a process at 568 was still started at 568, and hunting for an
internal drop is still a dead end.

Ten tests in `test_selfdrop.py`, all of the real ones needing root and so
running in the `tests (root)` job: that the drop keeps exactly the two
capabilities in all four sets, that they survive an `execve` under
`no_new_privs`, that `run_as: root` really writes a root-owned file from a
568 server, that a toolkit *without* `run_as` still writes as 568, that root
without `cap_add` is refused with the reason, that dropping to uid 0 is
refused outright, and that a failed drop exits 2 instead of serving.

## 0.31.0

**Reported again: `user: "0:0"` and `cap_add` both set, container recreated, and the process is still `uid=568` with an empty `CapEff` — so something inside gatekeeper must be dropping privileges. Nothing is. This release makes that checkable instead of arguable, and removes the `compose.yaml` trap that most likely caused it.**

There is no internal privilege drop, and now a test says so rather than a
changelog entry. `test_no_internal_drop.py` parses every module under
`src/gatekeeper` and fails if any of them calls `setuid`, `seteuid`,
`setreuid`, `setresuid`, the four `gid` equivalents, `setgroups` or
`initgroups` — with one allowance, `_runas.py`, whose calls run in the
short-lived helper *child* after the server has already forked and exec'd
it. Parsed rather than grepped, so the many docstrings that discuss
`setresuid` do not count as calling it. Further tests pin the other places
a drop could hide: that `become` is called from the helper's own entry
point and nowhere else, that the Dockerfile's only `USER` line is
`USER 568:568`, and that `ENTRYPOINT` goes straight to the console script
with no `gosu`/`su-exec`/`setpriv` wrapper in the image.

Which leaves the question the report should actually have been pointed at.
gatekeeper is started as some uid and stays it, so a process at 568 was
*started* at 568, and what starts it there is the image default —
`USER 568:568`. A compose `user:` overrides that unconditionally. If the
process is 568, the `user:` never reached the container, and no amount of
reading Python will explain why.

**The likeliest reason is a trap 0.30.0 shipped in `compose.yaml` itself.**
The commented block for enabling `run_as` contained its own
`# user: "0:0"` line, three lines under a comment warning not to add a
second `user:` key. Uncommenting the block did exactly that. A YAML mapping
with a repeated key does not merge — compose keeps one, and if it keeps the
`"568:568"` at the top of the service the result is precisely the reported
state: `cap_add` accepted, container still 568, `CapEff` empty, every
`run_as` call failing with a message about capabilities. The block no longer
contains a `user:` key to uncomment; it says to edit the existing line and
explains why there is nothing to uncomment. A test asserts the service
declares exactly one `user:` key and that no commented-out one is waiting.

The startup error now names all of this. Where the process is not root it
says gatekeeper never changes its own uid, that the image default is
`USER 568:568`, and lists what to check in order of likelihood: two `user:`
keys, a container restarted rather than recreated, or a compose file at a
different path than the one edited — with the `docker inspect -f
'{{.Config.User}}'` that settles all three. The previous wording named the
right cause ("Docker grants capabilities to uid 0 only") but left the reader
to work out that the container was not root *despite the file*, which is the
step where the search turns inward and stalls.

New, and off unless asked for: `GATEKEEPER_REQUIRE_RUN_AS=1` refuses to
start when a toolkit declares `run_as` and the process cannot assume another
user, exiting `2` with the reason. Without it — the default, unchanged — such
a container starts, logs an `ERROR`, passes its healthcheck, looks entirely
healthy, and fails every `run_as` call until somebody reads the log. It stays
opt-in because a toolkit may carry `run_as` for a call nobody makes, and
aborting on that would turn a merely over-declared deployment into one that
will not boot.

`docs/DEPLOYMENT.md` gains both: a section for "the container still comes up
as 568" with the three causes and the command that distinguishes them, and
one for the new switch. Ten tests cover the release, including a counter-test
that the compose assertion really does fail against the block as 0.30.0
shipped it.

## 0.30.2

**Fix: the `tests (root)` job named one test file, so the privilege tests added in 0.30.1 never ran in CI.**

0.30.0 added that job precisely because `needs_root` tests skip themselves
on an ordinary runner, which meant the assertions carrying the privilege
boundary were exercised nowhere. It ran `pytest tests/test_runas.py`. Then
0.30.1 put its own `needs_root` tests -- that a `local` binary really does
inherit ambient capabilities without the wrapper, that it holds none with
it, that a failed drop stops the binary running -- in a second file, and
the job kept naming only the first. The gap it was built to close reopened
one release later, silently and in exactly the way the job existed to
prevent.

A list of files here is maintenance that gets forgotten, so there is no
list: the job runs the whole suite as root. Any `needs_root` test, in any
file, present or future, runs without anyone remembering to wire it up.
The cost is a second full run of the suite, parallel to the ordinary one
and so free in wall-clock time.

## 0.30.1

**Fix: a `local` toolkit's binaries inherited gatekeeper's ambient capabilities. `docker`, `df`, `free` and `cat` ran holding `CAP_SETUID` — one call from being root — with no use for it.**

Only reachable in the deployment 0.30.0 opened up: gatekeeper started
unprivileged but keeping `CAP_SETUID`/`CAP_SETGID` across its own drop, a
`setpriv`/`gosu` wrapper. Capabilities kept that way necessarily live in
the *ambient* set, and the ambient set is inherited by every `execve`,
not only the one that needs it. Where the container starts as root and
gains the two through `cap_add`, they sit in uid 0's permitted set, no
child inherits them, and none of this applies.

0.30.0 reported this as a `WARNING` and left it standing, on the grounds
that the obvious mechanism was unavailable: clearing the ambient set
process-wide would disarm the `run_as` helper too, toggling it around
each spawn is a race across concurrent calls (the same objection that
rules out `seteuid` in the file executor), and a `preexec_fn` runs
between `fork` and `exec` in a process with an asyncio loop and threads
-- the exact window `_runas.py` uses `fork`+`exec` to stay out of. All
three still hold. What none of them ruled out is doing the work in a
process that is already past that window.

So `local` binaries are now exec'd through `_unpriv.py`, the mirror image
of `_runas.py`: where that module exists so one `file` operation can run
with *more* authority than gatekeeper, this one exists so a binary runs
with *less*. It empties its own capability sets, verifies they are empty,
and then `execve`s the real binary over itself. If the drop does not
take, it refuses to run the binary at all -- a `docker` that silently
kept `CAP_SETUID` is indistinguishable from a correct call from the
outside, which is the whole reason this is worth a process.

Three properties keep it from being felt anywhere else:

- **It is absent where there is nothing to strip.** The wrapper is
  inserted only when the process actually holds ambient capabilities.
  Every other deployment spawns binaries directly, with no extra exec and
  no behaviour change.
- **The pid does not move.** `execv` replaces the wrapper rather than
  forking, so the pid `execute.run` holds is the binary's. The timeout,
  the process-group kill on timeout and the output streaming are
  untouched.
- **Failures read the same.** A missing or non-executable binary raises
  the same `EXECUTOR_UNAVAILABLE` denial with the same wording, naming
  the binary rather than the interpreter asked to run it -- so whether a
  deployment inherits capabilities stays invisible to every caller.

Thirteen tests, in both directions: that a binary really does inherit the
capabilities without the wrapper (so the test below cannot pass against a
wrapper that does nothing), that `cat` reports all four of its capability
sets empty with it, that the drop failing stops the binary running, that
the pid survives, and that both denials are identical wrapped and
unwrapped.

## 0.30.0

**`run_as` now decides on the capability it actually needs instead of on uid 0 — a container told to add `cap_add: [SETUID, SETGID]` while still running as 568 was refused with a message asking for precisely what had just been added.**

Reported as: `run_as` on a `file` toolkit kept failing with *"gatekeeper
runs as uid=568 gid=568 and holds no privilege to change user"* after the
container had been recreated with `cap_add: [SETUID, SETGID]`, with
startup confirming the new configuration. The suspicion was a privilege
drop somewhere in startup that lost the capabilities for want of
`PR_SET_KEEPCAPS` before the `setuid`.

There is no such drop. gatekeeper never changes its own uid: outside the
short-lived `run_as` helper child, no `setuid`/`setresuid`/`initgroups`
call exists anywhere in the tree, and there is no entrypoint wrapper.
`PR_SET_KEEPCAPS` would have had nothing to keep capabilities across.

The real cause is one line in `become()`, which asked `geteuid() != 0`
and, on failure, advised adding `CAP_SETUID` and `CAP_SETGID`. That is
wrong in both directions. **Docker puts `cap_add` entries in the
permitted set of uid 0 only**, so a container that gains the capabilities
while its `user:` line still reads `568:568` comes up with an empty
`CapEff` — granted and simultaneously unusable — and the call fails with
the same message that asked for what was already there, redeploy after
redeploy, while the half that would have fixed it (`user: "0:0"`) is the
one thing the message never mentioned. In the other direction, a root
process whose capabilities were dropped passed the uid test and failed
three lines later at `setresuid` with a bare `EPERM`.

`become()` now reads `CapEff` from `/proc/self/status` and gates on
`CAP_SETUID`/`CAP_SETGID`, falling back to uid 0 only where the set
cannot be read at all. The failure message names which of the two halves
is missing and prints the capability set, and startup reports the same
thing as a checked fact rather than a restatement of `toolkits.yaml`: one
`INFO` line when `run_as` is usable, one `ERROR` naming the cause when it
is not. `compose.yaml`, `README.md` and `docs/DEPLOYMENT.md` say
throughout that both halves are required and that neither works alone.

Gating on the capability rather than on uid 0 also admits a deployment
that was previously refused outright: a process that is *not* root but
holds the two capabilities ambiently, as a `setpriv`/`gosu` wrapper
leaves it. That path needs one thing the root path gets for free —
leaving uid 0 makes the kernel empty the capability sets, but a change
between two non-root uids does not, so a child that kept `CAP_SETUID`
would be one `setuid(0)` from root. `become()` therefore clears the sets
explicitly with `capset` and verifies the result before running the
operation.

Two further gaps in that child, found while hardening the above:

- **The bounding set stays full.** `capset` does not reach `CapBnd`, and
  lowering it needs `CAP_SETPCAP`, which no deployment here grants and
  which would be an odd capability to grant in order to *drop*
  capabilities. While it is full, a setuid-root binary or a file carrying
  capabilities remains a route back up for anything the child execs. The
  child now sets `no_new_privs` as its first act, which closes that class
  outright, needs no privilege, cannot be undone, and costs nothing — the
  file operation runs in-process and never execs. It does not impede the
  drop: `no_new_privs` restricts what `execve` may grant and nothing
  about `setresuid`.
- **The verification only asked about `CapEff`.** A capability in the
  permitted set is one `capset` from being usable again and one in the
  ambient set survives the next `execve`, so that check called a process
  clean that was not. All four sets are read and any non-empty one is
  named.

Ambient capabilities are inherited by every process gatekeeper spawns,
not only the helper that needs them — a `local` toolkit's binaries would
hold `CAP_SETUID`/`CAP_SETGID` they have no use for. That cannot be
narrowed from the inside (clearing the ambient set would disarm the
helper too, and clearing it per-spawn would need a `preexec_fn`, which
reintroduces the fork-in-a-threaded-process hazard the helper avoids by
using `fork`+`exec`), so startup logs a `WARNING` naming the set, and
`docs/DEPLOYMENT.md` recommends the root + `cap_add` deployment wherever
`local` toolkits are also in play.

Finally, the privilege tests no longer skip themselves in CI. Everything
that asserts the boundary — that the drop really gives up authority, that
root is not regainable, that no capability survives — runs only as root
and was therefore skipped on every hosted runner. A `tests (root)`
container job now runs `tests/test_runas.py` as root, verifies first that
it is genuinely privileged (so a runner without the capabilities cannot
skip its way to green), and gates the image build alongside the ordinary
suite. Ten new tests cover the change, including both misdiagnoses and
the ambient-capability path end to end.

## 0.29.1

**Fix: `admin.toolkit_list` never reported `run_as` -- an approved toolkit_update proposal looked like it never took effect, with no restart able to fix that.**

Reported as: `run_as: root` on a `file` toolkit was genuinely approved and
deployed (the audit log showed the correct `before: null -> after:
"root"`), but `admin.toolkit_list` kept reporting nothing for it,
restart included. Traced it against 0.29.0's own change: `run_as` joined
`toolkits.yaml`, the loader (`load_tier1`), the toolkit-update proposal
path, and the `/ui` reference card -- but `admin_service.py`'s
`toolkit_list` dict comprehension was never taught the field, so it
simply never appeared in the response. Both halves that actually matter
were already correct and verified by a fresh reproduction: `toolkits.yaml`
carried the write (persistence is one write path, shared unconditionally
by create/update/delete), and `Service.reload_config` reassigns
`self.tier1` synchronously in the same process, so the value was live the
entire time. `toolkit_list` just never looked. Restarting the container
could not have fixed it, because the dict was missing the key regardless
of what `tier1.toolkit(name).run_as` held.

This is the same shape of bug `target`/`credential` needed fixing for
once already, per `toolkit_list`'s own docstring -- a field that exists
on `Toolkit` but is missing from this one reporting dict reads as "not
configured" to whoever asked, when it was really just unreported.

Fix is one line: `"run_as": tk.run_as` in the dict, reported plainly
(`None` on every toolkit that never set it, not merely absent). Three
tests guard it: presence when unset, the actual value when a toolkit
declares it at load time, and the exact reported scenario end to end --
propose a `run_as` update, deploy it, and read it back from
`toolkit_list` on the same running process with no restart in between.

## 0.29.0

**`run_as` is now changeable through a human-reviewed toolkit proposal, not only by a redeploy.**

0.28.0 shipped `run_as` (which OS user a `file` toolkit's operations run
as) as the one Tier 1 field refused in every proposal, on the grounds that
it decides *with whose authority* an operation runs rather than what is
allowed. That ban does not survive contact with `admin.toolkit_propose`,
which already carries a toolkit's **full** body, `path_roots` included: an
agent could propose a broad `file` toolkit and then update it. The ban cost
friction and bought no boundary, so it is gone rather than left standing as
something that reads like a guarantee and is not one.

`run_as` joins `executor`/`binaries`/`denied_args` in
`UPDATE_WRITABLE_FIELDS`:

```
admin.toolkit_update(name="agentcfg", updates={"run_as": "3001:3001"})
```

Still always-pending, still never live until a human approves it at
`/ui/requests`. `null` clears it, handing the toolkit back to the container
user — the inverse had to be proposable too, or undoing a `run_as` would
need the redeploy this path exists to avoid.

**What did not move, and is where the boundary actually lives:**

- **The container's privilege.** `run_as` only does anything where the
  container was started with `CAP_SETUID`/`CAP_SETGID`. No proposal can
  reach that decision. On a deployment that never granted it, a deployed
  `run_as` makes the calls *fail*, not escalate.
- **`path_roots` and `protected_resources`** stay redeploy-only. So a
  proposal may change *who* an operation runs as, never *where* it may
  reach. A test asserts `UPDATE_WRITABLE_FIELDS` is exactly those four
  names, so widening it stays a deliberate edit with a test to change
  rather than a one-word diff.

Be clear-eyed about what this does open: on a deployment that has already
granted the capabilities for one toolkit, an approved proposal can point an
*existing* `file` toolkit — including one whose `path_roots` are already
broad — at a more privileged user. The review card now says so explicitly
rather than leaving `run_as` to read as one more line of YAML: when a
proposal carries the field, the Approve & Deploy dialog names the user and
states that every file operation on that toolkit would run as it.

The tool schema gained `run_as` too — opening only the server-side set
would have left the MCP schema silently rejecting it one level up, so
there are tests at both layers.

## 0.28.0

**A `file` toolkit can now say which OS user its file operations run as (`run_as`) -- per toolkit, never globally, and never silently.**

The `file` executor works in-process, which is exactly what makes it safe
(no shell, no argv, one fixed operation per tool) and also its one limit:
every read and write happens as whatever user gatekeeper itself runs as,
`568` in the shipped image. A directory that belongs to somebody else with
mode `0700` is therefore unreachable no matter how `path_roots` is written
-- not because Tier 1 forbids it, but because the kernel does. The obvious
workaround, widening the container's own rights, is FR-4.9's union-of-needs
mistake applied to file ownership: every toolkit gains what one toolkit
needed.

A `file` toolkit may now declare `run_as` in `toolkits.yaml`, either an
account inside the image or the numeric `uid:gid` pair for a host uid that
has none:

```yaml
  agentcfg:
    executor: file
    path_roots: [/mnt/raid/agent]
    run_as: "3001:3001"
```

What the field is and is not:

- **Per toolkit, and only `file`.** `run_as` on a `docker`/`local`/`http`/
  `truenas`/`ssh` toolkit aborts startup rather than being ignored --
  config that reads as "these run as somebody else" and does not is worse
  than config that refuses to start. A `file` toolkit without the field
  takes the same in-process path as before, byte for byte; a test asserts
  that path still spawns nothing.
- **Redeploy-only.** No parameter, no tool field, no `/admin/mcp` call
  picks a user -- the rule FR-8.3i already states for destinations. It is
  refused even in a human-reviewed toolkit proposal, because it decides
  *with whose authority* an operation runs rather than what is allowed,
  and the redeploy is where the same person also decides whether the
  container may hold the privilege to honour it.
- **No silent fallback.** A process that cannot become the requested user
  fails the call and says so. Running it as the container user instead
  would make `run_as` a suggestion, and would dress a `Permission denied`
  up as though the override had been in effect.

An in-process executor cannot assume another user: `seteuid` is
process-wide, leaks into every concurrent call, and is reversible by
construction -- the opposite of a privilege boundary. So a `run_as`
operation runs in a short-lived child (`_runas.py`) that drops privileges
irreversibly first -- real, effective *and* saved ids together,
supplementary groups replaced -- verifies the drop took effect including
that root is no longer regainable, and only then touches the filesystem.
It re-checks the path against `path_roots`/`protected_resources` on the
privileged side too, and takes its request over stdin rather than argv: a
`file.write` carries the whole file content, which has no business in
`/proc/<pid>/cmdline`. A setuid-root helper binary in the image was the
alternative and is worse -- permanently privileged, reachable by anything
in the container.

Because the child is a real process it can also hang, so the `file`
executor now honours `timeout_seconds` on this path, with FR-6.9's
distinction intact: a killed non-idempotent write reports `unknown`, not
`failed`.

**Deploying this costs the container its unprivileged start, so scope it
deliberately.** `run_as` needs `user: "0:0"` plus `cap_add: [SETUID,
SETGID]` (everything else stays dropped; `no-new-privileges` stays on).
Prefer the owning uid over `root`: it is bounded by that user's own
permissions, whereas root additionally needs `CAP_DAC_OVERRIDE`, which
reads every file on every mount. `docs/DEPLOYMENT.md` has the full
recipe, `compose.yaml` the commented block, and startup logs a warning
line naming the user for every toolkit that declares one. A deployment
that adds none of this is completely unaffected.

Also in this release, from commits that had not been published yet:
`admin.toolkit_delete` (propose removing a Tier 1 toolkit over
`/admin/mcp`, same always-pending human-deploys path as
`toolkit_propose`/`toolkit_update`), and `/ui/requests` grant_set review
cards now show only the tools a proposal actually adds or removes instead
of re-listing the identity's whole resulting set.

## 0.27.3

**Fix: the access map's hover popup, properly this time -- clipped popups *and* the blank space below the table both gone.**

The last three releases each traded one symptom for another here, because
the constraint was never actually established. It is this: the matrix
needs `overflow-x: auto` to scroll sideways when there are many toolkits,
and CSS does not allow the *other* axis to stay `visible` when one axis
scrolls -- it is forced to a clipping/scrolling value. (`overflow-y:
clip` plus `overflow-clip-margin`, the obvious escape, computes straight
back to `hidden` here; measured in-browser, not assumed.) A cell's popup
therefore **cannot** leave that box, and the only real question is how to
make it fit inside. The two failed attempts:

- leaving the forced `auto`: popups keep their laid-out size at
  `opacity: 0`, so they inflated the scroll area and scrolling down led
  into a void (0.27.0);
- `hidden` + a tall `padding-bottom`: a popup hangs below *its own row's
  cell*, not below the table, so upper rows still clipped -- and 224px of
  permanently blank space read as broken on its own (0.27.1/0.27.2).

Now: the popup's height is bounded (`max-height: 9rem`, with the tool
list taking the leftover room and scrolling, so the identity/toolkit
title and call counts stay pinned), and rows near the bottom of the
table open their popup *upward* instead -- decided in `_access_matrix`,
which is the only place the row count is known. A table of three rows or
fewer has no rows above to open into either, so it alone also reserves
room at the top. Everything else keeps its column headers flush.

Verified in a browser against a 16-toolkit, 4-identity matrix
reproducing the reported layout: all 26 popups on the Overview and all
26 on the full-page map render with **zero** clipping, zero dead
vertical scroll, horizontal scrolling intact, on both the 4-row and the
filtered 2-row table -- with the reserved space down from 224px to 72px.

## 0.27.2

**Fix: the chart's hover tooltip rendered ~3x oversized, still hiding half its text off-screen.**

0.27.1 fixed the tooltip being clipped by moving it into one wide
`<foreignObject>` spanning the whole chart. That fixed the clipping but
not the real bug: content inside a `<foreignObject>` is painted through
the enclosing `<svg>`'s own viewBox-to-viewport scale -- this chart's
`viewBox="0 0 300 112"` rendered at up to ~1000 CSS px wide is roughly a
3x transform, and that transform applies to *everything* in the
foreignObject's subtree, including CSS `rem`/`px` sizes. A `.7rem`
tooltip came out looking like a `2rem` one, badly overlapping the bars
next to it.

Moved the tooltip out of the `<svg>` entirely: it's now a plain HTML
`<div>` positioned as a sibling of the chart, overlaid via `position:
absolute; inset: 0` on a wrapping `.chart-wrap` -- ordinary CSS box
layout, not subject to the SVG's internal coordinate transform at all.
Verified live: tooltip font now renders at the correct 11.2px (`.7rem`)
instead of the ~34px it was rendering at before.

Also: the access map's hover popups were getting clipped by last
release's `overflow-y: hidden` fix far more often than expected -- a
popup extends below *its own row's cell*, not below the table, so it
doesn't take a last-row cell to hit the bottom edge. `.am-tools` is
already capped at max-height 9rem, so a popup's tallest possible size is
bounded and known; reserved that much as `padding-bottom` on the
scroll container so `hidden` has room to never actually need to clip a
real popup. Also gave both scrollable areas (the access map and the new
recent-events card) a thin, themed scrollbar instead of the browser's
unstyled default.

## 0.27.1

**Fixes two real regressions from 0.27.0's own fixes.**

**The chart's new hover tooltip rendered visibly broken** -- clipped mid-
word, overlapping neighboring bars. 0.27.0 gave each hour its own
`<foreignObject>` exactly `slot_w` (~25 of 300 user units) wide to hold
the tooltip; a `<foreignObject>` clips its content to its own box, so
anything wider than that sliver -- which a "14:00 &ndash; 3 ok, 1
denied/failed" tooltip always was -- got cut off rather than overflowing
into view. Replaced with a single `<foreignObject>` spanning the whole
chart, divided into equal hourly zones with a plain flex row (no
per-zone positioning needed, let alone one that would've hit the same
`style=""` CSP wall as the hero bar did last release) -- a tooltip can
now overflow past its own zone into the shared box instead of being
clipped.

**The access map grew a wall of empty scrollable space below the
table.** 0.27.0's `.am-wrap { overflow-x: auto }` fix for the table
spilling out past its card had a side effect: per spec, a non-visible
overflow-x forces overflow-y away from "visible" too, defaulting it to
"auto". Every granted cell's hover popup is `position: absolute` and
still occupies its full laid-out size at `opacity: 0` (hidden, not
removed) -- with both axes now "auto", those normally-invisible popups
inflated the table's scrollable area, and scrolling down led into empty
space with nothing in it. Set `overflow-y: hidden` explicitly instead of
leaving it to that default; the trade-off is a popup hanging off the
very bottom row can get clipped instead of floating fully clear, far
rarer and far less confusing than the empty-space bug it replaces.

**Also:** the Activity/Recent-events split (new in 0.27.0) let the feed
grow to fit all 20 items before the grid measured row height, so an
uncapped feed became the tallest thing on the row and stretched the
chart's card to match -- a wall of empty space below the chart. The
feed's pad now caps at a fixed max-height close to the chart's own
typical rendered height and scrolls past that instead of growing past
it, keeping both cards close in height.

## 0.27.0

**Overview: fixes a CSP bug in the previous release, plus several real layout bugs on the Activity/Access map cards.**

**The hero's outcome bar was silently broken since 0.26.0.** It used
`<div style="width:N%">` for the ok/denied split; this console's CSP
(`style-src 'nonce-...'`, no `unsafe-inline`) does not cover per-element
`style=""` attributes -- only the one nonce'd `<style>` block -- so the
browser silently dropped the width and the bar never showed a
proportional split. Same landmine `_integration_logo`'s docstring already
warned about, hit for real this time. Rebuilt as an inline SVG (`<rect
width="N">`, a plain geometry attribute, not CSS) instead.

**Layout fixes, all pre-existing (not introduced by 0.24.0-0.26.0, just
made more visible by a taller chart and a live deployment with more
toolkits and history than the dev fixtures):**

- `.am-wrap` was `overflow: visible` despite the `::-webkit-scrollbar`
  rules right below it clearly intending a scrollable box -- a wide
  access map (many toolkits) spilled out past the card's edge instead of
  scrolling sideways. Now `overflow-x: auto`.
- `.filter-row` (the search box + button on the access map, overview, and
  tools pages) had no CSS rule at all -- input and button fell back to
  inline-flow baseline alignment, which is what actually made the search
  button look misaligned. Now a proper flex row.
- `.spacer` (pushes toolbar buttons to the right) was scoped to
  `.card-head .spacer` only, so it did nothing inside `.filter-row`'s
  Cards/Matrix toggle on the Tools page. Unscoped -- `flex: 1` is a no-op
  outside a flex box anyway, so this costs nothing where it already
  worked.
- The Activity card's chart+feed split had a broken `.card > .pad`
  selector two levels too deep to ever match, so the whole block had zero
  padding -- chart and feed sat flush against the card's edges, which is
  why the feed's scrollbar looked like it was bleeding past the border.
  Split Activity and Recent events into two separate cards (also just
  more consistent with the rest of the page), each getting real padding
  for free from the existing `.card > .pad` rule, and the feed now
  stretches to fill its card's full height instead of a fixed 200px.
- The access map's tool-list popup had no cap on height or width-safety
  for long destination-qualified tool ids (`docker.compose_up@nas-2`) --
  added `overflow-wrap` and a scrollable max-height so a long grant list
  or a long id can't push the popup off-screen.
- The chart's axis labels were sized for the chart's *old* height and
  read oversized once the chart got taller in 0.26.0 -- reduced from 9px
  to 7px.

**New: a real hover tooltip on the activity chart.** The `<title>` added
in 0.26.0 for hover counts relies on the browser's native (OS-styled,
often slow) tooltip, which most people never notice is there at all.
Replaced with a themed, instant CSS `:hover` tooltip matching the access
map's own popups -- positioned via `<foreignObject>` at plain SVG x/y/
width/height (not `style=""`, same CSP reason as the hero bar fix above).

## 0.26.0

**Overview: a real temperature gradient on the access map, and a taller, gradient-filled activity chart.**

The access map's heat coloring was shades of one hue (green, more or
less saturated) -- differentiating "busy" from "quiet" meant comparing
saturation, which doesn't read at a glance in a wide, dense matrix.
Granted-but-quiet pairs stay green; busy pairs now go amber (reusing
`--warn`); the busiest go a dedicated burnt orange (`--heat-hot`, new
token) rather than `--deny`'s crimson, so "this pair sees a lot of
traffic" never reads as "this pair is dangerous" -- `--deny` stays the
only color that means that.

The activity chart is about 30% taller and its bars now use a
top-lighter/bottom-richer gradient fill (`<linearGradient>`, stop-opacity
only -- still tracks `--ok`/`--deny` exactly in both themes, no separate
gradient palette to maintain) instead of a flat color, so a filled bar
reads as a filled column rather than a sticker. The current hour gets a
small accent-colored dot above its bar and a bolded axis label, so "now"
doesn't require reading all the way to the right-hand edge to find.

## 0.25.1

**Fix: the activity chart's gridlines were nearly invisible.**

`.c-grid` used `var(--line)` -- the same near-background-color token used
for card borders -- which in dark mode sits at #1e2a2e against a #101619
card, too low-contrast to read as a scale reference once bars covered
most of the height they'd otherwise be visible against. Switched to
`var(--muted)` with explicit opacity: the 0% baseline is solid at .6
opacity (a fixed reference even where no bar reaches it), the 50%/100%
lines are dashed at .4 opacity so a bar sitting at peak height doesn't
make the 100% line look like a stray solid stroke poking out beside it.

## 0.25.0

**Overview: a full visual redesign, not just clickable tiles.**

The flat 7-tile stat grid from 0.24.0 is replaced with a hero: a
server-rendered radial gauge (plain SVG `stroke-dasharray` arithmetic, no
JS or chart library — the CSP forbids scripts entirely) showing the
success rate at a glance, next to the call count, an ok/denied outcome
bar, and a legend. The gauge and call count link to `/ui/stats`, same as
the tiles they replace. The remaining posture counts (tools active,
identities, protected resources, tools disabled) move to a smaller
chip row underneath — still clickable, deliberately less visually loud
than the hero above it.

The activity chart's bars are now clipped to one rounded shape per bar
instead of two independently-rounded rects, so the ok/denied color seam
reads as a single pill rather than two lozenges pinched together; added
horizontal gridlines and a native `<title>` tooltip per bar (exact
counts on hover, no JS). The access map got more breathing room, zebra
striping on the identity/role/tools columns, and a subtle inset
highlight on granted cells.

Fixed in the same pass: `_dashboard_icon_url` had a bug where it always
guessed a dashboardicons.com URL from the raw toolkit name as a last
resort, even for toolkits with no icon there — producing a silently
broken `<img>` with no way to recover (the CSP forbids `onerror`
fallbacks along with every other script). It now returns `None` unless
there's a real slug or integration match, and the access map falls back
to a colored-monogram badge (reusing `integrations.py`'s existing
`monogram()`, now shared instead of duplicated) so an unmatched toolkit
gets a deliberate, varied look instead of a broken image or one flat
generic icon repeated for everything.

## 0.24.0

**Overview: stat tiles are now links, and pending requests surface on the front page.**

The stat tiles at the top of `/ui/` (Tools active, Identities, Protected
resources, Tools disabled, Calls, Success rate, Events) were static — the
`.stat-link` CSS class needed to make them clickable had existed in the
stylesheet but nothing ever used it. Each tile now links to the page that
explains its number (Tools, Identities, the Tier 1 reference, Stats,
Audit).

A pending Tier 1 change or toolkit proposal previously showed only as a
small badge on the "Requests" nav item — easy to miss if you weren't
looking at the sidebar. The Overview page now shows a banner with the
count and a direct link to `/ui/requests` when anything is awaiting
review, using the same counting logic the Requests page itself uses.

Also fixed in passing: the "Events" tile's icon name (`"list"`) didn't
match any defined icon and rendered blank; it now uses the same `"clock"`
icon as the Audit page it links to.

## 0.23.3

**Fix: a tool whose shape no longer fit its toolkit's executor could crash every future startup.**

`load_catalog` only caught its `Tier1Violation` exception subclass to
gracefully disable a stale tool definition; `_parse_tool` also raises the
plain `ConfigError` base class for a tool whose *shape* doesn't match its
toolkit's executor (e.g. a `binary`/`argv`-shaped tool with no
`file_operation`, after the toolkit's executor changed from `local` to
`file`). That case was uncaught -- it crashed catalog loading entirely,
which crashed every subsequent `gatekeeper serve` startup (`cmd_serve`
exits 2 on any `ConfigError`), not merely disabled the one tool. Combined
with `restart: unless-stopped`, a single stale tool definition left after a
`toolkit_update`/`toolkit_propose` executor change (or a redeploy that
changes one) could crash-loop the whole service until someone edited
`tools.yaml` on the host directly.

`load_catalog`'s per-entry `try` now catches `ConfigError` broadly (which
includes `Tier1Violation`) -- any tool definition that fails to parse
against the *current* Tier 1 is logged and disabled, exactly what FR-4.7
already promised for the narrower case. `strict=True` (CI) still aborts on
either exception, unchanged. What still raises unconditionally --
`tools.yaml` itself being structurally broken (a non-mapping entry, an
unresolvable `current_version`, a duplicate tool ID) -- is intentionally
unaffected: that is the file being corrupt, not one entry going stale.

## 0.23.2

**Security fix: `admin.toolkit_update` applied instantly from `/admin/mcp`, with no human review.**

v0.23.0 gave `ConfigStore` a narrowly-*field*-scoped (`executor`/`binaries`/
`denied_args` only) but not narrowly-*approval*-scoped write path to
`toolkits.yaml`: `admin.toolkit_update` called it directly and applied the
change immediately via `reload_config`, with no pending-approval step. This
contradicted the two-tier model's key invariant -- restated in `store.py`'s
own module docstring the whole time this was live, one function below the
contradiction -- that Tier 1 is never runtime-writable without a human in
the loop, and that nothing reachable from `/admin/mcp` can write
`toolkits.yaml` on its own (`docs/ARCHITECTURE.md`). In practice, an
admin-role MCP token could flip a toolkit's executor (e.g. `local` ->
`ssh`) live, unreviewed, the moment it called the tool.

Found while investigating an unrelated read-only-mount failure report: the
only thing that had stopped an instant, unreviewed executor change on a
report from the field was the operator's own `:ro` config mount -- an
accident of that deployment, not a control the software enforced.

Fixed: `admin.toolkit_update` now proposes into the same
`toolkit_proposals.yaml` queue `admin.toolkit_propose` already used
(`ToolkitProposalStore` gains a `kind` field, `"create"` or `"update"`),
reviewed and approved only by a human at `/ui/requests` (Toolkit tab),
exactly like a new-toolkit proposal. `ConfigStore.save_toolkit` (the
function that made this possible) is removed entirely -- `store.py`'s
guarantee that it has no function writing `toolkits.yaml` is true again,
not just asserted.

## 0.23.1

**Fix: `file.write`/`file.patch` rejected any multi-line content.**

`validate.py`'s control-character check (FR-6.3) ran on every string
parameter before its pattern was consulted, rejecting `\n`/`\t` unconditionally
— including `file.write`'s `content` and `file.patch`'s `old_string`/
`new_string`. Since `config/examples/file-tools.yaml` deliberately uses a
permissive `[\s\S]*` pattern to allow arbitrary file content, this meant
writing or patching any real (multi-line) file was silently impossible, with
no test exercising the path (existing tests called `execute_file.run`
directly, bypassing `validate.py` entirely).

Fixed with a per-parameter opt-out: `Parameter.allow_control_characters`
(`catalog.py`, set via `allow_control_characters: true` in a tool's YAML).
Off by default everywhere — FR-6.3 still applies to every other parameter
unchanged. Only `file.write`/`file.patch`'s content-bearing parameters opt
out, because their values are written to disk verbatim and never interpreted
as argv/URL/RPC structure, unlike every other parameter FR-6.3 protects.

## 0.23.0

**`admin.toolkit_update` + `file` executor registration fix.**

Two fixes:

1. **`file` executor was never registered in `KNOWN_EXECUTORS`.** The
   v0.22.0 `file` executor would have been rejected by `load_tier1` at
   startup with "executor 'file' is not enabled at this stage". Fixed.

2. **New `admin.toolkit_update` tool** — lets the admin change a
   toolkit's `executor`, `binaries`, and `denied_args` at runtime via
   `/admin/mcp`, without a manual file edit + redeploy. Security-critical
   fields (`path_roots`, `protected_resources`, `limits`) remain
   deploy-time only (FR-4.11) and are rejected. Applies immediately via
   `reload_config`.

6 new tests in `tests/test_toolkit_update.py` covering the rejection
contract and the full executor-switch + reload path.

---

## 0.22.0

**Built-in `file` executor: read/write/patch/list without shell.**

New executor type `file` that performs file operations directly in
Python — no shell, no process spawn, no argv chaining (FR-4 safe).

- `file.read` — read a file (bounded by `max_output_bytes`)
- `file.write` — write content, creates parent directories
- `file.patch` — replace a unique `old_string` with `new_string`
- `file.list` — list directory entries (files/dirs prefixed)

Path validation: `path_roots` enforced via `realpath` (no `..`
escape, no symlink breakout), `protected_resources` reject any
path touching `gatekeeper`/`dockhand`/`ix-dockhand`/`traefik`.

12 new tests in `tests/test_file_executor.py`.

---

## 0.21.0

**HTTP executor: nested JSON body templates.**

The `body` field in a tool spec now supports nested dicts, lists, and
scalar values — not just flat string→string maps. APIs like Tdarr that
expect `{"data":{"collection":"…","mode":"…"}}` can now be expressed.

- Leaf strings are `{param}` templates (same substitution as before).
- Non-string leaves (numbers, bools, null) pass through as static JSON.
- Flat body templates (existing tools) continue to work unchanged.
- 10 new tests in `tests/test_nested_body.py`.

---

## 0.20.9

**Test layers: ruff lint guard + serverInfo.version regression test.**

- `tests/test_lint.py`: runs `ruff check src/` inside pytest so
  import-ordering and style failures surface locally (not only in CI).
- `tests/test_version.py`: regression test that `build_mcp_server`
  uses `__version__`, not a hardcoded `"0.1.0"`.

---

## 0.20.8

**Fix: `serverInfo.version` reports actual version instead of hardcoded `0.1.0`.**

The MCP `initialize` response reported `version: "0.1.0"` regardless of
the installed release. Now uses `gatekeeper.__version__`.

---

## 0.20.7

**Fix: `grant_set` accepts bare tool IDs for multi-destination toolkits.**

`save_identity`/`create_identity` rejected `sabnzbd.request` as
"Unknown tool IDs" because the catalog only contains the
destination-expanded IDs (`sabnzbd.request@sabnzbd-movie`,
`sabnzbd.request@sabnzbd-serie`). Now bare IDs are validated against
the un-expanded form AND expanded to the actual catalog IDs before
saving — so `may_call()` succeeds at call time.

Also: call stats moved to top tile row (7 tiles), Activity card is
chart+feed only (70/30 split). Hover highlights and links on matrix
columns, identity rows, and tool IDs in popups.

---

## 0.20.5

**`admin.tool_get`/`admin.tool_list` now report `grantable_ids` — the actual, possibly destination-qualified id(s) `admin.grant_set` accepts.**

- A multi-destination toolkit's tools live in the catalog only as
  `<id>@<destination>` (FR-8.3h); the bare id an agent sees via
  `admin.tool_get` was never itself grantable, only its raw source
  definition. A grant submitted for the bare id was silently rejected as
  "Unknown tool IDs" on approval, with nothing in the read path pointing at
  why. Both responses now include `grantable_ids`, the exact id(s) to pass
  to `admin.grant_set`.

---

## 0.20.4

**Activity card: chart and feed side-by-side (80/20 split).**

Recent events now sit to the right of the call chart instead of below
it, cutting the Activity card's height significantly. Feed max 200px
with its own scrollbar.

---

## 0.20.3

**Overview layout: Activity above, Access map full-width below.**

The split-column layout (access map left, activity sidebar right) is
gone. Activity is now a full-width card on top with call tiles, chart,
and a scrollable event feed (max 280px). Access map sits below it at
full width — the matrix fits without horizontal scroll on most screens.

---

## 0.20.2

**Access matrix: hover popup replaces inline `<details>` expand.**

Cells no longer resize the row when expanded — hovering a grant cell
shows a floating popup above it with the identity→toolkit title, call
stats, and tool list. Pure CSS `:hover`, no JavaScript.

---

## 0.20.1

**Access matrix: integration logos from dashboardicons.com.**

Toolkit column headers now show the actual service logo (Jellyfin,
Sonarr, Radarr, etc.) loaded from the homarr-labs/dashboard-icons CDN
on jsDelivr — the same source the inline `_BRAND_LOGOS` were drawn
from, but now covering all 9000+ icons without hardcoding each one.

- CSP `img-src` widened to allow `https://cdn.jsdelivr.net`.
- `_dashboard_icon_url()` maps toolkit names to CDN SVG slugs, with
  a manual override table for names that don't match directly
  (hass→home-assistant, paperless→paperless-ngx, zfs→truenas, etc.).
- Logos render as `<img loading="lazy">` above the toolkit name.

---

## 0.20.0

**Access map redesigned: matrix grid replaces the Cytoscape.js graph.**

The Cytoscape.js graph (and before it the vanilla JS SVG graph) had a
spaghetti problem — with real-world identity and toolkit counts, edges
crossed so heavily the map was unreadable. The replacement is a
server-rendered HTML grid:

- **Identities as rows, toolkits as columns.** Each cell shows the
  number of granted tools (green, heat-mapped by call volume) or a
  dash (not granted). No edges, no crossing lines, no pan/zoom.
- **Expandable detail:** click a cell (native `<details>`) to see the
  concrete tool IDs and call stats for that identity×toolkit pair.
- **No JavaScript.** The entire map is server-rendered HTML + CSS.
  Removed: `_ACCESS_MAP_JS` (631 lines), `_vendor_cytoscape.py`,
  `CYTOSCAPE_JS_PATH`, `ACCESS_MAP_JS_PATH`, the JSON data endpoint,
  the JS routes, and the `script-src`/`connect-src` CSP exceptions.
- **Search** via `?q=` filters both identities and toolkits.
- 547 tests pass.

---

## 0.19.0

**Console shell: the sidebar and topbar title now stay fixed to the viewport instead of scrolling with the page; Overview's Access map and Activity cards match height.**

- **The content column, not the whole document, now owns the scrollbar.**
  `.app`/`.col` are pinned to `100vh` with `.col` scrolling internally, so
  the sidebar (`.side`) stretches to exactly the viewport height and never
  grows a scrollbar of its own, however long the page below it gets. The
  `<900px` mobile layout (sidebar collapses to a horizontal top bar) keeps
  its previous whole-page scroll, unaffected.
- **The topbar's subtitle now collapses once the page scrolls.** A small
  scroll listener toggles `.topbar.is-scrolled`, fading out the `<p>`
  subtitle so the sticky title bar takes less vertical space while
  reading; it reappears back at the top.
- **Overview's Access map and Activity cards render at equal height.**
  `.split` now stretches its two columns instead of sizing each to its
  own content, and the embedded map (`map-root-split`) grows to fill the
  remaining height rather than asserting its own `52vh`. `/ui/access-map`'s
  full-page map is unaffected.

## 0.18.1

**`admin.toolkit_list` reports a toolkit's target and credential name. The embedded access map's filter box and lane layout are fixed.**

- **`admin.toolkit_list` was missing the two fields that actually matter
  for diagnosing a toolkit.** It reported `executor`, limits, and
  `destinations` (the optional multi-host fan-out field) but never a
  toolkit's own `base_url`/`docker_host`/`ws_url` or which `credential` it
  references. That gap caused a real misdiagnosis: an agent debugging a
  401 read the missing field as "not configured" and proposed adding
  `destinations:` -- the base URL had been correctly wired the entire
  time, just never reported. Fixed by adding `target` (via the same
  `_target()` resolution the console's Tools page and access map already
  use, so this agrees with what a human sees) and `credential` (the name
  only -- the credential store stays write-only, FR-10.2, this doesn't
  change that).
- **The embedded Overview map card's filter box was cramming a text
  input, submit button, title, and "Open full page" link into one row
  narrower than the dedicated full page ever needs to be -- the
  placeholder text was visibly cut off.** The filter form now gets its
  own row, same structure the dedicated `/ui/access-map` page already
  used.
- **The map's lanes now rotate to match whatever container they're
  actually in**, instead of always laying out as columns. A short, wide
  container (the embedded card sits in half the dashboard's width) is a
  poor fit for tall stacked columns -- a short lane got stretched to
  match the busiest one's height, leaving huge gaps. Lanes are now
  columns when the container is taller than wide, rows (identities on
  top, toolkits below, spread left-to-right) when it's wider than tall --
  decided from the container's own measured shape at render time, not a
  per-route flag, so it also re-evaluates correctly on a browser resize.
  Each lane is now sized to its own item count rather than a shared
  per-lane maximum, which was the actual cause of the sparse look in
  either orientation.

## 0.18.0

**`admin.cred_propose`: an agent can name a new credential slot, but never touch its value.**

REQUIREMENTS.md §17 had an open question since the credential store's first
draft: "Do the first API keys come in via `admin.cred_set` after startup, or
via a one-time mounted file that is then removed?" Neither. There is still
no `admin.cred_set` (a single call that would carry a value over
`/admin/mcp`), and there never will be one that takes a value.

- **What an agent can do:** propose a credential's `name`, `kind`, and (for
  `api_key_header`/`url_query`) its `header`/param name. That's it — the
  tool has no `value` property, and `admin_service.py`'s `cred_propose`
  explicitly refuses one if sent anyway (the MCP SDK does not itself
  enforce `additionalProperties: false` against an unlisted argument, so
  this refusal is the actual enforcement point, not the schema alone).
  Every proposal lands in the same `pending.yaml` queue as a `grant_set` or
  `tool_delete` — visible at `/ui/requests` (Change tab) — but is excluded
  from "Approve all", since approving it needs a value typed in
  individually.
- **What a human does:** review the proposed name/kind/header at
  `/ui/requests` and, if it's right, click through to
  `/ui/pending/credential-fill` — a form that shows those three fields
  read-only (not editable, so a reviewer sees exactly what was proposed
  instead of silently retyping it) plus one password field. Submitting it
  calls `CredentialStore.create()` directly with the locked kind/header and
  the typed value, in the same request that marks the proposal approved.
  The value never exists in `pending.yaml`, at any point in the flow.
- **Deliberately not routed through `apply_pending`/`_APPLIERS`** — those
  assume a proposal's payload alone is enough to fully apply a change, with
  no way to collect additional input at approval time. Filling in the
  secret value *is* the approval here, so it gets its own route, the same
  way `admin.toolkit_propose` already stays off the generic path because
  Tier 1 has different rules than Tier 2.
- **Why the split, not one atomic `cred_set`-style call:** a name/kind/header
  an agent chooses on its own is metadata a human should consciously
  confirm before typing a secret against it — the wrong `kind` (e.g.
  `url_query` instead of `api_key_header`) changes whether the value ends
  up in a header or in a target service's own URL/access logs (FR-8.14).

## 0.17.0

**Overview drops its static reference cards; the Tools page gains a Cards/Matrix toggle.**

Call flow, Executors, and Tier 1 sat on Overview looking the same on every
visit, competing with the map and activity feed for attention -- the things
that actually change. Tier 1 already had a dedicated page
(`/ui/toolkits/reference`), so it was pure duplication there.

- **Call flow, Executors, and Tier 1 cards removed from Overview.** The
  8-layer pipeline diagram, the executor reachability panel (and its
  `/ui/probe-executors` endpoint), and the collapsed Tier 1 boundaries
  block are gone. `service.probe_executors()`/`executor_ready` are
  unaffected -- `/health/ready` and the Prometheus gauge still use them.
- **Tool matrix moves to `/ui/tools`.** Rather than delete it outright, the
  dense per-tool table is now a view on the Tools page: a Cards/Matrix
  toggle (`?view=cards|matrix`) switches between the existing per-toolkit
  cards and the table, the same pattern the access map already uses for
  its graph/table switch.

## 0.16.2

**The audit log now records which credential a call used, and masks
secret-shaped field names in every spelling.**

The credential store itself is unchanged -- it already encrypted at rest,
injected per kind, and never returned a value. What was missing sat on
either side of it: the log could not say *which* key a call had used, and
its field-name masking matched too narrowly to be relied on.

- **`"credentials"` in a call record is no longer always empty.**
  `audit.call()` has accepted a `credential_names` argument since the store
  landed, but `service.py` never passed one -- so the field every call
  record carried was `[]`, whatever the call actually did. It is now filled
  from the resolved toolkit, which means a destination's credential
  override is already applied and the audited name is the one the executor
  really resolves. Denials record it too: a rejected call against a service
  was previously invisible when answering "what touched this key?" after a
  leak. Names only, never values (FR-10.7).
- **Field-name masking matched exact names, and now matches normalized
  substrings.** `_NEVER_LOG` held `api_key` -- so a tool parameter named
  `apikey`, `x-api-key`, `access_token` or `client_secret` went to disk in
  cleartext. Keys are now lowercased with `-`, `_`, `.` and spaces stripped
  before being tested against the token set, which collapses every spelling
  onto one. The `Redactor` was never a backstop for this: it only knows
  values gatekeeper stores itself, not a foreign token an agent passed in
  as an argument. Deliberately generous, with one explicit exemption list
  for keys that *describe* a secret rather than carry one -- masking
  `credentials` or `credential_kind` would have deleted exactly the
  metadata the previous point adds.
- **Jellyseerr starter integration** (21 services now): port 5055,
  `X-Api-Key`, three read-only tools. Its monogram is deliberately not
  Jellystat's -- the two sit next to each other in the gallery, differ by
  three letters, and shared the same "Js" badge.
- **Docs.** A "Credentials: from zero to a working call" runbook in
  `docs/DEPLOYMENT.md` (master key, the Tier 1 `credential:` line, the
  console entry, enabling tools) -- the three-part setup was documented
  only in pieces, which is the usual reason a freshly deployed toolkit
  keeps answering 401. The README's Credentials section gains the
  kind-to-request table, `compose.yaml` documents
  `GATEKEEPER_CREDENTIAL_KEY`, and "What's not here (yet)" no longer
  claims the `ssh` executor is missing -- it shipped in 0.8.0.

## 0.16.1

**The access map's pan/zoom/click/drag now run on Cytoscape.js instead of ~700 lines of hand-rolled code.**

That hand-rolled pointer/touch state machine had already shipped one
silent bug (v0.13.2: `setPointerCapture` on every `pointerdown` broke
every click and zoom button) -- exactly the kind of code, multi-pointer,
device-dependent, unverifiable without a real browser, where the next one
hides. Rather than harden it further, pan/zoom/click/drag/touch now come
from Cytoscape's own well-exercised core.

- **One new dependency, vendored, not fetched.** `cytoscape.min.js`
  3.34.1 (MIT), pinned by version and SHA-256 in the new
  `_vendor_cytoscape.py`, served from this origin only under the same
  session gate and CSP `script-src` scoping as before (Overview and
  `/ui/access-map`, and only those two routes -- `test_vendor_cytoscape.py`
  re-hashes the bundle on every run, and a widened CSP scoping test
  confirms every other route stays exactly as script-free as it was).
  It is the one file in this project nobody has read line by line; the
  module docstring says so plainly and records what was checked instead
  (byte-identical across two independent CDNs at vendoring time).
- **Everything else about the map is unchanged.** The JSON contract
  (`_access_graph_data`), the lane-column layout, the executor/role
  clustering, the detail side panel, live search, and the light/dark
  palette all work exactly as before -- Cytoscape replaces only the
  rendering and interaction layer that kept breaking, fed the same data
  through a `preset` layout instead of hand-built SVG coordinates.
- **A real, independently-reproduced bug found and fixed during this
  migration**: Cytoscape colours nodes via a JS stylesheet, not CSS, so
  the map's per-identity "soft" tint (a colour at low alpha, e.g.
  `rgba(96,165,250,.16)`) needed its alpha pulled apart from its colour --
  gotten wrong on the first pass, it rendered as a solid, saturated fill
  instead of a tint. Fixed by parsing the alpha out of the existing
  `--cat-N-soft` custom properties at run time rather than hardcoding a
  number that could drift from the CSS.
- Cytoscape self-injects one `<style>` element on init
  (`.__________cytoscape_container { position: relative; }`); the CSP
  allows exactly that rule by SHA-256 hash, not `'unsafe-inline'`, and
  only on the two routes that load the library at all.

## 0.16.0

**Approve-all for the Requests page's Change tab.**

One click clears the entire pending Tier 2 queue — tool enables/updates,
deletes, grant sets, role sets. An "Approve all (N)" link appears above
the list when ≥2 proposals are pending and the session has write access.

- The confirm page lists every proposal with resolved detail (same
  `_pending_payload_summary` as the individual cards) and carries the
  ids as hidden fields. The POST applies *only those ids* — a proposal
  filed in the window between render and click stays pending.
- Each item is applied individually via `apply_pending` in oldest-first
  order (queue drains as it filled). A refusal (e.g. a stale proposal)
  does not stop the rest — the response names what was applied and what
  was refused.
- 6 new tests in `tests/test_ui_admin.py`.

---

## 0.15.2

**Stats page — aggregate call statistics in the console.**

A new "Stats" tab in the sidebar (`/ui/stats`) shows aggregate numbers
over the audit log: total calls, success rate, active identities and
toolkits, admin actions, latency (avg/p95 per toolkit), and error rate.
Three window selectors (24h / 7d / 30d) switch between hourly and
day-bucketed activity charts. Best-effort over the audit log tail.

- New aggregation helpers: `_bucket_calls_by_day`, `_admin_action_stats`,
  `_duration_stats`, `_outcome_totals`.
- Overview page shows two highlight tiles (calls + success rate, last 12h)
  and a "View full stats →" link.
- 17 new tests in `tests/test_ui_stats.py`.

---

## 0.15.1

**Fixed: approving one pending proposal no longer marks unrelated pending proposals "stale." Toolkit tab decluttered.**

- **Per-record staleness, not whole-file.** `PendingStore.approve` used to
  compare a proposal's `base_rev` against a hash of the *entire*
  `tools.yaml`/`identities.yaml` file. Since every write rewrites the whole
  document, approving one proposal (e.g. granting tools to one agent
  identity) changed that hash and falsely marked every *other* still-pending
  proposal against the same file "stale" -- even one targeting a completely
  different identity or tool. This is a normal pattern, not an edge case:
  Hermes batch-proposing several `grant_set`/`role_set`/`tool_update`/
  `tool_delete` calls in one session (e.g. onboarding a batch of identities)
  is exactly the trigger. `ConfigStore` gained `tool_revision(id)`/
  `identity_revision(id)`, a fingerprint of just the one record a proposal
  targets; `admin_service.py` now proposes and re-checks against that
  instead of the whole-file hash. The mutators' own whole-file `_check()`
  at the moment of writing is unchanged -- it's still the real atomic-write
  safety net for a genuine same-instant race.
  *Compatibility:* any proposal already queued from before this upgrade
  will show `stale` the first time it's approved (its stored fingerprint
  predates this change) -- just re-propose it; nothing is at risk.
- **The Toolkit tab of `/ui/requests` no longer repeats the live toolkit
  list.** That information already lives on the Tools page, grouped by
  toolkit. The tab now shows only proposals + archive, the same shape as
  the Change tab.

## 0.15.0

**Findings from a full security review: an unauthenticated DoS on the auth path, three HTTP-executor edge cases, reverse-proxy correctness, and tooling/supply-chain hygiene.**

- **`/mcp` no longer costs O(identity count) scrypt calls per request.**
  `IdentityStore.authenticate` ran scrypt against *every* identity's token
  hash on every call, deliberately without short-circuiting, to avoid
  revealing which one matched -- so a handful of concurrent requests with
  garbage bearer tokens could stall the whole event loop for seconds. Each
  identity now also carries a `token_lookup` (plain SHA-256 of its token --
  safe without a pepper, since a `generate_token()` output has 256 bits of
  entropy and brute-forcing it back is exactly as infeasible from a fast
  hash as a slow one): one O(1) dict lookup narrows a request to its
  candidate identity, then a single scrypt verification confirms it. An
  identities.yaml written before this field existed keeps working exactly
  as before, just without the speedup, until its token is next rotated.
- **Three HTTP-executor edge cases closed.** A resolved path containing
  `?`/`#` no longer escapes as an unaudited 500 (`httpx.InvalidURL` is now
  a `Denied`, routed through the same audit/outcome bookkeeping as every
  other rejection); a percent-encoded `%2e%2e%2f` traversal is rejected
  alongside a literal `..`; `allowed_path_prefixes` now matches at a
  segment boundary (`/api/v3/series` no longer also matches
  `/api/v3/seriesXYZ`), mirroring the `commonpath` fix `validate.py`
  already applies on the filesystem side.
- **A `{credential}` placeholder in a toolkit's `base_url` now requires a
  `url_path`-kind credential.** A toolkit misconfigured to reference a
  `bearer`/`api_key_header`/etc. credential there would have silently
  placed that value in the URL path -- landing in the target's own access
  logs, exactly what FR-8.14's header-first policy exists to prevent.
- **`--trusted-proxies` / `GATEKEEPER_TRUSTED_PROXIES`** configures
  uvicorn's own proxy-header handling for a reverse proxy in front of
  gatekeeper. Left unset (the previous, only behavior), a proxy in its own
  container is not `127.0.0.1` to gatekeeper, so `X-Forwarded-For` is
  silently ignored: the console's login throttle locks out every visitor
  at once instead of the one actually failing to sign in, the audit log
  records the proxy's address for every UI action instead of the real
  actor, and the session cookie's `Secure` flag never activates behind TLS
  termination. See docs/DEPLOYMENT.md's new "Behind a reverse proxy"
  section.
- **Credential rotation overlap windows no longer drift across a DST
  transition.** The expiry check compared local-time ISO strings
  lexicographically; both sides now use a fixed UTC offset, matching the
  idiom `catalog.py` already used elsewhere.
- **CI now runs `ruff` (blocking, scoped to `src/`), `mypy` (informational
  -- the first run surfaced ~30 pre-existing findings, mostly the MCP
  SDK's pydantic camelCase aliases, tracked as a follow-up rather than
  fixed blind), and `pip-audit` (blocking).** `constraints.txt` pins
  gatekeeper's direct runtime dependencies to the exact versions this
  release is tested against, in both CI and the Docker build, so two
  builds of the same commit resolve the same dependency tree.

## 0.14.0

**A new `admin.role_set` proposal, and Pending + Toolkits merged into one "Requests" menu with Change/Toolkit tabs, an archive, and pending-count badges.**

- **`admin.role_set`** lets an admin-role agent (Hermes) propose changing an
  identity's role, mirroring `admin.grant_set`'s shape exactly: always goes
  to the pending queue, `identities.yaml`'s revision is checked at approval
  (stale on a concurrent write, same as every other identity mutation).
  Promoting a passwordless identity straight to `viewer`/`admin` is refused
  at propose time -- `save_identity` would refuse it anyway (no password to
  sign in with), and this call has no password field of its own on purpose
  (a token must never double as a console password). A human sets the
  password directly in the identity editor first, then this proposal can
  go through.
- **`/ui/pending` and `/ui/toolkits` are now one page, `/ui/requests`**, with
  a Change tab (tool/grant/role proposals) and a Toolkit tab (Tier 1
  proposals) sharing the same layout: a compact, expandable row per
  proposal instead of an always-open card, so scanning the queue no longer
  means scrolling past every payload detail.
- **Resolved proposals no longer sit in the live list forever.** Approved,
  rejected, and stale items (deployed/rejected for toolkits) move into a
  collapsed "Archive" section per tab, reachable but out of the way.
- **A `stale` proposal now explains itself in place** -- "the configuration
  this referred to changed after it was proposed, ask Hermes to re-propose
  from the current state" -- instead of only ever surfacing as a raw
  exception to whoever clicked Approve.
- **Pending-count badges**: the tab switcher shows each tab's own pending
  count, and the sidebar's "Requests" nav entry shows the combined total,
  so it's visible without opening the page at all.

## 0.13.2

**Fix: clicking a map node, or the +/-/Fit buttons, did nothing. Protected resources removed from the map.**

- **Root cause of the dead clicks**: `wireZoomPan` called
  `root.setPointerCapture()` on every `pointerdown`, including ones that
  landed on a node or a control button. Capturing the pointer retargets
  the browser's subsequent `click` synthesis to the capturing element
  (`root`) instead of whatever was actually under the cursor, so no
  listener on a node or button ever saw the click. Fixed by dropping
  pointer capture entirely -- drag/pinch now track via `window`-level
  `pointermove`/`pointerup` while a gesture is active instead, which gets
  the same panning behavior without hijacking click delivery. A
  `pointerdown` that starts on the `.map-controls` bar no longer begins a
  pan gesture at all, so a button's own click is never at risk from it.
- **Protected resources dropped from the map.** They added nothing an
  identity can reach or a call can hit -- the Overview page's own
  "Protected resources" stat and each toolkit's card already cover them.
  `_access_graph_data` no longer emits `kind: "protected"` nodes or
  `meta.protected_count`; the map's third column is destinations only when
  present, two columns otherwise (labels simplified from "TOOLKITS AND
  BLOCKED"/"DESTINATIONS AND BLOCKED" to just "TOOLKITS"/"DESTINATIONS").

## 0.13.1

**Access map: a toolkit's connection target, and per-tool scopes on the identity panel.**

Two things the map's detail panel never showed, on any version: where a
toolkit actually connects to, and which scope a specific granted tool
needs (as opposed to the identity's scopes as a flat, undifferentiated
list).

- **Toolkit nodes now carry a `target`** (`docker_host`/`base_url`/`ws_url`
  — whichever the toolkit sets), reusing the same `_target()` helper
  already computing this for multi-destination nodes. The detail panel's
  existing generic `Target` row picks it up automatically — no JS change
  needed for this half.
- **An identity's granted-tool pills now show that tool's own
  `required_scopes` inline** (`tool.id · scope:pattern`), not just the
  identity's scopes as a separate list. Toolkit/destination nodes' tool
  pills are unaffected -- scopes only apply to what an identity actually
  holds.

## 0.13.0

**Hermes can now propose a brand-new Tier 1 toolkit through `/admin/mcp`; a human's one click validates, writes `toolkits.yaml`, and reloads it live — no redeploy, no restart.**

Hermes kept hitting the Tier 1 wall correctly (`Unknown toolkit` on `zfs`/
`file`) and had been drafting hand-checked toolkit YAML for a human to
paste into `toolkits.yaml` and redeploy manually. That copy-paste is now a
review-and-click, without weakening the guarantee that makes the admin
token not equivalent to root (REQUIREMENTS.md §6): Tier 1 still never
changes without a human decision.

- **`admin.toolkit_list` / `admin.toolkit_propose`** — two new `admin.*`
  actions. `toolkit_list` reads the live Tier 1 configuration (read-only);
  `toolkit_propose` drafts a brand-new toolkit, but — unlike every other
  action on this surface — has no low-risk variant at all: it always lands
  in a proposal queue, never applies, not even for a toolkit that looks
  entirely read-only.
- **A categorically separate review surface.** Proposals live in their own
  `toolkit_proposals.yaml`/`ToolkitProposalStore`
  (`src/gatekeeper/toolkit_proposals.py`), never `pending.yaml` — a toolkit
  changes what is *possible at all* (Tier 1), not just who can do what
  (Tier 2), so it is deliberately unreachable through the same approval
  path as an ordinary tool/grant change. Reviewed at the new `/ui/toolkits`
  page, with a visibly heavier confirmation than `/ui/pending`'s.
  `toolkit_deploy`/`toolkit_reject` are not part of the `admin.*` tool list
  and have no code path from `/admin/mcp` — the same structural
  self-approval prevention `pending.py` already established, extended here.
- **No restart.** "Approve & Deploy" merges the proposed toolkit into the
  live `toolkits.yaml` content, validates the result with the exact
  `load_tier1()` startup uses (rejecting a name collision or any Tier-1
  violation before touching anything real), atomically writes the file,
  then calls `Service.reload_config` in-process — the same function the
  existing SIGHUP handler already used, now with real test coverage for
  both its success and failure paths (previously untested).

## 0.12.0

**The interactive access map is now the default; the old fixed-size SVG map is gone. Real pan/zoom.**

`0.10.0` shipped a JS-driven access map, but only as a side door
(`/ui/access-map`) — the dashboard still showed the original static SVG by
default, and even the interactive version had no real zoom: its `viewBox`
was sized to exactly fit its own content, so nothing was actually
scale-adjustable.

- **Overview embeds the live map directly** — no more click-through. The
  dashboard's "Access map" card now mounts the same JS renderer as the
  dedicated page; `/ui/access-map` remains as a larger, separate view (more
  room to zoom) linked from the card.
- **`_access_graph`/`_svg_node` deleted.** The server no longer renders the
  map as SVG at all — only JSON (`_access_graph_data`, unchanged) for the
  client to draw. With scripts disabled, a plain notice ("Enable
  JavaScript to view the access map") replaces the old `<noscript>` SVG
  fallback.
- **Real pan/zoom**, entirely hand-written vanilla JS, no library: node/edge
  layout now renders into a `<g class="g-content">` inside a
  transform-driven `<g class="g-viewport">`, decoupled from a fixed-height
  `.map-root` container. Mouse wheel zooms to the cursor, drag pans,
  two-finger touch pinch-zooms, and `+`/`−`/Fit buttons give explicit
  control — all via the SVG's own `getScreenCTM()`, not naive pixel deltas,
  so the math stays correct regardless of how CSS scales the rendered
  `<svg>`. A `userAdjusted` flag means the user's own pan/zoom survives
  re-renders triggered by live search or cluster expand/collapse instead of
  snapping back to fit-to-content every time.
- **CSP stays narrowly scoped** — the `script-src`/`connect-src 'self'`
  exception now applies to both routes that render the map (Overview and
  `/ui/access-map`), and to no others; a widened
  `test_access_map_scopes_script_src_to_itself` asserts this explicitly.

## 0.11.0

**TrueNAS starter integration gains dataset and snapshot tools: list datasets, list snapshots, delete a snapshot.**

Researched against TrueNAS's real JSON-RPC API (api.truenas.com), not
guessed:

- `truenas.list_datasets` — `pool.dataset.query`, no arguments.
- `truenas.list_snapshots` — `zfs.snapshot.query`, no arguments.
- `truenas.delete_snapshot` — `zfs.snapshot.delete`, one positional `id`
  argument (`dataset@name`) validated by pattern; category
  `write_external` since destroying a snapshot is irreversible for the
  data it captured. `required_scopes: ["dataset:{id}"]`, same
  per-dataset scoping convention as the existing `truenas.create_dataset`
  reference example.

`zfs.snapshot.create` is deliberately **not** included: its real signature
takes one nested object argument (`{dataset, name, recursive}`), and this
project's `params_template` mechanism (`validate.py`'s `build_rpc_call`)
only substitutes flat string values into a positional list — it cannot
build a nested object today. Documented as a known gap in
`docs/ROADMAP.md` rather than worked around with an inaccurate call
shape. Dataset/pool creation and deletion remain out of the starter set
too, on purpose — much larger blast radius than a snapshot.

The `truenas` toolkit's `allowed_rpc_methods` whitelist (both the starter
default in `integrations.py` and the fuller worked example in
`config/examples/toolkits.yaml`) is extended to include
`zfs.snapshot.query` and `zfs.snapshot.delete`.

## 0.10.0

**Interactive access map, replacing the fixed server-drawn graph on the overview page. New `/ui/access-map`.**

The overview page's access map (identity → toolkit → destination) was already
computed live from `identities.yaml`/`toolkits.yaml`/the catalog/the audit
log, but rendered as one hand-laid-out SVG whose canvas grew linearly with
node count -- unreadable well before real-world scale, no icons or service
logos, and no way to click through to detail.

- **New `/ui/access-map` page** with a client-side renderer
  (`access-map.js`, vendored, no dependencies, no build step) fetching JSON
  from a new `/ui/access-map/data` endpoint. The overview page's original
  map is unchanged for now -- it gained a link to the new page rather than
  being replaced, so the page every session hits by default carries zero
  risk from this change.
- **Scales past a fixed canvas.** Toolkits group by executor and identities
  by role once past a threshold (8 / 20), collapsing into cluster nodes
  clicked open one lane at a time instead of rendering hundreds of nodes at
  once. Past 80 combined nodes the page defaults to a dense identity ×
  toolkit table (`?view=table`) instead of the graph.
- **Click a node for detail** -- a slide-in panel with call stats
  (ok/denied/failed), granted tools, executor/role, and destinations,
  without leaving the page. Search narrows and dims live as you type,
  no page reload.
- **The one narrowly-scoped exception to the console's script-free CSP.**
  Every other route keeps exactly the `default-src 'none'`, no-`script-src`
  policy as before (asserted by a new test,
  `test_access_map_scopes_script_src_to_itself`); `/ui/access-map` alone
  gets a nonce-scoped `script-src` (plus the `connect-src 'self'` its own
  same-origin `fetch()` needs), generated fresh per response and never
  widened to `'self'` or `'unsafe-inline'`. With scripts disabled, the page
  falls back to the original server-rendered SVG via `<noscript>`.
- The JS never uses `innerHTML` on server-derived data -- every label, tool
  ID, and identity name is set through `textContent`/`createElement`, so
  nothing rendered client-side can execute even if it originated from an
  agent's unvalidated audit-log data.

---

## 0.9.1

**Docs page — full project documentation in the console.**

A new "Docs" tab in the sidebar renders the complete README,
REQUIREMENTS.md, AGENTS.md, and RELEASE.md directly in the UI —
no JavaScript, no external dependency, CSP-safe.

- A minimal Markdown-to-HTML converter (`_md_to_html`) handles
  headings, paragraphs, lists, fenced code blocks, tables,
  blockquotes, inline code, bold/italic, links, and horizontal rules.
  All input is HTML-escaped first; only safe constructs produce
  live HTML — no raw passthrough.
- The doc files are bundled into the Docker image at build time
  (`COPY ... /opt/gatekeeper-docs/`) so the page works without
  runtime file access or network.
- Four tabs switch between documents via `?doc=<slug>`.
- Styled with `.prose` CSS — readable typography, scrollable code
  blocks, responsive tables, consistent with the design system.

## 0.9.0

**Self-service tool catalog management on a new, isolated `/admin/mcp` endpoint (REQUIREMENTS.md FR-2.8-3.7). Tool definitions are now versioned and append-only; deletion is a soft delete.**

- **New `/admin/mcp` endpoint** -- a second `mcp.server.lowlevel.Server`
  instance with a hand-written, fixed `admin.*` tool list
  (`admin_server.py`), sharing no catalog/tool registry with `/mcp`
  (`admin_service.py`). `AuthMiddleware` role-gates each mount:
  `admin`-role tokens are rejected on `/mcp`, every other role is rejected
  on `/admin/mcp`. `server.py`'s `build_app` composes both
  `streamable_http_app()` results (each with its own
  `StreamableHTTPSessionManager`) into one Starlette app with a combined
  lifespan -- Starlette does not propagate the ASGI `lifespan` scope into a
  mounted sub-app on its own, so both session managers are started
  explicitly.
- **Low-risk admin actions apply immediately; the rest goes to a pending
  queue.** Read-only queries, creating a tool (always created disabled),
  disabling a tool, and enabling/updating a `read`-category tool auto-apply.
  Enabling/updating a `write`/`write_external` tool, deleting a tool, and
  setting an identity's tool grants (`admin.grant_set`) are written to a
  new `pending.yaml` (`pending.py`) instead, reviewed at the new `/ui/pending`
  console page. Approving re-checks the proposal's captured revision against
  the live one and marks it `stale` -- never silently re-based -- if the
  config moved since it was proposed.
- **Self-approval is structurally impossible.** `approve`/`reject` are not
  part of `AdminService`'s dispatch table and have no MCP tool entry --
  there is no code path from `/admin/mcp` that reaches a decision on a
  pending item; only `/ui/pending` (human session, CSRF) can.
- **Tool definitions are now append-only and versioned** (FR-3.3): each
  `tools.yaml` entry can carry a nested `versions:` list with a
  `current_version` pointer; `tool_update` (via `/ui` or `admin.tool_update`)
  appends a version and never overwrites one. Today's flat entries still
  load unchanged, as an implicit version 1 -- no migration step.
  `tool_delete` is now a soft delete (`deleted: true`, full history kept)
  instead of removing the entry.
- **New `gatekeeper serve --pending`** CLI flag / `pending.yaml` state file,
  constructed alongside `tools.yaml`/`identities.yaml` whenever `--ui` runs
  with a writable Tier 2.

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