# Hermes recovery adapter — contract v1.1

This is the contract the **Hermes side** must meet. Gatekeeper 0.49.0
implements the other half (`src/gatekeeper/recovery.py`, off by default). Both
sides implement against the same revision of this file, identified by its
Gatekeeper commit and SHA-256. Every test in `tests/test_recovery.py` runs
against a mock adapter; no live round trip has been demonstrated yet.

**Changes in v1.1** (Gatekeeper 0.49.0):

- Correlation may travel in the reserved tool argument `_hermes_recovery`.
  Conflicting carriers produce no correlation (§1).
- The integrity rules are explicit: authenticated origin, derived
  installation, an incident pinned to one session, and an authoritative,
  echo-checked mapping (§6).
- Stop reasons are a closed enum. Hermes exit strings are mapped in the
  adapter, never in this contract. An exit the adapter cannot map is
  reported as `unmapped`, which is accepted and never continued (§2.1).
- Recovery ownership is binding: Gatekeeper never continues a session while
  a Hermes-internal recovery attempt or its backoff is pending (§3).
- Continuation acceptance and idempotency are journaled durably before the
  turn starts, with defined crash handling (§4).
- A newer turn that did not attempt Gatekeeper supersedes the incident; a
  user message during a cooldown is never continued over (§2).
- "Started" is durable and stays provable after the turn ended (§4, §5). The
  continuation marker counts only together with a matching journal row and a
  validated binding; the text alone does nothing (§5).

**Who owns what.** Hermes owns planning, delegation, Kanban tasks, result checks,
user replies, and its own in-place turn recovery. Gatekeeper owns permissions,
execution, and the decision whether to continue a session. The adapter is
plumbing: it never plans, retries tools, or creates a follow-up task in place
of a resume.

**Primary case.** An **orchestrator** session that is stuck on repeated
Gatekeeper failures. Kanban worker sessions remain under Hermes's own recovery
(§3).

**v1 coverage.** Recovery starts only from a Gatekeeper-observed failure. A turn
that stops (for example on iteration exhaustion) without a preceding failed
Gatekeeper call is **not** recovered in v1. Gatekeeper answers such a stop with
`action: none`. This is not universal automatic recovery.

## 1. Correlation on every `tools/call`

The correlation object travels in one of two carriers:

- `params._meta.hermes`, for MCP clients that can send per-call `_meta`;
- the reserved tool argument **`_hermes_recovery`**, for clients that cannot.
  Hermes v0.21.6's MCP client cannot: it calls
  `session.call_tool(name, arguments=args)`, and its headers are static per
  server. The adapter plugin sets the argument from a `pre_tool_call` hook
  returning `{"action": "modify", "args": {"_hermes_recovery": …}}`, for
  Gatekeeper tools only.

The rules for the carriers:

- **Always overwrite.** The plugin sets `_hermes_recovery` on **every**
  Gatekeeper call. A turn with no bound task gets `null`. `modify` merges the
  plugin's value over the model's arguments, so a value the model wrote itself
  never reaches Gatekeeper.
- **Only this exact name is reserved.** The name `_hermes_recovery` and
  nothing else: other parameter names, including names that start with `_`
  (even `_hermes_recovery_x`), stay valid.
- **Removal at the MCP boundary.** Gatekeeper removes `_hermes_recovery` from
  every call before the pipeline sees it, even while recovery is off. The call
  then runs through all the usual checks: authorization, parameter
  validation, scopes, rate limits, holds. The reserved argument is never
  validated, executed or audited as a parameter. A tool that declares a
  parameter of that name is refused at catalog load.
- **Conflicts.** If both carriers are present they must be identical. If they
  differ, Gatekeeper uses **neither**: the call gets no recovery and is
  logged as `correlation_rejected`, and the call itself still runs normally.
  `null` means "no correlation".

| Field | Req. | Rule |
|---|---|---|
| `session_id` | yes | The session making the call. |
| `board_id` | yes | Kanban board namespace. Part of the incident key, because task ids are not shown to be unique across boards. |
| `task_id` | yes | The task **this turn is accountable for**. An orchestrator uses the parent orchestration task it was asked to handle; a worker uses its own worker task. Never "the last task created". The binding is explicit (§6), never inferred. |
| `task_generation` | no (0) | Increment it when a task is reopened. A higher generation starts a fresh recovery lifecycle; a terminal event closes only its own generation. |
| `turn_id` | yes | Opaque, for logs only. Gatekeeper never orders by it. |
| `turn_seq` | yes | Integer, strictly increasing per session, durable across Hermes restarts. The only ordering Gatekeeper trusts. |
| `event_id` | yes | Unique per installation for the life of the install, and stable across retries of the same call (for example, derived from the tool call id). Duplicates are dropped. |
| `profile` | if configured | Must be one of the installation's `profiles` when the Gatekeeper config lists any. |
| `continuation_id` | on resumed turns | Set on every call of a turn that `/continue` started. This, not a new `turn_seq`, links activity to the continuation. |
| `cooldown_until` | no | Unix seconds while Hermes's own breaker for Gatekeeper is cooling. |
| `installation` | no | Consistency check only (§6). |

Ids match `^[A-Za-z0-9_.:@-]{1,128}$`. A turn with no bound Kanban task is not
covered, and the adapter must not create a task just for recovery.

## 2. Lifecycle events: Hermes → `POST /recovery/events`

These use the same bearer token as `/mcp`. The route executes nothing, so it can
stay usable while Hermes's breaker around the Gatekeeper tools is open without
any blocked tool running.

```json
{"event_id": "stop-sess_a1-7", "type": "turn_stopped", "profile": "orchestrator",
 "session_id": "…", "board_id": "…", "task_id": "…", "task_generation": 0,
 "turn_seq": 7, "reason": "exhausted", "cooldown_until": null, "gatekeeper_attempts": 3}
```

- **`gatekeeper_attempts`** (on `turn_stopped`, optional, default 0) is the
  number of Gatekeeper tool calls the stopped turn **attempted**. That count
  includes calls Hermes blocked client-side, for example while its breaker
  for Gatekeeper is open; such calls never reach Gatekeeper.
- **`cooldown_until`** carries the pause of Hermes's own breaker for
  Gatekeeper, when it is open. Continuing before that time would run
  straight into it.

- **`type`** is one of `turn_stopped`, `task_completed`, `task_cancelled` or
  `task_superseded`. A terminal event affects only that exact
  `(installation, board_id, task_id, task_generation)`. A worker completing
  never closes its parent, and the parent request is closed only by its own
  terminal event.
- **Outbox.** Events go through a persistent outbox with bounded retry and
  exponential backoff (for example 1 s to 5 min, given up after 24 h).
  Delivery is at-least-once; Gatekeeper dedups by `event_id`.
- **Crashes.** A crashed process cannot emit its own stop. On startup, the
  adapter emits `turn_stopped` with `reason: interrupted` for every turn its
  durable state shows as active. Independently, Gatekeeper reconciles an open
  incident with no traffic for `reconcile_after_seconds` (default 600) against
  `/status`, at most `max_reconciles` times (default 3).
- **Ordering.** Gatekeeper ignores a stop whose `turn_seq` is lower than the
  incident's latest, a stop for a different session or profile, and an event
  from an older `task_generation`.
- **The session moved on.** Gatekeeper never advances an incident's turn from
  an event alone. Take a stop for a turn **newer** than the incident's latest
  Gatekeeper-observed turn, which Gatekeeper did not start and which reports
  `gatekeeper_attempts: 0`, for example the user's own next message: there the
  session has moved on. The incident is suppressed
  (`superseded_by_newer_turn`), and any scheduled continuation is withdrawn.
- **Responses.** `200 {accepted, action, reason?, duplicate?}`, `400` for a
  malformed body or an unknown reason, `403` for an installation or profile
  mismatch, and `404` while the flag is off.

### 2.1 Stop reasons: closed enum, mapped in the adapter

`reason` is one of these stable values, and nothing else:

| Contract reason | Meaning | Gatekeeper may continue |
|---|---|---|
| `exhausted` | The turn's iteration budget ran out | yes |
| `breaker_open` | Hermes's breaker for Gatekeeper opened | yes, after `cooldown_until` |
| `error` | Technical failure | yes |
| `timeout` | The turn hit a wall-clock limit | yes |
| `interrupted` | A technical interruption (process restart, lost connection) | yes |
| `final_reply` | The turn ended normally | only after a cooldown Gatekeeper scheduled |
| `user_stopped` | An **explicit** user stop | **never**; the incident is suppressed, even mid-cooldown |
| `unmapped` | The adapter could not map the exit to one of the values above: an exit value its mapping layer does not know, or an interruption whose origin it did not observe | **never**. The value is accepted and recorded; a continuation already scheduled after a cooldown is withdrawn, and the incident stays open for tool-response guidance. |

Hermes's internal exit strings (for example `turn_exit_reason`) are
version-dependent diagnostics, and this contract does not depend on them. The
adapter keeps a **versioned mapping layer** from the Hermes version it runs on
to these reasons:

- A loop exit it cannot map is reported as **`unmapped`**, never as a
  continuable reason. The raw value is logged on the adapter side only.
- An explicit user stop is reported as `user_stopped` only when the adapter
  observed a user-initiated stop. A technical interruption is reported as
  `interrupted` only when the adapter knows it was technical, for example
  because the process restarted with the turn still marked active. An
  interruption of unknown origin is `unmapped`. Neither may be reported as
  the other.
- The adapter must emit `exhausted` from a **real loop-exit point**, not from
  inference over transcripts or timings. For the emission point found in
  Hermes v0.21.6, see §9. Homelab has confirmed the same reason-carrying
  `on_session_end` hook on the version it runs.

## 3. Recovery ownership

Hermes runs its own bounded, in-place recovery for dispatcher-owned Kanban
worker turns (`agent/kanban_turn_recovery.py` in v0.21.6). It makes a few
attempts with backoff, in the same session, and the dispatcher takes over
after that. **These rules are binding:** two recovery systems never act on
one session at the same time, and Gatekeeper never continues a session in
parallel with Hermes's own recovery.

- **Hermes-internal recovery wins.** While an internal recovery attempt or
  its backoff is pending for a session, the adapter **MUST** report
  `recovery_owner: "hermes"` and `recovery_until` (Unix seconds) on `/status`,
  and **MUST** reject `/continue` with
  `{"accepted": false, "reason": "internal_recovery", "retry_after_until": …}`.
- **What Gatekeeper does then.** It spends no recovery and starts nothing. It
  waits for the deadline like a cooldown and then checks once, at most 3 times
  per incident. A `recovery_owner: "hermes"` with no deadline (a session Hermes
  owns outright, such as a dispatcher-owned worker) means "leave it to Hermes":
  the incident is suppressed.
- **Stops during internal recovery.** The adapter does not report a session as
  stuck while internal recovery is pending. Any `turn_stopped` it sends then
  must still pass the §2.1 mapping, and Gatekeeper defers on the next
  `/status`.
- **Orchestrator sessions** are not under Hermes's in-place worker recovery
  and are the primary Gatekeeper case.

## 4. Adapter endpoints: Gatekeeper → Hermes

Every request is a `POST` with JSON, signed (§6). Each carries the reference
object `{installation, profile, session_id, board_id, task_id,
task_generation}`, which the adapter validates authoritatively (§6).

### `/status` (read-only, no side effects)

```json
{"session_id": "…", "board_id": "…", "task_id": "…",
 "turn": "stopped", "turn_seq": 7, "stop_reason": "exhausted",
 "task": "open", "task_generation": 0, "last_progress_at": 1791560000,
 "continuation_id": null,
 "last_continuation": {"continuation_id": "…", "state": "finished",
   "started_at": 1791559000, "started_turn_seq": 6,
   "ended_at": 1791559100, "exit_reason": "final_reply"},
 "recovery_owner": null, "recovery_until": null,
 "objective": "…", "acceptance_criteria": "…", "task_state": "…"}
```

- **Echo.** `session_id`, `board_id` and `task_id` **echo the reference the
  adapter validated**. A missing or different echo is a mapping failure.
- **`turn`** is `active`, `stopped` or `exhausted`. **`stop_reason`** uses §2.1.
- **`continuation_id`** names the continuation driving the **current** active
  turn, or is null.
- **`last_continuation`** is the durable journal record of the session's most
  recent continuation (§5). It is returned even after that turn ended.
- **`recovery_owner` and `recovery_until`** are defined in §3.
- **`last_progress_at`** is when the task owner last recorded meaningful
  progress on the bound task, such as a successful Kanban write to it. A tool
  call alone is not progress.
- **`objective`, `acceptance_criteria` and `task_state`** are short and hold no
  secrets. They are forwarded, redacted, to the rescue model.

### `/continue`

The request is the reference plus
`{incident_id, idempotency_key, expected_turn_seq, guidance}`.

The adapter must **atomically**, through the same per-session serialization as
normal Gateway turns:

1. Validate ownership, that the task is open at that generation, that the
   session has **no active turn**, that no Hermes-internal recovery is pending
   (§3), and that its latest `turn_seq` equals `expected_turn_seq`.
2. Journal the acceptance durably (§5), then start one new turn in **that
   session**, with its existing history, task association and **original
   reply destination**. Normal Hermes and Gatekeeper permission checks apply;
   `guidance` is the turn's input, and it is advice.

The response is `{"accepted": true, "continuation_id": "…"}` or
`{"accepted": false, "reason": "…"}`. The `continuation_id` is stable and is
returned again for a repeated `idempotency_key`. Rejection reasons:

| `reason` | Meaning | Gatekeeper |
|---|---|---|
| `turn_active`, `superseded`, `turn_seq_mismatch` | A user message, or the agent itself, won the race | back to guidance; no recovery spent, nothing overridden |
| `internal_recovery` | Hermes's own recovery owns the session (§3) | waits for `retry_after_until`; no recovery spent |
| `task_closed`, `not_owner`, `not_admitted`, other | Recovery cannot proceed | `blocked:continuation_rejected` with that reason |

A user message that arrives after acceptance queues behind the continuation
through normal session serialization. If it overtakes the continuation anyway,
the continuation turn sees a `turn_seq` past `expected_turn_seq + 1`. It then
records `lost` (`superseded`) and does nothing. Its turn never carries the
`continuation_id` into a Gatekeeper call.

### `/continuation` (read-only)

The request is the reference plus `{idempotency_key}`. The response is
`{"state": "none" | "accepted" | "admitted" | "started" | "finished" |
"rejected" | "lost", "continuation_id"?, "started_at"?, "started_turn_seq"?,
"ended_at"?, "exit_reason"?, "reason"?}`. `lost` is treated like `rejected`.

Gatekeeper calls this after an **ambiguous** `/continue`: a timeout, a dropped
connection, a 5xx, or its own crash after it recorded "sending". It never
re-sends blindly. On `none` it re-sends **once** with the same key. It stops
after 3 queries and reports `blocked:continuation_uncertain`.

## 5. Durable continuation journal

The adapter keeps one journal row per `idempotency_key` in its **own** store,
never in Hermes's `state.db` or `kanban.db`. The store is SQLite with WAL and
`synchronous=FULL`. A row moves through these states:

`accepted` → `admitted` → `started` → `finished`, or `rejected` / `lost`.

1. **Acceptance.** Under the session's serialization, the adapter validates
   the request and inserts `{idempotency_key, continuation_id, ref,
   expected_turn_seq, state: accepted}` in **one transaction**, then commits.
   Only after the commit does it hand the turn to Hermes, and only after the
   commit does it answer `accepted: true`. If Hermes refuses the turn
   definitively, the row becomes `rejected` (`not_admitted`) and the answer is
   `accepted: false`.
2. **Admission.** Hermes accepted the turn (for example, a run id was
   returned). Hermes-side idempotency keys are derived from the
   `idempotency_key`.
3. **Started.** The turn's input carries the marker
   `[gatekeeper-continuation <continuation_id>]`. **The marker alone proves
   nothing.** It is accepted only if all of the following hold:
   - a journal row with that `continuation_id` exists, in state `accepted` or
     `admitted`;
   - the row's `session_id` is the session of the starting turn;
   - the row's `board_id`, `task_id` and `task_generation` equal the
     session's current binding;
   - the starting turn is `expected_turn_seq + 1`.

   Only then does the adapter record `started_at`, `started_turn_seq` and
   `turn_id` durably **before the first model call**, and from then on tag that
   turn's Gatekeeper calls with the `continuation_id`. A marker without such a
   row is ignored and logged. The turn then runs as an ordinary turn, and its
   calls carry no `continuation_id`.
4. **Finished.** At turn end, the adapter records `ended_at` and the mapped
   `exit_reason` (§2.1).

**Crash handling:**

- *Before the acceptance commit:* there is no row, and the adapter never
  answered `accepted`. `/continuation` says `none`, and Gatekeeper re-sends
  once with the same key.
- *After the commit, before `started`:* at startup, the adapter re-validates
  each such row atomically. If the session is idle at `expected_turn_seq`, it
  re-delivers **once** with the same `continuation_id` (`deliveries` is capped
  at 2). Otherwise the row becomes `lost`, with reason `superseded` or
  `turn_active`. A turn never runs twice for one row, because `started` is
  written before any model work. At worst, a re-delivered input message
  appears twice in the transcript.
- *After `started`:* nothing is re-delivered. `/continuation` and
  `/status.last_continuation` report the durable record.
- *Answer lost in transit:* Gatekeeper asks `/continuation` and finds the row.

## 6. Integrity

Correlation can lead to a session being continued, so each link in the chain
is validated. It is not enough that a correlation grants no permissions.

1. **Authenticated origin.** Correlation is accepted only on authenticated
   calls and events. A tool call carries the identity's bearer token on `/mcp`;
   a lifecycle event carries the same token on `/recovery/events`. Gatekeeper's
   requests to the adapter are HMAC V2 signed with a per-installation secret:
   `X-Webhook-Timestamp` in Unix seconds, and `X-Webhook-Signature-V2` as hex
   HMAC-SHA256 of `<ts>.<raw body>`. The adapter verifies the raw bytes in
   constant time and rejects a timestamp more than 300 s off.
2. **Installation.** The installation is derived from the authenticated
   identity (`recovery.installations.<name>.identities`), never taken from the
   client. A client-supplied `installation`, or a `profile` outside the
   installation's list, is a mismatch with one behavior everywhere: on a tool
   call the correlation is dropped and the call runs normally; on an event the
   answer is `403`. Any number of installations can be configured, each with
   its own identities, profiles, adapter and secret.
3. **Carrier integrity.** The plugin overwrites `_hermes_recovery` on every
   Gatekeeper call (§1), so a model-written value never passes through.
   Conflicting carriers produce no correlation.
4. **Session pinning.** An open incident is pinned to the session and profile
   that opened it. A call or stop that names the same task from another session
   or profile neither feeds nor steers that incident.
5. **Authoritative mapping.** Before Gatekeeper spends a recovery, and before
   every continuation, it asks `/status`. The adapter checks the reference
   against its own binding of session, task, board and generation, and answers
   `404`/`409` on any mismatch, never falling back to another session.
   Gatekeeper also verifies the echo. A mapping failure blocks the incident
   (`blocked:session_mapping_failed`) and nothing is continued.
6. **Explicit task binding.** The adapter learns a session's accountable task
   from an explicit binding (for example, an adapter tool the orchestrator
   calls when it takes on a task, or the dispatcher's claim for a worker). It
   never infers the binding from timing or "the last task created".

## 7. Delivery is not recovery

| Stage | Evidence | Deadline → outcome |
|---|---|---|
| accepted | `/continue` returned `accepted` and a `continuation_id` | — |
| started | `/status.last_continuation` (or `/continuation`) names that `continuation_id` with a `started_at`, which stays provable after the turn ended. Live fallback: `turn: active` with that `continuation_id`. | — |
| activity | an **executed** (not denied) tool call carrying that `continuation_id` | `ack_timeout_seconds` (300) → `unacknowledged` |
| progress | `/status.last_progress_at` later than acceptance | `progress_timeout_seconds` (1800) after activity → `blocked:no_progress_after_continuation` |

Progress closes the incident as `recovered`. A later `task_completed` marks it
`resolved`. A statement such as "I will check" is neither activity nor
progress. Status polling is rate-limited per incident (`status_poll_seconds`,
30).

## 8. Live acceptance prerequisites

- The test session has a real delivery path: an adapter binding and a
  supported way to start a turn in that session. A Kanban `unblock` alone does
  not guarantee delivery.
- Restart and crash cases run in a **separate Hermes test instance**, not in
  the production `personal` container. Production recovery stays disabled until
  acceptance passes.
- File and directory access is configured explicitly. `docker exec --user hermes`
  does not grant access to a `700 root` directory.
- **First live goal:** a failure, then a stopped turn, then `/continue`, then
  **exactly one** new turn in the same session, then an executed call carrying
  the `continuation_id`, then recorded progress.
- **Then:** a duplicate request, a competing user message, and a restart.
- **Evidence to keep:** the adapter journal and log, the Gatekeeper
  `"kind": "recovery"` audit lines, and the session transcript.

## 9. Findings against Hermes v0.21.6

Checked against `nousresearch/hermes-agent:v0.21.6`
(`sha256:55e192fba0cd4fde61142abbff5adeacff40efdb482ccd0ff877924bd274f909`,
source commit `818c13be1dc4fd28987e1e881a9408224afd4535`). These are
**informative**: they describe the adapter's v0.21.6 implementation and are
not part of the contract.

- **Per-call `_meta`:** not supported by the MCP client. The adapter uses
  `_hermes_recovery` through `pre_tool_call` → `modify`.
- **Exhaustion emission point:** in `agent/turn_finalizer.py`, budget
  exhaustion without interrupt or failure sets
  `turn_exit_reason="max_iterations_reached(n/m)"`. The canonical
  `on_session_end` plugin hook then carries it, together with `session_id`,
  `turn_id`, `completed`, `failed` and `interrupted`. Hermes then asks the model
  for a summary, so **`completed` can be true on an exhausted turn**, which is
  why the mapping keys on the exit reason and not on `completed`. The hook is
  skipped when persistence is disabled. **Homelab has confirmed** this
  reason-carrying `on_session_end` hook on its Hermes version, so no Hermes
  source patch is needed.
- **Turn start:** `pre_llm_call` fires once per turn, before the loop, with
  `session_id`, `turn_id` and `user_message`. That is where the adapter records
  `started` and advances `turn_seq`.
- **Continuation path:** the documented Runs API, `POST /v1/runs` with
  `session_id` and an `Idempotency-Key` header. Hermes reserves that key
  durably, and session turn leases serialize concurrent writers. It continues
  API-server sessions. A session that originated on a push platform such as
  Telegram would answer to the API caller rather than the original chat; that
  needs Hermes's in-process wake path (`gateway/wake.py`), which is reachable
  only through private gateway internals. **This remains open for push-platform
  orchestrators.**
- **Worker recovery:** `agent/kanban_turn_recovery.py` applies to
  dispatcher-owned worker turns that failed retryably. It makes 3 attempts with
  15/45/90 s backoff, in place. See §3.
- **Plugins cannot serve HTTP routes.** The adapter is therefore a hook plugin
  plus a sidecar that serves `/status`, `/continue` and `/continuation`. The two
  share the journal.

## 10. Optional decision provider (Jev), disabled

`recovery.decision` defines a small interface for the one point the fixed rules
leave open: a repeated failure that could not be classified.

- **Input:** redacted attempts, the task and turn status, the operation status,
  the remaining budget, and `allowed_actions`.
- **Output:** `{action, rationale, evidence[]}`, where `action` is one of
  `WAIT`, `CHECK_OPERATION_STATUS`, `CONSULT_RESCUE`, `CHANGE_APPROACH` or
  `REPORT_BLOCKED`.
- **Fixed rules first:** permission, cooldown, user stop, budgets, duplicates,
  unknown outcomes and Hermes recovery ownership are all handled before the
  provider is asked. An action outside `allowed_actions` is rejected.
- **Fallback:** a timeout, invalid output, or an unavailable provider falls
  back to the deterministic choice.
- **Limits and logging:** at most one call per incident, and `max_per_hour`.
  The log records the provider, model, version, proposed action, accepted
  action and fallback, never the prompt. Shadow mode asks and logs, but always
  applies the deterministic choice.

**No concrete provider ships**, and enabling the provider is a startup error.
Before Jev can be used, these must be verified:

- the exact provider/model id in the OpenCode Go access;
- whether it can be called outside an OpenCode coding session;
- its structured-output format;
- whether the access terms permit non-coding use.

A call that works inside OpenCode does not prove direct API access for
Gatekeeper.
