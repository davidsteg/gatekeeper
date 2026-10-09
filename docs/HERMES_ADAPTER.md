# Hermes recovery adapter — contract v1

Gatekeeper 0.48.0 implements its half of recovery (`src/gatekeeper/recovery.py`,
off by default). This file is the contract the **Hermes side** must meet. Nothing
here exists in Hermes yet, and no live round trip has been demonstrated. Every
test in `tests/test_recovery.py` runs against a mock adapter.

**Who owns what.** Hermes owns planning, delegation, Kanban tasks, result checks
and user replies. Gatekeeper owns permissions, execution and the recovery
decision. The adapter is plumbing: it never plans, retries tools, or creates a
follow-up task in place of a resume.

**v1 coverage.** Recovery starts only from a Gatekeeper-observed failure. A turn
that stops (for example on iteration exhaustion) without a preceding failed
Gatekeeper call is **not** recovered in v1. Gatekeeper answers such a stop with
`action: none`. This is not universal automatic recovery.

## 1. Correlation on every `tools/call`

The adapter attaches `params._meta.hermes`:

| Field | Req. | Rule |
|---|---|---|
| `session_id` | yes | The session that makes the call. |
| `board_id` | yes | Kanban board namespace. Part of the incident key, because task ids are not shown to be unique across boards. |
| `task_id` | yes | The task **owned by this session's turn**: for an orchestrator, the parent orchestration task it was asked to handle; for a worker, its own worker task. Never "the last task created". When a turn coordinates several tasks, it is the task the turn is accountable for. |
| `task_generation` | no (0) | Increment it when a task is reopened. A higher generation starts a fresh recovery lifecycle; a terminal event closes only its own generation. |
| `turn_id` | yes | Opaque, for logs only. Gatekeeper never orders by it. |
| `turn_seq` | yes | Integer, strictly increasing per session, durable across Hermes restarts. The only ordering Gatekeeper trusts. |
| `event_id` | yes | Unique per installation for the life of the install, stable across retries of the same call. Duplicates are dropped. |
| `profile` | if configured | Must be one of the installation's `profiles` when the Gatekeeper config lists any. |
| `continuation_id` | on resumed turns | Set on every call of a turn that `/continue` started. This is what links activity to the continuation. A new `turn_seq` alone does not, because it may be the user's own next message. |
| `cooldown_until` | no | Unix seconds while Hermes's own breaker for Gatekeeper is cooling. |
| `installation` | no | Consistency check only (see §5). |

Ids match `^[A-Za-z0-9_.:@-]{1,128}$`. A turn with no Kanban task sends **no**
`_meta.hermes`. It is not covered, and the adapter must not create a task just
for recovery.

## 2. Lifecycle events: Hermes → `POST /recovery/events`

These use the same bearer token as `/mcp`. The route executes nothing, so it can
stay usable while Hermes's breaker around the Gatekeeper tools is open, without
any blocked tool running.

```json
{"event_id": "evt-…", "type": "turn_stopped", "profile": "orchestrator",
 "session_id": "…", "board_id": "…", "task_id": "…", "task_generation": 0,
 "turn_seq": 7, "reason": "exhausted", "cooldown_until": 1791561600}
```

- **`type`** is one of `turn_stopped`, `task_completed`, `task_cancelled` or
  `task_superseded`. A terminal event affects only that exact
  `(installation, board_id, task_id, task_generation)`. A worker completing
  never closes its parent, and the parent request is closed only by its own
  terminal event.
- **`reason`** (required for `turn_stopped`) is one of:
  - `exhausted`, `breaker_open`, `error`, `timeout` or `interrupted`: a
    technical stop, which may be continued.
  - `final_reply`: the turn ended normally. It is continued only after a
    cooldown.
  - `user_stopped`: an explicit user stop. **Never** overridden; it suppresses
    the incident, including one that is cooling down.
- **Outbox.** Events go through a persistent outbox with bounded retry and
  exponential backoff (for example 1 s to 5 min, at most 24 h). Delivery is
  at-least-once; Gatekeeper dedups by `event_id`.
- **Crashes.** A crashed process cannot emit its own stop. On startup, the
  adapter emits `turn_stopped` with `reason: interrupted` for every turn its
  durable state shows as active. Independently, Gatekeeper reconciles an open
  incident with no traffic for `reconcile_after_seconds` (default 600) against
  `/status`, at most `max_reconciles` times (default 3).
- **Ordering.** Gatekeeper ignores a stop whose `turn_seq` is lower than the
  incident's latest, a stop for a different session, and an event from an older
  `task_generation`.
- **Responses.** `200 {accepted, action, reason?, duplicate?}`, `400` for a
  malformed body, `403` for an installation or profile mismatch, and `404`
  while the flag is off.

## 3. Adapter endpoints: Gatekeeper → Hermes

Every request is a `POST` with JSON. Each carries a reference object
`{installation, profile, session_id, board_id, task_id, task_generation}`. The
adapter validates it **authoritatively** against its own state: the session
belongs to this installation and profile, and it owns that task on that board.
`task.session_id`-style hints are not proof, because they may name a worker
session. A mapping failure answers `404` (unknown) or `409` (wrong owner) and
**never** silently selects or creates another session.

### `/status` (read-only, no side effects)

```json
{"turn": "stopped", "turn_seq": 7, "stop_reason": "exhausted",
 "task": "open", "task_generation": 0, "last_progress_at": 1791560000,
 "continuation_id": null,
 "objective": "…", "acceptance_criteria": "…", "task_state": "…"}
```

- **`turn`** is `active`, `stopped` or `exhausted`. **`stop_reason`** uses the
  vocabulary from §2.
- **`continuation_id`** names the continuation that started the current or last
  turn, or null.
- **`last_progress_at`** is the time the task owner last recorded meaningful
  progress, such as a Kanban state change or a completed subtask. A tool call
  alone is not progress.
- **`objective`, `acceptance_criteria` and `task_state`** are short. They must
  contain no secrets, because they are forwarded, redacted, to the rescue model.

### `/continue`

The request is the reference object plus
`{incident_id, idempotency_key, expected_turn_seq, guidance}`.

The adapter must **atomically**, using the same serialization as normal Gateway
turns for that session:

1. Validate ownership, that the task is open at that generation, that the
   session has **no active turn**, and that its latest `turn_seq` equals
   `expected_turn_seq`.
2. Start one new turn in **that session** with its existing history, task
   association and **original reply destination**. Normal Hermes and Gatekeeper
   permission checks apply. `guidance` is the turn's input, and it is advice,
   not an instruction set.
3. Persist `idempotency_key → result` durably, so that it survives Hermes
   restarts.

The response is `{"accepted": true, "continuation_id": "…"}` or
`{"accepted": false, "reason": "…"}`. The `continuation_id` is stable and is
returned again for a repeated `idempotency_key`. Reasons:

- **`turn_active`, `superseded` or `turn_seq_mismatch`.** A user message (or
  the agent itself) won the race. No recovery is spent and nothing is overridden.
- **`task_closed`, `not_owner` or other.** Gatekeeper blocks the incident with
  that reason as the blocker.

A new user message that arrives after the continuation is accepted is queued
behind it by the normal session serialization. Its turn has no
`continuation_id`, so it never counts as acknowledgement.

### `/continuation` (read-only)

The request is the reference object plus `{idempotency_key}`. The response is
`{"state": "none" | "accepted" | "started" | "rejected", "continuation_id"?,
"reason"?}`.

Gatekeeper calls this after an **ambiguous** `/continue`: a timeout, a dropped
connection, a 5xx, or its own crash after it recorded "sending". It never
re-sends blindly. On `none`, it re-sends **once** with the same key. It stops
after 3 queries and reports the incident as `blocked:continuation_uncertain`.

## 4. Delivery is not recovery

Gatekeeper tracks four stages separately on the incident:

| Stage | Evidence | Deadline → outcome |
|---|---|---|
| accepted | `/continue` returned `accepted` + `continuation_id` | — |
| started | `/status` shows `turn: active` with that `continuation_id` | — |
| activity | an **executed** (not denied) tool call carrying that `continuation_id` | `ack_timeout_seconds` (300) → `unacknowledged` |
| progress | `/status.last_progress_at` later than acceptance | `progress_timeout_seconds` (1800) after activity → `blocked:no_progress_after_continuation` |

Progress closes the incident as `recovered`. A later `task_completed` marks it
`resolved`. A statement such as "I will check" is neither activity nor progress.
Status polling is rate-limited per incident (`status_poll_seconds`, 30).

## 5. Installation, profile, signing

- **Installation and profile.** The installation comes from the authenticated
  Gatekeeper identity (`recovery.installations.<name>.identities`). A
  client-supplied `installation`, or a `profile` outside the installation's
  list, is a mismatch. On a tool call, the correlation is dropped and the call
  runs normally with no recovery. On an event, the answer is `403`. Any number
  of installations can be configured (homelab, personal, later media or the
  Gatekeeper management bot), each with its own identities, profiles, adapter
  and secret.
- **Signing.** Gatekeeper → adapter requests are signed with HMAC V2:
  `X-Webhook-Timestamp` in unix seconds, and `X-Webhook-Signature-V2` as hex
  HMAC-SHA256 of `<ts>.<raw body>` with the installation's secret. The adapter
  verifies the raw bytes in constant time and rejects a timestamp more than
  300 s off.

## 6. Live acceptance prerequisites

- The test session has a real delivery path: an adapter mapping and a wake
  subscription. A Kanban `unblock` alone does not guarantee delivery.
- Restart and crash cases run in a **separate Hermes test instance**, not in the
  production `personal` container.
- File and directory access is configured explicitly. `docker exec --user hermes`
  does not grant access to a `700 root` directory.
- The first live goal is one bounded round trip: failure → stop → `/continue` →
  started → executed call with `continuation_id` → progress. Keep the adapter
  log, the Gatekeeper `"kind": "recovery"` audit lines, and the session transcript.

## 7. Optional decision provider (Jev), disabled

`recovery.decision` defines a small interface for the one point the fixed rules
leave open: a repeated failure that could not be classified.

- **Input.** Redacted attempts, the task and turn status, the operation status,
  the remaining budget and `allowed_actions`.
- **Output.** `{action, rationale, evidence[]}`, where `action` is one of
  `WAIT`, `CHECK_OPERATION_STATUS`, `CONSULT_RESCUE`, `CHANGE_APPROACH` or
  `REPORT_BLOCKED`.
- **Fixed rules apply first.** Permission, cooldown, user stop, budgets,
  duplicates and unknown outcomes are handled before the provider is asked.
  An action outside `allowed_actions` is rejected.
- **Fallback.** Timeout, invalid output and an unavailable provider all fall
  back to the deterministic choice.
- **Limits and logging.** At most one call per incident and `max_per_hour`. The
  log records the provider, model, version, proposed action, accepted action
  and fallback; it never contains the prompt.
- **Shadow mode** asks and logs, but always applies the deterministic choice.

**No concrete provider ships.** Enabling it with any provider name is a startup
error. Jev is said to be reachable through the existing OpenCode Go access.
That was **not** verifiable from the Gatekeeper repo (no OpenCode CLI or server
was reachable). Still open:

- the exact provider/model id;
- whether it can be called from outside an OpenCode coding session;
- its structured-output format;
- whether the access terms allow non-coding use.

A call that works inside OpenCode does not prove direct API access for
Gatekeeper. Until all of these are verified, Jev stays off. Before activation,
evaluate it in shadow mode against permission denial, rate limit, ambiguous
timeout and repeated reasoning failure, measuring decision quality, latency and
cost against the deterministic baseline.

## 8. Open questions for the Hermes code

- Which supported interface resumes an existing session with a new turn, and
  does it share the Gateway's per-session serialization? The webhook
  subscriptions in a May snapshot start new runs, so they do not qualify as-is.
- Can Hermes's MCP client attach `_meta` per call, and where do the session,
  task and turn identifiers live at that point?
- Is there a durable per-session turn counter to use as `turn_seq`, or must the
  adapter persist one?
- Which signal is the truthful `last_progress_at`?
- Where does the Gatekeeper breaker live in Hermes, and does it expose its
  deadline?
