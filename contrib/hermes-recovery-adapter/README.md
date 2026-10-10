# Gatekeeper recovery adapter for Hermes (isolated test implementation)

This is the Hermes side of Gatekeeper's recovery contract **v1.1**. It is
**not deployed to production**, and production recovery stays disabled until
acceptance.

**Telegram support:** safe automatic continuation of an existing Telegram
session is **not supported** by the verified, unchanged official Hermes
v0.21.6 interfaces. Automatic Telegram recovery stays disabled. The API-run
test evidence below does not establish Telegram delivery. No Hermes source
patch, custom image, monkeypatch or CLI-resume workaround is permitted. See
[the supported-interface assessment](../../docs/HERMES_TELEGRAM_SUPPORT.md).

## Pins

The adapter lives in the Gatekeeper repository. It is bound to whichever
commit it ships in, together with the contract in that same commit,
`docs/HERMES_ADAPTER.md`. Each Gatekeeper image carries both as artifacts
(`hermes-recovery-adapter`, `hermes-adapter-contract`), with commit and
sha256 recorded in the image's artifact manifest. Fetch them through the
`artifact.*` tools or `GET /artifacts/...`; see docs/DEPLOYMENT.md.

| | |
|---|---|
| Live acceptance run against | Gatekeeper `7aa7b394cb713162db98aad29c91c342508a49c7` (0.49.0), contract sha256 `d444f616c61c8ebd0e64dd25a9373316963a4eb3f164d7fcb737d300065614b0` |
| Hermes | `nousresearch/hermes-agent:v0.21.6@sha256:55e192fba0cd4fde61142abbff5adeacff40efdb482ccd0ff877924bd274f909` (source `818c13be`) |

Gatekeeper itself is not reimplemented. The live test runs the real Gatekeeper
from a checkout (`test/gk_serve.py`).

## Parts

- **`plugin/gatekeeper-recovery/`** is a Hermes plugin. It uses only
  documented surfaces: `register_hook` and `register_tool`.
  - `pre_tool_call` always overwrites `_hermes_recovery` on Gatekeeper calls,
    with `null` when the session is unbound, and counts attempts per turn.
  - `pre_llm_call` advances the durable `turn_seq` and records `started`. The
    continuation marker is accepted only with a matching journal row and
    binding; otherwise the turn runs as an ordinary turn.
  - `post_tool_call` records progress on a Kanban write to the bound task, and
    mirrors Hermes's MCP breaker (3 consecutive failures → 60 s pause in
    v0.21) from documented outcomes.
  - `on_session_end` maps exits through a versioned layer:
    `max_iterations_reached(…)` → `exhausted`, `failed` → `error`,
    `text_response(…)` → `final_reply`, an interruption with an observed user stop →
    `user_stopped`, and anything else, including an interruption of unknown
    origin, → `unmapped`, which is never continued. It then enqueues
    `turn_stopped` with `cooldown_until` and `gatekeeper_attempts`.
  - `kanban_task_completed` closes only that exact task.
  - The tool `gatekeeper_recovery_bind_task` is the explicit binding.
- **`sidecar/adapter.py`** runs on the standard library only. It serves the
  signed `/status`, `/continue` and `/continuation` endpoints, sends the
  outbox to Gatekeeper with backoff, and reconciles journaled-but-unstarted
  continuations. It talks to Hermes only through the documented Runs API.
- **`journal.py`** is the durable journal shared by both parts: SQLite with
  WAL and `synchronous=FULL`, in the adapter's own file, never in Hermes's
  databases.

## Live acceptance (isolated instance, mock-free on both sides)

Hermes and Gatekeeper are both real. The model is a scripted
OpenAI-compatible stub (`test/fake_model.py`) that calls tools through
Hermes's real `tool_call` bridge. Evidence files are in `test/out/`.

| Test | Result | Evidence |
|---|---|---|
| Error → stopped turn → continue → exactly one new turn in the same session → executed call with `continuation_id` → recorded progress | passed | `evidence-first-*.json` |
| Duplicate request: same `/continue` key ×3, same stop event ×2 | passed: one continuation id, `deliveries: 1`, events reported as duplicates, `turn_seq` unchanged | `evidence-duplicate.json` |
| Competing user message during the cooldown | passed: incident `superseded_by_newer_turn`, no continuation, still none 114 s after the deadline | `evidence-competing.json` |
| Restart of Gatekeeper, Hermes gateway and sidecar during the cooldown | passed: same deadline, exactly one continuation, `recovered` | `evidence-restart.json` |

## Findings from the live run

- **Hermes's own MCP breaker** (3 failures → 60 s pause, gateway-wide)
  blocked the resumed turn's first Gatekeeper call when Gatekeeper continued
  too early. The adapter now reports the pause as `cooldown_until`, and
  Gatekeeper waits it out.
- **A user message during the cooldown** used to let Gatekeeper continue
  after the user's turn. This is fixed in Gatekeeper `7aa7b39`: a newer turn
  without Gatekeeper attempts supersedes the incident.
- **The per-task recovery budget holds across runs.** Reusing one Kanban task
  across test runs exhausted it; that is correct behavior.

## Limitations

- Continuation goes through the Runs API, so a turn resumed for a
  **push-platform** session (for example Telegram) answers the API caller, not
  the original chat. Push platforms need Hermes's in-process wake path, which
  is only reachable through private gateway internals.
- A user stop is observed only through `agent_loop_stopped` (gateway
  `/stop`). Other interruptions are reported as `unmapped` (not continued).
  `interrupted` is used only after a gateway restart.
- The breaker mirror and the exit mapping are tied to Hermes v0.21.x. A new
  Hermes version needs its mapping checked.
- `tests/test_adapter.py` holds 25 regression tests for the exit mapping, the
  breaker mirror and the continuation journal: the plugin hooks, sidecar
  `/continue` idempotency and ownership checks, and reconciliation. They run
  without Hermes or Gatekeeper.
- Gatekeeper's full suite on this Windows box is **not green**: 1213 passed,
  11 failed and 33 errors, all pre-existing Windows environment failures that
  were identical before the recovery work. See
  `evidence/gatekeeper-suite-baseline.md`. The recovery tests pass 70/70. There
  is no Linux CI run for the branch.
- **Mapping fix after the live runs.** An exit Hermes reports as completed with
  an exit string this table does not know now maps to `unmapped`; it used to
  map to `final_reply`, which is continuable after a cooldown. The first round
  trip was re-run afterwards and passed
  (`evidence/evidence-first-rerun-after-mapping-fix.json`).

## Run it

```bash
python test/setup.py up            # fresh volume, secrets, Kanban task, both containers
python test/fake_model.py 18770    # host
python test/gk_serve.py <gatekeeper checkout at the pinned commit>   # host
python test/run_live.py first | duplicate <session> | competing | restart
python test/setup.py down
```
