# Telegram recovery with unchanged official Hermes

**Automatic recovery of an existing Telegram session with Gatekeeper's
atomic continuation contract is not supported by the verified, unchanged
Hermes v0.21.6 interfaces. Automatic Telegram recovery remains disabled.**
Gatekeeper and its release-bound Artifact Store remain available.

Only unchanged official Hermes images are permitted. No Gateway patch,
custom Hermes image, monkeypatch, private host bridge, CLI resume or Runs-API
substitute is part of the supported deployment.

## Verified version and supported interfaces

The evidence is the unmodified v0.21.6 source at
`818c13be1dc4fd28987e1e881a9408224afd4535`, corresponding to the existing pin
`nousresearch/hermes-agent:v0.21.6@sha256:55e192fba0cd4fde61142abbff5adeacff40efdb482ccd0ff877924bd274f909`.
This is a version-specific assessment, not a claim about future releases.

1. **Plugin message injection is supported.**
   [`PluginContext.inject_message`](https://github.com/NousResearch/hermes-agent/blob/818c13be1dc4fd28987e1e881a9408224afd4535/hermes_cli/plugins.py#L603)
   accepts content plus an existing `session_key` or an `origin`, with the
   documented per-plugin permission. The
   [official plugin documentation](https://github.com/NousResearch/hermes-agent/blob/818c13be1dc4fd28987e1e881a9408224afd4535/website/docs/user-guide/features/plugins.md#L897)
   specifies reuse of stored platform/chat/thread/profile/history, current
   authorization checks, pinned session routing and the native busy-session
   queue. Thus ordinary injection into a Telegram conversation is possible.
   Its boolean result confirms asynchronous scheduling, not a completed
   turn or Telegram delivery. It exposes no public HTTP/CLI injection endpoint.

2. **The Runs API is supported for API consumers.** The
   [official API documentation](https://github.com/NousResearch/hermes-agent/blob/818c13be1dc4fd28987e1e881a9408224afd4535/website/docs/user-guide/features/api-server.md#L448)
   describes existing session transcripts, session turn leases and durable
   `Idempotency-Key` handling. These do not supply original Telegram
   chat/thread delivery or the required Gateway recovery admission contract.
   They are not a Telegram recovery fallback.

3. **Native internal wake exists but is not a public recovery contract.**
   [`gateway.wake.admit_internal_event`](https://github.com/NousResearch/hermes-agent/blob/818c13be1dc4fd28987e1e881a9408224afd4535/gateway/wake.py#L88)
   calls the adapter message handler and checks its admission receipt. The
   source explicitly defines that receipt as scheduled/queued, not model
   execution, authorization of a later turn, or successful outbound delivery.
   We do not call private Gateway methods from an external bridge.

## Missing guarantee

The documented plugin signature has no expected turn sequence,
session/task/generation binding, recovery ownership predicate or persistent
continuation idempotency parameter. The
[native plugin dispatch](https://github.com/NousResearch/hermes-agent/blob/818c13be1dc4fd28987e1e881a9408224afd4535/gateway/run_plugin_injection.py)
passes conversational input to the normal adapter path. Its native busy
queue may accept input for a later turn; it does not atomically reject a
stale Gatekeeper incident against the complete recovery binding.

The concrete missing supported mechanism is an admission operation or
supported pre-start hook **inside the same serialization as ordinary user
input**, which atomically checks all of the following and durably reserves
the continuation before native execution:

- expected turn sequence;
- unique session, task and generation binding;
- no active turn and no Hermes-internal recovery;
- persistent continuation idempotency, including a crash between acceptance
  and start.

This conclusion follows from the documented interfaces and pinned dispatch
source. An adapter lock or subsequent `pre_llm_call` check cannot add that
missing Gateway guarantee. Routing support alone does not meet this contract.
No workaround will be built or activated.

## Narrower feasibility check: an ordinary status-check message

An ordinary queued message asking to recheck an open task is a different
use case from the atomic continuation contract above. The public plugin
injection API is a candidate for that message. It requires an installed
general plugin and its `allow_gateway_injection` permission; a standalone
external sidecar cannot invoke it through a public HTTP endpoint.
No new supervisor or Kanban architecture has been built.

The local running `hermes-test` container was inspected read-only. Its
image id and repository digest match the official digest above. Both
native Gateway source hashes match the unmodified pinned source, and the
experimental Gateway module is absent. No Telegram token was configured
in the process environment or home `.env`; its `config.yaml` has no
Telegram section. Consequently there is no live Telegram result here.
Experimental fixture tests are not evidence for this unchanged-image check.

1. **After an ended/exhausted turn:** the documented existing-session
   injection retains conversation history and the original route, and
   enters normal Gateway processing. Actual handling after exhaustion and
   a reply in the original Telegram chat remain **not live-proven**.
2. **Concurrent ordinary user input:** the native adapter installs its
   session guard synchronously before task creation. Native
   [`run_busy.py`](https://github.com/NousResearch/hermes-agent/blob/818c13be1dc4fd28987e1e881a9408224afd4535/gateway/run_busy.py)
   explicitly queues internal/plugin messages rather than interrupting or
   steering an active turn. This is source-backed serialization for a
   stable session key; a live competing-message trace is still missing.
3. **Explicit user stop:** the requested no-restart guarantee is **not
   supplied by native injection**. In
   [`_interrupt_and_clear_session`](https://github.com/NousResearch/hermes-agent/blob/818c13be1dc4fd28987e1e881a9408224afd4535/gateway/run_agent_cache.py#L524)
   `/stop` interrupts the current turn but deliberately preserves/promotes
   a queued internal wake. The adapter's post-command drain can start it.
   Plugin injection sets `internal=True`. A subsequent injection is also
   ordinary new input, not a permanently blocked recovery attempt.
4. **Duplicate recovery messages:** the requested no-duplicate-action
   guarantee is **not supplied by native injection**. The public signature
   has no idempotency key. The native FIFO gives separate text messages
   separate turns; it does not deduplicate a recovery incident. Runs API
   idempotency is a different interface and cannot be borrowed as proof.

For David, original-session routing and native serialization are supported
building blocks. They do not alone make automatic follow-up safe after a
user stop or against duplicate actions. Those two policies would require
additional proven behavior; none has been implemented or assumed here.
An instruction to only check status is also not a hard prohibition on
mutating tools. A live feasibility run must be isolated and restrict tool
permissions to read-only operations, and must report actual Telegram
delivery separately from source findings. Access to an isolated test bot
and original test session has been requested through David.

## Status and preserved experiments

The unmodified official Hermes pin remains the deployment basis. Do not
enable automatic Telegram recovery or install the experimental native
module/custom test image. Gatekeeper and Artifact Store configuration are
unchanged. The existing adapter's isolated API-session experiments are not
Telegram acceptance.

Experimental work is preserved locally, outside the documentation branch
and outside `main`:

- `codex/telegram-continuation`: `2658da9baa119a61f861c969610f70ea31e7d5aa`;
- unpublished release preparation `codex/experimental-gateway-release-051`:
  `62e18af`.

Neither experimental branch was pushed. The proposed 0.51.0 patch release
was withdrawn before publication; at that point local `main` was restored
to the fetched 0.50.0 main tip. Gatekeeper 0.51.0 publishes this documentation
assessment only, without the experimental patch or custom image.
Experimental regression results do not establish support
in an unchanged official image. The MCP reconnect issue remains separate
and does not change this support assessment.
