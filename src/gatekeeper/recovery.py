"""Bounded recovery supervisor for stuck Hermes turns.

**What it is for.** An orchestrating agent that keeps failing on the same
Gatekeeper call eventually exhausts its iteration budget and stops -- and
then sits there until a human types "continue". This module notices that
pattern from the one place that sees every call (`Service.call`), keeps a
durable incident per task, and either (a) hands structured guidance back
through the tool response while the turn is still running, or (b) once the
turn has stopped, asks the client's own adapter to continue *the same*
session and task.

**What it is not.** It does not plan, delegate, verify results, or talk to
the user -- Hermes owns all of that. It never executes a tool itself, never
retries a call on the agent's behalf, and never turns a denial into a
different way of reaching the same thing. Its outputs are advice (in a tool
response) and one continuation request (to the adapter); everything that
follows still passes through the normal permission pipeline.

**Coverage, v1.** Recovery starts from a Gatekeeper-observed failure. A
turn that stops (e.g. iteration exhaustion) without any preceding failed
Gatekeeper call has no incident and is *not* resumed -- silence is never
read as a stall, and this is not universal automatic recovery.

**Boundaries that carry the security:**

* The *installation* (homelab / personal / ...) is derived from the
  authenticated identity via Tier 1 config, never from a client field. A
  client-supplied installation is a consistency check only: on a tool call
  a mismatch drops the correlation (the call itself proceeds untouched), on
  a lifecycle event it is a 403. A continuation only ever goes to the
  adapter of the incident's own installation.
* Incidents are keyed by `(installation, board_id, task_id)` and a task
  generation, so a worker task's completion never touches its parent, and
  a reopened task starts a fresh lifecycle instead of staying suppressed.
* Ordering comes from an integer `turn_seq`, never from comparing opaque
  turn ids; acknowledgement comes from the adapter's `continuation_id`
  carried by the resumed turn, never from "some new turn appeared" (which
  might be the user's own next message).
* Denials that FR-7.7 keeps opaque to the agent stay opaque here: the
  guidance for "not granted", "scope mismatch", "protected" and "unknown
  tool" is one identical text. The precise reason is in the incident store
  and the audit log, which only the operator reads.
* The rescue model is diagnostic only: no tools, at most one consultation
  per incident, a hard timeout and token budget, and its answer is passed
  on marked as untrusted advice.
* Everything bounded: per incident (one rescue, one continuation key, one
  re-send after an ambiguous delivery), per task (`max_recoveries_per_task`
  across incidents), cooldowns capped, status polling rate-limited, a fixed
  number of reconciliations.

**Why a separate HTTP endpoint and not an MCP tool for lifecycle events.**
The breaker that opens on the client side is a breaker around the MCP
server's *tools*; a stopped-turn or cooldown report has to arrive even
while that breaker is open, so it gets its own small authenticated route
(`/recovery/events`). It does not bypass the breaker -- it executes nothing.

State lives in `recovery.yaml`, written with the same atomic-write
discipline as `messages.yaml` (`_atomic.py`), so cooldowns, duplicate
protection and continuation idempotency keys survive a restart.
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any

import yaml

from ._atomic import atomic_write as _atomic_write
from ._atomic import dump as _dump
from .errors import ConfigError

logger = logging.getLogger("gatekeeper.recovery")

# -- Configuration ------------------------------------------------------------

#: Shape for every client-supplied correlation id: the opencode session-id
#: character set plus `.`, `:` and `@`. Anything else is noise and is
#: dropped rather than stored. `|` is deliberately excluded -- it separates
#: the parts of a task key.
_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")

#: Turn stop reasons that mean "stuck". `interrupted` is a *technical*
#: interruption (process restart, lost connection); an explicit stop by the
#: user is `user_stopped` and is never overridden.
STUCK_REASONS = frozenset({"exhausted", "breaker_open", "error", "timeout", "interrupted"})
USER_STOP = "user_stopped"
STOP_REASONS = STUCK_REASONS | {"final_reply", USER_STOP}
TERMINAL_EVENTS = {
    "task_completed": "completed",
    "task_cancelled": "cancelled",
    "task_superseded": "superseded",
}
#: Adapter rejections that mean "someone else is already driving this
#: session" -- not a failure of recovery, so no recovery is spent.
BENIGN_REJECTIONS = frozenset({"turn_active", "superseded", "turn_seq_mismatch"})


@dataclasses.dataclass(frozen=True, slots=True)
class Installation:
    name: str
    #: Gatekeeper identities belonging to this installation. An identity
    #: belongs to at most one -- checked at load.
    identities: tuple[str, ...]
    #: Hermes profiles allowed to correlate under this installation. Empty:
    #: any profile (then `profile` is optional in `_meta.hermes`).
    profiles: tuple[str, ...] = ()
    #: Base URL of the client-side recovery adapter. None: guidance through
    #: tool responses only, no continuation.
    adapter_url: str | None = None
    #: Credential-store name of the HMAC secret for the adapter.
    credential: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class RescueConfig:
    enabled: bool = False
    #: OpenAI-compatible API root, e.g. `https://example/v1`. No default.
    base_url: str | None = None
    #: The exact model id. No default, never guessed: it is checked
    #: against `GET {base_url}/models` before the first consultation.
    model: str | None = None
    #: Sent as `reasoning_effort` only when set. Whether the provider and
    #: model honour it is for the operator to verify -- raising it does
    #: not select a stronger model.
    reasoning_effort: str | None = None
    timeout_seconds: float = 45.0
    max_tokens: int = 1200
    credential: str | None = None
    max_per_hour: int = 10


#: Recovery decisions a decision provider may propose. Anything else is
#: invalid output. None of them executes anything or continues a session.
DECISION_ACTIONS = frozenset({
    "WAIT", "CHECK_OPERATION_STATUS", "CONSULT_RESCUE", "CHANGE_APPROACH", "REPORT_BLOCKED",
})


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionConfig:
    """Optional decision provider for the one point the fixed rules leave
    open: what to do about a repeated, unclassified failure. Off by default.
    `mode: shadow` asks and logs but always applies the deterministic choice."""

    enabled: bool = False
    mode: str = "shadow"
    provider: str | None = None
    model: str | None = None
    credential: str | None = None
    timeout_seconds: float = 10.0
    max_tokens: int = 400
    max_per_hour: int = 20


#: name -> factory(DecisionConfig, secret_resolver) -> provider. Empty on
#: purpose: no concrete provider (Jev included) ships until its API, model
#: id, auth and structured-output format are verified. Enabling `decision`
#: with an unregistered provider is a startup error, not a silent no-op.
DECISION_PROVIDERS: dict[str, Callable[..., Any]] = {}


@dataclasses.dataclass(frozen=True, slots=True)
class RecoveryConfig:
    #: The feature flag. Off by default, and off when the block is absent.
    enabled: bool = False
    state_file: str | None = None
    trigger_after: int = 2
    max_recoveries_per_task: int = 3
    max_cooldown_seconds: int = 3600
    default_cooldown_seconds: int = 60
    uncertain_hold_seconds: int = 900
    #: Accepted continuation -> an executed tool call carrying its
    #: continuation_id must arrive within this.
    ack_timeout_seconds: int = 300
    #: Activity observed -> the task owner must report progress within this.
    progress_timeout_seconds: int = 1800
    #: Minimum gap between two `/status` polls for one incident.
    status_poll_seconds: int = 30
    #: An open incident with no traffic for this long is reconciled against
    #: `/status` (covers a Hermes crash that could not emit its own stop).
    reconcile_after_seconds: int = 600
    max_reconciles: int = 3
    tick_seconds: float = 5.0
    adapter_timeout_seconds: float = 10.0
    installations: dict[str, Installation] = dataclasses.field(default_factory=dict)
    rescue: RescueConfig = dataclasses.field(default_factory=RescueConfig)
    decision: DecisionConfig = dataclasses.field(default_factory=DecisionConfig)

    def installation_for(self, identity_id: str) -> Installation | None:
        for installation in self.installations.values():
            if identity_id in installation.identities:
                return installation
        return None

    def credential_references(self) -> dict[str, list[str]]:
        refs: dict[str, list[str]] = {}
        for installation in self.installations.values():
            if installation.credential:
                refs.setdefault(installation.credential, []).append(
                    f"recovery:{installation.name}"
                )
        if self.rescue.credential:
            refs.setdefault(self.rescue.credential, []).append("recovery:rescue")
        if self.decision.credential:
            refs.setdefault(self.decision.credential, []).append("recovery:decision")
        return refs


def _url(value: Any, where: str) -> str | None:
    if value is None or value == "":
        return None
    text = str(value)
    if not text.startswith(("http://", "https://")):
        raise ConfigError(f"toolkits.yaml: {where} must be an http(s) URL")
    return text.rstrip("/")


def _positive(raw: dict[str, Any], key: str, default: float, where: str) -> Any:
    value = raw.get(key, default)
    try:
        number = type(default)(value)
    except (TypeError, ValueError):
        raise ConfigError(f"toolkits.yaml: {where}.{key} must be a number") from None
    if number <= 0:
        raise ConfigError(f"toolkits.yaml: {where}.{key} must be positive")
    return number


def parse_config(raw: Any) -> RecoveryConfig:
    """The top-level `recovery:` block of toolkits.yaml. Absent -> disabled.

    Any number of installations: homelab and personal are the first two,
    not a limit.
    """
    if raw is None:
        return RecoveryConfig()
    if not isinstance(raw, dict):
        raise ConfigError("toolkits.yaml: section 'recovery' must be a mapping")
    defaults = RecoveryConfig()
    where = "recovery"

    installations: dict[str, Installation] = {}
    owner: dict[str, str] = {}
    section = raw.get("installations") or {}
    if not isinstance(section, dict):
        raise ConfigError("toolkits.yaml: recovery.installations must be a mapping")
    for name, spec in section.items():
        spec = spec or {}
        if not isinstance(spec, dict) or not _ID_RE.fullmatch(str(name)):
            raise ConfigError(f"toolkits.yaml: recovery.installations.{name} is invalid")
        identities = tuple(str(i) for i in spec.get("identities") or ())
        if not identities:
            raise ConfigError(
                f"toolkits.yaml: recovery.installations.{name} names no identities"
            )
        for identity in identities:
            if identity in owner:
                # One identity, two installations, would let either
                # installation's events address the other's incidents.
                raise ConfigError(
                    f"toolkits.yaml: identity {identity!r} is listed under both "
                    f"recovery installations {owner[identity]!r} and {name!r}"
                )
            owner[identity] = str(name)
        profiles = tuple(str(p) for p in spec.get("profiles") or ())
        if any(not _ID_RE.fullmatch(p) for p in profiles):
            raise ConfigError(f"toolkits.yaml: recovery.installations.{name}.profiles is invalid")
        adapter_url = _url(spec.get("adapter_url"), f"recovery.installations.{name}.adapter_url")
        credential = spec.get("credential")
        if adapter_url and not credential:
            raise ConfigError(
                f"toolkits.yaml: recovery.installations.{name} has an adapter_url "
                "but no credential -- continuation requests are always signed"
            )
        installations[str(name)] = Installation(
            name=str(name),
            identities=identities,
            profiles=profiles,
            adapter_url=adapter_url,
            credential=str(credential) if credential else None,
        )

    rescue_raw = raw.get("rescue") or {}
    if not isinstance(rescue_raw, dict):
        raise ConfigError("toolkits.yaml: recovery.rescue must be a mapping")
    rescue = RescueConfig(
        enabled=bool(rescue_raw.get("enabled", False)),
        base_url=_url(rescue_raw.get("base_url"), "recovery.rescue.base_url"),
        model=str(rescue_raw["model"]) if rescue_raw.get("model") else None,
        reasoning_effort=(
            str(rescue_raw["reasoning_effort"]) if rescue_raw.get("reasoning_effort") else None
        ),
        timeout_seconds=_positive(rescue_raw, "timeout_seconds", 45.0, "recovery.rescue"),
        max_tokens=_positive(rescue_raw, "max_tokens", 1200, "recovery.rescue"),
        credential=str(rescue_raw["credential"]) if rescue_raw.get("credential") else None,
        max_per_hour=_positive(rescue_raw, "max_per_hour", 10, "recovery.rescue"),
    )
    if rescue.enabled and not (rescue.base_url and rescue.model and rescue.credential):
        raise ConfigError(
            "toolkits.yaml: recovery.rescue.enabled needs base_url, model and "
            "credential -- there is no default rescue model"
        )

    decision_raw = raw.get("decision") or {}
    if not isinstance(decision_raw, dict):
        raise ConfigError("toolkits.yaml: recovery.decision must be a mapping")
    decision = DecisionConfig(
        enabled=bool(decision_raw.get("enabled", False)),
        mode=str(decision_raw.get("mode", "shadow")),
        provider=str(decision_raw["provider"]) if decision_raw.get("provider") else None,
        model=str(decision_raw["model"]) if decision_raw.get("model") else None,
        credential=str(decision_raw["credential"]) if decision_raw.get("credential") else None,
        timeout_seconds=_positive(decision_raw, "timeout_seconds", 10.0, "recovery.decision"),
        max_tokens=_positive(decision_raw, "max_tokens", 400, "recovery.decision"),
        max_per_hour=_positive(decision_raw, "max_per_hour", 20, "recovery.decision"),
    )
    if decision.mode not in ("shadow", "active"):
        raise ConfigError("toolkits.yaml: recovery.decision.mode must be 'shadow' or 'active'")
    if decision.enabled and decision.provider not in DECISION_PROVIDERS:
        raise ConfigError(
            f"toolkits.yaml: recovery.decision.provider {decision.provider!r} is not an "
            "implemented decision provider (implemented: "
            f"{sorted(DECISION_PROVIDERS) or 'none'}). No provider ships until its API "
            "is verified."
        )

    numbers = {
        key: _positive(raw, key, getattr(defaults, key), where)
        for key in (
            "trigger_after", "max_recoveries_per_task", "max_cooldown_seconds",
            "default_cooldown_seconds", "uncertain_hold_seconds", "ack_timeout_seconds",
            "progress_timeout_seconds", "status_poll_seconds", "reconcile_after_seconds",
            "max_reconciles", "tick_seconds", "adapter_timeout_seconds",
        )
    }
    return RecoveryConfig(
        enabled=bool(raw.get("enabled", False)),
        state_file=str(raw["state_file"]) if raw.get("state_file") else None,
        installations=installations,
        rescue=rescue,
        decision=decision,
        **numbers,
    )


# -- Correlation --------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Correlation:
    """Which Hermes session/task/turn a call belongs to.

    `installation` is *derived* from the authenticated identity; the rest
    comes from the client's `_meta.hermes` and is only shape-checked here.
    Ownership (does this session own this task on this board?) is the
    adapter's to validate, authoritatively, on `/status` and `/continue`.
    """

    installation: str
    identity: str
    session_id: str
    board_id: str
    task_id: str
    turn_id: str
    #: Monotonic per session. The only ordering Gatekeeper trusts.
    turn_seq: int
    #: Unique per installation; repeated -> dropped as a duplicate.
    event_id: str
    task_generation: int = 0
    profile: str | None = None
    #: Set by the adapter on every call of a turn it started via /continue.
    continuation_id: str | None = None
    #: Client-reported cooldown (e.g. its own open breaker), epoch seconds.
    cooldown_until: float | None = None


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _id(value: Any) -> str | None:
    return value if isinstance(value, str) and _ID_RE.fullmatch(value) else None


# -- Classification -----------------------------------------------------------

KIND_PERMISSION = "permission"
KIND_COOLDOWN = "cooldown"
KIND_INVALID = "invalid_arguments"
KIND_DEPENDENCY = "missing_dependency"
KIND_TIMEOUT = "timeout"
KIND_FAILURE = "tool_failure"

#: Denials a retry cannot fix and an alternative route must not try to.
_PERMISSION_REASONS = frozenset({
    "unknown_tool", "tool_disabled", "not_granted", "scope_mismatch",
    "protected_resource", "tier1_violation", "ssrf_blocked",
    "rpc_method_denied", "path_escape",
})
_INVALID_REASONS = frozenset({
    "param_invalid", "param_unknown", "param_missing",
    "param_derived_supplied", "control_character",
})
_DEPENDENCY_REASONS = frozenset({"executor_unavailable", "credential_unavailable"})


def classify(outcome: str, denial_reason: str | None, exit_code: int | None) -> str:
    if denial_reason in _PERMISSION_REASONS:
        return KIND_PERMISSION
    if denial_reason == "rate_limited":
        return KIND_COOLDOWN
    if denial_reason in _INVALID_REASONS:
        return KIND_INVALID
    if denial_reason in _DEPENDENCY_REASONS:
        return KIND_DEPENDENCY
    if denial_reason in ("timeout", "recovery_hold") or outcome == "unknown":
        return KIND_TIMEOUT
    if exit_code in (126, 127):
        return KIND_DEPENDENCY
    return KIND_FAILURE


_NORMALIZE = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f-]{27,}", re.I), "<uuid>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\d+"), "<n>"),
    (re.compile(r"(/[^\s/]+)+"), "<path>"),
    (re.compile(r"\s+"), " "),
]


def signature(tool_id: str, kind: str, text: str) -> str:
    """Normalized failure fingerprint -- the same failure with a different
    pid, timestamp or path hashes the same."""
    norm = text.lower()
    for pattern, replacement in _NORMALIZE:
        norm = pattern.sub(replacement, norm)
    norm = norm.strip()[:200]
    return hashlib.sha256(f"{tool_id}|{kind}|{norm}".encode()).hexdigest()[:16]


#: Foreign secrets in diagnostics: things Gatekeeper's own Redactor has
#: never seen (an agent can pass a token as a plain argument, an error can
#: echo an env var). Scrubbed before anything is stored or sent. Each
#: pattern's group 1 is kept, the rest of the match becomes `***`.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b([a-z0-9_]*(?:token|secret|password|passwd|api[_-]?key|authorization)"
        r"[a-z0-9_]*\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|\S+)"
    ),
    re.compile(r"\b(sk-|ghp_|github_pat_|xox[bap]-)[A-Za-z0-9_-]{8,}"),
]


def scrub(text: str, redact: Callable[[str], str] | None = None, limit: int = 600) -> str:
    if redact is not None:
        text = redact(text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(1) + "***", text)
    return text if len(text) <= limit else text[:limit] + "…"


# -- Persistence --------------------------------------------------------------

#: Statuses in which an incident is still in play. Everything else is final.
#: `accepted` = continuation accepted, waiting for its first executed call;
#: `active` = that call happened, waiting for progress reported by the owner.
OPEN_STATUSES = frozenset({
    "open", "guided", "cooling", "continuing", "accepted", "active",
})
MAX_ATTEMPTS = 20
MAX_SEEN_EVENTS = 500
MAX_CLOSED_INCIDENTS = 500


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class IncidentStore:
    """`recovery.yaml`: incidents plus per-task ledgers.

    Single instance (§14), so memory is the source of truth and every
    mutation is written through atomically under one lock -- the
    compare-and-set in `claim` is what makes "one recovery per task" hold
    between the tool-response path and the continuation path.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._data = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            with open(self.path, encoding="utf-8") as handle:
                raw = yaml.safe_load(handle) or {}
        except FileNotFoundError:
            raw = {}
        raw.setdefault("incidents", {})
        raw.setdefault("tasks", {})
        return raw

    def _save(self) -> None:
        self._prune()
        _atomic_write(self.path, _dump(self._data))

    def _prune(self) -> None:
        incidents = self._data["incidents"]
        closed = [i for i in incidents.values() if i["status"] not in OPEN_STATUSES]
        if len(closed) > MAX_CLOSED_INCIDENTS:
            closed.sort(key=lambda i: i.get("updated_at", 0))
            for incident in closed[: len(closed) - MAX_CLOSED_INCIDENTS]:
                incidents.pop(incident["id"], None)

    def mutate(self, fn: Callable[[dict[str, Any]], Any]) -> Any:
        with self._lock:
            result = fn(self._data)
            self._save()
            return copy.deepcopy(result)

    def read(self, fn: Callable[[dict[str, Any]], Any]) -> Any:
        with self._lock:
            return copy.deepcopy(fn(self._data))

    def claim(self, incident_id: str, allowed: frozenset[str] | set[str], to: str) -> bool:
        """Atomic status transition. False: someone else got there first."""
        with self._lock:
            incident = self._data["incidents"].get(incident_id)
            if incident is None or incident["status"] not in allowed:
                return False
            incident["status"] = to
            incident["updated_at"] = time.time()
            self._save()
            return True


def task_key(installation: str, board_id: str, task_id: str) -> str:
    return f"{installation}|{board_id}|{task_id}"


# -- Outbound clients ---------------------------------------------------------


class AdapterError(Exception):
    """`ambiguous`: the request may have been processed (timeout, dropped
    connection) -- the caller must ask before re-sending."""

    def __init__(self, message: str, *, ambiguous: bool = False, status: int | None = None):
        super().__init__(message)
        self.ambiguous = ambiguous
        self.status = status


def signed_headers(secret: str, body: bytes) -> dict[str, str]:
    """Hermes webhook adapter generic HMAC V2, the scheme the mailbox
    webhook already uses (`execute_agent._notify_delivery`)."""
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": ts,
        "X-Webhook-Signature-V2": sig,
    }


class HermesAdapter:
    """Client for the Hermes-side recovery adapter (contract in
    docs/ARCHITECTURE.md, "Hermes adapter contract")."""

    def __init__(self, installation: Installation, secret: str, timeout: float) -> None:
        assert installation.adapter_url
        self.installation = installation
        self._secret = secret
        self._timeout = timeout

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        import httpx

        payload = {"installation": self.installation.name, **payload}
        body = json.dumps(payload, sort_keys=True).encode()
        url = f"{self.installation.adapter_url}/{path}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False) as client:
                response = await client.post(url, content=body, headers=signed_headers(self._secret, body))
        except httpx.ConnectError as exc:
            # Never reached the adapter: safe to treat as not processed.
            raise AdapterError(f"{path}: {type(exc).__name__}") from None
        except httpx.HTTPError as exc:
            raise AdapterError(f"{path}: {type(exc).__name__}", ambiguous=True) from None
        if response.status_code != 200:
            raise AdapterError(f"{path}: HTTP {response.status_code}",
                               ambiguous=response.status_code >= 500,
                               status=response.status_code)
        try:
            data = response.json()
        except ValueError:
            raise AdapterError(f"{path}: response is not JSON", ambiguous=True) from None
        if not isinstance(data, dict):
            raise AdapterError(f"{path}: response is not an object", ambiguous=True)
        return data

    async def status(self, ref: dict[str, Any]) -> dict[str, Any]:
        return await self._post("status", ref)

    async def continue_(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._post("continue", payload)

    async def continuation(self, ref: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        return await self._post("continuation", {**ref, "idempotency_key": idempotency_key})


class RescueError(Exception):
    pass


_RESCUE_SYSTEM = (
    "You are a diagnostic reviewer for a stuck automation agent. You cannot "
    "call tools and nothing you write is executed. Given the objective, the "
    "task state, the failed attempts and the agent's available tools and "
    "permission constraints, reply with ONE JSON object and nothing else: "
    '{"likely_cause": str, "next_step": str, "required_checks": [str], '
    '"blocker": str|null}. next_step must differ from the failed attempts. '
    "Never suggest bypassing a permission denial, using a different tool or "
    "privilege path to reach a denied action, or re-running an operation "
    "whose outcome is unknown. If a human must intervene, say so in blocker."
)


class RescueClient:
    def __init__(self, config: RescueConfig, api_key: str) -> None:
        self.config = config
        self._key = api_key

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"}

    async def model_available(self) -> bool:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.get(f"{self.config.base_url}/models", headers=self._headers())
            ids = {m.get("id") for m in (response.json().get("data") or []) if isinstance(m, dict)}
        except Exception:
            return False
        return self.config.model in ids

    async def consult(self, context: dict[str, Any]) -> dict[str, Any]:
        import httpx

        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {"role": "system", "content": _RESCUE_SYSTEM},
                {"role": "user", "content": json.dumps(context, indent=1)},
            ],
        }
        if self.config.reasoning_effort:
            payload["reasoning_effort"] = self.config.reasoning_effort
        try:
            async with asyncio.timeout(self.config.timeout_seconds):
                async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                    response = await client.post(
                        f"{self.config.base_url}/chat/completions",
                        json=payload, headers=self._headers(),
                    )
        except (TimeoutError, httpx.HTTPError) as exc:
            raise RescueError(f"rescue request failed: {type(exc).__name__}") from None
        if response.status_code != 200:
            raise RescueError(f"rescue request failed: HTTP {response.status_code}")
        try:
            content = response.json()["choices"][0]["message"]["content"]
            text = re.sub(r"^```(?:json)?|```$", "", content.strip()).strip()
            advice = json.loads(text)
        except (ValueError, KeyError, IndexError, TypeError):
            raise RescueError("rescue answer is not the requested JSON object") from None
        if not isinstance(advice, dict) or not advice.get("next_step"):
            raise RescueError("rescue answer has no next_step")
        checks = advice.get("required_checks") or []
        return {
            "likely_cause": str(advice.get("likely_cause") or "")[:800],
            "next_step": str(advice["next_step"])[:800],
            "required_checks": [str(c)[:300] for c in checks if c][:6]
            if isinstance(checks, list) else [],
            "blocker": str(advice["blocker"])[:500] if advice.get("blocker") else None,
        }


# -- Supervisor ---------------------------------------------------------------

_GUIDANCE_PERMISSION = (
    "This action is not available to you. Do not retry it, and do not reach "
    "it through a different tool, command, path or privilege. Stop working "
    "on this step and report to the user that operator intervention is "
    "required, quoting the incident id."
)


class RecoverySupervisor:
    """Owns incidents, cooldowns, rescue and continuation for one deployment.

    `config_source` is read on every use so a SIGHUP reload of toolkits.yaml
    (including flipping `enabled`) takes effect without a restart.
    """

    def __init__(
        self,
        *,
        config_source: Callable[[], RecoveryConfig],
        store: IncidentStore,
        audit: Any = None,
        secret_resolver: Callable[[str], str | None] | None = None,
        tools_for: Callable[[str], list[dict[str, Any]]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._config_source = config_source
        self.store = store
        self._audit = audit
        self._secret = secret_resolver or (lambda _name: None)
        self._tools_for = tools_for
        self._clock = clock
        #: (base_url, model) -> listed by the provider. Re-checked when a
        #: reload changes either, so an unverified model is never consulted.
        self._rescue_checked: tuple[tuple[str | None, str | None], bool] | None = None
        self._rescue_calls: list[float] = []
        self._decision_calls: list[float] = []
        self._decision_provider: tuple[tuple[str | None, str | None], Any] | None = None
        #: Serializes the async halves (network calls) per task, so the
        #: tool-response path and the continuation path for the same task
        #: never interleave. `claim` alone already prevents a double
        #: transition; this keeps a slow adapter call from being overtaken.
        self._task_locks: dict[str, asyncio.Lock] = {}

    @property
    def config(self) -> RecoveryConfig:
        return self._config_source()

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def _lock_for(self, key: str) -> asyncio.Lock:
        lock = self._task_locks.get(key)
        if lock is None:
            lock = self._task_locks[key] = asyncio.Lock()
        return lock

    # -- Logging --

    def _redact(self, text: str) -> str:
        redact = getattr(self._audit, "redact", None)
        return scrub(text, redact)

    def _log(self, event: str, **fields: Any) -> None:
        record = {"event": f"recovery.{event}", **{k: v for k, v in fields.items() if v is not None}}
        logger.info(json.dumps(record, sort_keys=True, default=str))
        write = getattr(self._audit, "write", None)
        if write is not None:
            try:
                write({**record, "kind": "recovery"})
            except Exception:  # pragma: no cover -- logging must not break recovery
                logger.exception("recovery audit write failed")

    # -- Correlation --

    def correlate(self, identity_id: str, meta: Any) -> Correlation | None:
        """`_meta.hermes` -> Correlation, or None (the call then runs with no
        recovery at all). A turn with no Kanban task sends no `_meta.hermes`
        and is simply not covered -- nothing is fabricated for it."""
        config = self.config
        if not config.enabled or not isinstance(meta, dict):
            return None
        hermes = meta.get("hermes")
        if not isinstance(hermes, dict):
            return None
        installation = config.installation_for(identity_id)
        if installation is None:
            return None
        reason = self._mismatch(installation, hermes)
        if reason:
            self._log("correlation_rejected", identity=identity_id,
                      installation=installation.name, reason=reason)
            return None
        ids = {k: _id(hermes.get(k)) for k in ("session_id", "board_id", "task_id", "turn_id", "event_id")}
        turn_seq = _int(hermes.get("turn_seq"))
        generation = _int(hermes.get("task_generation", 0))
        if not all(ids.values()) or turn_seq is None or generation is None:
            return None
        cooldown_until = hermes.get("cooldown_until")
        if not isinstance(cooldown_until, (int, float)) or isinstance(cooldown_until, bool):
            cooldown_until = None
        return Correlation(
            installation=installation.name, identity=identity_id,
            turn_seq=turn_seq, task_generation=generation,
            profile=_id(hermes.get("profile")),
            continuation_id=_id(hermes.get("continuation_id")),
            cooldown_until=cooldown_until, **ids,  # type: ignore[arg-type]
        )

    @staticmethod
    def _mismatch(installation: Installation, fields: dict[str, Any]) -> str | None:
        claimed = fields.get("installation")
        if claimed is not None and claimed != installation.name:
            return "installation mismatch"
        profile = fields.get("profile")
        if installation.profiles:
            if profile not in installation.profiles:
                return "profile not allowed for this installation"
        elif profile is not None and not _id(profile):
            return "invalid profile"
        return None

    # -- Pre-execution: uncertain-outcome hold --

    def hold(self, corr: Correlation | None, *, tool_id: str, scopes: list[str]) -> str | None:
        """Refuse a second run of a mutation whose first outcome is unknown.

        Not a new permission: it only holds back an exact repeat (same
        task, same tool, same scopes) until the agent has checked state
        with a successful read on the same toolkit, or the hold expires.
        """
        if corr is None or not self.enabled:
            return None
        now = self._clock()
        key = task_key(corr.installation, corr.board_id, corr.task_id)

        def _find(data: dict[str, Any]) -> dict[str, Any] | None:
            task = data["tasks"].get(key) or {}
            for hold in task.get("holds", []):
                if hold["tool_id"] == tool_id and hold["scopes"] == sorted(scopes) and hold["until"] > now:
                    return hold
            return None

        hold = self.store.read(_find)
        if hold is None:
            return None
        self._log(
            "hold_enforced", incident_id=hold.get("incident_id"), task_id=corr.task_id,
            installation=corr.installation, tool_id=tool_id,
        )
        return (
            f"Held by recovery (incident {hold.get('incident_id')}): the previous "
            f"{tool_id} call on this task timed out with an UNKNOWN outcome and may "
            "still be running. Do not run it again. First check the current state "
            "with a read/status tool of the same service; once that succeeds, this "
            "hold is released."
        )

    # -- Observation (tool-response path) --

    async def observe(
        self,
        corr: Correlation | None,
        *,
        identity: Any = None,
        tool_id: str,
        toolkit: str | None,
        idempotent: bool,
        scopes: list[str],
        outcome: str,
        denial_reason: str | None = None,
        agent_text: str = "",
        exit_code: int | None = None,
        retry_after: float | None = None,
    ) -> str | None:
        """Record one call outcome; return guidance for the tool response."""
        if corr is None or not self.enabled:
            return None
        key = task_key(corr.installation, corr.board_id, corr.task_id)
        async with self._lock_for(key):
            try:
                return await self._observe(
                    corr, key, identity=identity, tool_id=tool_id, toolkit=toolkit,
                    idempotent=idempotent, scopes=scopes, outcome=outcome,
                    denial_reason=denial_reason, agent_text=agent_text,
                    exit_code=exit_code, retry_after=retry_after,
                )
            except Exception:
                logger.exception("recovery observe failed; the call result stands as is")
                return None

    def _task(self, data: dict[str, Any], key: str, installation: str, board_id: str,
              task_id: str) -> dict[str, Any]:
        return data["tasks"].setdefault(key, {
            "installation": installation, "board_id": board_id, "task_id": task_id,
            "generation": 0, "terminal": None, "recoveries": 0, "open_incident": None,
            "seen_events": [], "holds": [], "last_turn_seq": -1,
        })

    def _new_generation(self, data: dict[str, Any], task: dict[str, Any], generation: int) -> None:
        """A reopened task: a fresh recovery lifecycle, nothing carried over."""
        old = data["incidents"].get(task.get("open_incident") or "")
        if old is not None and old["status"] in OPEN_STATUSES:
            old.update(status="suppressed", outcome="suppressed:new_task_generation",
                       updated_at=self._clock())
        task.update(generation=generation, terminal=None, recoveries=0,
                    open_incident=None, holds=[])

    async def _observe(self, corr: Correlation, key: str, **call: Any) -> str | None:
        config = self.config
        now = self._clock()
        outcome: str = call["outcome"]
        denied = call["denial_reason"] is not None
        kind = None if outcome == "ok" and not denied else classify(
            outcome, call["denial_reason"], call["exit_code"]
        )
        error_text = self._redact(call["agent_text"] or "")

        def _record(data: dict[str, Any]) -> dict[str, Any]:
            task = self._task(data, key, corr.installation, corr.board_id, corr.task_id)
            if corr.event_id in task["seen_events"]:
                return {"duplicate": True}
            task["seen_events"] = (task["seen_events"] + [corr.event_id])[-MAX_SEEN_EVENTS:]
            if corr.task_generation < task["generation"]:
                return {"stale": "older task generation"}
            if corr.task_generation > task["generation"]:
                self._new_generation(data, task, corr.task_generation)
            if task.get("terminal"):
                return {"terminal": task["terminal"]}
            if corr.turn_seq < task["last_turn_seq"]:
                # A call from a turn older than one already seen: it says
                # nothing about the current state of the task.
                return {"stale": "older turn"}
            task["last_turn_seq"] = corr.turn_seq
            task["holds"] = [h for h in task["holds"] if h["until"] > now]
            result: dict[str, Any] = {}

            incident = data["incidents"].get(task["open_incident"] or "")
            if incident is not None and incident["status"] not in OPEN_STATUSES:
                task["open_incident"] = incident = None

            # Activity: only an *executed* call in the turn the adapter
            # started for this continuation counts -- matched by its
            # continuation_id, not by "a new turn appeared", which could be
            # the user's own next message.
            cont = incident["continuation"] if incident is not None else {}
            if (
                incident is not None
                and incident["status"] == "accepted"
                and not denied
                and corr.continuation_id is not None
                and corr.continuation_id == cont.get("continuation_id")
            ):
                incident["status"] = "active"
                cont.update(activity_at=now, activity_turn_seq=corr.turn_seq,
                            activity_tool_id=call["tool_id"])
                incident["updated_at"] = now
                result["activity"] = dict(incident)

            if kind is None:
                # Success. Releases an uncertain-outcome hold when it was a
                # read on the same toolkit -- that read *is* the status
                # check the hold asked for. It is not counted as progress.
                if call["idempotent"] and call["toolkit"]:
                    task["holds"] = [h for h in task["holds"] if h["toolkit"] != call["toolkit"]]
                if incident is not None:
                    incident["last_seen_at"] = now
                return result

            if outcome == "unknown" and not call["idempotent"]:
                task["holds"].append({
                    "tool_id": call["tool_id"], "toolkit": call["toolkit"],
                    "scopes": sorted(call["scopes"]), "since": now,
                    "until": now + config.uncertain_hold_seconds,
                    "incident_id": None,
                })

            if incident is None:
                incident = {
                    "id": "inc_" + secrets.token_hex(6),
                    "installation": corr.installation, "identity": corr.identity,
                    "profile": corr.profile, "session_id": corr.session_id,
                    "board_id": corr.board_id, "task_id": corr.task_id,
                    "task_generation": corr.task_generation,
                    "turn_id": corr.turn_id, "last_turn_id": corr.turn_id,
                    "last_turn_seq": corr.turn_seq,
                    "status": "open", "kind": kind, "signature": None,
                    "attempts": [], "created_at": now, "updated_at": now,
                    "last_seen_at": now, "reconciles": 0,
                    "cooldown_until": None, "check_done": False,
                    "consultation": {"status": "none"},
                    "continuation": {"status": "none"},
                    "guidance_count": 0, "failures_since_guidance": 0,
                    "outcome": None, "blocker": None,
                }
                data["incidents"][incident["id"]] = incident
                task["open_incident"] = incident["id"]
                result["created"] = True
            for hold in task["holds"]:
                hold["incident_id"] = hold["incident_id"] or incident["id"]
            sig = signature(call["tool_id"], kind, error_text)
            incident["attempts"] = (incident["attempts"] + [{
                "at": now, "tool_id": call["tool_id"], "kind": kind,
                "outcome": "denied" if denied else outcome,
                "reason": call["denial_reason"], "error": error_text,
                "turn_id": corr.turn_id, "turn_seq": corr.turn_seq, "signature": sig,
            }])[-MAX_ATTEMPTS:]
            incident.update(kind=kind, signature=sig, last_turn_id=corr.turn_id,
                            last_turn_seq=corr.turn_seq, updated_at=now, last_seen_at=now)
            incident["failures_since_guidance"] += 1
            result["incident"] = dict(incident)
            result["recoveries"] = task["recoveries"]
            return result

        state = self.store.mutate(_record)
        if state.get("duplicate") or state.get("stale"):
            self._log("duplicate_event" if state.get("duplicate") else "stale_event",
                      task_id=corr.task_id, board_id=corr.board_id, event_id=corr.event_id,
                      installation=corr.installation, reason=state.get("stale"))
            return None
        if "activity" in state:
            inc = state["activity"]
            self._log("continuation_activity", incident_id=inc["id"], task_id=inc["task_id"],
                      installation=inc["installation"],
                      continuation_id=inc["continuation"].get("continuation_id"),
                      turn_seq=corr.turn_seq, tool_id=call["tool_id"])
        incident = state.get("incident")
        if incident is None:
            return None
        if state.get("created"):
            self._log("incident_opened", incident_id=incident["id"], task_id=corr.task_id,
                      board_id=corr.board_id, session_id=corr.session_id,
                      installation=corr.installation, classification=kind,
                      tool_id=call["tool_id"], signature=incident["signature"])
        return await self._decide(corr, incident, state["recoveries"], call)

    async def _decide(
        self, corr: Correlation, incident: dict[str, Any], recoveries: int, call: dict[str, Any]
    ) -> str | None:
        config = self.config
        now = self._clock()
        kind = incident["kind"]
        status = incident["status"]
        inc_id = incident["id"]

        if status in ("continuing", "accepted"):
            # The continuation path owns this incident right now.
            return None

        if kind == KIND_PERMISSION:
            # FR-7.7: one text for every opaque denial reason.
            self._finish(incident, "blocked", "blocked:permission",
                         blocker=f"denied ({call['denial_reason']}) on {call['tool_id']}")
            return self._render(incident, "blocked", _GUIDANCE_PERMISSION)

        if kind == KIND_COOLDOWN or corr.cooldown_until:
            if corr.cooldown_until:
                until = corr.cooldown_until
            else:
                until = now + (call["retry_after"] or config.default_cooldown_seconds)
            until = min(until, now + config.max_cooldown_seconds)
            if status != "cooling" or (incident.get("cooldown_until") or 0) < until:
                self._update(inc_id, status="cooling", cooldown_until=until, check_done=False)
                self._log("cooldown_scheduled", incident_id=inc_id, task_id=corr.task_id,
                          installation=corr.installation, cooldown_until=_iso(until))
            return self._render(
                {**incident, "cooldown_until": until}, "wait_cooldown",
                f"Cooldown in effect until {_iso(until)} (UTC). Do not call this or "
                "related tools again before then, and do not probe. If your turn "
                "ends, Gatekeeper checks once after the cooldown and asks Hermes to "
                "continue this task in this session.",
            )

        if kind == KIND_TIMEOUT:
            return self._render(
                incident, "check_status_first",
                "The previous call's outcome is UNKNOWN -- it may still be running "
                "or may have completed. Query the current state with a read/status "
                "tool before doing anything else. Do not re-run a mutation until "
                "the state shows it did not happen.",
            )

        if incident["failures_since_guidance"] < config.trigger_after:
            return None

        if recoveries >= config.max_recoveries_per_task:
            self._finish(incident, "blocked", "blocked:recovery_budget_exhausted",
                         blocker=self._summary(incident))
            return self._render(incident, "blocked",
                                "Recovery budget for this task is exhausted. Stop retrying "
                                "and report the blocker below to the user.")

        if incident["guidance_count"] >= 1:
            # Guidance (and at most one rescue) was already given and the
            # agent still made no progress: stop instead of looping.
            self._finish(incident, "blocked", "blocked:no_progress_after_guidance",
                         blocker=self._summary(incident))
            return self._render(incident, "blocked",
                                "Recovery guidance did not resolve this. Stop retrying and "
                                "report the blocker below to the user.")

        if not self.store.claim(inc_id, {"open", "guided", "cooling", "active"}, "guided"):
            return None

        # Authoritative task state before spending a recovery.
        status_info = await self._adapter_status(incident)
        if status_info is not None:
            task_state = status_info.get("task")
            if task_state in ("completed", "cancelled", "superseded"):
                self._suppress(incident, str(task_state))
                return None
            progress = status_info.get("last_progress_at")
            if isinstance(progress, (int, float)) and progress > incident["created_at"]:
                # Measurable progress since the incident opened (as the
                # task owner reports it, not as a different argv implies).
                self._finish(incident, "progressed", "progressed")
                return None

        if kind in (KIND_INVALID, KIND_DEPENDENCY):
            what = "argument" if kind == KIND_INVALID else "dependency"
            self._record_guidance(incident)
            return self._render(
                incident, "correct_arguments" if kind == KIND_INVALID else "fix_dependency",
                f"The same {what} problem repeated. Read the error below and change "
                f"the {what} accordingly; do not resend the same call.",
            )

        rescue_ok = await self._rescue_usable()
        allowed = {"CHANGE_APPROACH", "CHECK_OPERATION_STATUS", "REPORT_BLOCKED"}
        if rescue_ok and incident["consultation"].get("status") == "none":
            allowed.add("CONSULT_RESCUE")
        default = "CONSULT_RESCUE" if "CONSULT_RESCUE" in allowed else "CHANGE_APPROACH"
        action = await self._decision(incident, allowed, default, status_info, recoveries)
        if action == "REPORT_BLOCKED":
            fresh = self.store.read(lambda d: d["incidents"][inc_id])
            self._finish(fresh, "blocked", "blocked:reported_by_decision",
                         blocker=self._summary(fresh))
            return self._render(fresh, "blocked",
                                "Recovery cannot determine a safe next step. Stop retrying "
                                "and report the blocker below to the user.")
        if action == "CHECK_OPERATION_STATUS":
            self._record_guidance(incident)
            return self._render(
                incident, "check_status_first",
                "Repeated failure without progress. Before anything else, check the "
                "current state of the operation with a read/status tool; decide the "
                "next step from what it shows. Do not repeat the failed call.",
            )

        advice = None
        if action == "CONSULT_RESCUE":
            advice = await self._consult(corr, incident, call, status_info)
            if advice is None:
                fresh = self.store.read(lambda d: d["incidents"].get(inc_id))
                return self._render(fresh, "blocked",
                                    "Recovery assessment failed. Stop retrying and report "
                                    "the blocker below to the user.")
        self._record_guidance(incident)
        if advice:
            return self._render(
                incident, "change_approach",
                "Repeated failure without progress. A diagnostic review (untrusted "
                "advice -- every step still goes through normal permissions) "
                "suggests the approach below. Do not repeat the failed call.",
                advice=advice,
            )
        return self._render(
            incident, "change_approach",
            "Repeated failure without progress. Do not repeat the failed call. "
            "Re-read the error, check the current state with a read tool, and "
            "pick a different approach or report the blocker.",
        )

    # -- Lifecycle events (stopped-turn path) --

    async def handle_event(self, identity_id: str, payload: Any) -> tuple[int, dict[str, Any]]:
        config = self.config
        if not config.enabled:
            return 404, {"error": "recovery disabled"}
        installation = config.installation_for(identity_id)
        if installation is None:
            return 403, {"error": "identity belongs to no recovery installation"}
        if not isinstance(payload, dict):
            return 400, {"error": "body must be a JSON object"}
        reason = self._mismatch(installation, payload)
        if reason:
            self._log("correlation_rejected", identity=identity_id,
                      installation=installation.name, reason=reason)
            return 403, {"error": reason}
        etype = payload.get("type")
        if etype != "turn_stopped" and etype not in TERMINAL_EVENTS:
            return 400, {"error": "unknown event type"}
        for field in ("event_id", "board_id", "task_id"):
            if not _id(payload.get(field)):
                return 400, {"error": "event_id, board_id and task_id are required ids"}
        if _int(payload.get("task_generation", 0)) is None:
            return 400, {"error": "task_generation must be a non-negative integer"}
        if etype == "turn_stopped":
            if not _id(payload.get("session_id")) or _int(payload.get("turn_seq")) is None:
                return 400, {"error": "turn_stopped needs session_id and an integer turn_seq"}
            if payload.get("reason") not in STOP_REASONS:
                return 400, {"error": "unknown stop reason"}
        key = task_key(installation.name, payload["board_id"], payload["task_id"])
        async with self._lock_for(key):
            return 200, await self._handle_event(installation, key, payload)

    async def _handle_event(
        self, installation: Installation, key: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        now = self._clock()
        etype = payload["type"]
        event_id = payload["event_id"]
        generation = int(payload.get("task_generation", 0))

        def _seen(data: dict[str, Any]) -> dict[str, Any]:
            task = data["tasks"].get(key)
            if task is None:
                if etype == "turn_stopped":
                    return {"task": None}
                task = self._task(data, key, installation.name, payload["board_id"],
                                  payload["task_id"])
            if event_id in task["seen_events"]:
                return {"duplicate": True}
            task["seen_events"] = (task["seen_events"] + [event_id])[-MAX_SEEN_EVENTS:]
            if generation < task["generation"]:
                return {"stale": "older task generation"}
            if generation > task["generation"]:
                self._new_generation(data, task, generation)
            incident = data["incidents"].get(task.get("open_incident") or "")
            if etype in TERMINAL_EVENTS:
                # Only this exact (installation, board, task, generation):
                # a worker's completion never reaches its parent's key.
                task["terminal"] = {"state": TERMINAL_EVENTS[etype], "generation": generation}
                task["holds"] = []
            return {"task": dict(task), "incident": dict(incident) if incident else None}

        state = self.store.mutate(_seen)
        if state.get("duplicate") or state.get("stale"):
            self._log("duplicate_event" if state.get("duplicate") else "stale_event",
                      task_id=payload["task_id"], event_id=event_id,
                      installation=installation.name, reason=state.get("stale"))
            return {"accepted": True, "duplicate": bool(state.get("duplicate")),
                    "action": "none", "reason": state.get("stale")}
        incident = state.get("incident")
        if etype in TERMINAL_EVENTS:
            final = TERMINAL_EVENTS[etype]
            if incident and incident["status"] in ("accepted", "active") and final == "completed":
                self._finish(incident, "resolved", "resolved")
                return {"accepted": True, "action": "resolved"}
            if incident and incident["status"] in OPEN_STATUSES:
                self._suppress(incident, final)
                return {"accepted": True, "action": "suppressed"}
            self._mark_resolved(key, final)
            return {"accepted": True, "action": "none"}
        if incident is None or incident["status"] not in OPEN_STATUSES:
            # v1: a turn that stopped with no Gatekeeper-observed failure
            # has no incident and is not resumed -- documented, not a bug.
            return {"accepted": True, "action": "none",
                    "reason": "no open incident (stop without a Gatekeeper failure is not "
                              "recovered in v1)"}
        if payload["session_id"] != incident["session_id"]:
            return {"accepted": True, "action": "none", "reason": "different session"}
        profile = payload.get("profile")
        if profile is not None and incident.get("profile") not in (None, profile):
            return {"accepted": True, "action": "none", "reason": "different profile"}
        if int(payload["turn_seq"]) < incident["last_turn_seq"]:
            return {"accepted": True, "action": "none", "reason": "older turn"}
        reason = payload["reason"]
        if reason == USER_STOP:
            # An explicit user stop is final for this incident, cooldown or not.
            self._suppress(incident, USER_STOP)
            return {"accepted": True, "action": "suppressed"}
        if incident["status"] in ("continuing", "accepted", "active"):
            return {"accepted": True, "action": "none", "reason": "continuation in progress"}
        cooldown_until = payload.get("cooldown_until")
        if isinstance(cooldown_until, (int, float)) and not isinstance(cooldown_until, bool) \
                and cooldown_until > now:
            until = min(cooldown_until, now + self.config.max_cooldown_seconds)
            self._update(incident["id"], status="cooling", cooldown_until=until, check_done=False,
                         last_turn_seq=int(payload["turn_seq"]))
            self._log("cooldown_scheduled", incident_id=incident["id"], task_id=incident["task_id"],
                      installation=installation.name, cooldown_until=_iso(until), source="event")
            return {"accepted": True, "action": "cooldown_scheduled", "incident_id": incident["id"]}
        if incident["status"] == "cooling" and (incident.get("cooldown_until") or 0) > now:
            return {"accepted": True, "action": "cooldown_pending", "incident_id": incident["id"]}
        if reason not in STUCK_REASONS and incident["status"] != "cooling":
            return {"accepted": True, "action": "none", "reason": f"turn ended: {reason}"}
        self._update(incident["id"], last_turn_seq=int(payload["turn_seq"]))
        result = await self._continue(incident["id"], trigger=f"turn_stopped:{reason}")
        return {"accepted": True, "action": result, "incident_id": incident["id"]}

    def _mark_resolved(self, key: str, final: str) -> None:
        """A completed task whose last incident already counted as recovered."""
        if final != "completed":
            return

        def _apply(data: dict[str, Any]) -> None:
            for inc in data["incidents"].values():
                if task_key(inc["installation"], inc["board_id"], inc["task_id"]) == key \
                        and inc["status"] == "recovered":
                    inc["continuation"]["resolved_at"] = self._clock()
                    inc["outcome"] = "resolved"
        self.store.mutate(_apply)

    # -- Continuation --

    def _ref(self, incident: dict[str, Any]) -> dict[str, Any]:
        """What the adapter validates ownership against, authoritatively."""
        return {
            "profile": incident.get("profile"), "session_id": incident["session_id"],
            "board_id": incident["board_id"], "task_id": incident["task_id"],
            "task_generation": incident.get("task_generation", 0),
        }

    async def _continue(self, inc_id: str, *, trigger: str) -> str:
        config = self.config
        if not self.store.claim(inc_id, {"open", "guided", "cooling"}, "continuing"):
            return "already_claimed"
        incident = self.store.read(lambda d: d["incidents"][inc_id])
        key = task_key(incident["installation"], incident["board_id"], incident["task_id"])
        recoveries = self.store.read(lambda d: d["tasks"][key]["recoveries"])
        if recoveries >= config.max_recoveries_per_task:
            self._finish(incident, "blocked", "blocked:recovery_budget_exhausted",
                         blocker=self._summary(incident))
            return "blocked"
        adapter = self._adapter(config.installations.get(incident["installation"]))
        if adapter is None:
            self._finish(incident, "blocked", "blocked:no_continuation_interface",
                         blocker="no recovery adapter configured for installation "
                                 f"{incident['installation']!r}")
            return "blocked"
        try:
            status = await adapter.status(self._ref(incident))
        except AdapterError as exc:
            outcome = "blocked:session_mapping_failed" if exc.status in (404, 409) \
                else "blocked:adapter_unreachable"
            self._finish(incident, "blocked", outcome, blocker=str(exc))
            return "blocked"
        task_state = status.get("task")
        if task_state in ("completed", "cancelled", "superseded"):
            self._suppress(incident, str(task_state))
            return "suppressed"
        if status.get("stop_reason") == USER_STOP:
            self._suppress(incident, USER_STOP)
            return "suppressed"
        status_seq = _int(status.get("turn_seq"))
        if status.get("turn") == "active" or (
            status_seq is not None and status_seq > incident["last_turn_seq"]
        ):
            # Someone (the agent's own next turn, or the user) is already
            # driving the session; the tool-response path reaches it.
            self._update(inc_id, status="guided", check_done=True)
            self._log("continuation_not_needed", incident_id=inc_id, task_id=incident["task_id"],
                      installation=incident["installation"], trigger=trigger)
            return "turn_active"
        if status.get("turn") not in ("stopped", "exhausted"):
            self._finish(incident, "blocked", "blocked:turn_state_unknown",
                         blocker=f"adapter reported turn={status.get('turn')!r}")
            return "blocked"

        idempotency_key = f"{inc_id}:1"
        self._update(inc_id, continuation={
            "status": "sending", "idempotency_key": idempotency_key, "trigger": trigger,
            "expected_turn_seq": incident["last_turn_seq"], "sent_at": self._clock(),
            "resends": 0, "queries": 0,
        })
        return await self._send_continue(inc_id)

    async def _send_continue(self, inc_id: str) -> str:
        incident = self.store.read(lambda d: d["incidents"][inc_id])
        cont = incident["continuation"]
        adapter = self._adapter(self.config.installations.get(incident["installation"]))
        if adapter is None:
            self._finish(incident, "blocked", "blocked:no_continuation_interface")
            return "blocked"
        payload = {
            **self._ref(incident), "incident_id": inc_id,
            "idempotency_key": cont["idempotency_key"],
            "expected_turn_seq": cont["expected_turn_seq"],
            "guidance": self._continuation_text(incident),
        }
        try:
            response = await adapter.continue_(payload)
        except AdapterError as exc:
            if exc.ambiguous:
                # It may have been processed. Never re-send blindly: the
                # scheduler asks /continuation first.
                self._update(inc_id, continuation={**cont, "status": "uncertain",
                                                   "error": str(exc), "sent_at": self._clock()})
                self._log("continuation_uncertain", incident_id=inc_id,
                          task_id=incident["task_id"], error=str(exc))
                return "uncertain"
            self._finish(incident, "blocked", "blocked:continuation_failed", blocker=str(exc),
                         continuation_status="failed")
            return "blocked"
        return self._apply_continue_response(incident, response)

    def _apply_continue_response(self, incident: dict[str, Any], response: dict[str, Any]) -> str:
        inc_id = incident["id"]
        continuation_id = _id(response.get("continuation_id"))
        if not response.get("accepted"):
            reason = str(response.get("reason") or "adapter declined")[:300]
            if reason in BENIGN_REJECTIONS:
                # A user message (or the agent itself) won the race: nothing
                # to recover, and no recovery spent.
                self._update(inc_id, status="guided", check_done=True,
                             continuation={**incident["continuation"], "status": "superseded",
                                           "reason": reason})
                self._log("continuation_superseded", incident_id=inc_id,
                          task_id=incident["task_id"], reason=reason)
                return "turn_active"
            self._finish(incident, "blocked", "blocked:continuation_rejected", blocker=reason,
                         continuation_status="rejected")
            return "blocked"
        if continuation_id is None:
            self._finish(incident, "blocked", "blocked:continuation_rejected",
                         blocker="adapter accepted without a valid continuation_id",
                         continuation_status="rejected")
            return "blocked"
        key = task_key(incident["installation"], incident["board_id"], incident["task_id"])
        now = self._clock()
        config = self.config

        def _accepted(data: dict[str, Any]) -> None:
            inc = data["incidents"][inc_id]
            inc["status"] = "accepted"
            inc["continuation"].update(
                status="accepted", continuation_id=continuation_id,
                delivery_id=continuation_id, accepted_at=now,
                ack_deadline=now + config.ack_timeout_seconds,
            )
            inc["updated_at"] = now
            data["tasks"][key]["recoveries"] += 1

        self.store.mutate(_accepted)
        self._log("continuation_accepted", incident_id=inc_id, task_id=incident["task_id"],
                  session_id=incident["session_id"], installation=incident["installation"],
                  continuation_id=continuation_id,
                  idempotency_key=incident["continuation"]["idempotency_key"])
        return "continued"

    async def _resolve_uncertain(self, incident: dict[str, Any]) -> None:
        """An ambiguous /continue (timeout, or a crash after 'sending' was
        persisted): ask the adapter what happened before doing anything."""
        inc_id = incident["id"]
        cont = incident["continuation"]
        adapter = self._adapter(self.config.installations.get(incident["installation"]))
        if adapter is None:
            self._finish(incident, "blocked", "blocked:no_continuation_interface")
            return
        if cont.get("queries", 0) >= 3:
            self._finish(incident, "blocked", "blocked:continuation_uncertain",
                         blocker="could not establish whether the continuation was delivered",
                         continuation_status="uncertain")
            return
        self._update(inc_id, continuation={**cont, "queries": cont.get("queries", 0) + 1,
                                           "sent_at": self._clock()})
        try:
            found = await adapter.continuation(self._ref(incident), cont["idempotency_key"])
        except AdapterError:
            return  # try again next tick, bounded by `queries`
        self._log("continuation_queried", incident_id=inc_id, task_id=incident["task_id"],
                  state=found.get("state"))
        if found.get("state") in ("accepted", "started"):
            fresh = self.store.read(lambda d: d["incidents"][inc_id])
            self._apply_continue_response(fresh, {"accepted": True, **found})
        elif found.get("state") == "rejected":
            fresh = self.store.read(lambda d: d["incidents"][inc_id])
            self._apply_continue_response(fresh, {"accepted": False, **found})
        elif found.get("state") == "none" and cont.get("resends", 0) < 1:
            # Never processed: one re-send with the same key, which the
            # adapter's persisted idempotency makes safe.
            self._update(inc_id, continuation={**cont, "resends": cont.get("resends", 0) + 1,
                                               "queries": cont.get("queries", 0) + 1})
            await self._send_continue(inc_id)
        else:
            fresh = self.store.read(lambda d: d["incidents"][inc_id])
            self._finish(fresh, "blocked", "blocked:continuation_failed",
                         blocker=f"continuation state {found.get('state')!r}",
                         continuation_status="failed")

    # -- Scheduler --

    async def tick(self) -> None:
        """One scheduler pass: cooldown checks, ambiguous deliveries,
        acknowledgement/progress deadlines, reconciliation."""
        if not self.enabled:
            return
        config = self.config
        now = self._clock()
        due = self.store.read(lambda d: [dict(i) for i in d["incidents"].values()
                                         if i["status"] in OPEN_STATUSES])
        for incident in due:
            key = task_key(incident["installation"], incident["board_id"], incident["task_id"])
            status = incident["status"]
            async with self._lock_for(key):
                if status == "cooling":
                    if not incident.get("check_done") and (incident.get("cooldown_until") or 0) <= now:
                        self._update(incident["id"], check_done=True)
                        await self._continue(incident["id"], trigger="cooldown_elapsed")
                elif status == "continuing":
                    cont = incident["continuation"]
                    if cont.get("status") in ("sending", "uncertain") and \
                            now - (cont.get("sent_at") or 0) >= config.adapter_timeout_seconds:
                        await self._resolve_uncertain(incident)
                elif status in ("accepted", "active"):
                    await self._follow(incident)
                elif status in ("open", "guided") and \
                        now - incident.get("last_seen_at", incident["updated_at"]) >= \
                        config.reconcile_after_seconds * (1 + incident.get("reconciles", 0)):
                    await self._reconcile(incident)

    async def _follow(self, incident: dict[str, Any]) -> None:
        """After acceptance: started -> activity -> progress -> resolved."""
        config = self.config
        now = self._clock()
        cont = incident["continuation"]
        inc_id = incident["id"]
        if now - (cont.get("polled_at") or 0) >= config.status_poll_seconds:
            self._update(inc_id, continuation={**cont, "polled_at": now})
            status = await self._adapter_status(incident) or {}
            cont = self.store.read(lambda d: d["incidents"][inc_id]["continuation"])
            if status.get("task") == "completed":
                self._finish(incident, "resolved", "resolved")
                return
            if status.get("task") in ("cancelled", "superseded") or status.get("stop_reason") == USER_STOP:
                self._suppress(incident, str(status.get("task") or USER_STOP))
                return
            if not cont.get("started_at") and status.get("continuation_id") == cont.get("continuation_id") \
                    and status.get("turn") == "active":
                cont = {**cont, "started_at": now}
                self._update(inc_id, continuation=cont)
                self._log("continuation_started", incident_id=inc_id, task_id=incident["task_id"],
                          installation=incident["installation"],
                          continuation_id=cont.get("continuation_id"), turn_seq=status.get("turn_seq"))
            progress = status.get("last_progress_at")
            fresh = self.store.read(lambda d: d["incidents"][inc_id])
            if fresh["status"] == "active" and isinstance(progress, (int, float)) \
                    and progress > (cont.get("accepted_at") or now):
                self._update(inc_id, continuation={**cont, "progress_at": progress})
                self._finish(fresh, "recovered", "recovered")
                return
        fresh = self.store.read(lambda d: d["incidents"][inc_id])
        cont = fresh["continuation"]
        if fresh["status"] == "accepted" and now >= (cont.get("ack_deadline") or 0):
            self._finish(fresh, "blocked", "unacknowledged",
                         blocker="continuation accepted but no tool call carrying its "
                                 "continuation_id was executed before the deadline",
                         continuation_status="unacknowledged")
        elif fresh["status"] == "active" and \
                now >= (cont.get("activity_at") or now) + config.progress_timeout_seconds:
            self._finish(fresh, "blocked", "blocked:no_progress_after_continuation",
                         blocker="the resumed turn was active but the task owner reported "
                                 "no progress before the deadline")

    async def _reconcile(self, incident: dict[str, Any]) -> None:
        """No traffic for a while: ask the authoritative source. Covers a
        Hermes crash that could not emit its own stop event."""
        config = self.config
        inc_id = incident["id"]
        if incident.get("reconciles", 0) >= config.max_reconciles:
            return
        self._update(inc_id, reconciles=incident.get("reconciles", 0) + 1, last_seen_at=self._clock())
        status = await self._adapter_status(incident)
        if status is None:
            return
        self._log("reconciled", incident_id=inc_id, task_id=incident["task_id"],
                  turn=status.get("turn"), task=status.get("task"))
        if status.get("task") in ("completed", "cancelled", "superseded"):
            self._suppress(incident, str(status["task"]))
        elif status.get("stop_reason") == USER_STOP:
            self._suppress(incident, USER_STOP)
        elif status.get("turn") in ("stopped", "exhausted") \
                and status.get("stop_reason") in STUCK_REASONS \
                and _int(status.get("turn_seq")) == incident["last_turn_seq"]:
            await self._continue(inc_id, trigger=f"reconciled:{status.get('stop_reason')}")

    async def run_scheduler(self, stop: asyncio.Event | None = None) -> None:
        stop = stop or asyncio.Event()
        await self.startup_checks()
        while not stop.is_set():
            try:
                await self.tick()
            except Exception:
                logger.exception("recovery scheduler tick failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.config.tick_seconds)
            except TimeoutError:
                pass

    async def startup_checks(self) -> None:
        config = self.config
        if not (config.enabled and config.rescue.enabled):
            return
        client = self._rescue_client()
        available = client is not None and await client.model_available()
        self._rescue_checked = ((config.rescue.base_url, config.rescue.model), available)
        self._log("rescue_availability", model=config.rescue.model, available=available)
        if not available:
            logger.warning(
                "Recovery rescue model %r is not listed by %s/models (or the "
                "credential is missing); rescue consultations are disabled.",
                config.rescue.model, config.rescue.base_url,
            )

    # -- Read access (for /recovery/incidents) --

    def incidents_for(self, identity_id: str, task_id: str | None = None) -> list[dict[str, Any]]:
        installation = self.config.installation_for(identity_id)
        if installation is None:
            return []
        return self.store.read(lambda d: [
            {k: i.get(k) for k in (
                "id", "board_id", "task_id", "session_id", "status", "kind", "outcome",
                "cooldown_until", "blocker", "created_at", "updated_at",
            )} | {"consultation_id": i["consultation"].get("id"),
                  "continuation_id": i["continuation"].get("continuation_id"),
                  "delivery_id": i["continuation"].get("delivery_id")}
            for i in d["incidents"].values()
            if i["installation"] == installation.name and (task_id is None or i["task_id"] == task_id)
        ])

    # -- Helpers --

    def _adapter(self, installation: Installation | None) -> HermesAdapter | None:
        if installation is None or not installation.adapter_url or not installation.credential:
            return None
        secret = self._secret(installation.credential)
        if not secret:
            return None
        return HermesAdapter(installation, secret, self.config.adapter_timeout_seconds)

    async def _adapter_status(self, incident: dict[str, Any]) -> dict[str, Any] | None:
        adapter = self._adapter(self.config.installations.get(incident["installation"]))
        if adapter is None:
            return None
        try:
            return await adapter.status(self._ref(incident))
        except AdapterError as exc:
            self._log("adapter_status_failed", incident_id=incident["id"],
                      task_id=incident["task_id"], error=str(exc))
            return None

    def _rescue_client(self) -> RescueClient | None:
        rescue = self.config.rescue
        if not (rescue.enabled and rescue.credential):
            return None
        key = self._secret(rescue.credential)
        return RescueClient(rescue, key) if key else None

    async def _rescue_usable(self) -> bool:
        rescue = self.config.rescue
        if not rescue.enabled:
            return False
        if self._rescue_checked is None or self._rescue_checked[0] != (rescue.base_url, rescue.model):
            await self.startup_checks()
        if not (self._rescue_checked and self._rescue_checked[1]):
            return False
        now = self._clock()
        self._rescue_calls = [t for t in self._rescue_calls if t > now - 3600]
        return len(self._rescue_calls) < rescue.max_per_hour

    async def _consult(
        self, corr: Correlation, incident: dict[str, Any], call: dict[str, Any],
        status_info: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        inc_id = incident["id"]
        if incident["consultation"].get("status") != "none":
            return incident["consultation"].get("recommendation")
        client = self._rescue_client()
        consultation_id = "rsc_" + secrets.token_hex(6)
        if client is None:
            self._update(inc_id, consultation={"id": consultation_id, "status": "skipped",
                                               "error": "rescue credential missing"})
            return None
        self._rescue_calls.append(self._clock())
        self._update(inc_id, consultation={"id": consultation_id, "status": "running"})
        self._log("rescue_started", incident_id=inc_id, task_id=corr.task_id,
                  consultation_id=consultation_id, model=self.config.rescue.model)
        tools = []
        if self._tools_for is not None:
            try:
                tools = self._tools_for(corr.identity)
            except Exception:
                tools = []
        status_info = status_info or {}
        context = {
            "objective": self._redact(str(status_info.get("objective") or "unknown"))[:1500],
            "acceptance_criteria": self._redact(
                str(status_info.get("acceptance_criteria") or "unknown"))[:1000],
            "task_state": self._redact(str(status_info.get("task_state") or "unknown"))[:1000],
            "execution_status": {"turn": status_info.get("turn"), "task": status_info.get("task")},
            "failed_attempts": [
                {k: a[k] for k in ("tool_id", "kind", "outcome", "error")}
                for a in incident["attempts"]
            ],
            "available_tools": tools[:60],
            "constraints": [
                "Every call passes Gatekeeper's permission checks; denied actions stay denied.",
                "Operations with an UNKNOWN outcome must be status-checked, not re-run.",
                "You cannot execute anything; the agent decides and acts.",
            ],
        }
        started = self._clock()
        try:
            advice = await client.consult(context)
        except RescueError as exc:
            self._update(inc_id, consultation={"id": consultation_id, "status": "failed",
                                               "error": str(exc),
                                               "duration_s": round(self._clock() - started, 2)})
            fresh = self.store.read(lambda d: d["incidents"][inc_id])
            self._finish(fresh, "blocked", "blocked:rescue_failed", blocker=str(exc))
            self._log("rescue_failed", incident_id=inc_id, task_id=corr.task_id,
                      consultation_id=consultation_id, error=str(exc))
            return None
        advice = {k: (self._redact(v) if isinstance(v, str) else v) for k, v in advice.items()}
        self._update(inc_id, consultation={"id": consultation_id, "status": "ok",
                                           "recommendation": advice,
                                           "duration_s": round(self._clock() - started, 2)})
        self._log("rescue_completed", incident_id=inc_id, task_id=corr.task_id,
                  consultation_id=consultation_id)
        return advice

    async def _decision(
        self, incident: dict[str, Any], allowed: set[str], default: str,
        status_info: dict[str, Any] | None, recoveries: int,
    ) -> str:
        """Ask the optional decision provider; return the action to apply.

        The fixed rules already ran (permission, cooldown, user stop,
        budgets, duplicates, unknown outcomes never reach this point), and
        `allowed` is what they still permit. A proposal outside it, invalid
        output, a timeout or an unavailable provider all fall back to
        `default`. Shadow mode asks and logs, and still applies `default`.
        """
        cfg = self.config.decision
        inc_id = incident["id"]
        if not cfg.enabled or incident.get("decision"):
            return default
        now = self._clock()
        self._decision_calls = [t for t in self._decision_calls if t > now - 3600]
        provider = self._decision_backend()
        record: dict[str, Any] = {"provider": cfg.provider, "model": cfg.model, "mode": cfg.mode,
                                  "default": default, "allowed": sorted(allowed)}
        if provider is None or len(self._decision_calls) >= cfg.max_per_hour:
            record.update(proposed=None, accepted=default,
                          fallback="provider unavailable" if provider is None else "hourly limit")
        else:
            self._decision_calls.append(now)
            request = {
                "incident_id": inc_id,
                "classification": incident["kind"],
                "failed_attempts": [
                    {k: a[k] for k in ("tool_id", "kind", "outcome", "error")}
                    for a in incident["attempts"]
                ],
                "task_status": {k: (status_info or {}).get(k) for k in ("turn", "task", "turn_seq")},
                "operation_status": "unknown" if incident["kind"] == KIND_TIMEOUT else "failed",
                "remaining_budget": {
                    "recoveries": max(0, self.config.max_recoveries_per_task - recoveries),
                    "rescue_available": "CONSULT_RESCUE" in allowed,
                },
                "allowed_actions": sorted(allowed),
            }
            started = time.monotonic()
            proposed = rationale = None
            evidence: list[str] = []
            fallback = None
            try:
                async with asyncio.timeout(cfg.timeout_seconds):
                    out = await provider.decide(request, max_tokens=cfg.max_tokens)
                proposed, rationale, evidence = self._validate_decision(out)
            except TimeoutError:
                fallback = "timeout"
            except Exception as exc:
                fallback = f"error: {type(exc).__name__}"
            if fallback is None and proposed is None:
                fallback = "invalid output"
            accepted = default
            if proposed is not None and proposed not in allowed:
                fallback = f"rejected: {proposed} conflicts with fixed rules"
            elif proposed is not None and cfg.mode == "active":
                accepted = proposed
            record.update(
                proposed=proposed, accepted=accepted, fallback=fallback,
                rationale=self._redact(rationale)[:300] if rationale else None,
                evidence=[self._redact(e)[:200] for e in evidence],
                latency_ms=int((time.monotonic() - started) * 1000),
                provider_version=getattr(provider, "version", None),
            )
        self._update(inc_id, decision=record)
        # Provider, model, proposed and accepted action -- never the request.
        self._log("decision", incident_id=inc_id, task_id=incident["task_id"],
                  provider=record["provider"], model=record["model"],
                  provider_version=record.get("provider_version"), mode=record["mode"],
                  proposed=record.get("proposed"), accepted=record["accepted"],
                  fallback=record.get("fallback"), latency_ms=record.get("latency_ms"))
        return str(record["accepted"])

    @staticmethod
    def _validate_decision(out: Any) -> tuple[str | None, str | None, list[str]]:
        if not isinstance(out, dict) or out.get("action") not in DECISION_ACTIONS:
            return None, None, []
        rationale = out.get("rationale")
        evidence = out.get("evidence") or []
        if not isinstance(rationale, str) or not isinstance(evidence, list) \
                or not all(isinstance(e, str) for e in evidence):
            return None, None, []
        return str(out["action"]), rationale, evidence[:5]

    def _decision_backend(self) -> Any:
        cfg = self.config.decision
        cache_key = (cfg.provider, cfg.model)
        if self._decision_provider is None or self._decision_provider[0] != cache_key:
            factory = DECISION_PROVIDERS.get(cfg.provider or "")
            backend = None
            if factory is not None:
                try:
                    backend = factory(cfg, self._secret)
                except Exception:
                    logger.exception("decision provider %r could not be built", cfg.provider)
            self._decision_provider = (cache_key, backend)
        return self._decision_provider[1]

    def _record_guidance(self, incident: dict[str, Any]) -> None:
        inc_id = incident["id"]
        key = task_key(incident["installation"], incident["board_id"], incident["task_id"])

        def _apply(data: dict[str, Any]) -> None:
            inc = data["incidents"][inc_id]
            inc["guidance_count"] += 1
            inc["failures_since_guidance"] = 0
            inc["updated_at"] = self._clock()
            data["tasks"][key]["recoveries"] += 1

        self.store.mutate(_apply)
        self._log("guidance_issued", incident_id=inc_id, task_id=incident["task_id"],
                  installation=incident["installation"], classification=incident["kind"])

    def _update(self, inc_id: str, **fields: Any) -> None:
        def _apply(data: dict[str, Any]) -> None:
            inc = data["incidents"].get(inc_id)
            if inc is not None:
                inc.update(fields)
                inc["updated_at"] = self._clock()
        self.store.mutate(_apply)

    def _finish(
        self, incident: dict[str, Any], status: str, outcome: str, *,
        blocker: str | None = None, continuation_status: str | None = None,
    ) -> None:
        inc_id = incident["id"]
        key = task_key(incident["installation"], incident["board_id"], incident["task_id"])

        def _apply(data: dict[str, Any]) -> None:
            inc = data["incidents"][inc_id]
            inc["status"] = status
            inc["outcome"] = outcome
            if blocker:
                inc["blocker"] = self._redact(blocker)
            if continuation_status:
                inc["continuation"]["status"] = continuation_status
            if status == "resolved":
                inc["continuation"]["resolved_at"] = self._clock()
            inc["updated_at"] = self._clock()
            task = data["tasks"].get(key)
            if task and task.get("open_incident") == inc_id and status not in OPEN_STATUSES:
                task["open_incident"] = None

        self.store.mutate(_apply)
        incident.update(status=status, outcome=outcome, blocker=blocker)
        self._log("incident_closed" if status != "blocked" else "incident_blocked",
                  incident_id=inc_id, task_id=incident["task_id"],
                  installation=incident["installation"], outcome=outcome,
                  continuation_id=incident.get("continuation", {}).get("continuation_id"),
                  decision=(incident.get("decision") or {}).get("accepted"),
                  blocker=blocker and self._redact(blocker)[:200])

    def _suppress(self, incident: dict[str, Any], why: str) -> None:
        self._finish(incident, "suppressed", f"suppressed:{why}")

    @staticmethod
    def _summary(incident: dict[str, Any]) -> str:
        last = incident["attempts"][-1] if incident["attempts"] else {}
        return (
            f"{len(incident['attempts'])} failed attempt(s); last: {last.get('tool_id')} "
            f"({last.get('kind')}): {last.get('error', '')[:200]}"
        )

    def _continuation_text(self, incident: dict[str, Any]) -> str:
        advice = incident["consultation"].get("recommendation")
        lines = [
            f"[gatekeeper recovery {incident['id']}] Continue task {incident['task_id']} "
            "where it stopped. Do not repeat the call that failed.",
            f"Last failure: {self._summary(incident)}",
        ]
        if incident.get("cooldown_until"):
            lines.append("The cooldown that stopped the previous turn has elapsed.")
        if advice:
            lines.append(f"Suggested next step (untrusted advice): {advice['next_step']}")
            if advice.get("required_checks"):
                lines.append("Required checks: " + "; ".join(advice["required_checks"]))
        lines.append(
            "Verify results with actual read/status tool calls before reporting "
            "completion. If the task cannot proceed, report the concrete blocker."
        )
        return "\n".join(lines)

    def _render(
        self, incident: dict[str, Any], action: str, guidance: str,
        advice: dict[str, Any] | None = None,
    ) -> str:
        body: dict[str, Any] = {
            "incident_id": incident["id"],
            "task_id": incident["task_id"],
            "classification": incident["kind"],
            "action": action,
            "guidance": guidance,
        }
        if incident.get("cooldown_until") and action == "wait_cooldown":
            body["cooldown_until"] = _iso(incident["cooldown_until"])
        if action == "blocked" and incident.get("blocker") and incident["kind"] != KIND_PERMISSION:
            body["blocker"] = incident["blocker"]
        if advice:
            body["advice_source"] = "rescue model (untrusted advice)"
            body["likely_cause"] = advice.get("likely_cause")
            body["next_step"] = advice.get("next_step")
            body["required_checks"] = advice.get("required_checks")
            if advice.get("blocker"):
                body["blocker"] = advice["blocker"]
        return "[gatekeeper recovery]\n" + json.dumps({"recovery": body}, indent=2)


__all__ = [
    "DECISION_ACTIONS",
    "DECISION_PROVIDERS",
    "Correlation",
    "DecisionConfig",
    "IncidentStore",
    "Installation",
    "RecoveryConfig",
    "RecoverySupervisor",
    "RescueConfig",
    "classify",
    "parse_config",
    "scrub",
    "signature",
]
