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

**Boundaries that carry the security:**

* The *installation* (homelab / personal / ...) is derived from the
  authenticated identity via Tier 1 config, never from a client field. A
  client that claims a different installation is ignored, and a
  continuation only ever goes to the adapter of the incident's own
  installation -- the two orchestrators cannot resume each other.
* Denials that FR-7.7 keeps opaque to the agent stay opaque here: the
  guidance for "not granted", "scope mismatch", "protected" and "unknown
  tool" is one identical text. The precise reason is in the incident store
  and the audit log, which only the operator reads.
* The rescue model is diagnostic only: no tools, at most one consultation
  per incident, a hard timeout and token budget, and its answer is passed
  on marked as untrusted advice.
* Everything bounded: per-incident (one rescue, one continuation),
  per-task (`max_recoveries_per_task` across incidents, so a slightly
  different error string cannot start an endless loop), cooldowns capped at
  `max_cooldown_seconds`, one status check per cooldown.

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

#: Shape for every client-supplied correlation id. The same character set
#: the opencode executor accepts for a session id, plus `.`/`:`/`@`, which
#: Hermes session ids are known to contain. Anything else is not a
#: correlation, it is noise, and is dropped rather than stored.
_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")

#: Turn stop reasons that mean "stuck", as opposed to a turn that ended on
#: its own terms (a final reply) or was ended by the user (interrupted).
#: Only these let an un-cooled incident be continued.
STUCK_REASONS = frozenset({"exhausted", "breaker_open", "error", "timeout"})


@dataclasses.dataclass(frozen=True, slots=True)
class Installation:
    name: str
    #: Gatekeeper identities belonging to this installation. An identity
    #: belongs to at most one -- checked at load.
    identities: tuple[str, ...]
    #: Base URL of the client-side recovery adapter (status / continue).
    #: None: guidance through tool responses only, no continuation.
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
    ack_timeout_seconds: int = 300
    tick_seconds: float = 5.0
    adapter_timeout_seconds: float = 10.0
    installations: dict[str, Installation] = dataclasses.field(default_factory=dict)
    rescue: RescueConfig = dataclasses.field(default_factory=RescueConfig)

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
    """The top-level `recovery:` block of toolkits.yaml. Absent -> disabled."""
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

    return RecoveryConfig(
        enabled=bool(raw.get("enabled", False)),
        state_file=str(raw["state_file"]) if raw.get("state_file") else None,
        trigger_after=_positive(raw, "trigger_after", defaults.trigger_after, where),
        max_recoveries_per_task=_positive(
            raw, "max_recoveries_per_task", defaults.max_recoveries_per_task, where
        ),
        max_cooldown_seconds=_positive(
            raw, "max_cooldown_seconds", defaults.max_cooldown_seconds, where
        ),
        default_cooldown_seconds=_positive(
            raw, "default_cooldown_seconds", defaults.default_cooldown_seconds, where
        ),
        uncertain_hold_seconds=_positive(
            raw, "uncertain_hold_seconds", defaults.uncertain_hold_seconds, where
        ),
        ack_timeout_seconds=_positive(
            raw, "ack_timeout_seconds", defaults.ack_timeout_seconds, where
        ),
        tick_seconds=_positive(raw, "tick_seconds", defaults.tick_seconds, where),
        adapter_timeout_seconds=_positive(
            raw, "adapter_timeout_seconds", defaults.adapter_timeout_seconds, where
        ),
        installations=installations,
        rescue=rescue,
    )


# -- Correlation --------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Correlation:
    """Which Hermes session/task/turn a call belongs to.

    `installation` is *derived* from the authenticated identity; the ids
    come from the client's `_meta.hermes` and are only shape-checked.
    """

    installation: str
    identity: str
    session_id: str
    task_id: str
    turn_id: str
    event_id: str | None = None
    #: Client-reported cooldown (e.g. its own open breaker), epoch seconds.
    cooldown_until: float | None = None


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
#: The FR-7.7 subset: the agent must not learn which of these it was.
_OPAQUE_REASONS = frozenset({
    "unknown_tool", "tool_disabled", "not_granted", "scope_mismatch",
    "protected_resource",
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
#: echo an env var). Scrubbed before anything is stored or sent.
#: Each pattern's group 1 is kept, the rest of the match becomes `***`.
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
OPEN_STATUSES = frozenset({
    "open", "guided", "cooling", "continuing", "awaiting_ack",
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
        def _claim(data: dict[str, Any]) -> bool:
            incident = data["incidents"].get(incident_id)
            if incident is None or incident["status"] not in allowed:
                return False
            incident["status"] = to
            incident["updated_at"] = time.time()
            return True
        with self._lock:
            ok = _claim(self._data)
            if ok:
                self._save()
            return ok


def task_key(installation: str, task_id: str) -> str:
    return f"{installation}:{task_id}"


# -- Outbound clients ---------------------------------------------------------


class AdapterError(Exception):
    pass


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
    docs/ARCHITECTURE.md, "Recovery supervisor")."""

    def __init__(self, installation: Installation, secret: str, timeout: float) -> None:
        assert installation.adapter_url
        self.installation = installation
        self._secret = secret
        self._timeout = timeout

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        import httpx

        body = json.dumps(payload, sort_keys=True).encode()
        url = f"{self.installation.adapter_url}/{path}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False) as client:
                response = await client.post(url, content=body, headers=signed_headers(self._secret, body))
        except httpx.HTTPError as exc:
            raise AdapterError(f"{path}: {type(exc).__name__}") from None
        if response.status_code != 200:
            raise AdapterError(f"{path}: HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError:
            raise AdapterError(f"{path}: response is not JSON") from None
        if not isinstance(data, dict):
            raise AdapterError(f"{path}: response is not an object")
        return data

    async def status(self, session_id: str, task_id: str) -> dict[str, Any]:
        return await self._post("status", {"session_id": session_id, "task_id": task_id})

    async def continue_(self, **payload: Any) -> dict[str, Any]:
        return await self._post("continue", payload)


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
        config = self.config
        if not config.enabled or not isinstance(meta, dict):
            return None
        hermes = meta.get("hermes")
        if not isinstance(hermes, dict):
            return None
        installation = config.installation_for(identity_id)
        if installation is None:
            return None
        claimed = hermes.get("installation")
        if claimed is not None and claimed != installation.name:
            self._log(
                "correlation_rejected", identity=identity_id,
                installation=installation.name, claimed=str(claimed)[:64],
            )
            return None
        ids = {k: hermes.get(k) for k in ("session_id", "task_id", "turn_id")}
        if not all(isinstance(v, str) and _ID_RE.fullmatch(v) for v in ids.values()):
            return None
        event_id = hermes.get("event_id")
        if not (isinstance(event_id, str) and _ID_RE.fullmatch(event_id)):
            event_id = None
        cooldown_until = hermes.get("cooldown_until")
        if not isinstance(cooldown_until, (int, float)) or isinstance(cooldown_until, bool):
            cooldown_until = None
        return Correlation(
            installation=installation.name, identity=identity_id,
            event_id=event_id, cooldown_until=cooldown_until, **ids,  # type: ignore[arg-type]
        )

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
        key = task_key(corr.installation, corr.task_id)

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
        key = task_key(corr.installation, corr.task_id)
        async with self._lock_for(key):
            try:
                return await self._observe(
                    corr, identity=identity, tool_id=tool_id, toolkit=toolkit,
                    idempotent=idempotent, scopes=scopes, outcome=outcome,
                    denial_reason=denial_reason, agent_text=agent_text,
                    exit_code=exit_code, retry_after=retry_after,
                )
            except Exception:
                logger.exception("recovery observe failed; the call result stands as is")
                return None

    async def _observe(self, corr: Correlation, **call: Any) -> str | None:
        config = self.config
        now = self._clock()
        key = task_key(corr.installation, corr.task_id)
        outcome: str = call["outcome"]
        denied = call["denial_reason"] is not None
        kind = None if outcome == "ok" and not denied else classify(
            outcome, call["denial_reason"], call["exit_code"]
        )
        error_text = self._redact(call["agent_text"] or "")

        def _record(data: dict[str, Any]) -> dict[str, Any]:
            task = data["tasks"].setdefault(key, {
                "installation": corr.installation, "task_id": corr.task_id,
                "recoveries": 0, "open_incident": None, "seen_events": [],
                "holds": [], "terminal": None,
            })
            if corr.event_id:
                if corr.event_id in task["seen_events"]:
                    return {"duplicate": True}
                task["seen_events"] = (task["seen_events"] + [corr.event_id])[-MAX_SEEN_EVENTS:]
            if task.get("terminal"):
                return {"terminal": task["terminal"]}
            task["session_id"] = corr.session_id
            task["latest_turn_id"] = corr.turn_id
            task["holds"] = [h for h in task["holds"] if h["until"] > now]
            result: dict[str, Any] = {}

            incident = data["incidents"].get(task["open_incident"] or "")
            if incident is not None and incident["status"] not in OPEN_STATUSES:
                task["open_incident"] = incident = None

            # Acknowledgement: only an *executed* call in a turn other than
            # the one that stopped counts. A denied call, or the agent
            # merely saying it will check, is not progress.
            if (
                incident is not None
                and incident["status"] == "awaiting_ack"
                and not denied
                and corr.turn_id != incident["continuation"].get("from_turn_id")
            ):
                incident["status"] = "recovered"
                incident["outcome"] = "recovered"
                incident["continuation"]["status"] = "acknowledged"
                incident["continuation"]["ack_turn_id"] = corr.turn_id
                incident["continuation"]["ack_tool_id"] = call["tool_id"]
                incident["continuation"]["acknowledged_at"] = now
                incident["updated_at"] = now
                result["acknowledged"] = dict(incident)
                task["open_incident"] = incident = None

            if kind is None:
                # Success. Releases an uncertain-outcome hold when it was a
                # read on the same toolkit -- that read *is* the status
                # check the hold asked for. It is not counted as progress.
                if call["idempotent"] and call["toolkit"]:
                    task["holds"] = [h for h in task["holds"] if h["toolkit"] != call["toolkit"]]
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
                    "session_id": corr.session_id, "task_id": corr.task_id,
                    "turn_id": corr.turn_id, "last_turn_id": corr.turn_id,
                    "status": "open", "kind": kind, "signature": None,
                    "attempts": [], "created_at": now, "updated_at": now,
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
                "turn_id": corr.turn_id, "signature": sig,
            }])[-MAX_ATTEMPTS:]
            incident["kind"] = kind
            incident["signature"] = sig
            incident["last_turn_id"] = corr.turn_id
            incident["session_id"] = corr.session_id
            incident["updated_at"] = now
            incident["failures_since_guidance"] += 1
            result["incident"] = dict(incident)
            result["recoveries"] = task["recoveries"]
            return result

        state = self.store.mutate(_record)
        if state.get("duplicate"):
            self._log("duplicate_event", task_id=corr.task_id, event_id=corr.event_id,
                      installation=corr.installation)
            return None
        if "acknowledged" in state:
            inc = state["acknowledged"]
            self._log("continuation_acknowledged", incident_id=inc["id"], task_id=inc["task_id"],
                      installation=inc["installation"],
                      delivery_id=inc["continuation"].get("delivery_id"),
                      turn_id=corr.turn_id, tool_id=call["tool_id"])
        incident = state.get("incident")
        if incident is None:
            return None
        if state.get("created"):
            self._log("incident_opened", incident_id=incident["id"], task_id=corr.task_id,
                      session_id=corr.session_id, installation=corr.installation,
                      classification=kind, tool_id=call["tool_id"], signature=incident["signature"])
        return await self._decide(corr, incident, state["recoveries"], call)

    async def _decide(
        self, corr: Correlation, incident: dict[str, Any], recoveries: int, call: dict[str, Any]
    ) -> str | None:
        config = self.config
        now = self._clock()
        kind = incident["kind"]
        status = incident["status"]
        inc_id = incident["id"]

        if status in ("continuing", "awaiting_ack"):
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

        if not self.store.claim(inc_id, {"open", "guided", "cooling"}, "guided"):
            return None

        # Authoritative task state before spending a recovery.
        status_info = await self._adapter_status(incident)
        if status_info is not None:
            task_state = status_info.get("task")
            if task_state in ("completed", "cancelled", "superseded"):
                self._suppress(incident, task_state)
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

        advice = None
        if await self._rescue_usable():
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
        claimed = payload.get("installation")
        if claimed is not None and claimed != installation.name:
            self._log("correlation_rejected", identity=identity_id,
                      installation=installation.name, claimed=str(claimed)[:64])
            return 403, {"error": "installation mismatch"}
        etype = payload.get("type")
        task_id = payload.get("task_id")
        event_id = payload.get("event_id")
        if etype not in ("turn_stopped", "task_completed", "task_cancelled", "task_superseded"):
            return 400, {"error": "unknown event type"}
        for value in (task_id, event_id):
            if not (isinstance(value, str) and _ID_RE.fullmatch(value)):
                return 400, {"error": "task_id and event_id are required ids"}
        key = task_key(installation.name, str(task_id))
        async with self._lock_for(key):
            return 200, await self._handle_event(installation, key, payload)

    async def _handle_event(
        self, installation: Installation, key: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        now = self._clock()
        etype = payload["type"]
        event_id = payload["event_id"]

        def _seen(data: dict[str, Any]) -> dict[str, Any]:
            task = data["tasks"].get(key)
            if task is None:
                return {"task": None}
            if event_id in task["seen_events"]:
                return {"duplicate": True}
            task["seen_events"] = (task["seen_events"] + [event_id])[-MAX_SEEN_EVENTS:]
            incident = data["incidents"].get(task.get("open_incident") or "")
            if etype != "turn_stopped":
                task["terminal"] = etype.removeprefix("task_")
                task["holds"] = []
            return {"task": dict(task), "incident": dict(incident) if incident else None}

        state = self.store.mutate(_seen)
        if state.get("duplicate"):
            self._log("duplicate_event", task_id=payload["task_id"], event_id=event_id,
                      installation=installation.name)
            return {"accepted": True, "duplicate": True, "action": "none"}
        incident = state.get("incident")
        if etype != "turn_stopped":
            if incident and incident["status"] in OPEN_STATUSES:
                self._suppress(incident, etype.removeprefix("task_"))
            return {"accepted": True, "action": "suppressed" if incident else "none"}
        if incident is None or incident["status"] not in OPEN_STATUSES:
            # A turn that stopped with nothing failing is not stuck as far
            # as Gatekeeper knows -- silence is not a stall.
            return {"accepted": True, "action": "none"}
        session_id = payload.get("session_id")
        if session_id is not None and session_id != incident["session_id"]:
            return {"accepted": True, "action": "none", "reason": "different session"}
        turn_id = payload.get("turn_id")
        if turn_id is not None and turn_id != incident["last_turn_id"]:
            return {"accepted": True, "action": "none", "reason": "stale turn"}
        reason = str(payload.get("reason") or "")
        cooldown_until = payload.get("cooldown_until")
        if reason == "interrupted":
            self._suppress(incident, "interrupted_by_user")
            return {"accepted": True, "action": "suppressed"}
        if isinstance(cooldown_until, (int, float)) and not isinstance(cooldown_until, bool) \
                and cooldown_until > now:
            until = min(cooldown_until, now + self.config.max_cooldown_seconds)
            self._update(incident["id"], status="cooling", cooldown_until=until, check_done=False)
            self._log("cooldown_scheduled", incident_id=incident["id"], task_id=incident["task_id"],
                      installation=installation.name, cooldown_until=_iso(until), source="event")
            return {"accepted": True, "action": "cooldown_scheduled", "incident_id": incident["id"]}
        if incident["status"] == "cooling" and (incident.get("cooldown_until") or 0) > now:
            return {"accepted": True, "action": "cooldown_pending", "incident_id": incident["id"]}
        if reason not in STUCK_REASONS and incident["status"] != "cooling":
            return {"accepted": True, "action": "none", "reason": f"turn ended: {reason or 'unspecified'}"}
        result = await self._continue(incident["id"], trigger=f"turn_stopped:{reason}")
        return {"accepted": True, "action": result, "incident_id": incident["id"]}

    async def _continue(self, inc_id: str, *, trigger: str) -> str:
        config = self.config
        if not self.store.claim(inc_id, {"open", "guided", "cooling"}, "continuing"):
            return "already_claimed"
        incident = self.store.read(lambda d: d["incidents"][inc_id])
        key = task_key(incident["installation"], incident["task_id"])
        recoveries = self.store.read(lambda d: d["tasks"][key]["recoveries"])
        if recoveries >= config.max_recoveries_per_task:
            self._finish(incident, "blocked", "blocked:recovery_budget_exhausted",
                         blocker=self._summary(incident))
            return "blocked"
        installation = config.installations.get(incident["installation"])
        adapter = self._adapter(installation)
        if adapter is None:
            self._finish(incident, "blocked", "blocked:no_continuation_interface",
                         blocker="no recovery adapter configured for installation "
                                 f"{incident['installation']!r}")
            return "blocked"
        try:
            status = await adapter.status(incident["session_id"], incident["task_id"])
        except AdapterError as exc:
            self._finish(incident, "blocked", "blocked:adapter_unreachable", blocker=str(exc))
            return "blocked"
        task_state = status.get("task")
        if task_state in ("completed", "cancelled", "superseded"):
            self._suppress(incident, task_state)
            return "suppressed"
        if status.get("turn") == "active":
            # The agent is already working; the tool-response path reaches it.
            self._update(inc_id, status="guided", check_done=True)
            self._log("continuation_not_needed", incident_id=inc_id, task_id=incident["task_id"],
                      installation=incident["installation"], trigger=trigger)
            return "turn_active"
        if status.get("turn") not in ("stopped", "exhausted"):
            self._finish(incident, "blocked", "blocked:turn_state_unknown",
                         blocker=f"adapter reported turn={status.get('turn')!r}")
            return "blocked"

        idempotency_key = f"{inc_id}:1"
        guidance = self._continuation_text(incident)
        self._update(inc_id, continuation={
            "status": "sending", "idempotency_key": idempotency_key, "trigger": trigger,
            "from_turn_id": incident["last_turn_id"], "sent_at": self._clock(),
        })
        try:
            response = await adapter.continue_(
                session_id=incident["session_id"], task_id=incident["task_id"],
                incident_id=inc_id, idempotency_key=idempotency_key, guidance=guidance,
            )
        except AdapterError as exc:
            self._finish(incident, "blocked", "blocked:continuation_failed", blocker=str(exc),
                         continuation_status="failed")
            return "blocked"
        delivery_id = str(response.get("delivery_id") or "")[:128] or None
        if not response.get("accepted"):
            self._finish(incident, "blocked", "blocked:continuation_rejected",
                         blocker=str(response.get("reason") or "adapter declined")[:300],
                         continuation_status="rejected", delivery_id=delivery_id)
            return "blocked"

        def _accepted(data: dict[str, Any]) -> None:
            inc = data["incidents"][inc_id]
            inc["status"] = "awaiting_ack"
            inc["continuation"].update(status="accepted", delivery_id=delivery_id,
                                       ack_deadline=self._clock() + config.ack_timeout_seconds)
            inc["updated_at"] = self._clock()
            data["tasks"][key]["recoveries"] += 1

        self.store.mutate(_accepted)
        self._log("continuation_sent", incident_id=inc_id, task_id=incident["task_id"],
                  session_id=incident["session_id"], installation=incident["installation"],
                  delivery_id=delivery_id, idempotency_key=idempotency_key, trigger=trigger)
        return "continued"

    # -- Scheduler --

    async def tick(self) -> None:
        """One scheduler pass: due cooldown checks and acknowledgement deadlines."""
        if not self.enabled:
            return
        now = self._clock()
        due = self.store.read(lambda d: [
            dict(i) for i in d["incidents"].values()
            if (i["status"] == "cooling" and not i.get("check_done")
                and (i.get("cooldown_until") or 0) <= now)
            or (i["status"] == "awaiting_ack")
        ])
        for incident in due:
            key = task_key(incident["installation"], incident["task_id"])
            async with self._lock_for(key):
                if incident["status"] == "cooling":
                    self._update(incident["id"], check_done=True)
                    await self._continue(incident["id"], trigger="cooldown_elapsed")
                else:
                    await self._check_ack(incident)

    async def _check_ack(self, incident: dict[str, Any]) -> None:
        cont = incident["continuation"]
        now = self._clock()
        if not cont.get("started"):
            adapter = self._adapter(self.config.installations.get(incident["installation"]))
            if adapter is not None:
                try:
                    status = await adapter.status(incident["session_id"], incident["task_id"])
                except AdapterError:
                    status = {}
                if status.get("turn") == "active" and status.get("turn_id") not in (
                    None, cont.get("from_turn_id")
                ):
                    self._update(incident["id"], continuation={**cont, "started": True,
                                                               "started_turn_id": status.get("turn_id")})
                    self._log("continuation_started", incident_id=incident["id"],
                              task_id=incident["task_id"], installation=incident["installation"],
                              delivery_id=cont.get("delivery_id"), turn_id=status.get("turn_id"))
                    return
        if now >= (cont.get("ack_deadline") or 0):
            fresh = self.store.read(lambda d: d["incidents"].get(incident["id"]))
            if fresh and fresh["status"] == "awaiting_ack":
                self._finish(fresh, "blocked", "unacknowledged",
                             blocker="continuation accepted but no tool call was executed "
                                     "in a new turn before the acknowledgement deadline",
                             continuation_status="unacknowledged")

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
                "id", "task_id", "session_id", "status", "kind", "outcome",
                "cooldown_until", "blocker", "created_at", "updated_at",
            )} | {"consultation_id": i["consultation"].get("id"),
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
            return await adapter.status(incident["session_id"], incident["task_id"])
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

    def _record_guidance(self, incident: dict[str, Any]) -> None:
        inc_id = incident["id"]
        key = task_key(incident["installation"], incident["task_id"])

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
        delivery_id: str | None = None,
    ) -> None:
        inc_id = incident["id"]
        key = task_key(incident["installation"], incident["task_id"])

        def _apply(data: dict[str, Any]) -> None:
            inc = data["incidents"][inc_id]
            inc["status"] = status
            inc["outcome"] = outcome
            if blocker:
                inc["blocker"] = self._redact(blocker)
            if continuation_status:
                inc["continuation"]["status"] = continuation_status
            if delivery_id:
                inc["continuation"]["delivery_id"] = delivery_id
            inc["updated_at"] = self._clock()
            task = data["tasks"].get(key)
            if task and task.get("open_incident") == inc_id and status not in OPEN_STATUSES:
                task["open_incident"] = None

        self.store.mutate(_apply)
        incident.update(status=status, outcome=outcome, blocker=blocker)
        self._log("incident_closed" if status != "blocked" else "incident_blocked",
                  incident_id=inc_id, task_id=incident["task_id"],
                  installation=incident["installation"], outcome=outcome,
                  delivery_id=delivery_id, blocker=blocker and self._redact(blocker)[:200])

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
        if incident["status"] == "cooling" or incident.get("cooldown_until"):
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
    "Correlation",
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
