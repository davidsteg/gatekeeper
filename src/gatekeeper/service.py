"""The call path (REQUIREMENTS.md §2).

Every call passes through the same layers in the same order:
authentication, authorization, registry, validation, argv construction,
executor, audit. Nothing bypasses this chain -- there is exactly one way
to execution.
"""

from __future__ import annotations

import dataclasses
import os
from collections import Counter
from typing import Any

from . import execute, execute_http, execute_truenas, validate
from .audit import AuditLog
from .catalog import Catalog, ToolDef, load_catalog
from .credentials import CredentialStore
from .errors import Denied, DenialReason
from .identity import Identity, load_identities
from .ratelimit import RateLimiter
from .tier1 import Tier1, load_tier1


@dataclasses.dataclass(slots=True)
class ToolView:
    """What an agent sees of a tool."""

    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool
    idempotent: bool


class Service:
    def __init__(
        self,
        *,
        tier1: Tier1,
        catalog: Catalog,
        audit: AuditLog,
        credentials: CredentialStore | None = None,
        docker_host: str | None = None,
    ) -> None:
        self.tier1 = tier1
        self.catalog = catalog
        self.audit = audit
        self.credentials = credentials
        self.docker_host = docker_host
        self.locks = execute.ResourceLocks()
        self.limiter = RateLimiter(tier1.rate_limits)
        self.metrics: Counter[tuple[str, str, str]] = Counter()
        self.executor_ready: dict[str, bool] = {}

    # -- Registry ---------------------------------------------------------

    def visible_tools(self, identity: Identity) -> list[ToolView]:
        """FR-1.4: filtered per identity.

        An agent sees exclusively what it is allowed to call. Non-visible
        tools do not exist for it -- and because `tools/call` answers
        rejections indistinguishably per FR-7.7, the rest cannot be
        guessed either.
        """
        views = []
        for tool in self.catalog.tools.values():
            if not tool.enabled or not identity.may_call(tool.id):
                continue
            views.append(
                ToolView(
                    name=tool.id,
                    title=tool.title,
                    description=tool.agent_description(),
                    input_schema=tool.input_schema(),
                    read_only=tool.category == "read",
                    idempotent=tool.idempotent,
                )
            )
        return sorted(views, key=lambda v: v.name)

    # -- Call --------------------------------------------------------------

    def _authorize(self, identity: Identity, tool_id: str) -> ToolDef:
        tool = self.catalog.tools.get(tool_id)
        if tool is None:
            raise Denied(DenialReason.UNKNOWN_TOOL, f"Tool {tool_id!r} does not exist")
        if not tool.enabled:
            raise Denied(DenialReason.TOOL_DISABLED, f"Tool {tool_id!r} is disabled")
        if not identity.may_call(tool.id):
            raise Denied(
                DenialReason.NOT_GRANTED,
                f"Identity {identity.id!r} has no right to {tool_id!r}",
            )
        return tool

    def _environment(self, executor: str) -> dict[str, str] | None:
        if executor != "docker" or not self.docker_host:
            return None
        # Deliberately minimal: the child process does not inherit the
        # gatekeeper environment, so that secrets located there do not
        # end up in foreign processes.
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        env["DOCKER_HOST"] = self.docker_host
        return env

    async def call(
        self, identity: Identity, tool_id: str, arguments: dict[str, Any]
    ) -> execute.Result:
        tool: ToolDef | None = None
        scopes: list[str] = []
        values: dict[str, str] = {}
        try:
            tool = self._authorize(identity, tool_id)
            toolkit = self.tier1.toolkit(tool.toolkit)

            if not self.limiter.check(identity.id, tool.category):
                raise Denied(
                    DenialReason.RATE_LIMITED,
                    f"Rate limit for category {tool.category!r} reached",
                )

            values = validate.resolve_parameters(tool, arguments)
            scopes = validate.resolve_scopes(tool, values)

            # FR-4.12 before the permission check: a protected resource
            # remains locked even if the permission profile would cover it.
            validate.check_protected(scopes, toolkit)

            for scope in scopes:
                if not identity.covers_scope(scope):
                    raise Denied(
                        DenialReason.SCOPE_MISMATCH,
                        f"Scope {scope!r} is not covered by the profile",
                    )

            # The executor-specific request is built here, inside the same
            # try/except as everything else -- a bad parameter surfaces as
            # a normal "denied" audit entry regardless of which executor
            # the toolkit uses (FR-8.7 is the HTTP counterpart of FR-5.4,
            # checked at the same point in the pipeline).
            argv: list[str] = []
            http_request: tuple[str, str, dict[str, str], dict[str, str] | None] | None = None
            rpc_call: tuple[str, dict[str, str]] | None = None
            if toolkit.executor in ("docker", "local"):
                argv = validate.build_argv(tool, values, toolkit)
            elif toolkit.executor == "http":
                http_request = validate.build_http_request(tool, values, toolkit)
            elif toolkit.executor == "truenas":
                rpc_call = validate.build_rpc_call(tool, values, toolkit)
        except Denied as denial:
            self.metrics[(tool_id, identity.id, "denied")] += 1
            self.audit.call(
                identity=identity.id,
                tool_id=tool_id,
                tool_version=tool.version if tool else None,
                parameters=arguments,
                scopes=scopes,
                outcome="denied",
                denial_reason=denial.reason.value,
                detail=denial.detail,
            )
            raise

        timeout_seconds = min(tool.timeout_seconds, toolkit.max_timeout_seconds)
        max_output_bytes = min(tool.max_output_bytes, toolkit.max_output_bytes)

        lock_key = scopes[0] if scopes else tool.id
        async with self.locks.get(lock_key):
            if toolkit.executor in ("docker", "local"):
                result = await execute.run(
                    argv,
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                    idempotent=tool.idempotent,
                    env=self._environment(toolkit.executor),
                )
            elif toolkit.executor == "http":
                assert http_request is not None
                method, path, query, body = http_request
                result = await execute_http.run(
                    method=method, path=path, query=query, body=body,
                    toolkit=toolkit, credentials=self.credentials,
                    timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
                    idempotent=tool.idempotent, redact=self.audit.redact,
                )
            else:
                assert toolkit.executor == "truenas" and rpc_call is not None
                rpc_method, params = rpc_call
                result = await execute_truenas.run(
                    method=rpc_method, params=params, toolkit=toolkit,
                    credentials=self.credentials,
                    timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
                    idempotent=tool.idempotent, redact=self.audit.redact,
                )

        self.metrics[(tool_id, identity.id, result.outcome)] += 1
        self.audit.call(
            identity=identity.id,
            tool_id=tool.id,
            tool_version=tool.version,
            parameters={k: v for k, v in values.items()},
            scopes=scopes,
            outcome=result.outcome,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            truncated=result.truncated,
        )
        return result

    # -- Operation ---------------------------------------------------------

    async def probe_executors(self) -> dict[str, bool]:
        """Reachability per executor for /health/ready (NFR-9).

        `live` and `ready` are different statements: a gatekeeper without
        a Docker socket runs but cannot accomplish anything.

        For `local`, only the binaries are checked for presence and
        executability. Starting an arbitrary program without arguments
        would be unsuitable as a health check: it can hang, have side
        effects, or -- like an interpreter -- wait for input. Only
        `docker` gets a real call, because there the connection to the
        socket is what matters, and `version` demonstrably changes nothing.
        """
        seen: dict[str, bool] = {}
        for toolkit in self.tier1.toolkits.values():
            if toolkit.executor in seen:
                continue
            if toolkit.executor == "local":
                seen["local"] = all(
                    os.path.isfile(b) and os.access(b, os.X_OK)
                    for b in toolkit.binaries
                )
                continue
            if toolkit.executor == "docker":
                try:
                    result = await execute.run(
                        [toolkit.binaries[0], "version", "--format", "{{.Server.Version}}"],
                        timeout_seconds=5,
                        max_output_bytes=4096,
                        idempotent=True,
                        env=self._environment("docker"),
                    )
                    seen["docker"] = result.outcome == execute.OUTCOME_OK
                except Denied:
                    seen["docker"] = False
                continue
            if toolkit.executor == "http":
                # TCP-connect only, no HTTP request: unlike `docker version`,
                # there is no safe, universal "does nothing" request across
                # arbitrary APIs. Reaching the validated IP:port is what
                # /health/ready can honestly claim.
                seen["http"] = await execute_http.probe(toolkit)
                continue
            if toolkit.executor == "truenas":
                seen["truenas"] = await execute_truenas.probe(toolkit)
                continue
            seen[toolkit.executor] = False
        self.executor_ready = seen
        return seen

    def render_metrics(self) -> str:
        """Prometheus text format (NFR-3a) -- without additional dependencies."""
        lines = [
            "# HELP gatekeeper_tool_calls_total Calls by tool, identity and outcome",
            "# TYPE gatekeeper_tool_calls_total counter",
        ]
        for (tool_id, identity_id, outcome), count in sorted(self.metrics.items()):
            lines.append(
                f'gatekeeper_tool_calls_total{{tool="{tool_id}",'
                f'identity="{identity_id}",outcome="{outcome}"}} {count}'
            )
        lines.append("# HELP gatekeeper_executor_ready Executor reachable (1/0)")
        lines.append("# TYPE gatekeeper_executor_ready gauge")
        for executor, ready in sorted(self.executor_ready.items()):
            lines.append(
                f'gatekeeper_executor_ready{{executor="{executor}"}} {1 if ready else 0}'
            )
        return "\n".join(lines) + "\n"

    # -- Reload -------------------------------------------------------------

    def reload_config(
        self,
        *,
        toolkits_path: str,
        tools_path: str,
        identities_path: str,
    ) -> str | None:
        """Reloads all three configuration files. Returns None on success,
        otherwise an error message. The old state is preserved on errors.

        Only Tier 1 (toolkits.yaml) needs this: Tier 2 (tools.yaml,
        identities.yaml) is reloaded by the UI itself on write.
        But a SIGHUP should reload everything at once, so that a
        hand-edited state takes effect without a restart.
        """
        import logging
        logger = logging.getLogger("gatekeeper")

        # Load everything before anything is swapped out. If one file
        # fails, the old state remains untouched.
        try:
            tier1 = load_tier1(toolkits_path)
        except Exception as exc:
            return f"toolkits.yaml: {exc}"

        try:
            catalog = load_catalog(tools_path, tier1)
        except Exception as exc:
            return f"tools.yaml: {exc}"

        try:
            identities = load_identities(identities_path)
        except Exception as exc:
            return f"identities.yaml: {exc}"

        # Atomically swap. The limiter is reinitialized so that changed
        # rate limits take effect immediately and old windows are not carried over.
        self.tier1 = tier1
        self.catalog = catalog
        self.limiter = RateLimiter(tier1.rate_limits)

        logger.info(
            "Configuration reloaded: %d toolkits, %d tools, %d identities",
            len(tier1.toolkits),
            len(catalog.tools),
            len(identities.identities),
        )
        for violation in catalog.disabled_by_tier1:
            logger.warning("Definition disabled by Tier 1 violation: %s", violation)
        return None