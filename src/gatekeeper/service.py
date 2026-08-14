"""Der Aufrufpfad (REQUIREMENTS.md §2).

Jeder Aufruf durchlaeuft dieselben Schichten in derselben Reihenfolge:
Authentifizierung, Autorisierung, Registry, Validierung, argv-Bau, Executor,
Audit. Nichts umgeht diese Kette -- es gibt genau einen Weg zur Ausfuehrung.
"""

from __future__ import annotations

import dataclasses
import os
from collections import Counter
from typing import Any

from . import execute, validate
from .audit import AuditLog
from .catalog import Catalog, ToolDef, load_catalog
from .errors import Denied, DenialReason
from .identity import Identity, load_identities
from .ratelimit import RateLimiter
from .tier1 import Tier1, load_tier1


@dataclasses.dataclass(slots=True)
class ToolView:
    """Was ein Agent von einem Tool zu sehen bekommt."""

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
        docker_host: str | None = None,
    ) -> None:
        self.tier1 = tier1
        self.catalog = catalog
        self.audit = audit
        self.docker_host = docker_host
        self.locks = execute.ResourceLocks()
        self.limiter = RateLimiter(tier1.rate_limits)
        self.metrics: Counter[tuple[str, str, str]] = Counter()
        self.executor_ready: dict[str, bool] = {}

    # -- Registry ---------------------------------------------------------

    def visible_tools(self, identity: Identity) -> list[ToolView]:
        """FR-1.4: pro Identitaet gefiltert.

        Ein Agent sieht ausschliesslich, was er auch aufrufen darf. Nicht
        sichtbare Tools existieren fuer ihn nicht -- und weil `tools/call`
        Ablehnungen nach FR-7.7 nicht unterscheidbar beantwortet, laesst sich
        der Rest auch nicht erraten.
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

    # -- Aufruf -----------------------------------------------------------

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
        # Bewusst minimal: der Kindprozess erbt nicht die Umgebung von
        # gatekeeper, damit dort liegende Geheimnisse nicht in fremden
        # Prozessen landen.
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

            # FR-4.12 vor der Rechtepruefung: eine geschuetzte Ressource bleibt
            # gesperrt, auch wenn das Rechteprofil sie abdecken wuerde.
            validate.check_protected(scopes, toolkit)

            for scope in scopes:
                if not identity.covers_scope(scope):
                    raise Denied(
                        DenialReason.SCOPE_MISMATCH,
                        f"Scope {scope!r} is not covered by the profile",
                    )

            argv = validate.build_argv(tool, values, toolkit)
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

        lock_key = scopes[0] if scopes else tool.id
        async with self.locks.get(lock_key):
            result = await execute.run(
                argv,
                timeout_seconds=min(tool.timeout_seconds, toolkit.max_timeout_seconds),
                max_output_bytes=min(tool.max_output_bytes, toolkit.max_output_bytes),
                idempotent=tool.idempotent,
                env=self._environment(toolkit.executor),
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

    # -- Betrieb ----------------------------------------------------------

    async def probe_executors(self) -> dict[str, bool]:
        """Erreichbarkeit je Executor fuer /health/ready (NFR-9).

        `live` und `ready` sind verschiedene Aussagen: ein gatekeeper ohne
        Docker-Socket laeuft, kann aber nichts ausrichten.

        Fuer `local` wird nur geprueft, ob die Binaries vorhanden und ausfuehrbar
        sind. Ein beliebiges Programm ohne Argumente zu starten waere als
        Gesundheitspruefung untauglich: es kann haengen, Nebenwirkungen haben
        oder - wie ein Interpreter - auf Eingabe warten. Nur `docker` bekommt
        einen echten Aufruf, weil dort die Verbindung zum Socket gemeint ist
        und `version` nachweislich nichts veraendert.
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
            seen[toolkit.executor] = False
        self.executor_ready = seen
        return seen

    def render_metrics(self) -> str:
        """Prometheus-Textformat (NFR-3a) -- ohne zusaetzliche Abhaengigkeit."""
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
        """Lädt alle drei Konfigurationsdateien neu. Gibt None bei Erfolg,
        sonst eine Fehlermeldung. Der alte Zustand bleibt bei Fehlern erhalten.

        Nur Ebene 1 (toolkits.yaml) braucht das: Ebene 2 (tools.yaml,
        identities.yaml) lädt die Oberfläche beim Schreiben selbst nach.
        Aber ein SIGHUP soll alles auf einmal neu laden, damit ein
        handeditierter Stand ohne Neustart wirksam wird.
        """
        import logging
        logger = logging.getLogger("gatekeeper")

        # Alles laden, bevor irgendetwas ausgetauscht wird. Schlägt eine Datei
        # fehl, bleibt der alte Zustand unangetastet.
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

        # Atomar tauschen. Der Limiter wird neu aufgesetzt, damit geänderte
        # Rate-Limits sofort greifen und alte Fenster nicht mitgeschleppt werden.
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
