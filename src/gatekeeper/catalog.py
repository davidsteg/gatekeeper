"""Tool-Definitionen und ihre Pruefung gegen Ebene 1 (REQUIREMENTS.md §7).

In Stufe 1 ist der Katalog eine statische Datei. Ab Stufe 3 kommt die
Admin-API dazu -- das Definitionsmodell und die Pruefungen hier bleiben dann
unveraendert, es aendert sich nur, wer schreibt.
"""

from __future__ import annotations

import dataclasses
import os
import re
from typing import Any

import yaml

from .errors import ConfigError, Tier1Violation
from .tier1 import Tier1, Toolkit

#: Platzhalter in argv-, derived- und scope-Templates.
PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

#: Tool-IDs folgen `<toolkit>.<aktion>` (FR-5.1b).
TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")

CATEGORIES = frozenset({"read", "write", "write_external"})
PARAM_TYPES = frozenset({"string", "enum", "integer", "path", "boolean"})


@dataclasses.dataclass(frozen=True, slots=True)
class Parameter:
    name: str
    type: str
    description: str
    required: bool = False
    pattern: re.Pattern[str] | None = None
    values: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    derived: str | None = None
    must_resolve_under: str | None = None
    flag: str | None = None

    @property
    def is_derived(self) -> bool:
        """Vom Server berechnet, vom Agenten nicht setzbar (FR-5.5)."""
        return self.derived is not None

    def json_schema(self) -> dict[str, Any]:
        """Schema-Fragment fuer `tools/list`."""
        if self.type == "integer":
            schema: dict[str, Any] = {"type": "integer"}
            if self.minimum is not None:
                schema["minimum"] = self.minimum
            if self.maximum is not None:
                schema["maximum"] = self.maximum
        elif self.type == "boolean":
            schema = {"type": "boolean"}
        elif self.type == "enum":
            schema = {"type": "string", "enum": list(self.values)}
        else:
            schema = {"type": "string"}
            if self.pattern is not None:
                schema["pattern"] = self.pattern.pattern
        schema["description"] = self.description
        return schema


@dataclasses.dataclass(frozen=True, slots=True)
class ToolDef:
    id: str
    toolkit: str
    version: int
    title: str
    description: str
    category: str
    idempotent: bool
    enabled: bool
    binary: str
    argv: tuple[str, ...]
    parameters: dict[str, Parameter]
    required_scopes: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int

    @property
    def agent_parameters(self) -> dict[str, Parameter]:
        """Nur die vom Agenten setzbaren Parameter."""
        return {n: p for n, p in self.parameters.items() if not p.is_derived}

    def input_schema(self) -> dict[str, Any]:
        agent_params = self.agent_parameters
        return {
            "type": "object",
            "properties": {n: p.json_schema() for n, p in agent_params.items()},
            "required": sorted(n for n, p in agent_params.items() if p.required),
            "additionalProperties": False,
        }

    def agent_description(self) -> str:
        """Beschreibung fuer den Agenten.

        Nicht-idempotente Tools werden ausdruecklich gekennzeichnet (FR-6.10):
        ein Modell, das das weiss, wiederholt seltener blind nach einem Timeout.
        """
        parts = [self.description]
        if not self.idempotent:
            parts.append(
                "NOT IDEMPOTENT: calling again repeats the effect. After a "
                "timeout the outcome is unknown -- do not retry without "
                "checking the state first."
            )
        if self.category == "write_external":
            parts.append("Has externally visible effects and cannot be undone.")
        return " ".join(parts)


def _placeholders(template: str) -> set[str]:
    return set(PLACEHOLDER_RE.findall(template))


def _parse_parameter(name: str, spec: dict[str, Any], where: str) -> Parameter:
    if not isinstance(spec, dict):
        raise ConfigError(f"{where}: parameter {name!r} expects a mapping")

    ptype = spec.get("type")
    if ptype not in PARAM_TYPES:
        raise ConfigError(
            f"{where}: parameter {name!r} has unknown type {ptype!r} "
            f"(allowed: {sorted(PARAM_TYPES)})"
        )

    pattern = None
    if raw_pattern := spec.get("pattern"):
        try:
            pattern = re.compile(raw_pattern)
        except re.error as exc:
            raise ConfigError(
                f"{where}: parameter {name!r} has an invalid pattern: {exc}"
            ) from exc

    derived = spec.get("derived")

    # FR-5.7: Es gibt keinen unvalidierten Freitext-Parameter. Nur abgeleitete
    # Werte duerfen ohne Pattern auskommen, weil der Server sie selbst baut.
    if ptype == "string" and pattern is None and derived is None:
        raise ConfigError(
            f"{where}: parameter {name!r} is a string without 'pattern'. "
            "Unvalidated free-text parameters are not permitted (FR-5.7)."
        )
    if ptype == "enum" and not spec.get("values"):
        raise ConfigError(f"{where}: parameter {name!r} is an enum without 'values'")
    if ptype == "path":
        if derived is None:
            raise ConfigError(
                f"{where}: parameter {name!r} is a path without 'derived'. "
                "Paths are built by the server, never supplied by the agent."
            )
        if not spec.get("must_resolve_under"):
            raise ConfigError(
                f"{where}: parameter {name!r} is a path without 'must_resolve_under'"
            )

    return Parameter(
        name=name,
        type=ptype,
        description=str(spec.get("description", "")),
        required=bool(spec.get("required", False)),
        pattern=pattern,
        values=tuple(str(v) for v in spec.get("values", ())),
        minimum=spec.get("minimum"),
        maximum=spec.get("maximum"),
        derived=derived,
        must_resolve_under=spec.get("must_resolve_under"),
        flag=spec.get("flag"),
    )


def _validate_against_tier1(tool: ToolDef, toolkit: Toolkit) -> None:
    """FR-4.6: Pruefung gegen Ebene 1 -- beim Laden und erneut bei Ausfuehrung.

    Doppelt, weil sich Ebene 1 durch einen Redeploy verschaerft haben kann,
    waehrend im Katalog noch aeltere Definitionen liegen.
    """
    where = f"tool {tool.id!r}"
    try:
        toolkit.check_binary(tool.binary)
    except ConfigError as exc:
        raise Tier1Violation(str(exc)) from exc

    if denied := toolkit.check_args(list(tool.argv)):
        raise Tier1Violation(
            f"{where}: argv template contains denied argument {denied!r}"
        )

    for param in tool.parameters.values():
        if param.must_resolve_under:
            try:
                toolkit.check_path_root(param.must_resolve_under)
            except ConfigError as exc:
                raise Tier1Violation(f"{where}: {exc}") from exc

    # FR-4.5: Ein Tool darf die Toolkit-Grenzen unterschreiten, nie ueberschreiten.
    if tool.timeout_seconds > toolkit.max_timeout_seconds:
        raise Tier1Violation(
            f"{where}: timeout_seconds={tool.timeout_seconds} exceeds the "
            f"toolkit maximum {toolkit.max_timeout_seconds}"
        )
    if tool.max_output_bytes > toolkit.max_output_bytes:
        raise Tier1Violation(
            f"{where}: max_output_bytes={tool.max_output_bytes} exceeds the "
            f"toolkit maximum {toolkit.max_output_bytes}"
        )


def _parse_tool(spec: dict[str, Any], tier1: Tier1) -> ToolDef:
    if not isinstance(spec, dict):
        raise ConfigError("tools.yaml: every entry must be a mapping")

    tool_id = spec.get("id")
    if not isinstance(tool_id, str) or not TOOL_ID_RE.match(tool_id):
        raise ConfigError(
            f"Tool ID {tool_id!r} does not match the scheme <toolkit>.<action>"
        )
    where = f"tool {tool_id!r}"

    toolkit_name = spec.get("toolkit")
    if not isinstance(toolkit_name, str):
        raise ConfigError(f"{where}: field 'toolkit' is missing")
    if not tool_id.startswith(f"{toolkit_name}."):
        raise ConfigError(
            f"{where}: ID prefix does not match toolkit {toolkit_name!r}"
        )
    toolkit = tier1.toolkit(toolkit_name)

    category = spec.get("category")
    if category not in CATEGORIES:
        raise ConfigError(
            f"{where}: category={category!r} is unknown (allowed: {sorted(CATEGORIES)})"
        )

    binary = spec.get("binary")
    if not isinstance(binary, str):
        raise ConfigError(f"{where}: field 'binary' is missing")

    raw_argv = spec.get("argv", [])
    if not isinstance(raw_argv, list) or any(not isinstance(a, str) for a in raw_argv):
        raise ConfigError(f"{where}: 'argv' must be a list of strings")

    parameters = {
        name: _parse_parameter(name, pspec, where)
        for name, pspec in (spec.get("parameters") or {}).items()
    }

    scopes = tuple(str(s) for s in (spec.get("required_scopes") or ()))

    # Jeder Platzhalter muss auf einen deklarierten Parameter zeigen. Ein Tippfehler
    # im Template wuerde sonst erst zur Laufzeit auffallen -- und dann als
    # unaufloesbarer Platzhalter im Befehl landen.
    declared = set(parameters)
    for template in (*raw_argv, *scopes, *(p.derived or "" for p in parameters.values())):
        for placeholder in _placeholders(template):
            if placeholder not in declared:
                raise ConfigError(
                    f"{where}: template references unknown parameter "
                    f"{placeholder!r}"
                )

    tool = ToolDef(
        id=tool_id,
        toolkit=toolkit_name,
        version=int(spec.get("version", 1)),
        title=str(spec.get("title", tool_id)),
        description=str(spec.get("description", "")),
        category=category,
        idempotent=bool(spec.get("idempotent", False)),
        enabled=bool(spec.get("enabled", False)),
        binary=binary,
        argv=tuple(raw_argv),
        parameters=parameters,
        required_scopes=scopes,
        timeout_seconds=int(spec.get("timeout_seconds", 30)),
        max_output_bytes=int(spec.get("max_output_bytes", 65536)),
    )
    _validate_against_tier1(tool, toolkit)
    return tool


def parse_tool_spec(spec: dict[str, Any], tier1: Tier1) -> ToolDef:
    """Oeffentlicher Einstieg fuer eine einzelne Definition.

    Die Admin-API (Stufe 3) und das UI muessen exakt denselben Weg nehmen wie
    der Start: dieselbe Syntaxpruefung, dieselbe Ebene-1-Pruefung. Gaebe es
    einen zweiten, milderen Pfad, waere die Grenze nur noch eine Empfehlung.
    """
    return _parse_tool(spec, tier1)


@dataclasses.dataclass(slots=True)
class Catalog:
    tools: dict[str, ToolDef]
    disabled_by_tier1: list[str]
    #: Die unveraenderten YAML-Abschnitte in Dateireihenfolge. Notwendig, um
    #: beim Speichern nicht ueber `ToolDef` zurueckzuschreiben -- das waere
    #: verlustbehaftet (Kommentare, Feldreihenfolge, unbekannte Felder).
    raw: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    #: Definitionen, die Ebene 1 verletzen: Rohfassung plus Grund. Sie bleiben
    #: sichtbar, damit man sie im UI reparieren kann statt sie zu verlieren.
    rejected: list[tuple[dict[str, Any], str]] = dataclasses.field(default_factory=list)

    def get(self, tool_id: str) -> ToolDef | None:
        tool = self.tools.get(tool_id)
        if tool is None or not tool.enabled:
            return None
        return tool

    def raw_of(self, tool_id: str) -> dict[str, Any] | None:
        for spec in self.raw:
            if spec.get("id") == tool_id:
                return spec
        return None


def load_catalog(path: str, tier1: Tier1, *, strict: bool = False) -> Catalog:
    """Laedt den Seed-Katalog.

    FR-4.7: Definitionen, die gegen die aktuelle Ebene 1 verstossen, werden
    protokolliert und deaktiviert -- nicht stillschweigend toleriert. Mit
    `strict=True` bricht der Start stattdessen ab (fuer CI).

    Eine fehlende Datei ist kein Fehler, sondern der Zustand nach der
    Installation: gatekeeper liefert keinen Katalog mit, Tools legt man in der
    Oberflaeche an. Der Aufrufer protokolliert das -- ein vertippter Pfad soll
    nicht als "leerer Katalog" durchgehen, ohne dass es jemand sieht.
    """
    if not os.path.exists(path):
        return Catalog(tools={}, disabled_by_tier1=[], raw=[], rejected=[])

    with open(path, encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    entries = raw.get("tools")
    if entries is None:
        # `tools:` ohne Inhalt ist ein leerer Katalog, kein Syntaxfehler.
        entries = []
    if not isinstance(entries, list):
        raise ConfigError("tools.yaml: section 'tools' is missing or not a list")

    tools: dict[str, ToolDef] = {}
    disabled: list[str] = []
    rejected: list[tuple[dict[str, Any], str]] = []
    for spec in entries:
        try:
            tool = _parse_tool(spec, tier1)
        except Tier1Violation as exc:
            if strict:
                raise
            disabled.append(str(exc))
            rejected.append((spec if isinstance(spec, dict) else {}, str(exc)))
            continue
        if tool.id in tools:
            raise ConfigError(f"Duplicate tool ID {tool.id!r}")
        tools[tool.id] = tool

    return Catalog(
        tools=tools,
        disabled_by_tier1=disabled,
        raw=[s for s in entries if isinstance(s, dict)],
        rejected=rejected,
    )
