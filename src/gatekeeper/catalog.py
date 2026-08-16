"""Tool definitions and their validation against Tier 1 (REQUIREMENTS.md §7).

In stage 1 the catalog is a static file. From stage 3 the admin API is
added -- the definition model and the checks here remain unchanged,
only who writes changes.
"""

from __future__ import annotations

import dataclasses
import os
import re
from typing import Any

import yaml

from .errors import ConfigError, Tier1Violation, read_config_file
from .tier1 import Tier1, Toolkit

#: Placeholders in argv, derived and scope templates.
PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

#: Tool IDs follow `<toolkit>.<action>` (FR-5.1b).
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
        """Computed by the server, not settable by the agent (FR-5.5)."""
        return self.derived is not None

    def json_schema(self) -> dict[str, Any]:
        """Schema fragment for `tools/list`."""
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
        """Only the parameters settable by the agent."""
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
        """Description for the agent.

        Non-idempotent tools are explicitly marked (FR-6.10):
        a model that knows this repeats less blindly after a timeout.
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

    # FR-5.7: There is no unvalidated free-text parameter. Only derived
    # values may go without a pattern, because the server builds them itself.
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
    """FR-4.6: validation against Tier 1 -- at load time and again at execution time.

    Doubled, because Tier 1 may have been tightened by a redeploy,
    while older definitions still sit in the catalog.
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

    # FR-4.5: A tool may stay below the toolkit limits, never exceed them.
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
    try:
        toolkit = tier1.toolkit(toolkit_name)
    except ConfigError as exc:
        # Treat as a Tier 1 violation, not a syntax error: if a toolkit
        # is removed during redeploy, its tools should be disabled
        # (FR-4.7) and not prevent startup. Otherwise, removing a
        # toolkit would be a way to bring the service down.
        raise Tier1Violation(f"{where}: {exc}") from exc

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

    # Every placeholder must point to a declared parameter. A typo
    # in the template would otherwise only surface at runtime -- and
    # then land as an unresolvable placeholder in the command.
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
    """Public entry point for a single definition.

    The admin API (stage 3) and the UI must take exactly the same path as
    startup: the same syntax check, the same Tier 1 check. If there were
    a second, more lenient path, the boundary would be merely a recommendation.
    """
    return _parse_tool(spec, tier1)


@dataclasses.dataclass(slots=True)
class Catalog:
    tools: dict[str, ToolDef]
    disabled_by_tier1: list[str]
    #: The unmodified YAML sections in file order. Necessary to avoid
    #: writing back through `ToolDef` on save -- that would be
    #: lossy (comments, field order, unknown fields).
    raw: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    #: Definitions that violate Tier 1: raw version plus reason. They remain
    #: visible so they can be repaired in the UI instead of being lost.
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
    """Loads the seed catalog.

    FR-4.7: definitions that violate the current Tier 1 are
    logged and disabled -- not silently tolerated. With
    `strict=True` startup aborts instead (for CI).

    A missing file is not an error but the state after
    installation: gatekeeper ships no catalog; tools are created in the
    UI. The caller logs this -- a mistyped path should
    not pass as an "empty catalog" without anyone noticing.
    """
    if not os.path.exists(path):
        return Catalog(tools={}, disabled_by_tier1=[], raw=[], rejected=[])

    raw = yaml.safe_load(read_config_file(path)) or {}

    entries = raw.get("tools")
    if entries is None:
        # `tools:` without content is an empty catalog, not a syntax error.
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