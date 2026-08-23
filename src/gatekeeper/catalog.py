"""Tool definitions and their validation against Tier 1 (REQUIREMENTS.md §7).

In stage 1 the catalog is a static file. From stage 3 the admin API is
added -- the definition model and the checks here remain unchanged,
only who writes changes.
"""

from __future__ import annotations

import dataclasses
import os
import re
from datetime import UTC, datetime
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
    parameters: dict[str, Parameter]
    required_scopes: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int

    # -- `docker`/`local` executors -----------------------------------
    binary: str | None = None
    argv: tuple[str, ...] = ()

    # -- `http` executor (FR-8.5 to FR-8.7) ----------------------------
    #: Scheme/host are never here -- they live exclusively on the toolkit
    #: (FR-8.5). `query_template` is a flat string->string map. `body_template`
    #: supports nested structures (dict/list/str) so APIs that expect a
    #: JSON body like `{"data":{"collection":...}}` can be expressed —
    #: every leaf string is a template resolved by `{param}` substitution,
    #: so FR-8.7 still holds at the value level.
    http_method: str | None = None
    path_template: str | None = None
    query_template: dict[str, str] = dataclasses.field(default_factory=dict)
    body_template: dict[str, Any] | list[Any] | str | None = None

    # -- `truenas` executor (FR-8.3a-f) --------------------------------
    #: JSON-RPC method name. Not agent-suppliable -- fixed per tool, exactly
    #: like `binary` for the argv executors.
    rpc_method: str | None = None
    params_template: dict[str, str] | None = None

    # -- Multi-destination (FR-8.3h) ------------------------------------
    #: Set only on the destination-qualified copies produced by
    #: `_expand_tool` (id = "<toolkit>.<action>@<destination>"). None on
    #: the single ToolDef a toolkit with no declared destinations gets,
    #: exactly as before this field existed.
    destination: str | None = None

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


def _validate_ceilings(tool: ToolDef, toolkit: Toolkit, where: str) -> None:
    """FR-4.5: A tool may stay below the toolkit limits, never exceed them.

    Shared by every executor -- timeout and output ceilings are a
    property of the toolkit's blast radius, independent of protocol.
    """
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


def _validate_against_tier1(tool: ToolDef, toolkit: Toolkit) -> None:
    """FR-4.6: validation against Tier 1 -- at load time and again at execution time.

    Doubled, because Tier 1 may have been tightened by a redeploy,
    while older definitions still sit in the catalog.
    """
    where = f"tool {tool.id!r}"

    if toolkit.executor in ("docker", "local", "ssh"):
        try:
            toolkit.check_binary(tool.binary or "")
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

    elif toolkit.executor == "http":
        if not toolkit.allows_method(tool.http_method or ""):
            raise Tier1Violation(
                f"{where}: method {tool.http_method!r} is not in the "
                f"allowlist {list(toolkit.allowed_methods)} of toolkit "
                f"{toolkit.name!r}"
            )
        # The literal portion of the template before its first placeholder
        # is what a redeploy actually promised (FR-8.6); the placeholder
        # itself is agent-controlled and re-checked on the *resolved* path
        # at call time by `execute_http.py`, mirroring the argv double-check.
        literal_prefix = (tool.path_template or "").split("{", 1)[0]
        if not toolkit.allows_path(literal_prefix):
            raise Tier1Violation(
                f"{where}: path {tool.path_template!r} matches none of the "
                f"allowed_path_prefixes {list(toolkit.allowed_path_prefixes)} "
                f"of toolkit {toolkit.name!r}"
            )

    elif toolkit.executor == "truenas":
        if not toolkit.allows_rpc_method(tool.rpc_method or ""):
            raise Tier1Violation(
                f"{where}: RPC method {tool.rpc_method!r} is not in the "
                f"allowlist {list(toolkit.allowed_rpc_methods)} of toolkit "
                f"{toolkit.name!r}"
            )

    _validate_ceilings(tool, toolkit, where)


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

    parameters = {
        name: _parse_parameter(name, pspec, where)
        for name, pspec in (spec.get("parameters") or {}).items()
    }
    scopes = tuple(str(s) for s in (spec.get("required_scopes") or ()))

    # The executor determines which action fields the definition needs --
    # exactly one shape, selected by the toolkit, never mixed (FR-8.1: a
    # tool does not choose its own executor).
    binary: str | None = None
    argv: tuple[str, ...] = ()
    http_method: str | None = None
    path_template: str | None = None
    query_template: dict[str, str] = {}
    body_template: dict[str, Any] | list[Any] | str | None = None
    rpc_method: str | None = None
    params_template: dict[str, str] | None = None
    #: Every template string that may contain a `{param}` placeholder --
    #: collected here so the typo guard below covers all executor shapes
    #: uniformly, the same way it already covers argv/scopes/derived.
    all_templates: list[str] = []

    if toolkit.executor in ("docker", "local", "ssh"):
        binary = spec.get("binary")
        if not isinstance(binary, str):
            raise ConfigError(f"{where}: field 'binary' is missing")
        raw_argv = spec.get("argv", [])
        if not isinstance(raw_argv, list) or any(not isinstance(a, str) for a in raw_argv):
            raise ConfigError(f"{where}: 'argv' must be a list of strings")
        argv = tuple(raw_argv)
        all_templates.extend(argv)

    elif toolkit.executor == "http":
        http_method = spec.get("method")
        if not isinstance(http_method, str):
            raise ConfigError(f"{where}: field 'method' is missing")
        path_template = spec.get("path")
        if not isinstance(path_template, str) or not path_template.startswith("/"):
            raise ConfigError(f"{where}: field 'path' must be a string starting with '/'")
        query_template = _str_str_map(spec.get("query"), where, "query")
        raw_body = spec.get("body")
        if raw_body is not None:
            body_template = _nested_body_map(raw_body, where, "body")
        all_templates.append(path_template)
        all_templates.extend(query_template.values())
        all_templates.extend(_collect_template_strings(body_template))

    elif toolkit.executor == "truenas":
        rpc_method = spec.get("method")
        if not isinstance(rpc_method, str):
            raise ConfigError(f"{where}: field 'method' is missing")
        params_template = _str_str_map(spec.get("params"), where, "params")
        all_templates.extend(params_template.values())

    # Every placeholder must point to a declared parameter. A typo
    # in the template would otherwise only surface at runtime -- and
    # then land as an unresolvable placeholder in the request.
    declared = set(parameters)
    for template in (*all_templates, *scopes, *(p.derived or "" for p in parameters.values())):
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
        parameters=parameters,
        required_scopes=scopes,
        timeout_seconds=int(spec.get("timeout_seconds", 30)),
        max_output_bytes=int(spec.get("max_output_bytes", 65536)),
        binary=binary,
        argv=argv,
        http_method=http_method,
        path_template=path_template,
        query_template=query_template,
        body_template=body_template,
        rpc_method=rpc_method,
        params_template=params_template,
    )
    _validate_against_tier1(tool, toolkit)
    return tool


def _expand_tool(tool: ToolDef, toolkit: Toolkit) -> list[ToolDef]:
    """Fans one parsed definition out into one ToolDef per destination the
    toolkit declares (FR-8.3h).

    The YAML entry itself keeps its bare id -- authors write the tool once.
    A toolkit with no `destinations` produces the single, unmodified
    ToolDef (destination=None), exactly today's behaviour. Each expansion
    shares every other field (argv/parameters/limits/...); only `id` and
    `destination` differ, so a grant on `docker.compose_up@nas1` and one on
    `@nas2` are independent, concrete capabilities (FR-8.3i) -- there is no
    parameter through which a call to one could reach the other.
    """
    if not toolkit.destinations:
        return [tool]
    return [
        dataclasses.replace(tool, id=f"{tool.id}@{dest_name}", destination=dest_name)
        for dest_name in toolkit.destinations
    ]


def _str_str_map(value: Any, where: str, field: str) -> dict[str, str]:
    """A flat string->string template map (query/body/params).

    Deliberately flat, not arbitrary nested JSON -- see the note on
    `ToolDef.query_template`. Keys are the field/param names sent to the
    target service, values are `{param}` templates resolved exactly like
    an argv element.
    """
    if value is None:
        return {}
    if not isinstance(value, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()
    ):
        raise ConfigError(f"{where}: '{field}' must be a mapping of string to string")
    return dict(value)


def _nested_body_map(
    value: Any, where: str, field: str
) -> Any:
    """A body template that may be nested.

    Unlike ``_str_str_map`` (flat string→string), the HTTP body template
    supports nested dicts and lists so APIs like Tdarr that expect
    ``{"data":{"collection":"…","mode":"…"}}`` can be expressed.  Every
    leaf must be a string (a ``{param}`` template); non-string leaves
    (numbers, bools, null) are passed through as-is so static JSON
    structure can be mixed with parameterised values.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return {k: _nested_body_map(v, where, field) for k, v in value.items()}
    if isinstance(value, list):
        return [_nested_body_map(v, where, field) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    raise ConfigError(
        f"{where}: '{field}' must be a string, mapping, list, number, bool, or null"
    )


def _collect_template_strings(
    body: dict[str, Any] | list[Any] | str | None,
) -> list[str]:
    """Flattens a nested body template to its leaf string values.

    Used by ``_parse_tool`` to collect every ``{param}`` placeholder for
    the missing-parameter check — recursively, the same way
    ``_str_str_map``'s ``.values()`` did for the flat case.
    """
    if body is None:
        return []
    if isinstance(body, str):
        return [body]
    if isinstance(body, dict):
        out: list[str] = []
        for v in body.values():
            out.extend(_collect_template_strings(v))
        return out
    if isinstance(body, list):
        out = []
        for v in body:
            out.extend(_collect_template_strings(v))
        return out
    return []


#: Bookkeeping keys that live on a raw `tools.yaml` entry (versioned shape)
#: rather than inside a version's own `spec` -- never part of a `ToolDef`'s
#: input to `_parse_tool`.
_ENTRY_KEYS = frozenset({"id", "enabled", "current_version", "deleted", "versions"})
#: Additionally stripped from a version's stored `spec` -- `id`/`enabled`
#: live on the entry, `version` is the version record's own field.
_VERSION_SPEC_STRIP = frozenset({"id", "enabled", "version"})


def now_iso() -> str:
    """Timestamp for a new tool version / pending action record."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S%z")


def _is_versioned(entry: dict[str, Any]) -> bool:
    return isinstance(entry.get("versions"), list)


def _current_version_spec(
    entry: dict[str, Any],
) -> tuple[dict[str, Any], int, bool, bool] | None:
    """Resolves one raw `tools.yaml` entry to `(spec, version, enabled, deleted)`.

    `spec` is the flat, `parse_tool_spec`-shaped mapping (with `id`,
    `enabled` and `version` filled in) that today's flat entries always
    were -- callers do not need to know whether the entry on disk is the
    legacy flat shape or the nested `versions:` shape (FR-3.3). Returns
    `None` if a versioned entry's `current_version` does not match any of
    its `versions` -- a malformed file, not a policy question.
    """
    tool_id = entry.get("id")
    if not _is_versioned(entry):
        spec = dict(entry)
        spec.setdefault("version", 1)
        return spec, int(spec.get("version", 1)), bool(entry.get("enabled", False)), False

    versions = entry.get("versions") or []
    current = entry.get("current_version")
    match = next(
        (v for v in versions if isinstance(v, dict) and v.get("version") == current),
        None,
    )
    if match is None:
        return None
    spec = dict(match.get("spec") or {})
    spec["id"] = tool_id
    version_num = int(match.get("version", current))
    spec["version"] = version_num
    enabled = bool(entry.get("enabled", False))
    deleted = bool(entry.get("deleted", False))
    return spec, version_num, enabled, deleted


def new_tool_entry(tool_id: str, spec: dict[str, Any], *, actor: str, created_at: str) -> dict[str, Any]:
    """The raw `tools.yaml` entry for a brand-new tool -- version 1."""
    fields = {k: v for k, v in spec.items() if k not in _VERSION_SPEC_STRIP}
    return {
        "id": tool_id,
        "enabled": bool(spec.get("enabled", False)),
        "current_version": 1,
        "deleted": False,
        "versions": [
            {
                "version": 1,
                "spec": fields,
                "created_at": created_at,
                "created_by": actor,
                "superseded": False,
            }
        ],
    }


def append_tool_version(
    existing_entry: dict[str, Any],
    tool_id: str,
    spec: dict[str, Any],
    *,
    actor: str,
    created_at: str,
) -> dict[str, Any]:
    """Appends a new version to an existing raw entry -- never overwrites
    (FR-3.1/3.3). A legacy flat entry is converted in place: its current
    content becomes version 1 (marked superseded), and the new spec
    becomes version 2. Old versions are retained in full.
    """
    if _is_versioned(existing_entry):
        versions = [dict(v) for v in (existing_entry.get("versions") or [])]
        next_version = max((int(v.get("version", 0)) for v in versions), default=0) + 1
        current = existing_entry.get("current_version")
        for v in versions:
            if v.get("version") == current:
                v["superseded"] = True
    else:
        old_fields = {k: v for k, v in existing_entry.items() if k not in _VERSION_SPEC_STRIP}
        versions = [
            {
                "version": 1,
                "spec": old_fields,
                "created_at": None,
                "created_by": None,
                "superseded": True,
            }
        ]
        next_version = 2

    new_fields = {k: v for k, v in spec.items() if k not in _VERSION_SPEC_STRIP}
    versions.append(
        {
            "version": next_version,
            "spec": new_fields,
            "created_at": created_at,
            "created_by": actor,
            "superseded": False,
        }
    )
    return {
        "id": tool_id,
        "enabled": bool(spec.get("enabled", existing_entry.get("enabled", False))),
        "current_version": next_version,
        "deleted": False,
        "versions": versions,
    }


def soft_delete_entry(existing_entry: dict[str, Any]) -> dict[str, Any]:
    """Marks a raw entry deleted without discarding its version history
    (FR-3.1). Converts a legacy flat entry to versioned shape first, the
    same as `append_tool_version`, so the pre-deletion definition is not
    lost either.
    """
    if _is_versioned(existing_entry):
        entry = dict(existing_entry)
        entry["versions"] = [dict(v) for v in (existing_entry.get("versions") or [])]
        entry["deleted"] = True
        return entry
    tool_id = existing_entry.get("id")
    old_fields = {k: v for k, v in existing_entry.items() if k not in _VERSION_SPEC_STRIP}
    return {
        "id": tool_id,
        "enabled": bool(existing_entry.get("enabled", False)),
        "current_version": 1,
        "deleted": True,
        "versions": [
            {
                "version": 1,
                "spec": old_fields,
                "created_at": None,
                "created_by": None,
                "superseded": False,
            }
        ],
    }


def normalize_tool_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """A JSON-serializable, version-shape-agnostic view of one raw entry --
    for `admin.tool_get`/`admin.tool_list`. Always returns the full
    `versions:` list (a legacy flat entry is reported as its implicit,
    single version 1) plus `current_version`/`enabled`/`deleted`.
    """
    resolved = _current_version_spec(entry)
    if _is_versioned(entry):
        versions = [dict(v) for v in (entry.get("versions") or [])]
        current_version = entry.get("current_version")
    else:
        fields = {k: v for k, v in entry.items() if k not in _VERSION_SPEC_STRIP}
        versions = [
            {
                "version": 1,
                "spec": fields,
                "created_at": None,
                "created_by": None,
                "superseded": False,
            }
        ]
        current_version = 1
    return {
        "id": entry.get("id"),
        "enabled": bool(entry.get("enabled", False)),
        "deleted": bool(entry.get("deleted", False)),
        "current_version": current_version,
        "category": (resolved[0].get("category") if resolved else None),
        "versions": versions,
    }


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

    def flat_spec_of(self, tool_id: str) -> dict[str, Any] | None:
        """The effective, editable flat spec for `tool_id` -- the shape
        `parse_tool_spec`/the `/ui` YAML editor/`admin.tool_update` all
        expect, regardless of whether the raw entry on disk is today's
        legacy flat shape or the nested `versions:` shape (FR-3.3). `None`
        for an unknown id, a deleted tool, or a versioned entry whose
        `current_version` does not match any stored version.
        """
        raw = self.raw_of(tool_id)
        if raw is None or raw.get("deleted"):
            return None
        resolved = _current_version_spec(raw)
        if resolved is None:
            return None
        spec, _version, enabled, _deleted = resolved
        spec["enabled"] = enabled
        return spec


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
    for entry in entries:
        if not isinstance(entry, dict):
            raise ConfigError("tools.yaml: every entry must be a mapping")

        resolved = _current_version_spec(entry)
        if resolved is None:
            raise ConfigError(
                f"tools.yaml: entry {entry.get('id')!r} has a 'current_version' "
                "that matches none of its 'versions'"
            )
        spec, _version, enabled, deleted = resolved
        if deleted:
            # Excluded from the live catalog entirely (FR-3.1), but the raw
            # entry -- full version history included -- stays in `raw` for
            # admin.tool_get/tool_list.
            continue
        spec["enabled"] = enabled

        try:
            tool = _parse_tool(spec, tier1)
        except Tier1Violation as exc:
            if strict:
                raise
            disabled.append(str(exc))
            rejected.append((spec, str(exc)))
            continue
        toolkit = tier1.toolkit(tool.toolkit)
        for expanded in _expand_tool(tool, toolkit):
            if expanded.id in tools:
                raise ConfigError(f"Duplicate tool ID {expanded.id!r}")
            tools[expanded.id] = expanded

    return Catalog(
        tools=tools,
        disabled_by_tier1=disabled,
        raw=[s for s in entries if isinstance(s, dict)],
        rejected=rejected,
    )