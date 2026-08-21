"""Parameter validation and argv construction (REQUIREMENTS.md §8).

The core. The fundamental guarantee is FR-5.4:

    A parameter always expands to exactly one argv element.

This is not a question of careful escaping, but a structural property:
each argv template element resolves to exactly one string and is passed as a
single list element to `execve`. There is no shell interpreter that could
subsequently split a value into multiple words. A parameter value therefore
cannot structurally produce an additional argument -- regardless of
which characters it contains.

The character check in `_reject_control_characters` is defense-in-depth
(FR-6.3), not the primary protection. The primary protection is the per-
parameter allowlist (FR-6.2).
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import unquote

from .catalog import PLACEHOLDER_RE, Parameter, ToolDef
from .errors import DenialReason, Denied
from .tier1 import Toolkit


def _reject_control_characters(name: str, value: str) -> None:
    """FR-6.3: Control characters and null bytes are an attack indicator.

    Executed before the pattern check, because a permissive pattern
    (e.g. using `.`) could otherwise let them through.
    """
    for char in value:
        codepoint = ord(char)
        if codepoint < 0x20 or codepoint == 0x7F:
            raise Denied(
                DenialReason.CONTROL_CHARACTER,
                f"Parameter {name!r} contains a control character (U+{codepoint:04X}).",
            )


def _validate_scalar(param: Parameter, value: Any) -> str:
    """Validates a value supplied by the agent and returns it as a string."""
    name = param.name

    if param.type == "boolean":
        if not isinstance(value, bool):
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"Parameter {name!r} expects a boolean.",
            )
        return "true" if value else "false"

    if param.type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"Parameter {name!r} expects an integer.",
            )
        if param.minimum is not None and value < param.minimum:
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"Parameter {name!r}: {value} is below the minimum "
                f"{param.minimum}.",
            )
        if param.maximum is not None and value > param.maximum:
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"Parameter {name!r}: {value} exceeds the maximum "
                f"{param.maximum}.",
            )
        return str(value)

    if not isinstance(value, str):
        raise Denied(
            DenialReason.PARAM_INVALID,
            f"Parameter {name!r} expects a string.",
        )

    _reject_control_characters(name, value)

    if param.type == "enum":
        if value not in param.values:
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"Parameter {name!r}: {value!r} is not an allowed value.",
            )
        return value

    # string -- allowlist via pattern, full match.
    # `fullmatch` instead of `match`, because `match` only checks the start
    # and would thus allow any suffix.
    if param.pattern is not None and not param.pattern.fullmatch(value):
        raise Denied(
            DenialReason.PARAM_INVALID,
            f"Parameter {name!r}: value does not match the allowed pattern.",
        )
    return value


def _substitute(template: str, values: dict[str, str]) -> str:
    """Replaces placeholders. The result is always exactly one string."""

    def replace(match: re.Match[str]) -> str:
        return values[match.group(1)]

    return PLACEHOLDER_RE.sub(replace, template)


def _resolve_path(param: Parameter, raw: str) -> str:
    """Resolves a derived path and checks it against its root.

    `realpath` resolves symlinks -- this catches an escape via a
    prepared symlink within the allowed root (FR-4.3).
    The comparison uses `commonpath` rather than a string prefix,
    because `/mnt/raid-evil` would otherwise be considered below `/mnt/raid`.
    """
    root = param.must_resolve_under or ""

    # The components are already allowlist-checked and can contain neither '/' nor
    # '..'. The check here catches a faulty derived template.
    if ".." in re.split(r"[\\/]", raw):
        raise Denied(
            DenialReason.PATH_ESCAPE,
            f"Parameter {param.name!r}: path contains '..'.",
        )

    real = os.path.realpath(raw)
    real_root = os.path.realpath(root)
    try:
        common = os.path.commonpath([real, real_root])
    except ValueError:
        # Different drives (Windows) -- can never be below the root.
        raise Denied(
            DenialReason.PATH_ESCAPE,
            f"Parameter {param.name!r}: path resolves outside {root!r}.",
        ) from None
    if common != real_root:
        raise Denied(
            DenialReason.PATH_ESCAPE,
            f"Parameter {param.name!r}: path resolves outside {root!r}.",
        )
    return real


def resolve_parameters(tool: ToolDef, arguments: dict[str, Any]) -> dict[str, str]:
    """Validates the agent input and adds the derived values."""
    agent_params = tool.agent_parameters

    for name in arguments:
        param = tool.parameters.get(name)
        if param is None:
            raise Denied(
                DenialReason.PARAM_UNKNOWN,
                f"Unknown parameter {name!r}.",
            )
        if param.is_derived:
            # FR-5.5: Derived values are computed by the server. Sending them
            # attempts to bypass the derivation.
            raise Denied(
                DenialReason.PARAM_DERIVED_SUPPLIED,
                f"Parameter {name!r} is determined by the server and must not "
                "be supplied.",
            )

    resolved: dict[str, str] = {}
    for name, param in agent_params.items():
        if name not in arguments:
            if param.required:
                raise Denied(
                    DenialReason.PARAM_MISSING,
                    f"Required parameter {name!r} is missing.",
                )
            continue
        resolved[name] = _validate_scalar(param, arguments[name])

    # Derived parameters after the agent parameters, so they can
    # build on them.
    for name, param in tool.parameters.items():
        if not param.is_derived:
            continue
        missing = _placeholders_missing(param.derived or "", resolved)
        if missing:
            raise Denied(
                DenialReason.PARAM_MISSING,
                f"Derived parameter {name!r} needs {sorted(missing)}.",
            )
        raw = _substitute(param.derived or "", resolved)
        resolved[name] = _resolve_path(param, raw) if param.type == "path" else raw

    return resolved


def _placeholders_missing(template: str, values: dict[str, str]) -> set[str]:
    return {p for p in PLACEHOLDER_RE.findall(template) if p not in values}


def build_argv(tool: ToolDef, values: dict[str, str], toolkit: Toolkit) -> list[str]:
    """Builds the argument list and checks it again against Tier 1.

    The second check is not a ritual: it operates on the *resolved* argv.
    A parameter value that resolves to a blocked subcommand is caught here --
    the check at load time only saw the template.
    """
    argv = [tool.binary]
    for element in tool.argv:
        missing = _placeholders_missing(element, values)
        if missing:
            raise Denied(
                DenialReason.PARAM_MISSING,
                f"Argument template needs {sorted(missing)}.",
            )
        # Exactly one list element per template element -- that is FR-5.4.
        argv.append(_substitute(element, values))

    toolkit.check_binary(tool.binary)
    if denied := toolkit.check_args(argv):
        raise Denied(
            DenialReason.TIER1_VIOLATION,
            f"Argument {denied!r} is denied for this toolkit.",
        )
    return argv


def _reject_path_traversal(name: str, path: str) -> None:
    """FR-8.7: `..` in a resolved path segment is rejected, not normalized.

    Normalizing would mean gatekeeper decides what the segment "really"
    meant -- exactly the ambiguity a target server could exploit. An
    outright reject has no such interpretation to get wrong.

    Checked both literally and percent-decoded: `toolkit.allows_path`'s
    prefix check only inspects the path as gatekeeper sends it, but the
    *target* server decodes percent-escapes before interpreting the path --
    `%2e%2e%2f` reads as an ordinary path segment here and as `../` there.
    A single `unquote` pass catches that gap the same way the literal
    check catches an unencoded `..`, without trying to guess or normalize
    what a doubly-encoded sequence would mean -- rejecting once is enough
    to close the ambiguity, guessing further would just reopen it.
    """
    if ".." in path.split("/"):
        raise Denied(
            DenialReason.PATH_ESCAPE,
            f"{name}: resolved path {path!r} contains a '..' segment.",
        )
    decoded = unquote(path)
    if decoded != path and ".." in decoded.split("/"):
        raise Denied(
            DenialReason.PATH_ESCAPE,
            f"{name}: resolved path {path!r} percent-decodes to a "
            "'..' segment.",
        )


def build_http_request(
    tool: ToolDef, values: dict[str, str], toolkit: Toolkit
) -> tuple[str, str, dict[str, str], dict[str, str] | None]:
    """Builds (method, path, query, body) and checks the result against Tier 1.

    The HTTP counterpart of `build_argv`: scheme and host are never built
    here (FR-8.5, they live exclusively on the toolkit), and the second
    Tier 1 check operates on the fully resolved path, not the template --
    a parameter value cannot structurally point outside the toolkit's
    allowed prefixes (FR-8.7, the HTTP equivalent of FR-5.4).
    """
    assert tool.http_method is not None and tool.path_template is not None

    missing = _placeholders_missing(tool.path_template, values)
    if missing:
        raise Denied(
            DenialReason.PARAM_MISSING, f"Path template needs {sorted(missing)}."
        )
    path = _substitute(tool.path_template, values)
    _reject_path_traversal("path", path)

    if not toolkit.allows_path(path):
        raise Denied(
            DenialReason.TIER1_VIOLATION,
            f"Resolved path {path!r} is outside the toolkit's allowed prefixes.",
        )
    if not toolkit.allows_method(tool.http_method):
        raise Denied(
            DenialReason.TIER1_VIOLATION,
            f"Method {tool.http_method!r} is not allowed for this toolkit.",
        )

    query: dict[str, str] = {}
    for key, template in tool.query_template.items():
        missing = _placeholders_missing(template, values)
        if missing:
            raise Denied(
                DenialReason.PARAM_MISSING,
                f"Query template {key!r} needs {sorted(missing)}.",
            )
        query[key] = _substitute(template, values)

    body: dict[str, str] | None = None
    if tool.body_template is not None:
        body = {}
        for key, template in tool.body_template.items():
            missing = _placeholders_missing(template, values)
            if missing:
                raise Denied(
                    DenialReason.PARAM_MISSING,
                    f"Body template {key!r} needs {sorted(missing)}.",
                )
            body[key] = _substitute(template, values)

    return tool.http_method, path, query, body


def build_rpc_call(
    tool: ToolDef, values: dict[str, str], toolkit: Toolkit
) -> tuple[str, dict[str, str]]:
    """Builds (method, params) for the truenas executor and re-checks the

    method against Tier 1. `method` is fixed per tool (not agent-suppliable),
    so this second check is an invariant assertion rather than a real gate --
    kept anyway for the same reason `build_argv` re-checks `check_binary`:
    consistency, and a defense against a future bug that makes it
    parameterizable.
    """
    assert tool.rpc_method is not None

    if not toolkit.allows_rpc_method(tool.rpc_method):
        raise Denied(
            DenialReason.RPC_METHOD_DENIED,
            f"RPC method {tool.rpc_method!r} is not allowed for this toolkit.",
        )

    params: dict[str, str] = {}
    for key, template in (tool.params_template or {}).items():
        missing = _placeholders_missing(template, values)
        if missing:
            raise Denied(
                DenialReason.PARAM_MISSING,
                f"Params template {key!r} needs {sorted(missing)}.",
            )
        params[key] = _substitute(template, values)

    return tool.rpc_method, params


def resolve_scopes(tool: ToolDef, values: dict[str, str]) -> list[str]:
    """Resolves `required_scopes` with the validated parameter values."""
    scopes = []
    for template in tool.required_scopes:
        missing = _placeholders_missing(template, values)
        if missing:
            raise Denied(
                DenialReason.PARAM_MISSING,
                f"Scope template needs {sorted(missing)}.",
            )
        scopes.append(_substitute(template, values))
    return scopes


def check_protected(scopes: list[str], toolkit: Toolkit) -> None:
    """FR-4.12: protected resources, independent of rights and scopes.

    A `docker.compose_down` on its own stack passes every other
    check: allowed binary, valid name, path below the root.
    Only this list knows that gatekeeper would terminate itself with it.
    """
    for scope in scopes:
        _, _, resource = scope.partition(":")
        if resource and toolkit.is_protected(resource):
            raise Denied(
                DenialReason.PROTECTED_RESOURCE,
                f"Resource {resource!r} is protected and reachable by no tool.",
            )
