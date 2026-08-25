"""Error types.

The separation is deliberate: `DenialReason` is what goes into the audit log
(FR-9.2), `AGENT_MESSAGE` is what the agent sees. Per FR-7.7
a missing permission and a non-existent tool must be indistinguishable
to the agent, otherwise `tools/call` becomes a catalog oracle.
"""

from __future__ import annotations

import enum
import os


class DenialReason(str, enum.Enum):
    """Internal denial reason - complete, for the audit log only."""

    UNKNOWN_TOKEN = "unknown_token"
    UNKNOWN_TOOL = "unknown_tool"
    TOOL_DISABLED = "tool_disabled"
    NOT_GRANTED = "not_granted"
    SCOPE_MISMATCH = "scope_mismatch"
    PROTECTED_RESOURCE = "protected_resource"
    PARAM_INVALID = "param_invalid"
    PARAM_UNKNOWN = "param_unknown"
    PARAM_MISSING = "param_missing"
    PARAM_DERIVED_SUPPLIED = "param_derived_supplied"
    CONTROL_CHARACTER = "control_character"
    PATH_ESCAPE = "path_escape"
    TIER1_VIOLATION = "tier1_violation"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    EXECUTOR_UNAVAILABLE = "executor_unavailable"
    SSRF_BLOCKED = "ssrf_blocked"
    RPC_METHOD_DENIED = "rpc_method_denied"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"


#: Uniform response for everything the agent should not know (FR-7.7).
#: Unknown tool and missing permission yield exactly this text.
#:
#: All output text is English: it reaches agents (i.e.
#: language models), the audit log, and the operations UI. Comments and docs
#: remain in German.
OPAQUE_DENIAL = "Unknown tool, or not available."

#: Denial reasons that are obscured from the agent.
_OPAQUE = frozenset(
    {
        DenialReason.UNKNOWN_TOOL,
        DenialReason.TOOL_DISABLED,
        DenialReason.NOT_GRANTED,
        DenialReason.SCOPE_MISMATCH,
        DenialReason.PROTECTED_RESOURCE,
    }
)


class GatekeeperError(Exception):
    """Base class."""


class ConfigError(GatekeeperError):
    """Configuration is invalid - causes startup to abort."""


def _whoami() -> str:
    """uid:gid of this process, for a chown recommendation that is correct.

    Read rather than assumed. This message used to state "568:568" as a
    fixed string, which is the shipped image's convention and not
    necessarily this process's identity -- and a permission error is
    exactly the moment when being told the wrong uid costs the most,
    because the reader chowns to it and the failure does not move.
    """
    try:
        return f"{os.geteuid()}:{os.getegid()}"  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover -- Windows has no euid
        return "this user"


def read_config_file(path: str, hint: str = "") -> str:
    """Reads a configuration file and translates OS errors into plain text.

    Without this, a failed mount breaks through as a raw `IsADirectoryError`.
    Exactly this case happens frequently with Docker and is incomprehensible
    from the outside: if you bind-mount a *file* that does not exist on the
    host, Docker creates a *directory* for it -- and afterwards you get an
    error message about a file that is seemingly there.
    """
    # Check before opening, not via the exception: Linux reports
    # IsADirectoryError, Windows PermissionError. A test that only knows
    # one case would green on the wrong platform.
    if os.path.isdir(path):
        raise ConfigError(
            f"{path} is a directory, not a file. Docker creates a directory "
            "when a bind-mounted file does not exist on the host. Remove it "
            "on the host, mount the containing directory instead of the "
            "single file, and create the file before starting."
            + (f" {hint}" if hint else "")
        )
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except PermissionError:
        raise ConfigError(
            f"{path} cannot be read by this process ({_whoami()}). "
            "Check the owner and mode of the file and of every directory "
            "above it -- a denial naming the file is often a parent "
            "directory without +x for that uid. Files created while the "
            "container ran as root stay root-owned, so this is the usual "
            "first failure after switching a deployment to a lesser user "
            f"(GATEKEEPER_DROP_TO, or 'user:'). On the host:\n"
            f"  chown -R {_whoami()} <the directory mounted at "
            f"{os.path.dirname(path) or path}>" + (f"\n{hint}" if hint else "")
        ) from None
    except OSError as exc:
        raise ConfigError(f"{path} cannot be read: {exc}") from None


class Tier1Violation(ConfigError):
    """A tool definition violates the deploy-time limits (FR-4.6)."""


class Denied(GatekeeperError):
    """A call was denied.

    `reason` and `detail` go into the audit log, `agent_message` to the agent.
    """

    def __init__(self, reason: DenialReason, detail: str = "") -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason
        self.detail = detail

    @property
    def agent_message(self) -> str:
        """What the agent sees - deliberately uninformative for catalog information."""
        if self.reason in _OPAQUE:
            return OPAQUE_DENIAL
        if self.reason is DenialReason.RATE_LIMITED:
            return "Rate limit reached. Try again later."
        if self.reason is DenialReason.TIMEOUT:
            return self.detail or "Timed out."
        # Validation errors may be specific: they reveal nothing about the
        # catalog, only about the values sent by the agent itself.
        return self.detail or "Call denied."