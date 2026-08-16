"""Tier 1 - the immutable-at-runtime limits (REQUIREMENTS.md §6).

Everything here is read from `toolkits.yaml` at startup and never
touched again. The admin API (stage 3) can create tools, but no toolkit --
otherwise Tier 1 would be mutable at runtime and the whole design would
have no foundation (FR-4.11).
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import PurePosixPath
from typing import Any

import yaml

from .errors import ConfigError, read_config_file

#: Executor types implemented in stage 1. `truenas`/`http`/`ssh` follow in
#: stage 2 -- a toolkit that references them is now rejected (FR-8.1).
KNOWN_EXECUTORS = frozenset({"docker", "local"})


@dataclasses.dataclass(frozen=True, slots=True)
class Toolkit:
    """Carrier of the Tier 1 limits (FR-4.8).

    Limits are attached to the toolkit, not globally: `diag.uptime` needs no
    path root under /mnt/raid, `docker.compose_up` does. A global
    allowlist would be the union of all needs (FR-4.9).
    """

    name: str
    executor: str
    binaries: tuple[str, ...]
    denied_args: tuple[str, ...]
    path_roots: tuple[str, ...]
    protected_resources: tuple[str, ...]
    max_timeout_seconds: int
    max_output_bytes: int

    def check_binary(self, binary: str) -> None:
        """FR-4.1: the executable must be exactly in the allowlist."""
        if binary not in self.binaries:
            raise ConfigError(
                f"Toolkit {self.name!r}: binary {binary!r} is not in the "
                f"allowlist {list(self.binaries)}"
            )

    def check_args(self, argv: list[str]) -> str | None:
        """FR-4.2: blocked subcommands and flags.

        Operates on the *resolved* argv, not on the template -- a
        parameter value that resolves to `rm` is caught just the same.
        """
        for arg in argv:
            if arg in self.denied_args:
                return arg
        return None

    def check_path_root(self, root: str) -> None:
        """A `must_resolve_under` must lie within the toolkit roots.

        FR-4.10: a tool may tighten the limits of its toolkit,
        never widen them.
        """
        if not self.path_roots:
            raise ConfigError(
                f"Toolkit {self.name!r} declares no path_roots, but a tool "
                f"requires {root!r}"
            )
        candidate = PurePosixPath(root)
        for allowed in self.path_roots:
            allowed_path = PurePosixPath(allowed)
            if candidate == allowed_path or allowed_path in candidate.parents:
                return
        raise ConfigError(
            f"Toolkit {self.name!r}: {root!r} lies outside the path_roots "
            f"{list(self.path_roots)}"
        )

    def is_protected(self, resource: str) -> bool:
        """FR-4.12: protected resources, independent of permissions and scopes.

        Tier 1 can check syntax but not meaning: `docker compose down`
        is the same operation to the validator, whether it hits a media stack
        or gatekeeper itself.
        """
        return resource in self.protected_resources


@dataclasses.dataclass(frozen=True, slots=True)
class RateLimit:
    count: int
    window_seconds: int


@dataclasses.dataclass(frozen=True, slots=True)
class Tier1:
    """The complete deploy-time configuration."""

    toolkits: dict[str, Toolkit]
    rate_limits: dict[str, RateLimit]
    max_concurrent: int
    audit_dir: str
    audit_max_bytes: int
    audit_keep_files: int

    def toolkit(self, name: str) -> Toolkit:
        try:
            return self.toolkits[name]
        except KeyError:
            raise ConfigError(f"Unknown toolkit {name!r}") from None


def _is_absolute(path: str) -> bool:
    """Absolute by POSIX OR by host convention.

    The paths in `toolkits.yaml` always describe the container filesystem,
    i.e. POSIX -- `os.path.isabs` alone would reject `/usr/bin/docker` under
    Windows starting Python 3.13 and make the configuration only checkable
    where it also runs. What matters anyway is only that no bare
    program name remains, over which PATH would then decide.
    """
    return path.startswith("/") or os.path.isabs(path)


def _require(data: dict[str, Any], key: str, where: str) -> Any:
    if key not in data:
        raise ConfigError(f"{where}: required field {key!r} is missing")
    return data[key]


def _str_tuple(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: expects a list of strings")
    return tuple(value)


def load_tier1(path: str) -> Tier1:
    """Loads and validates `toolkits.yaml`. Errors here abort startup.

    Unlike the catalog, Tier 1 has no meaningful empty state: it is
    the boundary within which everything else takes place. If it is
    missing, it is undecided what would be allowed -- and guessing
    would be the wrong reflex here.
    """
    if not os.path.exists(path):
        raise ConfigError(
            f"{path} not found. Tier 1 defines what is possible at all and has "
            "no safe default -- create it before starting. A starting point "
            "sits in config/examples/toolkits.yaml, or run 'gatekeeper init'."
        )
    raw = yaml.safe_load(
        read_config_file(path, "A starting point sits in config/examples/toolkits.yaml.")
    ) or {}

    # An empty section is valid and the state after `init`: then nothing
    # is possible. That is a valid statement, not a missing one -- and the
    # only one gatekeeper may make on its own. Which binaries an agent
    # should be able to reach is known only by someone who knows the system.
    toolkit_section = raw.get("toolkits")
    if toolkit_section is None:
        toolkit_section = {}
    if not isinstance(toolkit_section, dict):
        raise ConfigError("toolkits.yaml: section 'toolkits' must be a mapping")

    toolkits: dict[str, Toolkit] = {}
    for name, spec in toolkit_section.items():
        where = f"toolkit {name!r}"
        if not isinstance(spec, dict):
            raise ConfigError(f"{where}: expects a mapping")

        executor = _require(spec, "executor", where)
        if executor not in KNOWN_EXECUTORS:
            raise ConfigError(
                f"{where}: executor {executor!r} is not enabled at this stage "
                f"(available: {sorted(KNOWN_EXECUTORS)})"
            )

        binaries = _str_tuple(_require(spec, "binaries", where), where)
        if not binaries:
            raise ConfigError(f"{where}: 'binaries' must not be empty")
        for binary in binaries:
            if not _is_absolute(binary):
                raise ConfigError(
                    f"{where}: binary {binary!r} must be an absolute path -- "
                    "otherwise PATH decides what gets executed"
                )

        max_timeout = int(spec.get("max_timeout_seconds", 60))
        max_output = int(spec.get("max_output_bytes", 65536))
        if max_timeout <= 0 or max_output <= 0:
            raise ConfigError(f"{where}: ceilings must be positive")

        toolkits[name] = Toolkit(
            name=name,
            executor=executor,
            binaries=binaries,
            denied_args=_str_tuple(spec.get("denied_args"), where),
            path_roots=_str_tuple(spec.get("path_roots"), where),
            protected_resources=_str_tuple(spec.get("protected_resources"), where),
            max_timeout_seconds=max_timeout,
            max_output_bytes=max_output,
        )

    limits = raw.get("rate_limits") or {}
    rate_limits = {
        category: RateLimit(
            count=int(spec.get("count", 60)),
            window_seconds=int(spec.get("window_seconds", 60)),
        )
        for category, spec in limits.items()
    }
    for category in ("read", "write", "write_external"):
        rate_limits.setdefault(category, RateLimit(count=60, window_seconds=60))

    audit = raw.get("audit") or {}
    return Tier1(
        toolkits=toolkits,
        rate_limits=rate_limits,
        max_concurrent=int(raw.get("max_concurrent", 4)),
        audit_dir=str(audit.get("dir", "/mnt/raid/gatekeeper/logs")),
        audit_max_bytes=int(audit.get("max_bytes", 32 * 1024 * 1024)),
        audit_keep_files=int(audit.get("keep_files", 10)),
    )