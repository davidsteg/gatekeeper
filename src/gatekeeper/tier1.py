"""Tier 1 - the immutable-at-runtime limits (REQUIREMENTS.md §6).

Everything here is read from `toolkits.yaml` at startup and never
touched again. The admin API (stage 3) can create tools, but no toolkit --
otherwise Tier 1 would be mutable at runtime and the whole design would
have no foundation (FR-4.11).
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from .errors import ConfigError, read_config_file

#: Executor types implemented. `ssh` is optional per §17 and not yet built.
KNOWN_EXECUTORS = frozenset({"docker", "local", "http", "truenas"})

#: FR-8.6: methods an `http` toolkit may allow at all. A toolkit may
#: narrow this further; it may never widen it.
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


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
    #: Name of a credential in the credential store (§11), never a value.
    #: The *binding* of toolkit to credential name is Tier 1 -- only a
    #: redeploy may point a toolkit at a different credential (FR-10.4).
    credential: str | None = None

    # -- `http` executor only (FR-8.5 to FR-8.15) --------------------------

    #: Scheme and host live exclusively here, never in a tool definition or
    #: a parameter (FR-8.5). May itself contain a single `{credential}`
    #: placeholder for services (e.g. Telegram) whose secret sits in the
    #: URL path rather than a header -- resolved server-side only, in
    #: `execute_http.py`, never visible to a tool definition or the agent.
    base_url: str | None = None
    allowed_methods: tuple[str, ...] = ()
    allowed_path_prefixes: tuple[str, ...] = ()
    #: Post-DNS-resolution IP/CIDR allowlist (FR-8.9) -- the only effective
    #: target restriction for LAN services, so it must be scoped narrowly
    #: per toolkit (FR-8.15), never a blanket private-range allow.
    allowed_cidrs: tuple[str, ...] = ()

    # -- `truenas` executor only (FR-8.3a-f) -------------------------------

    #: JSON-RPC 2.0 endpoint, e.g. "wss://truenas.lan/api/current".
    ws_url: str | None = None
    #: For `truenas`, the whitelist acts on JSON-RPC *method names*
    #: (FR-8.3c) instead of binaries or path prefixes -- reuses the same
    #: field name as the http executor's HTTP methods because both are
    #: "the finite set of operations this toolkit may ever perform",
    #: just named differently by their respective protocols.
    allowed_rpc_methods: tuple[str, ...] = ()

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

    # -- `http` executor -----------------------------------------------
    #
    # These `allows_*`/`in_*` checks return a bool rather than raising:
    # unlike `check_binary` (fixed per tool, can never fail at call time
    # once load-time validation passed), method/path/CIDR depend on
    # resolved parameter values or a live DNS answer and so are genuinely
    # dynamic. Callers decide what a `False` means -- `catalog.py` turns it
    # into a `Tier1Violation` at load time, `execute_http.py` turns it into
    # a `Denied` at call time -- mirroring how `check_args`' return value
    # (rather than a raise) lets `validate.build_argv` wrap it in `Denied`.

    def allows_method(self, method: str) -> bool:
        """FR-8.6: only allowlisted HTTP methods."""
        return method in self.allowed_methods

    def allows_path(self, path: str) -> bool:
        """FR-8.6/FR-8.7: the path must start with an allowed prefix.

        Checked twice by callers -- once against the template's literal
        prefix at parse time, once against the fully resolved path at
        call time -- mirroring `check_binary`/`check_args` for argv tools.
        """
        return any(path.startswith(prefix) for prefix in self.allowed_path_prefixes)

    def in_allowed_cidrs(
        self, address: "ipaddress.IPv4Address | ipaddress.IPv6Address"
    ) -> bool:
        """FR-8.9: the *resolved* IP, checked immediately before connecting.

        This is what actually stops DNS rebinding -- a hostname allowlist
        alone would only be checked once, before the attacker's DNS server
        is free to answer the *next* lookup (the connect itself) with a
        different, disallowed address.
        """
        return any(
            address in ipaddress.ip_network(cidr, strict=False)
            for cidr in self.allowed_cidrs
        )

    # -- `truenas` executor ----------------------------------------------

    def allows_rpc_method(self, method: str) -> bool:
        """FR-8.3c: the whitelist acts on JSON-RPC method names.

        `pool.dataset.delete` simply never appears in the list -- there is
        no separate 'permission' to deny it, it structurally does not exist.
        """
        return method in self.allowed_rpc_methods


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

        max_timeout = int(spec.get("max_timeout_seconds", 60))
        max_output = int(spec.get("max_output_bytes", 65536))
        if max_timeout <= 0 or max_output <= 0:
            raise ConfigError(f"{where}: ceilings must be positive")

        credential = spec.get("credential")
        if credential is not None and not isinstance(credential, str):
            raise ConfigError(f"{where}: 'credential' must be a string name")

        binaries: tuple[str, ...] = ()
        base_url: str | None = None
        allowed_methods: tuple[str, ...] = ()
        allowed_path_prefixes: tuple[str, ...] = ()
        allowed_cidrs: tuple[str, ...] = ()
        ws_url: str | None = None
        allowed_rpc_methods: tuple[str, ...] = ()

        if executor in ("docker", "local"):
            binaries = _str_tuple(_require(spec, "binaries", where), where)
            if not binaries:
                raise ConfigError(f"{where}: 'binaries' must not be empty")
            for binary in binaries:
                if not _is_absolute(binary):
                    raise ConfigError(
                        f"{where}: binary {binary!r} must be an absolute path -- "
                        "otherwise PATH decides what gets executed"
                    )
        elif executor == "http":
            base_url = str(_require(spec, "base_url", where))
            parsed = urlsplit(base_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ConfigError(
                    f"{where}: base_url {base_url!r} must be an absolute "
                    "http(s) URL, e.g. 'http://sonarr.lan:8989'"
                )
            allowed_methods = _str_tuple(_require(spec, "allowed_methods", where), where)
            if not allowed_methods:
                raise ConfigError(f"{where}: 'allowed_methods' must not be empty")
            unknown_methods = sorted(set(allowed_methods) - HTTP_METHODS)
            if unknown_methods:
                raise ConfigError(
                    f"{where}: allowed_methods {unknown_methods} are not HTTP "
                    f"methods (known: {sorted(HTTP_METHODS)})"
                )
            allowed_path_prefixes = _str_tuple(
                _require(spec, "allowed_path_prefixes", where), where
            )
            if not allowed_path_prefixes:
                raise ConfigError(f"{where}: 'allowed_path_prefixes' must not be empty")
            for prefix in allowed_path_prefixes:
                if not prefix.startswith("/"):
                    raise ConfigError(
                        f"{where}: allowed_path_prefixes entry {prefix!r} must "
                        "start with '/'"
                    )
            allowed_cidrs = _str_tuple(_require(spec, "allowed_cidrs", where), where)
            if not allowed_cidrs:
                raise ConfigError(f"{where}: 'allowed_cidrs' must not be empty")
            for cidr in allowed_cidrs:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError as exc:
                    raise ConfigError(
                        f"{where}: allowed_cidrs entry {cidr!r} is not a valid "
                        f"IP network: {exc}"
                    ) from None
            # FR-8.8 is not a configurable knob: a toolkit that sets this
            # true would silently defeat the target allowlist, since the
            # target server -- not gatekeeper -- would then decide the
            # actual destination.
            follow_redirects = spec.get("follow_redirects", False)
            if follow_redirects:
                raise ConfigError(
                    f"{where}: 'follow_redirects' must be false -- gatekeeper "
                    "never follows redirects on an http toolkit (FR-8.8)"
                )
        elif executor == "truenas":
            ws_url = str(_require(spec, "ws_url", where))
            parsed = urlsplit(ws_url)
            if parsed.scheme not in ("ws", "wss") or not parsed.netloc:
                raise ConfigError(
                    f"{where}: ws_url {ws_url!r} must be an absolute ws(s) URL, "
                    "e.g. 'wss://truenas.lan/api/current'"
                )
            allowed_rpc_methods = _str_tuple(
                _require(spec, "allowed_rpc_methods", where), where
            )
            if not allowed_rpc_methods:
                raise ConfigError(f"{where}: 'allowed_rpc_methods' must not be empty")

        toolkits[name] = Toolkit(
            name=name,
            executor=executor,
            binaries=binaries,
            denied_args=_str_tuple(spec.get("denied_args"), where),
            path_roots=_str_tuple(spec.get("path_roots"), where),
            protected_resources=_str_tuple(spec.get("protected_resources"), where),
            max_timeout_seconds=max_timeout,
            max_output_bytes=max_output,
            credential=credential,
            base_url=base_url,
            allowed_methods=allowed_methods,
            allowed_path_prefixes=allowed_path_prefixes,
            allowed_cidrs=allowed_cidrs,
            ws_url=ws_url,
            allowed_rpc_methods=allowed_rpc_methods,
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