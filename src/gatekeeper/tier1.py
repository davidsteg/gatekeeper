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

from ._runas import RunAsError, parse_run_as
from .errors import ConfigError, read_config_file

#: Executor types implemented.
KNOWN_EXECUTORS = frozenset({"docker", "local", "http", "truenas", "ssh", "file", "google"})

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

    # -- Multi-destination (FR-8.3g-j) --------------------------------------

    #: Names into Tier1.destinations. Empty (the default) means "single
    #: implicit destination" -- exactly today's behaviour: docker falls
    #: back to the process-wide DOCKER_HOST, http/truenas use base_url/ws_url
    #: below directly. Every existing toolkits.yaml needs zero changes.
    destinations: tuple[str, ...] = ()
    #: The docker executor's own explicit target, mirroring base_url/ws_url
    #: above -- gives docker toolkits the same Tier1-visible target field
    #: http/truenas already had. None falls back to Service.docker_host
    #: (the process-wide DOCKER_HOST), exactly as before this field existed.
    docker_host: str | None = None
    #: Paired with docker_host, for a TLS-secured remote Docker daemon.
    docker_tls: bool = False

    # -- `ssh` executor only -------------------------------------------
    #
    # A tool on an `ssh` toolkit is shaped exactly like a `docker`/`local`
    # one (binary + argv, FR-5.3/5.4) -- what differs is only the transport:
    # `execute_ssh.py` runs the same resolved argv on a remote host over an
    # SSH exec channel instead of a local subprocess. Deliberately fixed,
    # allowlisted commands (this project's `local`/`docker` model), never
    # an interactive shell or an arbitrary-command "Linux CLI" tool -- that
    # class of tool has no boundary to validate against (REQUIREMENTS.md §17).

    ssh_host: str | None = None
    ssh_port: int = 22
    ssh_user: str | None = None
    #: `known_hosts`-file-format text (as `ssh-keyscan <host>` prints),
    #: pinning the exact host key(s) accepted for this toolkit. Required,
    #: not optional -- an SSH connection with host-key checking disabled
    #: (asyncssh's `known_hosts=None`) is trivially MITM-able, which this
    #: project's posture on target verification (FR-8.9's DNS-rebinding
    #: check for `http`) argues squarely against accepting here instead.
    ssh_known_hosts: str | None = None

    # -- `file` executor only ------------------------------------------

    #: The OS user the `file` executor's read/write/patch/list operations
    #: run as, either a name resolved through the container's passwd
    #: database (`"hermes"`) or a numeric `"uid:gid"` pair (`"3001:3001"`,
    #: the same notation `compose.yaml`'s own `user:` uses). `None` -- the
    #: default, and what every toolkit written before this field existed
    #: gets -- means the operations run in-process as whatever user
    #: gatekeeper itself runs as, exactly as before.
    #:
    #: Tier 1 and only Tier 1: there is no parameter, tool field, or admin
    #: API through which a call can pick a user (FR-8.3i says the same
    #: about destinations), and `toolkit_proposals.py` refuses it even in a
    #: human-reviewed proposal. Changing which user a toolkit's file
    #: operations run as is a redeploy.
    #:
    #: Rejected on any other executor. `http`/`docker`/`local`/`truenas`/
    #: `ssh` are unaffected by this field existing -- accepting it there
    #: silently would promise something none of them implements.
    run_as: str | None = None

    # -- `google` executor only ----------------------------------------
    #
    # The `google` executor runs `google_api.py` as a local subprocess
    # (shell=False, argv list -- FR-5.3/5.4/6.1, same model as `local`/
    # `docker`/`ssh`) and parses its JSON output. What differs from those
    # is the whitelist acts on *action strings* ("gmail search",
    # "calendar list") instead of binaries or path prefixes, and the
    # OAuth credential is materialized to a per-call tempfile rather than
    # passed as a header -- reuses the `allowed_rpc_methods` pattern from
    # the truenas executor, the same way that one reuses `allowed_methods`'s
    # field name.
    #: Absolute path to google_api.py inside the container. Required for a
    #: `google` toolkit; the binary that actually runs (python) is fixed by
    #: the executor, not configured here -- the same way `http` fixes the
    #: transport and only the toolkit chooses the target.
    google_script: str | None = None
    #: Optional: if set, the executor runs `docker exec <container> python
    #: <google_script> ...` instead of a local `python <google_script> ...`.
    #: A fallback for a deployment that keeps google_api.py and its deps in
    #: another container on the same Docker host -- not the primary path,
    #: but kept so the toolkit config can switch without a code change.
    google_container: str | None = None
    #: Whitelist of action strings this toolkit may ever call (FR-8.3c's
    #: google counterpart). "gmail.send" simply never appears in a
    #: read-only gmail toolkit's list -- there is no separate permission
    #: to deny it, it structurally does not exist.
    allowed_google_actions: tuple[str, ...] = ()

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
        """FR-8.6/FR-8.7: the path must start with an allowed prefix, at a
        segment boundary.

        Checked twice by callers -- once against the template's literal
        prefix at parse time, once against the fully resolved path at
        call time -- mirroring `check_binary`/`check_args` for argv tools.

        A bare `str.startswith` would let prefix `/api/v3/series` also match
        `/api/v3/seriesXYZ` -- the same ambiguity `validate.py`'s
        `_resolve_path` already rejects on the filesystem side via
        `commonpath` rather than a string prefix, for exactly the analogous
        `/mnt/raid` vs. `/mnt/raid-evil` reason. A prefix ending in `/`
        already has an unambiguous boundary built in; one that does not
        (an exact-endpoint prefix like `/api/v3/series`) additionally needs
        an exact match or the next character to be `/`.
        """
        for prefix in self.allowed_path_prefixes:
            if not path.startswith(prefix):
                continue
            if prefix.endswith("/") or path == prefix or path[len(prefix)] == "/":
                return True
        return False

    def in_allowed_cidrs(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address
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

    # -- `google` executor ----------------------------------------------

    def allows_google_action(self, action: str) -> bool:
        """The whitelist acts on google_api.py action strings.

        `gmail send` simply never appears in a read-only gmail toolkit's
        list -- there is no separate permission to deny it, it structurally
        does not exist. Mirrors `allows_rpc_method` for the same reason:
        both are "the finite set of operations this toolkit may ever
        perform", named differently by their respective protocols.
        """
        return action in self.allowed_google_actions


@dataclasses.dataclass(frozen=True, slots=True)
class Destination:
    """A concrete place a toolkit's actions may run (FR-8.3g, deploy-time).

    Mirrors Toolkit's own per-executor target fields -- exactly one of
    docker_host/base_url/ws_url is set, matching whichever executor the
    toolkit(s) referencing this destination use. Never carries
    binaries/allowed_methods/path_roots/limits -- those answer "what is
    allowed" and stay on the Toolkit, identical across all its destinations
    (FR-4.9). A tool defined against a toolkit with N declared destinations
    is expanded at catalog-load time into N independently-grantable tool
    IDs (FR-8.3h) -- see catalog.py.
    """

    name: str
    docker_host: str | None = None
    #: None (not declared) is distinct from an explicit `false` -- both
    #: must fall back to the toolkit's own docker_tls differently: unset
    #: inherits it, an explicit `false` overrides it even when the toolkit
    #: itself defaults to true. A plain `bool` couldn't tell these apart,
    #: which was a real bug (a destination could never opt out of a
    #: toolkit-level `docker_tls: true`).
    docker_tls: bool | None = None
    base_url: str | None = None
    ws_url: str | None = None
    #: Overrides the toolkit's own `credential` for this destination only.
    #: None means "use the toolkit's credential".
    credential: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class RateLimit:
    count: int
    window_seconds: int


@dataclasses.dataclass(frozen=True, slots=True)
class Tier1:
    """The complete deploy-time configuration."""

    toolkits: dict[str, Toolkit]
    destinations: dict[str, Destination]
    rate_limits: dict[str, RateLimit]
    max_concurrent: int
    audit_dir: str
    audit_max_bytes: int
    audit_keep_files: int
    #: FR-2.8 exception, declared at deploy time and therefore not
    #: reachable from the admin API (FR-4). When true, an `admin`-role
    #: identity may execute catalog tools through `admin.tool_exec`
    #: without holding a grant -- see `Service._admin_may_execute` for
    #: what that does and does not relax.
    #:
    #: Off by default, and deliberately so. With it on, `tool_create`
    #: (auto-applies) plus `tool_enable` (auto-applies for a `read`
    #: category) plus `tool_exec` is a path from an admin token to a
    #: running command that no human reviewed. Off, that path still ends
    #: at `grant_set`, which goes through the pending queue and
    #: `/ui/requests`. Turning it on is a decision about that trade,
    #: which is why it takes a redeploy rather than an API call.
    admin_exec: bool = False

    def toolkit(self, name: str) -> Toolkit:
        try:
            return self.toolkits[name]
        except KeyError:
            raise ConfigError(f"Unknown toolkit {name!r}") from None

    def destination(self, name: str) -> Destination:
        try:
            return self.destinations[name]
        except KeyError:
            raise ConfigError(f"Unknown destination {name!r}") from None

    def credential_references(self) -> dict[str, tuple[str, ...]]:
        """Credential name -> the labels of everything that refers to it.

        One source for two readers: the console's "Used by" row, and the
        startup check for a binding that names a credential the store does
        not have. Two hand-rolled copies of this walk would eventually
        disagree about destinations -- and a destination's own
        `credential:` overrides the toolkit's (FR-8.3g), so it is exactly
        the half that a second copy tends to forget.

        Names only. A reference is a name, never a value -- this stays as
        true here as everywhere else (FR-10.2).
        """
        refs: dict[str, list[str]] = {}
        for toolkit in self.toolkits.values():
            if toolkit.credential:
                refs.setdefault(toolkit.credential, []).append(toolkit.name)
        for dest in self.destinations.values():
            if dest.credential:
                refs.setdefault(dest.credential, []).append(f"{dest.name} (destination)")
        return {name: tuple(labels) for name, labels in refs.items()}


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


def _validate_url(
    value: str, where: str, field: str, schemes: tuple[str, ...], example: str,
    *, allow_path: bool = False,
) -> str:
    """Shared shape check behind `_validate_docker_host`/`_http_base_url`/

    `_ws_url` below -- same three steps for every `<scheme>://...` config
    field: split it, check the scheme is one of the allowed ones, check
    there's an address to connect to. `allow_path` is docker_host's
    `unix:///path/to/socket` case, where the address is a filesystem path
    rather than a network authority (`netloc`).
    """
    parsed = urlsplit(value)
    has_address = bool(parsed.netloc) or (allow_path and bool(parsed.path))
    if parsed.scheme not in schemes or not has_address:
        raise ConfigError(f"{where}: {field} {value!r} must be {example}")
    return value


def _validate_docker_host(value: str, where: str) -> str:
    return _validate_url(
        value, where, "docker_host", ("tcp", "unix"),
        "a 'tcp://host:port' or 'unix:///path/to/socket' URL", allow_path=True,
    )


def _validate_http_base_url(value: str, where: str, field: str = "base_url") -> str:
    return _validate_url(
        value, where, field, ("http", "https"),
        "an absolute http(s) URL, e.g. 'http://sonarr.lan:8989'",
    )


def _validate_ws_url(value: str, where: str, field: str = "ws_url") -> str:
    return _validate_url(
        value, where, field, ("ws", "wss"),
        "an absolute ws(s) URL, e.g. 'wss://truenas.lan/api/current'",
    )


def _parse_destinations(raw: dict[str, Any]) -> dict[str, Destination]:
    """Parses the top-level `destinations:` section (FR-8.3g).

    Shape validation against a *particular* executor happens where a
    toolkit references a destination (below) -- a bare destination spec
    here doesn't yet know which executor(s) will use it.
    """
    section = raw.get("destinations")
    if section is None:
        section = {}
    if not isinstance(section, dict):
        raise ConfigError("toolkits.yaml: section 'destinations' must be a mapping")

    destinations: dict[str, Destination] = {}
    for name, spec in section.items():
        where = f"destination {name!r}"
        if not isinstance(spec, dict):
            raise ConfigError(f"{where}: expects a mapping")

        docker_host = spec.get("docker_host")
        if docker_host is not None:
            docker_host = _validate_docker_host(str(docker_host), where)
        base_url = spec.get("base_url")
        if base_url is not None:
            base_url = _validate_http_base_url(str(base_url), where)
        ws_url = spec.get("ws_url")
        if ws_url is not None:
            ws_url = _validate_ws_url(str(ws_url), where)
        credential = spec.get("credential")
        if credential is not None and not isinstance(credential, str):
            raise ConfigError(f"{where}: 'credential' must be a string name")
        raw_docker_tls = spec.get("docker_tls")
        docker_tls = None if raw_docker_tls is None else bool(raw_docker_tls)

        destinations[name] = Destination(
            name=name,
            docker_host=docker_host,
            docker_tls=docker_tls,
            base_url=base_url,
            ws_url=ws_url,
            credential=credential,
        )
    return destinations


def _check_destination_shape(
    dest: Destination, executor: str, toolkit_where: str
) -> None:
    """A toolkit's destinations must carry the target field its executor
    reads (FR-8.3g) -- a `docker` toolkit pointed at a destination with only
    `base_url` set would silently connect nowhere.
    """
    where = f"{toolkit_where}: destination {dest.name!r}"
    if executor == "docker" and dest.docker_host is None:
        raise ConfigError(f"{where} has no 'docker_host', required for a docker toolkit")
    if executor == "http" and dest.base_url is None:
        raise ConfigError(f"{where} has no 'base_url', required for an http toolkit")
    if executor == "truenas" and dest.ws_url is None:
        raise ConfigError(f"{where} has no 'ws_url', required for a truenas toolkit")


def _toolkit_destinations(
    spec: dict[str, Any], executor: str, where: str, destinations: dict[str, Destination]
) -> tuple[str, ...]:
    """Resolves and validates one toolkit's `destinations:` list (FR-8.3g):

    `local` may not declare any (nothing remote to connect to), every name
    must exist in the top-level `destinations` section, and each must carry
    the field its executor needs.
    """
    dest_names = _str_tuple(spec.get("destinations"), where)
    if dest_names and executor == "local":
        raise ConfigError(
            f"{where}: 'local' toolkits cannot declare destinations -- "
            "there is nothing remote to connect to"
        )
    if dest_names and executor == "ssh":
        raise ConfigError(
            f"{where}: 'ssh' toolkits cannot declare destinations yet -- "
            "one toolkit, one host (use a separate toolkit per host)"
        )
    for dest_name in dest_names:
        if dest_name not in destinations:
            raise ConfigError(
                f"{where}: destination {dest_name!r} is not declared in "
                "the top-level 'destinations' section"
            )
        _check_destination_shape(destinations[dest_name], executor, where)
    return dest_names


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

    destinations = _parse_destinations(raw)

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
        docker_host: str | None = None
        docker_tls = False
        ssh_host: str | None = None
        ssh_port = 22
        ssh_user: str | None = None
        ssh_known_hosts: str | None = None
        google_script: str | None = None
        google_container: str | None = None
        allowed_google_actions: tuple[str, ...] = ()

        # `run_as` (file executor only). Parsed for every executor rather
        # than only inside the `file` branch below, so a `run_as` on an
        # `http`/`docker`/`local`/`truenas`/`ssh` toolkit aborts startup
        # instead of sitting in the file being silently ignored -- a
        # configuration that reads as "these operations run as someone
        # else" and does not is worse than one that refuses to start.
        run_as = spec.get("run_as")
        if run_as is not None:
            if executor != "file":
                raise ConfigError(
                    f"{where}: 'run_as' is only supported on a 'file' toolkit, "
                    f"not on {executor!r}. The other executors reach their "
                    "target as a remote user (ssh_user), through a socket, or "
                    "with a credential -- none of them runs local file "
                    "operations there is a user to choose for."
                )
            run_as = str(run_as).strip()
            try:
                parse_run_as(run_as)
            except RunAsError as exc:
                raise ConfigError(f"{where}: {exc}") from None

        dest_names = _toolkit_destinations(spec, executor, where, destinations)

        if executor in ("docker", "local", "ssh"):
            binaries = _str_tuple(_require(spec, "binaries", where), where)
            if not binaries:
                raise ConfigError(f"{where}: 'binaries' must not be empty")
            for binary in binaries:
                if not _is_absolute(binary):
                    raise ConfigError(
                        f"{where}: binary {binary!r} must be an absolute path -- "
                        "otherwise PATH decides what gets executed"
                    )
            if executor == "docker":
                raw_docker_host = spec.get("docker_host")
                if raw_docker_host is not None:
                    docker_host = _validate_docker_host(str(raw_docker_host), where)
                docker_tls = bool(spec.get("docker_tls", False))
            elif executor == "ssh":
                ssh_host = str(_require(spec, "ssh_host", where))
                ssh_port = int(spec.get("ssh_port", 22))
                if not 1 <= ssh_port <= 65535:
                    raise ConfigError(f"{where}: ssh_port {ssh_port} is out of range")
                ssh_user = str(_require(spec, "ssh_user", where))
                ssh_known_hosts = str(_require(spec, "ssh_known_hosts", where)).strip()
                if not ssh_known_hosts:
                    raise ConfigError(
                        f"{where}: 'ssh_known_hosts' must not be empty -- run "
                        "'ssh-keyscan -t ed25519 <host>' and paste its output here. "
                        "Host-key checking is not optional (FR-8.9's DNS-rebinding "
                        "check exists for the same reason: verify the target, not "
                        "just the name)."
                    )
        elif executor == "http":
            base_url = str(_require(spec, "base_url", where))
            base_url = _validate_http_base_url(base_url, where)
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
            ws_url = _validate_ws_url(ws_url, where)
            allowed_rpc_methods = _str_tuple(
                _require(spec, "allowed_rpc_methods", where), where
            )
            if not allowed_rpc_methods:
                raise ConfigError(f"{where}: 'allowed_rpc_methods' must not be empty")
        elif executor == "google":
            google_script = str(_require(spec, "google_script", where))
            if not _is_absolute(google_script):
                raise ConfigError(
                    f"{where}: 'google_script' must be an absolute path -- "
                    "otherwise PATH decides what gets executed"
                )
            raw_container = spec.get("google_container")
            if raw_container is not None:
                google_container = str(raw_container)
                if not google_container:
                    raise ConfigError(f"{where}: 'google_container' must not be empty")
            allowed_google_actions = _str_tuple(
                _require(spec, "allowed_google_actions", where), where
            )
            if not allowed_google_actions:
                raise ConfigError(f"{where}: 'allowed_google_actions' must not be empty")

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
            destinations=dest_names,
            docker_host=docker_host,
            docker_tls=docker_tls,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_known_hosts=ssh_known_hosts,
            run_as=run_as,
            google_script=google_script,
            google_container=google_container,
            allowed_google_actions=allowed_google_actions,
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
        destinations=destinations,
        rate_limits=rate_limits,
        max_concurrent=int(raw.get("max_concurrent", 4)),
        audit_dir=str(audit.get("dir", "/mnt/raid/gatekeeper/logs")),
        audit_max_bytes=int(audit.get("max_bytes", 32 * 1024 * 1024)),
        audit_keep_files=int(audit.get("keep_files", 10)),
        admin_exec=bool(raw.get("admin_exec", False)),
    )