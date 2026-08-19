"""Entry point, token and password tool."""

from __future__ import annotations

import argparse
import logging
import os
import sys

import uvicorn

from .audit import AuditLog, Redactor
from .catalog import load_catalog
from .credentials import KEY_ENV, CredentialStore, generate_master_key
from .errors import ConfigError
from .identity import (
    UI_ROLES,
    IdentityStore,
    generate_password,
    generate_token,
    hash_token,
    load_identities,
)
from .pending import PendingStore
from .server import build_app, log_startup
from .service import Service
from .store import ConfigStore, set_password_in_file
from .tier1 import load_tier1
from .ui import has_ui_identity

logger = logging.getLogger("gatekeeper")


def _config_dir() -> str:
    """Tier 1. May be mounted read-only."""
    return os.environ.get("GATEKEEPER_CONFIG_DIR", "/etc/gatekeeper")


def _state_dir() -> str:
    """Tier 2. Must be writable if the console is to write.

    Falls back to the configuration directory when the variable is not set --
    then everything sits in one mount, which suffices for simple setups.
    The bundled compose.yaml separates the two so that Tier 1 can actually
    be read-only.
    """
    return os.environ.get("GATEKEEPER_STATE_DIR") or _config_dir()


def _config_path(name: str, args_value: str | None) -> str:
    if args_value:
        return args_value
    base = (
        _state_dir()
        if name in ("tools.yaml", "identities.yaml", "credentials.yaml", "pending.yaml")
        else _config_dir()
    )
    return os.path.join(base, name)


def cmd_serve(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=os.environ.get("GATEKEEPER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # First start: a mounted, empty directory suffices. Only when none
    # of the three files exist -- see `_bootstrap_on_first_start`.
    if not (args.no_bootstrap or os.environ.get("GATEKEEPER_NO_BOOTSTRAP", "")
            in ("1", "true", "yes")):
        problem = _bootstrap_on_first_start(_config_dir(), _state_dir())
        if problem:
            # Do not continue: the loader would immediately
            # report "not found" and name the wrong cause.
            print(problem, file=sys.stderr)
            return 2

    try:
        tier1 = load_tier1(_config_path("toolkits.yaml", args.toolkits))
        catalog = load_catalog(
            _config_path("tools.yaml", args.tools), tier1, strict=args.strict
        )
        identities = load_identities(_config_path("identities.yaml", args.identities))
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    try:
        audit = AuditLog(
            tier1.audit_dir,
            max_bytes=tier1.audit_max_bytes,
            keep_files=tier1.audit_keep_files,
            redactor=Redactor(),
        )
    except OSError as exc:
        # Without an audit log, startup is refused. A service that brokers
        # host operations and cannot record them is worse than
        # none: the calls happen, but nobody knows which afterwards.
        print(
            f"Configuration error: cannot use the audit directory "
            f"{tier1.audit_dir!r}: {exc}\n"
            f"This process runs as {_whoami()}. Either mount a directory it "
            "owns there, or point 'audit.dir' in toolkits.yaml at one:\n"
            f"  chown -R {_whoami()} <the directory mounted at {tier1.audit_dir}>",
            file=sys.stderr,
        )
        return 2

    credentials_path = _config_path("credentials.yaml", args.credentials)
    credentials = CredentialStore(path=credentials_path, audit=audit)
    try:
        # Forces a load and, if any credential exists, a decrypt -- a
        # missing/wrong master key or a corrupt file fails startup here,
        # not on the first agent call that happens to need a credential.
        credentials.plaintext_values_for_masking()
    except ConfigError as exc:
        print(f"Configuration error: {credentials_path}: {exc}", file=sys.stderr)
        return 2
    audit.set_secrets(credentials.plaintext_values_for_masking())

    service = Service(
        tier1=tier1,
        catalog=catalog,
        audit=audit,
        credentials=credentials,
        docker_host=os.environ.get("DOCKER_HOST"),
    )

    def _on_credentials_change() -> None:
        audit.set_secrets(credentials.plaintext_values_for_masking())
        # A rotated docker_tls credential must not keep serving a stale
        # cert/key from service.py's temp-dir cache (FR-8.3g).
        service.invalidate_docker_tls_cache()

    credentials.on_change = _on_credentials_change

    log_startup(service, identities)

    # SIGHUP reloads all three configuration files without restarting
    # the process. Only Tier 1 (toolkits.yaml) truly needs this --
    # Tier 2 is reloaded by the console on write. But a
    # hand-edited state should take effect without a restart.
    import signal as _signal

    def _on_sighup(_signum: int, _frame: object) -> None:
        error = service.reload_config(
            toolkits_path=_config_path("toolkits.yaml", args.toolkits),
            tools_path=_config_path("tools.yaml", args.tools),
            identities_path=_config_path("identities.yaml", args.identities),
        )
        if error:
            logger.error("SIGHUP reload failed: %s", error)
        # On success, reload_config has already logged.

    _signal.signal(_signal.SIGHUP, _on_sighup)

    ui_enabled = args.ui or os.environ.get("GATEKEEPER_UI", "") in ("1", "true", "yes")
    if ui_enabled:
        identities_path = _config_path("identities.yaml", args.identities)
        if not any(i.role in UI_ROLES for i in identities.identities.values()):
            # Fail closed: a console without a sign-in-capable identity would
            # be an open surface with no use. Better not to start at all than
            # to offer a login form that nobody can get past.
            print(
                "Configuration error: --ui requires at least one identity with "
                "role: viewer or role: admin in identities.yaml.",
                file=sys.stderr,
            )
            return 2
        # After that, every console role has a password -- or
        # `problem` says why not, and then startup is refused.
        problem = _ensure_console_passwords(identities_path, identities)
        if problem:
            print(problem, file=sys.stderr)
            return 2
        assert has_ui_identity(identities)

    store = None
    pending = None
    if ui_enabled:
        read_only = args.ui_read_only or os.environ.get(
            "GATEKEEPER_UI_READ_ONLY", ""
        ) in ("1", "true", "yes")
        if read_only:
            logger.info("Console enabled at /ui (read-only, writes disabled by flag)")
        else:
            store = ConfigStore(
                service=service,
                identities=identities,
                audit=audit,
                tools_path=_config_path("tools.yaml", args.tools),
                identities_path=_config_path("identities.yaml", args.identities),
            )
            # A third Tier 2 file, alongside tools.yaml/identities.yaml --
            # proposals from /admin/mcp that a human has not yet approved
            # (or rejected) at /ui/pending.
            pending = PendingStore(
                path=_config_path("pending.yaml", args.pending),
                audit=audit,
            )
            stuck = sorted(n for n, ok in store.writability().items() if not ok)
            if stuck:
                # No startup abort: reading remains useful. But it must be in
                # the log, otherwise someone will look for the error in the form.
                logger.warning(
                    "Console writes will be refused: %s not writable (read-only mount?)",
                    ", ".join(f"{n}.yaml" for n in stuck),
                )
            logger.info(
                "Console enabled at /ui (admins may write; %d admin(s) configured); "
                "admin MCP endpoint enabled at /admin/mcp",
                sum(1 for i in identities.identities.values() if i.role == "admin"),
            )
            if not credentials.writable():
                logger.warning(
                    "Credential writes will be refused: credentials.yaml not "
                    "writable (read-only mount?)"
                )

    app = build_app(
        service=service,
        identities=identities,
        audit=audit,
        host=args.host,
        ui=ui_enabled,
        store=store,
        credentials=credentials if store is not None else None,
        pending=pending,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Validate the configuration strictly, without starting -- for CI and deploy."""
    try:
        tier1 = load_tier1(_config_path("toolkits.yaml", args.toolkits))
        catalog = load_catalog(_config_path("tools.yaml", args.tools), tier1, strict=True)
        identities = load_identities(_config_path("identities.yaml", args.identities))
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(tier1.toolkits)} toolkits, {len(catalog.tools)} tools, "
        f"{len(identities.identities)} identities"
    )
    for identity in identities.identities.values():
        unknown = sorted(identity.tools - set(catalog.tools))
        if unknown:
            print(
                f"WARNING: {identity.id!r} has rights on unknown tools: {unknown}",
                file=sys.stderr,
            )
    return 0


#: Tier 1, empty. gatekeeper makes no assumption about what an agent
#: should be able to reach -- only someone who knows the system knows that.
#: After `init`, nothing is possible; every toolkit is a deliberate decision
#: that costs a redeploy and therefore does not happen by the way.
_INIT_TOOLKITS = """\
# Tier 1 - deploy-time, immutable at runtime (REQUIREMENTS.md §6).
#
# Created empty by 'gatekeeper init'. As long as no toolkit is defined here,
# gatekeeper cannot execute anything - no administrator can change this,
# because the console creates tools but never a toolkit
# (FR-4.11). Extending means: edit this file and redeploy.
#
# A toolkit looks like this. The values are examples and must match
# the host - a complete set is in config/examples/toolkits.yaml:
#
# toolkits:
#   diag:
#     executor: local          # local | docker
#     binaries:                # absolute paths, exact allowlist (FR-4.1)
#       - /usr/bin/uptime
#     denied_args: []          # blocked subcommands and flags (FR-4.2)
#     path_roots: []           # roots for derived paths (FR-4.3)
#     protected_resources: []  # reachable by no tool (FR-4.12)
#     max_timeout_seconds: 10
#     max_output_bytes: 16384

toolkits: {{}}

# FR-6.8
rate_limits:
  read:
    count: 120
    window_seconds: 60
  write:
    count: 20
    window_seconds: 60
  write_external:
    count: 5
    window_seconds: 60

max_concurrent: 4

# FR-9.4/9.5 - append-only with rotation. Without rotation, the log fills the dataset.
audit:
  dir: {audit_dir}
  max_bytes: 33554432
  keep_files: 10
"""

_INIT_TOOLS = """\
# Catalog (REQUIREMENTS.md §7). Created empty - this is by design.
#
# Tools are created in the console at /ui; it writes this file.
# Examples to learn from are in config/examples/tools.yaml.

tools: []
"""


def _paths(config_dir: str, state_dir: str) -> dict[str, str]:
    return {
        "toolkits": os.path.join(config_dir, "toolkits.yaml"),
        "tools": os.path.join(state_dir, "tools.yaml"),
        "identities": os.path.join(state_dir, "identities.yaml"),
    }


def bootstrap(
    config_dir: str, state_dir: str, audit_dir: str | None = None
) -> tuple[str, str]:
    """Writes the empty state, returns token and console password.

    The administrator gets both, because both are needed and because they are two
    different things: the token addresses `/mcp`, the password opens
    the console. Both appear exactly once (FR-2.6).

    Shared core of `init` and first start. There is deliberately only one
    version: two paths that produce an initial configuration would eventually
    diverge -- and the less frequently used one would be the broken one.
    """
    for directory in {config_dir, state_dir}:
        os.makedirs(directory, exist_ok=True)

    paths = _paths(config_dir, state_dir)
    token = generate_token()
    password = generate_password()
    audit = audit_dir or os.path.join(state_dir, "logs")
    files = {
        paths["toolkits"]: _INIT_TOOLKITS.format(audit_dir=audit),
        paths["tools"]: _INIT_TOOLS,
        paths["identities"]: (
            "# Identities and permissions (REQUIREMENTS.md §4 and §9).\n"
            "#\n"
            "# Contains only hashes. The console creates further identities.\n"
            "#\n"
            "# Two separate credentials: 'token_hash' belongs to the API (/mcp),\n"
            "# 'password_hash' for signing in to the console (/ui). Losing one\n"
            "# does not mean losing both.\n\n"
            "identities:\n"
            "  - id: admin\n"
            "    role: admin\n"
            f'    token_hash: "{hash_token(token)}"\n'
            f'    password_hash: "{hash_token(password)}"\n'
            "    # An administrator needs no tool rights: the console\n"
            "    # calls nothing.\n"
            "    tools: []\n"
            "    scopes: []\n"
        ),
    }
    for path, content in files.items():
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    return token, password


def _whoami() -> str:
    """uid:gid of the running process, for a usable chown recommendation."""
    try:
        return f"{os.getuid()}:{os.getgid()}"  # type: ignore[attr-defined]
    except AttributeError:
        return "the container user"


def _bootstrap_on_first_start(config_dir: str, state_dir: str) -> str | None:
    """First start: if everything is missing, everything is created. If something is missing, not.

    This makes it sufficient to mount a directory and start the container.

    The condition is narrowly scoped, and that is the point: creation happens
    only when *none* of the three files exist. If even one were present, that
    would indicate an existing installation with a problem -- a slipped
    mount, perhaps. Overwriting that with a fresh configuration and a new
    administrator would hide the error and look like the catalog
    disappeared. Better to fail loudly.

    Returns `None` if there was nothing to do or it succeeded, otherwise
    a human-readable message. Writing is done optimistically rather than
    asking with `os.access` first: the pre-check can be wrong, and above all
    its silent exit was the worse diagnosis -- the loader would then report
    "not found" even though the directory was there and just owned by nobody.
    """
    paths = _paths(config_dir, state_dir)
    if any(os.path.exists(p) for p in paths.values()):
        return None

    try:
        token, password = bootstrap(config_dir, state_dir)
    except OSError as exc:
        return (
            f"Cannot create the configuration in {config_dir}: {exc}\n"
            f"This process runs as {_whoami()}. Docker creates a missing "
            "bind-mount source as root, which that user cannot write to.\n"
            "On the host, give the directory to the container user, then "
            "start again:\n"
            f"  chown -R {_whoami()} <the directory mounted at {config_dir}>"
        )
    logger.warning(
        "First start: created an empty configuration in %s. No toolkits, no "
        "tools, no agents -- gatekeeper can do nothing until you say what it "
        "may do.",
        config_dir,
    )
    # Both secrets are now in the container log. That is the price for
    # a first start without a second command; anyone who does not want this
    # uses `gatekeeper init` and GATEKEEPER_NO_BOOTSTRAP=1.
    logger.warning(
        "Administrator console password (shown once, and only here): %s -- "
        "sign in at /ui as 'admin', then change it there so it no longer "
        "lives in this log.",
        password,
    )
    logger.warning(
        "Administrator API token (shown once, and only here): %s -- for "
        "/mcp only; it does not sign in to /ui. Rotate it in the console.",
        token,
    )
    return None


def _ensure_console_passwords(path: str, identities: IdentityStore) -> str | None:
    """Gives console accounts without a password one -- once, into the log.

    The upgrade path. An `identities.yaml` from a version before
    console sign-in knows only tokens; after the upgrade nobody
    could sign in anymore. Three ways out were conceivable: let the token
    continue to count as a password (then the separation would be a
    mere claim), refuse to start (then a running deployment
    would stand still after an image change), or generate a password and write
    it to the log exactly once -- just as the first start does with the token
    anyway. The third way wins.

    Returns `None` if there was nothing to do or it succeeded, otherwise
    a human-readable message.
    """
    missing = [
        i.id
        for i in identities.identities.values()
        if i.role in UI_ROLES and not i.password_hash
    ]
    if not missing:
        return None

    for identity_id in missing:
        password = generate_password()
        try:
            set_password_in_file(path, identity_id, password)
        except (ConfigError, OSError) as exc:
            return (
                f"Configuration error: {identity_id!r} has role "
                f"{identities.identities[identity_id].role!r} but no console "
                f"password, and one cannot be written: {exc}\n"
                "Signing in to /ui needs a password since 0.3.0 -- the API "
                "token no longer opens the console. Set one on a writable "
                "copy of the file with:\n"
                f"  gatekeeper password --identity {identity_id}"
            )
        logger.warning(
            "Console password for %r (shown once, and only here): %s -- this "
            "identity had none; signing in to /ui needs one since 0.3.0. "
            "Change it under /ui/account so it no longer lives in this log.",
            identity_id,
            password,
        )

    # Reload from the file, not patched in memory: only this proves
    # that the running state matches what a restart would produce.
    identities.identities = load_identities(path).identities
    return None


def cmd_password(args: argparse.Namespace) -> int:
    """Sets the console password of an identity in `identities.yaml`.

    The way back in when nobody can get in anymore -- and the way in for
    a stock that does not yet know passwords.
    """
    path = _config_path("identities.yaml", args.identities)
    password = args.password or generate_password()
    try:
        set_password_in_file(path, args.identity, password)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: cannot write {path}: {exc}", file=sys.stderr)
        return 2
    print(f"Console password for {args.identity!r} in {path} set.")
    if not args.password:
        print(f"\nPassword (shown once):\n  {password}")
    print(
        "\nThis opens /ui only. The API token of this identity is unchanged "
        "and still authenticates /mcp."
    )
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Creates a runnable empty state: no tools, one administrator.

    gatekeeper deliberately ships without a catalog. A tool that
    brokers root-equivalent access should be able to do nothing after
    installation -- every capability from here on is a deliberate decision
    that is recorded in the audit log.
    """
    base = args.config_dir or _config_dir()
    state = args.state_dir or (_state_dir() if not args.config_dir else base)
    paths = _paths(base, state)

    existing = [p for p in paths.values() if os.path.exists(p)]
    if existing and not args.force:
        print(
            "Refusing to overwrite:\n  " + "\n  ".join(existing)
            + "\nPass --force to replace them. Note that this discards the "
            "current catalog and every identity, including their tokens.",
            file=sys.stderr,
        )
        return 1

    try:
        token, password = bootstrap(base, state, args.audit_dir)
    except OSError as exc:
        print(f"Cannot write the configuration: {exc}", file=sys.stderr)
        return 2

    print("Created:")
    for name in ("toolkits", "tools", "identities"):
        print(f"  {paths[name]}")
    print(
        "\nNo tools, no agents. Start with --ui and create what you need;\n"
        "every capability from here on is a deliberate, audited decision."
    )
    # Two lines, because there are two credentials. Collapsing them into one
    # would be exactly the misunderstanding that the separation is meant to resolve.
    print(
        f"\nAdministrator console password for /ui (shown once):\n  {password}"
        f"\n\nAdministrator API token for /mcp (shown once):\n  {token}"
    )
    return 0


def cmd_credential_key(args: argparse.Namespace) -> int:
    """Generates the master key for the credential store (REQUIREMENTS.md §11).

    Shown exactly once, like the token/password from `init` (FR-2.6). This
    is deliberately a separate command, not something `init`/`serve`
    generates on its own: the master key must sit outside the dataset that
    holds the ciphertext it protects (FR-10.3), and gatekeeper cannot know
    on its own where an operator wants that -- an env var here, a mounted
    secret file there.
    """
    key = generate_master_key()
    print(f"Credential master key (shown once):\n  {key}")
    print(
        f"\nSet it before starting gatekeeper, as {KEY_ENV} or in a file "
        "referenced by GATEKEEPER_CREDENTIAL_KEY_FILE. Losing it makes every "
        "stored credential unrecoverable -- back it up separately from "
        "credentials.yaml, never next to it."
    )
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    """Generates a token and outputs plaintext plus hash.

    The plaintext appears here exactly once (FR-2.6) -- only the hash
    belongs in the configuration.
    """
    token = args.token or generate_token()
    print(f"Token (shown once, goes into the agent config.yaml):\n  {token}\n")
    print(f"token_hash (goes into identities.yaml):\n  {hash_token(token)}")
    return 0


def cmd_integration(args: argparse.Namespace) -> int:
    """Prints the same toolkit YAML the `/ui/toolkits/reference` page shows.

    A terminal formatter around `integrations.INTEGRATIONS`, nothing more -- useful
    right after 'gatekeeper init', before --ui is even reachable, or for
    anyone who would rather copy from a shell than a browser.
    """
    from .integrations import INTEGRATIONS

    if args.integration_action == "list":
        for key in sorted(INTEGRATIONS):
            integration = INTEGRATIONS[key]
            print(f"{key:<14} {integration.display_name}")
        return 0

    integration = INTEGRATIONS.get(args.key)
    if integration is None:
        print(
            f"ERROR: no integration named {args.key!r}. Run 'gatekeeper integration list' "
            "to see the available ones.",
            file=sys.stderr,
        )
        return 1
    print(f"# {integration.display_name} -- paste under 'toolkits:' in toolkits.yaml,")
    print("# fill in the CHANGEME placeholders, then redeploy (FR-4.11).")
    if integration.notes:
        print(f"# {integration.notes}")
    print(integration.toolkit_yaml, end="")
    print(f"\n# {len(integration.tool_specs)} starter tool(s), created via /ui/tools/integrations:")
    for spec in integration.tool_specs:
        print(f"#   {spec['id']}: {spec.get('title', '')}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="gatekeeper")
    parser.add_argument("--toolkits")
    parser.add_argument("--tools")
    parser.add_argument("--identities")
    parser.add_argument("--credentials")
    parser.add_argument("--pending")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Start the server")
    serve.add_argument("--host", default=os.environ.get("GATEKEEPER_HOST", "0.0.0.0"))
    serve.add_argument(
        "--port", type=int, default=int(os.environ.get("GATEKEEPER_PORT", "8080"))
    )
    serve.add_argument(
        "--strict",
        action="store_true",
        help="Abort on a Tier 1 violation instead of disabling the tool",
    )
    serve.add_argument(
        "--ui",
        action="store_true",
        help="Serve the operations console at /ui (needs role: viewer or admin)",
    )
    serve.add_argument(
        "--ui-read-only",
        action="store_true",
        help="Serve the console without any write functions, whatever the roles say",
    )
    serve.add_argument(
        "--no-bootstrap",
        action="store_true",
        help="Never create configuration on start; fail if it is missing",
    )
    serve.set_defaults(func=cmd_serve)

    check = sub.add_parser("check", help="Validate the configuration")
    check.set_defaults(func=cmd_check)

    init = sub.add_parser(
        "init", help="Create an empty, runnable configuration and one administrator"
    )
    init.add_argument(
        "--config-dir", help="Where toolkits.yaml goes (default: GATEKEEPER_CONFIG_DIR)"
    )
    init.add_argument(
        "--state-dir",
        help="Where tools.yaml and identities.yaml go, must be writable "
        "(default: GATEKEEPER_STATE_DIR, else the config directory)",
    )
    init.add_argument("--audit-dir", help="Where the audit log goes (default: <state-dir>/logs)")
    init.add_argument(
        "--force", action="store_true", help="Overwrite existing files"
    )
    init.set_defaults(func=cmd_init)

    credential_key = sub.add_parser(
        "credential-key", help="Generate the credential store's master key"
    )
    credential_key.set_defaults(func=cmd_credential_key)

    integration = sub.add_parser(
        "integration", help="Print starter toolkit YAML for a known service"
    )
    integration_sub = integration.add_subparsers(dest="integration_action", required=True)
    integration_list = integration_sub.add_parser("list", help="List available integrations")
    integration_list.set_defaults(func=cmd_integration)
    integration_show = integration_sub.add_parser(
        "show", help="Print one integration's toolkit YAML and starter tools"
    )
    integration_show.add_argument("key", help="Integration key, e.g. sonarr (see 'integration list')")
    integration_show.set_defaults(func=cmd_integration)

    token = sub.add_parser("token", help="Generate an API token")
    token.add_argument("--token", help="Hash an existing token instead of generating one")
    token.set_defaults(func=cmd_token)

    password = sub.add_parser(
        "password", help="Set the console password of an identity (/ui sign-in)"
    )
    password.add_argument(
        "--identity", required=True, help="Which identity gets the password"
    )
    password.add_argument(
        "--password",
        help="Use this password instead of generating one. Beware the shell "
        "history -- omit it and gatekeeper generates one.",
    )
    password.set_defaults(func=cmd_password)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
