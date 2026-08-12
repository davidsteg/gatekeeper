"""Einstiegspunkt und Token-Werkzeug."""

from __future__ import annotations

import argparse
import logging
import os
import sys

import uvicorn

from .audit import AuditLog, Redactor
from .catalog import load_catalog
from .errors import ConfigError
from .identity import generate_token, hash_token, load_identities
from .server import build_app, log_startup
from .service import Service
from .store import ConfigStore
from .tier1 import load_tier1
from .ui import has_ui_identity

logger = logging.getLogger("gatekeeper")


def _config_path(name: str, args_value: str | None) -> str:
    if args_value:
        return args_value
    base = os.environ.get("GATEKEEPER_CONFIG_DIR", "/etc/gatekeeper")
    return os.path.join(base, name)


def cmd_serve(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=os.environ.get("GATEKEEPER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        tier1 = load_tier1(_config_path("toolkits.yaml", args.toolkits))
        catalog = load_catalog(
            _config_path("tools.yaml", args.tools), tier1, strict=args.strict
        )
        identities = load_identities(_config_path("identities.yaml", args.identities))
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    audit = AuditLog(
        tier1.audit_dir,
        max_bytes=tier1.audit_max_bytes,
        keep_files=tier1.audit_keep_files,
        redactor=Redactor(),
    )
    service = Service(
        tier1=tier1,
        catalog=catalog,
        audit=audit,
        docker_host=os.environ.get("DOCKER_HOST"),
    )
    log_startup(service, identities)

    ui_enabled = args.ui or os.environ.get("GATEKEEPER_UI", "") in ("1", "true", "yes")
    if ui_enabled and not has_ui_identity(identities):
        # Fail closed: eine Oberflaeche ohne anmeldefaehige Identitaet waere eine
        # offene Flaeche ohne Nutzen. Lieber gar nicht starten als eine
        # Anmeldemaske anbieten, hinter die niemand kommt.
        print(
            "Configuration error: --ui requires at least one identity with "
            "role: viewer or role: admin in identities.yaml.",
            file=sys.stderr,
        )
        return 2

    store = None
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
            stuck = sorted(n for n, ok in store.writability().items() if not ok)
            if stuck:
                # Kein Startabbruch: lesen bleibt nuetzlich. Aber es muss im Log
                # stehen, sonst sucht jemand den Fehler im Formular.
                logger.warning(
                    "Console writes will be refused: %s not writable (read-only mount?)",
                    ", ".join(f"{n}.yaml" for n in stuck),
                )
            logger.info(
                "Console enabled at /ui (admins may write; %d admin(s) configured)",
                sum(1 for i in identities.identities.values() if i.role == "admin"),
            )

    app = build_app(
        service=service,
        identities=identities,
        audit=audit,
        host=args.host,
        ui=ui_enabled,
        store=store,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Konfiguration streng pruefen, ohne zu starten -- fuer CI und Deploy."""
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


def cmd_token(args: argparse.Namespace) -> int:
    """Erzeugt einen Token und gibt Klartext plus Hash aus.

    Der Klartext erscheint hier genau einmal (FR-2.6) -- in die Konfiguration
    gehoert ausschliesslich der Hash.
    """
    token = args.token or generate_token()
    print(f"Token (shown once, goes into the agent config.yaml):\n  {token}\n")
    print(f"token_hash (goes into identities.yaml):\n  {hash_token(token)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="gatekeeper")
    parser.add_argument("--toolkits")
    parser.add_argument("--tools")
    parser.add_argument("--identities")
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
    serve.set_defaults(func=cmd_serve)

    check = sub.add_parser("check", help="Validate the configuration")
    check.set_defaults(func=cmd_check)

    token = sub.add_parser("token", help="Generate a token")
    token.add_argument("--token", help="Hash an existing token instead of generating one")
    token.set_defaults(func=cmd_token)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
