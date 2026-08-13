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


def _config_dir() -> str:
    """Ebene 1. Darf read-only gemountet sein."""
    return os.environ.get("GATEKEEPER_CONFIG_DIR", "/etc/gatekeeper")


def _state_dir() -> str:
    """Ebene 2. Muss beschreibbar sein, wenn die Oberflaeche schreiben soll.

    Faellt ohne gesetzte Variable auf das Konfigurationsverzeichnis zurueck --
    dann liegt alles in einem Mount, was fuer einfache Installationen genuegt.
    Die mitgelieferte compose.yaml trennt beides, damit Ebene 1 tatsaechlich
    read-only sein kann.
    """
    return os.environ.get("GATEKEEPER_STATE_DIR") or _config_dir()


def _config_path(name: str, args_value: str | None) -> str:
    if args_value:
        return args_value
    base = _state_dir() if name in ("tools.yaml", "identities.yaml") else _config_dir()
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


#: Ebene 1, leer. gatekeeper trifft keine Annahme darueber, was ein Agent
#: erreichen koennen soll -- das weiss nur, wer das System kennt. Nach `init`
#: ist nichts moeglich; jedes Toolkit ist eine bewusste Entscheidung, die einen
#: Redeploy kostet und damit nicht nebenbei passiert.
_INIT_TOOLKITS = """\
# Ebene 1 - Deploy-Zeit, zur Laufzeit unveraenderlich (REQUIREMENTS.md §6).
#
# Von 'gatekeeper init' leer angelegt. Solange hier kein Toolkit steht, kann
# gatekeeper nichts ausfuehren - auch kein Administrator kann daran etwas
# aendern, denn die Oberflaeche legt Tools an, aber niemals ein Toolkit
# (FR-4.11). Erweitern heisst: diese Datei bearbeiten und neu ausrollen.
#
# Ein Toolkit sieht so aus. Die Werte sind Beispiele und muessen zum Host
# passen - vollstaendiger Vorrat in config/examples/toolkits.yaml:
#
# toolkits:
#   diag:
#     executor: local          # local | docker
#     binaries:                # absolute Pfade, exakte Allowlist (FR-4.1)
#       - /usr/bin/uptime
#     denied_args: []          # gesperrte Unterbefehle und Flags (FR-4.2)
#     path_roots: []           # Wurzeln fuer abgeleitete Pfade (FR-4.3)
#     protected_resources: []  # fuer kein Tool erreichbar (FR-4.12)
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

# FR-9.4/9.5 - append-only mit Rotation. Ohne Rotation fuellt das Log das Dataset.
audit:
  dir: {audit_dir}
  max_bytes: 33554432
  keep_files: 10
"""

_INIT_TOOLS = """\
# Katalog (REQUIREMENTS.md §7). Leer angelegt - so ist es gemeint.
#
# Tools legt man in der Oberflaeche unter /ui an; sie schreibt diese Datei.
# Vorlagen zum Abschauen stehen in config/examples/tools.yaml.

tools: []
"""


def cmd_init(args: argparse.Namespace) -> int:
    """Legt einen lauffaehigen Leerzustand an: keine Tools, ein Administrator.

    gatekeeper liefert bewusst keinen Katalog mit. Ein Werkzeug, das
    root-aequivalenten Zugriff vermittelt, soll nach der Installation nichts
    koennen -- jede Faehigkeit ist danach eine bewusste Entscheidung, die im
    Audit-Log steht.
    """
    base = args.config_dir or _config_dir()
    state = args.state_dir or (_state_dir() if not args.config_dir else base)
    paths = {
        "toolkits": os.path.join(base, "toolkits.yaml"),
        "tools": os.path.join(state, "tools.yaml"),
        "identities": os.path.join(state, "identities.yaml"),
    }

    existing = [p for p in paths.values() if os.path.exists(p)]
    if existing and not args.force:
        print(
            "Refusing to overwrite:\n  " + "\n  ".join(existing)
            + "\nPass --force to replace them. Note that this discards the "
            "current catalog and every identity, including their tokens.",
            file=sys.stderr,
        )
        return 1

    for directory in {base, state}:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            print(f"Cannot create {directory}: {exc}", file=sys.stderr)
            return 2

    token = generate_token()
    audit_dir = args.audit_dir or os.path.join(state, "logs")
    files = {
        paths["toolkits"]: _INIT_TOOLKITS.format(audit_dir=audit_dir),
        paths["tools"]: _INIT_TOOLS,
        paths["identities"]: (
            "# Identitaeten und Rechte (REQUIREMENTS.md §4 und §9).\n"
            "#\n"
            "# Enthaelt nur Hashes. Weitere Identitaeten legt die Oberflaeche an.\n\n"
            "identities:\n"
            "  - id: admin\n"
            "    role: admin\n"
            f'    token_hash: "{hash_token(token)}"\n'
            "    # Ein Administrator braucht keine Tool-Rechte: die Oberflaeche\n"
            "    # ruft nichts auf.\n"
            "    tools: []\n"
            "    scopes: []\n"
        ),
    }
    for path, content in files.items():
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    print("Created:")
    for name in ("toolkits", "tools", "identities"):
        print(f"  {paths[name]}")
    print(
        "\nNo tools, no agents. Start with --ui and create what you need;\n"
        "every capability from here on is a deliberate, audited decision."
    )
    print(f"\nAdministrator token (shown once):\n  {token}")
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

    token = sub.add_parser("token", help="Generate a token")
    token.add_argument("--token", help="Hash an existing token instead of generating one")
    token.set_defaults(func=cmd_token)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
