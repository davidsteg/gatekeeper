"""Ebene 1 - die zur Laufzeit unveraenderlichen Grenzen (REQUIREMENTS.md §6).

Alles hier wird beim Start aus `toolkits.yaml` gelesen und danach nie wieder
angefasst. Die Admin-API (Stufe 3) kann Tools anlegen, aber kein Toolkit --
sonst waere Ebene 1 zur Laufzeit veraenderbar und der ganze Entwurf haette
keinen Boden mehr (FR-4.11).
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import PurePosixPath
from typing import Any

import yaml

from .errors import ConfigError

#: In Stufe 1 implementierte Executor-Typen. `truenas`/`http`/`ssh` folgen in
#: Stufe 2 -- ein Toolkit, das sie referenziert, wird jetzt abgelehnt (FR-8.1).
KNOWN_EXECUTORS = frozenset({"docker", "local"})


@dataclasses.dataclass(frozen=True, slots=True)
class Toolkit:
    """Traeger der Ebene-1-Grenzen (FR-4.8).

    Grenzen haengen am Toolkit, nicht global: `diag.uptime` braucht keine
    Pfad-Wurzel unter /mnt/raid, `docker.compose_up` schon. Eine globale
    Allowlist waere die Vereinigungsmenge aller Beduerfnisse (FR-4.9).
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
        """FR-4.1: Executable muss exakt in der Allowlist stehen."""
        if binary not in self.binaries:
            raise ConfigError(
                f"Toolkit {self.name!r}: binary {binary!r} is not in the "
                f"allowlist {list(self.binaries)}"
            )

    def check_args(self, argv: list[str]) -> str | None:
        """FR-4.2: Gesperrte Unterbefehle und Flags.

        Greift auf das *aufgeloeste* argv, nicht auf das Template -- ein
        Parameterwert, der zu `rm` aufloest, wird genauso gefangen.
        """
        for arg in argv:
            if arg in self.denied_args:
                return arg
        return None

    def check_path_root(self, root: str) -> None:
        """Ein `must_resolve_under` muss innerhalb der Toolkit-Wurzeln liegen.

        FR-4.10: ein Tool darf die Grenzen seines Toolkits verschaerfen,
        niemals erweitern.
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
        """FR-4.12: geschuetzte Ressourcen, unabhaengig von Rechten und Scopes.

        Ebene 1 kann Syntax pruefen, aber keine Bedeutung: `docker compose down`
        ist fuer den Validator dieselbe Operation, egal ob sie einen Medien-Stack
        oder gatekeeper selbst trifft.
        """
        return resource in self.protected_resources


@dataclasses.dataclass(frozen=True, slots=True)
class RateLimit:
    count: int
    window_seconds: int


@dataclasses.dataclass(frozen=True, slots=True)
class Tier1:
    """Die vollstaendige Deploy-Zeit-Konfiguration."""

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
    """Absolut nach POSIX- ODER nach Host-Konvention.

    Die Pfade in `toolkits.yaml` beschreiben immer das Container-Dateisystem,
    also POSIX -- `os.path.isabs` allein wuerde `/usr/bin/docker` unter Windows
    ab Python 3.13 ablehnen und die Konfiguration damit nur dort pruefbar
    machen, wo sie auch laeuft. Entscheidend ist ohnehin nur, dass kein blosser
    Programmname stehenbleibt, ueber den dann PATH entscheiden wuerde.
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
    """Laedt und validiert `toolkits.yaml`. Fehler hier brechen den Start ab.

    Anders als der Katalog hat Ebene 1 keinen sinnvollen Leerzustand: sie ist
    die Grenze, innerhalb derer alles andere stattfindet. Fehlt sie, ist nicht
    entschieden, was erlaubt waere -- und Raten waere hier der falsche Reflex.
    """
    if not os.path.exists(path):
        raise ConfigError(
            f"{path} not found. Tier 1 defines what is possible at all and has "
            "no safe default -- create it before starting. A starting point "
            "sits in config/examples/toolkits.yaml, or run 'gatekeeper init'."
        )
    with open(path, encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    # Ein leerer Abschnitt ist zulaessig und der Zustand nach `init`: dann ist
    # nichts moeglich. Das ist eine gueltige Aussage, keine fehlende -- und die
    # einzige, die gatekeeper von sich aus treffen darf. Welche Binaries ein
    # Agent erreichen koennen soll, weiss nur, wer das System kennt.
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
