"""Parametervalidierung und argv-Bau (REQUIREMENTS.md §8).

Das Herzstueck. Die tragende Zusicherung ist FR-5.4:

    Ein Parameter expandiert immer zu genau einem argv-Element.

Das ist keine Frage der Sorgfalt beim Escapen, sondern eine Struktureigenschaft:
jedes argv-Template-Element wird zu genau einem String aufgeloest und als ein
Listenelement an `execve` uebergeben. Es gibt keinen Shell-Interpreter, der einen
Wert nachtraeglich in mehrere Woerter zerlegen koennte. Ein Parameterwert kann
deshalb strukturell kein zusaetzliches Argument erzeugen -- unabhaengig davon,
welche Zeichen er enthaelt.

Die Zeichenpruefung in `_reject_control_characters` ist Defense-in-Depth
(FR-6.3), nicht der Primaerschutz. Der Primaerschutz ist die Allowlist pro
Parameter (FR-6.2).
"""

from __future__ import annotations

import os
import re
from typing import Any

from .catalog import PLACEHOLDER_RE, Parameter, ToolDef
from .errors import Denied, DenialReason
from .tier1 import Toolkit


def _reject_control_characters(name: str, value: str) -> None:
    """FR-6.3: Steuerzeichen und Nullbytes sind ein Angriffsindikator.

    Wird vor der Pattern-Pruefung ausgefuehrt, weil ein nachlaessiges Pattern
    (etwa mit `.`) sie sonst durchlassen koennte.
    """
    for char in value:
        codepoint = ord(char)
        if codepoint < 0x20 or codepoint == 0x7F:
            raise Denied(
                DenialReason.CONTROL_CHARACTER,
                f"Parameter {name!r} contains a control character (U+{codepoint:04X}).",
            )


def _validate_scalar(param: Parameter, value: Any) -> str:
    """Prueft einen vom Agenten gelieferten Wert und gibt ihn als String zurueck."""
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

    # string -- Allowlist per Pattern, vollstaendige Uebereinstimmung.
    # `fullmatch` statt `match`, weil `match` nur den Anfang prueft und damit
    # jeden Suffix durchliesse.
    if param.pattern is not None and not param.pattern.fullmatch(value):
        raise Denied(
            DenialReason.PARAM_INVALID,
            f"Parameter {name!r}: value does not match the allowed pattern.",
        )
    return value


def _substitute(template: str, values: dict[str, str]) -> str:
    """Ersetzt Platzhalter. Das Ergebnis ist immer genau ein String."""

    def replace(match: re.Match[str]) -> str:
        return values[match.group(1)]

    return PLACEHOLDER_RE.sub(replace, template)


def _resolve_path(param: Parameter, raw: str) -> str:
    """Loest einen abgeleiteten Pfad auf und prueft ihn gegen seine Wurzel.

    `realpath` loest Symlinks auf -- damit faellt der Ausbruch ueber einen
    praeparierten Symlink innerhalb der erlaubten Wurzel auf (FR-4.3).
    Der Vergleich laeuft ueber `commonpath` statt ueber einen String-Praefix,
    weil `/mnt/raid-evil` sonst als unterhalb von `/mnt/raid` gelten wuerde.
    """
    root = param.must_resolve_under or ""

    # Die Bausteine sind bereits Allowlist-geprueft und koennen weder '/' noch
    # '..' enthalten. Die Pruefung hier faengt ein fehlerhaftes derived-Template ab.
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
        # Unterschiedliche Laufwerke (Windows) -- kann nie unterhalb liegen.
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
    """Validiert die Agenten-Eingabe und ergaenzt die abgeleiteten Werte."""
    agent_params = tool.agent_parameters

    for name in arguments:
        param = tool.parameters.get(name)
        if param is None:
            raise Denied(
                DenialReason.PARAM_UNKNOWN,
                f"Unknown parameter {name!r}.",
            )
        if param.is_derived:
            # FR-5.5: Abgeleitete Werte berechnet der Server. Wer sie mitschickt,
            # versucht, die Ableitung zu umgehen.
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

    # Abgeleitete Parameter nach den Agenten-Parametern, damit sie auf ihnen
    # aufbauen koennen.
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
    """Baut die Argumentliste und prueft sie erneut gegen Ebene 1.

    Die zweite Pruefung ist kein Ritual: sie greift auf das *aufgeloeste* argv.
    Ein Parameterwert, der zu einem gesperrten Unterbefehl aufloest, wird hier
    gefangen -- die Pruefung beim Laden sah nur das Template.
    """
    argv = [tool.binary]
    for element in tool.argv:
        missing = _placeholders_missing(element, values)
        if missing:
            raise Denied(
                DenialReason.PARAM_MISSING,
                f"Argument template needs {sorted(missing)}.",
            )
        # Genau ein Listenelement pro Template-Element -- das ist FR-5.4.
        argv.append(_substitute(element, values))

    toolkit.check_binary(tool.binary)
    if denied := toolkit.check_args(argv):
        raise Denied(
            DenialReason.TIER1_VIOLATION,
            f"Argument {denied!r} is denied for this toolkit.",
        )
    return argv


def resolve_scopes(tool: ToolDef, values: dict[str, str]) -> list[str]:
    """Loest `required_scopes` mit den geprueften Parameterwerten auf."""
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
    """FR-4.12: geschuetzte Ressourcen, unabhaengig von Rechten und Scopes.

    Ein `docker.compose_down` auf den eigenen Stack besteht jede andere
    Pruefung: erlaubtes Binary, gueltiger Name, Pfad unterhalb der Wurzel.
    Nur diese Liste weiss, dass gatekeeper sich damit selbst beendet.
    """
    for scope in scopes:
        _, _, resource = scope.partition(":")
        if resource and toolkit.is_protected(resource):
            raise Denied(
                DenialReason.PROTECTED_RESOURCE,
                f"Resource {resource!r} is protected and reachable by no tool.",
            )
