"""Schreibzugriff auf Ebene 2 (REQUIREMENTS.md §7, Stufe 3).

Hier -- und nur hier -- veraendert gatekeeper seine eigene Konfiguration. Fuenf
Zusicherungen tragen diese Schicht:

1. **Ebene 1 bleibt unberuehrbar.** Es gibt keine Funktion, die `toolkits.yaml`
   schreibt. Binary-Allowlist, gesperrte Argumente, Pfad-Wurzeln, geschuetzte
   Ressourcen und Obergrenzen aendert ausschliesslich ein Redeploy (FR-4.11).

2. **Nur ein Pruefpfad.** Jede Definition laeuft durch `parse_tool_spec` --
   dieselbe Funktion, die beim Start prueft. Ein zweiter, milderer Weg wuerde
   die Grenze zur blossen Empfehlung machen.

3. **Atomar.** Geschrieben wird in eine Nachbardatei, die nach `fsync` per
   `os.replace` an ihren Platz rueckt. Ein Absturz mittendrin hinterlaesst die
   alte Datei, nie eine halbe.

4. **Was gilt, steht auf der Platte.** Nach jedem Schreibvorgang wird aus der
   Datei neu geladen und der laufende Zustand ausgetauscht. Die Anzeige kann
   damit nicht von dem abweichen, was ein Neustart ergaebe.

5. **Kein stilles Ueberschreiben.** Jedes Formular traegt die Revision der
   Datei, aus der es gebaut wurde. Hat inzwischen jemand anderes geschrieben,
   wird abgelehnt statt zugebuegelt.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import tempfile
import threading
from typing import Any

import yaml

from .audit import AuditLog
from .catalog import load_catalog, parse_tool_spec
from .errors import ConfigError
from .identity import (
    ADMIN_ROLE,
    Identity,
    MIN_PASSWORD_LENGTH,
    ROLES,
    UI_ROLES,
    dump_identities,
    generate_token,
    hash_token,
    load_identities,
    to_spec,
    verify_token,
)
from .service import Service

#: Kopf jeder geschriebenen Datei. Wer sie spaeter von Hand oeffnet, soll
#: sofort sehen, dass hier eine Oberflaeche mitschreibt.
_HEADER = (
    "# Von gatekeeper verwaltet. Die Admin-Oberflaeche schreibt diese Datei;\n"
    "# Aenderungen von Hand sind moeglich, gehen aber beim naechsten Schreiben\n"
    "# aus dem UI verloren, wenn sie nicht vorher neu geladen wurden.\n"
)


class WriteRefused(ConfigError):
    """Ein Schreibversuch wurde abgelehnt -- mit einem Grund fuer den Menschen."""


def revision(path: str) -> str:
    """Kurzer Fingerabdruck des Dateiinhalts fuer die Nebenlaeufigkeitspruefung."""
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()[:16]
    except OSError:
        return ""


def _atomic_write(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, prefix=".gk-", suffix=".tmp", delete=False
    )
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def _dump(payload: dict[str, Any]) -> str:
    return _HEADER + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def writable(path: str) -> bool:
    """Laesst sich hier ueberhaupt schreiben?

    Geprueft wird das Verzeichnis, nicht nur die Datei: `os.replace` legt eine
    neue Datei an. Ein Mount mit `:ro` faellt damit auf, bevor ein Admin ein
    Formular ausfuellt und erst beim Absenden merkt, dass nichts ankommt.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    return os.access(directory, os.W_OK) and (
        not os.path.exists(path) or os.access(path, os.W_OK)
    )


@dataclasses.dataclass(slots=True)
class ConfigStore:
    """Besitzt die Ebene-2-Dateien und den daraus abgeleiteten Laufzeitzustand."""

    service: Service
    identities: Any  # IdentityStore -- als Any, um einen Zirkelbezug zu sparen
    audit: AuditLog
    tools_path: str
    identities_path: str
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    # -- Zustand -----------------------------------------------------------

    def tools_revision(self) -> str:
        return revision(self.tools_path)

    def identities_revision(self) -> str:
        return revision(self.identities_path)

    def writability(self) -> dict[str, bool]:
        return {
            "tools": writable(self.tools_path),
            "identities": writable(self.identities_path),
        }

    def _check(self, path: str, supplied: str) -> None:
        """Optimistische Nebenlaeufigkeit."""
        if not writable(path):
            raise WriteRefused(
                f"{os.path.basename(path)} is not writable. The file or its "
                "directory is mounted read-only."
            )
        current = revision(path)
        if supplied and current and supplied != current:
            raise WriteRefused(
                "The file changed since this form was opened. Reload the page "
                "and apply your edit again -- otherwise it would silently "
                "discard someone else's change."
            )

    # -- Tools -------------------------------------------------------------

    def _write_tools(self, specs: list[dict[str, Any]]) -> None:
        _atomic_write(self.tools_path, _dump({"tools": specs}))
        # Aus der Datei neu laden, nicht aus dem Speicher: nur so ist belegt,
        # dass der Zustand im Betrieb dem entspricht, was ein Neustart ergaebe.
        self.service.catalog = load_catalog(self.tools_path, self.service.tier1)

    def _specs(self) -> list[dict[str, Any]]:
        return [dict(spec) for spec in self.service.catalog.raw]

    def save_tool(
        self,
        spec: dict[str, Any],
        *,
        actor: str,
        rev: str,
        replaces: str | None = None,
    ) -> str:
        """Legt eine Definition an oder ersetzt sie. Gibt die Tool-ID zurueck."""
        with self._lock:
            self._check(self.tools_path, rev)

            # Derselbe Pruefweg wie beim Start. Wirft ConfigError oder
            # Tier1Violation -- beides landet als Klartext im Formular.
            tool = parse_tool_spec(spec, self.service.tier1)

            specs = self._specs()
            existing = {s.get("id") for s in specs}
            if replaces is None and tool.id in existing:
                raise WriteRefused(f"A tool with ID {tool.id!r} already exists.")
            if replaces is not None and tool.id != replaces and tool.id in existing:
                raise WriteRefused(f"A tool with ID {tool.id!r} already exists.")

            if replaces is None:
                specs.append(spec)
            else:
                specs = [spec if s.get("id") == replaces else s for s in specs]

            self._write_tools(specs)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "tool_update" if replaces else "tool_create",
                    "target": tool.id,
                    "previous_id": replaces if replaces != tool.id else None,
                    "spec": spec,
                }
            )
            if replaces is not None and replaces != tool.id:
                self._orphan_warning(replaces)
            return tool.id

    def set_tool_enabled(self, tool_id: str, enabled: bool, *, actor: str, rev: str) -> None:
        with self._lock:
            self._check(self.tools_path, rev)
            specs = self._specs()
            if not any(s.get("id") == tool_id for s in specs):
                raise WriteRefused(f"No tool with ID {tool_id!r}.")
            for spec in specs:
                if spec.get("id") == tool_id:
                    spec["enabled"] = enabled
            self._write_tools(specs)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "tool_enable" if enabled else "tool_disable",
                    "target": tool_id,
                }
            )

    def delete_tool(self, tool_id: str, *, actor: str, rev: str) -> None:
        with self._lock:
            self._check(self.tools_path, rev)
            specs = self._specs()
            removed = [s for s in specs if s.get("id") == tool_id]
            if not removed:
                raise WriteRefused(f"No tool with ID {tool_id!r}.")
            self._write_tools([s for s in specs if s.get("id") != tool_id])
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "tool_delete",
                    "target": tool_id,
                    # Die vollstaendige Definition mitschreiben: eine Loeschung
                    # bleibt damit aus dem Log heraus wiederherstellbar.
                    "spec": removed[0],
                }
            )
            self._orphan_warning(tool_id)

    def _orphan_warning(self, tool_id: str) -> None:
        """Haelt fest, wer jetzt ein Recht auf ein Tool haelt, das es nicht gibt.

        Kein Fehler: das Recht laeuft ins Leere und wird beim Aufruf abgelehnt.
        Aber es ist eine stille Abweichung, und stille Abweichungen gehoeren
        ins Log.
        """
        holders = sorted(
            i.id for i in self.identities.identities.values() if tool_id in i.tools
        )
        if holders:
            self.audit.write(
                {
                    "kind": "admin_note",
                    "action": "dangling_grant",
                    "target": tool_id,
                    "identities": holders,
                }
            )

    # -- Identitaeten ------------------------------------------------------

    def _write_identities(self, payload: dict[str, Any]) -> None:
        _atomic_write(self.identities_path, _dump(payload))
        fresh = load_identities(self.identities_path)
        # Den Inhalt austauschen, nicht das Objekt: `AuthMiddleware` und die
        # UI-Routen halten eine Referenz auf den Store, nicht auf das Dict.
        self.identities.identities = fresh.identities

    def _admins(self, identities: dict[str, Identity]) -> list[str]:
        return [i.id for i in identities.values() if i.role == ADMIN_ROLE]

    @staticmethod
    def _check_password(password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise WriteRefused(
                f"The console password must be at least {MIN_PASSWORD_LENGTH} "
                "characters long."
            )

    def save_identity(
        self,
        *,
        identity_id: str,
        role: str,
        tools: list[str],
        scopes: list[str],
        actor: str,
        rev: str,
        replaces: str | None = None,
        password: str = "",
    ) -> None:
        """Aendert eine bestehende Identitaet.

        `password=""` heisst: das bestehende Konsolenpasswort bleibt. Ein
        leeres Feld im Formular darf keinen Zugang loeschen -- wer das will,
        setzt die Rolle auf `agent`.
        """
        with self._lock:
            self._check(self.identities_path, rev)
            if role not in ROLES:
                raise WriteRefused(f"Unknown role {role!r}.")
            if not identity_id or not identity_id.replace("-", "").replace("_", "").isalnum():
                raise WriteRefused(
                    "Identity ID must be alphanumeric (dashes and underscores allowed)."
                )

            current = dict(self.identities.identities)
            if replaces is None and identity_id in current:
                raise WriteRefused(f"An identity {identity_id!r} already exists.")
            if replaces is not None and identity_id != replaces and identity_id in current:
                raise WriteRefused(f"An identity {identity_id!r} already exists.")

            unknown = sorted(set(tools) - set(self.service.catalog.tools))
            if unknown:
                raise WriteRefused(f"Unknown tool IDs: {', '.join(unknown)}")

            payload = dump_identities(self.identities)
            entries = payload["identities"]

            if replaces is None:
                # Neue Identitaeten bekommen sofort einen Token, sonst gaebe es
                # einen Eintrag ohne gueltigen Hash -- und der Loader verweigert
                # den naechsten Start.
                raise WriteRefused(
                    "Use create_identity() for new entries -- a token is required."
                )

            previous = current[replaces]
            if password and role not in UI_ROLES:
                # Muss *vor* dem Schreiben scheitern: der Loader lehnt ein
                # Passwort auf einer Agentenrolle ab, und `_write_identities`
                # laedt direkt nach dem Schreiben neu. Erst hier zu bemerken
                # hiesse, die Datei bereits unlesbar gemacht zu haben.
                raise WriteRefused(
                    f"role {role!r} cannot sign in to the console, so a "
                    "password would be a door without a room. Choose "
                    f"{' or '.join(UI_ROLES)} instead."
                )
            if password:
                self._check_password(password)
                password_hash = hash_token(password)
            elif role in UI_ROLES:
                password_hash = previous.password_hash
            else:
                # Rolle `agent`: der Konsolenzugang faellt weg, und mit ihm
                # gehoert der Hash aus der Datei. Ihn stehen zu lassen waere
                # ein Zugang, der nach der naechsten Rollenaenderung stumm
                # wieder auflebt.
                password_hash = ""

            if role in UI_ROLES and not password_hash:
                raise WriteRefused(
                    f"role {role!r} needs a console password -- without one, "
                    f"{identity_id!r} could not sign in. Set one in this form."
                )

            updated = {
                "id": identity_id,
                "role": role,
                "token_hash": previous.token_hash,
                "tools": sorted(set(tools)),
                "scopes": [s for s in scopes if s],
            }
            if password_hash:
                updated["password_hash"] = password_hash
            entries = [updated if e["id"] == replaces else e for e in entries]

            self._guard_last_admin(entries, action=f"changing {replaces!r}")
            self._write_identities({"identities": entries})
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "identity_update",
                    "target": identity_id,
                    "previous_id": replaces if replaces != identity_id else None,
                    "role": role,
                    "tools": sorted(set(tools)),
                    "scopes": [s for s in scopes if s],
                    # Der Klartext wird nie protokolliert, die Tatsache schon:
                    # ein Passwortwechsel gehoert in die Spur.
                    "password_changed": bool(password),
                }
            )

    def create_identity(
        self,
        *,
        identity_id: str,
        role: str,
        tools: list[str],
        scopes: list[str],
        actor: str,
        rev: str,
        password: str = "",
    ) -> str:
        """Legt eine Identitaet an und gibt den Klartext-Token genau einmal zurueck.

        `viewer` und `admin` brauchen zusaetzlich ein Passwort: ohne eines
        entstuende ein Konsolenkonto, an dem sich niemand anmelden kann.
        """
        with self._lock:
            self._check(self.identities_path, rev)
            if role not in ROLES:
                raise WriteRefused(f"Unknown role {role!r}.")
            if not identity_id or not identity_id.replace("-", "").replace("_", "").isalnum():
                raise WriteRefused(
                    "Identity ID must be alphanumeric (dashes and underscores allowed)."
                )
            if identity_id in self.identities.identities:
                raise WriteRefused(f"An identity {identity_id!r} already exists.")
            unknown = sorted(set(tools) - set(self.service.catalog.tools))
            if unknown:
                raise WriteRefused(f"Unknown tool IDs: {', '.join(unknown)}")
            if role in UI_ROLES and not password:
                raise WriteRefused(
                    f"role {role!r} signs in to the console and therefore "
                    "needs a password."
                )
            if password and role not in UI_ROLES:
                raise WriteRefused(
                    f"role {role!r} cannot sign in to the console, so a "
                    "password would be a door without a room. Choose "
                    f"{' or '.join(UI_ROLES)} instead."
                )
            if password:
                self._check_password(password)

            token = generate_token()
            entry = {
                "id": identity_id,
                "role": role,
                "token_hash": hash_token(token),
                "tools": sorted(set(tools)),
                "scopes": [s for s in scopes if s],
            }
            if password:
                entry["password_hash"] = hash_token(password)
            payload = dump_identities(self.identities)
            payload["identities"].append(entry)
            self._write_identities(payload)
            # Der Klartext wird bewusst NICHT protokolliert (FR-2.6) -- weder
            # der Token noch das Passwort.
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "identity_create",
                    "target": identity_id,
                    "role": role,
                    "tools": sorted(set(tools)),
                    "scopes": [s for s in scopes if s],
                }
            )
            return token

    def rotate_token(self, identity_id: str, *, actor: str, rev: str) -> str:
        with self._lock:
            self._check(self.identities_path, rev)
            if identity_id not in self.identities.identities:
                raise WriteRefused(f"No identity {identity_id!r}.")
            token = generate_token()
            payload = dump_identities(self.identities)
            for entry in payload["identities"]:
                if entry["id"] == identity_id:
                    entry["token_hash"] = hash_token(token)
            self._write_identities(payload)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "token_rotate",
                    "target": identity_id,
                }
            )
            return token

    def set_password(
        self,
        identity_id: str,
        password: str,
        *,
        actor: str,
        rev: str,
        current_password: str = "",
        require_current: bool = False,
    ) -> None:
        """Setzt das Konsolenpasswort einer Identitaet.

        `require_current` gilt fuer die Selbstbedienung: wer sein eigenes
        Passwort aendert, muss das alte kennen. Sonst genuegte eine
        unbeaufsichtigte Sitzung, um den Zugang dauerhaft zu uebernehmen --
        das Abmelden allein wuerde ihn dann nicht mehr zurueckholen.
        Ein Administrator, der ein *fremdes* Passwort setzt, kennt das alte
        naturgemaess nicht; dort steht die Aenderung stattdessen mit Urheber
        im Audit-Log.
        """
        with self._lock:
            self._check(self.identities_path, rev)
            identity = self.identities.identities.get(identity_id)
            if identity is None:
                raise WriteRefused(f"No identity {identity_id!r}.")
            if identity.role not in UI_ROLES:
                raise WriteRefused(
                    f"{identity_id!r} has role {identity.role!r} and does not "
                    "sign in to the console. A password would change nothing."
                )
            if require_current and not verify_token(
                current_password, identity.password_hash
            ):
                raise WriteRefused("The current password is not correct.")
            self._check_password(password)

            payload = dump_identities(self.identities)
            for entry in payload["identities"]:
                if entry["id"] == identity_id:
                    entry["password_hash"] = hash_token(password)
            self._write_identities(payload)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "password_set",
                    "target": identity_id,
                    "self_service": identity_id == actor,
                }
            )

    def delete_identity(self, identity_id: str, *, actor: str, rev: str) -> None:
        with self._lock:
            self._check(self.identities_path, rev)
            if identity_id not in self.identities.identities:
                raise WriteRefused(f"No identity {identity_id!r}.")
            payload = dump_identities(self.identities)
            entries = [e for e in payload["identities"] if e["id"] != identity_id]
            self._guard_last_admin(entries, action=f"deleting {identity_id!r}")
            self._write_identities({"identities": entries})
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "identity_delete",
                    "target": identity_id,
                }
            )

    def _guard_last_admin(self, entries: list[dict[str, Any]], *, action: str) -> None:
        """Verhindert die Aussperrung.

        Bliebe kein `admin` uebrig, koennte niemand mehr einen anlegen -- die
        Oberflaeche waere fuer immer zu, und der einzige Ausweg fuehrte ueber
        einen Editor auf dem Host. Der Fehlerfall ist billig zu verhindern und
        teuer zu beheben.

        Seit der Konsolenanmeldung genuegt die Rolle allein nicht: ein
        Administrator ohne Passwort kann sich nicht anmelden und ist als
        letzter Ausweg wertlos. Geprueft wird das aber nur, wenn es vorher
        einen anmeldefaehigen Administrator *gab* -- eine Konfiguration aus
        einer aelteren Fassung soll sich nicht selbst blockieren.
        """
        if not any(e.get("role") == ADMIN_ROLE for e in entries):
            raise WriteRefused(
                f"Refused: {action} would leave no identity with role 'admin', "
                "and nobody could sign in to create one."
            )
        had_console = any(
            i.role == ADMIN_ROLE and i.password_hash
            for i in self.identities.identities.values()
        )
        keeps_console = any(
            e.get("role") == ADMIN_ROLE and e.get("password_hash") for e in entries
        )
        if had_console and not keeps_console:
            raise WriteRefused(
                f"Refused: {action} would leave no administrator with a "
                "console password, and nobody could sign in to set one."
            )


def set_password_in_file(path: str, identity_id: str, password: str) -> None:
    """Setzt ein Konsolenpasswort direkt in `identities.yaml`.

    Der Weg ohne laufenden Dienst: fuer `gatekeeper password` und fuer den
    Start, der einem Bestand aus einer aelteren Fassung erstmals ein Passwort
    gibt. Geladen wird vorher aus der Datei, geschrieben wird atomar -- damit
    gilt hier dieselbe Zusicherung wie fuer die Oberflaeche.
    """
    store = load_identities(path)
    identity = store.identities.get(identity_id)
    if identity is None:
        known = ", ".join(sorted(store.identities)) or "none"
        raise ConfigError(f"No identity {identity_id!r} in {path}. Known: {known}")
    if identity.role not in UI_ROLES:
        raise ConfigError(
            f"{identity_id!r} has role {identity.role!r} and does not sign in "
            f"to the console. Only {' and '.join(UI_ROLES)} do."
        )
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ConfigError(
            f"The console password must be at least {MIN_PASSWORD_LENGTH} "
            "characters long."
        )
    if not writable(path):
        raise ConfigError(
            f"{path} is not writable. The file or its directory is mounted "
            "read-only."
        )
    payload = dump_identities(store)
    for entry in payload["identities"]:
        if entry["id"] == identity_id:
            entry["password_hash"] = hash_token(password)
    _atomic_write(path, _dump(payload))


def load_tool_yaml(text: str) -> dict[str, Any]:
    """Liest genau eine Tool-Definition aus dem Formularfeld."""
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise WriteRefused(f"Not valid YAML: {exc}") from exc
    if not isinstance(parsed, dict):
        raise WriteRefused("Expected a single tool definition as a YAML mapping.")
    if "tools" in parsed and isinstance(parsed["tools"], list):
        raise WriteRefused(
            "Paste one tool definition, not the whole file -- drop the 'tools:' key."
        )
    return parsed


def tool_to_yaml(spec: dict[str, Any]) -> str:
    return yaml.safe_dump(spec, sort_keys=False, allow_unicode=True)


__all__ = [
    "ConfigStore",
    "WriteRefused",
    "load_tool_yaml",
    "revision",
    "set_password_in_file",
    "to_spec",
    "tool_to_yaml",
    "writable",
]
