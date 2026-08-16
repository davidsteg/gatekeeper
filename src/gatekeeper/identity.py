"""Identitaeten, Tokens, Passwoerter und Rechte (REQUIREMENTS.md §4 und §9).

Eine Identitaet traegt zwei getrennte Nachweise, und die Trennung ist
Absicht (FR-11.5):

* **Token** -- fuer die API. Geht als `Authorization: Bearer` an `/mcp` und
  gehoert in die Konfiguration eines Agenten, nicht in einen Browser.
* **Passwort** -- fuer die Konsole unter `/ui`. Nur `viewer` und `admin`
  haben eines; ein Agent bekommt keines, weil er sich nirgends anmeldet.

Der Grund fuer zwei Nachweise statt einem: ein Token, das jemand in ein
Anmeldeformular tippt, liegt danach in der Zwischenablage, im Passwortspeicher
des Browsers und mit etwas Pech im Verlauf -- und dasselbe Geheimnis oeffnet
dann auch noch `/mcp`. Wer eines von beiden verliert, soll nicht beides
verlieren: ein gestohlenes Konsolenpasswort ruft keine Tools auf, ein
gestohlener Token oeffnet keine Oberflaeche.

Beides liegt ausschliesslich als scrypt-Hash vor (FR-2.4). Damit ist
`identities.yaml` nicht secret-kritisch und darf nach Homelab-Regel im
Dataset mit chown 568:568 liegen.
"""

from __future__ import annotations

import base64
import dataclasses
import fnmatch
import functools
import hashlib
import hmac
import os
import secrets
from typing import Any

import yaml

from .errors import ConfigError, read_config_file

#: scrypt-Parameter. n=2**15 kostet rund 32 MB und ~50 ms -- fuer eine
#: Handvoll Tokens pro Sekunde reichlich, fuer Brute-Force teuer genug.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32

_PREFIX = "scrypt"

#: `viewer` und `admin` unterscheiden Lesen und Schreiben im Betriebs-UI.
#: Ohne diese Trennung haette jeder, der das Audit-Log ansehen darf, zugleich
#: das Recht, Tools anzulegen und Rechte zu vergeben.
ROLES = ("agent", "viewer", "admin")

#: Rollen, die sich am UI anmelden duerfen. `agent` gehoert nicht dazu: ein
#: Agenten-Token ist fuer `/mcp` gedacht und oeffnet keine Oberflaeche.
UI_ROLES = ("viewer", "admin")

#: Nur diese Rolle darf schreiben.
ADMIN_ROLE = "admin"

#: Mindestlaenge eines Konsolenpassworts. Kein Zeichenklassen-Zwang: Laenge
#: traegt hier mehr als ein Grossbuchstabe an Position drei, und die Anmeldung
#: ist zusaetzlich gedrosselt (`LoginThrottle`) sowie durch scrypt gebremst.
MIN_PASSWORD_LENGTH = 12


def hash_token(token: str, *, salt: bytes | None = None) -> str:
    """Erzeugt `scrypt$n$r$p$salt$hash`.

    Dieselbe Funktion hasht Tokens und Passwoerter -- es gibt keinen Grund,
    zwei Verfahren zu pflegen, und das schwaechere waere dann das, das man
    vergisst.
    """
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(
        token.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=64 * 1024 * 1024,
    )
    return "$".join(
        [
            _PREFIX,
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(derived).decode("ascii"),
        ]
    )


def verify_token(token: str, encoded: str) -> bool:
    """Prueft einen Token gegen seinen Hash -- in konstanter Zeit (FR-2.5)."""
    try:
        prefix, n_s, r_s, p_s, salt_b64, hash_b64 = encoded.split("$")
        if prefix != _PREFIX:
            return False
        derived = hashlib.scrypt(
            token.encode("utf-8"),
            salt=base64.b64decode(salt_b64),
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(base64.b64decode(hash_b64)),
            maxmem=64 * 1024 * 1024,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, base64.b64decode(hash_b64))


def generate_token() -> str:
    """Erzeugt einen neuen Agenten-Token."""
    return "gk_" + secrets.token_urlsafe(32)


def generate_password() -> str:
    """Erzeugt ein Konsolenpasswort.

    Ohne `gk_`-Praefix: das Praefix markiert einen API-Token, und die beiden
    sollen sich auch im Klartext auseinanderhalten lassen.
    """
    return secrets.token_urlsafe(18)


@functools.cache
def _decoy_hash() -> str:
    """Ein Hash, gegen den kein Passwort passt.

    Gebraucht wird er, damit eine Anmeldung mit unbekannter Kennung genauso
    lange dauert wie eine mit bekannter. Ohne ihn waere die Antwortzeit ein
    Verzeichnis aller Konsolenkennungen. Erst bei Bedarf berechnet -- scrypt
    kostet rund 50 ms, und die will kein Importvorgang bezahlen.
    """
    return hash_token(secrets.token_urlsafe(32))


@dataclasses.dataclass(frozen=True, slots=True)
class Identity:
    id: str
    role: str
    token_hash: str
    tools: frozenset[str]
    scopes: tuple[str, ...]
    #: Leer heisst: diese Identitaet kann sich an der Konsole nicht anmelden.
    #: Bei `agent` ist das der Normalfall.
    password_hash: str = ""

    @property
    def can_sign_in(self) -> bool:
        """Darf und kann sich diese Identitaet an der Konsole anmelden?

        Beides muss stimmen: die Rolle erlaubt es, und ein Passwort ist
        gesetzt. Eine Rolle ohne Passwort ist kein Zugang, sondern eine
        Zeile in einer Datei.
        """
        return self.role in UI_ROLES and bool(self.password_hash)

    def may_call(self, tool_id: str) -> bool:
        """FR-7.5: Rechte haengen an Tool-IDs, nie an einem ganzen Toolkit.

        Bewusst kein Praefix- oder Wildcard-Abgleich auf Toolkit-Ebene: sonst
        besaesse diese Identitaet jedes kuenftig im Toolkit angelegte Tool
        automatisch mit.
        """
        return tool_id in self.tools

    def covers_scope(self, scope: str) -> bool:
        """Prueft einen aufgeloesten Scope gegen die Muster des Profils."""
        return any(fnmatch.fnmatchcase(scope, pattern) for pattern in self.scopes)


@dataclasses.dataclass(slots=True)
class IdentityStore:
    identities: dict[str, Identity]

    def authenticate(self, token: str) -> Identity | None:
        """Loest einen API-Token zu einer Identitaet auf.

        Prueft gegen alle Hashes, ohne beim ersten Treffer abzukuerzen, damit
        die Laufzeit nicht verraet, welche Identitaet getroffen wurde.

        Gilt ausschliesslich fuer `/mcp`. Die Konsole benutzt
        `authenticate_console` -- ein Token oeffnet dort nichts.
        """
        found: Identity | None = None
        for identity in self.identities.values():
            if verify_token(token, identity.token_hash):
                found = identity
        return found

    def authenticate_console(self, identity_id: str, password: str) -> Identity | None:
        """Prueft Kennung und Passwort fuer die Anmeldung an `/ui`.

        Anders als beim Token wird hier zuerst nachgeschlagen und dann genau
        ein Hash geprueft -- die Kennung steht ja im Formular. Fuer jeden
        Fehlschlag wird trotzdem einmal scrypt gerechnet: sonst antwortete
        eine unbekannte Kennung sofort und eine bekannte nach 50 ms, und die
        Anmeldemaske waere ein Verzeichnis aller Konsolenkonten.
        """
        identity = self.identities.get(identity_id)
        if identity is None or not identity.can_sign_in:
            verify_token(password, _decoy_hash())
            return None
        if not verify_token(password, identity.password_hash):
            return None
        return identity


def load_identities(path: str) -> IdentityStore:
    if not os.path.exists(path):
        raise ConfigError(
            f"{path} not found. Without identities nobody can authenticate -- "
            "run 'gatekeeper init' to create one administrator."
        )
    raw = yaml.safe_load(
        read_config_file(path, "Run 'gatekeeper init' to create one.")
    ) or {}

    entries = raw.get("identities")
    if not isinstance(entries, list) or not entries:
        raise ConfigError("identities.yaml: 'identities' is missing or empty")

    identities: dict[str, Identity] = {}
    for spec in entries:
        if not isinstance(spec, dict):
            raise ConfigError("identities.yaml: every entry must be a mapping")
        identity_id = spec.get("id")
        if not isinstance(identity_id, str) or not identity_id:
            raise ConfigError("identities.yaml: 'id' is missing")
        where = f"identity {identity_id!r}"

        role = spec.get("role", "agent")
        if role not in ROLES:
            raise ConfigError(f"{where}: role={role!r} is unknown")

        token_hash = spec.get("token_hash")
        if not isinstance(token_hash, str) or not token_hash.startswith(_PREFIX + "$"):
            raise ConfigError(
                f"{where}: 'token_hash' is missing or not an scrypt hash. "
                "Plaintext tokens do not belong in this file."
            )
        if "REPLACE_ME" in token_hash:
            # Fail closed: ein Platzhalter wuerde sonst einen Server ergeben,
            # der zwar startet, aber jeden Token ablehnt - schwer zu deuten.
            raise ConfigError(
                f"{where}: token_hash is still the placeholder from the example "
                "file. Generate a real hash with: gatekeeper token"
            )

        # Optional: eine Datei aus einer Fassung vor der Konsolenanmeldung hat
        # kein Passwort, und sie muss weiter laden. Was fehlt, ist kein Fehler
        # in dieser Datei, sondern ein fehlender Konsolenzugang - darueber
        # entscheidet der Start mit --ui, nicht der Loader.
        password_hash = spec.get("password_hash") or ""
        if not isinstance(password_hash, str):
            raise ConfigError(f"{where}: 'password_hash' must be a string")
        if password_hash and not password_hash.startswith(_PREFIX + "$"):
            raise ConfigError(
                f"{where}: 'password_hash' is not an scrypt hash. Plaintext "
                "passwords do not belong in this file -- set one with: "
                "gatekeeper password --identity " + identity_id
            )
        if "REPLACE_ME" in password_hash:
            raise ConfigError(
                f"{where}: password_hash is still the placeholder from the "
                "example file. Set a real one with: gatekeeper password "
                f"--identity {identity_id}"
            )
        if password_hash and role not in UI_ROLES:
            # Ein Agent meldet sich nirgends an. Ein Passwort auf einem
            # Agenten sieht nach einem Zugang aus, den es nicht gibt -- und
            # deutet meist auf eine falsch gesetzte Rolle hin.
            raise ConfigError(
                f"{where}: role={role!r} has a password_hash, but only "
                f"{' and '.join(UI_ROLES)} can sign in to the console."
            )

        tools = spec.get("tools") or []
        if not isinstance(tools, list):
            raise ConfigError(f"{where}: 'tools' must be a list")
        for entry in tools:
            if not isinstance(entry, str):
                raise ConfigError(f"{where}: tool entries must be strings")
            if "*" in entry:
                raise ConfigError(
                    f"{where}: wildcard {entry!r} in 'tools' is not permitted. "
                    "Rights are granted on individual tool IDs (FR-7.5)."
                )

        scopes = spec.get("scopes") or []
        if not isinstance(scopes, list):
            raise ConfigError(f"{where}: 'scopes' must be a list")

        if identity_id in identities:
            raise ConfigError(f"Duplicate identity {identity_id!r}")

        identities[identity_id] = Identity(
            id=identity_id,
            role=role,
            token_hash=token_hash,
            tools=frozenset(tools),
            scopes=tuple(str(s) for s in scopes),
            password_hash=password_hash,
        )

    return IdentityStore(identities=identities)


def summarize(store: IdentityStore) -> list[dict[str, Any]]:
    """Fuer das Startlog (NFR-7) -- ohne Hashes."""
    return [
        {
            "id": i.id,
            "role": i.role,
            "tools": len(i.tools),
            "scopes": list(i.scopes),
            "console": i.can_sign_in,
        }
        for i in store.identities.values()
    ]


def to_spec(identity: Identity) -> dict[str, Any]:
    """Serialisiert eine Identitaet zurueck nach YAML-Form.

    Enthaelt die Hashes, aber niemals einen Klartext -- Token wie Passwort
    gibt es nur im Moment der Ausstellung (FR-2.6).
    """
    spec = {
        "id": identity.id,
        "role": identity.role,
        "token_hash": identity.token_hash,
        "tools": sorted(identity.tools),
        "scopes": list(identity.scopes),
    }
    # Nur schreiben, was es gibt: eine Datei ohne Konsolenkonten soll auch
    # nach einem Schreibvorgang keine leeren Passwortfelder tragen.
    if identity.password_hash:
        spec["password_hash"] = identity.password_hash
    return spec


def dump_identities(store: IdentityStore) -> dict[str, Any]:
    return {"identities": [to_spec(i) for i in store.identities.values()]}
