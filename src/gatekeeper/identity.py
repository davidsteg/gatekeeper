"""Identitaeten, Tokens und Rechte (REQUIREMENTS.md §4 und §9).

Tokens liegen ausschliesslich als scrypt-Hash vor (FR-2.4). Damit ist
`identities.yaml` nicht secret-kritisch und darf nach Homelab-Regel im
Dataset mit chown 568:568 liegen.
"""

from __future__ import annotations

import base64
import dataclasses
import fnmatch
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


def hash_token(token: str, *, salt: bytes | None = None) -> str:
    """Erzeugt `scrypt$n$r$p$salt$hash`."""
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


@dataclasses.dataclass(frozen=True, slots=True)
class Identity:
    id: str
    role: str
    token_hash: str
    tools: frozenset[str]
    scopes: tuple[str, ...]

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
        """Loest einen Token zu einer Identitaet auf.

        Prueft gegen alle Hashes, ohne beim ersten Treffer abzukuerzen, damit
        die Laufzeit nicht verraet, welche Identitaet getroffen wurde.
        """
        found: Identity | None = None
        for identity in self.identities.values():
            if verify_token(token, identity.token_hash):
                found = identity
        return found


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
        )

    return IdentityStore(identities=identities)


def summarize(store: IdentityStore) -> list[dict[str, Any]]:
    """Fuer das Startlog (NFR-7) -- ohne Hashes."""
    return [
        {"id": i.id, "role": i.role, "tools": len(i.tools), "scopes": list(i.scopes)}
        for i in store.identities.values()
    ]


def to_spec(identity: Identity) -> dict[str, Any]:
    """Serialisiert eine Identitaet zurueck nach YAML-Form.

    Enthaelt den Hash, aber niemals einen Klartext-Token -- den gibt es nur im
    Moment der Ausstellung (FR-2.6).
    """
    return {
        "id": identity.id,
        "role": identity.role,
        "token_hash": identity.token_hash,
        "tools": sorted(identity.tools),
        "scopes": list(identity.scopes),
    }


def dump_identities(store: IdentityStore) -> dict[str, Any]:
    return {"identities": [to_spec(i) for i in store.identities.values()]}
