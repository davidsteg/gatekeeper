"""Identities, tokens, passwords and permissions (REQUIREMENTS.md §4 and §9).

An identity carries two separate credentials, and the separation is
intentional (FR-11.5):

* **Token** -- for the API. Goes as `Authorization: ***` to `/mcp` and
  belongs in an agent's configuration, not in a browser.
* **Password** -- for the console at `/ui`. Only `viewer` and `admin`
  have one; an agent gets none, because it never logs in anywhere.

The reason for two credentials instead of one: a token typed into a
login form then sits in the clipboard, the browser's password store,
and with bad luck in the history -- and the same secret opens `/mcp`
too. Whoever loses one should not lose both: a stolen console password
cannot invoke tools, a stolen token cannot open the UI.

Both are stored exclusively as scrypt hashes (FR-2.4). This means
`identities.yaml` is not secret-critical and may sit in the dataset
with chown 568:568 per homelab convention.
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

#: scrypt parameters. n=2**15 costs about 32 MB and ~50 ms -- plenty for a
#: handful of tokens per second, expensive enough for brute force.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32

_PREFIX = "scrypt"

#: `viewer` and `admin` distinguish reading and writing in the operations UI.
#: Without this separation, anyone allowed to view the audit log would also
#: have the right to create tools and grant permissions.
ROLES = ("agent", "viewer", "admin")

#: Roles that may sign in to the UI. `agent` is not among them: an
#: agent token is meant for `/mcp` and does not open the console.
UI_ROLES = ("viewer", "admin")

#: Only this role may write.
ADMIN_ROLE = "admin"

#: Minimum length of a console password. No character-class requirement: length
#: matters more here than an uppercase letter in position three, and sign-in
#: is additionally rate-limited (`LoginThrottle`) and slowed by scrypt.
MIN_PASSWORD_LENGTH = 12


def hash_token(token: str, *, salt: bytes | None = None) -> str:
    """Produces `scrypt$n$r$p$salt$hash`.

    The same function hashes tokens and passwords -- there is no reason
    to maintain two methods, and the weaker one would be the one
    forgotten.
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
    """Verifies a token against its hash -- in constant time (FR-2.5)."""
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
    """Generates a new agent token."""
    return "gk_" + secrets.token_urlsafe(32)


def generate_password() -> str:
    """Generates a console password.

    Without the `gk_` prefix: the prefix marks an API token, and the two
    should be distinguishable even in plaintext.
    """
    return secrets.token_urlsafe(18)


@functools.cache
def _decoy_hash() -> str:
    """A hash that no password matches.

    Needed so that a sign-in with an unknown ID takes just as
    long as one with a known ID. Without it, the response time would be a
    directory of all console IDs. Computed only on demand -- scrypt
    costs about 50 ms, and no import operation should pay that.
    """
    return hash_token(secrets.token_urlsafe(32))


@dataclasses.dataclass(frozen=True, slots=True)
class Identity:
    id: str
    role: str
    token_hash: str
    tools: frozenset[str]
    scopes: tuple[str, ...]
    #: Empty means: this identity cannot sign in to the console.
    #: For `agent` this is the normal case.
    password_hash: str = ""

    @property
    def can_sign_in(self) -> bool:
        """May and can this identity sign in to the console?

        Both must be true: the role allows it, and a password is
        set. A role without a password is not access, but a
        line in a file.
        """
        return self.role in UI_ROLES and bool(self.password_hash)

    def may_call(self, tool_id: str) -> bool:
        """FR-7.5: Rights attach to tool IDs, never to a whole toolkit.

        Deliberately no prefix or wildcard matching at the toolkit level: otherwise
        this identity would automatically possess every tool created in the toolkit
        in the future.
        """
        return tool_id in self.tools

    def holds_definition(self, base_tool_id: str) -> bool:
        """Whether this identity holds a grant on the YAML definition

        `base_tool_id` names -- either the bare id itself, or any of its
        destination expansions (`base_tool_id@nas1`, FR-8.3h). For admin-UI
        and audit display only ("who would be affected by editing/deleting
        this definition") -- never for call authorization, which is
        `may_call`'s exact, un-prefixed match against the concrete,
        destination-qualified id the agent actually named (FR-8.3i).
        """
        prefix = base_tool_id + "@"
        return base_tool_id in self.tools or any(t.startswith(prefix) for t in self.tools)

    def covers_scope(self, scope: str) -> bool:
        """Checks a resolved scope against the profile patterns."""
        return any(fnmatch.fnmatchcase(scope, pattern) for pattern in self.scopes)


@dataclasses.dataclass(slots=True)
class IdentityStore:
    identities: dict[str, Identity]

    def authenticate(self, token: str) -> Identity | None:
        """Resolves an API token to an identity.

        Checks against all hashes, without short-circuiting on the first match, so
        that the runtime does not reveal which identity was matched.

        Applies exclusively to `/mcp`. The console uses
        `authenticate_console` -- a token opens nothing there.
        """
        found: Identity | None = None
        for identity in self.identities.values():
            if verify_token(token, identity.token_hash):
                found = identity
        return found

    def authenticate_console(self, identity_id: str, password: str) -> Identity | None:
        """Checks ID and password for sign-in at `/ui`.

        Unlike with the token, a lookup happens first and then exactly
        one hash is checked -- the ID is in the form after all. For every
        failed attempt, scrypt is still computed once: otherwise an
        unknown ID would respond immediately and a known one after 50 ms,
        and the login form would be a directory of all console accounts.
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
            # Fail closed: a placeholder would otherwise produce a server
            # that starts but rejects every token - hard to diagnose.
            raise ConfigError(
                f"{where}: token_hash is still the placeholder from the example "
                "file. Generate a real hash with: gatekeeper token"
            )

        # Optional: a file from a version before console sign-in has
        # no password, and it must still load. What is missing is not an error
        # in this file, but a missing console access -- that is
        # decided by the start with --ui, not by the loader.
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
            # An agent never signs in anywhere. A password on an
            # agent looks like an access that does not exist -- and
            # usually indicates a wrongly set role.
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
    """For the startup log (NFR-7) -- without hashes."""
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
    """Serializes an identity back to YAML form.

    Contains the hashes, but never a plaintext -- token and password
    exist only at the moment of issuance (FR-2.6).
    """
    spec = {
        "id": identity.id,
        "role": identity.role,
        "token_hash": identity.token_hash,
        "tools": sorted(identity.tools),
        "scopes": list(identity.scopes),
    }
    # Only write what exists: a file without console accounts should
    # not carry empty password fields after a write operation either.
    if identity.password_hash:
        spec["password_hash"] = identity.password_hash
    return spec


def dump_identities(store: IdentityStore) -> dict[str, Any]:
    return {"identities": [to_spec(i) for i in store.identities.values()]}
