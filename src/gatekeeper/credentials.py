"""The credential store (REQUIREMENTS.md §11).

    gatekeeper is a credential consumer with lifecycle management --
    not a credential provider.

Named, encrypted-at-rest secrets that toolkits reference by name (FR-10.1).
The one requirement everything else here serves: **no operation, for no
role, ever returns a credential value** (FR-10.2). Create, rotate, delete --
yes. Read -- never. Enforcement is structural, not just a convention: the
only function in this module that can see a plaintext value is `_resolve`,
and it is used by nothing outside the http/ssh/truenas executors and
`service.py`'s docker TLS materialization (and this module's own tests,
which never assert its return value crosses back out through
`CredentialStore`'s public surface).
"""

from __future__ import annotations

import dataclasses
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml
from cryptography.fernet import Fernet, InvalidToken

from ._atomic import atomic_write, dump, revision, writable
from .audit import AuditLog
from .errors import ConfigError

#: Kinds understood by the http/truenas/docker executors. `header` names the
#: HTTP header for api_key_header; bearer/basic build their own header value;
#: ws_api_key is consumed by the truenas JSON-RPC auth call, not a header;
#: url_path is substituted into a toolkit's `base_url` (the Telegram bot
#: API embeds its token in the path, not a header) and emits no header at
#: all -- `execute_http.py`'s `_credential_headers` returns {} for it.
#: docker_tls's value is a JSON bundle {"cert", "key", "ca"} of PEM material
#: for a TLS-secured remote Docker daemon (FR-8.3g) -- materialized to a
#: private temp dir by Service, never written back through ui.py.
#: ssh_private_key's value is PEM-format private key text (optionally
#: passphrase-free -- gatekeeper has no prompt to type one into) for the
#: `ssh` executor; the matching public key must already be in the remote
#: host's authorized_keys, which is out of gatekeeper's control by design
#: (a credential names a secret gatekeeper holds, not one it can push).
#: url_query, like url_path, is a deliberately narrow exception to "a
#: credential is always a header" (FR-8.14) -- for a service with no
#: header-auth option at all (SABnzbd's classic API), injected as a query
#: parameter (named by `header`) directly by execute_http.py, never
#: through a tool's own query_template.
#: oauth2's value is a JSON bundle {"client_id", "client_secret",
#: "refresh_token"} for the `google` executor -- materialized to a
#: private tempfile (chmod 600) per call by Service, pointed at via HOME
#: so google_api.py finds its token file, and removed afterwards. Never
#: passed through argv (FR-10.2: a secret never sits in a process
#: argument list that a `ps` on the host would reveal) or written back
#: through ui.py.
KINDS = frozenset(
    {
        "api_key_header", "bearer", "basic", "ws_api_key", "url_path",
        "url_query", "docker_tls", "ssh_private_key", "oauth2",
    }
)

#: Env var holding the base64 urlsafe Fernet key directly.
KEY_ENV = "GATEKEEPER_CREDENTIAL_KEY"
#: Env var holding a path to a file containing that same key -- for a
#: separately mounted secret instead of a plain environment variable.
KEY_FILE_ENV = "GATEKEEPER_CREDENTIAL_KEY_FILE"


class WriteRefused(ConfigError):
    """A write attempt was refused -- with a human-readable reason."""


def generate_master_key() -> str:
    """A fresh Fernet key, base64 urlsafe -- for `gatekeeper credential-key`."""
    return Fernet.generate_key().decode("ascii")


def _load_master_key() -> bytes | None:
    """Reads the master key from its deploy-time source.

    Deliberately never generated implicitly at runtime (FR-10.3): a key
    gatekeeper invented itself and stored next to the ciphertext would
    make the encryption decorative. Returns `None` if neither source is
    set -- the caller decides whether that is fatal (it is only fatal
    once `credentials.yaml` actually holds something to decrypt).
    """
    raw = os.environ.get(KEY_ENV)
    if not raw:
        path = os.environ.get(KEY_FILE_ENV)
        if path:
            try:
                with open(path, encoding="utf-8") as handle:
                    raw = handle.read().strip()
            except OSError as exc:
                raise ConfigError(
                    f"{KEY_FILE_ENV} points at {path!r}, which cannot be read: {exc}"
                ) from None
    if not raw:
        return None
    try:
        # Validated by round-tripping through Fernet, not just base64 --
        # Fernet keys are exactly 32 raw bytes and a plain base64 decode
        # would accept far more than that.
        Fernet(raw.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise ConfigError(
            f"{KEY_ENV} (or the file named by {KEY_FILE_ENV}) does not hold a "
            f"valid Fernet key. Generate one with 'gatekeeper credential-key'. ({exc})"
        ) from None
    return raw.encode("ascii")


@dataclasses.dataclass(frozen=True, slots=True)
class CredentialMeta:
    """What `names()` returns. Structurally excludes any value -- there is

    no field here a caller could misuse to leak one, unlike a dict that
    merely happens to omit a key today.
    """

    name: str
    kind: str
    header: str | None
    created_at: str
    rotated_at: str | None
    in_overlap: bool
    used_by: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class ResolvedCredential:
    """Internal only. Never constructed by, or returned to, `ui.py`/`store.py`."""

    name: str
    kind: str
    header: str | None
    value: str
    previous_value: str | None = None


def _now() -> str:
    """UTC, not local time (catalog.py's `now_iso` uses the same idiom):

    `_resolve`'s `expires_at > _now()` compares these strings
    lexicographically, which is only monotonic across a fixed UTC offset --
    `time.strftime("%Y-%m-%dT%H:%M:%S%z")` would use the local offset at
    call time, which changes across a DST transition and could make an
    overlap window expire up to an hour early or late.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S%z")


@dataclasses.dataclass(slots=True)
class CredentialStore:
    """Owns `credentials.yaml`. Parallel to `store.ConfigStore`, deliberately

    separate: mixing credential writes into the same class as tool/identity
    writes would make it one accidental refactor away from a read path.
    """

    path: str
    audit: AuditLog
    #: Called after create/rotate/delete so the caller can refresh whatever
    #: needs the current plaintext set (the audit-log Redactor -- see
    #: `audit.Redactor.set_secrets`). Never told *which* value changed.
    on_change: Callable[[], None] | None = None
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    # -- Loading -----------------------------------------------------------

    def _raw(self) -> dict[str, dict[str, Any]]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle.read()) or {}
        section = data.get("credentials") or {}
        if not isinstance(section, dict):
            raise ConfigError(f"{self.path}: section 'credentials' must be a mapping")
        return section

    def _write(self, section: dict[str, dict[str, Any]]) -> None:
        atomic_write(self.path, dump({"credentials": section}))
        if self.on_change is not None:
            self.on_change()

    def revision(self) -> str:
        return revision(self.path)

    def writable(self) -> bool:
        return writable(self.path)

    def _check(self, supplied: str) -> None:
        current = self.revision()
        if supplied and current and supplied != current:
            raise WriteRefused(
                "The file changed since this form was opened. Reload the page "
                "and apply your edit again -- otherwise it would silently "
                "discard someone else's change."
            )

    # -- Encryption ----------------------------------------------------

    def _fernet(self) -> Fernet:
        key = _load_master_key()
        if key is None:
            raise ConfigError(
                f"No credential master key is configured ({KEY_ENV} or "
                f"{KEY_FILE_ENV}), but {self.path} needs one. Generate a key "
                "with 'gatekeeper credential-key' and set it before starting."
            )
        return Fernet(key)

    def _encrypt(self, value: str) -> str:
        return self._fernet().encrypt(value.encode("utf-8")).decode("ascii")

    def _decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ConfigError(
                "A credential could not be decrypted -- the master key does "
                "not match the one it was encrypted with."
            ) from exc

    # -- Public, write-only surface -----------------------------------

    def names(self, *, used_by: dict[str, tuple[str, ...]] | None = None) -> list[CredentialMeta]:
        """Metadata only -- FR-10.2. `used_by` maps name -> toolkit names

        referencing it, supplied by the caller (which has Tier 1 in hand),
        purely for display; this module has no Tier 1 dependency itself.
        """
        used_by = used_by or {}
        metas = []
        for name, spec in self._raw().items():
            metas.append(
                CredentialMeta(
                    name=name,
                    kind=str(spec.get("kind", "")),
                    header=spec.get("header"),
                    created_at=str(spec.get("created_at", "")),
                    rotated_at=spec.get("rotated_at"),
                    in_overlap=bool(spec.get("previous_ciphertext")),
                    used_by=tuple(used_by.get(name, ())),
                )
            )
        return sorted(metas, key=lambda m: m.name)

    def create(
        self,
        name: str,
        *,
        kind: str,
        value: str,
        header: str | None = None,
        actor: str,
        rev: str,
    ) -> None:
        if kind not in KINDS:
            raise WriteRefused(f"Unknown credential kind {kind!r} (allowed: {sorted(KINDS)})")
        if kind in ("api_key_header", "url_query") and not header:
            raise WriteRefused(f"kind {kind!r} requires a header/param name")
        if not value:
            raise WriteRefused("A credential needs a value")
        with self._lock:
            self._check(rev)
            section = self._raw()
            if name in section:
                raise WriteRefused(f"A credential named {name!r} already exists.")
            section[name] = {
                "kind": kind,
                "header": header,
                "ciphertext": self._encrypt(value),
                "created_at": _now(),
                "rotated_at": None,
                "previous_ciphertext": None,
                "previous_expires_at": None,
            }
            self._write(section)
        # Audit records only the name and kind -- never the value (FR-10.7).
        self.audit.write(
            {
                "kind": "admin_change",
                "actor": actor,
                "action": "credential_create",
                "target": name,
                "credential_kind": kind,
            }
        )

    def rotate(
        self, name: str, *, value: str, overlap_seconds: int = 0, actor: str, rev: str
    ) -> None:
        if not value:
            raise WriteRefused("A credential needs a value")
        if overlap_seconds < 0:
            raise WriteRefused("overlap_seconds must not be negative")
        with self._lock:
            self._check(rev)
            section = self._raw()
            existing = section.get(name)
            if existing is None:
                raise WriteRefused(f"No credential named {name!r}.")
            previous_ciphertext = existing["ciphertext"] if overlap_seconds > 0 else None
            previous_expires_at = (
                # UTC, same reasoning as `_now`: this value is later
                # compared against `_now()` in `_resolve`, and both sides
                # of that comparison must share a fixed offset.
                (datetime.now(UTC) + timedelta(seconds=overlap_seconds)).strftime(
                    "%Y-%m-%dT%H:%M:%S%z"
                )
                if overlap_seconds > 0
                else None
            )
            section[name] = {
                **existing,
                "ciphertext": self._encrypt(value),
                "rotated_at": _now(),
                "previous_ciphertext": previous_ciphertext,
                "previous_expires_at": previous_expires_at,
            }
            self._write(section)
        self.audit.write(
            {
                "kind": "admin_change",
                "actor": actor,
                "action": "credential_rotate",
                "target": name,
                "overlap_seconds": overlap_seconds,
            }
        )

    def delete(self, name: str, *, actor: str, rev: str) -> None:
        with self._lock:
            self._check(rev)
            section = self._raw()
            if name not in section:
                raise WriteRefused(f"No credential named {name!r}.")
            del section[name]
            self._write(section)
        self.audit.write(
            {
                "kind": "admin_change",
                "actor": actor,
                "action": "credential_delete",
                "target": name,
            }
        )

    def plaintext_values_for_masking(self) -> tuple[str, ...]:
        """All current *and* in-overlap plaintext values, for the audit

        Redactor (FR-10.6). This is the one place outside `_resolve` that
        touches plaintext -- and it never returns a value tied to a name,
        only an unordered bag of strings to scrub, which is all masking needs.

        A missing/wrong master key is raised, not swallowed: with credentials
        on file that gatekeeper cannot decrypt, masking would silently do
        nothing, and a startup that should have aborted (FR-10.3) would
        instead run with secrets unmasked in logs.
        """
        section = self._raw()
        if not section:
            return ()
        self._fernet()  # raises ConfigError if no master key is configured
        values: list[str] = []
        for spec in section.values():
            ciphertext = spec.get("ciphertext")
            if ciphertext:
                values.append(self._decrypt(ciphertext))
            previous = spec.get("previous_ciphertext")
            if previous:
                values.append(self._decrypt(previous))
        return tuple(values)

    # -- Internal: the only decrypt point used by executors ---------------

    def _resolve(self, name: str) -> ResolvedCredential | None:
        """Used only by `execute_http.py` / `execute_ssh.py` /

        `execute_truenas.py`, and by `service.py`'s docker TLS
        materialization. Not part of the public API surface exposed
        through `ui.py` or `store.py` -- no route handler may call this.
        """
        spec = self._raw().get(name)
        if spec is None:
            return None
        previous_value = None
        previous_ciphertext = spec.get("previous_ciphertext")
        expires_at = spec.get("previous_expires_at")
        if previous_ciphertext and expires_at and expires_at > _now():
            previous_value = self._decrypt(previous_ciphertext)
        return ResolvedCredential(
            name=name,
            kind=str(spec.get("kind", "")),
            header=spec.get("header"),
            value=self._decrypt(spec["ciphertext"]),
            previous_value=previous_value,
        )
