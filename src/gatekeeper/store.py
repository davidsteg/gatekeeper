"""Write access to Tier 2 (REQUIREMENTS.md §7, Stage 3).

Here -- and only here -- does gatekeeper modify its own configuration. Five
guarantees underpin this layer:

1. **Tier 1 remains untouchable.** There is no function that writes `toolkits.yaml`.
   Binary allowlist, blocked arguments, path roots, protected
   resources and ceilings are changed exclusively by a redeploy (FR-4.11).

2. **Only one validation path.** Every definition runs through `parse_tool_spec` --
   the same function that checks at startup. A second, more lenient path would
   reduce the boundary to a mere recommendation.

3. **Atomic.** Writing goes to a sibling file that is moved into place via
   `os.replace` after `fsync`. A crash in between leaves the
   old file, never a half-written one.

4. **What holds is on disk.** After every write, the file is reloaded
   and the running state is swapped out. The display can
   thus not deviate from what a restart would produce.

5. **No silent overwriting.** Every form carries the revision of
   the file it was built from. If someone else has written in the meantime,
   the request is refused rather than ironed over.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import threading
from typing import Any

import yaml

from ._atomic import atomic_write as _atomic_write
from ._atomic import dump as _dump
from ._atomic import revision, writable
from .audit import AuditLog
from .catalog import (
    append_tool_version,
    load_catalog,
    new_tool_entry,
    now_iso,
    parse_tool_spec,
    soft_delete_entry,
)
from .errors import ConfigError
from .identity import (
    ADMIN_ROLE,
    MIN_PASSWORD_LENGTH,
    ROLES,
    UI_ROLES,
    Identity,
    dump_identities,
    generate_token,
    hash_token,
    hash_token_lookup,
    load_identities,
    to_spec,
    verify_token,
)
from .service import Service


class WriteRefused(ConfigError):
    """A write attempt was refused -- with a human-readable reason."""


def _fingerprint(record: Any) -> str:
    """Deterministic sha256 fingerprint of one record, truncated to 16 hex
    chars for consistency with `_atomic.revision()`'s whole-file hash.
    `None` (the record does not exist) fingerprints as "" -- same
    convention `revision()` uses for a missing file.
    """
    if record is None:
        return ""
    encoded = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


@dataclasses.dataclass(slots=True)
class ConfigStore:
    """Owns the Tier 2 files and the runtime state derived from them."""

    service: Service
    identities: Any  # IdentityStore -- as Any to avoid a circular import
    audit: AuditLog
    tools_path: str
    identities_path: str
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    # -- State -----------------------------------------------------------

    def tools_revision(self) -> str:
        return revision(self.tools_path)

    def identities_revision(self) -> str:
        return revision(self.identities_path)

    def tool_revision(self, tool_id: str) -> str:
        """Fingerprint of a single tool's raw entry -- unlike
        `tools_revision()`, unaffected by any OTHER entry in tools.yaml
        changing. Used only to gate pending-proposal staleness (see
        `admin_service.apply_pending`); `_check()`'s own whole-file check
        at the moment of writing is the real concurrency guarantee and is
        untouched by this.
        """
        return _fingerprint(self.service.catalog.raw_of(tool_id))

    def identity_revision(self, identity_id: str) -> str:
        """Fingerprint of a single identity's spec -- unlike
        `identities_revision()`, unaffected by any OTHER identity in
        identities.yaml changing. Same rationale as `tool_revision()`.
        """
        identity = self.identities.identities.get(identity_id)
        return _fingerprint(None if identity is None else to_spec(identity))

    def writability(self) -> dict[str, bool]:
        return {
            "tools": writable(self.tools_path),
            "identities": writable(self.identities_path),
        }

    def _check(self, path: str, supplied: str) -> None:
        """Optimistic concurrency."""
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
        # Reload from the file, not from memory: only this proves
        # that the running state matches what a restart would produce.
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
        """Creates a definition or replaces it. Returns the tool ID."""
        with self._lock:
            self._check(self.tools_path, rev)

            # The same validation path as at startup. Raises ConfigError or
            # Tier1Violation -- both appear as plaintext in the form.
            tool = parse_tool_spec(spec, self.service.tier1)

            specs = self._specs()
            existing = {s.get("id") for s in specs}
            if replaces is None and tool.id in existing:
                raise WriteRefused(f"A tool with ID {tool.id!r} already exists.")
            if replaces is not None and tool.id != replaces and tool.id in existing:
                raise WriteRefused(f"A tool with ID {tool.id!r} already exists.")

            now = now_iso()
            if replaces is None:
                specs.append(new_tool_entry(tool.id, spec, actor=actor, created_at=now))
            else:
                old_entry = next((s for s in specs if s.get("id") == replaces), None)
                if old_entry is None:
                    raise WriteRefused(f"No tool with ID {replaces!r}.")
                new_entry = append_tool_version(
                    old_entry, tool.id, spec, actor=actor, created_at=now
                )
                specs = [new_entry if s.get("id") == replaces else s for s in specs]

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
        """Soft-deletes: the entry is marked `deleted: true` and excluded
        from the live catalog, but its full version history stays on disk
        (FR-3.1) -- unlike a hard removal, it is not only recoverable from
        the audit log but directly inspectable via `admin.tool_get`.
        """
        with self._lock:
            self._check(self.tools_path, rev)
            specs = self._specs()
            target = next((s for s in specs if s.get("id") == tool_id), None)
            if target is None or target.get("deleted"):
                raise WriteRefused(f"No tool with ID {tool_id!r}.")
            deleted_entry = soft_delete_entry(target)
            self._write_tools(
                [deleted_entry if s.get("id") == tool_id else s for s in specs]
            )
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "tool_delete",
                    "target": tool_id,
                    # Record the full definition: a deletion
                    # can thus be restored from the log.
                    "spec": target,
                }
            )
            self._orphan_warning(tool_id)

    def _orphan_warning(self, tool_id: str) -> None:
        """Records who now holds a right to a tool that no longer exists.

        No error: the right goes nowhere and is rejected at call time.
        But it is a silent deviation, and silent deviations belong
        in the log. `tool_id` is the bare definition id -- a grant on any
        of its destination expansions (`tool_id@nas1`, FR-8.3h) is just as
        dangling once the definition itself is gone.
        """
        holders = sorted(
            i.id for i in self.identities.identities.values() if i.holds_definition(tool_id)
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

    # -- Identities ------------------------------------------------------

    def _write_identities(self, payload: dict[str, Any]) -> None:
        _atomic_write(self.identities_path, _dump(payload))
        fresh = load_identities(self.identities_path)
        # Swap the contents, not the object: `AuthMiddleware` and the
        # UI routes hold a reference to the store, not to the dict.
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
        """Changes an existing identity.

        `password=""` means: the existing console password stays. An
        empty field in the form must not delete access -- anyone who wants that
        sets the role to `agent`.
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

            # Expand bare tool IDs to their destination-qualified catalog IDs.
            # A multi-destination toolkit's tools live in the catalog only as
            # `<id>@<dest>` (FR-8.3h); accepting the bare id for validation but
            # storing it unexpanded would make may_call() fail at call time.
            resolved_tools = set()
            for tid in tools:
                if tid in self.service.catalog.tools:
                    resolved_tools.add(tid)
                else:
                    prefix = f"{tid}@"
                    expanded = sorted(
                        t for t in self.service.catalog.tools if t.startswith(prefix)
                    )
                    if expanded:
                        resolved_tools.update(expanded)
                    else:
                        resolved_tools.add(tid)  # will be caught by unknown check
            unknown = sorted(
                set(tools)
                - set(self.service.catalog.tools)
                - {
                    tid.rsplit("@", 1)[0]
                    for tid in self.service.catalog.tools
                    if "@" in tid
                }
            )
            if unknown:
                raise WriteRefused(f"Unknown tool IDs: {', '.join(unknown)}")

            payload = dump_identities(self.identities)
            entries = payload["identities"]

            if replaces is None:
                # New identities get a token immediately, otherwise there would
                # be an entry without a valid hash -- and the loader refuses
                # the next start.
                raise WriteRefused(
                    "Use create_identity() for new entries -- a token is required."
                )

            previous = current[replaces]
            if password and role not in UI_ROLES:
                # Must fail *before* writing: the loader rejects a
                # password on an agent role, and `_write_identities`
                # reloads immediately after writing. Noticing it only here
                # would mean having already made the file unreadable.
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
                # Role `agent`: console access is removed, and with it
                # the hash belongs out of the file. Leaving it in would be
                # an access that silently comes back to life after the
                # next role change.
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
                "tools": sorted(resolved_tools),
                "scopes": [s for s in scopes if s],
            }
            if password_hash:
                updated["password_hash"] = password_hash
            # The token itself is not changing here -- carry its lookup
            # index over unchanged, same as token_hash above.
            if previous.token_lookup:
                updated["token_lookup"] = previous.token_lookup
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
                    "tools": sorted(resolved_tools),
                    "scopes": [s for s in scopes if s],
                    # The plaintext is never logged, but the fact is:
                    # a password change belongs in the trail.
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
        """Creates an identity and returns the plaintext token exactly once.

        `viewer` and `admin` additionally need a password: without one
        there would be a console account that nobody can sign in to.
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
            # Expand bare tool IDs to destination-qualified catalog IDs.
            resolved_tools = set()
            for tid in tools:
                if tid in self.service.catalog.tools:
                    resolved_tools.add(tid)
                else:
                    prefix = f"{tid}@"
                    expanded = sorted(
                        t for t in self.service.catalog.tools if t.startswith(prefix)
                    )
                    if expanded:
                        resolved_tools.update(expanded)
                    else:
                        resolved_tools.add(tid)
            unknown = sorted(
                set(tools)
                - set(self.service.catalog.tools)
                - {
                    tid.rsplit("@", 1)[0]
                    for tid in self.service.catalog.tools
                    if "@" in tid
                }
            )
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
                "token_lookup": hash_token_lookup(token),
                "tools": sorted(resolved_tools),
                "scopes": [s for s in scopes if s],
            }
            if password:
                entry["password_hash"] = hash_token(password)
            payload = dump_identities(self.identities)
            payload["identities"].append(entry)
            self._write_identities(payload)
            # The plaintext is deliberately NOT logged (FR-2.6) -- neither
            # the token nor the password.
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "identity_create",
                    "target": identity_id,
                    "role": role,
                    "tools": sorted(resolved_tools),
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
                    entry["token_lookup"] = hash_token_lookup(token)
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
        """Sets the console password of an identity.

        `require_current` applies to self-service: anyone changing their own
        password must know the old one. Otherwise an
        unattended session would suffice to permanently take over the access --
        signing out alone would not bring it back.
        An administrator setting *someone else's* password naturally
        does not know the old one; there the change is instead recorded with
        the actor in the audit log.
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
        """Prevents lockout.

        If no `admin` remained, nobody could create one -- the
        console would be closed forever, and the only way out would be
        an editor on the host. The failure case is cheap to prevent and
        expensive to fix.

        Since console sign-in, the role alone is not enough: an
        administrator without a password cannot sign in and is
        worthless as a last resort. This is checked only if there
        previously *was* a sign-in-capable administrator -- a configuration from
        an older version should not block itself.
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
    """Sets a console password directly in `identities.yaml`.

    The path without a running service: for `gatekeeper password` and for
    startup, which gives a stock from an older version a password for the
    first time. Loading is done from the file beforehand, writing is atomic -- so
    the same guarantee applies here as for the console.
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
    """Reads exactly one tool definition from the form field."""
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
