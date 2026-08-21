"""The credential store (REQUIREMENTS.md §11).

The recurring shape of these tests: prove a value never comes back out
through any *public* API, not merely that the UI happens not to display it.
"""

from __future__ import annotations

import json
import os

import pytest

from gatekeeper.audit import AuditLog, Redactor
from gatekeeper.credentials import (
    KEY_ENV,
    CredentialStore,
    WriteRefused,
    generate_master_key,
)
from gatekeeper.errors import ConfigError


@pytest.fixture
def master_key(monkeypatch):
    key = generate_master_key()
    monkeypatch.setenv(KEY_ENV, key)
    return key


@pytest.fixture
def store(tmp_path, master_key):
    audit = AuditLog(str(tmp_path / "logs"))
    return CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)


def test_create_never_returns_a_value(store):
    store.create(
        "sonarr", kind="api_key_header", header="X-Api-Key",
        value="super-secret-key", actor="admin", rev="",
    )
    metas = store.names()
    assert len(metas) == 1
    meta = metas[0]
    assert meta.name == "sonarr"
    assert meta.kind == "api_key_header"
    # Structural guarantee, not a convention: CredentialMeta simply has no
    # field that could hold a value.
    assert not hasattr(meta, "value")
    assert not hasattr(meta, "ciphertext")
    assert "super-secret-key" not in repr(meta)


def test_duplicate_name_refused(store):
    store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="a", actor="x", rev="")
    with pytest.raises(WriteRefused):
        store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="b", actor="x", rev="")


def test_unknown_kind_refused(store):
    with pytest.raises(WriteRefused):
        store.create("x", kind="not_a_kind", value="a", actor="x", rev="")


def test_api_key_header_requires_header_name(store):
    with pytest.raises(WriteRefused):
        store.create("x", kind="api_key_header", value="a", actor="x", rev="")


def test_resolve_round_trips_internally(store):
    store.create(
        "sonarr", kind="api_key_header", header="X-Api-Key",
        value="super-secret-key", actor="admin", rev="",
    )
    resolved = store._resolve("sonarr")
    assert resolved is not None
    assert resolved.value == "super-secret-key"
    assert resolved.header == "X-Api-Key"


def test_resolve_unknown_name_returns_none(store):
    assert store._resolve("nope") is None


def test_rotation_with_overlap(store):
    store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="old", actor="x", rev="")
    rev = store.revision()
    store.rotate("sonarr", value="new", overlap_seconds=3600, actor="x", rev=rev)

    resolved = store._resolve("sonarr")
    assert resolved.value == "new"
    assert resolved.previous_value == "old"

    meta = store.names()[0]
    assert meta.in_overlap is True
    assert meta.rotated_at


def test_rotation_without_overlap_drops_old_value(store):
    store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="old", actor="x", rev="")
    rev = store.revision()
    store.rotate("sonarr", value="new", overlap_seconds=0, actor="x", rev=rev)

    resolved = store._resolve("sonarr")
    assert resolved.value == "new"
    assert resolved.previous_value is None


def test_overlap_timestamps_use_a_fixed_utc_offset(store):
    """`_resolve` compares `previous_expires_at` against `_now()` as plain

    strings -- correct only if both always carry the same UTC offset. Local
    time would use whatever offset is in effect at the moment each string
    is generated, which changes across a DST transition and could make an
    overlap window expire up to an hour early or late. Asserting both
    strings end in the fixed '+0000' offset is what makes that lexicographic
    comparison actually safe, regardless of the host's timezone or DST state
    when the test runs.
    """
    from gatekeeper.credentials import _now

    assert _now().endswith("+0000")

    store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="old", actor="x", rev="")
    rev = store.revision()
    store.rotate("sonarr", value="new", overlap_seconds=3600, actor="x", rev=rev)

    raw = store._raw()
    assert raw["sonarr"]["previous_expires_at"].endswith("+0000")


def test_rotate_unknown_name_refused(store):
    with pytest.raises(WriteRefused):
        store.rotate("nope", value="x", actor="x", rev="")


def test_delete(store):
    store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="a", actor="x", rev="")
    rev = store.revision()
    store.delete("sonarr", actor="x", rev=rev)
    assert store.names() == []
    assert store._resolve("sonarr") is None


def test_delete_unknown_name_refused(store):
    with pytest.raises(WriteRefused):
        store.delete("nope", actor="x", rev="")


def test_concurrency_check(store):
    store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="a", actor="x", rev="")
    with pytest.raises(WriteRefused):
        # A stale revision must be refused, exactly like tools.yaml/identities.yaml.
        store.rotate("sonarr", value="b", actor="x", rev="stale-revision")


def test_file_bytes_never_contain_plaintext(store):
    store.create(
        "sonarr", kind="api_key_header", header="X-Api-Key",
        value="super-secret-key-xyz", actor="admin", rev="",
    )
    with open(store.path, "rb") as handle:
        raw = handle.read()
    assert b"super-secret-key-xyz" not in raw


def test_missing_master_key_with_nonempty_file_aborts(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    audit = AuditLog(str(tmp_path / "logs"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="a", actor="x", rev="")

    monkeypatch.delenv(KEY_ENV, raising=False)
    store2 = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    with pytest.raises(ConfigError):
        store2._resolve("sonarr")


def test_empty_store_needs_no_key(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY_ENV, raising=False)
    audit = AuditLog(str(tmp_path / "logs"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    # No credentials exist yet -- listing must not require a master key.
    assert store.names() == []


def test_wrong_master_key_is_a_config_error(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    audit = AuditLog(str(tmp_path / "logs"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store.create("sonarr", kind="api_key_header", header="X-Api-Key", value="a", actor="x", rev="")

    monkeypatch.setenv(KEY_ENV, generate_master_key())
    with pytest.raises(ConfigError):
        store._resolve("sonarr")


def test_masking_scrubs_secret_from_audit_log(tmp_path, master_key):
    redactor = Redactor()
    audit = AuditLog(str(tmp_path / "logs"), redactor=redactor)
    store = CredentialStore(
        path=str(tmp_path / "credentials.yaml"),
        audit=audit,
        on_change=lambda: redactor.set_secrets(store.plaintext_values_for_masking()),
    )
    store.create(
        "sonarr", kind="api_key_header", header="X-Api-Key",
        value="super-secret-key-xyz", actor="admin", rev="",
    )

    assert redactor("the response was super-secret-key-xyz") == "the response was ***"

    audit.write({"kind": "call", "detail": "leaked super-secret-key-xyz here"})
    with open(os.path.join(str(tmp_path / "logs"), "audit.jsonl"), encoding="utf-8") as handle:
        lines = [json.loads(line) for line in handle]
    assert all("super-secret-key-xyz" not in json.dumps(line) for line in lines)


def test_credential_create_audited_without_value(tmp_path, master_key):
    audit = AuditLog(str(tmp_path / "logs"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store.create(
        "sonarr", kind="api_key_header", header="X-Api-Key",
        value="super-secret-key-xyz", actor="admin", rev="",
    )
    with open(os.path.join(str(tmp_path / "logs"), "audit.jsonl"), encoding="utf-8") as handle:
        lines = [json.loads(line) for line in handle]
    assert any(line.get("action") == "credential_create" for line in lines)
    assert all("super-secret-key-xyz" not in json.dumps(line) for line in lines)
