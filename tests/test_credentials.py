"""The credential store (REQUIREMENTS.md §11).

The recurring shape of these tests: prove a value never comes back out
through any *public* API, not merely that the UI happens not to display it.
"""

from __future__ import annotations

import json
import os
import sys

import pytest
import yaml
import httpx

from gatekeeper.audit import AuditLog, Redactor
from gatekeeper.credentials import (
    KEY_ENV,
    CredentialStore,
    WriteRefused,
    generate_master_key,
)
from gatekeeper.errors import ConfigError
from gatekeeper.tier1 import load_tier1


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


# -- Dangling references: a binding whose credential does not exist ----------
#
# The binding lives in toolkits.yaml (Tier 1, deploy-time) and the value in
# credentials.yaml (Tier 2, typed into the console). Nothing used to compare
# the two, so a `credential:` naming a credential nobody had created yet was
# silent until the first call refused it with "is not configured yet".


def _tier1_with(tmp_path, spec: dict):
    path = tmp_path / "toolkits.yaml"
    spec = {**spec, "audit": {"dir": str(tmp_path / "logs")}}
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return load_tier1(str(path))


def _local(**extra):
    return {"executor": "local", "binaries": [sys.executable], **extra}


def test_credential_references_maps_toolkit_bindings(tmp_path):
    tier1 = _tier1_with(
        tmp_path,
        {
            "toolkits": {
                "sonarr": _local(credential="sonarr-key"),
                "radarr": _local(credential="radarr-key"),
            }
        },
    )
    assert tier1.credential_references() == {
        "sonarr-key": ("sonarr",),
        "radarr-key": ("radarr",),
    }


def test_credential_references_includes_destination_level_bindings(tmp_path):
    """The half that a second, hand-rolled copy of this walk always forgets.

    A destination's own `credential:` overrides the toolkit's (FR-8.3g), so
    a check that only walked toolkits would call a live reference dangling.
    """
    tier1 = _tier1_with(
        tmp_path,
        {
            "destinations": {
                "nas2": {
                    "docker_host": "tcp://nas2.lan:2376",
                    "docker_tls": True,
                    "credential": "docker-nas2-tls",
                }
            },
            "toolkits": {
                "docker": {
                    "executor": "docker",
                    "destinations": ["nas2"],
                    "binaries": [sys.executable],
                }
            },
        },
    )
    assert tier1.credential_references() == {
        "docker-nas2-tls": ("nas2 (destination)",)
    }


def test_credential_references_empty_without_bindings(tmp_path):
    tier1 = _tier1_with(tmp_path, {"toolkits": {"sonarr": _local()}})
    assert tier1.credential_references() == {}


def test_dangling_reference_detected_and_cleared_by_create(tmp_path, store):
    """The set difference that the startup check and the console both compute."""
    tier1 = _tier1_with(
        tmp_path, {"toolkits": {"sonarr": _local(credential="sonarr-key")}}
    )

    def dangling():
        return sorted(
            set(tier1.credential_references()) - {meta.name for meta in store.names()}
        )

    # An empty store loads as `{}` without complaint -- which is exactly why
    # this needed a check of its own rather than falling out of loading.
    assert store.names() == []
    assert dangling() == ["sonarr-key"]

    store.create(
        "sonarr-key", kind="api_key_header", header="X-Api-Key",
        value="filled-in-later", actor="admin", rev="",
    )
    assert dangling() == []


# -- Detection-only probes ---------------------------------------------------


class _ProbeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _ProbeClient:
    calls: list[tuple[str, dict[str, str]]] = []
    status_code = 200
    exc: Exception | None = None

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, url, *, headers):
        self.calls.append((url, headers))
        if self.exc is not None:
            raise self.exc
        return _ProbeResponse(self.status_code)


async def _assert_probe_status(store, monkeypatch, *, status_code=None, exc=None, expected):
    from gatekeeper import credentials as credentials_mod

    _ProbeClient.calls = []
    _ProbeClient.status_code = status_code or 200
    _ProbeClient.exc = exc
    monkeypatch.setattr(credentials_mod.httpx, "AsyncClient", _ProbeClient)

    store.create(
        "probe", kind="bearer", value="secret-token", probe_url="https://service.test/me",
        actor="admin", rev="",
    )
    before = store._raw()["probe"]["ciphertext"]

    assert await store.probe_credential("probe") == expected

    after_raw = store._raw()["probe"]
    assert after_raw["ciphertext"] == before
    assert after_raw["previous_ciphertext"] is None
    assert store._resolve("probe").value == "secret-token"
    assert store.names()[0].probe_status == expected
    assert _ProbeClient.calls == [
        ("https://service.test/me", {"Authorization": "Bearer secret-token"})
    ]


async def test_probe_verified_preserves_secret(store, monkeypatch):
    await _assert_probe_status(store, monkeypatch, status_code=204, expected="verified")


async def test_probe_auth_failed_preserves_secret(store, monkeypatch):
    await _assert_probe_status(store, monkeypatch, status_code=401, expected="auth_failed")


async def test_probe_other_response_preserves_secret(store, monkeypatch):
    await _assert_probe_status(store, monkeypatch, status_code=500, expected="unreachable")


async def test_probe_network_error_preserves_secret(store, monkeypatch):
    await _assert_probe_status(
        store, monkeypatch,
        exc=httpx.ConnectError("boom", request=httpx.Request("GET", "https://service.test/me")),
        expected="unreachable",
    )


async def test_probe_missing_url_preserves_secret_and_does_not_call_network(store, monkeypatch):
    from gatekeeper import credentials as credentials_mod

    _ProbeClient.calls = []
    monkeypatch.setattr(credentials_mod.httpx, "AsyncClient", _ProbeClient)
    store.create("probe", kind="bearer", value="secret-token", actor="admin", rev="")
    before = store._raw()["probe"]["ciphertext"]

    assert await store.probe_credential("probe") == "no_probe_url"

    assert store._raw()["probe"]["ciphertext"] == before
    assert store._resolve("probe").value == "secret-token"
    assert store.names()[0].probe_status == "no_probe_url"
    assert _ProbeClient.calls == []


def test_mark_suspect_preserves_secret(store):
    store.create("probe", kind="bearer", value="secret-token", actor="admin", rev="")
    before = store._raw()["probe"]["ciphertext"]

    store.mark_suspect("probe")

    meta = store.names()[0]
    assert meta.suspect_status == "auth_failed"
    assert meta.suspect_at
    assert store._raw()["probe"]["ciphertext"] == before
    assert store._resolve("probe").value == "secret-token"
