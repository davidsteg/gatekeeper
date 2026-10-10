"""Release-bound artifacts: build, store, `artifact` executor, HTTP download.

The image's own `artifacts.SOURCES` is empty since the recovery adapter was
removed, so these tests build from a small fixture repository: one text
file and one directory, the two kinds a source can have."""

from __future__ import annotations

import hashlib
import json
import os

import httpx2
import pytest
import yaml
from conftest import make_catalog

from gatekeeper.artifacts import SOURCES, ArtifactStore, build
from gatekeeper.audit import AuditLog
from gatekeeper.errors import ConfigError
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

COMMIT = "7aa7b394cb713162db98aad29c91c342508a49c7"
CONTRACT, ADAPTER = "example-doc", "example-kit"
DOC_FILE, KIT_FILE = "EXAMPLE.md", "example-kit.tar.gz"
FIXTURE_SOURCES = (
    {"id": CONTRACT, "kind": "file", "path": "docs/EXAMPLE.md", "file": DOC_FILE,
     "media_type": "text/markdown; charset=utf-8", "text": True},
    {"id": ADAPTER, "kind": "tree", "path": "kit", "file": KIT_FILE,
     "media_type": "application/gzip", "text": False},
)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "EXAMPLE.md").write_bytes(b"# Example document\r\n\nreleased with the image\n")
    (root / "kit" / "pkg" / "__pycache__").mkdir(parents=True)
    (root / "kit" / "pkg" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "kit" / "pkg" / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"\0")
    (root / "kit" / "out").mkdir()
    (root / "kit" / "out" / "generated.txt").write_text("x", encoding="utf-8")
    (root / "kit" / "README.md").write_text("kit\n", encoding="utf-8")
    return root


@pytest.fixture
def store_dir(tmp_path, repo):
    out = tmp_path / "artifacts"
    build(str(repo), str(out), commit=COMMIT, release="0.52.0", sources=FIXTURE_SOURCES)
    return out


def _tier1(tmp_path, **toolkit):
    spec = {"executor": "artifact", "allowed_artifact_operations": ["list", "info", "read", "transfer"],
            "allowed_artifacts": [CONTRACT, ADAPTER], "handover_dir": str(tmp_path / "handover"),
            "max_output_bytes": 200000, **toolkit}
    path = tmp_path / "toolkits.yaml"
    path.write_text(yaml.safe_dump({"toolkits": {"artifact": spec}, "audit": {"dir": str(tmp_path / "logs")}}),
                    encoding="utf-8")
    return load_tier1(str(path))


ART_PARAMS = {"artifact": {"type": "string", "required": True, "pattern": "^[a-z0-9-]+$",
                           "description": "artifact id"},
              "version": {"type": "string", "pattern": "^[0-9a-f]{7,40}$", "description": "commit"}}


def _tools():
    common = {"toolkit": "artifact", "version": 1, "enabled": True, "category": "read", "idempotent": True,
              "required_scopes": [], "timeout_seconds": 30, "max_output_bytes": 200000,
              "description": "artifact tool"}
    return [
        {**common, "id": "artifact.list", "title": "List", "artifact_operation": "list", "parameters": {}},
        {**common, "id": "artifact.info", "title": "Info", "artifact_operation": "info", "parameters": ART_PARAMS},
        {**common, "id": "artifact.read", "title": "Read", "artifact_operation": "read", "parameters": ART_PARAMS},
        {**common, "id": "artifact.transfer", "title": "Transfer", "artifact_operation": "transfer",
         "category": "write", "parameters": ART_PARAMS},
    ]


@pytest.fixture
def env(tmp_path, store_dir):
    tier1 = _tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, _tools())
    tokens = {"homelab": generate_token(), "other": generate_token()}
    ipath = tmp_path / "identities.yaml"
    ipath.write_text(yaml.safe_dump({"identities": [
        {"id": "homelab", "role": "agent", "token_hash": hash_token(tokens["homelab"]),
         "tools": [t["id"] for t in _tools()], "scopes": ["artifact:*"]},
        {"id": "other", "role": "agent", "token_hash": hash_token(tokens["other"]),
         "tools": [t["id"] for t in _tools()], "scopes": [f"artifact:{CONTRACT}"]},
    ]}), encoding="utf-8")
    identities = load_identities(str(ipath))
    service = Service(tier1=tier1, catalog=catalog, audit=AuditLog(str(tmp_path / "logs")),
                      identities=identities)
    service.artifact_store = ArtifactStore(str(store_dir))
    return service, identities, tokens


async def call(service, identities, who, tool, **args):
    return await service.call(identities.identities[who], tool, args)


# -- Build and store ------------------------------------------------------------------


def test_build_is_deterministic_and_bound_to_the_commit(tmp_path, repo, store_dir):
    again = tmp_path / "again"
    build(str(repo), str(again), commit=COMMIT, release="0.52.0", sources=FIXTURE_SOURCES)
    m1 = json.loads((store_dir / "manifest.json").read_text())
    m2 = json.loads((again / "manifest.json").read_text())
    assert m1 == m2
    assert m1["commit"] == COMMIT and {a["version"] for a in m1["artifacts"]} == {COMMIT}
    contract = (repo / "docs" / "EXAMPLE.md").read_bytes().replace(b"\r\n", b"\n")
    entry = next(a for a in m1["artifacts"] if a["id"] == CONTRACT)
    assert entry["sha256"] == hashlib.sha256(contract).hexdigest()


def test_tree_archive_contains_the_tree_and_nothing_generated(store_dir):
    import tarfile
    with tarfile.open(store_dir / KIT_FILE) as tar:
        names = tar.getnames()
    assert f"{ADAPTER}/pkg/main.py" in names
    assert f"{ADAPTER}/README.md" in names
    assert not any("/out/" in n or n.endswith(".pyc") or "__pycache__" in n for n in names)


def test_tampered_file_is_disabled(store_dir):
    (store_dir / DOC_FILE).write_text("tampered", encoding="utf-8")
    store = ArtifactStore(str(store_dir))
    assert store.get(CONTRACT) is None and store.disabled[CONTRACT] == "sha256 mismatch"
    assert store.get(ADAPTER) is not None


def test_missing_directory_serves_nothing(tmp_path):
    assert ArtifactStore(str(tmp_path / "nowhere")).list() == []


def test_the_image_builds_a_commit_bound_manifest_without_the_removed_adapter(tmp_path):
    # What the Dockerfile runs: no repository path is required any more,
    # and the removed Hermes recovery artifacts are not built.
    assert not {s["id"] for s in SOURCES} & {"hermes-adapter-contract", "hermes-recovery-adapter"}
    out = tmp_path / "image"
    manifest = build(str(tmp_path / "empty-checkout"), str(out), commit=COMMIT, release="0.52.0")
    assert manifest["commit"] == COMMIT and manifest["artifacts"] == []
    store = ArtifactStore(str(out))
    assert store.commit == COMMIT and store.list() == []


# -- Executor -------------------------------------------------------------------------


async def test_list_is_filtered_by_scope(env):
    service, identities, _ = env
    full = json.loads((await call(service, identities, "homelab", "artifact.list")).stdout)
    narrow = json.loads((await call(service, identities, "other", "artifact.list")).stdout)
    assert {a["id"] for a in full["artifacts"]} == {CONTRACT, ADAPTER} and full["commit"] == COMMIT
    assert {a["id"] for a in narrow["artifacts"]} == {CONTRACT}


async def test_missing_scope_looks_like_an_unknown_artifact(env):
    service, identities, _ = env
    hidden = await call(service, identities, "other", "artifact.info", artifact=ADAPTER)
    unknown = await call(service, identities, "other", "artifact.info", artifact="does-not-exist")
    assert hidden.outcome == unknown.outcome == "failed" and hidden.stderr == unknown.stderr


async def test_info_and_read_with_version_prefix(env):
    service, identities, _ = env
    info = json.loads((await call(service, identities, "homelab", "artifact.info",
                                  artifact=CONTRACT, version=COMMIT[:7])).stdout)
    assert info["commit"] == COMMIT and info["download_path"] == f"/artifacts/{CONTRACT}/{COMMIT}"
    text = (await call(service, identities, "homelab", "artifact.read", artifact=CONTRACT)).stdout
    assert text.startswith("# Example document\n")
    wrong = await call(service, identities, "homelab", "artifact.info", artifact=CONTRACT, version="deadbee")
    assert wrong.outcome == "failed"


async def test_read_refuses_a_binary_artifact(env):
    service, identities, _ = env
    res = await call(service, identities, "homelab", "artifact.read", artifact=ADAPTER)
    assert res.outcome == "failed" and "artifact.transfer" in res.stderr


async def test_transfer_writes_verified_and_is_idempotent(env, tmp_path):
    service, identities, _ = env
    first = json.loads((await call(service, identities, "homelab", "artifact.transfer", artifact=ADAPTER)).stdout)
    target = tmp_path / "handover" / ADAPTER / COMMIT / KIT_FILE
    assert first["transfer"] == "transferred" and first["path"] == str(target)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == first["sha256"]
    assert not [p for p in target.parent.iterdir() if p.name.startswith(".gk-")]
    again = json.loads((await call(service, identities, "homelab", "artifact.transfer", artifact=ADAPTER)).stdout)
    assert again["transfer"] == "already_present"


async def test_transfer_never_overwrites_a_different_file(env, tmp_path):
    service, identities, _ = env
    target = tmp_path / "handover" / CONTRACT / COMMIT / DOC_FILE
    target.parent.mkdir(parents=True)
    target.write_text("someone else's file", encoding="utf-8")
    res = await call(service, identities, "homelab", "artifact.transfer", artifact=CONTRACT)
    assert res.outcome == "failed" and "not overwritten" in res.stderr
    assert target.read_text(encoding="utf-8") == "someone else's file"


async def test_transfer_writes_nothing_when_the_bytes_changed_on_disk(env, tmp_path, store_dir):
    service, identities, _ = env
    (store_dir / KIT_FILE).write_bytes(b"changed after startup")
    res = await call(service, identities, "homelab", "artifact.transfer", artifact=ADAPTER)
    assert res.outcome == "failed" and "nothing was written" in res.stderr
    target_dir = tmp_path / "handover" / ADAPTER / COMMIT
    assert not target_dir.exists() or list(target_dir.iterdir()) == []


async def test_artifact_id_shape_is_checked(env):
    service, identities, _ = env
    from gatekeeper.errors import Denied
    with pytest.raises(Denied):
        await call(service, identities, "homelab", "artifact.info", artifact="../etc")


# -- Tier 1 and catalog guard rails ------------------------------------------------------


def test_transfer_requires_an_absolute_handover_dir(tmp_path):
    with pytest.raises(ConfigError, match="handover_dir"):
        _tier1(tmp_path, handover_dir=None)
    with pytest.raises(ConfigError, match="absolute"):
        _tier1(tmp_path, handover_dir="relative/dir")
    with pytest.raises(ConfigError, match="only meaningful"):
        _tier1(tmp_path, allowed_artifact_operations=["list"])


def test_run_as_and_destinations_are_refused(tmp_path):
    with pytest.raises(ConfigError):
        _tier1(tmp_path, run_as="hermes")


def test_a_tool_cannot_take_a_path_or_url(tmp_path):
    tier1 = _tier1(tmp_path)
    tool = {**_tools()[3], "parameters": {**ART_PARAMS, "path": {"type": "string", "pattern": "^.+$",
                                                                 "description": "x"}}}
    with pytest.raises(ConfigError, match="does not read"):
        make_catalog(tmp_path, tier1, [tool])


# -- HTTP download ---------------------------------------------------------------------


async def test_http_download_streams_verified_bytes(env, store_dir):
    service, identities, tokens = env
    app = build_app(service=service, identities=identities, audit=service.audit)
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://gk.test") as http:
        ok = await http.get(f"/artifacts/{ADAPTER}/{COMMIT[:12]}",
                            headers={"Authorization": f"Bearer {tokens['homelab']}"})
        hidden = await http.get(f"/artifacts/{ADAPTER}", headers={"Authorization": f"Bearer {tokens['other']}"})
        unknown = await http.get("/artifacts/nope", headers={"Authorization": f"Bearer {tokens['homelab']}"})
        anonymous = await http.get(f"/artifacts/{ADAPTER}")
    assert ok.status_code == 200
    assert hashlib.sha256(ok.content).hexdigest() == ok.headers["x-artifact-sha256"]
    assert ok.content == (store_dir / KIT_FILE).read_bytes()
    assert ok.headers["x-artifact-commit"] == COMMIT
    assert hidden.status_code == unknown.status_code == 404 and hidden.json() == unknown.json()
    assert anonymous.status_code == 401
    audit = open(os.path.join(service.tier1.audit_dir, "audit.jsonl"), encoding="utf-8").read()
    assert '"kind": "artifact_download"' in audit
