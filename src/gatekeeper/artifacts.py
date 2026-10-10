"""Release-bound artifacts: built from this repository, served read-only.

**Single source of truth: the git commit.** Artifacts are never uploaded.
`build()` packages fixed repository paths (`SOURCES`) into a directory
with a `manifest.json` that records
the commit, the release version, and each file's SHA-256. The image build
runs it once (Dockerfile); the release job copies those exact files out of
the published image for the GitHub release instead of rebuilding them (gzip
output depends on the zlib build), so there is exactly one build of every
artifact.
"Released" means "contained in a released commit": there is no upload
route and no second approval path.

The running server reads that directory read-only (`ArtifactStore`). Every
file's SHA-256 is verified against the manifest at load; a mismatching
file is disabled, never served. One image carries the artifacts of its own
release and nothing older.

`stream()` is the only way bytes leave the store -- the authenticated HTTP
download and the `artifact.transfer` tool both use it, and both verify the
SHA-256 over exactly the bytes they hand on.
"""

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import io
import json
import logging
import os
import re
import tarfile
from collections.abc import Iterator, Sequence
from typing import Any

logger = logging.getLogger("gatekeeper")

MANIFEST = "manifest.json"
SCHEMA = 1
DEFAULT_DIR = "/opt/gatekeeper/artifacts"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
#: A version is the full commit id or an unambiguous prefix of it.
VERSION_RE = re.compile(r"^[0-9a-f]{7,40}$")
CHUNK = 64 * 1024

#: What gets built, from where. Fixed here, not configurable: an artifact
#: is a repository path at a commit, nothing else. An entry is either a
#: single file (`"kind": "file"`) or a directory packaged as a
#: deterministic tar.gz (`"kind": "tree"`), e.g.
#:
#:   {"id": "example-doc", "kind": "file", "path": "docs/EXAMPLE.md",
#:    "file": "EXAMPLE.md", "media_type": "text/markdown; charset=utf-8", "text": True}
#:
#: Empty since 1.0.0: the Hermes recovery adapter and its contract, the
#: only artifacts so far, were removed with the recovery supervisor. The
#: image still carries a commit-bound (empty) manifest.
SOURCES: tuple[dict[str, Any], ...] = ()
_EXCLUDE_PARTS = {"__pycache__", ".pytest_cache", "out"}


# -- Build -------------------------------------------------------------------


def _deterministic_tar(root: str, rel: str, prefix: str) -> bytes:
    """A byte-identical tar.gz for identical input: sorted entries, fixed
    mtime/owner/mode, gzip header without timestamp or name."""
    base = os.path.join(root, rel)
    entries: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in _EXCLUDE_PARTS)
        for name in sorted(filenames):
            if name.endswith(".pyc"):
                continue
            entries.append(os.path.relpath(os.path.join(dirpath, name), base))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for relpath in sorted(entries):
            data = open(os.path.join(base, relpath), "rb").read()
            if relpath.endswith((".py", ".md", ".yaml", ".json", ".txt")) or "." not in relpath:
                data = data.replace(b"\r\n", b"\n")  # checkout line endings never change the hash
            info = tarfile.TarInfo(f"{prefix}/{relpath.replace(os.sep, '/')}")
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def build(
    root: str, out: str, *, commit: str, release: str,
    sources: Sequence[dict[str, Any]] = SOURCES,
) -> dict[str, Any]:
    """Build every artifact in `sources` (default: SOURCES) from the
    checkout at `root` into `out`."""
    os.makedirs(out, exist_ok=True)
    artifacts = []
    for src in sources:
        if src["kind"] == "file":
            data = open(os.path.join(root, src["path"]), "rb").read().replace(b"\r\n", b"\n")
        else:
            data = _deterministic_tar(root, src["path"], src["id"])
        with open(os.path.join(out, src["file"]), "wb") as f:
            f.write(data)
        artifacts.append({
            "id": src["id"], "version": commit, "file": src["file"],
            "media_type": src["media_type"], "text": src["text"], "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "source": src["path"],
        })
    manifest = {"schema": SCHEMA, "release": release, "commit": commit, "artifacts": artifacts}
    with open(os.path.join(out, MANIFEST), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    return manifest


# -- Store -------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Artifact:
    id: str
    version: str
    file: str
    media_type: str
    text: bool
    size: int
    sha256: str
    source: str
    commit: str
    release: str

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "version": self.version, "commit": self.commit,
                "release": self.release, "file": self.file, "media_type": self.media_type,
                "size": self.size, "sha256": self.sha256, "source": self.source,
                "download_path": f"/artifacts/{self.id}/{self.version}"}


class IntegrityError(Exception):
    """The bytes on disk are not the bytes the manifest describes."""


class ArtifactStore:
    """Read-only view of one build's artifact directory."""

    def __init__(self, directory: str) -> None:
        self.directory = directory
        self.commit = ""
        self.release = ""
        self._artifacts: dict[str, Artifact] = {}
        self.disabled: dict[str, str] = {}
        self._load()

    @classmethod
    def from_env(cls) -> ArtifactStore:
        return cls(os.environ.get("GATEKEEPER_ARTIFACT_DIR", DEFAULT_DIR))

    def _load(self) -> None:
        path = os.path.join(self.directory, MANIFEST)
        try:
            manifest = json.load(open(path, encoding="utf-8"))
        except FileNotFoundError:
            return  # no artifacts in this build: nothing is served
        except (OSError, ValueError) as exc:
            logger.warning("Artifact manifest %s is unreadable (%s); no artifacts are served.", path, exc)
            return
        if manifest.get("schema") != SCHEMA:
            logger.warning("Artifact manifest %s has unknown schema %r; no artifacts are served.",
                           path, manifest.get("schema"))
            return
        self.commit = str(manifest.get("commit") or "")
        self.release = str(manifest.get("release") or "")
        for entry in manifest.get("artifacts") or []:
            art = Artifact(commit=self.commit, release=self.release,
                           **{k: entry[k] for k in ("id", "version", "file", "media_type", "text",
                                                    "size", "sha256", "source")})
            if not ID_RE.fullmatch(art.id) or os.path.basename(art.file) != art.file:
                self.disabled[art.id] = "invalid manifest entry"
                continue
            try:
                actual = _sha256_file(os.path.join(self.directory, art.file))
            except OSError as exc:
                self.disabled[art.id] = f"unreadable: {exc}"
                continue
            if actual != art.sha256:
                self.disabled[art.id] = "sha256 mismatch"
                logger.warning("Artifact %s (%s) does not match its manifest sha256; it is disabled.",
                               art.id, art.file)
                continue
            self._artifacts[art.id] = art

    def list(self) -> list[Artifact]:
        return sorted(self._artifacts.values(), key=lambda a: a.id)

    def get(self, artifact_id: str, version: str | None = None) -> Artifact | None:
        art = self._artifacts.get(artifact_id)
        if art is None:
            return None
        if version and not (VERSION_RE.fullmatch(version) and art.version.startswith(version)):
            return None
        return art

    def stream(self, art: Artifact) -> Iterator[bytes]:
        """The bytes of `art`, verified: raises IntegrityError at the end if
        what was read is not what the manifest promises (a file changed on
        disk after startup). Callers must not commit anything before the
        iterator is exhausted."""
        digest = hashlib.sha256()
        size = 0
        with open(os.path.join(self.directory, art.file), "rb") as f:
            while chunk := f.read(CHUNK):
                digest.update(chunk)
                size += len(chunk)
                yield chunk
        if digest.hexdigest() != art.sha256 or size != art.size:
            raise IntegrityError(f"{art.id}: content changed since startup")

    def read_text(self, art: Artifact, max_bytes: int) -> str:
        if not art.text:
            raise ValueError("not a text artifact")
        if art.size > max_bytes:
            raise ValueError(f"{art.size} bytes exceed the output limit of {max_bytes}")
        return b"".join(self.stream(art)).decode("utf-8")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m gatekeeper.artifacts",
                                     description="Build the release-bound artifact directory.")
    parser.add_argument("--root", default=".", help="repository checkout")
    parser.add_argument("--out", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--release", required=True)
    args = parser.parse_args(argv)
    manifest = build(args.root, args.out, commit=args.commit, release=args.release)
    for a in manifest["artifacts"]:
        print(f"{a['sha256']}  {a['file']}  ({a['size']} bytes, {a['id']}@{a['version'][:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
