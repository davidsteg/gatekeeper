"""Built-in `artifact` executor -- release-bound artifacts (artifacts.py).

Four operations and no fifth: `list`, `info`, `read` and `transfer`. All
four run in-process against the read-only `ArtifactStore`; there is no argv,
no URL and no path parameter. The only things a call can name are an
artifact id and, optionally, a version (a commit prefix) -- both checked
against the manifest of the running image.

`transfer` writes into the toolkit's Tier 1 `handover_dir`, under
`<handover_dir>/<id>/<version>/<file>`: the directory comes from
toolkits.yaml, and the remaining path components come from the manifest,
never from the caller. It reads through `ArtifactStore.stream` -- the same
function the authenticated HTTP download (`GET /artifacts/...`) serves
from -- writes to a temp file, verifies the SHA-256, and only then renames.
An existing target with the same SHA-256 is left as is (idempotent); a
different file at that path is refused, never overwritten.

No output of this executor contains a credential: the store holds
repository files, and the transfer needs no token at all.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable

from .artifacts import Artifact, ArtifactStore, IntegrityError
from .execute import OUTCOME_FAILED, OUTCOME_OK, Result
from .tier1 import Toolkit


def _result(outcome: str, started: float, stdout: str = "", stderr: str = "") -> Result:
    return Result(outcome=outcome, exit_code=0 if outcome == OUTCOME_OK else 1, stdout=stdout,
                  stderr=stderr, truncated=False, duration_ms=int((time.monotonic() - started) * 1000))


async def run(
    *,
    operation: str,
    values: dict[str, str],
    toolkit: Toolkit,
    store: ArtifactStore,
    visible: Callable[[str], bool],
    max_output_bytes: int,
) -> Result:
    """`visible(id)` is the caller's scope check (`artifact:<id>`); an
    artifact it may not see is indistinguishable from one that does not
    exist (FR-7.7)."""
    started = time.monotonic()

    def allowed(art_id: str) -> bool:
        return art_id in toolkit.allowed_artifacts and visible(art_id)

    if operation == "list":
        items = [a.public() for a in store.list() if allowed(a.id)]
        return _result(OUTCOME_OK, started, json.dumps(
            {"release": store.release, "commit": store.commit, "artifacts": items}, indent=2))

    art_id = values.get("artifact", "")
    art = store.get(art_id, values.get("version") or None) if allowed(art_id) else None
    if art is None:
        return _result(OUTCOME_FAILED, started, stderr=(
            "Unknown artifact, or not available. Use artifact.list to see the artifacts "
            "of this release."))

    if operation == "info":
        return _result(OUTCOME_OK, started, json.dumps(art.public(), indent=2))
    if operation == "read":
        try:
            text = store.read_text(art, max_output_bytes)
        except (ValueError, IntegrityError) as exc:
            return _result(OUTCOME_FAILED, started, stderr=(
                f"{art.id} cannot be read inline: {exc}. Use artifact.transfer, or the "
                f"authenticated download {art.public()['download_path']}."))
        return _result(OUTCOME_OK, started, text)
    if operation == "transfer":
        return _transfer(art, store, toolkit, started)
    return _result(OUTCOME_FAILED, started, stderr=f"Unknown artifact operation: {operation!r}")


def _transfer(art: Artifact, store: ArtifactStore, toolkit: Toolkit, started: float) -> Result:
    handover = toolkit.handover_dir or ""
    target_dir = os.path.join(handover, art.id, art.version)
    target = os.path.join(target_dir, art.file)

    def done(state: str) -> Result:
        return _result(OUTCOME_OK, started, json.dumps({
            "transfer": state, "artifact": art.id, "version": art.version, "commit": art.commit,
            "path": target, "sha256": art.sha256, "size": art.size}, indent=2))

    if os.path.exists(target):
        if _sha256(target) == art.sha256:
            return done("already_present")
        return _result(OUTCOME_FAILED, started, stderr=(
            f"{target} exists with different content; it is not overwritten. An operator "
            "must remove or move it first."))
    try:
        os.makedirs(target_dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target_dir, prefix=".gk-", suffix=".part")
    except OSError as exc:
        return _result(OUTCOME_FAILED, started, stderr=f"handover_dir is not writable: {exc}")
    try:
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as out:
            for chunk in store.stream(art):
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if digest.hexdigest() != art.sha256:
            raise IntegrityError(f"{art.id}: written bytes do not match the manifest")
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except (OSError, IntegrityError) as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return _result(OUTCOME_FAILED, started, stderr=f"transfer failed, nothing was written: {exc}")
    return done("transferred")


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


async def probe(toolkit: Toolkit, store: ArtifactStore) -> bool:
    """Ready when the store serves at least one allowed artifact and, if the
    toolkit may transfer, its handover_dir is writable."""
    from ._atomic import writable

    if not any(a.id in toolkit.allowed_artifacts for a in store.list()):
        return False
    if "transfer" in toolkit.allowed_artifact_operations:
        probe_path = os.path.join(toolkit.handover_dir or "", ".probe")
        return bool(toolkit.handover_dir) and writable(probe_path)
    return True
