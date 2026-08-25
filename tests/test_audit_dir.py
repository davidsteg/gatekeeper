"""Where a fresh install points its audit log.

Three answers used to coexist in the tree, which is two too many: `init`
wrote `<state-dir>/logs` (in the image, `/etc/gatekeeper/logs`), the
example config and the compose mount said `/mnt/raid/gatekeeper/logs`, and
the Tier 1 fallback said the same. The first of those is the one that
mattered, because it is what a real first start actually produces -- and it
put a file that rotates every few seconds inside the configuration
directory, which is precisely what stops that mount from being `:ro` and
Tier 1 from being immutable at runtime.

`GATEKEEPER_AUDIT_DIR` resolves it without hardcoding a container path into
a library: the image names its own layout, a bare `pip install` keeps the
self-contained default, and `--audit-dir` still wins over both.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest
import yaml

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
_REPO = pathlib.Path(__file__).resolve().parent.parent

#: What the image declares, and what the compose mount and the example
#: config must agree on.
STANDARD = "/var/log/gatekeeper"


def _init(config_dir: str, *args: str, **env: str) -> str:
    """Runs `gatekeeper init` and returns the audit dir it wrote."""
    completed = subprocess.run(
        [sys.executable, "-m", "gatekeeper", "init", "--config-dir", config_dir, *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **{k: v for k, v in os.environ.items() if k != "GATEKEEPER_AUDIT_DIR"},
            "PYTHONPATH": _SRC,
            **env,
        },
    )
    assert completed.returncode == 0, completed.stderr
    written = yaml.safe_load(
        (pathlib.Path(config_dir) / "toolkits.yaml").read_text(encoding="utf-8")
    )
    return written["audit"]["dir"]


def test_the_env_names_the_audit_dir(tmp_path):
    """How the image gets `/var/log/gatekeeper` without the library

    knowing that a container exists.
    """
    assert _init(str(tmp_path / "cfg"), GATEKEEPER_AUDIT_DIR=STANDARD) == STANDARD


def test_without_the_env_it_stays_self_contained(tmp_path):
    """A bare `pip install`, and the CI step that inits into a temp dir and

    then runs `check` against it. An absolute default would leave both with
    a configuration pointing somewhere they cannot write.
    """
    config = str(tmp_path / "cfg")
    assert _init(config) == os.path.join(config, "logs")


def test_the_flag_beats_the_env(tmp_path):
    """Explicit over implicit, and the escape hatch for a deployment whose

    storage is somewhere else entirely.
    """
    written = _init(
        str(tmp_path / "cfg"),
        "--audit-dir",
        "/somewhere/else",
        GATEKEEPER_AUDIT_DIR=STANDARD,
    )
    assert written == "/somewhere/else"


def test_the_audit_dir_is_not_inside_the_config_dir(tmp_path):
    """The property the change exists for.

    A configuration directory that is written to every few seconds cannot
    be mounted read-only, and then the file that decides what the agent may
    do is writable at runtime. That is the trade this avoids.
    """
    config = str(tmp_path / "cfg")
    written = _init(config, GATEKEEPER_AUDIT_DIR=STANDARD)
    assert not written.startswith(config)


def test_the_image_declares_the_standard_path():
    """Pinned, because the compose mount and the example config below are

    only correct if the image agrees with them.
    """
    dockerfile = (_REPO / "Dockerfile").read_text(encoding="utf-8")
    assert f"GATEKEEPER_AUDIT_DIR={STANDARD}" in dockerfile


def test_the_example_config_uses_the_standard_path():
    example = yaml.safe_load(
        (_REPO / "config" / "examples" / "toolkits.yaml").read_text(encoding="utf-8")
    )
    assert example["audit"]["dir"] == STANDARD


def test_the_compose_mount_targets_the_standard_path():
    """And does not map the host path onto itself.

    That is what made the in-container path an artefact of one particular
    NAS layout: left of the colon is storage, right of it is the container,
    and only the right-hand side should look standard.
    """
    compose = yaml.safe_load((_REPO / "compose.yaml").read_text(encoding="utf-8"))
    mounts = compose["services"]["gatekeeper"]["volumes"]
    targets = [m.split(":")[1] for m in mounts if isinstance(m, str) and ":" in m]
    assert STANDARD in targets, mounts
    for mount in mounts:
        host, _, container = mount.partition(":")
        if container.rstrip(":ro").rstrip(":") == STANDARD:
            assert host != STANDARD, "the log mount maps the host path onto itself"


@pytest.mark.parametrize("path", [STANDARD])
def test_the_standard_path_is_not_under_etc(path):
    """Stated as an assertion because it is the whole argument: /etc is for

    configuration, and a rotating log is not configuration.
    """
    assert not path.startswith("/etc/")
    assert path.startswith("/var/log/")
