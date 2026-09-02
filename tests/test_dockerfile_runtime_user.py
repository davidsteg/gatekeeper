"""The image's runtime user must be able to resolve `docker compose`.

Reported as `docker.compose_ps(stack=…)` exiting 125 with

    WARNING: Error loading config file: open /root/.docker/config.json:
             permission denied
    unknown shorthand flag: 'p' in -p

over two consecutive releases, with the docker executor suspected of
dropping the `compose` subcommand. It does not, and
`test_docker_compose_argv.py` pins that it cannot: there is no docker
branch that touches argv, so `docker compose -p …` is what reaches the
process. The failure is one layer lower -- docker itself would not
dispatch `compose`, because the CLI derives its config directory (the
first entry of its cli-plugin search path) from HOME, and the image left
HOME=/root while running as uid 568.

What let it ship twice is that the `RUN docker compose version` check runs
as root, whose HOME *is* readable. A build-time check performed as a
different user than the workload verifies the wrong thing and goes green
while production fails. These tests read the Dockerfile as text -- no
daemon, no build -- and pin the two halves that were missing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


@pytest.fixture
def lines() -> list[str]:
    return DOCKERFILE.read_text(encoding="utf-8").splitlines()


def _index_of(lines: list[str], pattern: str) -> int:
    for i, line in enumerate(lines):
        if re.match(pattern, line.strip()):
            return i
    raise AssertionError(f"no line matching {pattern!r} in the Dockerfile")


def test_home_is_not_root_for_the_unprivileged_user(lines):
    """HOME must move with USER, or the runtime user cannot read its own.

    `/root` is readable only by root. Leaving HOME there while running as
    568 is what produced the "permission denied" warning, and with it the
    failed plugin lookup.
    """
    body = "\n".join(lines)
    assert re.search(r"^\s*HOME=/home/apps", body, re.M), "the image must set HOME"
    assert not re.search(r"^\s*HOME=/root", body, re.M)


def test_the_home_directory_exists_and_belongs_to_the_runtime_user(lines):
    """Setting HOME at a path nobody created just moves the error."""
    body = "\n".join(lines)
    assert "mkdir -p /home/apps/.docker" in body
    assert "chown -R 568:568 /home/apps" in body


def test_compose_is_verified_after_dropping_to_the_runtime_user(lines):
    """The check that would have caught this, in the position that matters.

    A `docker compose version` before USER proves only that root can
    resolve the plugin. At least one has to run after the drop.
    """
    user_line = _index_of(lines, r"^USER 568:568")
    checks = [
        i for i, line in enumerate(lines)
        if line.strip().startswith("RUN docker compose version")
    ]
    assert checks, "the image must verify 'docker compose' at build time"
    assert any(i > user_line for i in checks), (
        "every 'docker compose version' check runs before USER 568:568, so it "
        "verifies root's view and not the runtime user's -- which is exactly "
        "how the 0.41.x exit-125 failure passed a green build"
    )
