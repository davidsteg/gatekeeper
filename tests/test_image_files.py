"""What the Dockerfile, compose.yaml and the example config promise each other.

These read the files as text -- no daemon, no build. They moved here from
the Python implementation's suite (test_audit_dir.py and
test_no_internal_drop.py) when it was removed; the code-scanning halves of
those files are ported to the crate (rust/tests/cli.rs,
rust/tests/no_internal_drop.rs).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parent.parent

#: Where the audit log goes (FHS), outside /etc/gatekeeper, so that mount
#: can be read-only.
STANDARD = "/var/log/gatekeeper"


def _dockerfile() -> str:
    return (_REPO / "Dockerfile").read_text(encoding="utf-8")


# -- The audit directory ----------------------------------------------------


def test_the_image_declares_the_standard_path():
    """Pinned, because the compose mount and the example config below are
    only correct if the image agrees with them."""
    assert f"GATEKEEPER_AUDIT_DIR={STANDARD}" in _dockerfile()


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


def test_the_standard_path_is_not_under_etc():
    """/etc is for configuration, and a rotating log is not configuration."""
    assert not STANDARD.startswith("/etc/")
    assert STANDARD.startswith("/var/log/")


# -- Where 568 comes from ---------------------------------------------------


def test_the_image_declares_the_unprivileged_default():
    """Every message that tells an operator "gatekeeper did not change its
    own uid, so it was started this way" is only useful if the image really
    is what starts it that way."""
    user_lines = [
        line.strip()
        for line in _dockerfile().splitlines()
        if line.strip().startswith("USER ")
    ]
    assert user_lines == ["USER 568:568"], user_lines


def test_the_image_has_no_entrypoint_script_to_hide_a_drop():
    """ENTRYPOINT goes straight to the binary. A shell wrapper is the other
    place a uid change could live without showing up in the code scan --
    so there must not be one."""
    dockerfile = _dockerfile()
    entrypoints = [
        line.strip()
        for line in dockerfile.splitlines()
        if line.strip().startswith("ENTRYPOINT")
    ]
    assert entrypoints == ['ENTRYPOINT ["gatekeeper"]'], entrypoints
    assert "gosu" not in dockerfile
    assert "su-exec" not in dockerfile
    assert "setpriv" not in dockerfile


def test_the_compose_service_declares_exactly_one_user_key():
    """A service with two `user:` keys does not merge them -- compose keeps
    one, and if it keeps the unprivileged one the container comes up at
    568 with the capabilities granted and unusable, which looks exactly
    like an internal privilege drop. The commented `run_as` block must
    therefore not contain a `user:` key for anyone to uncomment."""
    compose = (_REPO / "compose.yaml").read_text(encoding="utf-8")
    user_keys = [line for line in compose.splitlines() if line.strip().startswith("user:")]
    assert len(user_keys) == 1, user_keys
    commented = [line for line in compose.splitlines() if re.match(r"^\s*#\s*user:", line)]
    assert not commented, (
        "a commented-out `user:` key in compose.yaml is a second one waiting "
        f"to be uncommented: {commented}"
    )
