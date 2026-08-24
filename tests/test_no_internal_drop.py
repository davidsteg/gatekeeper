"""That gatekeeper never changes its own process identity.

This file exists because the question keeps being asked, and answering it
by reading the source is both slow and unconvincing -- "I grepped and
found nothing" is not a guarantee, it is a report about one afternoon.

The question arrives in a recognisable shape: a container is configured
with `user: "0:0"` and `cap_add: [SETUID, SETGID]`, the process turns out
to be uid 568 with an empty `CapEff` anyway, and the natural conclusion is
that something inside gatekeeper dropped it -- an entrypoint, a PUID/PGID
convention, a `setuid` in the startup path that forgot `PR_SET_KEEPCAPS`.

There is no such thing, and these tests are what makes that a fact rather
than a claim. gatekeeper is started as some uid and stays that uid; the
only identity change in the whole tree happens in the short-lived `run_as`
helper *child*, after the parent has already forked and exec'd it. So a
process observed at 568 was started at 568, and the thing that starts it
there is the image's own `USER 568:568` -- which means the compose
`user:` never reached the container, and no amount of reading Python will
show why.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

_SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "gatekeeper"
_REPO = pathlib.Path(__file__).resolve().parent.parent

#: Everything in `os` that changes who the process is. `setgroups` and
#: `initgroups` are in here too: they do not change the uid, but they are
#: the other half of a privilege drop and have no other reason to appear.
_IDENTITY_CALLS = frozenset(
    {
        "setuid",
        "seteuid",
        "setreuid",
        "setresuid",
        "setgid",
        "setegid",
        "setregid",
        "setresgid",
        "setgroups",
        "initgroups",
    }
)

#: The one module allowed to contain them, and the reason it is allowed:
#: every call there runs in a child process that exists for exactly one
#: file operation and exits. See `_runas.py`'s own docstring.
_ALLOWED = "_runas.py"


def _identity_calls(path: pathlib.Path) -> list[tuple[str, int]]:
    """Every `os.<identity call>(...)` in `path`, as (name, line).

    Parsed rather than grepped, so the prose in a docstring that *names*
    `setresuid` -- of which this codebase has plenty -- does not count as
    a call to it.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = None
        if isinstance(func, ast.Attribute) and func.attr in _IDENTITY_CALLS:
            name = func.attr
        elif isinstance(func, ast.Name) and func.id in _IDENTITY_CALLS:
            name = func.id
        if name is not None:
            found.append((name, node.lineno))
    return found


def _modules() -> list[pathlib.Path]:
    return sorted(p for p in _SRC.rglob("*.py"))


def test_there_are_modules_to_check():
    """Guards the two tests below against passing on an empty scan."""
    names = {p.name for p in _modules()}
    assert len(names) > 10
    assert {"__main__.py", "service.py", "execute.py", _ALLOWED} <= names


@pytest.mark.parametrize("module", _modules(), ids=lambda p: p.name)
def test_only_the_run_as_helper_changes_process_identity(module):
    """No startup path, no executor, no entrypoint drops privileges.

    If this fails, the failure message is the answer to the question this
    file exists for: here is the drop, in this file, on this line.
    """
    calls = _identity_calls(module)
    if module.name == _ALLOWED:
        return
    assert not calls, (
        f"{module.name} changes the process identity: "
        + ", ".join(f"{name}() at line {line}" for name, line in calls)
        + f" -- only {_ALLOWED} may, and only inside its helper child."
    )


def test_the_helper_is_the_place_that_does_it():
    """The other direction: the allowance is not vacuous.

    A refactor that moved the drop somewhere else would otherwise leave
    the test above passing while the guarantee quietly changed shape.
    """
    calls = _identity_calls(_SRC / _ALLOWED)
    assert {name for name, _ in calls} >= {"setresuid", "setresgid"}


def test_the_helper_only_drops_from_its_own_entry_point():
    """`become` is reachable from the child's `_main` and nowhere else.

    What keeps the identity change inside a process that exists for one
    file operation, rather than in the server that spawned it.
    """
    callers = []
    for module in _modules():
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "become"
            ):
                callers.append((module.name, node.lineno))
    assert [name for name, _ in callers] == [_ALLOWED], callers


def test_the_image_declares_the_unprivileged_default():
    """Where 568 actually comes from, pinned so the docs stay true.

    Every message that tells an operator "gatekeeper never changes its own
    uid, so it was started this way" is only useful if the image really is
    what starts it that way.
    """
    dockerfile = (_REPO / "Dockerfile").read_text(encoding="utf-8")
    user_lines = [
        line.strip()
        for line in dockerfile.splitlines()
        if line.strip().startswith("USER ")
    ]
    assert user_lines == ["USER 568:568"], user_lines


def test_the_image_has_no_entrypoint_script_to_hide_a_drop():
    """ENTRYPOINT goes straight to the console script.

    A shell wrapper is the other place a uid change could live without
    showing up in any of the scans above -- so there must not be one.
    """
    dockerfile = (_REPO / "Dockerfile").read_text(encoding="utf-8")
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
    """The trap that produces the report this file answers.

    A service with two `user:` keys does not merge them -- compose keeps
    one, and if it keeps the unprivileged one the container comes up at
    568 with the capabilities granted and unusable, which looks exactly
    like an internal privilege drop. The commented `run_as` block must
    therefore not contain a `user:` key for anyone to uncomment.
    """
    compose = (_REPO / "compose.yaml").read_text(encoding="utf-8")
    user_keys = [
        line for line in compose.splitlines() if line.strip().startswith("user:")
    ]
    assert len(user_keys) == 1, user_keys
    # A line that would *become* a `user:` key if the comment marker were
    # stripped -- not merely prose that mentions one, of which the block
    # deliberately has several.
    commented = [
        line for line in compose.splitlines() if re.match(r"^\s*#\s*user:", line)
    ]
    assert not commented, (
        "a commented-out `user:` key in compose.yaml is a second one waiting "
        f"to be uncommented: {commented}"
    )
