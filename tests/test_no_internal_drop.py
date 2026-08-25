"""Where gatekeeper is allowed to change a process's identity, and nowhere else.

Until 0.31.0 this file asserted something stronger and simpler: that
gatekeeper *never* changed its own uid, so a process found at 568 must
have been started at 568. 0.32.0 deliberately gave that up -- `_selfdrop`
exists precisely so the server can start as root and become 568 itself,
keeping the two capabilities `run_as` needs. The guarantee is therefore
narrower now, and this file pins the narrower one rather than being
deleted along with the old claim.

What still holds, and what these tests check:

- Two modules may change identity, and only two. `_runas.py` does it in
  the short-lived helper *child*, one file operation per process, one-way.
  `_selfdrop.py` does it once at startup, downward, keeping exactly
  `CAP_SETUID` and `CAP_SETGID`. No executor, no service, no server
  module.
- The startup drop cannot happen by accident. `drop_privileges` is
  reachable from `main()` alone, and only when `GATEKEEPER_DROP_TO` is
  set -- so an unconfigured deployment behaves exactly as it always did.
- The image still declares `USER 568:568` and still `exec`s the console
  script directly, with no shell wrapper in between.
- `compose.yaml` still declares exactly one `user:` key, so the run_as
  profile cannot be enabled by uncommenting a second one.

The diagnostic value survives the change: if the process is at 568 with an
empty `CapEff` and `GATEKEEPER_DROP_TO` is *unset*, gatekeeper did not put
it there and looking for an internal drop is still a dead end.
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

#: The only two modules allowed to contain them, and why each is allowed.
#: `_runas.py`: every call runs in a child process that exists for one file
#: operation and exits. `_selfdrop.py`: one call at startup, downward,
#: gated on `GATEKEEPER_DROP_TO`. Both have docstrings that argue the case;
#: a third entry here would need one too.
_ALLOWED = frozenset({"_runas.py", "_selfdrop.py"})


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
    """Guards the tests below against passing on an empty scan."""
    names = {p.name for p in _modules()}
    assert len(names) > 10
    assert {"__main__.py", "service.py", "execute.py"} | _ALLOWED <= names


@pytest.mark.parametrize("module", _modules(), ids=lambda p: p.name)
def test_only_the_two_sanctioned_modules_change_process_identity(module):
    """No executor, no service, no server module drops privileges.

    If this fails, the failure message is the answer to the question this
    file exists for: here is the drop, in this file, on this line.
    """
    calls = _identity_calls(module)
    if module.name in _ALLOWED:
        return
    assert not calls, (
        f"{module.name} changes the process identity: "
        + ", ".join(f"{name}() at line {line}" for name, line in calls)
        + f" -- only {sorted(_ALLOWED)} may."
    )


@pytest.mark.parametrize("allowed", sorted(_ALLOWED))
def test_each_allowance_is_actually_used(allowed):
    """The other direction: neither allowance is vacuous.

    A refactor that moved a drop somewhere else would otherwise leave the
    test above passing while the guarantee quietly changed shape.
    """
    calls = _identity_calls(_SRC / allowed)
    assert {name for name, _ in calls} >= {"setresuid", "setresgid"}


def test_the_startup_drop_cannot_happen_by_accident():
    """`drop_privileges` is called from `main()` and nowhere else, and only

    behind the `GATEKEEPER_DROP_TO` check. An unconfigured deployment must
    behave exactly as it did before the setting existed -- which is what
    lets the diagnostic in this file's docstring still hold.
    """
    callers = []
    for module in _modules():
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "drop_privileges"
            ):
                callers.append((module.name, node.lineno))
    assert [name for name, _ in callers] == ["__main__.py"], callers

    # ...and guarded, not unconditional: the call sits inside a branch that
    # tests the configured target for None.
    source = (_SRC / "__main__.py").read_text(encoding="utf-8")
    guard = source.index("configured_target()")
    call = source.index("drop_privileges(")
    assert guard < call, "drop_privileges runs before the setting is consulted"


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
    assert [name for name, _ in callers] == ["_runas.py"], callers


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
