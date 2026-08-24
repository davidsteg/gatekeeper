"""Stripping inherited ambient capabilities from `local` binaries (`_unpriv.py`).

Three things under test, and they fail differently:

1. **When the wrapper is used at all.** It must be absent from the spawn
   in every deployment that has no ambient capabilities to inherit --
   which is all of them but one -- and present in the one that does.
2. **That it is transparent.** Output, exit code, pid and the two
   `Denied` reasons for an unrunnable binary must not depend on whether
   the wrapper was in the way.
3. **That it actually drops.** Only provable while privileged, so those
   skip off root; between an ordinary CI runner and the `tests (root)`
   container job, both halves get exercised.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import textwrap

import pytest

from gatekeeper import execute
from gatekeeper._runas import CAP_SETGID, CAP_SETUID
from gatekeeper._unpriv import EXIT_NOT_EXECUTABLE, EXIT_NOT_FOUND, MARKER
from gatekeeper.errors import Denied

IS_ROOT = os.geteuid() == 0
_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))

needs_root = pytest.mark.skipif(
    not IS_ROOT, reason="raising ambient capabilities needs a privileged process"
)
needs_linux = pytest.mark.skipif(
    sys.platform != "linux", reason="capabilities are a Linux concept"
)

#: A capability set with exactly the two `run_as` needs.
SETID = (1 << CAP_SETUID) | (1 << CAP_SETGID)


def _run(argv, **kwargs):
    kwargs.setdefault("timeout_seconds", 30)
    kwargs.setdefault("max_output_bytes", 65536)
    kwargs.setdefault("idempotent", True)
    return asyncio.run(execute.run(argv, **kwargs))


def _spawned_argv(monkeypatch, ambient: int) -> list[str]:
    """The argv `execute.run` would really hand to the kernel."""
    captured: list[str] = []
    real = asyncio.create_subprocess_exec  # bound before patching, or it recurses

    async def capture(*argv, **kwargs):
        captured.extend(argv)
        # A process that exits immediately, so `run` can finish normally.
        return await real(sys.executable, "-c", "", **kwargs)

    monkeypatch.setattr(execute, "_ambient_capabilities", lambda: ambient)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture)
    _run(["/bin/echo", "hello"])
    return captured


# -- 1. Whether the wrapper is in the way ----------------------------------


def test_no_ambient_capabilities_means_no_wrapper(monkeypatch):
    """The deployment nearly everyone runs. Nothing to strip, so nothing is

    inserted: the binary is spawned directly, exactly as before this
    module existed.
    """
    assert _spawned_argv(monkeypatch, 0) == ["/bin/echo", "hello"]


def test_ambient_capabilities_put_the_wrapper_in_front(monkeypatch):
    argv = _spawned_argv(monkeypatch, SETID)
    assert argv == [sys.executable, "-m", "gatekeeper._unpriv", "/bin/echo", "hello"]


@needs_linux
def test_a_plain_process_reports_no_ambient_capabilities():
    """The gate itself: on a process that inherited nothing, the wrapper is

    never reached. Asserted against the real procfs rather than a stub,
    because a bug here silently costs every `local` call an interpreter.
    """
    assert execute._ambient_capabilities() == 0


# -- 2. That it changes nothing observable ---------------------------------


def test_the_wrapper_passes_output_and_exit_code_through():
    completed = subprocess.run(
        [sys.executable, "-m", "gatekeeper._unpriv", "/bin/sh", "-c", "echo out; exit 3"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHONPATH": _SRC},
    )
    assert completed.returncode == 3
    assert completed.stdout.strip() == "out"


def test_the_binary_keeps_the_pid_the_caller_is_holding():
    """`execv` replaces this process rather than forking, so the pid the

    parent holds *is* the binary's. That is what lets the timeout and the
    process-group kill in `execute.run` stay exactly as they are -- a
    wrapper that forked would leave them killing the wrapper.
    """
    with subprocess.Popen(
        [sys.executable, "-m", "gatekeeper._unpriv", "/bin/sh", "-c", "echo $$"],
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": _SRC},
    ) as process:
        out, _ = process.communicate(timeout=30)
    assert int(out.strip()) == process.pid


@pytest.mark.parametrize("ambient", [0, SETID], ids=["direct", "wrapped"])
def test_a_missing_binary_is_denied_identically(monkeypatch, ambient):
    """Whether a deployment inherits capabilities must not change what a

    caller sees. Same denial, same wording, naming the binary that was
    asked for rather than the interpreter asked to run it.
    """
    monkeypatch.setattr(execute, "_ambient_capabilities", lambda: ambient)
    with pytest.raises(Denied) as raised:
        _run(["/nonexistent/binary", "arg"])
    assert "Executable not found: /nonexistent/binary" in str(raised.value)


@pytest.mark.parametrize("ambient", [0, SETID], ids=["direct", "wrapped"])
def test_a_non_executable_file_is_denied_identically(monkeypatch, tmp_path, ambient):
    target = os.path.join(str(tmp_path), "not-executable")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\necho nope\n")
    os.chmod(target, 0o644)

    monkeypatch.setattr(execute, "_ambient_capabilities", lambda: ambient)
    with pytest.raises(Denied) as raised:
        _run([target])
    assert f"No permission to execute {target}" in str(raised.value)


# -- 3. That it actually drops ---------------------------------------------

#: Leaves the process unprivileged but ambiently capable -- the deployment
#: shape this module exists for. `PR_SET_KEEPCAPS` keeps the permitted set
#: across the uid change; `PR_CAP_AMBIENT_RAISE` is what makes the two
#: survive the following `execve`.
_AMBIENT_PREAMBLE = """
    import ctypes
    from gatekeeper._runas import CAP_SETGID, CAP_SETUID, _CAP_VERSION_3

    class _Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class _Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    libc = ctypes.CDLL(None, use_errno=True)
    _SETID = (1 << CAP_SETUID) | (1 << CAP_SETGID)

    def _set():
        header = _Header(_CAP_VERSION_3, 0)
        data = (_Data * 2)()
        data[0].effective = _SETID
        data[0].permitted = _SETID
        data[0].inheritable = _SETID
        assert libc.capset(ctypes.byref(header), ctypes.byref(data)) == 0

    _set()
    assert libc.prctl(8, 1, 0, 0, 0) == 0        # PR_SET_KEEPCAPS
    os.setresgid(1, 1, 1)
    os.setresuid(1, 1, 1)
    _set()
    for _cap in (CAP_SETUID, CAP_SETGID):        # PR_CAP_AMBIENT_RAISE
        assert libc.prctl(47, 2, _cap, 0, 0) == 0
"""


def _probe(*parts: str) -> subprocess.CompletedProcess:
    source = f"import os, sys\nsys.path.insert(0, {_SRC!r})\n" + "".join(
        textwrap.dedent(part) for part in parts
    )
    return subprocess.run(
        [sys.executable, "-c", source], capture_output=True, text=True, timeout=30
    )


def _capamb(status: str) -> int:
    return next(
        int(line.split(":", 1)[1].strip(), 16)
        for line in status.splitlines()
        if line.startswith("CapAmb:")
    )


@needs_root
def test_without_the_wrapper_a_binary_really_does_inherit_them():
    """The bug, demonstrated before the fix is asserted. Without this the

    test below would pass just as happily against a wrapper that did
    nothing at all.
    """
    completed = _probe(
        _AMBIENT_PREAMBLE,
        """
        os.execv("/bin/cat", ["/bin/cat", "/proc/self/status"])
        """,
    )
    assert completed.returncode == 0, completed.stderr
    assert _capamb(completed.stdout) == (1 << CAP_SETUID) | (1 << CAP_SETGID)


@needs_root
def test_the_wrapper_strips_them_before_the_binary_starts():
    """The same process, the same binary, with the wrapper in between:

    `cat` reports its own capability sets, so this is the binary's own
    account of what it was given rather than the wrapper's.
    """
    completed = _probe(
        _AMBIENT_PREAMBLE,
        """
        os.execv(
            sys.executable,
            [sys.executable, "-m", "gatekeeper._unpriv",
             "/bin/cat", "/proc/self/status"],
        )
        """,
    )
    assert completed.returncode == 0, completed.stderr
    status = completed.stdout
    assert _capamb(status) == 0
    for field in ("CapEff", "CapPrm", "CapInh"):
        value = next(
            int(line.split(":", 1)[1].strip(), 16)
            for line in status.splitlines()
            if line.startswith(f"{field}:")
        )
        assert value == 0, f"{field} survived: {value:016x}"


@needs_root
def test_it_refuses_to_run_the_binary_when_the_drop_did_not_take():
    """The one outcome worth failing loudly for. A `docker` that kept

    CAP_SETUID is indistinguishable from a correct call at the call site,
    so the wrapper must not fall back to running it.
    """
    completed = _probe(
        _AMBIENT_PREAMBLE,
        """
        import gatekeeper._unpriv as unpriv

        unpriv._clear_capabilities = lambda: None      # the drop silently fails
        code = unpriv._main(["/bin/echo", "should not run"])
        print("exit", code)
        """,
    )
    assert completed.returncode == 0, completed.stderr
    assert f"exit {EXIT_NOT_EXECUTABLE}" in completed.stdout
    assert "should not run" not in completed.stdout
    assert MARKER in completed.stderr
    assert "survived the drop" in completed.stderr


def test_a_missing_binary_reports_itself_with_the_marker():
    """What `execute.run` matches on to rebuild the ordinary denial."""
    completed = subprocess.run(
        [sys.executable, "-m", "gatekeeper._unpriv", "/nonexistent/binary"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHONPATH": _SRC},
    )
    assert completed.returncode == EXIT_NOT_FOUND
    assert completed.stderr.startswith(MARKER)
    assert completed.stderr[len(MARKER):].strip() == "not found"
