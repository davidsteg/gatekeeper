"""The server's own startup privilege drop (`_selfdrop.py`).

Every test here changes the process's identity irreversibly, so each runs
in its own interpreter rather than in the pytest process. And every one of
them needs to *start* privileged -- a non-root process cannot conjure
CAP_SETUID for itself -- so the real assertions skip off root and run in
the `tests (root)` container job. The two that do not need privilege (the
setting being off by default, and the refusals) run everywhere.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from gatekeeper._runas import CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_SETGID, CAP_SETUID

IS_ROOT = os.geteuid() == 0
_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))

needs_root = pytest.mark.skipif(
    not IS_ROOT, reason="dropping privileges requires starting with some"
)

#: What the drop must leave behind, and nothing besides.
KEPT = (1 << CAP_SETUID) | (1 << CAP_SETGID)

#: A uid that exists in no image's passwd file, which is the point: the
#: numeric form has to work without one, because a host uid usually has no
#: entry inside the container.
DROP_UID = 568


def _traversable(path: str) -> str:
    """Opens the ancestor chain up to /tmp for `x`.

    pytest's `tmp_path` tree is created 0700 under the *invoking* user, so
    the dropped-to uid cannot walk into it -- an artefact of the harness,
    not of anything under test, and it would otherwise mask the real
    permission being asserted one level down.
    """
    current = os.path.abspath(path)
    while current not in ("/", "/tmp"):
        os.chmod(current, os.stat(current).st_mode | 0o111)
        current = os.path.dirname(current)
    return path


def _probe(*parts: str, **env_extra: str) -> subprocess.CompletedProcess:
    """Runs the given source in a fresh interpreter.

    Each part is dedented on its own, so a shared preamble written at one
    indentation can be concatenated with a test body written at another.
    """
    source = f"import os, sys\nsys.path.insert(0, {_SRC!r})\n" + "".join(
        textwrap.dedent(part) for part in parts
    )
    return subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, **env_extra},
    )


#: Sets `no_new_privs` first, exactly as `no-new-privileges: true` does for
#: the container. Prefixed to the tests that must show the drop surviving
#: it, because "does this conflict with no-new-privileges" is the question
#: the design turns on and the one an implementation gets wrong silently.
_UNDER_NNP = """
    import ctypes
    assert ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) == 0
"""


# -- 1. Off unless configured ----------------------------------------------


def test_nothing_happens_without_the_setting():
    """The default, and every deployment that does not opt in.

    Asserted through `main()` rather than the module, because the wiring
    is the part that could start dropping by accident.
    """
    completed = _probe(
        """
        before = (os.getuid(), os.getgid())
        from gatekeeper._selfdrop import configured_target
        assert configured_target() is None
        assert (os.getuid(), os.getgid()) == before
        print("unchanged", before)
        """,
        GATEKEEPER_DROP_TO="",
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("unchanged")


def test_dropping_to_root_is_refused():
    """The one value the setting cannot take, since giving up root is its

    entire purpose. A typo here would otherwise read as "stay root".
    """
    completed = _probe(
        """
        from gatekeeper._selfdrop import SelfDropError, drop_privileges
        try:
            drop_privileges("0:0")
        except SelfDropError as exc:
            print(exc)
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert "cannot take" in completed.stdout


def test_an_unprivileged_process_says_so_instead_of_pretending(tmp_path):
    """Started as 568 with the setting pointing somewhere else: there is

    nothing to drop and nothing to keep, and saying so beats serving with
    a log line that claims a drop happened.
    """
    completed = _probe(
        f"""
        {"if os.geteuid() == 0:" if IS_ROOT else "if False:"}
            os.setresgid(65534, 65534, 65534)
            os.setresuid(65534, 65534, 65534)
        from gatekeeper._selfdrop import SelfDropError, drop_privileges
        try:
            drop_privileges("{DROP_UID}:{DROP_UID}")
        except SelfDropError as exc:
            print("refused:", exc)
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert "refused:" in completed.stdout
    assert "already running unprivileged" in completed.stdout


# -- 2. What the drop leaves behind ----------------------------------------


@needs_root
def test_the_drop_keeps_exactly_the_two_capabilities():
    """The claim the whole design rests on, under `no_new_privs`.

    Not "some capabilities": exactly `CAP_SETUID` and `CAP_SETGID`, in all
    of effective, permitted and ambient. A deployment that granted more
    must not carry the extra through the drop.
    """
    completed = _probe(
        _UNDER_NNP,
        f"""
        from gatekeeper._runas import capability_sets
        from gatekeeper._selfdrop import drop_privileges

        uid, gid = drop_privileges("{DROP_UID}:{DROP_UID}")
        print(os.getresuid(), os.getresgid(), sorted(capability_sets().items()))
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert f"({DROP_UID}, {DROP_UID}, {DROP_UID})" in completed.stdout
    held = dict(eval(completed.stdout[completed.stdout.index("["):]))  # noqa: S307
    for field in ("CapEff", "CapPrm", "CapInh", "CapAmb"):
        assert held[field] == KEPT, f"{field}={held[field]:016x}, want {KEPT:016x}"


@needs_root
def test_the_capabilities_survive_an_exec_under_no_new_privs():
    """Why the ambient set is raised at all.

    The `run_as` helper is a separate process reached by fork+exec, and
    the ambient set is the only one an `execve` carries. If this fails the
    drop looks perfect in the server and every `run_as` call still fails.
    `/bin/cat` reports its own capabilities, so this is the child's
    account rather than the parent's.
    """
    completed = _probe(
        _UNDER_NNP,
        f"""
        from gatekeeper._selfdrop import drop_privileges

        drop_privileges("{DROP_UID}:{DROP_UID}")
        os.execv("/bin/cat", ["/bin/cat", "/proc/self/status"])
        """
    )
    assert completed.returncode == 0, completed.stderr
    status = {
        line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in completed.stdout.splitlines()
        if ":" in line
    }
    assert status["NoNewPrivs"] == "1", "the probe must run under no_new_privs"
    assert int(status["CapEff"], 16) == KEPT
    assert int(status["CapPrm"], 16) == KEPT


@needs_root
def test_root_without_the_capabilities_cannot_drop_and_says_why():
    """`user: "0:0"` with `cap_drop: ALL` and no matching `cap_add`.

    Root alone is not enough: `setresuid` to an arbitrary uid needs
    CAP_SETUID like anyone else. Startup must refuse rather than carry on
    as root.
    """
    completed = _probe(
        f"""
        from gatekeeper._runas import _clear_capabilities
        from gatekeeper._selfdrop import SelfDropError, drop_privileges

        _clear_capabilities()
        assert os.geteuid() == 0
        try:
            drop_privileges("{DROP_UID}:{DROP_UID}")
        except SelfDropError as exc:
            print("refused:", exc)
        print("still root:", os.geteuid() == 0)
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert "refused:" in completed.stdout
    assert "cap_add: [SETUID, SETGID]" in completed.stdout


@needs_root
def test_discarding_hands_everything_back():
    """The config-dependent half: kept on spec, returned when unneeded."""
    completed = _probe(
        f"""
        from gatekeeper._runas import capability_sets
        from gatekeeper._selfdrop import discard_capabilities, drop_privileges

        drop_privileges("{DROP_UID}:{DROP_UID}")
        discard_capabilities()
        print(sorted(capability_sets().items()), os.getresuid())
        """
    )
    assert completed.returncode == 0, completed.stderr
    held = dict(eval(completed.stdout[:completed.stdout.index("]") + 1]))  # noqa: S307
    assert all(value == 0 for value in held.values()), held
    assert f"({DROP_UID}, {DROP_UID}, {DROP_UID})" in completed.stdout


# -- 3. That run_as actually works afterwards ------------------------------


@needs_root
def test_run_as_root_writes_as_root_from_a_dropped_server(tmp_path):
    """The point of the whole exercise, end to end.

    A server at 568 performing a `run_as: root` file operation, proved by
    the one fact the filesystem can confirm on its own: who owns what came
    out.
    """
    root = _traversable(str(tmp_path))
    os.chmod(root, 0o777)
    completed = _probe(
        _UNDER_NNP,
        f"""
        import asyncio
        from gatekeeper._selfdrop import drop_privileges
        from gatekeeper.execute_file import run as file_run

        drop_privileges("{DROP_UID}:{DROP_UID}")
        assert os.geteuid() == {DROP_UID}

        result = asyncio.run(file_run(
            operation="write", path={root + "/as-root.txt"!r},
            content="written by uid 0", path_roots=[{root!r}], protected=[],
            timeout_seconds=30, max_output_bytes=65536, idempotent=True,
            run_as="0:0",
        ))
        print("outcome", result.outcome, result.stderr[:200])
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("outcome ok"), completed.stdout
    written = os.path.join(root, "as-root.txt")
    assert os.stat(written).st_uid == 0


@needs_root
def test_without_run_as_the_server_user_still_writes(tmp_path):
    """The other half, and the one a regression would break silently: a

    toolkit that declares no `run_as` must keep writing as the dropped-to
    user, not quietly acquire root because the capability is available.
    """
    root = _traversable(str(tmp_path))
    os.chmod(root, 0o777)
    completed = _probe(
        _UNDER_NNP,
        f"""
        import asyncio
        from gatekeeper._selfdrop import drop_privileges
        from gatekeeper.execute_file import run as file_run

        drop_privileges("{DROP_UID}:{DROP_UID}")
        result = asyncio.run(file_run(
            operation="write", path={root + "/plain.txt"!r},
            content="written by the server", path_roots=[{root!r}],
            protected=[], timeout_seconds=30, max_output_bytes=65536,
            idempotent=True,
        ))
        print("outcome", result.outcome, result.stderr[:200])
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("outcome ok"), completed.stdout
    assert os.stat(os.path.join(root, "plain.txt")).st_uid == DROP_UID


# -- 4. The CLI wiring -----------------------------------------------------


@needs_root
def test_a_failed_drop_aborts_startup_rather_than_serving_as_root(tmp_path):
    """`main()` returns 2, and nothing goes on to listen.

    The failure this guards is the worst-behaved one available: a server
    that was told to give up root, could not, and served anyway.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "gatekeeper", "check"],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **os.environ,
            "PYTHONPATH": _SRC,
            "GATEKEEPER_CONFIG_DIR": str(tmp_path),
            "GATEKEEPER_DROP_TO": "0:0",
        },
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert "Configuration error" in completed.stderr


# -- 5. Supplementary groups ------------------------------------------------
#
# The drop parts company with `_runas.become` here. There, emptying the
# group set is the boundary; here the groups came from `group_add:` in the
# deployment and are the only way the container reaches the Docker socket.


@needs_root
def test_group_add_survives_the_drop():
    """`group_add: "999"` is how the container reaches /var/run/docker.sock.

    A drop that discarded it would leave every `docker` toolkit failing
    with EACCES, and nothing would say why -- with `user: "0:0"` the
    breakage only appears once the drop is switched on, because root did
    not need the group in the first place.
    """
    completed = _probe(
        f"""
        from gatekeeper._selfdrop import drop_privileges

        os.setgroups([0, 999])          # what Docker hands a 0:0 + group_add
        drop_privileges("{DROP_UID}:{DROP_UID}")
        print(sorted(os.getgroups()))
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert eval(completed.stdout.strip()) == [999]  # noqa: S307


@needs_root
def test_root_own_group_is_not_carried_across():
    """Group 0 is there because the container started as `user: "0:0"`, not

    because anyone asked for it. A process that has just given up root
    keeps no read access to root-group files on the way out.
    """
    completed = _probe(
        f"""
        from gatekeeper._selfdrop import drop_privileges

        os.setgroups([0])
        drop_privileges("{DROP_UID}:{DROP_UID}")
        print(sorted(os.getgroups()))
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert eval(completed.stdout.strip()) == []  # noqa: S307


# -- 6. GATEKEEPER_KEEP_CAPS ----------------------------------------------
#
# The base two (SETUID+SETGID) are always kept. GATEKEEPER_KEEP_CAPS names
# extras to carry through the drop into the run_as child's ambient set.
# The split: extras are in permitted/inheritable/ambient but NOT effective
# -- the server itself cannot use them, only the child can after execve.

_DAC_CAPS = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_DAC_READ_SEARCH)


def test_keep_caps_off_by_default():
    """No env var, no extras -- the base two only, as before."""
    completed = _probe(
        """
        from gatekeeper._selfdrop import configured_extra_caps
        assert configured_extra_caps() == 0
        print("zero")
        """,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "zero"


def test_keep_caps_empty_string_is_zero():
    """An empty GATEKEEPER_KEEP_CAPS is the same as unset."""
    completed = _probe(
        """
        from gatekeeper._selfdrop import configured_extra_caps
        assert configured_extra_caps() == 0
        print("zero")
        """,
        GATEKEEPER_KEEP_CAPS="",
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "zero"


def test_keep_caps_unknown_name_is_refused():
    """An unknown capability name is a config error, not a silent skip."""
    completed = _probe(
        """
        from gatekeeper._selfdrop import SelfDropError, configured_extra_caps
        try:
            configured_extra_caps()
        except SelfDropError as exc:
            print("refused:", exc)
        """,
        GATEKEEPER_KEEP_CAPS="NONSENSE",
    )
    assert completed.returncode == 0, completed.stderr
    assert "refused:" in completed.stdout
    assert "NONSENSE" in completed.stdout


def test_keep_caps_accepts_cap_prefix():
    """Both ``DAC_OVERRIDE`` and ``CAP_DAC_OVERRIDE`` are valid."""
    completed = _probe(
        """
        from gatekeeper._selfdrop import configured_extra_caps
        bits = configured_extra_caps()
        print(f"{bits:x}")
        """,
        GATEKEEPER_KEEP_CAPS="CAP_DAC_OVERRIDE,DAC_READ_SEARCH",
    )
    assert completed.returncode == 0, completed.stderr
    assert int(completed.stdout.strip(), 16) == _DAC_CAPS


@needs_root
def test_keep_caps_preserves_extras_in_permitted_inheritable_ambient():
    """The extras survive the drop in CapPrm, CapInh, CapAmb -- but not CapEff.

    This is the split: the server process cannot use DAC_OVERRIDE directly,
    only the run_as child can after inheriting it from the ambient set on
    execve. CapEff stays at the base two (SETUID+SETGID).
    """
    completed = _probe(
        _UNDER_NNP,
        f"""
        from gatekeeper._runas import capability_sets
        from gatekeeper._selfdrop import drop_privileges

        uid, gid = drop_privileges("{DROP_UID}:{DROP_UID}")
        print(os.getresuid(), os.getresgid(), sorted(capability_sets().items()))
        """,
        GATEKEEPER_KEEP_CAPS="DAC_OVERRIDE,DAC_READ_SEARCH",
    )
    assert completed.returncode == 0, completed.stderr
    assert f"({DROP_UID}, {DROP_UID}, {DROP_UID})" in completed.stdout
    held = dict(eval(completed.stdout[completed.stdout.index("["):]))  # noqa: S307
    kept = KEPT | _DAC_CAPS
    # Effective: base two only -- the server itself cannot use the extras.
    assert held["CapEff"] == KEPT, f"CapEff={held['CapEff']:016x}, want {KEPT:016x}"
    # Permitted, inheritable, ambient: the full kept set including extras.
    for field in ("CapPrm", "CapInh", "CapAmb"):
        assert held[field] == kept, f"{field}={held[field]:016x}, want {kept:016x}"


@needs_root
def test_keep_caps_extras_survive_exec_into_child():
    """The extras reach the run_as child through the ambient set.

    The child (here simulated by exec'ing /bin/cat) inherits the extras
    from ambient on execve, so its CapEff includes DAC_OVERRIDE. This is
    the mechanism that lets ``run_as: root`` read files owned by other
    users when GATEKEEPER_KEEP_CAPS is configured.
    """
    completed = _probe(
        _UNDER_NNP,
        f"""
        from gatekeeper._selfdrop import drop_privileges

        drop_privileges("{DROP_UID}:{DROP_UID}")
        os.execv("/bin/cat", ["/bin/cat", "/proc/self/status"])
        """,
        GATEKEEPER_KEEP_CAPS="DAC_OVERRIDE,DAC_READ_SEARCH",
    )
    assert completed.returncode == 0, completed.stderr
    status = {
        line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in completed.stdout.splitlines()
        if ":" in line
    }
    assert status["NoNewPrivs"] == "1"
    kept = KEPT | _DAC_CAPS
    # The child's CapEff includes the extras -- inherited from ambient.
    assert int(status["CapEff"], 16) == kept, (
        f"CapEff={status['CapEff']}, want {kept:016x}"
    )
    assert int(status["CapPrm"], 16) == kept


@needs_root
def test_keep_caps_run_as_root_reads_foreign_file(tmp_path):
    """End-to-end: run_as: root reads a 0600 file owned by another uid.

    Without GATEKEEPER_KEEP_CAPS, this would fail with Permission denied
    because root in the container has no DAC_OVERRIDE. With it, the child
    inherits DAC_OVERRIDE from ambient and reads the file.
    """
    root = _traversable(str(tmp_path))
    os.chmod(root, 0o777)

    # Create a file owned by a non-root uid (568), mode 0600 -- unreadable
    # to uid 0 without DAC_OVERRIDE. The test process is root, so it can
    # chown to 568; the dropped-to uid is also 568, but the child becomes
    # uid 0 via run_as="0:0", so it is NOT the owner and cannot read it
    # without the DAC capability.
    foreign = os.path.join(root, "foreign-0600.txt")
    with open(foreign, "w") as f:
        f.write("secret")
    os.chown(foreign, DROP_UID, DROP_UID)
    os.chmod(foreign, 0o600)

    completed = _probe(
        _UNDER_NNP,
        f"""
        import asyncio
        from gatekeeper._selfdrop import drop_privileges
        from gatekeeper.execute_file import run as file_run

        drop_privileges("{DROP_UID}:{DROP_UID}")
        assert os.geteuid() == {DROP_UID}

        result = asyncio.run(file_run(
            operation="read", path={foreign!r},
            path_roots=[{root!r}], protected=[],
            timeout_seconds=30, max_output_bytes=65536, idempotent=True,
            run_as="0:0",
        ))
        print("outcome", result.outcome, repr(result.stdout[:20]))
        """,
        GATEKEEPER_KEEP_CAPS="DAC_OVERRIDE,DAC_READ_SEARCH",
    )
    assert completed.returncode == 0, completed.stderr
    assert "outcome ok" in completed.stdout, completed.stdout
    assert "secret" in completed.stdout


@needs_root
def test_without_keep_caps_run_as_root_cannot_read_foreign_file(tmp_path):
    """The flip side: without GATEKEEPER_KEEP_CAPS, run_as: root is checked
    against file modes like any other user and cannot read a 0600 file it
    does not own. This is the documented, expected behavior.
    """
    root = _traversable(str(tmp_path))
    os.chmod(root, 0o777)

    # Owned by 568, mode 0600: root (uid 0) is not the owner and without
    # DAC_OVERRIDE cannot read it.
    foreign = os.path.join(root, "foreign-0600.txt")
    with open(foreign, "w") as f:
        f.write("secret")
    os.chown(foreign, DROP_UID, DROP_UID)
    os.chmod(foreign, 0o600)

    completed = _probe(
        _UNDER_NNP,
        f"""
        import asyncio
        from gatekeeper._selfdrop import drop_privileges
        from gatekeeper.execute_file import run as file_run

        drop_privileges("{DROP_UID}:{DROP_UID}")
        assert os.geteuid() == {DROP_UID}

        result = asyncio.run(file_run(
            operation="read", path={foreign!r},
            path_roots=[{root!r}], protected=[],
            timeout_seconds=30, max_output_bytes=65536, idempotent=True,
            run_as="0:0",
        ))
        print("outcome", result.outcome, repr(result.stderr[:60]))
        """,
        # No GATEKEEPER_KEEP_CAPS -- the default behavior.
    )
    assert completed.returncode == 0, completed.stderr
    assert "outcome failed" in completed.stdout, completed.stdout
    assert "Permission denied" in completed.stdout
