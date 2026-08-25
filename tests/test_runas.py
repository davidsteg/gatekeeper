"""The `file` executor's per-toolkit OS user (`run_as`, `_runas.py`).

Three separate things are under test here and they fail in different ways,
so they are kept apart:

1. **Parsing and Tier 1** -- what `toolkits.yaml` accepts. Pure, runs
   anywhere.
2. **The executor path** -- that a `run_as` toolkit routes through the
   helper child and comes back with an ordinary `Result`. Exercised with
   `run_as` set to *the user the tests already are*, which needs no
   privilege at all and therefore runs in CI.
3. **The actual privilege drop** -- that the operation really executes as
   somebody else. Only provable while privileged, so those tests skip off
   root; the mirror-image test (an unprivileged process refusing to
   pretend) skips *on* root. Between an ordinary CI runner and a root
   container, both halves get exercised.
"""

from __future__ import annotations

import asyncio
import json
import os
import pwd
import subprocess
import sys
import textwrap

import pytest
import yaml

from gatekeeper._runas import RunAsError, parse_run_as, resolve_run_as
from gatekeeper.errors import ConfigError
from gatekeeper.execute_file import run as file_run
from gatekeeper.tier1 import load_tier1

IS_ROOT = os.geteuid() == 0
ME = f"{os.geteuid()}:{os.getegid()}"

needs_root = pytest.mark.skipif(
    not IS_ROOT, reason="a real privilege drop needs a privileged process"
)
needs_unprivileged = pytest.mark.skipif(
    IS_ROOT, reason="refusing to change user is only observable when unprivileged"
)


def _traversable(path: str) -> str:
    """Opens the ancestor chain up to /tmp for `x`.

    pytest's own `tmp_path` tree is created 0700 under the *invoking*
    user, so a dropped-to user cannot even walk into it -- an artefact of
    the test harness, not of anything under test, and it would otherwise
    mask the real permission being asserted one level down.
    """
    current = os.path.abspath(path)
    while current not in ("/", "/tmp"):
        os.chmod(current, os.stat(current).st_mode | 0o111)
        current = os.path.dirname(current)
    return path


def _nobody() -> tuple[int, int]:
    try:
        entry = pwd.getpwnam("nobody")
    except KeyError:
        pytest.skip("no 'nobody' account in this environment")
    return entry.pw_uid, entry.pw_gid


def _run(**kwargs):
    kwargs.setdefault("protected", [])
    kwargs.setdefault("timeout_seconds", 30)
    kwargs.setdefault("max_output_bytes", 65536)
    return asyncio.run(file_run(**kwargs))


# -- 1. Parsing -------------------------------------------------------------


def test_parses_a_user_name():
    assert parse_run_as("hermes") == ("hermes", None, None)


def test_parses_a_numeric_uid_gid_pair():
    assert parse_run_as("3001:3002") == (None, 3001, 3002)


def test_bare_numeric_uid_is_rejected():
    """`3001` alone would leave the group to a passwd lookup that a *host*

    uid does not have inside this image -- it would silently resolve to
    something, or to nothing, and neither is a group anyone chose.
    """
    with pytest.raises(RunAsError):
        parse_run_as("3001")


@pytest.mark.parametrize(
    "value",
    ["", "   ", "root nobody", "../root", "ro\not", "ro/ot", "-root", "root;id", "3001:"],
)
def test_malformed_values_are_rejected(value):
    with pytest.raises(RunAsError):
        parse_run_as(value)


def test_surrounding_whitespace_is_trimmed_not_rejected():
    """A YAML block scalar picks up a trailing newline; that is formatting,

    not a different user. Whitespace *inside* the value stays a rejection
    (above) -- the anchored pattern never sees a trimmed value it would
    otherwise have let through.
    """
    assert parse_run_as("  root\n") == ("root", None, None)


def test_resolves_a_real_account_to_its_own_group():
    uid, gid, name = resolve_run_as("root")
    assert (uid, gid, name) == (0, 0, "root")


def test_unknown_account_names_its_own_problem():
    with pytest.raises(RunAsError, match="passwd"):
        resolve_run_as("nosuchuser-cbc1f7")


def test_numeric_form_needs_no_passwd_entry():
    """The point of the numeric form: a host uid has no account inside the

    image, so a name lookup could never work for it.
    """
    assert resolve_run_as("60123:60124") == (60123, 60124, None)


# -- 2. Tier 1 --------------------------------------------------------------


def _tier1(tmp_path, spec: dict, name: str = "files"):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump({"toolkits": {name: spec}, "audit": {"dir": str(tmp_path / "l")}}),
        encoding="utf-8",
    )
    return load_tier1(str(path))


def test_file_toolkit_carries_run_as(tmp_path):
    tier1 = _tier1(tmp_path, {"executor": "file", "path_roots": ["/mnt/raid"], "run_as": "root"})
    assert tier1.toolkit("files").run_as == "root"


def test_file_toolkit_without_run_as_is_none(tmp_path):
    """The default, and what every toolkit written before the field existed

    gets: operations run in-process, as gatekeeper itself.
    """
    tier1 = _tier1(tmp_path, {"executor": "file", "path_roots": ["/mnt/raid"]})
    assert tier1.toolkit("files").run_as is None


@pytest.mark.parametrize(
    "spec",
    [
        {"executor": "local", "binaries": ["/bin/cat"]},
        {"executor": "docker", "binaries": ["/usr/bin/docker"]},
        {
            "executor": "http",
            "base_url": "http://x.lan",
            "allowed_methods": ["GET"],
            "allowed_path_prefixes": ["/api/"],
            "allowed_cidrs": ["10.0.0.0/8"],
        },
        {"executor": "truenas", "ws_url": "wss://x.lan/api", "allowed_rpc_methods": ["pool.query"]},
        {
            "executor": "ssh",
            "binaries": ["/bin/ps"],
            "ssh_host": "x.lan",
            "ssh_user": "ops",
            "ssh_known_hosts": "x.lan ssh-ed25519 AAAA",
        },
    ],
)
def test_run_as_on_any_other_executor_aborts_startup(tmp_path, spec):
    """Not "ignored where it means nothing": a toolkit that reads as

    "these operations run as somebody else" and does not is worse than one
    that refuses to start.
    """
    with pytest.raises(ConfigError, match="run_as"):
        _tier1(tmp_path, {**spec, "run_as": "root"})


def test_malformed_run_as_aborts_startup(tmp_path):
    with pytest.raises(ConfigError, match="run_as"):
        _tier1(tmp_path, {"executor": "file", "path_roots": ["/mnt/raid"], "run_as": "3001"})


# -- 2b. Per-tool run_as (catalog) -----------------------------------------
#
# Since 0.36.0 a tool spec can carry `run_as`, overriding the toolkit's.
# This is the fix for the bug where a per-tool `run_as: root` was silently
# ignored by write/patch (and only worked for read by coincidence of the
# toolkit also setting root). The tool-level field wins; None inherits
# the toolkit; "" explicitly clears it.

from gatekeeper.catalog import parse_tool_spec  # noqa: E402


def _file_tier1(tmp_path, run_as=None):
    """A one-toolkit file tier1, with an optional toolkit-level run_as."""
    spec = {"executor": "file", "path_roots": ["/mnt/raid"]}
    if run_as is not None:
        spec["run_as"] = run_as
    return _tier1(tmp_path, spec)


def test_tool_spec_without_run_as_inherits_none(tmp_path):
    """No run_as on the tool spec -> ToolDef.run_as is None, meaning
    'inherit the toolkit'. This is the default and what every tool
    written before 0.36.0 gets."""
    tier1 = _file_tier1(tmp_path)
    tool = parse_tool_spec(
        {"id": "files.read", "toolkit": "files", "category": "read",
         "file_operation": "read", "parameters": {"path": {"type": "string", "required": True}}},
        tier1,
    )
    assert tool.run_as is None


def test_tool_spec_run_as_is_parsed_into_tooldef(tmp_path):
    """A `run_as` on the tool spec lands in ToolDef.run_as, not lost."""
    tier1 = _file_tier1(tmp_path)
    tool = parse_tool_spec(
        {"id": "files.read", "toolkit": "files", "category": "read",
         "file_operation": "read", "run_as": "root",
         "parameters": {"path": {"type": "string", "required": True}}},
        tier1,
    )
    assert tool.run_as == "root"


def test_tool_spec_run_as_empty_string_is_explicit_clear(tmp_path):
    """An empty string is distinct from unset: it means 'run as the
    container user, ignoring what the toolkit says'."""
    tier1 = _file_tier1(tmp_path, run_as="root")
    tool = parse_tool_spec(
        {"id": "files.read", "toolkit": "files", "category": "read",
         "file_operation": "read", "run_as": "",
         "parameters": {"path": {"type": "string", "required": True}}},
        tier1,
    )
    assert tool.run_as == ""


def test_tool_spec_run_as_null_is_none(tmp_path):
    """A null run_as on the tool spec is the same as not setting it."""
    tier1 = _file_tier1(tmp_path, run_as="root")
    tool = parse_tool_spec(
        {"id": "files.read", "toolkit": "files", "category": "read",
         "file_operation": "read", "run_as": None,
         "parameters": {"path": {"type": "string", "required": True}}},
        tier1,
    )
    assert tool.run_as is None


def test_tool_spec_run_as_malformed_aborts_startup(tmp_path):
    """The same validation as the toolkit level: a bad value fails at
    parse time, not on the first call."""
    tier1 = _file_tier1(tmp_path)
    with pytest.raises(ConfigError, match="run_as"):
        parse_tool_spec(
            {"id": "files.read", "toolkit": "files", "category": "read",
             "file_operation": "read", "run_as": "3001",
             "parameters": {"path": {"type": "string", "required": True}}},
            tier1,
        )


# -- 3. The executor path ---------------------------------------------------


def test_run_as_self_round_trips_every_operation(tmp_path):
    """`run_as` pointing at the user the process already is exercises the

    whole helper path -- spawn, JSON in, operation, JSON out -- without
    needing any privilege, which is what makes it runnable in CI.
    """
    root = str(tmp_path)
    target = os.path.join(root, "sub", "config.yaml")

    written = _run(
        operation="write", path=target, content="version: 1\n",
        path_roots=[root], run_as=ME,
    )
    assert written.outcome == "ok", written.stderr

    patched = _run(
        operation="patch", path=target, old_string="version: 1", new_string="version: 2",
        path_roots=[root], run_as=ME,
    )
    assert patched.outcome == "ok", patched.stderr

    read = _run(operation="read", path=target, path_roots=[root], run_as=ME)
    assert read.outcome == "ok"
    assert "version: 2" in read.stdout

    listed = _run(operation="list", path=os.path.join(root, "sub"), path_roots=[root], run_as=ME)
    assert listed.outcome == "ok"
    assert "f config.yaml" in listed.stdout


def test_run_as_reports_an_ordinary_failure_as_failed(tmp_path):
    result = _run(
        operation="read", path=os.path.join(str(tmp_path), "missing.txt"),
        path_roots=[str(tmp_path)], run_as=ME,
    )
    assert result.outcome == "failed"
    assert "not found" in result.stderr.lower()


def test_run_as_still_honours_max_output_bytes(tmp_path):
    path = os.path.join(str(tmp_path), "big.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("A" * 400)

    result = _run(
        operation="read", path=path, path_roots=[str(tmp_path)],
        max_output_bytes=100, run_as=ME,
    )
    assert result.outcome == "ok"
    assert result.truncated is True
    assert len(result.stdout.encode("utf-8")) <= 100 + len("\n... [truncated]")


def test_run_as_does_not_widen_path_roots(tmp_path):
    """Tier 1 is checked before anything is spawned -- a `run_as` toolkit is

    not a way around `path_roots`, only around file ownership.
    """
    result = _run(
        operation="read", path="/etc/passwd", path_roots=[str(tmp_path)], run_as=ME,
    )
    assert result.outcome == "failed"
    assert "outside allowed roots" in result.stderr.lower()


def test_run_as_does_not_widen_protected_resources(tmp_path):
    os.makedirs(os.path.join(str(tmp_path), "gatekeeper"))
    result = _run(
        operation="read", path=os.path.join(str(tmp_path), "gatekeeper", "x.yaml"),
        path_roots=[str(tmp_path)], protected=["gatekeeper"], run_as=ME,
    )
    assert result.outcome == "failed"
    assert "protected resource" in result.stderr.lower()


def test_helper_revalidates_tier1_itself(tmp_path):
    """The child re-runs `validate_path` after dropping privileges.

    Driven by calling the helper directly with a path its own `path_roots`
    do not cover -- which the parent would never send. The parent's check
    is the real gate; this one is why a future refactor of the parent
    cannot turn the privileged half into a confused deputy.
    """
    request = {
        "run_as": ME,
        "operation": "read",
        "path": "/etc/passwd",
        "path_roots": [str(tmp_path)],
        "protected": [],
        "max_output_bytes": 4096,
    }
    completed = subprocess.run(
        [sys.executable, "-m", "gatekeeper._runas"],
        input=json.dumps(request).encode("utf-8"),
        capture_output=True,
        timeout=30,
    )
    payload = json.loads(completed.stdout.decode("utf-8"))
    assert payload["outcome"] == "failed"
    assert "outside allowed roots" in payload["stderr"].lower()
    assert "root:" not in payload["stdout"]


def test_run_as_timeout_is_unknown_for_a_non_idempotent_write(tmp_path):
    """FR-6.9 applies to the helper too: a killed write may or may not have

    reached the disk, and calling that `failed` invites the retry that
    truncates the file a second time.
    """
    result = _run(
        operation="write", path=os.path.join(str(tmp_path), "x.txt"), content="hi",
        path_roots=[str(tmp_path)], timeout_seconds=0, idempotent=False, run_as=ME,
    )
    assert result.outcome == "unknown"
    assert "UNKNOWN" in result.stderr


def test_run_as_timeout_on_an_idempotent_read_is_a_plain_failure(tmp_path):
    result = _run(
        operation="read", path=os.path.join(str(tmp_path), "x.txt"),
        path_roots=[str(tmp_path)], timeout_seconds=0, idempotent=True, run_as=ME,
    )
    assert result.outcome == "failed"
    assert "UNKNOWN" not in result.stderr


def test_default_path_spawns_nothing(tmp_path, monkeypatch):
    """The toolkit without `run_as` -- every toolkit that existed before

    this field -- must still be the in-process executor it always was. A
    `create_subprocess_exec` that raises if called is the check.
    """
    async def refuse(*args, **kwargs):
        raise AssertionError("the default file executor must not spawn a process")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", refuse)
    path = os.path.join(str(tmp_path), "plain.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("still in-process")

    result = _run(operation="read", path=path, path_roots=[str(tmp_path)])
    assert result.outcome == "ok"
    assert "still in-process" in result.stdout


# -- 4. The privilege boundary ---------------------------------------------


@needs_unprivileged
def test_unprivileged_process_refuses_rather_than_pretends(tmp_path):
    """The property that makes `run_as` a boundary and not a hint: a process

    that cannot become the requested user fails the call, instead of
    quietly running it as itself and letting the resulting "Permission
    denied" imply the override was in effect.
    """
    path = os.path.join(str(tmp_path), "x.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("data")

    result = _run(operation="read", path=path, path_roots=[str(tmp_path)], run_as="0:0")
    assert result.outcome == "failed"
    assert "no privilege to change user" in result.stderr
    assert "data" not in result.stdout


@needs_root
def test_the_written_file_belongs_to_the_run_as_user(tmp_path):
    """That the operation *really* ran as somebody else, stated as the one

    fact the filesystem can confirm independently: who owns what came out.
    """
    uid, gid = _nobody()
    root = _traversable(str(tmp_path))
    os.chmod(root, 0o777)
    target = os.path.join(root, "owned.txt")

    result = _run(
        operation="write", path=target, content="written by nobody",
        path_roots=[root], run_as=f"{uid}:{gid}",
    )
    assert result.outcome == "ok", result.stderr
    assert os.stat(target).st_uid == uid
    assert os.stat(target).st_gid == gid


@needs_root
def test_the_drop_actually_removes_authority(tmp_path):
    """The other direction, and the more important one: after the drop the

    operation is bound by the target user's permissions, not by root's. A
    root-only directory the in-process executor writes into without
    trouble must be closed to the dropped-to user.
    """
    uid, gid = _nobody()
    root = _traversable(str(tmp_path))
    locked = os.path.join(root, "root-only")
    os.makedirs(locked)
    os.chmod(root, 0o755)
    os.chmod(locked, 0o700)
    target = os.path.join(locked, "x.txt")

    as_root = _run(operation="write", path=target, content="root wrote this", path_roots=[root])
    assert as_root.outcome == "ok", as_root.stderr

    as_nobody = _run(
        operation="read", path=target, path_roots=[root], run_as=f"{uid}:{gid}",
    )
    assert as_nobody.outcome == "failed"
    assert "permission denied" in as_nobody.stderr.lower()
    assert "root wrote this" not in as_nobody.stdout


@needs_root
def test_run_as_reaches_a_directory_the_container_user_cannot(tmp_path):
    """The case the field exists for, inverted into a test: a directory

    owned by another user with mode 0700, which the process could not read
    as itself but can read as that user.
    """
    uid, gid = _nobody()
    root = _traversable(str(tmp_path))
    theirs = os.path.join(root, "theirs")
    os.makedirs(theirs)
    secret = os.path.join(theirs, "agent.yaml")
    with open(secret, "w", encoding="utf-8") as handle:
        handle.write("model: hermes\n")
    os.chown(secret, uid, gid)
    os.chown(theirs, uid, gid)
    os.chmod(theirs, 0o700)

    result = _run(operation="read", path=secret, path_roots=[root], run_as=f"{uid}:{gid}")
    assert result.outcome == "ok", result.stderr
    assert "model: hermes" in result.stdout


@needs_root
def test_root_is_not_regainable_after_the_drop():
    """`become` sets real, effective *and* saved ids. The saved id is the

    one that matters: left at 0, everything after the drop could call
    `setuid(0)` and be root again -- which is what this asserts cannot
    happen, from inside a child that has already dropped.
    """
    uid, gid = _nobody()
    src = os.path.join(os.path.dirname(__file__), "..", "src")
    probe = (
        f"import os, sys;"
        f"sys.path.insert(0, {src!r});"
        f"from gatekeeper._runas import become;"
        f"become({uid}, {gid}, None);"
        f"ok = False\n"
        f"try:\n"
        f"    os.setuid(0)\n"
        f"except OSError:\n"
        f"    ok = True\n"
        f"print(ok, os.getresuid(), os.getresgid())"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=30
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("True")
    assert f"({uid}, {uid}, {uid})" in completed.stdout
    assert f"({gid}, {gid}, {gid})" in completed.stdout


@needs_root
def test_an_unknown_run_as_user_fails_the_call_and_reads_nothing(tmp_path):
    path = os.path.join(str(tmp_path), "x.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("data")

    result = _run(
        operation="read", path=path, path_roots=[str(tmp_path)], run_as="nosuchuser-cbc1f7",
    )
    assert result.outcome == "failed"
    assert "passwd" in result.stderr
    assert "data" not in result.stdout


# -- 5. What the privilege actually is -------------------------------------
#
# The section that exists because of a real misdiagnosis. `become` used to
# ask `geteuid() != 0` and answer with "add CAP_SETUID and CAP_SETGID",
# which is wrong in both directions: root whose capabilities were dropped
# passes that test and fails three lines later with a bare EPERM, and a
# container still running as 568 is told to add capabilities it already
# added -- because Docker grants `cap_add` in uid 0's permitted set only,
# so `cap_add` without `user: "0:0"` grants nothing and the message repeats
# itself unchanged after every redeploy. The privilege is a capability, so
# these ask about the capability.

IS_LINUX = sys.platform == "linux"

needs_linux = pytest.mark.skipif(not IS_LINUX, reason="capabilities are a Linux concept")

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def _probe(*parts: str) -> subprocess.CompletedProcess:
    """Runs the given source in a fresh interpreter that can import gatekeeper.

    A subprocess rather than a fixture because every one of these tests
    changes the process's own uid or capability set irreversibly -- doing
    that in the pytest process would break every test after it. Each part
    is dedented on its own, so a caller can concatenate a shared preamble
    written at one indentation with a test body written at another.
    """
    source = f"import os, sys\nsys.path.insert(0, {_SRC!r})\n" + "".join(
        textwrap.dedent(part) for part in parts
    )
    return subprocess.run(
        [sys.executable, "-c", source], capture_output=True, text=True, timeout=30
    )


#: Raises CAP_SETUID/CAP_SETGID into the inheritable set, turns on
#: `PR_SET_KEEPCAPS`, and drops to `uid` -- the shape a hardened deployment
#: has when it runs unprivileged but ambiently capable. Without KEEPCAPS the
#: kernel empties the permitted set on the way out of uid 0, which is the
#: ordinary case the other tests cover.
_KEEP_CAPS_AND_DROP_TO = """
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

    def _set(effective, permitted, inheritable):
        header = _Header(_CAP_VERSION_3, 0)
        data = (_Data * 2)()
        data[0].effective = effective & 0xFFFFFFFF
        data[0].permitted = permitted & 0xFFFFFFFF
        data[0].inheritable = inheritable & 0xFFFFFFFF
        assert libc.capset(ctypes.byref(header), ctypes.byref(data)) == 0, \\
            ctypes.get_errno()

    _SETID = (1 << CAP_SETUID) | (1 << CAP_SETGID)
"""


@needs_linux
def test_the_effective_capability_set_is_read_from_procfs():
    """The one fact everything below rests on: the number in

    `/proc/self/status` is what `effective_capabilities` returns.
    """
    from gatekeeper._runas import effective_capabilities

    with open("/proc/self/status", encoding="ascii") as handle:
        expected = next(
            int(line.split(":", 1)[1].strip(), 16)
            for line in handle
            if line.startswith("CapEff:")
        )
    assert effective_capabilities() == expected


@needs_root
def test_a_capable_root_process_can_change_user():
    from gatekeeper._runas import can_change_user

    assert can_change_user() is True


@needs_root
def test_root_without_the_capabilities_cannot_change_user():
    """The half the old `geteuid() != 0` test let through. A container that

    is root but ran `cap_drop: ALL` with no matching `cap_add` has no more
    ability to become another user than an unprivileged one -- and used to
    discover that only when `setresuid` returned EPERM.
    """
    completed = _probe(
        """
        from gatekeeper._runas import _clear_capabilities, can_change_user

        assert os.geteuid() == 0, "probe must start privileged"
        assert can_change_user() is True
        _clear_capabilities()
        print(os.geteuid(), can_change_user())
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "0 False"


@needs_root
def test_the_message_for_a_capability_less_root_names_cap_drop():
    """...and says which half is missing, rather than naming both and

    leaving the operator to guess.
    """
    completed = _probe(
        """
        from gatekeeper._runas import RunAsError, _clear_capabilities, become

        _clear_capabilities()
        try:
            become(3001, 3001, None)
        except RunAsError as exc:
            print(exc)
        """
    )
    assert completed.returncode == 0, completed.stderr
    message = completed.stdout
    assert "no privilege to change user" in message
    assert "cap_drop: ALL" in message
    assert "runs as root" in message


@needs_root
def test_the_message_for_a_non_root_container_names_the_user_directive():
    """The bug this section exists for, stated as an assertion: a container

    still running as 568 must be told that `user: "0:0"` is what is
    missing. Telling it to add capabilities is what made the failure
    survive a redeploy that added them.
    """
    uid, gid = _nobody()
    completed = _probe(
        f"""
        from gatekeeper._runas import RunAsError, become

        os.setresgid({gid}, {gid}, {gid})
        os.setresuid({uid}, {uid}, {uid})
        try:
            become(3001, 3001, None)
        except RunAsError as exc:
            print(exc)
        """
    )
    assert completed.returncode == 0, completed.stderr
    message = completed.stdout
    assert "no privilege to change user" in message
    assert 'user: "0:0"' in message
    assert "not running as root" in message
    # ...and says so about `cap_add` explicitly, because the operator has
    # by this point already added it and needs to be told that doing it
    # again is not the fix.
    assert "not 'cap_add'" in message


@needs_root
def test_the_drop_leaves_no_capabilities_behind():
    """Property 1 of the module, restated for the half `getresuid` cannot

    see: dropping the ids while keeping CAP_SETUID would leave `setuid(0)`
    one call away.
    """
    uid, gid = _nobody()
    completed = _probe(
        f"""
        from gatekeeper._runas import become, effective_capabilities

        become({uid}, {gid}, None)
        print(effective_capabilities(), os.getresuid())
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("0 ")
    assert f"({uid}, {uid}, {uid})" in completed.stdout


@needs_root
def test_ambient_capabilities_are_enough_without_being_root():
    """The case the uid test refused outright: a process that is *not* root

    but does hold CAP_SETUID/CAP_SETGID can assume another user, and this
    is the configuration a deployment reaches by keeping the capabilities
    across its own drop rather than staying uid 0.
    """
    uid, gid = _nobody()
    completed = _probe(
        _KEEP_CAPS_AND_DROP_TO,
        f"""
        from gatekeeper._runas import become, can_change_user, effective_capabilities

        _set(_SETID, _SETID, _SETID)
        assert ctypes.CDLL(None).prctl(8, 1, 0, 0, 0) == 0  # PR_SET_KEEPCAPS
        os.setresgid(1, 1, 1)
        os.setresuid(1, 1, 1)
        _set(_SETID, _SETID, _SETID)  # re-raise: the drop clears *effective*

        assert os.geteuid() != 0, "probe must be unprivileged"
        assert can_change_user() is True, "ambient CAP_SETUID must count"

        become({uid}, {gid}, None)
        print(os.getresuid(), os.getresgid(), effective_capabilities())
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert f"({uid}, {uid}, {uid})" in completed.stdout
    assert f"({gid}, {gid}, {gid})" in completed.stdout
    # And the capabilities did not survive the drop -- a non-root-to-non-root
    # uid change does not clear them, so `become` has to do it itself.
    assert completed.stdout.rstrip().endswith(" 0")


@needs_linux
def test_the_helper_child_forbids_gaining_privilege_through_exec(tmp_path):
    """`no_new_privs` is set before the child reads its own request.

    Emptying the capability sets says what the child holds; it says nothing
    about the bounding set, which stays full because lowering it needs
    CAP_SETPCAP. So the child closes the `execve` route instead -- and does
    it first, so it holds even on the paths that never reach the drop.

    Runs unprivileged too: `run_as` is the user the test already is, which
    needs no privilege and exercises the same entry point.
    """
    path = os.path.join(str(tmp_path), "x.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("data")
    request = json.dumps(
        {
            "run_as": ME,
            "operation": "read",
            "path": path,
            "path_roots": [str(tmp_path)],
            "protected": [],
            "max_output_bytes": 4096,
        }
    )
    source = (
        f"import sys\nsys.path.insert(0, {_SRC!r})\n"
        "from gatekeeper._runas import _main\n"
        "_main()\n"
        # ...to stderr, so it does not land in the JSON result on stdout.
        "print(next(l.split(':')[1].strip() for l in open('/proc/self/status')\n"
        "           if l.startswith('NoNewPrivs')), file=sys.stderr)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", source],
        input=request,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["outcome"] == "ok"
    assert completed.stderr.strip().endswith("1"), "NoNewPrivs must be 1"


@needs_root
def test_no_new_privs_does_not_stand_in_the_way_of_the_drop():
    """The reason it can be set unconditionally: `no_new_privs` restricts

    what `execve` may grant, and nothing about `setresuid`. If it did cost
    the drop anything, it would not be worth having.
    """
    uid, gid = _nobody()
    completed = _probe(
        f"""
        from gatekeeper._runas import _set_no_new_privs, become

        assert _set_no_new_privs() is True
        become({uid}, {gid}, None)
        print(os.getresuid(), os.getresgid())
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert f"({uid}, {uid}, {uid})" in completed.stdout
    assert f"({gid}, {gid}, {gid})" in completed.stdout


@needs_root
def test_the_drop_empties_every_capability_set_not_only_the_effective_one():
    """A capability in the permitted set is one `capset` from being usable

    again, and one in the ambient set survives the next `execve` -- so
    "CapEff is zero" is not the property worth asserting. The ambient
    deployment is the one that can actually get this wrong: a
    non-root-to-non-root id change clears nothing by itself.
    """
    uid, gid = _nobody()
    completed = _probe(
        _KEEP_CAPS_AND_DROP_TO,
        f"""
        from gatekeeper._runas import become, capability_sets

        _set(_SETID, _SETID, _SETID)
        assert ctypes.CDLL(None).prctl(8, 1, 0, 0, 0) == 0  # PR_SET_KEEPCAPS
        os.setresgid(1, 1, 1)
        os.setresuid(1, 1, 1)
        _set(_SETID, _SETID, _SETID)
        # ...and into the ambient set, which is what survives an execve:
        # PR_CAP_AMBIENT=47, PR_CAP_AMBIENT_RAISE=2.
        for _cap in (CAP_SETUID, CAP_SETGID):
            assert ctypes.CDLL(None).prctl(47, 2, _cap, 0, 0) == 0

        before = capability_sets()
        assert before["CapAmb"] == _SETID, before
        become({uid}, {gid}, None)
        print(sorted(capability_sets().items()))
        """
    )
    assert completed.returncode == 0, completed.stderr
    after = dict(eval(completed.stdout))  # noqa: S307 -- our own repr, one line
    assert set(after) >= {"CapEff", "CapPrm", "CapInh", "CapAmb"}
    assert all(value == 0 for value in after.values()), after


# -- 6. Refusing to start on a run_as that cannot work ----------------------
#
# A container that holds no privilege starts, passes its healthcheck, looks
# entirely healthy, and fails every `run_as` call until somebody reads the
# log. GATEKEEPER_REQUIRE_RUN_AS turns that into a container that does not
# start. Opt-in: a toolkit may declare `run_as` for a call nobody makes, and
# aborting on that would break a deployment that is merely over-declared.


def _deployment(tmp_path, run_as: str = "3001:3001") -> str:
    """A config directory with one `run_as` toolkit, ready for `serve`."""
    config = os.path.join(str(tmp_path), "cfg")
    logs = os.path.join(str(tmp_path), "logs")
    os.makedirs(config)
    os.makedirs(logs)
    completed = subprocess.run(
        [sys.executable, "-m", "gatekeeper", "init"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": _SRC, "GATEKEEPER_CONFIG_DIR": config},
    )
    assert completed.returncode == 0, completed.stderr
    with open(os.path.join(config, "toolkits.yaml"), "w", encoding="utf-8") as handle:
        handle.write(
            f"audit:\n  dir: {logs}\ntoolkits:\n  agentcfg:\n"
            f"    executor: file\n    path_roots: [{tmp_path}]\n"
            f'    run_as: "{run_as}"\n'
            "    max_timeout_seconds: 15\n    max_output_bytes: 4096\n"
        )
    _traversable(str(tmp_path))
    for root, dirs, files in os.walk(str(tmp_path)):
        for entry in dirs + files:
            os.chmod(os.path.join(root, entry), 0o777)
    return config


def _serve_unprivileged(config: str, port: int, **env_extra) -> subprocess.CompletedProcess:
    """Starts `gatekeeper serve` as a user that cannot change user.

    Drops to `nobody` first when the suite runs as root, so the same test
    asserts the same thing on a hosted runner and in the root container job
    -- the point being what an *unprivileged* container does.
    """
    uid, gid = _nobody()
    launcher = textwrap.dedent(
        f"""
        import os, sys
        if os.geteuid() == 0:
            os.setresgid({gid}, {gid}, {gid})
            os.setresuid({uid}, {uid}, {uid})
        os.execv(sys.executable, [sys.executable, "-m", "gatekeeper", "serve"])
        """
    )
    return subprocess.run(
        [sys.executable, "-c", launcher],
        capture_output=True, text=True, timeout=25,
        env={
            **os.environ,
            "PYTHONPATH": _SRC,
            "GATEKEEPER_CONFIG_DIR": config,
            "GATEKEEPER_PORT": str(port),
            **env_extra,
        },
    )


def test_require_run_as_refuses_to_start_without_the_privilege(tmp_path):
    """The state this switch exists to remove: healthy-looking and broken."""
    completed = _serve_unprivileged(
        _deployment(tmp_path), 18131, GATEKEEPER_REQUIRE_RUN_AS="1"
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert "GATEKEEPER_REQUIRE_RUN_AS" in completed.stderr
    assert "cannot assume another user" in completed.stderr


def test_without_the_switch_an_unusable_run_as_still_starts(tmp_path):
    """The default, unchanged: it logs and serves.

    A deployment that declares `run_as` on a toolkit nobody calls must not
    be turned into a container that will not boot by an upgrade.
    """
    with pytest.raises(subprocess.TimeoutExpired):
        _serve_unprivileged(_deployment(tmp_path), 18132)


@pytest.mark.parametrize(
    "value, aborts",
    [("1", True), ("true", True), ("yes", True), ("0", False), ("", False)],
)
def test_the_switch_reads_the_usual_truthy_values(monkeypatch, value, aborts):
    from gatekeeper.__main__ import _require_run_as

    monkeypatch.setenv("GATEKEEPER_REQUIRE_RUN_AS", value)
    assert _require_run_as() is aborts


# -- 7. When root is not above file permissions ----------------------------
#
# The recommended container is `cap_drop: ALL` plus `cap_add: [SETUID,
# SETGID]`, which leaves uid 0 without CAP_DAC_OVERRIDE and
# CAP_DAC_READ_SEARCH. `run_as: root` is then checked against file modes
# like any other user -- so against a 0600 file owned by 568 it reaches
# *less* than 568 does. That reads as a bug in run_as and is not one, so
# the denial has to say it.

#: Drops everything but SETUID/SETGID from the bounding set, which is what
#: `cap_drop: ALL` + `cap_add` actually does. Restricting only the parent's
#: permitted set is not enough: on `execve` the kernel re-derives a root
#: child's permitted set from the bounding set, so the helper would get
#: CAP_DAC_OVERRIDE straight back.
_CAP_DROP_ALL = """
    import ctypes
    from gatekeeper._runas import CAP_SETGID, CAP_SETUID, capset

    _libc = ctypes.CDLL(None, use_errno=True)
    for _cap in range(0, 41):
        if _cap not in (CAP_SETGID, CAP_SETUID):
            _libc.prctl(24, _cap, 0, 0, 0)          # PR_CAPBSET_DROP
    _SETID = (1 << CAP_SETUID) | (1 << CAP_SETGID)
    capset(_SETID, _SETID, 0)
"""


@needs_root
def test_run_as_root_cannot_read_another_users_private_file(tmp_path):
    """The reported failure, reproduced: root, correct capabilities, and a

    plain "Permission denied" on a file owned by somebody else.
    """
    uid, gid = _nobody()
    root = _traversable(str(tmp_path))
    os.chmod(root, 0o755)
    secret = os.path.join(root, "compose.yaml")
    with open(secret, "w", encoding="utf-8") as handle:
        handle.write("services: {}\n")
    os.chown(secret, uid, gid)
    os.chmod(secret, 0o600)

    completed = _probe(
        _CAP_DROP_ALL,
        f"""
        import asyncio
        from gatekeeper.execute_file import run as file_run

        for target in ("root", "{uid}:{gid}"):
            result = asyncio.run(file_run(
                operation="read", path={secret!r}, path_roots=[{root!r}],
                protected=[], timeout_seconds=30, max_output_bytes=4096,
                idempotent=True, run_as=target,
            ))
            print(target, result.outcome, result.stderr.replace("\\n", " "))
        """,
    )
    assert completed.returncode == 0, completed.stderr
    as_root, as_owner = completed.stdout.splitlines()[:2]
    assert as_root.startswith("root failed"), as_root
    assert "Permission denied" in as_root
    # ...and the owning uid, which holds no capabilities at all, succeeds
    # where root did not. That inversion is the whole point.
    assert as_owner.startswith(f"{uid}:{gid} ok"), as_owner


@needs_root
def test_the_denial_names_the_uid_and_the_missing_capability(tmp_path):
    """What the bare message left out, and what sent the search in the

    wrong direction: which user actually performed the operation, and that
    uid 0 here is not above file permissions.
    """
    uid, gid = _nobody()
    root = _traversable(str(tmp_path))
    os.chmod(root, 0o755)
    secret = os.path.join(root, "compose.yaml")
    with open(secret, "w", encoding="utf-8") as handle:
        handle.write("services: {}\n")
    os.chown(secret, uid, gid)
    os.chmod(secret, 0o600)

    completed = _probe(
        _CAP_DROP_ALL,
        f"""
        import asyncio
        from gatekeeper.execute_file import run as file_run

        result = asyncio.run(file_run(
            operation="read", path={secret!r}, path_roots=[{root!r}],
            protected=[], timeout_seconds=30, max_output_bytes=4096,
            idempotent=True, run_as="root",
        ))
        print(result.stderr.replace("\\n", " "))
        """,
    )
    assert completed.returncode == 0, completed.stderr
    message = completed.stdout
    assert "ran as uid=0 gid=0" in message
    assert "run_as: 'root'" in message
    assert "NOT above file permissions" in message
    assert "CAP_DAC_OVERRIDE" in message


@needs_root
def test_a_denial_for_a_non_root_target_stays_an_ordinary_one(tmp_path):
    """No capability lecture where none applies: for a normal uid the

    answer is the file's mode or a directory above it, and the message
    should say that instead.
    """
    uid, gid = _nobody()
    root = _traversable(str(tmp_path))
    os.chmod(root, 0o755)
    locked = os.path.join(root, "root-only")
    os.makedirs(locked)
    os.chmod(locked, 0o700)
    target = os.path.join(locked, "x.txt")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("data")

    completed = _probe(
        f"""
        import asyncio
        from gatekeeper.execute_file import run as file_run

        result = asyncio.run(file_run(
            operation="read", path={target!r}, path_roots=[{root!r}],
            protected=[], timeout_seconds=30, max_output_bytes=4096,
            idempotent=True, run_as="{uid}:{gid}",
        ))
        print(result.stderr.replace("\\n", " "))
        """,
    )
    assert completed.returncode == 0, completed.stderr
    message = completed.stdout
    assert f"ran as uid={uid} gid={gid}" in message
    assert "traversable" in message
    assert "NOT above file permissions" not in message


@needs_linux
def test_bypasses_file_permissions_reports_the_real_set():
    from gatekeeper._runas import (
        CAP_DAC_OVERRIDE,
        CAP_DAC_READ_SEARCH,
        bypasses_file_permissions,
        effective_capabilities,
    )

    held = effective_capabilities()
    expected = bool(
        held & ((1 << CAP_DAC_OVERRIDE) | (1 << CAP_DAC_READ_SEARCH))
    )
    assert bypasses_file_permissions() is expected


# -- 6. Per-tool run_as through the service path ----------------------------
#
# The bug this section guards against: service.py:360 used toolkit.run_as
# unconditionally, ignoring a per-tool `run_as` in the tool spec. A tool
# that set `run_as: root` while its toolkit set `run_as: 568:568` would
# silently run write/patch as 568 -- read worked only by coincidence of
# the toolkit also setting root. Fixed in 0.36.0: the tool's run_as wins.

from gatekeeper.audit import AuditLog  # noqa: E402
from gatekeeper.catalog import load_catalog  # noqa: E402
from gatekeeper.identity import Identity, generate_token, hash_token  # noqa: E402
from gatekeeper.service import Service  # noqa: E402


def _service_env(tmp_path, toolkit_run_as=None):
    """A Service with a single `file` toolkit and one read+one write tool.

    The toolkit's run_as is `toolkit_run_as` (or None). Each tool has its
    own `run_as` in the spec -- the field under test. Returns the Service
    and the identity needed to call it.
    """
    toolkits_yaml = tmp_path / "toolkits.yaml"
    tk_spec = {"executor": "file", "path_roots": [str(tmp_path)]}
    if toolkit_run_as is not None:
        tk_spec["run_as"] = toolkit_run_as
    toolkits_yaml.write_text(
        yaml.safe_dump({"toolkits": {"files": tk_spec}, "audit": {"dir": str(tmp_path / "l")}}),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(toolkits_yaml))

    tools_yaml = tmp_path / "tools.yaml"
    tools = []
    for op, run_as in [("read", "root"), ("write", "root")]:
        tool_spec = {
            "id": f"files.{op}", "toolkit": "files", "category": "read" if op == "read" else "write",
            "file_operation": op, "enabled": True,
            "parameters": {"path": {"type": "string", "required": True}},
        }
        if run_as is not None:
            tool_spec["run_as"] = run_as
        tools.append(tool_spec)
    tools_yaml.write_text(yaml.safe_dump({"tools": tools}), encoding="utf-8")
    catalog = load_catalog(str(tools_yaml), tier1)

    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)

    token = generate_token()
    identity = Identity(
        id="agent", role="agent",
        token_hash=hash_token(token), token_lookup=hash_token(token)[:16],
        password_hash="", tools=["files.read", "files.write"], scopes=[],
    )
    return service, identity


def test_tool_run_as_wins_over_toolkit_run_as(tmp_path, monkeypatch):
    """The fix: service.py routes the tool's run_as to the executor, not
    the toolkit's. Asserted by intercepting the `run_as` argument that
    `execute_file.run` receives -- it must be the tool-level value, not
    the toolkit's.

    This test does not need root: it checks the wiring, not the privilege.
    The tool says `run_as: root`, the toolkit says `run_as: 568:568`. If
    the bug were still present, `run_as` would arrive as `568:568`; after
    the fix it arrives as `root`.
    """
    service, identity = _service_env(tmp_path, toolkit_run_as="568:568")

    captured: dict[str, str | None] = {}
    from gatekeeper import execute_file as _ef

    real_run = _ef.run

    async def spy_run(**kwargs):
        captured["run_as"] = kwargs.get("run_as")
        # Don't actually spawn the helper -- we only care about the
        # argument. Return a synthetic ok result.
        from gatekeeper.execute import Result, OUTCOME_OK
        return Result(
            outcome=OUTCOME_OK, exit_code=0, stdout="", stderr="",
            truncated=False, duration_ms=0,
        )

    monkeypatch.setattr(_ef, "run", spy_run)

    path = os.path.join(str(tmp_path), "x.txt")
    asyncio.run(service.call(identity, "files.read", {"path": path}))
    assert captured["run_as"] == "root", (
        f"tool-level run_as 'root' was not forwarded; got {captured['run_as']!r} "
        f"(this is the bug: service.py used toolkit.run_as instead of tool.run_as)"
    )

    asyncio.run(service.call(identity, "files.write", {"path": path, "content": "x"}))
    assert captured["run_as"] == "root", (
        f"write path dropped the per-tool run_as; got {captured['run_as']!r}"
    )


def test_tool_without_run_as_inherits_toolkit_run_as(tmp_path, monkeypatch):
    """A tool that does not set run_as inherits the toolkit's. This is
    the 'None means inherit' rule -- the default for every tool written
    before 0.36.0."""
    service, identity = _service_env(tmp_path, toolkit_run_as="3001:3001")

    # Override the tools to have no per-tool run_as.
    tier1 = service.tier1
    tools_yaml = tmp_path / "tools_no_runas.yaml"
    tools_yaml.write_text(
        yaml.safe_dump({"tools": [
            {"id": "files.read", "toolkit": "files", "category": "read",
             "file_operation": "read", "enabled": True,
             "parameters": {"path": {"type": "string", "required": True}}},
        ]}),
        encoding="utf-8",
    )
    catalog = load_catalog(str(tools_yaml), tier1)
    service.catalog = catalog

    captured: dict[str, str | None] = {}
    from gatekeeper import execute_file as _ef

    async def spy_run(**kwargs):
        captured["run_as"] = kwargs.get("run_as")
        from gatekeeper.execute import Result, OUTCOME_OK
        return Result(outcome=OUTCOME_OK, exit_code=0, stdout="", stderr="",
                       truncated=False, duration_ms=0)

    monkeypatch.setattr(_ef, "run", spy_run)

    path = os.path.join(str(tmp_path), "x.txt")
    asyncio.run(service.call(identity, "files.read", {"path": path}))
    assert captured["run_as"] == "3001:3001", (
        f"expected toolkit-level run_as '3001:3001'; got {captured['run_as']!r}"
    )


def test_tool_run_as_empty_string_clears_toolkit_run_as(tmp_path, monkeypatch):
    """An empty string run_as on the tool explicitly clears the toolkit's.

    The use case: a toolkit with `run_as: root` for write tools, and a
    read tool that does not need the privilege and should run as the
    container user instead."""
    service, identity = _service_env(tmp_path, toolkit_run_as="root")

    tier1 = service.tier1
    tools_yaml = tmp_path / "tools_clear_runas.yaml"
    tools_yaml.write_text(
        yaml.safe_dump({"tools": [
            {"id": "files.read", "toolkit": "files", "category": "read",
             "file_operation": "read", "enabled": True, "run_as": "",
             "parameters": {"path": {"type": "string", "required": True}}},
        ]}),
        encoding="utf-8",
    )
    catalog = load_catalog(str(tools_yaml), tier1)
    service.catalog = catalog

    captured: dict[str, str | None] = {}
    from gatekeeper import execute_file as _ef

    async def spy_run(**kwargs):
        captured["run_as"] = kwargs.get("run_as")
        from gatekeeper.execute import Result, OUTCOME_OK
        return Result(outcome=OUTCOME_OK, exit_code=0, stdout="", stderr="",
                       truncated=False, duration_ms=0)

    monkeypatch.setattr(_ef, "run", spy_run)

    path = os.path.join(str(tmp_path), "x.txt")
    asyncio.run(service.call(identity, "files.read", {"path": path}))
    assert captured["run_as"] is None, (
        f"empty-string run_as should clear to None; got {captured['run_as']!r}"
    )
