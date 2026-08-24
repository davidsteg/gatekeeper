"""Running one `file` operation as a different OS user (`run_as`).

The `file` executor (`execute_file.py`) is deliberately in-process: no
shell, no argv, no subprocess. That is also its one limitation -- it
touches the filesystem as whatever user gatekeeper itself runs as (568 in
the shipped image), so a directory the agent is legitimately meant to edit
but that is `drwx------ someoneelse` is simply unreachable.

`run_as` on a `file` toolkit closes that gap, and this module is the whole
of it. The shape of the problem dictates the shape of the solution: an
in-process executor cannot "become" another user for one call and change
back -- `seteuid` is process-wide, it would leak into every other coroutine
running concurrently, and it is reversible by construction, which is the
opposite of what a privilege boundary needs. So the operation moves into
its own short-lived process instead:

    parent (execute_file.run)          child (this module, `python -m`)
    ---------------------------        --------------------------------
    validate path against Tier 1
    spawn `sys.executable -m gatekeeper._runas`
    write request as JSON on stdin ->  resolve run_as -> uid/gid
                                       DROP PRIVILEGES, irreversibly
                                       re-validate path against Tier 1
                                       perform exactly one file operation
    <- read result as JSON on stdout   emit result, exit

Why this and not the alternatives:

- **A forked child without exec** would be cheaper, but `fork()` in a
  process that runs an asyncio loop (and, via the audit log, threads) is
  only safe up to `exec` -- a child that goes on to run Python can deadlock
  on a lock some other thread held at fork time. `fork`+`exec` has no such
  window.
- **A setuid-root helper binary** in the image would let gatekeeper stay
  unprivileged, but it is a permanently-privileged executable sitting on
  disk, reachable by anything inside the container. That is a strictly
  larger attack surface than a Python module that is only privileged
  because the process that spawned it already was.

Three properties this file exists to guarantee:

1. **The privilege drop is one-way.** Real and saved ids are set together
   (`setresuid`/`setresgid`), supplementary groups are replaced, every
   capability set is emptied, and all of it is verified -- including an
   explicit attempt to regain root that must fail. A child that cannot
   prove it dropped does not run the operation. The capability half is not
   redundant with the id half: leaving uid 0 makes the kernel clear the
   capability sets, but a change between two *non-root* uids does not, and
   a child that kept `CAP_SETUID` is one call away from being root again.
   The one set that cannot be emptied is the bounding set -- lowering it
   needs `CAP_SETPCAP`, which no deployment here grants -- so the child
   sets `no_new_privs` instead, which makes a full bounding set harmless
   by closing the `execve` route it would be reached through.
2. **It never silently falls back.** If the process is not privileged
   enough to become the requested user, the call fails with a message
   saying so. It does not quietly run as the container user, which would
   make `run_as` a suggestion rather than a boundary. What "privileged
   enough" means is `CAP_SETUID`/`CAP_SETGID` in the effective set, not
   uid 0 -- root whose capabilities were dropped cannot change user
   either, and a container told to add the capabilities while still
   running as 568 never receives them, because Docker grants them in uid
   0's permitted set alone.
3. **Tier 1 is checked on the privileged side too.** `path_roots` and
   `protected_resources` are re-validated *inside* the child, after the
   drop -- the same `_validate_path` the parent already ran. The parent's
   check is the real gate; this one is there so a future refactor cannot
   make the privileged half trust a path it did not check itself.

The agent never sees this module: `run_as` is a Tier 1 field on the
toolkit (deploy time, `toolkits.yaml`), there is no parameter and no tool
field through which a call can pick a user -- the same rule FR-8.3i states
for destinations.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

#: A `run_as` given as a name, resolved through the container's own
#: passwd database at call time. Deliberately narrow: this ends up in
#: `pwd.getpwnam`, and a name with a slash or a newline in it is a
#: configuration mistake, never a real account.
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?$")

#: A `run_as` given numerically, as `uid:gid`. Both halves are required --
#: a bare `3001` would leave the group to a passwd lookup that, for a uid
#: belonging to the *host* rather than the container image, does not exist.
#: `568:568` in `compose.yaml` is the same notation.
_IDS_RE = re.compile(r"^(\d{1,10}):(\d{1,10})$")


class RunAsError(ValueError):
    """A `run_as` value that cannot be parsed, resolved, or assumed."""


def parse_run_as(value: str) -> tuple[str | None, int | None, int | None]:
    """Splits a `run_as` value into `(name, uid, gid)`.

    Exactly one of the two forms comes back populated: a name (uid/gid
    `None`, resolved later against passwd) or a numeric pair (name `None`).
    Called at Tier 1 load time for the shape check and again in the child
    for the real resolution, so a malformed value fails at startup rather
    than on the first agent call.
    """
    text = str(value).strip()
    if not text:
        raise RunAsError("'run_as' must not be empty")

    ids = _IDS_RE.fullmatch(text)
    if ids is not None:
        uid, gid = int(ids.group(1)), int(ids.group(2))
        if uid > 0xFFFFFFFF or gid > 0xFFFFFFFF:
            raise RunAsError(f"'run_as' {text!r}: uid/gid out of range")
        return None, uid, gid

    if _NAME_RE.fullmatch(text):
        return text, None, None

    raise RunAsError(
        f"'run_as' {text!r} is neither a user name nor a 'uid:gid' pair "
        "(e.g. 'hermes' or '3001:3001'). A bare numeric uid is rejected on "
        "purpose -- the group would then depend on a passwd entry that a "
        "host uid does not have inside this image."
    )


def resolve_run_as(value: str) -> tuple[int, int, str | None]:
    """Turns a `run_as` value into the concrete `(uid, gid, name)` to assume.

    A name is looked up in the container's passwd database; the numeric
    form is taken as given. `name` comes back only for the passwd form,
    because it is what `os.initgroups` needs to find the account's
    supplementary groups -- there is no equivalent for a bare uid.
    """
    name, uid, gid = parse_run_as(value)
    if name is None:
        assert uid is not None and gid is not None
        return uid, gid, None

    import pwd

    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        raise RunAsError(
            f"'run_as' user {name!r} does not exist in this container's "
            "passwd database. Host accounts are not visible inside the "
            "image -- use the numeric 'uid:gid' form for those."
        ) from None
    return entry.pw_uid, entry.pw_gid, name


#: Capability bit numbers from `linux/capability.h`. Only the two this
#: module's drop actually needs -- there is no reason for it to know about
#: any other.
CAP_SETGID = 6
CAP_SETUID = 7

#: `_LINUX_CAPABILITY_VERSION_3`, the 64-bit capability ABI. The header it
#: comes from also fixes the shape of the two structs in
#: `_clear_capabilities`: a version+pid header, and *two* 32-bit data words,
#: because 64 capability bits do not fit in one.
_CAP_VERSION_3 = 0x20080522


#: The per-process capability sets, as `/proc/self/status` names them.
#: `CapBnd` is deliberately absent: the bounding set cannot be lowered
#: without `CAP_SETPCAP`, which the deployment does not grant and which it
#: would be a strange trade to grant *in order to* drop capabilities. What
#: makes a full bounding set harmless is `_set_no_new_privs`, not this.
_CAP_SETS = ("CapEff", "CapPrm", "CapInh", "CapAmb")


def capability_sets() -> dict[str, int] | None:
    """Every per-process capability set as a bitmask, or `None`.

    Read out of `/proc/self/status` rather than through `capget`: they are
    the same kernel-maintained sets, need no `ctypes`, and a machine
    without procfs (a non-Linux dev box) answers "unknown" instead of
    raising -- which is a different thing from "holds nothing", and the
    callers below treat it as such.

    All four rather than just the effective one, because the effective set
    is the least of the four for this purpose: a capability sitting in the
    permitted set can be made effective again at will, and one in the
    ambient set survives the next `execve`. Reporting only `CapEff` would
    call a process clean that is one `capset` away from not being.
    """
    found: dict[str, int] = {}
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            for line in handle:
                field, _, value = line.partition(":")
                if field in _CAP_SETS:
                    found[field] = int(value.strip(), 16)
    except (OSError, ValueError):
        return None
    return found or None


def effective_capabilities() -> int | None:
    """Just the effective set -- what a process can use *right now*."""
    sets = capability_sets()
    return None if sets is None else sets.get("CapEff")


def can_change_user() -> bool:
    """Whether this process can actually assume another uid/gid.

    The question `run_as` turns on, and the one a `geteuid() != 0` test
    gets wrong in both directions. On Linux the right to call
    `setresuid`/`setresgid` for an arbitrary target is `CAP_SETUID` /
    `CAP_SETGID` in the *effective* set, not uid 0: a root process whose
    capabilities were dropped (`cap_drop: ALL` with no matching `cap_add`)
    holds neither, and a non-root process granted them ambiently holds
    both. Only where the capability set cannot be read at all does uid 0
    remain the best available proxy.
    """
    caps = effective_capabilities()
    if caps is None:
        return os.geteuid() == 0
    return bool(caps & (1 << CAP_SETUID)) and bool(caps & (1 << CAP_SETGID))


def _clear_capabilities() -> None:
    """Empties the effective, permitted and inheritable capability sets.

    Needed only on the path where the process was *not* uid 0 to begin
    with. Dropping from root to a lesser uid makes the kernel clear the
    capability sets by itself; changing between two non-root uids does
    not, so a process holding ambient `CAP_SETUID` would come out of the
    drop still able to call `setuid(0)` -- the one thing `become` exists to
    prevent.

    Lowering one's own capabilities never requires a capability of its own,
    so this cannot fail for lack of privilege. The ambient set needs no
    separate call: the kernel keeps it a subset of the permitted set and
    empties it along with this one.
    """
    import ctypes

    class _Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class _Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    libc = ctypes.CDLL(None, use_errno=True)
    header = _Header(_CAP_VERSION_3, 0)
    data = (_Data * 2)()  # zeroed by construction: every set emptied
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), "capset")


#: `PR_SET_NO_NEW_PRIVS` (`linux/prctl.h`).
_PR_SET_NO_NEW_PRIVS = 38


def _set_no_new_privs() -> bool:
    """Forbids this process ever gaining privilege through `execve`.

    The half `_clear_capabilities` cannot reach. Emptying the effective,
    permitted, inheritable and ambient sets settles what this process
    holds; it settles nothing about the *bounding* set, which stays full
    because lowering it needs `CAP_SETPCAP` -- a capability the deployment
    deliberately does not grant. While the bounding set is full, a
    setuid-root binary or a file carrying capabilities remains a way back
    up for anything this process goes on to exec.

    `no_new_privs` closes that entire class, needs no privilege of its own,
    and cannot be undone once set. The container ordinarily sets it too
    (`no-new-privileges: true` in `compose.yaml`), but that is a line
    somebody can leave out of a hand-written deployment; this one cannot be
    left out. It costs nothing: the helper performs its file operation
    in-process and never execs anything.

    Defence in depth, not the boundary itself -- the boundary is the
    verified id drop and the emptied capability sets -- so a kernel that
    does not know the option is reported, not fatal.
    """
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        return bool(libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0)
    except (OSError, AttributeError, TypeError):
        return False


def _privilege_diagnosis(uid: int, gid: int) -> str:
    """The message for a process that cannot become `uid`/`gid`.

    Worth this much prose because the failure it reports is one an operator
    can hit *after* doing what a shorter version of it asked for. "Add
    CAP_SETUID and CAP_SETGID" is the wrong instruction for a container
    still running as 568: Docker puts `cap_add` entries in the permitted
    set of uid 0 only, so the capabilities are granted and simultaneously
    unusable, the message repeats itself unchanged after the redeploy, and
    the one thing that would fix it -- `user: "0:0"` -- is the half it
    never mentions. So: name which of the two is actually missing, and the
    command that shows it.
    """
    caps = effective_capabilities()
    where = f"gatekeeper runs as uid={os.geteuid()} gid={os.getegid()}" + (
        "" if caps is None else f" with CapEff={caps:016x}"
    )

    if caps is None:
        cause = (
            "This process is not uid 0 and its capability set cannot be read "
            "here, so it has no way to assume another user."
        )
    elif os.geteuid() != 0:
        cause = (
            "The container is not running as root, so the two capabilities "
            "cannot take effect even when 'cap_add' lists them -- Docker "
            "grants them in uid 0's permitted set only. The half missing "
            "here is 'user: \"0:0\"', not 'cap_add'."
        )
    else:
        cause = (
            "The container runs as root but holds neither capability, so "
            "'cap_drop: ALL' took effect and a matching "
            "'cap_add: [SETUID, SETGID]' did not."
        )

    return (
        f"cannot run this file operation as uid={uid} gid={gid}: {where} "
        f"and holds no privilege to change user. {cause} Both halves are "
        "needed together; check what the container actually got with:\n"
        "  docker inspect -f '{{.Config.User}} {{.HostConfig.CapAdd}}' gatekeeper\n"
        "  docker exec gatekeeper grep -E '^(Uid|CapEff):' /proc/self/status\n"
        "See docs/DEPLOYMENT.md."
    )


def _can_regain_root() -> bool:
    """Whether root is still reachable after the drop.

    The check that makes `setresuid` a boundary rather than a convenience:
    if the saved-set-user-id had been left at 0, this call would succeed
    and everything after it would run as root again.
    """
    try:
        os.setuid(0)
    except OSError:
        return False
    return True


def become(uid: int, gid: int, name: str | None) -> None:
    """Irreversibly assumes `uid`/`gid`, or raises.

    Never returns having assumed something *other* than what was asked
    for -- that is the whole point (property 2 in the module docstring).
    """
    if not can_change_user():
        # No privilege to become anybody. The only user this process can be
        # is the one it already is, and saying so plainly beats running the
        # operation as the container user and letting a "Permission denied"
        # three lines later imply the override was in effect.
        if (os.geteuid(), os.getegid()) != (uid, gid):
            raise RunAsError(_privilege_diagnosis(uid, gid))
        return

    try:
        # Supplementary groups first: both calls need the privilege that
        # setresuid below gives away. `initgroups` for a real account so it
        # keeps the groups it is actually in; an explicit empty set for the
        # numeric form, which drops whatever the container was started
        # with (`group_add: 999`, the docker socket's group, among them)
        # rather than carrying it into the operation.
        if name is not None:
            os.initgroups(name, gid)
        else:
            os.setgroups([])
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
    except OSError as exc:
        # Not a missing capability: `can_change_user` just confirmed both
        # are held. What is left is the target itself -- a gid the kernel
        # rejects, a name whose passwd entry moved between resolution and
        # here -- so the message points at `run_as`, not at the container.
        raise RunAsError(
            f"cannot run this file operation as uid={uid} gid={gid}: {exc}. "
            "The process holds CAP_SETUID and CAP_SETGID, so check the "
            "toolkit's 'run_as' value itself -- see docs/DEPLOYMENT.md."
        ) from None

    # Verify rather than assume. A partial drop is the failure mode worth
    # catching here: it looks like success from the call site and runs the
    # operation with more authority than the toolkit asked for.
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        raise RunAsError(
            f"privilege drop to uid={uid} gid={gid} did not take effect "
            f"(now uid={os.getresuid()} gid={os.getresgid()})"
        )
    if uid != 0:
        # The ids are right; the capabilities need not be. Leaving uid 0
        # clears them, but a process that held them ambiently while already
        # unprivileged keeps every one across a non-root-to-non-root change
        # -- CAP_SETUID among them, which is `setuid(0)` and the boundary
        # gone. Clear them outright rather than depending on which of the
        # two paths arrived here.
        try:
            _clear_capabilities()
        except (OSError, AttributeError, TypeError) as exc:
            # Not fatal by itself: what decides is whether anything was
            # actually left behind, which the check below asks directly.
            if any((capability_sets() or {}).values()):
                raise RunAsError(
                    f"privilege drop to uid={uid} could not clear the "
                    f"capability sets ({exc}) -- refusing to run the operation"
                ) from None
        # Every set, not just the effective one. Zeroing the permitted and
        # inheritable sets is what empties the ambient set as a side effect
        # (the kernel keeps ambient a subset of both), and that is a kernel
        # invariant this module relies on -- so it asks, rather than
        # assuming it held.
        remaining = {
            field: value
            for field, value in (capability_sets() or {}).items()
            if value
        }
        if remaining:
            listed = ", ".join(f"{f}={v:016x}" for f, v in sorted(remaining.items()))
            raise RunAsError(
                f"privilege drop to uid={uid} left capabilities behind "
                f"({listed}) -- refusing to run the operation"
            )
        if _can_regain_root():
            raise RunAsError(
                f"privilege drop to uid={uid} left root regainable -- refusing "
                "to run the operation"
            )


def _fail(message: str) -> dict[str, Any]:
    return {
        "outcome": "failed",
        "exit_code": 1,
        "stdout": "",
        "stderr": message,
        "truncated": False,
    }


def _main() -> int:
    """Child entry point: one request on stdin, one result on stdout.

    The request travels over stdin rather than argv on purpose. argv is
    world-readable through `/proc/<pid>/cmdline` for the duration of the
    call, and a `file.write` request carries the file's entire content --
    which is exactly the kind of thing that must not become visible to
    anything else on the box just because it was being written.

    Always exits 0 with a JSON result, including on failure: the parent
    then has one shape to parse instead of two, and a non-zero exit means
    something genuinely unexpected (a crash before this ran) rather than
    an ordinary "file not found".
    """
    # Before anything else, the request included: from here on this
    # process cannot gain privilege through `execve`, whatever it goes on
    # to do. See `_set_no_new_privs` for why that is not already covered by
    # emptying the capability sets.
    _set_no_new_privs()

    try:
        request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        if not isinstance(request, dict):
            raise ValueError("request must be a JSON object")
    except (ValueError, UnicodeDecodeError) as exc:
        sys.stdout.write(json.dumps(_fail(f"malformed run_as request: {exc}")))
        return 0

    try:
        uid, gid, name = resolve_run_as(str(request["run_as"]))
        become(uid, gid, name)
    except (RunAsError, KeyError) as exc:
        sys.stdout.write(json.dumps(_fail(str(exc))))
        return 0

    # Imported only now, and only in the child: keeps `tier1.py`'s import of
    # `parse_run_as` above from dragging the executor in, and keeps every
    # line below this point running as the dropped-to user.
    from .execute_file import perform, validate_path

    try:
        path = validate_path(
            str(request["path"]),
            list(request.get("path_roots") or []),
            list(request.get("protected") or []),
        )
        outcome, exit_code, stdout, stderr, truncated = perform(
            operation=str(request["operation"]),
            path=path,
            content=request.get("content"),
            old_string=request.get("old_string"),
            new_string=request.get("new_string"),
            max_output_bytes=int(request["max_output_bytes"]),
        )
    except Exception as exc:  # noqa: BLE001 -- reported, never swallowed
        sys.stdout.write(json.dumps(_fail(str(exc))))
        return 0

    sys.stdout.write(
        json.dumps(
            {
                "outcome": outcome,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "truncated": truncated,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(_main())
