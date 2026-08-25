"""Giving up root at startup while keeping the capabilities `run_as` needs.

The third shape of the same trade, and the only one that is process-wide.
`_runas.py` raises a child's authority for one file operation; `_unpriv.py`
lowers a spawned binary's; this module decides what the *server itself* is
for its whole life.

The problem it solves is that `run_as` needs `CAP_SETUID`/`CAP_SETGID`, and
Docker grants capabilities to uid 0 alone. That left two deployments, both
unattractive:

- `user: "568:568"` — unprivileged, and `run_as` cannot work at all.
- `user: "0:0"` + `cap_add` — `run_as` works, and every file the server
  writes is root-owned, every bug is a root bug, and the whole process
  spends its life at uid 0 to serve calls that need the privilege for
  milliseconds.

This module is the third: the container starts at `user: "0:0"` with
`cap_add: [SETUID, SETGID]`, and gatekeeper immediately becomes 568 *itself*
while keeping exactly those two capabilities. Config files, the audit log
and everything a `file` toolkit writes without `run_as` come out owned by
568, as they always did; `run_as` still works, because the capability is
what the kernel checks, not the uid (see `_runas.can_change_user`).

How, in order, and why each step is not optional:

1. `PR_SET_KEEPCAPS(1)` — without it the kernel empties the permitted set
   the moment euid leaves 0, and there is nothing left to keep.
2. Supplementary groups, then `setresgid`, then `setresuid` — groups first
   because both need the privilege `setresuid` gives away.
3. `capset` back to the kept set — the uid change preserves *permitted*
   under KEEPCAPS but still clears *effective*, so without this the
   process holds the capabilities and cannot use them. Setting
   inheritable at the same time is what makes step 4 legal.
4. `PR_CAP_AMBIENT_RAISE` for each kept capability — the step that
   actually matters, and the one an implementation gets wrong silently. The
   `run_as` helper is a *separate process*, reached by `fork`+`exec`. On
   `execve` of an ordinary file the kernel computes the new permitted set
   from the file's own capabilities, which are none — so a child of a
   non-root parent inherits nothing from permitted or inheritable. The
   ambient set is the only set that survives an `execve`, and therefore the
   only way the helper ever sees the capability its whole existence depends
   on.

`no-new-privileges: true` stays on and does not conflict: it governs what
`execve` may *grant* from a file, and the ambient set is not a grant from a
file. Verified rather than reasoned about -- a test execs a plain binary
under `no_new_privs` and reads the capabilities back out of its
`/proc/self/status`.

**What this costs, stated plainly.** A process holding `CAP_SETUID` can
call `setuid(0)` whenever it likes. Running as 568-with-CAP_SETUID is
therefore *not* a privilege boundary against a compromised gatekeeper --
against an attacker with code execution in this process it is worth about
what `user: "0:0"` is worth. What it does buy is real but narrower: file
ownership (nothing the server writes lands root-owned), a smaller blast
radius for the ordinary bugs that are not code execution, and a capability
set of exactly two entries instead of root's full complement. Deploy it for
those reasons, not in the belief that it contains a hostile process.

**Keeping extra capabilities (`GATEKEEPER_KEEP_CAPS`).** The default keeps
exactly `CAP_SETUID` and `CAP_SETGID` -- the minimum for `run_as` to work.
A deployment that grants more through `cap_add` (commonly
`CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`, so a `run_as: root` child
can read files owned by other users) would otherwise see those capabilities
silently discarded by step 3. `GATEKEEPER_KEEP_CAPS` names the extra
capabilities to carry through the drop, in the same notation Docker's
`cap_add` uses (``DAC_OVERRIDE,DAC_READ_SEARCH``; a ``CAP_`` prefix is
accepted too). The extras are kept in the *permitted*, *inheritable* and
*ambient* sets but not the *effective* set: the server process itself
cannot use them, but the `run_as` child inherits them via the ambient set
on `execve`. This is the narrowest split that lets a privileged child read
files without the server itself being able to -- which is the point, since
the server runs the whole time and the child lives for one operation.

Off unless configured. `GATEKEEPER_DROP_TO` names the target; without it
this module does nothing at all, which is what keeps `gatekeeper serve` on
a bare host from suddenly trying to become a uid that does not exist there.
"""

from __future__ import annotations

import os

from ._runas import (
    CAP_SETGID,
    CAP_SETUID,
    CAPABILITY_NAMES,
    RunAsError,
    capability_sets,
    capset,
    resolve_run_as,
)

#: The environment variable that turns this on, and the whole interface.
#: Takes the same notation `run_as` does -- a name from the container's
#: passwd database, or a `uid:gid` pair -- because it is the same question
#: asked about a different process, and two spellings for one idea is one
#: too many.
DROP_TO_ENV = "GATEKEEPER_DROP_TO"

#: Extra capabilities to keep across the drop, beyond the mandatory two.
#: Comma-separated, in Docker `cap_add` notation (``DAC_OVERRIDE``) with or
#: without the ``CAP_`` prefix. Empty/unset = keep only SETUID+SETGID.
KEEP_CAPS_ENV = "GATEKEEPER_KEEP_CAPS"

#: `linux/prctl.h`.
_PR_SET_KEEPCAPS = 8
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_RAISE = 2

#: The two capabilities the drop always keeps -- `run_as` cannot work
#: without them. Everything in `_KEPT_EXTRA` is *in addition to* these.
_BASE_KEPT = (1 << CAP_SETUID) | (1 << CAP_SETGID)


class SelfDropError(RuntimeError):
    """The configured drop could not be performed, so startup must not continue."""


def configured_target() -> str | None:
    """The `GATEKEEPER_DROP_TO` value, or `None` when unset."""
    return os.environ.get(DROP_TO_ENV, "").strip() or None


def _parse_capability_name(token: str) -> int:
    """One token from `GATEKEEPER_KEEP_CAPS` -> capability bit number.

    Accepts both ``DAC_OVERRIDE`` (Docker notation) and ``CAP_DAC_OVERRIDE``
    (kernel notation). The capability must be one this codebase knows
    about -- an unknown name is a configuration error, not a silent skip,
    because the operator typed it for a reason and carrying on without the
    capability they asked for would produce the exact "looks like a bug"
    failure this module exists to make legible.
    """
    name = token.strip().upper()
    if name.startswith("CAP_"):
        name = name[4:]
    if name not in CAPABILITY_NAMES:
        raise SelfDropError(
            f"{KEEP_CAPS_ENV}={token!r}: unknown capability {name!r}. "
            f"Known: {', '.join(sorted(CAPABILITY_NAMES))} (with or without "
            "the 'CAP_' prefix)."
        )
    return CAPABILITY_NAMES[name]


def configured_extra_caps() -> int:
    """The extra capability bitmask from `GATEKEEPER_KEEP_CAPS`, or 0.

    Raises `SelfDropError` on an unknown capability name -- see
    `_parse_capability_name` for why an unknown is not silently ignored.
    """
    raw = os.environ.get(KEEP_CAPS_ENV, "").strip()
    if not raw:
        return 0
    bits = 0
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        bits |= 1 << _parse_capability_name(token)
    return bits


def _kept_groups() -> list[int]:
    """The supplementary groups to carry across the drop.

    Whatever the container was started with, minus root's own group. This
    is where `_selfdrop` deliberately parts company with `_runas.become`,
    which empties the set outright: there the drop *is* a privilege
    boundary for one operation, and carrying the server's groups into it
    would widen exactly what the boundary narrows. Here the drop means
    "become the unprivileged version of myself", and the groups came from
    `group_add:` in the deployment -- deliberate configuration, not
    privilege that happens to be lying around.

    Emptying it silently breaks the obvious case: `group_add: "999"` is how
    the container reaches `/var/run/docker.sock`, so a drop that discarded
    it would leave every `docker` toolkit failing with EACCES, and nothing
    would say why.

    Group 0 is filtered out. It is there because the container started as
    `user: "0:0"`, not because anyone asked for it, and a process that has
    just given up root has no business keeping read access to every
    root-group file on the way out.
    """
    return sorted({group for group in os.getgroups() if group != 0})


def _prctl(*args: int) -> None:
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(*args) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), f"prctl{args}")


def drop_privileges(value: str) -> tuple[int, int]:
    """Becomes `value`, keeping `CAP_SETUID`/`CAP_SETGID` plus any extras.

    Returns `(uid, gid)`. Raises rather than returning a process that is
    still root: a startup that was told to give up privilege and did not
    must not go on to serve requests as though it had. The caller aborts.

    Extra capabilities (from `GATEKEEPER_KEEP_CAPS`) are kept in the
    permitted, inheritable and ambient sets but *not* the effective set.
    The server process itself cannot use them -- only the `run_as` child
    can, after inheriting them via the ambient set on `execve`.
    """
    try:
        # The name, if there was one, is not needed: the supplementary
        # groups come from what the container was started with rather than
        # from the account's own entry -- see `_kept_groups`.
        uid, gid, _ = resolve_run_as(value)
    except RunAsError as exc:
        raise SelfDropError(f"{DROP_TO_ENV}: {exc}") from None

    if uid == 0:
        raise SelfDropError(
            f"{DROP_TO_ENV}={value!r} resolves to uid 0. This setting exists to "
            "give up root, so root is the one value it cannot take."
        )

    extra = configured_extra_caps()

    if os.geteuid() != 0:
        # Already unprivileged: nothing to give up, and nothing to keep --
        # a non-root process cannot conjure CAP_SETUID for itself. Report
        # the mismatch rather than pretending the drop happened.
        if (os.geteuid(), os.getegid()) != (uid, gid):
            raise SelfDropError(
                f"{DROP_TO_ENV}={value!r} asks this process to become "
                f"uid={uid} gid={gid}, but it is already running unprivileged "
                f"as uid={os.geteuid()} gid={os.getegid()} and cannot change "
                "user. Start the container as root ('user: \"0:0\"' with "
                "'cap_add: [SETUID, SETGID]') for this setting to mean "
                "anything -- see docs/DEPLOYMENT.md."
            )
        return uid, gid

    # What the drop keeps: the base two (always) plus any extras (if
    # configured). The extras are in all three sets the kernel checks for
    # the ambient raise, but only effective is the one that lets the
    # *server* use the capability -- and that one stays at the base two.
    # A `run_as` child inherits the extras from ambient on execve and gets
    # them in its effective set for free, which is the whole point.
    kept = _BASE_KEPT | extra

    try:
        # 1. Without this the capabilities are gone the instant euid != 0.
        _prctl(_PR_SET_KEEPCAPS, 1, 0, 0, 0)

        # 2. Groups before ids: setting them needs what setresuid gives away.
        os.setgroups(_kept_groups())
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)

        # 3. KEEPCAPS preserved *permitted*; effective was cleared anyway.
        #    Inheritable is set here because the ambient raise below is only
        #    legal for a capability that is in both permitted and inheritable.
        #    Effective is the *base* two only: the server itself can change
        #    user (the point of run_as) but cannot use DAC_OVERRIDE etc.
        #    directly. The child gets the extras from ambient on execve.
        capset(_BASE_KEPT, kept, kept)

        # 4. The only set that survives the helper's execve. Every kept
        #    capability goes into ambient, not only the base two: the
        #    extras are what `run_as: root` needs to read files owned by
        #    other users, and they only reach the child through this set.
        for bit in range(64):
            if kept & (1 << bit):
                _prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_RAISE, bit, 0, 0)

        # Tidy: the flag has done its work, and leaving it on would keep
        # capabilities across any *further* uid change, which nothing here
        # intends to make.
        _prctl(_PR_SET_KEEPCAPS, 0, 0, 0, 0)
    except OSError as exc:
        raise SelfDropError(
            f"cannot drop to uid={uid} gid={gid}: {exc}. The container must "
            "start as root with CAP_SETUID and CAP_SETGID for this "
            "('user: \"0:0\"' plus 'cap_add: [SETUID, SETGID]'); root alone "
            "is not enough, because 'cap_drop: ALL' without a matching "
            "'cap_add' leaves even root unable to change user. See "
            "docs/DEPLOYMENT.md."
        ) from None

    _verify(uid, gid, extra)
    return uid, gid


def _verify(uid: int, gid: int, extra: int) -> None:
    """Confirms the drop landed, in both directions.

    A partial result here is the failure worth catching: ids changed but
    capabilities gone is a server that will fail every `run_as` call, and
    capabilities kept but ids unchanged is a server still running as root
    while its log says otherwise. Neither announces itself.
    """
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        raise SelfDropError(
            f"drop to uid={uid} gid={gid} did not take effect "
            f"(now uid={os.getresuid()} gid={os.getresgid()})"
        )

    held = capability_sets()
    if held is None:
        # No procfs to check against. The ids are right and the calls all
        # returned success; say what could not be confirmed rather than
        # failing a startup that is probably fine.
        return

    kept = _BASE_KEPT | extra

    # Effective: the base two only. The server process itself must not hold
    # the extras here -- that is the split that keeps DAC_OVERRIDE out of
    # the server and in the child.
    cap_eff = held.get("CapEff")
    if cap_eff != _BASE_KEPT:
        raise SelfDropError(
            f"drop to uid={uid} kept the wrong effective capabilities: "
            f"CapEff={cap_eff if cap_eff is None else format(cap_eff, '016x')}, "
            f"expected {_BASE_KEPT:016x} (CAP_SETUID + CAP_SETGID only). "
            "The server itself must not hold extra capabilities -- only the "
            "run_as child should, via the ambient set. See "
            "docs/DEPLOYMENT.md."
        )

    # Permitted, inheritable and ambient: the full kept set, extras
    # included. This is what the child inherits.
    for field in ("CapPrm", "CapInh", "CapAmb"):
        value = held.get(field)
        if value != kept:
            raise SelfDropError(
                f"drop to uid={uid} kept the wrong capabilities: "
                f"{field}={value if value is None else format(value, '016x')}, "
                f"expected {kept:016x} (CAP_SETUID + CAP_SETGID"
                + (f" + {KEEP_CAPS_ENV}" if extra else "")
                + "). 'run_as' would not work, and the process is no longer "
                "root either -- refusing to start in that state."
            )


def discard_capabilities() -> None:
    """Gives up all capabilities after all, for a config that needs none.

    Called once Tier 1 is loaded and turns out to declare no `run_as`
    anywhere. The drop has to happen before any file is written, which is
    before the configuration is read, so the capabilities are kept on the
    chance they are needed and handed back the moment it is clear they are
    not. Cheap, and it leaves the common case holding nothing.

    Discards extras too: if `GATEKEEPER_KEEP_CAPS` was set but no toolkit
    uses `run_as`, the extras were never needed. A future toolkit that
    adds `run_as` would re-add the base two on the next start; the extras
    would need `GATEKEEPER_KEEP_CAPS` again, which is the deploy-time gate.
    """
    capset(0, 0, 0)