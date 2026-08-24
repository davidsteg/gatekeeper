"""Running a `local` binary without the capabilities this process inherited.

The mirror image of `_runas.py`. That module exists so one `file`
operation can run with *more* authority than gatekeeper itself; this one
exists so a `local` toolkit's binary runs with *less* -- with none of the
ambient capabilities gatekeeper may have been started with.

Only one deployment needs it, and that is the point. Where the container
starts as root and is handed CAP_SETUID/CAP_SETGID through `cap_add`, the
capabilities live in uid 0's permitted set, no child inherits them, and
`execute.run` spawns binaries exactly as it always did -- this module is
never reached. But a deployment that keeps the two capabilities across its
own drop to an unprivileged user (a `setpriv`/`gosu` wrapper, see
docs/DEPLOYMENT.md) necessarily holds them in the *ambient* set, and the
ambient set is inherited by every `execve`, not only the one that needs
it. `docker`, `df`, `free` and `cat` would each run holding CAP_SETUID,
which is one call away from being root -- none of them has any use for it.

Why a separate process rather than a `preexec_fn`: that hook runs between
`fork` and `exec` in a process that runs an asyncio loop and, through the
audit log, threads. It is the exact window `_runas.py` uses `fork`+`exec`
to stay out of, because a child that runs Python there can deadlock on a
lock some other thread held at fork time. Clearing capabilities from a
`preexec_fn` would buy this safety by reintroducing that hazard. This
module is already past the window: it is an ordinary process that empties
its own capability sets and then `execve`s the real binary over itself.

Why `execv` and not a child: the binary *replaces* this process and keeps
the pid `execute.run` is holding. The timeout, the process-group kill and
the output streaming therefore behave exactly as they do without the
wrapper -- there is no extra process to reap, and no second pid to lose
track of when a call has to be killed.

The one thing this module must never do is run the binary anyway. Failing
to drop is reported and refused, because a `docker` that silently kept
CAP_SETUID looks identical to a successful call from the outside.
"""

from __future__ import annotations

import os
import sys

from ._runas import _clear_capabilities, capability_sets

#: Prefix for anything this module reports on stderr. Only ever reachable
#: when `execv` did not happen: a successful exec replaces this process, so
#: nothing it might have written can still be pending afterwards. That is
#: what lets `execute.run` treat a line starting with this as its own and
#: turn it back into the `Denied` an unwrapped spawn would have raised.
MARKER = "gatekeeper._unpriv: "

#: Shell convention, reserved here for the same two meanings, so the exit
#: code alone already distinguishes "no such binary" from "cannot run it".
EXIT_NOT_EXECUTABLE = 126
EXIT_NOT_FOUND = 127


def _main(argv: list[str]) -> int:
    """Clears the inherited capabilities, then becomes `argv`."""
    if not argv:
        sys.stderr.write(f"{MARKER}no command given\n")
        return EXIT_NOT_FOUND

    try:
        _clear_capabilities()
    except (OSError, AttributeError, TypeError) as exc:
        sys.stderr.write(f"{MARKER}cannot drop inherited capabilities: {exc}\n")
        return EXIT_NOT_EXECUTABLE

    # Verify rather than assume, for the same reason `become` does: a
    # binary that ran with the capabilities still on is indistinguishable
    # from one that ran correctly, right up until it matters.
    remaining = {
        field: value for field, value in (capability_sets() or {}).items() if value
    }
    if remaining:
        listed = ", ".join(f"{f}={v:016x}" for f, v in sorted(remaining.items()))
        sys.stderr.write(f"{MARKER}capabilities survived the drop ({listed})\n")
        return EXIT_NOT_EXECUTABLE

    try:
        # execv, not execvp: gatekeeper resolves no binary through PATH
        # (FR-4.1) -- toolkits.yaml names absolute paths, and a wrapper that
        # quietly searched PATH would be a way around that allowlist.
        os.execv(argv[0], argv)
    except FileNotFoundError:
        sys.stderr.write(f"{MARKER}not found\n")
        return EXIT_NOT_FOUND
    except PermissionError:
        sys.stderr.write(f"{MARKER}no permission\n")
        return EXIT_NOT_EXECUTABLE
    except OSError as exc:
        sys.stderr.write(f"{MARKER}cannot execute: {exc}\n")
        return EXIT_NOT_EXECUTABLE
    return EXIT_NOT_EXECUTABLE  # unreachable: a successful execv never returns


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
