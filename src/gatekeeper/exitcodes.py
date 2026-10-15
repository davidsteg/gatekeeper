"""Benign exit-1 classification.

Some commands use exit status 1 to mean "no match" / "differs" / "false"
rather than "error": grep and friends, rg, diff, cmp, test and `[`. For
those, a failed outcome with exit code 1 and empty stderr is a normal
answer, not a failure.

Rules -- `benign_exit1()` returns True only if ALL hold:

- outcome is OUTCOME_FAILED,
- exit_code == 1,
- stderr is empty or whitespace-only,
- the inner command's basename is in BENIGN_EXIT1_COMMANDS.

The inner command is found like this:

- A `sh -c` / `bash -c` pair counts ONLY in two positions: as argv[0]
  itself (local/ssh executors), or as the first word after
  `docker exec <container>` (docker executor: binary `docker`, template
  `exec {container} sh -c {command}`). A bare `exec` as argv[0] is not
  the docker form -- it is whatever binary is called `exec` -- so it does
  not open a shell position. A `sh -c` pair anywhere else in
  argv is a parameter value and is ignored, so a tool with two adjacent
  free-text parameters cannot fake the shape.
- The string following `-c` is the command. If it contains any of
  ``;|&><`$(){}`` or a newline it is a pipeline/compound command whose
  exit status cannot be judged by name, so the result is False
  (conservative). Otherwise it is shlex-split (unbalanced quotes -> False)
  and its first token's basename is checked.
- Without such a shell position, argv[0]'s basename is checked.

Limitation: `grep a /x | wc -l` and similar pipelines are never benign,
even when the exit 1 came from grep -- we do not guess which stage failed.

Everything else stays a failure: Denied (never reaches here), timeouts
(exit_code None, outcome unknown or failed), exit codes >= 2, and any exit
1 with stderr output.

Audit and metrics: the service rewrites only the *outcome* of such a call
to `ok`, before metrics and audit are written. The audit entry therefore
reads `outcome=ok` with the real `exit_code=1`, and the agent still sees
`exit=1` in the rendered result. Calls reclassified this way can be found
in the audit as `outcome == "ok" and exit_code == 1`.
"""

from __future__ import annotations

import shlex

from .execute import OUTCOME_FAILED

BENIGN_EXIT1_COMMANDS = frozenset(
    {"grep", "egrep", "fgrep", "rg", "diff", "cmp", "test", "["}
)

_SHELLS = frozenset({"sh", "bash"})
_COMPOUND_CHARS = set(";|&><`$(){}\n")


def _basename(token: str) -> str:
    return token.rsplit("/", 1)[-1]


def _shell_position(argv: list[str]) -> int | None:
    """Index of `sh`/`bash` when the shell IS the command, else None.

    Accepted shapes: `sh -c ...` (index 0) and
    `docker exec <ctr> sh -c ...` (index 3). A bare `exec <ctr> sh -c`
    (argv[0] == "exec") is NOT accepted.
    """
    i = 0
    if argv and _basename(argv[0]) == "docker":
        if len(argv) < 2 or argv[1] != "exec":
            return None  # `docker <something other than exec>`
        i = 3  # skip `docker exec <container>`
    if i + 1 < len(argv) and _basename(argv[i]) in _SHELLS and argv[i + 1] == "-c":
        return i
    return None


def _inner_command(argv: list[str]) -> str | None:
    """Basename of the command that actually ran, or None if undecidable."""
    pos = _shell_position(argv)
    if pos is None:
        return _basename(argv[0]) if argv else None
    if pos + 2 >= len(argv):
        return None
    script = argv[pos + 2]
    if any(c in _COMPOUND_CHARS for c in script):
        return None
    try:
        tokens = shlex.split(script)
    except ValueError:
        return None
    return _basename(tokens[0]) if tokens else None


def benign_exit1(
    argv: list[str],
    stdout: str,
    stderr: str,
    exit_code: int | None,
    outcome: str,
) -> bool:
    """True if this failed result is a benign "no match"/"false" exit 1."""
    if outcome != OUTCOME_FAILED or exit_code != 1:
        return False
    if (stderr or "").strip():
        return False
    return _inner_command(list(argv)) in BENIGN_EXIT1_COMMANDS
