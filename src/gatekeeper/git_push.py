"""`git_push_feat`: push exactly one feature branch, never main.

Narrow push executor for the gatekeeper repo (Option A, Phase 2a). It is
the only place where the GitHub token leaves the credential store for a
git operation, and it keeps the token out of every channel an agent or
the audit can see:

- Token source: the credential slot `github` (Tier 2), resolved by the
  caller-supplied `resolve_credential(slot)`. A slot value stored with an
  HTTP scheme (`Bearer <t>` / `token <t>`) is accepted; the scheme is
  stripped.
- Token transport: environment variable `GK_PUSH_TOKEN` of the git child
  process only, read by a throwaway GIT_ASKPASS script in a private 0700
  temp dir. The script itself contains no secret; it is deleted after the
  call. The token is never in argv, never in a file, never in a log.
- Remote: fixed `REMOTE_URL` (not `origin` from .git/config).
- Refspec: exactly `refs/heads/<b>:refs/heads/<b>` for a branch matching
  `FEAT_BRANCH_RE` -- no `+` (force), no other ref, never main/master.
- Hooks off: `core.hooksPath=/dev/null` plus `--no-verify`; system and
  global git config are ignored (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL`).
- Output and error text are passed through `redact()` with the token (and
  the raw slot value) before they are returned.

Not wired into Tier 1/the service yet: the tool definition proposal lives
in docs/proposals/gkrepo-option-a.yaml.
"""

from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Iterable
from typing import Any

REMOTE_URL = "https://github.com/davidsteg/gatekeeper.git"
CREDENTIAL_SLOT = "github"
TOKEN_ENV = "GK_PUSH_TOKEN"
REDACTED = "***"

#: feat/<name>: lowercase a-z0-9._-, 1-60 chars, no '..', no '.lock'
#: suffix, must not start with '.'/'-' or end with '.'. No '/', '+', ':',
#: '@', whitespace -- so `main`, `+feat/x`, `feat/x:main` cannot match.
FEAT_BRANCH_RE = re.compile(
    r"^feat/(?![.-])(?!.*\.\.)(?!.*\.lock$)[a-z0-9._-]{1,60}(?<!\.)$"
)

_ASKPASS = """#!/bin/sh
case "$1" in
  Username*) echo x-access-token ;;
  *) printf '%s\\n' "$GK_PUSH_TOKEN" ;;
esac
"""

OUTCOME_OK = "ok"
OUTCOME_FAILED = "failed"
OUTCOME_UNKNOWN = "unknown"


class PushRefused(ValueError):
    """The request was refused before git ran (bad branch, empty slot)."""


@dataclasses.dataclass(frozen=True)
class PushResult:
    outcome: str
    exit_code: int | None
    output: str


def validate_branch(branch: str) -> str:
    if not isinstance(branch, str) or not FEAT_BRANCH_RE.fullmatch(branch):
        raise PushRefused("branch not allowed: only feat/<name> may be pushed")
    return branch


def build_argv(branch: str, *, repo: str, git: str = "/usr/bin/git") -> list[str]:
    b = validate_branch(branch)
    return [
        git, "-C", repo,
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
        "push", "--porcelain", "--no-verify",
        REMOTE_URL,
        f"refs/heads/{b}:refs/heads/{b}",
    ]


def _token_from_slot(value: str) -> str:
    parts = value.strip().split(None, 1)
    if parts and parts[0].lower() in ("bearer", "token"):
        return parts[1].strip() if len(parts) > 1 else ""
    return parts[0] if len(parts) == 1 else value.strip()


def redact(text: str, secrets: Iterable[str]) -> str:
    out = text or ""
    for s in sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True):
        out = out.replace(s, REDACTED)
    return out


def push_feat(
    branch: str,
    *,
    resolve_credential: Callable[[str], str | None],
    repo: str,
    git: str = "/usr/bin/git",
    timeout_seconds: float = 60,
    runner: Callable[..., Any] = subprocess.run,
) -> PushResult:
    argv = build_argv(branch, repo=repo, git=git)
    raw = resolve_credential(CREDENTIAL_SLOT) or ""
    token = _token_from_slot(raw)
    if not token:
        raise PushRefused(f"credential slot {CREDENTIAL_SLOT!r} is empty")
    secrets = (token, raw.strip(), raw)
    with tempfile.TemporaryDirectory(prefix="gk-push-") as tmp:
        os.chmod(tmp, 0o700)
        askpass = os.path.join(tmp, "askpass.sh")
        fd = os.open(askpass, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, "w") as fh:
            fh.write(_ASKPASS)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": tmp,
            "GIT_ASKPASS": askpass,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            TOKEN_ENV: token,
        }
        try:
            proc = runner(
                argv, env=env, cwd=tmp, capture_output=True, text=True,
                timeout=timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            partial = "".join(
                x.decode(errors="replace") if isinstance(x, bytes) else (x or "")
                for x in (exc.stdout, exc.stderr)
            )
            return PushResult(OUTCOME_UNKNOWN, None, redact(
                f"push timed out after {timeout_seconds}s; state unknown\n{partial}", secrets))
        except Exception as exc:  # noqa: BLE001 -- any failure text is redacted
            return PushResult(OUTCOME_FAILED, None, redact(
                f"push failed: {type(exc).__name__}: {exc}", secrets))
    output = redact((proc.stdout or "") + (proc.stderr or ""), secrets)
    rc = proc.returncode
    return PushResult(OUTCOME_OK if rc == 0 else OUTCOME_FAILED, rc, output)
