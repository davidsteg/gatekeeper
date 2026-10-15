"""`git_push_feat`: push exactly one feature branch, never main.

Narrow push executor for the gatekeeper repo (Option A, Phase 2a). It is
the only place where the GitHub token leaves the credential store for a
git operation, and it keeps the token out of every channel an agent or
the audit can see:

- Token source: the credential slot `github` (Tier 2), resolved by the
  caller-supplied `resolve_credential(slot)`. Accepted slot values are
  exactly `<token>`, `Bearer <token>` and `token <token>` (scheme
  case-insensitive); the token must match `TOKEN_RE`. Any other shape
  (unknown scheme such as `Basic x`, three or more words) is refused
  instead of guessing which word is the secret. Errors never echo it.
- Token transport: environment variable `GK_PUSH_TOKEN` of the `git push`
  child only, read by a throwaway GIT_ASKPASS script in a private 0700
  temp dir. The script holds no secret; it is deleted after the call.
  The token is never in argv, never in a file, never in a log.
- Refspec: exactly `refs/heads/<b>:refs/heads/<b>` for a branch matching
  `FEAT_BRANCH_RE` -- no `+` (force), no other ref, never main/master.
- Output and error text are passed through `redact()` with the token (and
  the raw slot value) before they are returned.

Config isolation -- why the push never runs inside the source repo: its
`.git/config` (and whatever that `include`s) is writable by anyone who can
write into the repo. `url.<x>.insteadOf` / `pushInsteadOf`, `http.*`,
`credential.*` or `core.sshCommand` there would redirect the push, and
the token with it. So the token never meets that config:

1. Without the token: a fresh bare GIT_DIR is created in the private temp
   dir (`git init --bare --template=`), and only the branch is fetched
   into it from the source repo (local fetch; file protocol allowed for
   this step only, every other protocol off).
2. The effective config of that GIT_DIR is listed (`git config --list
   --show-origin --name-only`). It must consist of the core keys `git
   init` writes, from the GIT_DIR's own config file; anything else
   (url.*, include*, http.*, credential.*, core.sshCommand,
   core.hooksPath, remote.*, ...) refuses the push before the token is
   read into any child environment.
3. `git push` runs against that GIT_DIR with `protocol.allow=never` +
   `protocol.https.allow=always`, `http.followRedirects=false`, hooks off
   (`core.hooksPath=/dev/null`, `--no-verify`), no credential helper, and
   the fixed `REMOTE_URL` as URL argument (no named remote).

Every step runs with an environment built from scratch: system and
global config off (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_SYSTEM`/
`GIT_CONFIG_GLOBAL=/dev/null`, `HOME`/`XDG_CONFIG_HOME` = temp dir), and
no parent `GIT_CONFIG_COUNT`/`GIT_CONFIG_*`/`GIT_CONFIG_PARAMETERS`/
`GIT_DIR` reaches git.

Not wired into Tier 1/the service yet: the tool definition proposal and
the wiring notes (git binary, noexec /tmp) live in
docs/proposals/gkrepo-option-a.yaml.
"""

from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import tempfile
import time
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

#: GitHub token charset (classic `ghp_...`, fine-grained `github_pat_...`).
#: Also keeps newlines and shell metacharacters out of the askpass answer.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_]{20,255}$")
_SCHEMES = frozenset({"bearer", "token"})

#: The only keys the effective config of the push GIT_DIR may contain:
#: what `git init --bare` writes into a fresh config file.
ALLOWED_CONFIG_KEYS = frozenset({
    "core.repositoryformatversion", "core.filemode", "core.bare",
    "core.logallrefupdates", "core.ignorecase", "core.precomposeunicode",
    "core.symlinks", "extensions.objectformat", "extensions.refstorage",
})

_ASKPASS = """#!/bin/sh
case "$1" in
  Username*) echo x-access-token ;;
  *) printf '%s\\n' "$GK_PUSH_TOKEN" ;;
esac
"""

#: Applied to every git call: no hooks, no credential helper, no protocol
#: unless a step explicitly allows exactly one.
_HARDEN = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "-c", "protocol.allow=never",
)

OUTCOME_OK = "ok"
OUTCOME_FAILED = "failed"
OUTCOME_UNKNOWN = "unknown"


class PushRefused(ValueError):
    """The push was refused before the token reached git."""


@dataclasses.dataclass(frozen=True)
class PushResult:
    outcome: str
    exit_code: int | None
    output: str


def validate_branch(branch: str) -> str:
    if not isinstance(branch, str) or not FEAT_BRANCH_RE.fullmatch(branch):
        raise PushRefused("branch not allowed: only feat/<name> may be pushed")
    return branch


def token_from_slot(value: str | None) -> str:
    """The token from the slot value; see the module docstring for the forms."""
    parts = (value or "").split()
    if not parts or (len(parts) == 1 and parts[0].lower() in _SCHEMES):
        raise PushRefused(f"credential slot {CREDENTIAL_SLOT!r} is empty")
    if len(parts) == 1:
        token = parts[0]
    elif len(parts) == 2 and parts[0].lower() in _SCHEMES:
        token = parts[1]
    else:
        raise PushRefused(
            f"credential slot {CREDENTIAL_SLOT!r} has an unsupported format "
            "(expected '<token>', 'Bearer <token>' or 'token <token>')"
        )
    if not TOKEN_RE.fullmatch(token):
        raise PushRefused(
            f"credential slot {CREDENTIAL_SLOT!r} does not hold a GitHub token "
            "(A-Za-z0-9_, 20-255 chars)"
        )
    return token


def init_argv(git_dir: str, *, git: str = "/usr/bin/git") -> list[str]:
    return [git, *_HARDEN, "init", "--quiet", "--bare", "--template=", git_dir]


def fetch_argv(branch: str, *, repo: str, git_dir: str, git: str = "/usr/bin/git") -> list[str]:
    b = validate_branch(branch)
    return [
        git, "--git-dir", git_dir, *_HARDEN,
        "-c", "protocol.file.allow=always",
        "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules",
        "--", repo, f"refs/heads/{b}:refs/heads/{b}",
    ]


def config_argv(git_dir: str, *, git: str = "/usr/bin/git") -> list[str]:
    return [git, "--git-dir", git_dir, "config", "--list", "--show-origin", "--name-only"]


def build_argv(branch: str, *, git_dir: str, git: str = "/usr/bin/git") -> list[str]:
    b = validate_branch(branch)
    return [
        git, "--git-dir", git_dir, *_HARDEN,
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
        "push", "--porcelain", "--no-verify",
        REMOTE_URL,
        f"refs/heads/{b}:refs/heads/{b}",
    ]


def unexpected_config(listing: str, git_dir: str) -> list[str]:
    """Keys in `listing` that are not allowed, or not from GIT_DIR/config."""
    own = "file:" + os.path.join(git_dir, "config")
    bad = set()
    for line in (listing or "").splitlines():
        if not line.strip():
            continue
        origin, _, key = line.partition("\t")
        key = key.strip().lower()
        if origin != own or key not in ALLOWED_CONFIG_KEYS:
            bad.add(key or "<unparsed>")
    return sorted(bad)


def redact(text: str, secrets: Iterable[str]) -> str:
    out = text or ""
    for s in sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True):
        out = out.replace(s, REDACTED)
    return out


def _base_env(tmp: str) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": tmp,
        "XDG_CONFIG_HOME": tmp,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _text(proc: Any) -> str:
    return (proc.stdout or "") + (proc.stderr or "")


def push_feat(
    branch: str,
    *,
    resolve_credential: Callable[[str], str | None],
    repo: str,
    git: str = "/usr/bin/git",
    timeout_seconds: float = 60,
    runner: Callable[..., Any] = subprocess.run,
) -> PushResult:
    validate_branch(branch)
    if not isinstance(repo, str) or not os.path.isabs(repo):
        raise PushRefused("repo must be an absolute path")
    raw = resolve_credential(CREDENTIAL_SLOT) or ""
    token = token_from_slot(raw)
    secrets = (token, raw.strip(), raw)
    deadline = time.monotonic() + timeout_seconds
    pushing = False
    with tempfile.TemporaryDirectory(prefix="gk-push-") as tmp:
        os.chmod(tmp, 0o700)
        git_dir = os.path.join(tmp, "push.git")
        env = _base_env(tmp)

        def run(argv: list[str], child_env: dict[str, str]) -> Any:
            return runner(
                argv, env=child_env, cwd=tmp, capture_output=True, text=True,
                timeout=max(1.0, deadline - time.monotonic()), check=False,
            )

        try:
            # 1. token-free: fresh GIT_DIR, fetch only the branch into it.
            for argv in (init_argv(git_dir, git=git),
                         fetch_argv(branch, repo=repo, git_dir=git_dir, git=git)):
                proc = run(argv, dict(env))
                if proc.returncode != 0:
                    return PushResult(OUTCOME_FAILED, proc.returncode, redact(
                        "push not attempted: preparing the branch failed\n" + _text(proc),
                        secrets))
            # 2. token-free: the push GIT_DIR's effective config must be pristine.
            proc = run(config_argv(git_dir, git=git), dict(env))
            if proc.returncode != 0:
                return PushResult(OUTCOME_FAILED, proc.returncode, redact(
                    "push not attempted: reading the push config failed\n" + _text(proc),
                    secrets))
            bad = unexpected_config(proc.stdout, git_dir)
            if bad:
                raise PushRefused(
                    "push refused: unexpected git config for the push: " + ", ".join(bad))
            # 3. push with the token, fixed URL, protocols restricted.
            askpass = os.path.join(tmp, "askpass.sh")
            fd = os.open(askpass, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(fd, "w") as fh:
                fh.write(_ASKPASS)
            push_env = {**env, "GIT_ASKPASS": askpass, TOKEN_ENV: token}
            pushing = True
            proc = run(build_argv(branch, git_dir=git_dir, git=git), push_env)
        except PushRefused:
            raise
        except subprocess.TimeoutExpired as exc:
            partial = "".join(
                x.decode(errors="replace") if isinstance(x, bytes) else (x or "")
                for x in (exc.stdout, exc.stderr)
            )
            if not pushing:
                return PushResult(OUTCOME_FAILED, None, redact(
                    f"push not attempted: preparation timed out\n{partial}", secrets))
            return PushResult(OUTCOME_UNKNOWN, None, redact(
                f"push timed out after {timeout_seconds}s; state unknown\n{partial}", secrets))
        except Exception as exc:  # noqa: BLE001 -- any failure text is redacted
            return PushResult(OUTCOME_FAILED, None, redact(
                f"push failed: {type(exc).__name__}: {exc}", secrets))
    output = redact(_text(proc), secrets)
    rc = proc.returncode
    return PushResult(OUTCOME_OK if rc == 0 else OUTCOME_FAILED, rc, output)
