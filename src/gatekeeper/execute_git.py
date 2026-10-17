"""The `git` executor: push one branch from an allowlisted repository.

A worker that commits into a checkout on this host still needs the result
on GitHub, and the obvious ways to get it there are the ones gatekeeper
exists to replace: a token in the worker's environment or in the
checkout's `.git/config`, or the worker shipping file contents through
an API call. This executor pushes instead. The caller names a repository
(a key in the toolkit's `repos:`) and a branch, nothing else; the path,
the remote and the token are Tier 1 and the credential store.

One operation, `push`, and it is narrow on purpose:

* The target is always `refs/heads/<branch>` with the branch under
  `tier1.GIT_PUSH_BRANCH_PREFIX` (`feat/`). `main` is not refused by a
  rule that could be edited, it is simply not a name this module builds.
* The refspec has no `+`, and there is no `--force`, `--force-with-lease`,
  `--delete` or `--mirror` anywhere in this file. A push that is not a
  fast-forward is rejected by git itself, and reported as such.
* The output is the old and new SHA of the remote branch and a capped
  list of the commits that went over -- never a diff or file content.

**The worker's repository is read, never trusted.** Whoever writes into
the checkout also writes its `.git/config` and `.git/hooks`, and a push
run *in* that repository would execute its `pre-push` hook, follow its
`url.<x>.insteadOf` to wherever it points, and hand the token to its
`credential.helper`. So no git command here runs in it. Each call builds
a throwaway bare repository whose config gatekeeper writes, borrows the
worker's object store as an alternate (so nothing is copied), and
fetches the one branch from the worker's path -- the only thing that
touches the worker's repository is `git upload-pack`, which ignores the
repository's hooks and code-running config keys. The push then runs in
the throwaway repository: no hooks, no system or global config, no
credential helper, no redirects, https only.

**The token never sits in argv.** It reaches git as
`http.<remote>.extraHeader` through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`
in the child's environment -- readable by the same user and root, not by
a `ps` on the host (FR-10.2) -- and only for the two steps that talk to
the remote. Every text that leaves this module is scrubbed of the token
and of the encoded header before the audit redactor sees it.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import tempfile
import time
from typing import Any

from . import execute
from .credentials import CredentialStore, ResolvedCredential
from .errors import DenialReason, Denied
from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result
from .tier1 import DEFAULT_GIT_BINARY, GIT_PUSH_BRANCH_PREFIX, GitRepo, Toolkit, is_runnable

#: How many commits the output lists, and how much of each subject. The
#: total is reported separately, so a long branch is visibly cut, not
#: silently short.
MAX_COMMITS = 20
MAX_SUBJECT_CHARS = 100

#: Ceiling on the remote heads a new branch's commit list is measured
#: against (`rev-list --not ...`). Only bounds argv on a remote with an
#: unusual number of branches; past it the count can only come out high.
_MAX_EXCLUDED_HEADS = 256

#: How much of git's own stderr a failure carries.
_MAX_ERROR_CHARS = 2000

#: One path component of a branch under the prefix: no leading '.' or
#: '-', none of git's ref metacharacters. Stricter than
#: `git check-ref-format`, which is the point.
_BRANCH_COMPONENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_MAX_BRANCH_CHARS = 200

_SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def check_values(toolkit: Toolkit, values: dict[str, str]) -> None:
    """The executor's own floor under whatever the tool definition says:
    the repo is a key of the toolkit's `repos:`, the branch is a plain
    name under `feat/`."""
    repo = values.get("repo", "")
    if toolkit.git_repo(repo) is None:
        raise Denied(
            DenialReason.TIER1_VIOLATION,
            f"Repository {repo!r} is not one this toolkit may push from "
            f"(allowed: {[r.name for r in toolkit.git_repos]}).",
        )
    branch = values.get("branch", "")
    if not branch.startswith(GIT_PUSH_BRANCH_PREFIX):
        raise Denied(
            DenialReason.PARAM_INVALID,
            f"Parameter 'branch' must start with {GIT_PUSH_BRANCH_PREFIX!r}; "
            "nothing else can be pushed.",
        )
    rest = branch[len(GIT_PUSH_BRANCH_PREFIX):]
    if (
        len(branch) > _MAX_BRANCH_CHARS
        or not rest
        or ".." in branch
        or branch.endswith((".", ".lock"))
        or any(not _BRANCH_COMPONENT.match(part) or part.endswith(".lock")
               for part in rest.split("/"))
    ):
        raise Denied(
            DenialReason.PARAM_INVALID,
            f"Parameter 'branch' must be {GIT_PUSH_BRANCH_PREFIX}<name>, with "
            "letters, digits, '.', '_', '-' and '/' between parts, at most "
            f"{_MAX_BRANCH_CHARS} characters.",
        )


def _auth_header(credential: ResolvedCredential) -> tuple[str, list[str]]:
    """The Authorization header for git over https, and every form of the
    secret that must never appear in an output.

    A `bearer` credential is a token on its own (GitHub's convention is
    any user name with the token as password); a `basic` one is
    `user:token`. Git over https takes Basic, not Bearer.
    """
    if credential.kind == "bearer":
        token = credential.value
        pair = f"x-access-token:{token}"
    elif credential.kind == "basic" and ":" in credential.value:
        token = credential.value.split(":", 1)[1]
        pair = credential.value
    else:
        raise Denied(
            DenialReason.CREDENTIAL_UNAVAILABLE,
            f"Credential {credential.name!r} must be kind 'bearer' (a token) or "
            "'basic' (user:token).",
        )
    encoded = base64.b64encode(pair.encode("utf-8")).decode("ascii")
    secrets = [s for s in (credential.value, token, pair, encoded) if s]
    return f"Authorization: Basic {encoded}", secrets


def _object_dir(path: str) -> str | None:
    """The worker repository's object store, for use as an alternate.

    A checkout (`<path>/.git/objects`) or a bare repository
    (`<path>/objects`). A `.git` *file* (a linked worktree, a submodule)
    gets none: the fetch below still works, it just copies the objects.
    """
    for candidate in (os.path.join(path, ".git", "objects"), os.path.join(path, "objects")):
        if os.path.isdir(candidate):
            return candidate
    return None


def _config_env(entries: list[tuple[str, str]]) -> dict[str, str]:
    env = {"GIT_CONFIG_COUNT": str(len(entries))}
    for i, (key, value) in enumerate(entries):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


class _Failed(Exception):
    def __init__(self, message: str, result: Result | None = None) -> None:
        super().__init__(message)
        self.result = result


async def run(
    *,
    operation: str,
    values: dict[str, str],
    toolkit: Toolkit,
    credentials: CredentialStore | None,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    redact: Any = None,
) -> Result:
    started = time.monotonic()
    deadline = started + timeout_seconds
    secrets: list[str] = []

    def _elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    def _clean(text: str) -> str:
        for secret in sorted(secrets, key=len, reverse=True):
            text = text.replace(secret, "***")
        return redact(text) if redact is not None else text

    def _denied(denial: Denied) -> Result:
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=_clean(denial.agent_message),
            truncated=False,
            duration_ms=_elapsed(),
            denial_reason=denial.reason.value,
            denial_detail=denial.detail,
        )

    # Defensive re-checks: `operation` is fixed per tool and the values
    # were validated by `validate.build_git_call`.
    if operation != "push" or not toolkit.allows_git_operation(operation):
        return _denied(Denied(DenialReason.TIER1_VIOLATION,
                              f"Git operation {operation!r} is not allowed for this toolkit."))
    try:
        check_values(toolkit, values)
    except Denied as denial:
        return _denied(denial)
    repo = toolkit.git_repo(values["repo"])
    assert repo is not None
    branch = values["branch"]

    if not toolkit.credential or credentials is None:
        return _denied(Denied(DenialReason.CREDENTIAL_UNAVAILABLE,
                              "This toolkit needs a push token in the credential store."))
    credential = credentials._resolve(toolkit.credential)
    if credential is None:
        return _denied(Denied(DenialReason.CREDENTIAL_UNAVAILABLE,
                              f"Credential {toolkit.credential!r} is not configured yet."))
    try:
        header, secrets[:] = _auth_header(credential)
    except Denied as denial:
        return _denied(denial)

    if not os.path.isdir(repo.path):
        return _denied(Denied(DenialReason.EXECUTOR_UNAVAILABLE,
                              f"Repository {repo.name!r} does not exist at its configured path."))

    workdir = tempfile.mkdtemp(prefix="gatekeeper-git-")
    try:
        summary = await _push(
            repo=repo, branch=branch, header=header, workdir=workdir,
            git=toolkit.git_binary or DEFAULT_GIT_BINARY, deadline=deadline,
            max_output_bytes=max_output_bytes, idempotent=idempotent,
        )
    except Denied as denial:
        return _denied(denial)
    except _Failed as failure:
        timed_out = failure.result is not None and failure.result.exit_code is None
        message = str(failure)
        if failure.result is not None and failure.result.stderr.strip():
            message += "\n" + failure.result.stderr.strip()[-_MAX_ERROR_CHARS:]
        return Result(
            outcome=failure.result.outcome if timed_out and failure.result else OUTCOME_FAILED,
            exit_code=failure.result.exit_code if failure.result else None,
            stdout="",
            stderr=_clean(message),
            truncated=False,
            duration_ms=_elapsed(),
            external_untrusted=True,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    stdout = json.dumps(summary, ensure_ascii=False)
    encoded = stdout.encode("utf-8")
    truncated = len(encoded) > max_output_bytes
    if truncated:
        stdout = encoded[:max_output_bytes].decode("utf-8", errors="replace")
    return Result(
        outcome=OUTCOME_OK,
        exit_code=0,
        stdout=_clean(stdout),
        stderr="",
        truncated=truncated,
        duration_ms=_elapsed(),
        # Commit subjects are whatever the worker wrote.
        external_untrusted=True,
    )


async def _push(
    *, repo: GitRepo, branch: str, header: str, workdir: str, git: str,
    deadline: float, max_output_bytes: int, idempotent: bool,
) -> dict[str, Any]:
    bare = os.path.join(workdir, "push.git")
    home = os.path.join(workdir, "home")
    os.mkdir(home)
    ref = f"refs/heads/{branch}"

    base_env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": home,
        "XDG_CONFIG_HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
    }
    hardening = [
        ("core.hooksPath", os.devnull),
        ("core.fsmonitor", "false"),
        ("credential.helper", ""),
        ("core.askPass", ""),
        ("http.followRedirects", "false"),
        ("protocol.allow", "never"),
        ("safe.directory", repo.path),
        ("safe.directory", os.path.join(repo.path, ".git")),
    ]
    scheme = repo.remote.split(":", 1)[0]
    remote_config = [
        *hardening,
        (f"protocol.{scheme}.allow", "always"),
        (f"http.{repo.remote}.extraHeader", header),
    ]

    async def _git(args: list[str], config: list[tuple[str, str]], *,
                   idempotent_step: bool = True, what: str) -> Result:
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise _Failed(f"Timeout exceeded before {what}.",
                          Result(OUTCOME_FAILED, None, "", "", False, 0))
        result = await execute.run(
            [git, *args],
            timeout_seconds=remaining,
            max_output_bytes=max(max_output_bytes, 1 << 16),
            idempotent=idempotent_step,
            cwd=workdir,
            env={**base_env, **_config_env(config)},
        )
        if result.outcome != OUTCOME_OK:
            raise _Failed(f"git {what} failed.", result)
        return result

    gd = f"--git-dir={bare}"
    await _git(["init", "--bare", "--quiet", "--template=", bare], hardening, what="init")
    objects = _object_dir(repo.path)
    if objects is not None:
        os.makedirs(os.path.join(bare, "objects", "info"), exist_ok=True)
        with open(os.path.join(bare, "objects", "info", "alternates"), "w", encoding="utf-8") as fh:
            fh.write(os.path.abspath(objects) + "\n")

    try:
        await _git(
            [gd, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
             "--no-write-fetch-head", repo.path, f"{ref}:{ref}"],
            [*hardening, ("protocol.file.allow", "always")],
            what="reading the branch from the repository",
        )
    except _Failed as failure:
        stderr = failure.result.stderr if failure.result else ""
        if "couldn't find remote ref" in stderr:
            raise Denied(DenialReason.PARAM_INVALID,
                         f"Branch {branch!r} does not exist in repository {repo.name!r}.") from None
        raise
    new = (await _git([gd, "rev-parse", "--verify", f"{ref}^{{commit}}"], hardening,
                      what="rev-parse")).stdout.strip()

    listed = await _git([gd, "ls-remote", "--heads", repo.remote], remote_config,
                        what=f"ls-remote against {repo.remote}")
    heads: dict[str, str] = {}
    for line in listed.stdout.splitlines():
        sha, _, name = line.partition("\t")
        if _SHA.match(sha) and name.startswith("refs/heads/"):
            heads[name] = sha
    old = heads.get(ref)

    summary: dict[str, Any] = {
        "repo": repo.name, "branch": branch, "remote": repo.remote,
        "old": old, "new": new,
    }
    if old == new:
        return {**summary, "status": "up_to_date", "commits": [], "commits_total": 0,
                "commits_truncated": False}

    # What goes over: everything reachable from `new` that the remote
    # already has is excluded -- its old tip for an update, every head it
    # has (as far as those objects exist here) for a new branch.
    exclude = [old] if old else list(heads.values())[:_MAX_EXCLUDED_HEADS]
    not_args = ["--not", *exclude] if exclude else []
    count = await _git([gd, "rev-list", "--count", "--ignore-missing", new, *not_args],
                       hardening, what="rev-list")
    log = await _git([gd, "log", "--no-decorate", "--no-show-signature",
                      f"--max-count={MAX_COMMITS}", "--format=%h %s", "--ignore-missing",
                      new, *not_args], hardening, what="log")
    commits = [line[:MAX_SUBJECT_CHARS] for line in log.stdout.splitlines() if line]
    total = int(count.stdout.strip() or 0)

    try:
        pushed = await _git(
            [gd, "push", "--porcelain", "--no-verify", repo.remote, f"{ref}:{ref}"],
            remote_config, idempotent_step=idempotent, what=f"push to {repo.remote}",
        )
    except _Failed as failure:
        result = failure.result
        porcelain = result.stdout if result else ""
        if "[rejected]" in porcelain or "[remote rejected]" in porcelain:
            line = next((ln for ln in porcelain.splitlines() if "rejected]" in ln), "")
            reason = line.split("\t")[-1].strip() if line else "rejected"
            raise _Failed(
                f"The remote refused the push of {branch!r}: {reason}. Only fast-forward "
                "pushes are possible; integrate the remote branch in the repository first.",
                result,
            ) from None
        if result is not None and result.outcome == OUTCOME_UNKNOWN:
            raise _Failed(
                "The outcome is UNKNOWN: the push may have reached the remote. Call "
                "again -- an already-pushed branch comes back as up_to_date.",
                result,
            ) from None
        raise
    status = "created" if old is None else "updated"
    for line in pushed.stdout.splitlines():
        if line.startswith("=\t"):
            status = "up_to_date"
    return {**summary, "status": status, "commits": commits, "commits_total": total,
            "commits_truncated": total > len(commits)}


async def probe(toolkit: Toolkit) -> bool:
    """For /health/ready: git is there and runnable. Nothing is sent to the
    remote -- a liveness question does not put the token on the wire."""
    return is_runnable(toolkit.git_binary or DEFAULT_GIT_BINARY)
