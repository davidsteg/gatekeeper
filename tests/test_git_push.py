"""git_push_feat: feat/* only, fixed remote, no force, token never leaks."""

from __future__ import annotations

import os
import subprocess
import types

import pytest

from gatekeeper import git_push
from gatekeeper.git_push import (
    FEAT_BRANCH_RE,
    REMOTE_URL,
    PushRefused,
    build_argv,
    push_feat,
    redact,
)

TOKEN = "ghp_TESTTOKEN0123456789abcdefABCDEF0000"
REPO = "/repo"


def slot(value=TOKEN):
    calls = []

    def resolve(name):
        calls.append(name)
        return value

    resolve.calls = calls
    return resolve


class FakeRunner:
    def __init__(self, returncode=0, stdout="", stderr="", exc=None):
        self.returncode, self.stdout, self.stderr, self.exc = returncode, stdout, stderr, exc
        self.calls = []

    def __call__(self, argv, **kw):
        env = kw["env"]
        askpass = env["GIT_ASKPASS"]
        with open(askpass) as fh:
            script = fh.read()
        user = subprocess.run([askpass, "Username for 'https://github.com': "],
                              env=env, capture_output=True, text=True, check=True).stdout
        pw = subprocess.run([askpass, "Password for 'https://x@github.com': "],
                            env=env, capture_output=True, text=True, check=True).stdout
        self.calls.append(types.SimpleNamespace(
            argv=list(argv), kw=kw, script=script, user=user, pw=pw,
            mode=os.stat(askpass).st_mode & 0o777,
            dir_mode=os.stat(os.path.dirname(askpass)).st_mode & 0o777,
        ))
        if self.exc is not None:
            raise self.exc
        return types.SimpleNamespace(returncode=self.returncode, stdout=self.stdout,
                                     stderr=self.stderr)


@pytest.mark.parametrize("branch", [
    "feat/x", "feat/benign-exit1", "feat/gkrepo-tools", "feat/a.b_c-1", "feat/" + "a" * 60,
])
def test_branch_allowed(branch):
    assert FEAT_BRANCH_RE.fullmatch(branch)


@pytest.mark.parametrize("branch", [
    "main", "master", "feat/", "feat/../main", "feat/a..b", "feat/x.lock", "+feat/x",
    "feat/x:main", "feat/x:refs/heads/main", "refs/heads/main", "refs/heads/feat/x",
    "feat/-x", "feat/.x", "feat/x.", "feat/a/b", "feat/X", "feat/x main", "feat/x\n",
    "fix/x", "feat/x@{1}", "", "feat/" + "a" * 61, " feat/x",
])
def test_branch_refused(branch):
    with pytest.raises(PushRefused):
        build_argv(branch, repo=REPO)


def test_argv_shape():
    argv = build_argv("feat/x", repo=REPO, git="/usr/bin/git")
    assert argv[:3] == ["/usr/bin/git", "-C", REPO]
    assert "core.hooksPath=/dev/null" in argv
    assert "--no-verify" in argv
    assert argv[-2] == REMOTE_URL == "https://github.com/davidsteg/gatekeeper.git"
    assert argv[-1] == "refs/heads/feat/x:refs/heads/feat/x"
    assert argv[argv.index("push") + 1:] == ["--porcelain", "--no-verify", REMOTE_URL,
                                              "refs/heads/feat/x:refs/heads/feat/x"]
    for bad in ("--force", "-f", "--force-with-lease", "--mirror", "--all", "--tags",
                "--delete", "origin"):
        assert bad not in argv
    assert not any(a.startswith("+") for a in argv)


def test_push_uses_slot_via_askpass_and_never_argv():
    run = FakeRunner(stdout="To https://github.com/davidsteg/gatekeeper.git\n*\trefs/heads/feat/x\n")
    resolve = slot()
    res = push_feat("feat/x", resolve_credential=resolve, repo=REPO, runner=run)
    assert res.outcome == "ok" and res.exit_code == 0
    assert resolve.calls == ["github"]
    call = run.calls[0]
    assert not any(TOKEN in a for a in call.argv)
    assert TOKEN not in call.script  # askpass file holds no secret
    assert call.user.strip() == "x-access-token"
    assert call.pw.strip() == TOKEN
    assert call.mode == 0o700 and call.dir_mode == 0o700
    env = call.kw["env"]
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert [k for k, v in env.items() if TOKEN in v] == [git_push.TOKEN_ENV]
    assert not os.path.exists(env["GIT_ASKPASS"])  # temp dir removed afterwards
    assert TOKEN not in res.output


@pytest.mark.parametrize("stored", [f"Bearer {TOKEN}", f"token {TOKEN}", f"  {TOKEN}\n"])
def test_scheme_prefix_is_stripped(stored):
    run = FakeRunner()
    push_feat("feat/x", resolve_credential=slot(stored), repo=REPO, runner=run)
    assert run.calls[0].pw.strip() == TOKEN


def test_output_and_stderr_are_redacted():
    run = FakeRunner(returncode=128, stdout=f"out {TOKEN}\n",
                     stderr=f"fatal: https://x-access-token:{TOKEN}@github.com denied\n")
    res = push_feat("feat/x", resolve_credential=slot(), repo=REPO, runner=run)
    assert res.outcome == "failed" and res.exit_code == 128
    assert TOKEN not in res.output and "***" in res.output


def test_raw_slot_value_with_scheme_is_redacted_too():
    stored = f"Bearer {TOKEN}"
    run = FakeRunner(returncode=1, stderr=f"echo {stored}")
    res = push_feat("feat/x", resolve_credential=slot(stored), repo=REPO, runner=run)
    assert TOKEN not in res.output and stored not in res.output


def test_exception_text_is_redacted():
    run = FakeRunner(exc=OSError(f"boom {TOKEN}"))
    res = push_feat("feat/x", resolve_credential=slot(), repo=REPO, runner=run)
    assert res.outcome == "failed" and res.exit_code is None
    assert TOKEN not in res.output and "OSError" in res.output


def test_timeout_is_unknown_and_redacted():
    exc = subprocess.TimeoutExpired(["git"], 60, output=f"partial {TOKEN}".encode(),
                                    stderr=TOKEN)
    run = FakeRunner(exc=exc)
    res = push_feat("feat/x", resolve_credential=slot(), repo=REPO, runner=run)
    assert res.outcome == "unknown" and res.exit_code is None
    assert TOKEN not in res.output


@pytest.mark.parametrize("value", [None, "", "   ", "Bearer "])
def test_empty_slot_is_refused_without_running_git(value):
    run = FakeRunner()
    with pytest.raises(PushRefused) as ei:
        push_feat("feat/x", resolve_credential=slot(value), repo=REPO, runner=run)
    assert run.calls == []
    assert "github" in str(ei.value)


def test_bad_branch_refused_before_slot_is_read():
    resolve = slot()
    with pytest.raises(PushRefused) as ei:
        push_feat("main", resolve_credential=resolve, repo=REPO, runner=FakeRunner())
    assert resolve.calls == []
    assert TOKEN not in str(ei.value)


def test_redact_helper():
    assert redact(f"a {TOKEN} b {TOKEN}", [TOKEN]) == "a *** b ***"
    assert redact("abc", ["", None, "ab"]) == "abc"  # too-short secrets are not masked
