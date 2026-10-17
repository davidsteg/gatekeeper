"""The `git` executor: push one `feat/*` branch to its Tier 1 remote.

Against real git on both ends: a worker checkout on disk, and a bare
repository served over git's smart HTTP protocol by `git http-backend`
behind a loopback HTTP server that insists on the token -- not a mocked
subprocess. What matters is what reaches the remote (only fast-forwards
of `feat/*`, nothing forced, nothing deleted), that the worker's own
hooks and config never run or redirect anything, and that the token is
nowhere but the Authorization header.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml
from conftest import make_catalog

from gatekeeper import execute, execute_git
from gatekeeper.audit import AuditLog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.errors import ConfigError, Denied
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

GIT = shutil.which("git")
HTTP_BACKEND = None
if GIT:
    exec_path = subprocess.run([GIT, "--exec-path"], capture_output=True, text=True).stdout.strip()
    candidate = os.path.join(exec_path, "git-http-backend")
    HTTP_BACKEND = candidate if os.path.exists(candidate) else None

pytestmark = pytest.mark.skipif(not (GIT and HTTP_BACKEND), reason="needs git and git-http-backend")

TOKEN = "ghp_test-push-token-0123456789"
ENCODED = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()


def _git(*args, cwd=None, check=True):
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_AUTHOR_NAME": "w", "GIT_AUTHOR_EMAIL": "w@x", "GIT_COMMITTER_NAME": "w",
           "GIT_COMMITTER_EMAIL": "w@x"}
    return subprocess.run([GIT, *args], cwd=cwd, env=env, capture_output=True, text=True,
                          check=check).stdout.strip()


class GitServer:
    """Smart HTTP in front of a directory of bare repositories, via
    `git http-backend` as a CGI. Every request is recorded; one without
    the expected Authorization header gets a 401."""

    def __init__(self, root: str, expected_auth: str | None) -> None:
        self.root = root
        self.expected_auth = expected_auth
        self.requests: list[tuple[str, str, str | None]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: D401 -- quiet
                pass

            def _serve(self):
                auth = self.headers.get("Authorization")
                server.requests.append((self.command, self.path, auth))
                if server.expected_auth is not None and auth != server.expected_auth:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="test"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                path, _, query = self.path.partition("?")
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                env = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "GIT_PROJECT_ROOT": server.root, "GIT_HTTP_EXPORT_ALL": "1",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                    "PATH_INFO": path, "QUERY_STRING": query, "REQUEST_METHOD": self.command,
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": str(len(body)), "REMOTE_USER": "x-access-token",
                    "REMOTE_ADDR": "127.0.0.1",
                }
                if self.headers.get("Content-Encoding"):
                    env["HTTP_CONTENT_ENCODING"] = self.headers["Content-Encoding"]
                if self.headers.get("Git-Protocol"):
                    env["GIT_PROTOCOL"] = self.headers["Git-Protocol"]
                out = subprocess.run([HTTP_BACKEND], input=body, env=env, capture_output=True).stdout
                head, _, payload = out.partition(b"\r\n\r\n")
                status = 200
                headers = []
                for line in head.decode("latin-1").split("\r\n"):
                    key, _, value = line.partition(":")
                    if key.lower() == "status":
                        status = int(value.strip().split()[0])
                    elif key:
                        headers.append((key, value.strip()))
                self.send_response(status)
                for key, value in headers:
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _serve
            do_POST = _serve

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, name: str) -> str:
        return f"http://127.0.0.1:{self.port}/{name}.git"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def ref(self, name: str, ref: str) -> str | None:
        out = _git("--git-dir", os.path.join(self.root, f"{name}.git"), "rev-parse",
                   "--verify", "--quiet", ref, check=False)
        return out or None


@pytest.fixture
def remote(tmp_path):
    root = tmp_path / "remote"
    root.mkdir()
    bare = root / "proj.git"
    _git("init", "--bare", "--quiet", "-b", "main", str(bare))
    _git("--git-dir", str(bare), "config", "http.receivepack", "true")
    server = GitServer(str(root), f"Basic {ENCODED}")
    yield server
    server.close()


@pytest.fixture
def worker(tmp_path, remote):
    """The checkout a worker commits into, with `main` already on the remote."""
    path = tmp_path / "work" / "proj"
    path.mkdir(parents=True)
    _git("init", "--quiet", "-b", "main", cwd=path)
    (path / "README").write_text("hello\n")
    _git("add", "README", cwd=path)
    _git("commit", "--quiet", "-m", "initial", cwd=path)
    _git("push", "--quiet", os.path.join(remote.root, "proj.git"), "main:refs/heads/main", cwd=path)
    return path


def _commit(path, name, text="x"):
    (path / name).write_text(text)
    _git("add", name, cwd=path)
    _git("commit", "--quiet", "-m", f"add {name}", cwd=path)
    return _git("rev-parse", "HEAD", cwd=path)


def _tier1(tmp_path, repos, **overrides):
    spec = {"executor": "git", "credential": "github", "allowed_git_operations": ["push"],
            "git_binary": GIT, "repos": repos, "max_timeout_seconds": 60, **overrides}
    spec = {k: v for k, v in spec.items() if v is not None}
    path = tmp_path / "toolkits.yaml"
    path.write_text(yaml.safe_dump({"toolkits": {"gkrepo": spec},
                                    "audit": {"dir": str(tmp_path / "logs")}}), encoding="utf-8")
    return load_tier1(str(path))


def _toolkit(tmp_path, worker, remote, **overrides):
    repos = {"proj": {"path": str(worker), "remote": remote.url("proj")}}
    return _tier1(tmp_path, repos, **overrides).toolkit("gkrepo")


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"),
                            audit=AuditLog(str(tmp_path / "clogs")))
    store.create("github", kind="bearer", value=TOKEN, actor="test", rev="")
    return store


async def _push(toolkit, credentials, branch, repo="proj", *, timeout=30):
    return await execute_git.run(
        operation="push", values={"repo": repo, "branch": branch}, toolkit=toolkit,
        credentials=credentials, timeout_seconds=timeout, max_output_bytes=65536,
        idempotent=True,
    )


# -- Pushing ------------------------------------------------------------------------------


async def test_new_branch_is_created_with_its_commits(tmp_path, worker, remote, credentials):
    _git("checkout", "--quiet", "-b", "feat/one", cwd=worker)
    _commit(worker, "a.txt")
    head = _commit(worker, "b.txt")
    result = await _push(_toolkit(tmp_path, worker, remote), credentials, "feat/one")
    assert result.outcome == OUTCOME_OK, result.stderr
    assert result.external_untrusted
    payload = json.loads(result.stdout)
    assert payload["status"] == "created"
    assert payload["old"] is None and payload["new"] == head
    assert payload["commits_total"] == 2
    assert [c.split(" ", 1)[1] for c in payload["commits"]] == ["add b.txt", "add a.txt"]
    assert remote.ref("proj", "refs/heads/feat/one") == head
    assert TOKEN not in result.stdout and ENCODED not in result.stdout
    # Every request to the remote carried the token, and only as the header.
    assert remote.requests and all(auth == f"Basic {ENCODED}" for _, _, auth in remote.requests)
    assert all(TOKEN not in path for _, path, _ in remote.requests)


async def test_update_is_a_fast_forward_listing_only_new_commits(tmp_path, worker, remote, credentials):
    toolkit = _toolkit(tmp_path, worker, remote)
    _git("checkout", "--quiet", "-b", "feat/two", cwd=worker)
    first = _commit(worker, "a.txt")
    assert (await _push(toolkit, credentials, "feat/two")).outcome == OUTCOME_OK
    second = _commit(worker, "b.txt")
    result = await _push(toolkit, credentials, "feat/two")
    payload = json.loads(result.stdout)
    assert payload["status"] == "updated"
    assert (payload["old"], payload["new"]) == (first, second)
    assert payload["commits_total"] == 1 and payload["commits"][0].endswith("add b.txt")
    again = json.loads((await _push(toolkit, credentials, "feat/two")).stdout)
    assert again["status"] == "up_to_date" and again["commits"] == []


async def test_non_fast_forward_is_rejected_not_forced(tmp_path, worker, remote, credentials):
    toolkit = _toolkit(tmp_path, worker, remote)
    _git("checkout", "--quiet", "-b", "feat/three", cwd=worker)
    _commit(worker, "a.txt")
    _commit(worker, "b.txt")
    assert (await _push(toolkit, credentials, "feat/three")).outcome == OUTCOME_OK
    on_remote = remote.ref("proj", "refs/heads/feat/three")
    _git("reset", "--quiet", "--hard", "HEAD~1", cwd=worker)
    _commit(worker, "c.txt")
    result = await _push(toolkit, credentials, "feat/three")
    assert result.outcome == OUTCOME_FAILED
    assert "fast-forward" in result.stderr
    assert remote.ref("proj", "refs/heads/feat/three") == on_remote


@pytest.mark.parametrize("branch", [
    "main", "feat", "feat/", "feature/x", "refs/heads/feat/x", "feat/../main", "feat/x.lock",
    "feat/-x", "feat/.x", "feat//x", "feat/x/", "feat/x y", "feat/x:main", "+feat/x", "feat/x~1",
    "feat/" + "a" * 200,
])
async def test_only_plain_feat_branches_are_accepted(tmp_path, worker, remote, credentials, branch):
    result = await _push(_toolkit(tmp_path, worker, remote), credentials, branch)
    assert result.outcome == OUTCOME_FAILED
    assert result.denial_reason == "param_invalid"
    assert remote.requests == []


async def test_unknown_repo_is_refused_before_git_runs(tmp_path, worker, remote, credentials):
    result = await _push(_toolkit(tmp_path, worker, remote), credentials, "feat/x", repo="other")
    assert result.denial_reason == "tier1_violation"
    assert remote.requests == []


async def test_missing_branch_is_a_denial_without_touching_the_remote(tmp_path, worker, remote,
                                                                     credentials):
    result = await _push(_toolkit(tmp_path, worker, remote), credentials, "feat/nope")
    assert result.denial_reason == "param_invalid"
    assert "does not exist" in result.stderr
    assert remote.requests == []


async def test_the_worker_repository_config_and_hooks_never_run(tmp_path, worker, remote,
                                                               credentials):
    """Whoever writes the checkout writes its .git/config and hooks too."""
    marker = tmp_path / "pwned"
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat >/dev/null\nexit 0\n")
    script.chmod(0o755)
    evil = GitServer(str(tmp_path / "remote"), None)
    try:
        hooks = worker / ".git" / "hooks"
        for hook in ("pre-push", "reference-transaction", "post-checkout"):
            (hooks / hook).write_text(script.read_text())
            (hooks / hook).chmod(0o755)
        _git("config", f"url.http://127.0.0.1:{evil.port}/.insteadOf",
             f"http://127.0.0.1:{remote.port}/", cwd=worker)
        _git("config", "credential.helper", f"!{script}", cwd=worker)
        _git("config", "core.fsmonitor", str(script), cwd=worker)
        _git("config", "core.sshCommand", str(script), cwd=worker)
        _git("config", "http.proxy", f"http://127.0.0.1:{evil.port}", cwd=worker)
        _git("checkout", "--quiet", "-b", "feat/evil", cwd=worker)
        head = _commit(worker, "a.txt")
        marker.unlink(missing_ok=True)  # the commit above ran the worker's hooks itself

        result = await _push(_toolkit(tmp_path, worker, remote), credentials, "feat/evil")
        assert result.outcome == OUTCOME_OK, result.stderr
        assert remote.ref("proj", "refs/heads/feat/evil") == head
        assert evil.requests == []
        assert not marker.exists()
    finally:
        evil.close()


async def test_the_token_is_never_in_argv(tmp_path, worker, remote, credentials, monkeypatch):
    seen: list[tuple[list[str], dict]] = []
    real = execute.run

    async def spy(argv, **kwargs):
        seen.append((list(argv), dict(kwargs.get("env") or {})))
        return await real(argv, **kwargs)

    monkeypatch.setattr(execute, "run", spy)
    _git("checkout", "--quiet", "-b", "feat/argv", cwd=worker)
    _commit(worker, "a.txt")
    assert (await _push(_toolkit(tmp_path, worker, remote), credentials, "feat/argv")).outcome == OUTCOME_OK
    joined = "\n".join(" ".join(argv) for argv, _ in seen)
    assert TOKEN not in joined and ENCODED not in joined
    assert "--force" not in joined and "--delete" not in joined and ":refs/heads/main" not in joined
    with_token = [argv for argv, env in seen if any(ENCODED in v for v in env.values())]
    # Only the two steps that talk to the remote get the header.
    assert {argv[2] for argv in with_token} == {"ls-remote", "push"}


async def test_wrong_token_fails_without_echoing_it(tmp_path, worker, remote, credentials):
    remote.expected_auth = "Basic something-else"
    _git("checkout", "--quiet", "-b", "feat/auth", cwd=worker)
    _commit(worker, "a.txt")
    result = await _push(_toolkit(tmp_path, worker, remote), credentials, "feat/auth")
    assert result.outcome == OUTCOME_FAILED
    assert TOKEN not in result.stderr and ENCODED not in result.stderr
    assert remote.ref("proj", "refs/heads/feat/auth") is None


async def test_a_non_token_credential_is_refused(tmp_path, worker, remote, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    store = CredentialStore(path=str(tmp_path / "c2.yaml"), audit=AuditLog(str(tmp_path / "c2")))
    store.create("github", kind="api_key_header", header="X-Key", value=TOKEN, actor="t", rev="")
    result = await _push(_toolkit(tmp_path, worker, remote), store, "feat/x")
    assert result.denial_reason == "credential_unavailable"
    assert remote.requests == []


async def test_probe_checks_the_binary_only(tmp_path, worker, remote):
    assert await execute_git.probe(_toolkit(tmp_path, worker, remote))
    assert not await execute_git.probe(_toolkit(tmp_path, worker, remote, git_binary="/nonexistent/git"))
    assert remote.requests == []


# -- Tier 1 -------------------------------------------------------------------------------


@pytest.mark.parametrize("overrides, fragment", [
    ({"credential": None}, "needs 'credential'"),
    ({"allowed_git_operations": ["force_push"]}, "unknown: ['force_push']"),
    ({"allowed_git_operations": []}, "non-empty subset"),
    ({"git_binary": "git"}, "absolute path"),
    ({"repos": {}}, "non-empty mapping"),
    ({"repos": {"p": {"path": "relative", "remote": "https://github.com/a/b.git"}}}, "absolute"),
    ({"repos": {"p": {"path": "/srv/../etc", "remote": "https://github.com/a/b.git"}}}, "'..'"),
    ({"repos": {"p": {"path": "/srv/p", "remote": "http://github.com/a/b.git"}}}, "https"),
    ({"repos": {"p": {"path": "/srv/p", "remote": "ssh://git@github.com/a/b.git"}}}, "https"),
    ({"repos": {"p": {"path": "/srv/p", "remote": "file:///srv/x"}}}, "https"),
    ({"repos": {"p": {"path": "/srv/p", "remote": "https://u:t@github.com/a/b.git"}}}, "no user"),
    ({"repos": {"p": {"path": "/srv/p", "remote": "https://github.com/a/b.git?x=1"}}}, "query"),
    ({"repos": {"p": {"path": "/srv/p", "remote": "https://github.com/a/b.git", "push": "x"}}},
     "unknown fields"),
    ({"repos": {"bad name": {"path": "/srv/p", "remote": "https://github.com/a/b.git"}}}, "repo name"),
])
def test_tier1_refuses_an_incomplete_git_toolkit(tmp_path, overrides, fragment):
    repos = overrides.pop("repos", {"p": {"path": "/srv/p", "remote": "https://github.com/a/b.git"}})
    with pytest.raises(ConfigError) as exc:
        _tier1(tmp_path, repos, **overrides)
    assert fragment in str(exc.value)


def test_tier1_takes_https_and_loopback_http(tmp_path):
    toolkit = _tier1(tmp_path, {
        "a": {"path": "/srv/a", "remote": "https://github.com/davidsteg/gatekeeper.git"},
        "b": {"path": "/srv/b", "remote": "http://127.0.0.1:9418/b.git"},
    }).toolkit("gkrepo")
    assert [r.name for r in toolkit.git_repos] == ["a", "b"]
    assert toolkit.git_repo("a").remote == "https://github.com/davidsteg/gatekeeper.git"


# -- Catalog ------------------------------------------------------------------------------

PARAMS = {
    "repo": {"type": "enum", "required": True, "values": ["p"], "description": "repo"},
    "branch": {"type": "string", "required": True, "pattern": "^feat/[A-Za-z0-9._/-]{1,100}$",
               "description": "branch"},
}


def _tools(**change):
    return [{"id": "gkrepo.push", "toolkit": "gkrepo", "version": 1, "enabled": True,
             "required_scopes": [], "timeout_seconds": 60, "max_output_bytes": 16384,
             "description": "push", "title": "Push", "category": "write", "idempotent": True,
             "git_operation": "push", "parameters": PARAMS, **change}]


def _plain_tier1(tmp_path):
    return _tier1(tmp_path, {"p": {"path": "/srv/p", "remote": "https://github.com/a/b.git"}})


def test_example_tool_loads(tmp_path):
    catalog = make_catalog(tmp_path, _plain_tier1(tmp_path), _tools())
    assert catalog.tools["gkrepo.push"].git_operation == "push"


@pytest.mark.parametrize("change, fragment", [
    ({"category": "read"}, "must be 'write'"),
    ({"git_operation": "force_push"}, "unknown"),
    ({"parameters": {**PARAMS, "force": {"type": "boolean", "description": "f"}}}, "does not read"),
    ({"parameters": {"branch": PARAMS["branch"]}}, "'repo'"),
    ({"parameters": {**PARAMS, "branch": {"type": "integer", "required": True, "description": "b"}}},
     "string or an enum"),
    ({"parameters": {**PARAMS, "repo": {**PARAMS["repo"], "values": ["p", "q"]}}}, "not in the 'repos'"),
])
def test_catalog_refuses_a_definition_wider_than_the_executor(tmp_path, change, fragment):
    with pytest.raises((ConfigError, Exception)) as exc:
        make_catalog(tmp_path, _plain_tier1(tmp_path), _tools(**change))
    assert fragment in str(exc.value)


def test_shipped_example_toolkit_and_tool_load(tmp_path):
    from pathlib import Path

    examples = Path(__file__).resolve().parent.parent / "config" / "examples"
    toolkits = yaml.safe_load((examples / "toolkits.yaml").read_text(encoding="utf-8"))["toolkits"]
    tools = [t for t in yaml.safe_load((examples / "tools.yaml").read_text(encoding="utf-8"))["tools"]
             if t.get("toolkit") == "gkrepo"]
    path = tmp_path / "toolkits.yaml"
    path.write_text(yaml.safe_dump({"toolkits": {"gkrepo": toolkits["gkrepo"]},
                                    "audit": {"dir": str(tmp_path / "logs")}}), encoding="utf-8")
    catalog = make_catalog(tmp_path, load_tier1(str(path)), tools)
    assert sorted(catalog.tools) == ["gkrepo.push"]


# -- Through the service, with audit ------------------------------------------------------


async def test_service_call_is_audited_without_the_token(tmp_path, worker, remote, credentials):
    repos = {"proj": {"path": str(worker), "remote": remote.url("proj")}}
    tier1 = _tier1(tmp_path, repos)
    loose = {"repo": {"type": "string", "required": True, "pattern": "^\\S{1,64}$", "description": "r"},
             "branch": {"type": "string", "required": True, "pattern": "^\\S{1,200}$",
                        "description": "b"}}
    catalog = make_catalog(tmp_path, tier1, _tools(parameters=loose))
    ipath = tmp_path / "identities.yaml"
    ipath.write_text(yaml.safe_dump({"identities": [
        {"id": "homelab", "role": "agent", "token_hash": hash_token(generate_token()),
         "tools": ["gkrepo.push"], "scopes": []},
    ]}), encoding="utf-8")
    identities = load_identities(str(ipath))
    service = Service(tier1=tier1, catalog=catalog, audit=AuditLog(str(tmp_path / "logs")),
                      identities=identities, credentials=credentials)
    homelab = identities.identities["homelab"]

    _git("checkout", "--quiet", "-b", "feat/svc", cwd=worker)
    head = _commit(worker, "a.txt")
    pushed = await service.call(homelab, "gkrepo.push", {"repo": "proj", "branch": "feat/svc"})
    assert pushed.outcome == OUTCOME_OK, pushed.stderr
    assert json.loads(pushed.stdout)["new"] == head
    # A loose schema does not widen the executor: main is still refused.
    with pytest.raises(Denied) as denied:
        await service.call(homelab, "gkrepo.push", {"repo": "proj", "branch": "main"})
    assert "feat/" in denied.value.agent_message
    assert remote.ref("proj", "refs/heads/main") != head

    log = "".join(p.read_text() for p in (tmp_path / "logs").rglob("*") if p.is_file())
    calls = [json.loads(line) for line in log.splitlines() if line.strip()]
    calls = [r for r in calls if r.get("kind") == "call"]
    assert [r["tool"] for r in calls][-2:] == ["gkrepo.push", "gkrepo.push"]
    assert TOKEN not in log and ENCODED not in log
