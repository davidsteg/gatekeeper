"""The `ssh` executor (REQUIREMENTS.md §17).

Against a real asyncssh server, not a mock: the properties that matter --
argv elements arrive shell-quoted, host-key pinning actually rejects an
unpinned/wrong key, a denied binary/arg never reaches the wire -- are
exactly what a mocked `run()` call would assume away. The server-side
process handler never spawns a real system shell (this suite also runs on
Windows dev machines); it just inspects the received command string
directly, which doubles as a check on exactly what `execute_ssh.py` sent.
"""

from __future__ import annotations

import asyncio

import asyncssh
import pytest

from gatekeeper import execute_ssh, validate
from gatekeeper.catalog import parse_tool_spec
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN
from gatekeeper.tier1 import load_tier1

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


class _RecordingServer(asyncssh.SSHServer):
    def __init__(self, authorized_key):
        self.authorized_key = authorized_key

    def begin_auth(self, username):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return key == self.authorized_key


async def _handle_process(process):
    command = process.command or ""
    process.last_command = command  # type: ignore[attr-defined]
    if "slow" in command:
        await asyncio.sleep(2)
        process.stdout.write("late\n")
        process.exit(0)
        return
    if "denied-binary" in command:
        process.stderr.write("not found\n")
        process.exit(127)
        return
    process.stdout.write(f"ran: {command}\n")
    process.exit(0)


@pytest.fixture
async def ssh_server():
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    server_factory = lambda: _RecordingServer(client_key.convert_to_public())

    server = await asyncssh.create_server(
        server_factory,
        "127.0.0.1",
        0,
        server_host_keys=[host_key],
        process_factory=_handle_process,
    )
    port = server.sockets[0].getsockname()[1]
    known_hosts_line = f"127.0.0.1 {host_key.export_public_key().decode().strip()}"
    yield {
        "port": port,
        "known_hosts": known_hosts_line,
        "client_private_key": client_key.export_private_key().decode(),
    }
    server.close()
    await server.wait_closed()


@pytest.fixture
def toolkit(tmp_path, ssh_server):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        f"""
toolkits:
  demo_ssh:
    executor: ssh
    ssh_host: "127.0.0.1"
    ssh_port: {ssh_server["port"]}
    ssh_user: "gatekeeper"
    ssh_known_hosts: "{ssh_server["known_hosts"]}"
    binaries: ["/usr/bin/uptime", "/usr/bin/denied-binary"]
    denied_args: ["--evil"]
    credential: demo_ssh_key
audit:
  dir: {tmp_path / 'logs'}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    return tier1.toolkit("demo_ssh"), tier1


def _tool(tier1, **overrides):
    spec = {
        "id": "demo_ssh.uptime", "toolkit": "demo_ssh", "version": 1,
        "title": "Uptime", "description": "test", "category": "read",
        "enabled": True, "binary": "/usr/bin/uptime", "argv": ["{arg}"],
        "parameters": {"arg": {"type": "string", "pattern": "^.*$", "required": True}},
        "timeout_seconds": 5, "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return parse_tool_spec(spec, tier1)


@pytest.fixture
def credentials(tmp_path, ssh_server, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "logs2"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store.create(
        "demo_ssh_key", kind="ssh_private_key",
        value=ssh_server["client_private_key"], actor="test", rev="",
    )
    return store


async def test_successful_command(toolkit, credentials):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    argv = validate.build_argv(tool, {"arg": "-a"}, tk)
    result = await execute_ssh.run(
        argv, toolkit=tk, credentials=credentials,
        timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_OK
    assert result.exit_code == 0
    assert "ran: /usr/bin/uptime -a" in result.stdout


async def test_argv_elements_are_shell_quoted(toolkit, credentials):
    """A parameter value with shell metacharacters must arrive as ONE

    literal token server-side, not break out into a second command.
    """
    tk, tier1 = toolkit
    tool = _tool(
        tier1,
        parameters={"arg": {"type": "string", "pattern": "^.*$", "required": True}},
    )
    dangerous = "; rm -rf / #"
    argv = validate.build_argv(tool, {"arg": dangerous}, tk)
    result = await execute_ssh.run(
        argv, toolkit=tk, credentials=credentials,
        timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_OK
    # The server echoed back the exact command string it received --
    # confirming the dangerous value was quoted into one token, not split.
    assert f"ran: /usr/bin/uptime {execute_ssh.shlex.quote(dangerous)}" in result.stdout


async def test_wrong_host_key_is_refused(tmp_path, ssh_server, credentials):
    path = tmp_path / "toolkits-wrong.yaml"
    other_host_key = asyncssh.generate_private_key("ssh-ed25519")
    wrong_known_hosts = f"127.0.0.1 {other_host_key.export_public_key().decode().strip()}"
    path.write_text(
        f"""
toolkits:
  demo_ssh:
    executor: ssh
    ssh_host: "127.0.0.1"
    ssh_port: {ssh_server["port"]}
    ssh_user: "gatekeeper"
    ssh_known_hosts: "{wrong_known_hosts}"
    binaries: ["/usr/bin/uptime"]
    credential: demo_ssh_key
audit:
  dir: {tmp_path / 'logs'}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("demo_ssh")
    tool = _tool(tier1)
    argv = validate.build_argv(tool, {"arg": "-a"}, tk)
    result = await execute_ssh.run(
        argv, toolkit=tk, credentials=credentials,
        timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "host key" in result.stderr.lower() or "mitm" in result.stderr.lower()


async def test_missing_credential_denied(toolkit):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    argv = validate.build_argv(tool, {"arg": "-a"}, tk)
    result = await execute_ssh.run(
        argv, toolkit=tk, credentials=None,
        timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED


async def test_wrong_client_key_is_refused(tmp_path, toolkit, monkeypatch):
    tk, tier1 = toolkit
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    other_key = asyncssh.generate_private_key("ssh-ed25519")
    audit = AuditLog(str(tmp_path / "logs3"))
    store = CredentialStore(path=str(tmp_path / "credentials-wrong.yaml"), audit=audit)
    store.create(
        "demo_ssh_key", kind="ssh_private_key",
        value=other_key.export_private_key().decode(), actor="test", rev="",
    )
    tool = _tool(tier1)
    argv = validate.build_argv(tool, {"arg": "-a"}, tk)
    result = await execute_ssh.run(
        argv, toolkit=tk, credentials=store,
        timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED


async def test_timeout_on_non_idempotent_is_unknown(toolkit, credentials):
    tk, tier1 = toolkit
    tool = _tool(tier1, id="demo_ssh.slow", category="write", idempotent=False)
    argv = validate.build_argv(tool, {"arg": "slow"}, tk)
    # Craft a command the fake server's handler recognizes as "slow".
    argv[0] = "true; slow"
    result = await execute_ssh.run(
        ["true; slow"], toolkit=tk, credentials=credentials,
        timeout_seconds=0.3, max_output_bytes=65536, idempotent=False,
    )
    assert result.outcome == OUTCOME_UNKNOWN


async def test_denied_binary_rejected_before_send(toolkit):
    tk, tier1 = toolkit
    with pytest.raises(Exception):
        _tool(tier1, id="demo_ssh.evil", binary="/usr/bin/does-not-exist")


async def test_denied_arg_rejected_at_build_time(toolkit):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    from gatekeeper.errors import Denied

    with pytest.raises(Denied):
        validate.build_argv(tool, {"arg": "--evil"}, tk)


async def test_probe_reachable(toolkit):
    tk, _ = toolkit
    assert await execute_ssh.probe(tk) is True


async def test_probe_unreachable(tmp_path):
    path = tmp_path / "toolkits-unreachable.yaml"
    path.write_text(
        """
toolkits:
  demo_ssh:
    executor: ssh
    ssh_host: "127.0.0.1"
    ssh_port: 1
    ssh_user: "gatekeeper"
    ssh_known_hosts: "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVALIDKEYVALUEXXXXXXXXXXXXXXXXXXXXXXXXX"
    binaries: ["/usr/bin/uptime"]
audit:
  dir: /tmp/gk-test-logs
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("demo_ssh")
    assert await execute_ssh.probe(tk) is False
