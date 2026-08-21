"""The `ssh` executor (REQUIREMENTS.md §17, optional).

A tool on an `ssh` toolkit is shaped exactly like a `docker`/`local` one --
`validate.build_argv` already builds and Tier-1-checks its argv, so this
module's only job is to run that same resolved argv on a remote host
instead of a local subprocess.

That reuse comes with one real difference to guard against: `execute.py`'s
local `create_subprocess_exec` never involves a shell (`shell=False`, a true
argv, FR-6.1). SSH's exec channel (RFC 4254 §6.5) sends the server a single
command *string*, and the near-universal server-side behaviour (OpenSSH
included) is to hand that string to the remote user's login shell --
there is no portable way to ask an sshd to skip this. So unlike every other
executor here, this one runs through a shell, structurally -- the mitigation
is that each argv element is `shlex.quote`d before being joined into that
string, which is the correct way to neutralise shell metacharacters in a
value the allowlist pattern already restricted (defense in depth, not the
primary control).

Host-key verification is mandatory, not optional (see `tier1.py`'s
`ssh_known_hosts` field): an SSH connection that accepts any host key is
trivially MITM-able, which is the same class of gap FR-8.9's DNS-rebinding
check exists to close for the `http` executor.
"""

from __future__ import annotations

import asyncio
import shlex
import time
from typing import Any

import asyncssh

from .credentials import CredentialStore, ResolvedCredential
from .errors import DenialReason, Denied
from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result
from .tier1 import Toolkit


async def _connect(toolkit: Toolkit, credential: ResolvedCredential | None, timeout_seconds: float):
    assert toolkit.ssh_host is not None
    client_keys = None
    if credential is not None:
        client_keys = [asyncssh.import_private_key(credential.value)]
    # `known_hosts=<str>` is treated by asyncssh as a *filename* to open --
    # `import_known_hosts` is what turns the pinned `known_hosts`-format
    # text in Tier 1 into the in-memory object form `connect()` needs to
    # actually verify against, instead of trying (and failing) to open it
    # as a path on disk.
    known_hosts = asyncssh.import_known_hosts(toolkit.ssh_known_hosts or "")
    return await asyncio.wait_for(
        asyncssh.connect(
            toolkit.ssh_host,
            port=toolkit.ssh_port,
            username=toolkit.ssh_user,
            known_hosts=known_hosts,
            client_keys=client_keys,
            # No interactive prompts exist in this process -- a key that
            # needs a passphrase or a server that falls back to
            # keyboard-interactive/password auth must fail closed, not hang.
            preferred_auth=["publickey"] if client_keys else ["none"],
        ),
        timeout=timeout_seconds,
    )


async def run(
    argv: list[str],
    *,
    toolkit: Toolkit,
    credentials: CredentialStore | None,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    redact: Any = None,
) -> Result:
    started = time.monotonic()

    def _denied(denial: Denied) -> Result:
        # Mirrors execute_http.py/execute_truenas.py: a rejection here
        # (missing credential, unreachable host) happens after
        # `service.call()`'s own validation try/except has closed, so it
        # is reported as a Result to stay inside the normal audit
        # bookkeeping instead of escaping as a bare exception.
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=denial.agent_message,
            truncated=False,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    credential: ResolvedCredential | None = None
    if toolkit.credential:
        if credentials is None:
            return _denied(
                Denied(
                    DenialReason.CREDENTIAL_UNAVAILABLE,
                    "No credential store is configured, but this toolkit needs one.",
                )
            )
        credential = credentials._resolve(toolkit.credential)
        if credential is None:
            return _denied(
                Denied(
                    DenialReason.CREDENTIAL_UNAVAILABLE,
                    f"Credential {toolkit.credential!r} is not configured yet.",
                )
            )
        if credential.kind != "ssh_private_key":
            return _denied(
                Denied(
                    DenialReason.CREDENTIAL_UNAVAILABLE,
                    f"Credential {toolkit.credential!r} is not an ssh_private_key credential.",
                )
            )

    # FR-6.1's guarantee (no shell) cannot hold structurally over SSH (see
    # module docstring) -- shlex.quote is the defense-in-depth substitute:
    # each element becomes one shell-safe token, so a value cannot inject
    # an extra command via ';'/'&&'/backticks/etc. even though it is,
    # unavoidably, being parsed by a shell on the other end.
    command = " ".join(shlex.quote(part) for part in argv)

    try:
        async with await _connect(toolkit, credential, timeout_seconds) as conn:
            proc = await asyncio.wait_for(
                conn.run(command, check=False), timeout=timeout_seconds
            )
    except TimeoutError:
        duration = int((time.monotonic() - started) * 1000)
        return Result(
            outcome=OUTCOME_FAILED if idempotent else OUTCOME_UNKNOWN,
            exit_code=None,
            stdout="",
            stderr=(
                f"Timeout of {timeout_seconds}s exceeded."
                if idempotent
                else (
                    f"Timeout of {timeout_seconds}s exceeded. The outcome is "
                    "UNKNOWN: the command may have run on the remote host. Do "
                    "not retry without checking the state first."
                )
            ),
            truncated=False,
            duration_ms=duration,
        )
    except asyncssh.HostKeyNotVerifiable as exc:
        return _denied(
            Denied(
                DenialReason.SSRF_BLOCKED,
                f"Host key for {toolkit.ssh_host} did not match ssh_known_hosts "
                f"-- refusing to connect (possible MITM): {exc}",
            )
        )
    except (asyncssh.Error, OSError) as exc:
        duration = int((time.monotonic() - started) * 1000)
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=f"SSH connection failed: {exc}",
            truncated=False,
            duration_ms=duration,
        )

    stdout = proc.stdout if isinstance(proc.stdout, str) else (proc.stdout or b"").decode(
        "utf-8", errors="replace"
    )
    stderr = proc.stderr if isinstance(proc.stderr, str) else (proc.stderr or b"").decode(
        "utf-8", errors="replace"
    )
    truncated = False
    if len(stdout.encode("utf-8")) > max_output_bytes:
        stdout = stdout.encode("utf-8")[:max_output_bytes].decode("utf-8", errors="replace")
        truncated = True
    if len(stderr.encode("utf-8")) > max_output_bytes:
        stderr = stderr.encode("utf-8")[:max_output_bytes].decode("utf-8", errors="replace")
        truncated = True

    if redact is not None:
        stdout = redact(stdout)
        stderr = redact(stderr)

    exit_status = proc.exit_status
    return Result(
        outcome=OUTCOME_OK if exit_status == 0 else OUTCOME_FAILED,
        exit_code=exit_status,
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


async def probe(toolkit: Toolkit) -> bool:
    """TCP-connect only, for /health/ready -- no SSH handshake or auth.

    Mirrors `execute_http.py`'s probe (same rationale: reaching the target
    port is what a liveness check can honestly claim without a real call).
    A full SSH auth attempt would need this toolkit's actual credential
    just to answer a reachability question -- `probe()`'s signature has no
    credential store to resolve one from, matching `execute_http.probe`/
    `execute_truenas.probe`, neither of which authenticate either.
    """
    assert toolkit.ssh_host is not None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(toolkit.ssh_host, toolkit.ssh_port), timeout=5
        )
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True
    except (OSError, TimeoutError):
        return False
