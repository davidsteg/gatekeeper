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
    password = None
    if credential is not None:
        if credential.kind == "ssh_password":
            password = credential.value
        else:
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
            password=password,
            # No interactive prompts exist in this process -- a key that
            # needs a passphrase or a server that falls back to
            # keyboard-interactive/password auth must fail closed, not hang.
            # `client_keys=None` is also load-bearing for password auth:
            # asyncssh would otherwise offer a default identity from
            # ~/.ssh if any, before ever trying the password.
            preferred_auth=["password"] if password else (
                ["publickey"] if client_keys else ["none"]
            ),
        ),
        timeout=timeout_seconds,
    )


def _split_args_elements(argv: list[str], tool: Any) -> list[str]:
    """An `{args}` element is a shell-like token string, not one token.

    FR-5.4's "exactly one argv element per template element" is what
    `validate.build_argv` guarantees, and it is right for every ordinary
    parameter -- a value with spaces or metacharacters must stay one
    literal token (that is what `test_argv_elements_are_shell_quoted`
    pins). A template element that is *only* `{args}` is the one
    deliberate exception: its value is a trailing argument *string*
    (`--oneline -3`), so quoting it whole hands the remote binary a
    single unrecognised argument, and an empty value hands it a stray
    empty token (`git status ''` -> "empty string is not a valid
    pathspec"). Splitting it here, at the one place the remote command
    string is assembled, gives `shlex.split` semantics: multiple tokens
    stay multiple tokens, quotes inside the value still group, and an
    empty/blank value contributes no element at all.

    Only a bare `{args}` element is split -- a template that merely
    embeds it (`--pretty={args}`) is a single-value element like any
    other and is left untouched.
    """
    templates = list(getattr(tool, "argv", None) or [])
    # argv is [binary, *one element per template]. Anything else is not
    # a `build_argv` product (the dispatch test hands `run` a crafted
    # argv), and there is then no template to attribute an element to.
    if len(argv) != len(templates) + 1:
        return argv
    out = [argv[0]]
    for template, element in zip(templates, argv[1:], strict=True):
        if template != "{args}":
            out.append(element)
            continue
        try:
            args_tokens = shlex.split(element) if element and element.strip() else []
        except ValueError as exc:
            # Unbalanced quote: refuse rather than silently fall back to
            # the old one-token behaviour, which would reach the remote
            # binary as an unexplainable single argument.
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"args {element!r} is not a parseable argument string: {exc}",
            ) from exc
        out.extend(args_tokens)
    return out


async def run(
    argv: list[str],
    *,
    toolkit: Toolkit,
    credentials: CredentialStore | None,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    redact: Any = None,
    tool: Any = None,
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
        if credential.kind not in ("ssh_private_key", "ssh_password"):
            return _denied(
                Denied(
                    DenialReason.CREDENTIAL_UNAVAILABLE,
                    f"Credential {toolkit.credential!r} is not an ssh_private_key "
                    "or ssh_password credential.",
                )
            )

    try:
        argv = _split_args_elements(argv, tool)
    except Denied as denial:
        return _denied(denial)
    # The split can create argv elements Tier 1 never saw (`build_argv`
    # checked the unsplit `{args}` string), so a denied_args flag hidden
    # inside it would otherwise become a real flag on the remote side.
    if denied_arg := toolkit.check_args(argv):
        return _denied(
            Denied(
                DenialReason.TIER1_VIOLATION,
                f"Argument {denied_arg!r} is denied for this toolkit.",
            )
        )

    # FR-6.1's guarantee (no shell) cannot hold structurally over SSH (see
    # module docstring) -- shlex.quote is the defense-in-depth substitute:
    # each element becomes one shell-safe token, so a value cannot inject
    # an extra command via ';'/'&&'/backticks/etc. even though it is,
    # unavoidably, being parsed by a shell on the other end.
    command = " ".join(shlex.quote(part) for part in argv)
    if getattr(tool, 'ssh_dispatch', False):
        # setsid, not bare nohup: nohup only ignores SIGHUP, so when the
        # sshd session tears down (e.g. the recreated container dies mid
        # `compose up`) the whole process group still takes the SIGKILL.
        # A new session detaches the dispatched process from that group.
        # inner nohup sh -c re-applies SIGHUP immunity; --wait health-gates the beacon
        if any(part == 'compose' for part in argv):
            beacon = (shlex.quote(command + ' --wait')
                      + ' </dev/null >>/tmp/gatekeeper-recreate.log 2>&1; '
                        'echo EXIT=$? >>/tmp/gatekeeper-recreate.log')
            command = ('setsid nohup sh -c '
                       + shlex.quote('nohup sh -c ' + shlex.quote(beacon))
                       + ' & echo dispatched')
        else:
            command = 'setsid nohup ' + command + ' </dev/null >>/tmp/gatekeeper-dispatch.log 2>&1 & echo dispatched'

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
