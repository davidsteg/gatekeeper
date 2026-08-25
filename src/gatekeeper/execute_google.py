"""The `google` executor (REQUIREMENTS.md §8, FR-8.3a-f counterpart).

The `google_api.py` CLI is a thin wrapper around the Google REST APIs
(gmail, calendar, drive) that authenticates via an OAuth2 token file and
emits JSON on stdout. This executor runs it as a local subprocess -- the
same argv model as `local`/`docker` (FR-5.3/5.4/6.1, `shell=False`) --
and parses the JSON output, capping list length the way `execute_http`
does for REST responses (FR-8.12).

Why a separate executor rather than a `local` toolkit: three properties
the `local` executor does not provide, all already present as patterns
elsewhere in this codebase:

1. `external_untrusted=True` -- Google responses (mail bodies, event
   descriptions) are external, potentially prompt-injection-bearing
   data, the same way an HTTP response is (FR-8.12, execute.py:40).
2. JSON output capping via `_cap_json` -- `gmail search` can return
   thousands of messages, the same list-length risk a Sonarr `GET
   /api/v3/series` carries (execute_http.py:130-150).
3. An action-string whitelist per toolkit -- `allowed_google_actions`
   mirrors `allowed_rpc_methods` for the truenas executor (FR-8.3c):
   `gmail send` simply never appears in a read-only gmail toolkit's
   list, so there is no separate permission to deny it.

The OAuth credential is *not* passed through argv (FR-10.2: a secret
never sits in a process argument list that a `ps` on the host would
reveal). The caller (`service.py`) materializes the `oauth2` credential
bundle to a per-call tempfile (chmod 600) and points the subprocess at
it via `HOME` -- google_api.py reads `~/.hermes/google_token.json` from
there. The tempfile is removed after the call, mirroring
`service.py:_docker_tls_env`'s cert materialization pattern.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any

from .errors import DenialReason, Denied
from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result
from .execute_http import MAX_JSON_ITEMS, _cap_json
from .tier1 import Toolkit


def _build_argv(toolkit: Toolkit, google_action: str, args: list[str]) -> list[str]:
    """Assembles the full argv list.

    `google_action` is a fixed string like ``"gmail search"`` (not
    agent-suppliable); `args` is the per-call tail built by
    `validate.build_google_call`. The binary that runs is the same
    interpreter that is running gatekeeper (`sys.executable`, the same
    idiom `conftest.py`'s `PYTHON` uses) -- never a bare `python`, which
    some environments resolve to `python3` and some don't resolve at all.
    `google_script` is the script path; `google_container` (optional)
    switches the call to ``docker exec <container> python <script> ...``
    for a deployment that keeps google_api.py in another container on the
    same host.
    """
    assert toolkit.google_script is not None
    action_parts = google_action.split()
    if toolkit.google_container:
        return [
            "docker", "exec", toolkit.google_container,
            "python", toolkit.google_script, *action_parts, *args,
        ]
    return [sys.executable, toolkit.google_script, *action_parts, *args]


def _interpret_exit(
    exit_code: int | None, stdout: str, stderr: str
) -> tuple[str, str, str]:
    """Turns a google_api.py exit into (outcome, stdout, stderr).

    google_api.py exits 0 on success and non-zero on failure, with a
    JSON error object on stderr for API-level failures (401 token
    expired, 403 insufficient_scope). A non-JSON stderr line is a
    usage/transport error -- reported plainly, not as a denial.
    """
    if exit_code == 0:
        return OUTCOME_OK, stdout, stderr

    # Try to parse a structured error from stderr for a clear message.
    detail = stderr.strip()
    try:
        err = json.loads(detail)
    except (ValueError, TypeError):
        err = None
    if isinstance(err, dict):
        msg = err.get("message") or err.get("error") or detail
        code = err.get("code") or err.get("status")
        if code in (401, "UNAUTHENTICATED") or "invalid_grant" in str(msg):
            return (
                OUTCOME_FAILED,
                "",
                f"Google authentication failed (token expired or revoked): {msg}. "
                "Re-run the OAuth consent flow to obtain a new refresh token.",
            )
        if code in (403, "PERMISSION_DENIED") or "insufficient" in str(msg).lower():
            return (
                OUTCOME_FAILED,
                "",
                f"Google denied the request: scope not covered by the refresh "
                f"token ({msg}). Re-authorize with the additional scope, or "
                "grant the identity the required scope.",
            )
        return (OUTCOME_FAILED, "", f"Google API error ({code}): {msg}")

    return (OUTCOME_FAILED, "", detail or f"google_api.py exited {exit_code}")


async def run(
    *,
    google_action: str,
    args: list[str],
    toolkit: Toolkit,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    env: dict[str, str] | None = None,
    redact: Any = None,
) -> Result:
    """Runs google_api.py as a subprocess and parses its JSON output.

    `env` carries the materialized OAuth token path (via HOME) -- built
    by `service.py`'s `_google_token_env`, the same way
    `_docker_tls_env` builds the cert-path env for a TLS-secured docker
    destination. Never passed through argv (FR-10.2).
    """
    assert toolkit.google_script is not None
    started = time.monotonic()

    # Defensive re-check (FR-8.3c's google counterpart): `google_action`
    # is fixed per tool, not agent-suppliable, so this can only fail on a
    # programming error -- kept for the same reason `build_argv` re-checks
    # `check_binary`.
    if not toolkit.allows_google_action(google_action):
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=f"Google action {google_action!r} is not allowed for this toolkit.",
            truncated=False,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    argv = _build_argv(toolkit, google_action, args)

    # `execute.run` gives us the no-shell, timeout, output-capping
    # machinery for free -- the same one `local`/`docker` use. We pass
    # the token env through it; the child never inherits gatekeeper's
    # own env (execute.run builds the env from scratch).
    try:
        result = await asyncio.wait_for(
            _run_subprocess(argv, env, timeout_seconds, max_output_bytes),
            timeout=timeout_seconds,
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
                    "UNKNOWN: the call may have reached Google. Do not "
                    "retry without checking the state first."
                )
            ),
            truncated=False,
            duration_ms=duration,
            external_untrusted=True,
        )
    except Denied as denial:
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=denial.agent_message,
            truncated=False,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    outcome, stdout_text, stderr_text = _interpret_exit(
        result.exit_code, result.stdout, result.stderr
    )

    # Parse JSON stdout and cap list length (FR-8.12's google counterpart).
    if outcome == OUTCOME_OK and stdout_text and not result.truncated:
        try:
            parsed = json.loads(stdout_text)
            capped = _cap_json(parsed, limit=MAX_JSON_ITEMS, budget=[MAX_JSON_ITEMS])
            stdout_text = json.dumps(capped, ensure_ascii=False)
        except (ValueError, TypeError):
            pass  # not JSON -- leave as-is (google_api.py should always emit JSON)

    if redact is not None:
        stdout_text = redact(stdout_text)
        stderr_text = redact(stderr_text)

    return Result(
        outcome=outcome,
        exit_code=result.exit_code,
        stdout=stdout_text,
        stderr=stderr_text,
        truncated=result.truncated,
        duration_ms=result.duration_ms,
        external_untrusted=True,
    )


async def _run_subprocess(
    argv: list[str],
    env: dict[str, str] | None,
    timeout_seconds: int,
    max_output_bytes: int,
) -> Result:
    """Runs the subprocess and reads capped output.

    Deliberately not reusing `execute.run` directly: that function wraps
    the binary in `_unpriv` when ambient capabilities are present, which
    is correct for `local`/`docker` tools but wrong here -- google_api.py
    is a Python script, not an allowlisted binary, and the capability
    wrapper would reject it. The subprocess machinery itself (no shell,
    capped reads, timeout kill) is the part we need, replicated here.
    """
    import sys

    popen_kwargs: dict[str, object] = {}
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True

    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            env=env,
            **popen_kwargs,  # type: ignore[arg-type]
        )
    except FileNotFoundError as exc:
        raise Denied(
            DenialReason.EXECUTOR_UNAVAILABLE,
            f"Executable not found: {argv[0]}",
        ) from exc
    except PermissionError as exc:
        raise Denied(
            DenialReason.EXECUTOR_UNAVAILABLE,
            f"No permission to execute {argv[0]}",
        ) from exc

    started = time.monotonic()

    async def _read_capped(
        stream: asyncio.StreamReader | None, limit: int
    ) -> tuple[bytes, bool]:
        if stream is None:
            return b"", False
        chunks: list[bytes] = []
        total = 0
        truncated = False
        while True:
            chunk = await stream.read(8192)
            if not chunk:
                break
            if total + len(chunk) > limit:
                chunks.append(chunk[: limit - total])
                truncated = True
                while await stream.read(65536):
                    pass
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks), truncated

    (out_bytes, out_trunc), (err_bytes, err_trunc) = await asyncio.gather(
        _read_capped(process.stdout, max_output_bytes),
        _read_capped(process.stderr, max_output_bytes),
    )
    await process.wait()

    return Result(
        outcome=OUTCOME_OK if process.returncode == 0 else OUTCOME_FAILED,
        exit_code=process.returncode,
        stdout=out_bytes.decode("utf-8", errors="replace"),
        stderr=err_bytes.decode("utf-8", errors="replace"),
        truncated=out_trunc or err_trunc,
        duration_ms=int((time.monotonic() - started) * 1000),
        external_untrusted=True,
    )


async def probe(toolkit: Toolkit) -> bool:
    """For /health/ready: checks the script file exists (and, if
    google_container is set, that `docker` is reachable). Does not run
    google_api.py -- a health check must not have side effects, and
    authenticating against Google on every probe would be both slow and
    a token-rotation risk.
    """
    assert toolkit.google_script is not None
    if toolkit.google_container:
        # `docker` present and the container running is enough -- the
        # script path is checked inside the container on first real use.
        try:
            result = await asyncio.create_subprocess_exec(
                "docker", "ps", "--filter", f"name={toolkit.google_container}",
                "--format", "{{.Names}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(result.wait(), timeout=5)
            return result.returncode == 0
        except (OSError, TimeoutError):
            return False
    return os.path.isfile(toolkit.google_script) and os.access(
        toolkit.google_script, os.R_OK
    )