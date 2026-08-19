"""The `truenas` executor (REQUIREMENTS.md §8, FR-8.3a-f).

TrueNAS's REST API v2.0 is deprecated as of 25.04 and removed in TrueNAS 26;
the authoritative interface is JSON-RPC 2.0 over WebSocket. This is why
`truenas` is its own executor rather than an `http` toolkit: the whitelist
here acts on *method names* (`pool.dataset.create`, `pool.query`) instead
of binaries or path prefixes, and parameters travel as JSON-RPC params,
not as a string that could be concatenated (FR-8.3d) -- the injection
question does not arise structurally, the same way it does not for argv.

Each call opens its own connection, authenticates, sends one request, and
closes -- simpler than a pooled/reconnecting connection manager, and
correct: TrueNAS calls in this catalog are infrequent diagnostic/management
operations, not a hot path where connection setup cost matters. A pooled
connection is a valid later optimization; it would not change the tool
definition contract (method + params) at all.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

import websockets

from .credentials import CredentialStore, ResolvedCredential
from .errors import Denied, DenialReason
from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result
from .tier1 import Toolkit

#: TrueNAS's JSON-RPC auth method for a static API key (FR-8.3e). SCRAM-
#: SHA-512 mutual auth is TrueNAS 26's preferred alternative where
#: available; it is not implemented here -- api key auth is the baseline
#: this module ships with, not a permanent ceiling.
_AUTH_METHOD = "auth.login_with_api_key"


async def _authenticate(
    ws: Any, credential: ResolvedCredential | None, timeout_seconds: float
) -> None:
    if credential is None:
        return
    request_id = str(uuid.uuid4())
    await ws.send(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "method": _AUTH_METHOD,
                "params": [credential.value],
                "id": request_id,
            }
        )
    )
    raw = await asyncio.wait_for(ws.recv(), timeout=timeout_seconds)
    response = json.loads(raw)
    if response.get("error") or not response.get("result"):
        raise Denied(
            DenialReason.CREDENTIAL_UNAVAILABLE, "TrueNAS authentication failed."
        )


async def run(
    *,
    method: str,
    params: dict[str, str],
    toolkit: Toolkit,
    credentials: CredentialStore | None,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    redact: Any = None,
) -> Result:
    assert toolkit.ws_url is not None
    started = time.monotonic()

    def _denied(denial: Denied) -> Result:
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=denial.agent_message,
            truncated=False,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    # Defensive re-check (FR-8.3c): `method` is fixed per tool, not
    # agent-suppliable, so this can only fail on a programming error --
    # kept for the same reason `build_argv` re-checks `check_binary`.
    if not toolkit.allows_rpc_method(method):
        return _denied(
            Denied(
                DenialReason.RPC_METHOD_DENIED,
                f"RPC method {method!r} is not allowed for this toolkit.",
            )
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

    try:
        ws = await asyncio.wait_for(
            websockets.connect(toolkit.ws_url), timeout=timeout_seconds
        )
    except (OSError, TimeoutError, asyncio.TimeoutError) as exc:
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=f"Could not connect to {toolkit.ws_url}: {exc}",
            truncated=False,
            duration_ms=int((time.monotonic() - started) * 1000),
            external_untrusted=True,
        )

    try:
        try:
            await _authenticate(ws, credential, timeout_seconds)
        except Denied as denial:
            return _denied(denial)

        request_id = str(uuid.uuid4())
        # FR-8.3d: params are JSON-RPC params, never string-concatenated.
        # A `params_template` is an ordered name->value mapping in the
        # tool definition; it is sent positionally, in declaration order,
        # matching how TrueNAS's JSON-RPC methods take positional args.
        await ws.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": list(params.values()),
                    "id": request_id,
                }
            )
        )
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout_seconds)
        except (asyncio.TimeoutError, TimeoutError):
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
                        "UNKNOWN: the call may have reached TrueNAS. Do not "
                        "retry without checking the state first."
                    )
                ),
                truncated=False,
                duration_ms=duration,
                external_untrusted=True,
            )
    except websockets.exceptions.WebSocketException as exc:
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=f"Connection error: {exc}",
            truncated=False,
            duration_ms=int((time.monotonic() - started) * 1000),
            external_untrusted=True,
        )
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001 -- best-effort cleanup only
            pass

    text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
    encoded = text.encode("utf-8")
    truncated = len(encoded) > max_output_bytes
    if truncated:
        text = encoded[:max_output_bytes].decode("utf-8", errors="replace")

    try:
        response = json.loads(text)
    except ValueError:
        response = None

    if isinstance(response, dict) and response.get("error"):
        outcome = OUTCOME_FAILED
        exit_code = 1
        stdout = ""
        stderr = json.dumps(response["error"], ensure_ascii=False)
    elif isinstance(response, dict):
        outcome = OUTCOME_OK
        exit_code = 0
        stdout = json.dumps(response.get("result"), ensure_ascii=False)
        stderr = ""
    else:
        outcome = OUTCOME_FAILED
        exit_code = None
        stdout = text
        stderr = "Response was not a JSON-RPC object."

    if redact is not None:
        stdout = redact(stdout)
        stderr = redact(stderr)

    return Result(
        outcome=outcome,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
        duration_ms=int((time.monotonic() - started) * 1000),
        external_untrusted=True,
    )


async def probe(toolkit: Toolkit) -> bool:
    """TCP/WebSocket-handshake reachability only, for /health/ready."""
    assert toolkit.ws_url is not None
    try:
        ws = await asyncio.wait_for(websockets.connect(toolkit.ws_url), timeout=5)
        await ws.close()
        return True
    except Exception:  # noqa: BLE001 -- any failure means "not ready"
        return False
