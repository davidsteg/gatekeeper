"""The `microsoft` executor -- the Outlook/Graph counterpart of `google`.

`_microsoft_api/microsoft_api.py` is a thin stdlib-only wrapper around
Microsoft Graph's mail endpoints that authenticates with an OAuth2 token
file and emits JSON on stdout. This executor runs it as a local
subprocess -- the same argv model as `local`/`docker`/`google`
(FR-5.3/5.4/6.1, `shell=False`) -- and parses the JSON output, capping
list length the way `execute_http` does for REST responses (FR-8.12).

Everything `execute_google.py`'s docstring says about why this is a
separate executor rather than a `local` toolkit holds here unchanged:
Graph responses are `external_untrusted=True` (a mail body is the
canonical prompt-injection carrier), `_cap_json` bounds a mailbox
listing the way it bounds a Sonarr series list, and
`allowed_microsoft_actions` is a per-toolkit whitelist of action strings
-- `mail send` simply never appears in a read-only mailbox toolkit's
list, so there is no separate permission to deny it.

The OAuth credential is *not* passed through argv (FR-10.2). The caller
(`service.py`) materializes the `oauth2` credential bundle to a per-call
tempfile (chmod 600) and points the subprocess at it via `HOME` --
microsoft_api.py reads `~/.hermes/microsoft_token.json` from there.

The subprocess machinery itself is `execute_google._run_subprocess`,
imported rather than copied: it is already the "no shell, capped reads,
timeout kill, no `_unpriv` wrapper" runner both vendored CLIs need, and
a second copy would be a second place to fix. Same direction of reuse as
`execute_google`'s own import of `execute_http._cap_json`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
from typing import Any

from .errors import Denied
from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result
from .execute_google import _run_subprocess
from .execute_http import MAX_JSON_ITEMS, _cap_json
from .tier1 import MICROSOFT_FALLBACK_SCRIPT, Toolkit

logger = logging.getLogger("gatekeeper")


def _resolve_script(toolkit: Toolkit, *, warn: bool) -> str:
    """The script path this call actually runs.

    Normally the toolkit's own `microsoft_script`; the image's own copy
    (`tier1.MICROSOFT_FALLBACK_SCRIPT`) stands in when that path does not
    exist on this filesystem. Same rule and same reasoning as
    `execute_google._resolve_script`: a toolkit naming a path this image
    does not have would otherwise die on a FileNotFound that names only
    the path that is wrong, never the one that would work.

    Not applied to a `microsoft_container` toolkit: there the script
    lives on another container's filesystem, so this filesystem has no
    opinion about whether the configured path exists.

    `warn=False` is for `probe`, which asks the same question for
    readiness and must not turn a health check into a log line per poll.
    """
    assert toolkit.microsoft_script is not None
    configured = toolkit.microsoft_script
    if toolkit.microsoft_container:
        return configured
    if os.path.isfile(configured):
        return configured
    if not os.path.isfile(MICROSOFT_FALLBACK_SCRIPT):
        return configured
    if warn:
        logger.warning(
            "Toolkit %r: microsoft_script %s does not exist -- falling back to "
            "the image's copy at %s. Update microsoft_script in toolkits.yaml "
            "so the configuration names the script that actually runs.",
            toolkit.name,
            configured,
            MICROSOFT_FALLBACK_SCRIPT,
        )
    return MICROSOFT_FALLBACK_SCRIPT


#: The services microsoft_api.py dispatches on. Its argv is
#: ``microsoft_api.py <service> <action> [args]``, so `mail list` is a
#: listing of messages while a bare `list` is a usage error.
MICROSOFT_SERVICES = ("mail",)

#: The service a bare action runs under when the toolkit name says
#: nothing. Unlike google -- where `gmail`, `calendar` and `drive` are
#: three different CLIs behind one script and guessing would be wrong --
#: Graph mail is the only service this script has, so the one answer is
#: also the correct one. This constant is what a second service would
#: have to displace.
DEFAULT_MICROSOFT_SERVICE = "mail"


def _service_prefix(toolkit: Toolkit) -> str:
    """The CLI service token this toolkit's actions run under.

    Taken from the toolkit name where it names a service (`mail`), so a
    toolkit called `outlook-mail` and one called `mail` resolve the same
    way; otherwise `DEFAULT_MICROSOFT_SERVICE`, because there is exactly
    one service to resolve to. A toolkit named `outlook` therefore works
    without spelling `mail` into every action string.
    """
    for part in re.split(r"[^a-z0-9]+", toolkit.name.lower()):
        if part in MICROSOFT_SERVICES:
            return part
    return DEFAULT_MICROSOFT_SERVICE


def _action_argv(toolkit: Toolkit, microsoft_action: str) -> list[str]:
    """`microsoft_action` as argv words, with the service token in front.

    An action that already names its service (`mail list`, the form
    config/examples/toolkits.yaml uses) is passed through untouched --
    prefixing it again would run `mail mail list`. A bare action (`list`,
    `send`) gets the toolkit's service inserted before it; flags and
    positional args in `args` are never touched, since only the head of
    the argv is in question here.
    """
    parts = microsoft_action.split()
    if not parts or parts[0] in MICROSOFT_SERVICES:
        return parts
    return [_service_prefix(toolkit), *parts]


def _build_argv(toolkit: Toolkit, microsoft_action: str, args: list[str]) -> list[str]:
    """Assembles the full argv list.

    `microsoft_action` is a fixed string like ``"mail list"`` (not
    agent-suppliable); `args` is the per-call tail built by
    `validate.build_microsoft_call`. The binary that runs is the same
    interpreter running gatekeeper (`sys.executable`) -- never a bare
    `python`. `microsoft_container` (optional) switches the call to
    ``docker exec <container> python <script> ...`` for a deployment that
    keeps the script in another container on the same host.
    """
    assert toolkit.microsoft_script is not None
    action_parts = _action_argv(toolkit, microsoft_action)
    script = _resolve_script(toolkit, warn=True)
    if toolkit.microsoft_container:
        return [
            "docker", "exec", toolkit.microsoft_container,
            "python", script, *action_parts, *args,
        ]
    return [sys.executable, script, *action_parts, *args]


def _interpret_exit(
    exit_code: int | None, stdout: str, stderr: str
) -> tuple[str, str, str]:
    """Turns a microsoft_api.py exit into (outcome, stdout, stderr).

    The script exits 0 on success and non-zero on failure, with a JSON
    error object on stderr (`{"code", "message"}`) -- the same contract
    google_api.py has, so this reads it the same way. A non-JSON stderr
    line is a usage/transport error, reported plainly.

    The two cases worth their own sentence are the two an operator can
    actually act on: a dead grant (re-consent) and a missing scope
    (re-consent asking for more). Graph spells the second
    `ErrorAccessDenied`/`insufficient` rather than Google's
    `PERMISSION_DENIED`, which is the only real difference.
    """
    if exit_code == 0:
        return OUTCOME_OK, stdout, stderr

    detail = stderr.strip()
    try:
        err = json.loads(detail)
    except (ValueError, TypeError):
        err = None
    if isinstance(err, dict):
        msg = err.get("message") or err.get("error") or detail
        code = err.get("code") or err.get("status")
        if code in (401, "401", "InvalidAuthenticationToken") or "invalid_grant" in str(msg):
            return (
                OUTCOME_FAILED,
                "",
                f"Microsoft authentication failed (token expired or revoked): {msg}. "
                "Re-run the OAuth consent flow from the console to obtain a new "
                "refresh token.",
            )
        if (
            code in (403, "403", "ErrorAccessDenied")
            or "insufficient" in str(msg).lower()
            or "invalid_scope" in str(msg)
        ):
            return (
                OUTCOME_FAILED,
                "",
                f"Microsoft denied the request: scope not covered by the refresh "
                f"token ({msg}). Re-authorize with the additional scope, or "
                "grant the identity the required scope.",
            )
        return (OUTCOME_FAILED, "", f"Microsoft Graph error ({code}): {msg}")

    return (OUTCOME_FAILED, "", detail or f"microsoft_api.py exited {exit_code}")


async def run(
    *,
    microsoft_action: str,
    args: list[str],
    toolkit: Toolkit,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    env: dict[str, str] | None = None,
    redact: Any = None,
) -> Result:
    """Runs microsoft_api.py as a subprocess and parses its JSON output.

    `env` carries the materialized OAuth token path (via HOME) -- built
    by `service._microsoft_token_env`, never passed through argv
    (FR-10.2).
    """
    assert toolkit.microsoft_script is not None
    started = time.monotonic()

    # Defensive re-check: `microsoft_action` is fixed per tool, not
    # agent-suppliable, so this can only fail on a programming error --
    # kept for the same reason `build_argv` re-checks `check_binary`.
    if not toolkit.allows_microsoft_action(microsoft_action):
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=(
                f"Microsoft action {microsoft_action!r} is not allowed for this toolkit."
            ),
            truncated=False,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    argv = _build_argv(toolkit, microsoft_action, args)

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
                    "UNKNOWN: the call may have reached Microsoft. Do not "
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

    # Parse JSON stdout and cap list length (FR-8.12's counterpart).
    if outcome == OUTCOME_OK and stdout_text and not result.truncated:
        try:
            parsed = json.loads(stdout_text)
            capped = _cap_json(parsed, limit=MAX_JSON_ITEMS, budget=[MAX_JSON_ITEMS])
            stdout_text = json.dumps(capped, ensure_ascii=False)
        except (ValueError, TypeError):
            pass  # not JSON -- leave as-is (microsoft_api.py should always emit JSON)

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


async def probe(toolkit: Toolkit) -> bool:
    """For /health/ready: checks the script file exists (and, if
    `microsoft_container` is set, that `docker` is reachable). Does not
    run microsoft_api.py -- a health check must not have side effects,
    and refreshing a token on every probe would be both slow and a
    token-rotation risk.
    """
    assert toolkit.microsoft_script is not None
    if toolkit.microsoft_container:
        try:
            result = await asyncio.create_subprocess_exec(
                "docker", "ps", "--filter", f"name={toolkit.microsoft_container}",
                "--format", "{{.Names}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(result.wait(), timeout=5)
            return result.returncode == 0
        except (OSError, TimeoutError):
            return False
    # The same path the call itself would run (fallback included,
    # quietly: a readiness poll must not write a log line per probe).
    script = _resolve_script(toolkit, warn=False)
    return os.path.isfile(script) and os.access(script, os.R_OK)
