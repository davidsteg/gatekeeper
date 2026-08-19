"""The `http` executor (REQUIREMENTS.md §8, FR-8.5 to FR-8.15).

What the argv template is to `execute.py`, the URL template is here. The
one property everything below serves: the agent can never determine the
actual network target. Scheme and host come exclusively from the toolkit
(FR-8.5); a parameter fills exactly one path segment, query value, or body
field (FR-8.7); the resolved IP is checked against the toolkit's CIDR
allowlist immediately before connecting, closing the DNS-rebinding gap a
one-time hostname check would leave open (FR-8.9); redirects are reported,
never followed (FR-8.8); the credential is injected as a header by this
module directly, never through a tool's own query/body template (FR-8.14).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from .credentials import CredentialStore, ResolvedCredential
from .errors import Denied, DenialReason
from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result
from .tier1 import Toolkit

#: FR-8.12: responses are capped not just in bytes but in list length --
#: a single "list all series" call must not smuggle thousands of fields
#: worth of untrusted text into the agent's context.
MAX_JSON_ITEMS = 500


async def probe(toolkit: Toolkit) -> bool:
    """TCP-connect only, for /health/ready -- no HTTP request is issued.

    A base_url containing an unresolved `{credential}` placeholder (the
    Telegram case) is skipped as "not checkable this way" rather than
    reported unreachable -- opening a probe connection would otherwise
    need a real credential just to answer a liveness question.
    """
    assert toolkit.base_url is not None
    if "{credential}" in toolkit.base_url:
        return True
    parsed = urlsplit(toolkit.base_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        resolved_ip = await _resolve_and_check(host, port, toolkit)
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_ip, port), timeout=5
        )
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True
    except (Denied, OSError, asyncio.TimeoutError, TimeoutError):
        return False


def _substitute_base_url(base_url: str, credential: ResolvedCredential | None) -> str:
    """Resolves a `{credential}` placeholder in `base_url` server-side only.

    The one contained exception to "credentials are always a header"
    (FR-8.10): a handful of services (Telegram's bot API) put the secret
    in the URL path itself. The placeholder never appears in a tool
    definition or a response -- only here, immediately before use.
    """
    if "{credential}" not in base_url:
        return base_url
    if credential is None:
        raise Denied(
            DenialReason.CREDENTIAL_UNAVAILABLE,
            "This toolkit's base_url needs a credential that is not configured.",
        )
    return base_url.replace("{credential}", credential.value)


async def _resolve_and_check(host: str, port: int, toolkit: Toolkit) -> str:
    """Resolves `host` and checks every returned address against the

    toolkit's `allowed_cidrs` (FR-8.9). Fail-closed: if *any* resolved
    address falls outside the allowlist, the call is denied -- a
    multi-homed or round-robin DNS answer does not get to pick the
    permissive address.
    """
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise Denied(
            DenialReason.EXECUTOR_UNAVAILABLE, f"Could not resolve {host!r}: {exc}"
        ) from exc
    if not infos:
        raise Denied(DenialReason.EXECUTOR_UNAVAILABLE, f"Could not resolve {host!r}")

    addresses = {info[4][0] for info in infos}
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if not toolkit.in_allowed_cidrs(address):
            raise Denied(
                DenialReason.SSRF_BLOCKED,
                f"{host!r} resolves to {raw}, which is outside this toolkit's "
                "allowed_cidrs.",
            )
    # Any one of the checked addresses is equally allowed; the first is as
    # good as any other now that all have passed.
    return next(iter(addresses))


def _cap_json(value: Any, *, limit: int, budget: list[int]) -> Any:
    """Truncates list/dict field counts recursively (FR-8.12)."""
    if budget[0] <= 0:
        return "...(truncated)..." if isinstance(value, (list, dict)) else value
    if isinstance(value, list):
        kept = []
        for item in value:
            if budget[0] <= 0:
                break
            kept.append(_cap_json(item, limit=limit, budget=budget))
            budget[0] -= 1
        return kept
    if isinstance(value, dict):
        kept_d: dict[str, Any] = {}
        for key, item in value.items():
            if budget[0] <= 0:
                break
            kept_d[key] = _cap_json(item, limit=limit, budget=budget)
            budget[0] -= 1
        return kept_d
    return value


def _credential_headers(credential: ResolvedCredential | None) -> dict[str, str]:
    if credential is None:
        return {}
    if credential.kind == "api_key_header" and credential.header:
        return {credential.header: credential.value}
    if credential.kind == "bearer":
        return {"Authorization": f"Bearer {credential.value}"}
    if credential.kind == "basic":
        # `value` is expected as "user:pass"; httpx would base64-encode it
        # for us via auth=, but building the header directly here keeps
        # this module the single place that ever touches credential.value.
        import base64

        encoded = base64.b64encode(credential.value.encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}
    return {}


def _credential_query(credential: ResolvedCredential | None) -> dict[str, str]:
    """FR-8.14 says gatekeeper prefers a header over `?apikey=` because a

    query string ends up in the target's own access logs -- but a handful
    of real services (SABnzbd's classic API is the one in this project's
    presets) offer no header alternative at all. `url_query` is the
    deliberately narrow, documented exception: injected here, by this
    module, exactly like a header would be -- never through a tool's own
    `query_template`, which structurally cannot carry a credential either
    way (FR-8.7: a parameter fills one value, and no tool definition ever
    sees `credential.value` in the first place).
    """
    if credential is None or credential.kind != "url_query" or not credential.header:
        return {}
    return {credential.header: credential.value}


async def run(
    *,
    method: str,
    path: str,
    query: dict[str, str],
    body: dict[str, str] | None,
    toolkit: Toolkit,
    credentials: CredentialStore | None,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    redact: Any = None,
) -> Result:
    """`credentials`/`toolkit.credential` rather than a pre-resolved value:

    this module is one of exactly three places in the codebase allowed to
    call `CredentialStore._resolve` (the others are `execute_truenas.py`
    and `service.py`'s `_docker_tls_env` -- the docker executor has no
    per-call request object to thread a resolved credential through, so
    that one materialization has to live in `service.py` itself) --
    keeping the decrypt call here for http, not duplicated elsewhere, is
    what makes that invariant grep-able instead of merely documented.
    """
    assert toolkit.base_url is not None
    started = time.monotonic()

    def _denied(denial: Denied) -> Result:
        # A rejection here (missing credential, SSRF block) is still a
        # denial, not a network failure -- but it happens after
        # `service.call()`'s own validation try/except has already closed,
        # so it is reported as a `Result` instead of propagating, which
        # keeps it inside the normal audit.call()/outcome bookkeeping
        # rather than becoming an unaudited exception.
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

    try:
        base_url = _substitute_base_url(toolkit.base_url, credential)
    except Denied as denial:
        return _denied(denial)
    parsed = urlsplit(base_url)
    scheme = parsed.scheme
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)

    try:
        resolved_ip = await _resolve_and_check(host, port, toolkit)
    except Denied as denial:
        return _denied(denial)

    headers = {"Host": host if port in (80, 443) else f"{host}:{port}"}
    headers.update(_credential_headers(credential))
    query = {**query, **_credential_query(credential)}

    # Connect to the *checked* IP directly rather than letting httpx do its
    # own DNS lookup a second time -- that second lookup is exactly the
    # rebinding window FR-8.9 closes. `sni_hostname` keeps TLS verification
    # bound to the real hostname/certificate despite the IP-literal URL.
    request_url = httpx.URL(scheme=scheme, host=resolved_ip, port=port, path=parsed.path + path)
    extensions = {"sni_hostname": host} if scheme == "https" else {}

    outcome = OUTCOME_FAILED
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    truncated = False

    try:
        async with httpx.AsyncClient(verify=True) as client:
            request = client.build_request(
                method,
                request_url,
                params=query or None,
                json=body if body else None,
                headers=headers,
                extensions=extensions,
            )
            response = await asyncio.wait_for(
                client.send(request, follow_redirects=False, stream=True),
                timeout=timeout_seconds,
            )
            try:
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    if total + len(chunk) > max_output_bytes:
                        chunks.append(chunk[: max_output_bytes - total])
                        truncated = True
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                raw = b"".join(chunks)
            finally:
                await response.aclose()

        exit_code = response.status_code
        content_type = response.headers.get("content-type", "")
        if "json" in content_type and not truncated:
            try:
                parsed_json = json.loads(raw.decode("utf-8", errors="replace"))
                capped = _cap_json(parsed_json, limit=MAX_JSON_ITEMS, budget=[MAX_JSON_ITEMS])
                stdout = json.dumps(capped, ensure_ascii=False)
            except (ValueError, UnicodeDecodeError):
                stdout = raw.decode("utf-8", errors="replace")
        else:
            stdout = raw.decode("utf-8", errors="replace")

        if 300 <= response.status_code < 400:
            # FR-8.8: reported as data, never chased. The Location header is
            # itself untrusted external data and is included as such.
            location = response.headers.get("location", "")
            stderr = f"Redirect ({response.status_code}) to {location!r}, not followed."
            outcome = OUTCOME_FAILED
        elif 200 <= response.status_code < 300:
            outcome = OUTCOME_OK
        else:
            outcome = OUTCOME_FAILED
    except (asyncio.TimeoutError, TimeoutError, httpx.TimeoutException):
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
                    "UNKNOWN: the request may have reached the target. Do not "
                    "retry without checking the state first."
                )
            ),
            truncated=False,
            duration_ms=duration,
            external_untrusted=True,
        )
    except httpx.HTTPError as exc:
        duration = int((time.monotonic() - started) * 1000)
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=f"Request failed: {exc}",
            truncated=False,
            duration_ms=duration,
            external_untrusted=True,
        )

    duration = int((time.monotonic() - started) * 1000)
    if redact is not None:
        stdout = redact(stdout)
        stderr = redact(stderr)
    return Result(
        outcome=outcome,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
        duration_ms=duration,
        external_untrusted=True,
    )
