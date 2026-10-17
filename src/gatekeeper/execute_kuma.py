"""The `kuma` executor: Uptime Kuma monitors over Socket.IO.

Uptime Kuma has no REST API for monitors. Its own web UI creates, pauses
and lists them over a Socket.IO connection, so the `http` executor cannot
reach any of it -- and the alternatives (an INSERT into Kuma's database
plus a restart, or a host script holding the Kuma login outside the
credential store) are exactly what gatekeeper exists to replace.

So this executor has the `opencode`/`truenas` shape: the whitelist acts on
**operation names** (`tier1.KUMA_OPERATIONS`), and one operation is one
fixed exchange with Kuma, written out here and nowhere else:

* `monitor_list` -- the monitor list Kuma pushes after login, projected to
  a handful of fields. Kuma's own monitor objects carry basic-auth
  passwords, request headers and bodies; none of those fields is copied.
* `monitor_add_http` -- one `add` with type fixed to `http`, method GET,
  no notifications. The caller supplies name, URL, interval and the
  accepted status range, nothing else of the monitor object.
* `monitor_pause` / `monitor_resume` -- only for a monitor this executor
  created. Ownership is the `description` it writes on `add`
  (`MANAGED_MARKER`); a monitor somebody set up by hand is refused before
  anything is sent for it.

There is no delete, no edit, and nothing that touches notifications or
settings: those events are simply never emitted by this module.

What it keeps from `execute_http.py`, by reusing that module's helpers:
the target lives only on the toolkit (`base_url`), the resolved address
is checked against `allowed_hosts`/`allowed_cidrs` immediately before the
connect and the socket is opened to that address literally (FR-8.9), and
every answer is external, untrusted data with the FR-8.12 field cap.

The Socket.IO client is the minimum Kuma needs, written against
`websockets` (already a dependency) rather than pulling in a Socket.IO
library: Engine.IO v4 over a WebSocket transport, the default namespace,
events with acknowledgements, and answering the server's pings. Each call
opens one connection, logs in, does its one thing, and closes -- the same
reasoning as `execute_truenas.py`.

Login is Kuma's socket `login` event (Uptime Kuma 1.23 and 2.0) with a
`basic` credential (`user:password`). The password goes to Kuma and
nowhere else -- not into a response, an error text or the audit log.
A Kuma account with 2FA cannot be used: there is nobody to type the code.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import websockets

from . import execute_http
from .credentials import CredentialStore, ResolvedCredential
from .errors import DenialReason, Denied
from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result
from .execute_http import MAX_JSON_ITEMS, _cap_json, _resolve_and_check
from .tier1 import (
    KUMA_INTERVAL_MAX,
    KUMA_INTERVAL_MIN,
    KUMA_STATUS_CODES,
    Toolkit,
)

#: What `monitor_add_http` writes into a monitor's description, and what
#: `monitor_pause`/`monitor_resume` require to find there. A prefix rather
#: than an exact string so the toolkit name after it is information for
#: the human reading Kuma's UI, not a second key that a toolkit rename
#: would silently orphan.
MANAGED_MARKER = "Managed by gatekeeper"

#: How long `monitor_add_http` waits for Kuma's `info` event (which names
#: its version) before assuming a 1.x server. Kuma sends it right after
#: login; this only bounds a server that never does.
_INFO_WAIT_SECONDS = 3.0

#: The events that change something in Kuma. Once one is on the wire, a
#: timeout no longer means "nothing happened" (FR-6.9).
_WRITE_EVENTS = frozenset({"add", "pauseMonitor", "resumeMonitor"})


class _KumaError(Exception):
    """Kuma answered, and the answer was a refusal or not understood."""


class _SocketIO:
    """Engine.IO v4 + Socket.IO v4, default namespace, WebSocket only.

    Packets are text frames: Engine.IO type digit first (`0` open, `2`
    ping, `3` pong, `4` message), and inside a message the Socket.IO type
    (`0` connect, `2` event, `3` ack, `4` connect error), an optional
    ack id, then a JSON array. Events Kuma pushes on its own
    (`monitorList`, `info`, ...) are kept by name, last one wins, so an
    operation can wait for one that arrived while it was waiting for
    something else.
    """

    def __init__(self, ws: Any, deadline: float) -> None:
        self.ws = ws
        self.deadline = deadline
        self.events: dict[str, list[Any]] = {}
        self._acks: dict[int, Any] = {}
        self._next_id = 0
        #: True once a `_WRITE_EVENTS` event has been sent.
        self.sent_write = False

    def _remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        return remaining

    async def _recv(self, until: float | None = None) -> str:
        budget = self._remaining()
        if until is not None:
            budget = min(budget, until - time.monotonic())
            if budget <= 0:
                raise TimeoutError
        raw = await asyncio.wait_for(self.ws.recv(), timeout=budget)
        return raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")

    async def _pump(self, until: float | None = None) -> str | None:
        """Reads one frame and files it. Returns the Socket.IO packet
        (without the Engine.IO `4`) for the caller to inspect, or None for
        transport-level frames."""
        frame = await self._recv(until)
        if frame == "2":
            await self.ws.send("3")
            return None
        if frame.startswith("1"):
            raise _KumaError("Uptime Kuma closed the connection.")
        if not frame.startswith("4"):
            return None
        packet = frame[1:]
        if packet.startswith("2"):
            args = _json_array(_strip_ack_id(packet[1:]))
            if args and isinstance(args[0], str):
                self.events[args[0]] = args[1:]
        elif packet.startswith("3"):
            body = packet[1:]
            digits = len(body) - len(body.lstrip("0123456789"))
            if digits:
                self._acks[int(body[:digits])] = _json_array(body[digits:])
        return packet

    async def open(self) -> None:
        """The Engine.IO handshake, then a connect to the default namespace."""
        frame = await self._recv()
        if not frame.startswith("0"):
            raise _KumaError("The server did not open a Socket.IO session -- is base_url an Uptime Kuma?")
        await self.ws.send("40")
        while True:
            packet = await self._pump()
            if packet is None:
                continue
            if packet.startswith("0"):
                return
            if packet.startswith("4"):
                raise _KumaError("Uptime Kuma refused the Socket.IO connection.")

    async def call(self, event: str, *args: Any) -> Any:
        """Emits `event` with an ack id and returns the ack's first value."""
        ack_id = self._next_id
        self._next_id += 1
        if event in _WRITE_EVENTS:
            self.sent_write = True
        await self.ws.send(f"42{ack_id}" + json.dumps([event, *args], ensure_ascii=False))
        while ack_id not in self._acks:
            await self._pump()
        values = self._acks.pop(ack_id)
        return values[0] if values else None

    async def event(
        self,
        name: str,
        wait_seconds: float | None = None,
        accept: Any = None,
    ) -> list[Any] | None:
        """The args of the last `name` event, waiting for it if needed.

        `accept`, if given, is a predicate over those args: an event it
        rejects counts as not yet arrived. With `wait_seconds`, gives up
        after that long and returns None; without, waits for the
        operation's whole remaining budget.
        """
        until = None if wait_seconds is None else time.monotonic() + wait_seconds

        def arrived() -> bool:
            return name in self.events and (accept is None or accept(self.events[name]))

        while not arrived():
            try:
                await self._pump(until)
            except TimeoutError:
                if until is not None and time.monotonic() < self.deadline:
                    return None
                raise
        return self.events[name]


def _strip_ack_id(body: str) -> str:
    return body.lstrip("0123456789")


def _json_array(body: str) -> list[Any]:
    try:
        value = json.loads(body)
    except ValueError:
        return []
    return value if isinstance(value, list) else []


def _socket_url(base_url: str) -> tuple[str, str, int]:
    """The Socket.IO endpoint under `base_url`, and the host/port to check."""
    parsed = urlsplit(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path.rstrip("/") + "/socket.io/"
    return urlunsplit((scheme, parsed.netloc, path, "EIO=4&transport=websocket", "")), host, port


def _split_basic(credential: ResolvedCredential) -> tuple[str, str]:
    if credential.kind != "basic" or ":" not in credential.value:
        raise Denied(
            DenialReason.CREDENTIAL_UNAVAILABLE,
            f"Credential {credential.name!r} must be kind 'basic' with the value "
            "'username:password' of the Kuma login.",
        )
    username, password = credential.value.split(":", 1)
    return username, password


async def _login(sio: _SocketIO, credential: ResolvedCredential) -> None:
    username, password = _split_basic(credential)
    answer = await sio.call("login", {"username": username, "password": password, "token": ""})
    if not isinstance(answer, dict):
        raise Denied(DenialReason.CREDENTIAL_UNAVAILABLE, "Uptime Kuma did not answer the login.")
    if answer.get("tokenRequired"):
        raise Denied(
            DenialReason.CREDENTIAL_UNAVAILABLE,
            "The Kuma account has 2FA enabled. Gatekeeper cannot supply a TOTP "
            "code; use an account without 2FA for this toolkit.",
        )
    if answer.get("ok") is not True:
        # Kuma's own texts here are fixed strings ("Incorrect username or
        # password.", a rate-limit notice) and never echo the password.
        reason = answer.get("msg") if isinstance(answer.get("msg"), str) else "refused"
        raise Denied(
            DenialReason.CREDENTIAL_UNAVAILABLE,
            f"Uptime Kuma login failed: {reason}",
        )


def _is_managed(monitor: Any) -> bool:
    description = monitor.get("description") if isinstance(monitor, dict) else None
    return isinstance(description, str) and description.startswith(MANAGED_MARKER)


def _public_url(raw: Any) -> str | None:
    """A monitor URL without userinfo, query or fragment.

    A hand-made monitor may well carry a token in its URL; the list is
    for telling monitors apart, which scheme, host and path already do.
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not parsed.scheme or not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _summary(monitor_id: Any, monitor: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": monitor.get("id", monitor_id),
        "name": monitor.get("name"),
        "type": monitor.get("type"),
        "url": _public_url(monitor.get("url")) if monitor.get("type") in ("http", "keyword", "json-query") else None,
        "active": bool(monitor.get("active")),
        "interval": monitor.get("interval"),
        "managed": _is_managed(monitor),
    }


def _version_of(info: list[Any] | None) -> str | None:
    payload = info[0] if info else None
    version = payload.get("version") if isinstance(payload, dict) else None
    return version if isinstance(version, str) and version else None


def _major_version(info: list[Any] | None) -> int:
    """Kuma's major version from its `info` event, 1 when it names none.

    Kuma sends `info` twice: on connect with the version hidden, and again
    after login with it -- so the caller waits for one that has it.
    """
    version = _version_of(info)
    if version is not None:
        head = version.lstrip("v").split(".", 1)[0]
        if head.isdigit():
            return int(head)
    return 1


def http_monitor(
    *, name: str, url: str, interval: int, expected_status: str, toolkit: str, major: int
) -> dict[str, Any]:
    """The `add` payload: Kuma's own UI defaults for an HTTP(s) monitor,
    with only name, url, interval and the accepted status range taken from
    the call. Everything that could carry a secret or reach somewhere
    else (headers, body, auth, proxy, notifications) is left empty.

    Kuma's `add` handler JSON-encodes the Kafka fields on 1.23 and 2.0
    alike and additionally `conditions`/`rabbitmqNodes` on 2.0, whose
    database rejects them missing -- so those two are sent to a 2.x server
    only, where the column exists.
    """
    monitor: dict[str, Any] = {
        "type": "http",
        "name": name,
        "url": url,
        "method": "GET",
        "interval": interval,
        "retryInterval": interval,
        "resendInterval": 0,
        "maxretries": 0,
        "timeout": min(48, int(interval * 0.8)),
        "accepted_statuscodes": [expected_status],
        "notificationIDList": {},
        "ignoreTls": False,
        "upsideDown": False,
        "maxredirects": 10,
        "expiryNotification": False,
        "description": f"{MANAGED_MARKER} (toolkit {toolkit})",
        "kafkaProducerBrokers": [],
        "kafkaProducerSaslOptions": {"mechanism": "None"},
    }
    if major >= 2:
        monitor["conditions"] = []
        monitor["rabbitmqNodes"] = []
    return monitor


def _ack_ok(answer: Any, what: str) -> dict[str, Any]:
    if not isinstance(answer, dict):
        raise _KumaError(f"Uptime Kuma sent no usable answer to {what}.")
    if answer.get("ok") is not True:
        msg = answer.get("msg")
        raise _KumaError(f"Uptime Kuma refused {what}: {msg if isinstance(msg, str) else 'no reason given'}")
    return answer


async def _op_list(sio: _SocketIO, values: dict[str, str], toolkit: Toolkit) -> dict[str, Any]:
    args = await sio.event("monitorList")
    monitors = args[0] if args and isinstance(args[0], dict) else {}
    items = [
        _summary(mid, m) for mid, m in monitors.items() if isinstance(m, dict)
    ]
    items.sort(key=lambda m: (str(m.get("name") or ""), str(m.get("id"))))
    return {"monitors": items, "count": len(items)}


async def _op_add_http(sio: _SocketIO, values: dict[str, str], toolkit: Toolkit) -> dict[str, Any]:
    major = _major_version(
        await sio.event("info", _INFO_WAIT_SECONDS, accept=lambda args: _version_of(args) is not None)
    )
    monitor = http_monitor(
        name=values["name"],
        url=values["url"],
        interval=int(values.get("interval") or 60),
        expected_status=values.get("expected_status") or "200-299",
        toolkit=toolkit.name,
        major=major,
    )
    answer = _ack_ok(await sio.call("add", monitor), "the new monitor")
    return {
        "monitor_id": answer.get("monitorID"),
        "name": monitor["name"],
        "url": monitor["url"],
        "interval": monitor["interval"],
        "accepted_statuscodes": monitor["accepted_statuscodes"],
    }


async def _owned_monitor(sio: _SocketIO, monitor_id: int) -> dict[str, Any]:
    answer = await sio.call("getMonitor", monitor_id)
    monitor = answer.get("monitor") if isinstance(answer, dict) and answer.get("ok") else None
    if not isinstance(monitor, dict):
        raise _KumaError(f"Monitor {monitor_id} does not exist.")
    if not _is_managed(monitor):
        raise Denied(
            DenialReason.TIER1_VIOLATION,
            f"Monitor {monitor_id} was not created through gatekeeper; this toolkit "
            "only pauses and resumes its own monitors.",
        )
    return monitor


async def _op_pause(sio: _SocketIO, values: dict[str, str], toolkit: Toolkit) -> dict[str, Any]:
    monitor_id = int(values["monitor_id"])
    monitor = await _owned_monitor(sio, monitor_id)
    _ack_ok(await sio.call("pauseMonitor", monitor_id), f"pausing monitor {monitor_id}")
    return {"monitor_id": monitor_id, "name": monitor.get("name"), "active": False}


async def _op_resume(sio: _SocketIO, values: dict[str, str], toolkit: Toolkit) -> dict[str, Any]:
    monitor_id = int(values["monitor_id"])
    monitor = await _owned_monitor(sio, monitor_id)
    _ack_ok(await sio.call("resumeMonitor", monitor_id), f"resuming monitor {monitor_id}")
    return {"monitor_id": monitor_id, "name": monitor.get("name"), "active": True}


_OPERATIONS = {
    "monitor_list": _op_list,
    "monitor_add_http": _op_add_http,
    "monitor_pause": _op_pause,
    "monitor_resume": _op_resume,
}


def check_values(operation: str, values: dict[str, str]) -> None:
    """The executor's own floor under whatever the tool definition says.

    A tool definition may narrow these (a stricter URL pattern, a shorter
    enum); it can never widen them, because they are checked here again
    regardless of what it declares.
    """
    if operation == "monitor_add_http":
        name = values.get("name", "")
        if not name.strip() or len(name) > 150:
            raise Denied(DenialReason.PARAM_INVALID, "Parameter 'name' must be 1-150 characters.")
        url = values.get("url", "")
        try:
            parsed = urlsplit(url)
            parsed.port  # noqa: B018 -- raises on a malformed port
        except ValueError:
            raise Denied(DenialReason.PARAM_INVALID, "Parameter 'url' is not a valid URL.") from None
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise Denied(DenialReason.PARAM_INVALID, "Parameter 'url' must be an absolute http(s) URL.")
        if parsed.username is not None or parsed.password is not None:
            raise Denied(
                DenialReason.PARAM_INVALID,
                "Parameter 'url' must not carry a user or password.",
            )
        if any(ch.isspace() for ch in url):
            raise Denied(DenialReason.PARAM_INVALID, "Parameter 'url' must not contain whitespace.")
        interval = values.get("interval")
        if interval is not None and not (
            interval.isdigit() and KUMA_INTERVAL_MIN <= int(interval) <= KUMA_INTERVAL_MAX
        ):
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"Parameter 'interval' must be {KUMA_INTERVAL_MIN}-{KUMA_INTERVAL_MAX} seconds.",
            )
        status = values.get("expected_status")
        if status is not None and status not in KUMA_STATUS_CODES:
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"Parameter 'expected_status' must be one of {sorted(KUMA_STATUS_CODES)}.",
            )
    elif operation in ("monitor_pause", "monitor_resume"):
        monitor_id = values.get("monitor_id", "")
        if not monitor_id.isdigit() or int(monitor_id) < 1:
            raise Denied(DenialReason.PARAM_INVALID, "Parameter 'monitor_id' must be a positive integer.")


async def run(
    *,
    operation: str,
    values: dict[str, str],
    toolkit: Toolkit,
    credentials: CredentialStore | None,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    redact: Any = None,
) -> Result:
    assert toolkit.base_url is not None
    started = time.monotonic()
    deadline = started + timeout_seconds

    def _elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    def _clean(text: str) -> str:
        return redact(text) if redact is not None else text

    def _denied(denial: Denied) -> Result:
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=_clean(denial.agent_message),
            truncated=False,
            duration_ms=_elapsed(),
            denial_reason=denial.reason.value,
            denial_detail=denial.detail,
        )

    def _failed(message: str, exit_code: int | None = None) -> Result:
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=exit_code,
            stdout="",
            stderr=_clean(message),
            truncated=False,
            duration_ms=_elapsed(),
            external_untrusted=True,
        )

    # Defensive re-checks: `operation` is fixed per tool and the values
    # were validated by `validate.build_kuma_call` -- kept for the same
    # reason `build_argv` re-checks `check_binary`.
    if not toolkit.allows_kuma_operation(operation) or operation not in _OPERATIONS:
        return _denied(
            Denied(
                DenialReason.TIER1_VIOLATION,
                f"Kuma operation {operation!r} is not allowed for this toolkit.",
            )
        )
    try:
        check_values(operation, values)
    except Denied as denial:
        return _denied(denial)

    if not toolkit.credential or credentials is None:
        return _denied(
            Denied(
                DenialReason.CREDENTIAL_UNAVAILABLE,
                "This toolkit needs the Kuma login in the credential store.",
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

    url, host, port = _socket_url(toolkit.base_url)
    try:
        # FR-8.9: resolved and checked now, and the socket goes to that
        # literal address -- `host`/`port` only change the TCP target,
        # the URL's hostname stays in the Host header and TLS SNI. No
        # proxy: a proxy would make its own lookup this check never saw.
        resolved_ip = await _resolve_and_check(host, port, toolkit)
    except Denied as denial:
        return _denied(denial)

    sio: _SocketIO | None = None
    try:
        ws = await asyncio.wait_for(
            websockets.connect(
                url,
                host=resolved_ip,
                port=port,
                proxy=None,
                open_timeout=None,
                ping_interval=None,
                max_size=max(1 << 20, max_output_bytes * 4),
            ),
            timeout=max(0.1, deadline - time.monotonic()),
        )
    except (OSError, TimeoutError, websockets.exceptions.WebSocketException) as exc:
        return _failed(f"Could not connect to Uptime Kuma at {toolkit.base_url}: {exc}")

    try:
        sio = _SocketIO(ws, deadline)
        await sio.open()
        await _login(sio, credential)
        summary = await _OPERATIONS[operation](sio, values, toolkit)
    except Denied as denial:
        return _denied(denial)
    except _KumaError as exc:
        return _failed(str(exc), exit_code=1)
    except TimeoutError:
        unknown = sio is not None and sio.sent_write and not idempotent
        return Result(
            outcome=OUTCOME_UNKNOWN if unknown else OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=(
                f"Timeout of {timeout_seconds}s exceeded. The outcome is UNKNOWN: "
                "the request may have reached Uptime Kuma. List the monitors "
                "before trying again."
                if unknown
                else f"Timeout of {timeout_seconds}s exceeded."
            ),
            truncated=False,
            duration_ms=_elapsed(),
            external_untrusted=True,
        )
    except websockets.exceptions.WebSocketException as exc:
        return _failed(f"Connection error: {exc}")
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001 -- best-effort cleanup only
            pass

    stdout = json.dumps(
        _cap_json(summary, limit=MAX_JSON_ITEMS, budget=[MAX_JSON_ITEMS]),
        ensure_ascii=False,
    )
    encoded = stdout.encode("utf-8")
    truncated = len(encoded) > max_output_bytes
    if truncated:
        stdout = encoded[:max_output_bytes].decode("utf-8", errors="replace")

    return Result(
        outcome=OUTCOME_OK,
        exit_code=0,
        stdout=_clean(stdout),
        stderr="",
        truncated=truncated,
        duration_ms=_elapsed(),
        external_untrusted=True,
    )


async def probe(toolkit: Toolkit) -> bool:
    """TCP-connect only, for /health/ready -- `execute_http.probe` verbatim:
    same `base_url`, same address checks. No login: that would put a
    credential on the wire for a liveness question."""
    return await execute_http.probe(toolkit)
