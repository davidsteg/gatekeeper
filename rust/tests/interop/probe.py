"""Raw-HTTP wire probe for an MCP server built like gatekeeper's.

    python probe.py http://127.0.0.1:PORT > transcript.txt

Sends a fixed sequence of requests (both protocol eras, both mounts,
every error path the transport has) and prints a normalized transcript:
status, the headers that matter, and the body with session ids masked.
Its transcript against the Python SDK server the Python gatekeeper ran
is frozen in `rust/tests/fixtures/mcp_wire_python_transcript.txt`;
`rust/tests/mcp_interop.rs` runs it against `mcp_echo` (the Rust port)
and the two must be identical. Needs only the MCP SDK (`httpx2` comes
with `mcp==2.2.0`).
"""

from __future__ import annotations

import asyncio
import json
import re
import sys

import httpx2 as httpx

BASE = sys.argv[1].rstrip("/")
OUT: list[str] = []
SESSIONS: dict[str, str] = {}

ACCEPT_BOTH = "application/json, text/event-stream"
JSON_CT = "application/json"
MODERN = "2026-07-28"
META = {
    "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "probe", "version": "1"},
}


def mask(text: str) -> str:
    for real, alias in SESSIONS.items():
        text = text.replace(real, alias)
    return text


def remember(session_id: str | None) -> None:
    if session_id and session_id not in SESSIONS:
        SESSIONS[session_id] = f"<session-{len(SESSIONS) + 1}>"


def render_body(content_type: str, body: str) -> list[str]:
    if content_type.startswith("text/event-stream"):
        lines = []
        for line in body.replace("\r\n", "\n").split("\n"):
            if line.startswith("data:"):
                data = line[5:].strip()
                try:
                    lines.append("  sse data " + json.dumps(json.loads(data), sort_keys=True))
                except ValueError:
                    lines.append("  sse data-raw " + repr(data))
            elif line.startswith("event:"):
                lines.append("  sse " + line.strip())
            elif line.startswith(":"):
                lines.append("  sse comment " + line[1:].strip())
            elif line.startswith("id:") or line.startswith("retry:"):
                lines.append("  sse " + line.strip())
        return lines
    if not body:
        return ["  (empty body)"]
    try:
        return ["  json " + json.dumps(json.loads(body), sort_keys=True)]
    except ValueError:
        return ["  text " + repr(body)]


def record(name: str, response: httpx.Response, body: str) -> None:
    remember(response.headers.get("mcp-session-id"))
    OUT.append(f"== {name}")
    OUT.append(f"  status {response.status_code}")
    content_type = response.headers.get("content-type", "")
    for header in ("content-type", "mcp-session-id", "allow", "cache-control", "x-accel-buffering"):
        value = response.headers.get(header)
        if value is not None:
            OUT.append(f"  header {header}: {mask(value)}")
    OUT.extend(mask(line) for line in render_body(content_type, body))


async def post(http, name, payload, *, path="/mcp", headers=None, raw=None, accept=ACCEPT_BOTH, ctype=JSON_CT):
    # A list of pairs, not a dict: the duplicate-header case needs two copies.
    h: list[tuple[str, str]] = []
    if accept is not None:
        h.append(("Accept", accept))
    if ctype is not None:
        h.append(("Content-Type", ctype))
    h.extend(headers.items() if isinstance(headers, dict) else (headers or []))
    content = raw if raw is not None else json.dumps(payload).encode()
    response = await http.post(BASE + path, content=content, headers=h)
    record(name, response, response.text)
    return response


def first_result(response: httpx.Response) -> dict:
    body = response.text
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        for line in body.replace("\r\n", "\n").split("\n"):
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
    return json.loads(body)


def init_payload(version: str, rid=1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "1"},
        },
    }


def modern_headers(method: str, name: str | None = None, version: str = MODERN) -> dict:
    h = {"MCP-Protocol-Version": version, "Mcp-Method": method}
    if name is not None:
        h["Mcp-Name"] = name
    return h


_READERS: dict[int, list] = {}


async def read_stream_events(stream: httpx.Response, count: int, timeout: float = 10.0) -> list[str]:
    """The next `count` data frames of an SSE stream (keepalive comments skipped)."""
    state = _READERS.setdefault(id(stream), [stream.aiter_text(), ""])
    events: list[str] = []

    async def pump():
        while True:
            normalized = state[1].replace("\r\n", "\n")
            while "\n\n" in normalized:
                frame, _, rest = normalized.partition("\n\n")
                normalized = rest
                state[1] = rest
                rendered = [e for e in render_body("text/event-stream", frame) if "comment" not in e]
                if any(" data" in e for e in rendered):
                    events.extend(rendered)
                if len([e for e in events if " data" in e]) >= count:
                    return
            state[1] = normalized + await state[0].__anext__()

    await asyncio.wait_for(pump(), timeout)
    return events


async def session_era(http: httpx.AsyncClient) -> None:
    OUT.append("#### session era")
    r = await post(http, "initialize 2025-06-18", init_payload("2025-06-18"))
    sid = r.headers["mcp-session-id"]
    s = {"Mcp-Session-Id": sid}
    s_v = {"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-06-18"}
    await post(http, "initialized notification", {"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=s)
    await post(http, "tools/list", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=s_v)
    await post(http, "tools/list with params", {"jsonrpc": "2.0", "id": "two", "method": "tools/list", "params": {}}, headers=s)
    await post(http, "tools/call echo", {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "demo.echo", "arguments": {"text": "hi"}}}, headers=s)
    await post(http, "tools/call no args", {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "demo.echo"}}, headers=s)
    await post(http, "tools/call unknown", {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "nope", "arguments": {}}}, headers=s)
    await post(http, "tools/call raises", {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "demo.fail", "arguments": {}}}, headers=s)
    await post(http, "tools/call missing name", {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"arguments": {}}}, headers=s)
    await post(http, "tools/call no params", {"jsonrpc": "2.0", "id": 8, "method": "tools/call"}, headers=s)
    await post(http, "tools/call args not object", {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "demo.echo", "arguments": [1]}}, headers=s)
    await post(http, "tools/call name not string", {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": 5}}, headers=s)
    await post(http, "ping", {"jsonrpc": "2.0", "id": 11, "method": "ping"}, headers=s)
    await post(http, "ping with params", {"jsonrpc": "2.0", "id": 12, "method": "ping", "params": {"_meta": {"progressToken": 1}}}, headers=s)
    await post(http, "unknown method", {"jsonrpc": "2.0", "id": 13, "method": "foo/bar"}, headers=s)
    await post(http, "resources/list (no handler)", {"jsonrpc": "2.0", "id": 14, "method": "resources/list"}, headers=s)
    await post(http, "server/discover at session era", {"jsonrpc": "2.0", "id": 15, "method": "server/discover"}, headers=s)
    await post(http, "subscriptions/listen at session era", {"jsonrpc": "2.0", "id": 16, "method": "subscriptions/listen", "params": {"notifications": {"toolsListChanged": True}}}, headers=s)
    await post(http, "logging/setLevel (no handler)", {"jsonrpc": "2.0", "id": 17, "method": "logging/setLevel", "params": {"level": "info"}}, headers=s)
    await post(http, "second initialize on session", init_payload("2025-03-26", rid=18), headers=s)
    await post(http, "params not object", {"jsonrpc": "2.0", "id": 19, "method": "ping", "params": [1]}, headers=s)
    await post(http, "float id", {"jsonrpc": "2.0", "id": 1.5, "method": "ping"}, headers=s)
    await post(http, "null id", {"jsonrpc": "2.0", "id": None, "method": "ping"}, headers=s)
    await post(http, "bool id", {"jsonrpc": "2.0", "id": True, "method": "ping"}, headers=s)
    await post(http, "string id", {"jsonrpc": "2.0", "id": "abc", "method": "ping"}, headers=s)
    await post(http, "negative id", {"jsonrpc": "2.0", "id": -3, "method": "ping"}, headers=s)
    await post(http, "unknown notification", {"jsonrpc": "2.0", "method": "notifications/whatever"}, headers=s)
    await post(http, "cancel unknown request", {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 999}}, headers=s)
    await post(http, "client response", {"jsonrpc": "2.0", "id": 77, "result": {}}, headers=s)
    await post(http, "client error response", {"jsonrpc": "2.0", "id": 78, "error": {"code": 1, "message": "x"}}, headers=s)
    await post(http, "batch", [{"jsonrpc": "2.0", "id": 1, "method": "ping"}], headers=s)
    await post(http, "wrong jsonrpc version", {"jsonrpc": "1.0", "id": 1, "method": "ping"}, headers=s)
    await post(http, "missing method", {"jsonrpc": "2.0", "id": 1}, headers=s)
    await post(http, "parse error", None, raw=b"{not json", headers=s)
    await post(http, "empty body", None, raw=b"", headers=s)
    await post(http, "accept json only", {"jsonrpc": "2.0", "id": 20, "method": "ping"}, headers=s, accept="application/json")
    await post(http, "accept sse only", {"jsonrpc": "2.0", "id": 21, "method": "ping"}, headers=s, accept="text/event-stream")
    await post(http, "accept wildcard", {"jsonrpc": "2.0", "id": 22, "method": "ping"}, headers=s, accept="*/*")
    await post(http, "accept with q params", {"jsonrpc": "2.0", "id": 23, "method": "ping"}, headers=s, accept="application/json;q=0.9, text/event-stream;q=0.8")
    await post(http, "no accept", {"jsonrpc": "2.0", "id": 24, "method": "ping"}, headers=s, accept=None)
    await post(http, "no content-type", {"jsonrpc": "2.0", "id": 25, "method": "ping"}, headers=s, ctype=None)
    await post(http, "text/plain content-type", {"jsonrpc": "2.0", "id": 26, "method": "ping"}, headers=s, ctype="text/plain")
    await post(http, "json charset content-type", {"jsonrpc": "2.0", "id": 27, "method": "ping"}, headers=s, ctype="application/json; charset=utf-8")
    r = await post(http, "missing session id", {"jsonrpc": "2.0", "id": 28, "method": "ping"})
    # A refused opening request establishes nothing: the id it was answered
    # with is already forgotten.
    refused = r.headers.get("mcp-session-id")
    if refused:
        await post(http, "id from refused opening request", {"jsonrpc": "2.0", "id": 28, "method": "ping"}, headers={"Mcp-Session-Id": refused})
    await post(http, "unknown session id", {"jsonrpc": "2.0", "id": 29, "method": "ping"}, headers={"Mcp-Session-Id": "deadbeef"})
    await post(http, "session-era version header", {"jsonrpc": "2.0", "id": 30, "method": "ping"}, headers={**s, "MCP-Protocol-Version": "2024-11-05"})
    await post(http, "modern envelope on session", {"jsonrpc": "2.0", "id": 31, "method": "tools/list", "params": {"_meta": META}}, headers=s)

    r = await http.get(BASE + "/mcp", headers={"Accept": "application/json", **s})
    record("GET without sse accept", r, r.text)
    r = await http.get(BASE + "/mcp", headers={"Accept": "text/event-stream"})
    record("GET without session id", r, r.text)
    refused = r.headers.get("mcp-session-id")
    if refused:
        r = await http.get(BASE + "/mcp", headers={"Accept": "text/event-stream", "Mcp-Session-Id": refused})
        record("GET with id from refused GET", r, r.text)
    r = await http.put(BASE + "/mcp", headers=s, content=b"{}")
    record("PUT on session", r, r.text)
    r = await http.request("PATCH", BASE + "/mcp", content=b"")
    record("PATCH without session", r, r.text)

    # Big body: capped for every method, not just POST.
    big = b'{"x":"' + b"a" * (4 * 1024 * 1024) + b'"}'
    await post(http, "oversized body", None, raw=big, headers=s)
    tracked = (await http.get(BASE + "/_tracked")).json()
    OUT.append(f"== tracked before oversized DELETE: {tracked['tracked']}")
    r = await http.request("DELETE", BASE + "/mcp", headers=s, content=big)
    record("DELETE with oversized body", r, r.text)
    # `SessionReaper` sits outside the body cap: the session is untracked
    # even though the transport never saw the DELETE.
    tracked = (await http.get(BASE + "/_tracked")).json()
    OUT.append(f"== tracked after oversized DELETE: {tracked['tracked']}")
    r = await http.request("GET", BASE + "/mcp", headers={"Accept": "text/event-stream", **s}, content=big)
    record("GET with oversized body", r, r.text)
    await post(http, "session survives oversized DELETE", {"jsonrpc": "2.0", "id": 32, "method": "tools/list"}, headers=s)
    tracked = (await http.get(BASE + "/_tracked")).json()
    OUT.append(f"== tracked again after tools/list: {tracked['tracked']}")

    # Other negotiated versions.
    for version in ("2024-11-05", "2025-03-26", "2025-11-25", "1999-01-01", MODERN):
        await post(http, f"initialize {version}", init_payload(version))
    await post(http, "initialize missing params", {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    await post(http, "initialize bad clientInfo", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
    await post(http, "initialize as notification", {"jsonrpc": "2.0", "method": "initialize"})

    # Standalone stream: notification after a catalog change, then 409 for a second GET.
    async with http.stream("GET", BASE + "/mcp", headers={"Accept": "text/event-stream", **s}) as stream:
        record("GET standalone stream (headers)", stream, "")
        r2 = await http.get(BASE + "/mcp", headers={"Accept": "text/event-stream", **s})
        record("second GET stream", r2, r2.text)
        await http.post(BASE + "/_change")
        events = await read_stream_events(stream, 1)
        OUT.append("== standalone stream events after change")
        OUT.extend(mask(e) for e in events)
    await http.post(BASE + "/_change")  # restore

    # Tracking and DELETE.
    tracked = (await http.get(BASE + "/_tracked")).json()
    OUT.append(f"== tracked before delete: {tracked['tracked'] > 0}")
    r = await http.delete(BASE + "/mcp", headers=s)
    record("DELETE session", r, r.text)
    await post(http, "after DELETE", {"jsonrpc": "2.0", "id": 40, "method": "ping"}, headers=s)
    r = await http.delete(BASE + "/mcp", headers=s)
    record("DELETE again", r, r.text)
    r = await http.delete(BASE + "/mcp")
    record("DELETE without session id", r, r.text)

    # Initialize-then-request without the initialized notification.
    r = await post(http, "initialize (no initialized notification)", init_payload("2025-06-18"))
    s2 = {"Mcp-Session-Id": r.headers["mcp-session-id"]}
    await post(http, "tools/list before initialized notification", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=s2)

    # Cancellation of an in-flight request on the session era.
    async def slow():
        return await http.post(
            BASE + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 50, "method": "tools/call", "params": {"name": "demo.slow", "arguments": {"seconds": 5}}}),
            headers={"Accept": ACCEPT_BOTH, "Content-Type": JSON_CT, **s2},
        )

    task = asyncio.create_task(slow())
    await asyncio.sleep(0.5)
    await post(http, "cancel in-flight", {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 50, "reason": "x"}}, headers=s2)
    r = await task
    record("cancelled request response", r, r.text)


async def modern_era(http: httpx.AsyncClient) -> None:
    OUT.append("#### modern era")

    def req(rid, method, params=None, meta=True):
        p = dict(params or {})
        if meta:
            p["_meta"] = META
        return {"jsonrpc": "2.0", "id": rid, "method": method, "params": p}

    await post(http, "discover", req(1, "server/discover"), headers=modern_headers("server/discover"))
    await post(http, "tools/list", req(2, "tools/list"), headers=modern_headers("tools/list"))
    await post(http, "tools/call echo", req(3, "tools/call", {"name": "demo.echo", "arguments": {"text": "hi"}}), headers=modern_headers("tools/call", "demo.echo"))
    await post(http, "tools/call raises", req(4, "tools/call", {"name": "demo.fail", "arguments": {}}), headers=modern_headers("tools/call", "demo.fail"))
    await post(http, "tools/call unknown", req(5, "tools/call", {"name": "nope"}), headers=modern_headers("tools/call", "nope"))
    await post(http, "tools/call missing name", req(6, "tools/call", {}), headers=modern_headers("tools/call"))
    await post(http, "tools/call name header missing", req(7, "tools/call", {"name": "demo.echo", "arguments": {"text": "x"}}), headers=modern_headers("tools/call"))
    await post(http, "tools/call name header mismatch", req(8, "tools/call", {"name": "demo.echo", "arguments": {"text": "x"}}), headers=modern_headers("tools/call", "other"))
    await post(http, "tools/call name header base64", req(9, "tools/call", {"name": "demo.echo", "arguments": {"text": "x"}}), headers=modern_headers("tools/call", "=?base64?ZGVtby5lY2hv?="))
    await post(http, "ping (removed at 2026)", req(10, "ping"), headers=modern_headers("ping"))
    await post(http, "initialize on modern wire", req(11, "initialize", {"protocolVersion": MODERN, "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}), headers=modern_headers("initialize"))
    await post(http, "unknown method", req(12, "foo/bar"), headers=modern_headers("foo/bar"))
    await post(http, "resources/list (no handler)", req(13, "resources/list"), headers=modern_headers("resources/list"))
    await post(http, "missing _meta", req(14, "tools/list", meta=False), headers=modern_headers("tools/list"))
    await post(http, "no params", {"jsonrpc": "2.0", "id": 15, "method": "tools/list"}, headers=modern_headers("tools/list"))
    bad_meta = {"jsonrpc": "2.0", "id": 16, "method": "tools/list", "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": MODERN}}}
    await post(http, "meta missing capabilities", bad_meta, headers=modern_headers("tools/list"))
    await post(http, "method header mismatch", req(17, "tools/list"), headers=modern_headers("tools/call"))
    await post(http, "method header missing", req(18, "tools/list"), headers={"MCP-Protocol-Version": MODERN})
    other = dict(META)
    other["io.modelcontextprotocol/protocolVersion"] = "2030-01-01"
    await post(http, "unsupported version (header+meta agree)", {"jsonrpc": "2.0", "id": 19, "method": "tools/list", "params": {"_meta": other}}, headers=modern_headers("tools/list", version="2030-01-01"))
    await post(http, "version header mismatch", req(20, "tools/list"), headers=modern_headers("tools/list", version="2030-01-01"))
    await post(http, "duplicate routing header", req(21, "tools/list"), headers=[("MCP-Protocol-Version", MODERN), ("Mcp-Method", "tools/list"), ("Mcp-Method", "tools/list")])
    await post(http, "notification body", {"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=modern_headers("notifications/initialized"))
    await post(http, "cancelled notification", {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}, headers=modern_headers("notifications/cancelled"))
    await post(http, "notification without method header", {"jsonrpc": "2.0", "method": "notifications/initialized"}, headers={"MCP-Protocol-Version": MODERN})
    await post(http, "notification at unsupported version", {"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=modern_headers("notifications/initialized", version="2030-01-01"))
    await post(http, "notification missing method", {"jsonrpc": "2.0"}, headers=modern_headers("x"))
    await post(http, "notification wrong jsonrpc", {"jsonrpc": "1.0", "method": "notifications/initialized"}, headers=modern_headers("notifications/initialized"))
    await post(http, "notification params not object", {"jsonrpc": "2.0", "method": "notifications/initialized", "params": [1]}, headers=modern_headers("notifications/initialized"))
    await post(http, "posted response", {"jsonrpc": "2.0", "id": 5, "result": {}}, headers=modern_headers("x"))
    await post(http, "request with null id", {"jsonrpc": "2.0", "id": None, "method": "tools/list", "params": {"_meta": META}}, headers=modern_headers("tools/list"))
    await post(http, "admin notification", {"jsonrpc": "2.0", "method": "notifications/initialized"}, path="/admin/mcp", headers=modern_headers("notifications/initialized"))
    await post(http, "parse error", None, raw=b"[1,", headers=modern_headers("tools/list"))
    await post(http, "batch", [req(22, "tools/list")], headers=modern_headers("tools/list"))
    await post(http, "accept json only", req(23, "tools/list"), headers=modern_headers("tools/list"), accept="application/json")
    await post(http, "no content-type", req(24, "tools/list"), headers=modern_headers("tools/list"), ctype=None)
    await post(http, "string id", req("s-1", "tools/list"), headers=modern_headers("tools/list"))
    await post(http, "no clientInfo", {"jsonrpc": "2.0", "id": 25, "method": "tools/list", "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}}}}, headers=modern_headers("tools/list"))
    await post(http, "listen without sse accept", req(26, "subscriptions/listen", {"notifications": {"toolsListChanged": True}}), headers=modern_headers("subscriptions/listen"), accept="application/json")
    await post(http, "listen missing notifications", req(27, "subscriptions/listen"), headers=modern_headers("subscriptions/listen"))
    await post(http, "session id header is ignored", req(28, "tools/list"), headers={**modern_headers("tools/list"), "Mcp-Session-Id": "whatever"})
    r = await http.get(BASE + "/mcp", headers={"Accept": "text/event-stream", **modern_headers("x")})
    record("GET on modern wire", r, r.text)
    r = await http.delete(BASE + "/mcp", headers=modern_headers("x"))
    record("DELETE on modern wire", r, r.text)
    await post(http, "admin discover", req(29, "server/discover"), path="/admin/mcp", headers=modern_headers("server/discover"))
    await post(http, "admin tools/list", req(30, "tools/list"), path="/admin/mcp", headers=modern_headers("tools/list"))
    await post(http, "admin listen (not served)", req(31, "subscriptions/listen", {"notifications": {"toolsListChanged": True}}), path="/admin/mcp", headers=modern_headers("subscriptions/listen"))

    # A listen stream: ack first, then the change notification, filtered.
    listen = req(40, "subscriptions/listen", {"notifications": {"toolsListChanged": True, "promptsListChanged": False, "resourceSubscriptions": []}})
    async with http.stream(
        "POST", BASE + "/mcp", content=json.dumps(listen),
        headers={"Accept": ACCEPT_BOTH, "Content-Type": JSON_CT, **modern_headers("subscriptions/listen")},
    ) as stream:
        record("listen stream (headers)", stream, "")
        first = await read_stream_events(stream, 1)
        OUT.append("== listen ack")
        OUT.extend(first)
        await http.post(BASE + "/_change")
        later = await read_stream_events(stream, 1)
        OUT.append("== listen event after change")
        OUT.extend(later)
    await http.post(BASE + "/_change")

    listen = req(41, "subscriptions/listen", {"notifications": {"resourcesListChanged": True}})
    async with http.stream(
        "POST", BASE + "/mcp", content=json.dumps(listen),
        headers={"Accept": ACCEPT_BOTH, "Content-Type": JSON_CT, **modern_headers("subscriptions/listen")},
    ) as stream:
        first = await read_stream_events(stream, 1)
        OUT.append("== listen ack (other kinds only)")
        OUT.extend(first)


async def stateless(http: httpx.AsyncClient) -> None:
    OUT.append("#### stateless mount")
    path = "/admin/mcp"
    await post(http, "initialize", init_payload("2025-06-18"), path=path)
    await post(http, "tools/list without initialize", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, path=path)
    await post(http, "tools/list with version header", {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, path=path, headers={"MCP-Protocol-Version": "2025-11-25"})
    await post(http, "tools/call", {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "demo.echo", "arguments": {"text": "a"}}}, path=path)
    await post(http, "initialized notification", {"jsonrpc": "2.0", "method": "notifications/initialized"}, path=path)
    await post(http, "session id is ignored", {"jsonrpc": "2.0", "id": 5, "method": "ping"}, path=path, headers={"Mcp-Session-Id": "abc"})
    await post(http, "subscriptions/listen", {"jsonrpc": "2.0", "id": 6, "method": "subscriptions/listen", "params": {"notifications": {}}}, path=path)
    await post(http, "unknown method", {"jsonrpc": "2.0", "id": 7, "method": "nope"}, path=path)
    await post(http, "parse error", None, raw=b"nope", path=path)
    await post(http, "accept json only", {"jsonrpc": "2.0", "id": 8, "method": "ping"}, path=path, accept="application/json")
    r = await http.delete(BASE + path)
    record("DELETE", r, r.text)
    r = await http.put(BASE + path, content=b"")
    record("PUT", r, r.text)
    r = await http.get(BASE + path, headers={"Accept": "application/json"})
    record("GET without sse accept", r, r.text)
    try:
        async with http.stream("GET", BASE + path, headers={"Accept": "text/event-stream"}, timeout=2.0) as stream:
            record("GET stream (headers)", stream, "")
    except httpx.TimeoutException:
        OUT.append("== GET stream timed out")


async def main() -> None:
    try:
        async with httpx.AsyncClient(timeout=30.0) as http:
            await session_era(http)
            await modern_era(http)
            await stateless(http)
    finally:
        # Print what was gathered even when a step blows up, so a diff
        # shows where the two servers parted ways.
        print("\n".join(OUT))


if __name__ == "__main__":
    asyncio.run(main())
