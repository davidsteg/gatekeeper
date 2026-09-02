"""The `opencode` executor (REQUIREMENTS.md §8, FR-8.5/8.7/8.9/8.12 applied
to a multi-request workflow).

opencode runs as a headless server on the LAN and exposes an OpenAPI 3.1
HTTP API -- not MCP. Reaching it through the plain `http` executor would
work for a single endpoint, but the useful units of work are not single
requests: "ask a question and get the answer" is `POST /session` followed
by `POST /session/{id}/message`; "run this task to completion" is a
session, an async dispatch, and a poll loop. Expressed as `http` tools
that would be three or four agent round trips per task, with the session
id travelling back through the agent's context each time -- and every
intermediate response (raw opencode message objects) spent on context for
no one to read.

So this executor is the same shape as `truenas`/`google`: the whitelist
acts on **operation names**, and one operation is one fixed workflow.
What it keeps from `execute_http.py`, deliberately by reusing that
module's own helpers rather than restating them:

* the target lives exclusively on the toolkit (`base_url`, FR-8.5) --
  there is no parameter, on any operation, that carries a URL, a host, or
  a path;
* every request resolves the host and re-checks the resolved IP against
  the toolkit's `allowed_cidrs` immediately before connecting (FR-8.9),
  per request, not once per call;
* redirects are reported, never followed (FR-8.8);
* the credential is injected as a header by this module (FR-8.14);
* responses are external, untrusted data -- an opencode session summarises
  files and diffs it read from a repository, so `external_untrusted=True`
  and the JSON field-count cap (FR-8.12) both apply exactly as they do to
  a Sonarr response.

The request paths are **fixed here**, in `_EP` below, and nowhere else.
They are the one part of this module that tracks an external API's shape,
so they are a single table to re-point if a future opencode release moves
an endpoint, rather than strings scattered through eight workflows.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import execute_http
from .credentials import CredentialStore, ResolvedCredential
from .errors import DenialReason, Denied
from .execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN, Result
from .execute_http import (
    MAX_JSON_ITEMS,
    _cap_json,
    _credential_headers,
    _resolve_and_check,
)
from .tier1 import Toolkit

#: The opencode HTTP API endpoints this executor uses, as
#: ``(method, path template)``. `{id}` is filled with a session id that
#: has already passed `check_session_id` -- the only value from a
#: parameter that ever reaches a path, and it is restricted to a
#: character set that cannot introduce a segment (FR-8.7's counterpart:
#: a parameter fills exactly one path segment, and cannot become two).
_EP: dict[str, tuple[str, str]] = {
    "session_create": ("POST", "/session"),
    "session_message": ("POST", "/session/{id}/message"),
    "session_prompt_async": ("POST", "/session/{id}/prompt_async"),
    "session_get": ("GET", "/session/{id}"),
    "session_todo": ("GET", "/session/{id}/todo"),
    "session_diff": ("GET", "/session/{id}/diff"),
    "session_abort": ("POST", "/session/{id}/abort"),
    "providers": ("GET", "/config/providers"),
    "health": ("GET", "/global/health"),
}

#: The header opencode reads to decide which project root a session works
#: in. This is why one toolkit fans out across repositories without one
#: toolkit per repository -- and why `directory` is checked against the
#: toolkit's `path_roots` before it is sent (`check_directory`).
_DIRECTORY_HEADER = "x-opencode-directory"

#: A session id, as it may appear in a request path. Deliberately
#: narrower than "whatever opencode returns": no `/`, no `.`, no
#: percent-escape, so a value that reached here through a permissive
#: tool pattern still cannot address a different endpoint.
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: How often `run` asks the session whether it is finished. Short enough
#: that a 20-second task does not sit idle for a minute afterwards, long
#: enough that a 10-minute task costs ~120 cheap GETs, not thousands.
_POLL_INTERVAL_SECONDS = 5.0

#: Ceiling for any single HTTP request inside a workflow. The call's own
#: `timeout_seconds` is the budget for the *whole* operation; a single
#: request that hangs must not be able to spend all of it silently, so
#: each one is additionally capped here.
_PER_REQUEST_TIMEOUT_SECONDS = 60.0

#: Field-count cap for the compact summaries below. Lower than
#: `MAX_JSON_ITEMS`, on purpose: an opencode answer goes straight into an
#: agent's context, and the point of these workflows is that the agent
#: gets a result, not a transcript.
_SUMMARY_ITEMS = 200


async def _read_capped(
    response: httpx.Response, limit: int
) -> tuple[bytes, bool]:
    """Reads a streamed response body, stopping at `limit` bytes.

    Streamed rather than `response.content` for the same reason
    `execute_http.run` streams: the ceiling has to bound what gatekeeper
    *reads*, not merely what it forwards. A response that exceeds it is
    reported (the caller raises), never silently truncated into an
    unparseable half-document.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        if total + len(chunk) > limit:
            return b"".join(chunks), True
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), False


class _OpencodeError(Exception):
    """An HTTP-level failure inside a workflow.

    Carries the status and a short message so the operation that raised
    it can be reported with the request that actually failed, rather than
    as a generic "the workflow did not complete".
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


# -- Tier 1 checks on the two agent-supplied values --------------------------
#
# Both are public: `validate.build_opencode_call` runs them *before*
# execution so a bad value is an ordinary audited denial, and this module
# runs them again on the values it is handed -- the same doubled check
# `build_argv` does with `check_binary`, for the same reason.


def check_session_id(session_id: str) -> str:
    """FR-8.7's counterpart for the one parameter that reaches a path."""
    if not _SESSION_ID_RE.fullmatch(session_id):
        raise Denied(
            DenialReason.PARAM_INVALID,
            "session_id must be 1-128 characters of A-Z, a-z, 0-9, '_' or '-'.",
        )
    return session_id


def check_directory(directory: str, toolkit: Toolkit) -> str:
    """Checks a `directory` against the toolkit's `path_roots` (FR-4.10).

    `path_roots` is the whole target restriction here, the way
    `allowed_path_prefixes` is for `http`: a toolkit that declares none
    accepts no `directory` at all, and a toolkit that declares
    `/mnt/raid/projects` can never be pointed at `/etc`.

    Two deliberate differences from `validate._resolve_path`, which does
    the same job for the `file`/`local` executors:

    * The comparison is purely lexical (`PurePosixPath`), not
      `realpath`-based. This path names a directory inside the **opencode
      container's** filesystem, not gatekeeper's -- resolving symlinks
      here would resolve them in the wrong namespace, and a root that
      gatekeeper cannot see at all would resolve to itself and quietly
      compare as equal.
    * Existence is therefore checked only when the matching root is
      visible in gatekeeper's own filesystem (the usual case: the same
      host directory is mounted into both containers). Where it is not,
      gatekeeper cannot answer the question and does not pretend to --
      opencode reports an unknown directory itself.
    """
    if not directory.startswith("/"):
        raise Denied(
            DenialReason.PARAM_INVALID,
            f"directory {directory!r} must be an absolute path.",
        )
    parts = PurePosixPath(directory).parts
    if ".." in parts:
        raise Denied(
            DenialReason.PATH_ESCAPE,
            f"directory {directory!r} contains a '..' segment.",
        )
    if not toolkit.path_roots:
        raise Denied(
            DenialReason.TIER1_VIOLATION,
            f"Toolkit {toolkit.name!r} declares no path_roots, so no "
            "'directory' can be accepted for it.",
        )

    candidate = PurePosixPath(directory)
    for root in toolkit.path_roots:
        root_path = PurePosixPath(root)
        if candidate == root_path or root_path in candidate.parents:
            _check_exists_if_visible(directory, root)
            return directory
    raise Denied(
        DenialReason.PATH_ESCAPE,
        f"directory {directory!r} lies outside this toolkit's path_roots "
        f"{list(toolkit.path_roots)}.",
    )


def _check_exists_if_visible(directory: str, root: str) -> None:
    """Rejects a typo'd directory -- but only where that is answerable.

    See `check_directory`: if the root itself is not mounted into this
    container, gatekeeper has no filesystem to check against and stays
    quiet rather than rejecting every valid path.
    """
    if not os.path.isdir(root):
        return
    if not os.path.isdir(directory):
        raise Denied(
            DenialReason.PARAM_INVALID,
            f"directory {directory!r} does not exist.",
        )


# -- One HTTP request, SSRF-checked ------------------------------------------


class _Client:
    """Issues the requests of one workflow against one checked target.

    Holds no state beyond the toolkit, the resolved headers and a shared
    `httpx.AsyncClient` -- but re-resolves and re-checks the host per
    request (FR-8.9). A workflow can span minutes (`run` polls), and a
    single check at the start of it would leave exactly the rebinding
    window that requirement exists to close.
    """

    def __init__(
        self,
        *,
        toolkit: Toolkit,
        credential: ResolvedCredential | None,
        directory: str | None,
        client: httpx.AsyncClient,
        deadline: float,
    ) -> None:
        assert toolkit.base_url is not None
        self.toolkit = toolkit
        self.client = client
        self.deadline = deadline
        parsed = urlsplit(toolkit.base_url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.base_path = parsed.path.rstrip("/")
        self.headers: dict[str, str] = {
            "Host": self.host if self.port in (80, 443) else f"{self.host}:{self.port}",
            "Accept": "application/json",
        }
        self.headers.update(_credential_headers(credential))
        if directory:
            self.headers[_DIRECTORY_HEADER] = directory
        #: The status of the most recent response, reported as the
        #: Result's exit_code the way `execute_http` reports its single
        #: response's status.
        self.last_status: int | None = None
        #: The session this workflow is working on, once it is known.
        #: Recorded here rather than only in the summary because the one
        #: path that never reaches a summary -- a timed-out `run` -- is
        #: precisely the one where losing it would strand a session the
        #: agent can then never `check` on.
        self.session_id: str | None = None

    def _remaining(self) -> float:
        return self.deadline - time.monotonic()

    async def request(
        self,
        endpoint: str,
        *,
        session_id: str | None = None,
        body: dict[str, Any] | None = None,
        max_output_bytes: int,
    ) -> Any:
        """Issues one request and returns its parsed JSON body.

        Raises `_OpencodeError` for anything that is not a 2xx with a
        readable body, and `TimeoutError` when the operation's overall
        budget is gone -- the caller turns both into a `Result`.
        """
        method, template = _EP[endpoint]
        path = template
        if session_id is not None:
            path = template.replace("{id}", check_session_id(session_id))

        remaining = self._remaining()
        if remaining <= 0:
            raise TimeoutError
        timeout = min(remaining, _PER_REQUEST_TIMEOUT_SECONDS)

        # The resolved IP, re-checked now, is what we connect to -- httpx
        # is handed an IP literal so it never performs a second lookup
        # this check would not have seen (FR-8.9).
        resolved_ip = await _resolve_and_check(self.host, self.port, self.toolkit)
        url = httpx.URL(
            scheme=self.scheme,
            host=resolved_ip,
            port=self.port,
            path=self.base_path + path,
        )
        extensions = {"sni_hostname": self.host} if self.scheme == "https" else {}

        request = self.client.build_request(
            method, url, json=body, headers=self.headers, extensions=extensions
        )
        try:
            response = await asyncio.wait_for(
                self.client.send(request, follow_redirects=False, stream=True),
                timeout=timeout,
            )
            try:
                raw, over_cap = await _read_capped(response, max_output_bytes)
            finally:
                await response.aclose()
        except (TimeoutError, httpx.TimeoutException) as exc:
            if self._remaining() <= 0:
                raise TimeoutError from exc
            raise _OpencodeError(
                f"{method} {path} did not answer within {int(timeout)}s."
            ) from exc
        except httpx.HTTPError as exc:
            raise _OpencodeError(f"{method} {path} failed: {exc}") from exc

        self.last_status = response.status_code

        if 300 <= response.status_code < 400:
            # FR-8.8: reported as data, never chased.
            location = response.headers.get("location", "")
            raise _OpencodeError(
                f"{method} {path} redirected ({response.status_code}) to "
                f"{location!r}; redirects are not followed.",
                status=response.status_code,
            )
        if not 200 <= response.status_code < 300:
            detail = raw.decode("utf-8", errors="replace").strip()
            raise _OpencodeError(
                f"{method} {path} returned {response.status_code}: "
                f"{detail[:500] or '(empty body)'}",
                status=response.status_code,
            )

        if over_cap:
            # A body larger than the call's own output ceiling cannot be
            # parsed into a summary -- half a JSON document is not a
            # smaller JSON document. Reported as what it is rather than
            # as "not JSON", which would send the reader looking for the
            # wrong problem.
            raise _OpencodeError(
                f"{method} {path} returned more than the tool's "
                f"max_output_bytes ({max_output_bytes}); no summary could be "
                "built. Narrow the request or raise the ceiling.",
                status=response.status_code,
            )
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError as exc:
            raise _OpencodeError(
                f"{method} {path} returned a non-JSON body.",
                status=response.status_code,
            ) from exc


# -- Reading opencode's responses --------------------------------------------
#
# Every reader below is written to *degrade*, not to fail, when a field is
# named differently than expected: opencode is a fast-moving upstream, and
# a renamed key should cost an agent a less tidy summary, not the whole
# operation. `_summarise` therefore attaches the (capped) raw payload
# whenever a summary came back empty, so the agent still has something to
# work with and the drift is visible in the response rather than silent.


def _first(payload: Any, *keys: str) -> Any:
    """The first present, non-empty value among `keys`, at the top level or
    one level down under `info`/`session`/`data` -- the three wrappers
    opencode's own responses use interchangeably.
    """
    if not isinstance(payload, dict):
        return None
    scopes: list[dict[str, Any]] = [payload]
    for wrapper in ("info", "session", "data", "result"):
        nested = payload.get(wrapper)
        if isinstance(nested, dict):
            scopes.append(nested)
    for scope in scopes:
        for key in keys:
            value = scope.get(key)
            if value not in (None, "", [], {}):
                return value
    return None


def _session_id_of(payload: Any) -> str | None:
    value = _first(payload, "id", "sessionId", "session_id", "sessionID")
    return str(value) if isinstance(value, (str, int)) else None


#: Session states that mean "opencode is no longer working on this".
_TERMINAL_STATES = frozenset(
    {"idle", "completed", "complete", "done", "finished", "error", "aborted", "cancelled"}
)


def _session_is_done(payload: Any) -> bool:
    """Whether a session has stopped working, read tolerantly.

    Four independent signals, any one of which is conclusive; a response
    that carries none of them is treated as "still running", so `run`
    keeps polling until its own timeout rather than declaring a task
    finished it cannot see the end of.
    """
    state = _first(payload, "status", "state")
    if isinstance(state, str) and state.strip().lower() in _TERMINAL_STATES:
        return True
    if _first(payload, "error") is not None:
        return True
    idle = _first(payload, "idle")
    if idle is True:
        return True
    for key in ("busy", "running", "working"):
        if isinstance(payload, dict) and payload.get(key) is False:
            return True
    time_field = _first(payload, "time")
    if isinstance(time_field, dict) and time_field.get("completed"):
        return True
    return False


def _session_status(payload: Any) -> str:
    state = _first(payload, "status", "state")
    if isinstance(state, str) and state.strip():
        return state.strip()
    if _first(payload, "error") is not None:
        return "error"
    return "idle" if _session_is_done(payload) else "running"


def _message_text(payload: Any) -> str:
    """The assistant's answer, out of whichever shape it arrived in.

    opencode has returned answers as a bare string, as ``{"text": ...}``,
    and as a ``parts``/``content`` list of typed blocks. All three are
    read here; anything else falls through to the raw-payload fallback in
    `_summarise`.
    """
    if isinstance(payload, str):
        return payload
    direct = _first(payload, "text", "content", "answer", "message", "output")
    if isinstance(direct, str):
        return direct
    blocks = direct if isinstance(direct, list) else _first(payload, "parts")
    if isinstance(blocks, list):
        chunks: list[str] = []
        for block in blocks:
            if isinstance(block, str):
                chunks.append(block)
            elif isinstance(block, dict):
                text = block.get("text") or block.get("content")
                if isinstance(text, str):
                    chunks.append(text)
        if chunks:
            return "\n".join(chunks)
    return ""


def _files_changed(diff_payload: Any) -> list[dict[str, Any]]:
    """Per-file add/remove counts out of a diff response.

    Accepts a list of file objects, a ``{"files": [...]}`` wrapper, or a
    ``{path: patch}`` mapping -- the last one counting `+`/`-` lines out
    of the unified diff itself, which is the only reading that works when
    opencode hands back raw patches instead of statistics.
    """
    entries = diff_payload
    if isinstance(diff_payload, dict):
        wrapped = _first(diff_payload, "files", "diffs", "changes")
        entries = wrapped if wrapped is not None else diff_payload

    files: list[dict[str, Any]] = []
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, str):
                files.append({"path": entry})
            elif isinstance(entry, dict):
                path = entry.get("path") or entry.get("file") or entry.get("filename")
                record: dict[str, Any] = {"path": str(path) if path else "(unnamed)"}
                for key, out in (
                    ("additions", "added"), ("added", "added"), ("insertions", "added"),
                    ("deletions", "removed"), ("removed", "removed"),
                ):
                    if isinstance(entry.get(key), int) and out not in record:
                        record[out] = entry[key]
                if "added" not in record and isinstance(entry.get("patch"), str):
                    record.update(_count_patch_lines(entry["patch"]))
                if entry.get("status"):
                    record["status"] = str(entry["status"])
                files.append(record)
    elif isinstance(entries, dict):
        for path, patch in entries.items():
            record = {"path": str(path)}
            if isinstance(patch, str):
                record.update(_count_patch_lines(patch))
            files.append(record)
    return files


def _count_patch_lines(patch: str) -> dict[str, int]:
    added = removed = 0
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return {"added": added, "removed": removed}


def _todos(payload: Any) -> list[dict[str, Any]]:
    entries = payload
    if isinstance(payload, dict):
        wrapped = _first(payload, "todos", "items", "todo")
        entries = wrapped if wrapped is not None else []
    if not isinstance(entries, list):
        return []
    todos: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, str):
            todos.append({"task": entry})
        elif isinstance(entry, dict):
            task = entry.get("content") or entry.get("text") or entry.get("task")
            todos.append(
                {
                    "task": str(task) if task else "(unnamed)",
                    "status": str(entry.get("status") or entry.get("state") or "unknown"),
                }
            )
    return todos


def _providers(payload: Any) -> list[dict[str, Any]]:
    entries = payload
    defaults: dict[str, Any] = {}
    if isinstance(payload, dict):
        raw_defaults = payload.get("default") or payload.get("defaults")
        if isinstance(raw_defaults, dict):
            defaults = raw_defaults
        wrapped = _first(payload, "providers", "items")
        entries = wrapped if wrapped is not None else []
    if not isinstance(entries, list):
        return []
    providers: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        provider_id = str(entry.get("id") or entry.get("name") or "(unnamed)")
        models = entry.get("models")
        model_ids: list[str] = []
        if isinstance(models, dict):
            model_ids = [str(k) for k in models]
        elif isinstance(models, list):
            model_ids = [
                str(m.get("id") or m.get("name")) if isinstance(m, dict) else str(m)
                for m in models
            ]
        record: dict[str, Any] = {"id": provider_id}
        if entry.get("name"):
            record["name"] = str(entry["name"])
        if provider_id in defaults:
            record["default_model"] = str(defaults[provider_id])
        if model_ids:
            record["models"] = model_ids
        providers.append(record)
    return providers


def _summarise(summary: dict[str, Any], payload: Any, *keys: str) -> dict[str, Any]:
    """Attaches the capped raw payload when every extracted field is empty.

    The one guard against this module's tolerant readers silently
    returning `{"operation": "check"}` after an upstream rename: the
    agent gets the raw response instead, and the drift is visible in the
    output rather than only in a diff of opencode's OpenAPI spec.
    """
    if payload is None:
        return summary
    if any(summary.get(key) not in (None, "", [], {}) for key in keys):
        return summary
    summary["raw"] = _cap_json(payload, limit=_SUMMARY_ITEMS, budget=[_SUMMARY_ITEMS])
    return summary


# -- The workflows -----------------------------------------------------------


def _prompt_body(values: dict[str, str]) -> dict[str, Any]:
    """The message body every prompt-carrying operation sends.

    One shape, opencode's own: a `parts` list of typed blocks, plus
    `providerID`/`modelID` and `agent` only when the call actually named
    them -- an explicit null would override opencode's own default
    instead of deferring to it.

    Deliberately *not* belt-and-braces. The readers below tolerate
    several field names because responses are outside gatekeeper's
    control; a request body is the opposite case, and shipping extra keys
    on the chance that one of them is the real one would leave nobody
    able to say which shape this executor actually asserts. Like `_EP`
    above, this is a place that tracks an external API: when it drifts,
    opencode answers 4xx with its own complaint, and the complaint
    reaches the agent verbatim in the failure message.
    """
    body: dict[str, Any] = {
        "parts": [{"type": "text", "text": values.get("prompt", "")}],
    }
    model = values.get("model")
    if model:
        provider, sep, model_id = model.partition("/")
        if not sep or not provider or not model_id:
            raise Denied(
                DenialReason.PARAM_INVALID,
                f"model {model!r} must be 'provider/model', e.g. "
                "'anthropic/claude-opus-5'.",
            )
        body["providerID"] = provider
        body["modelID"] = model_id
    agent = values.get("agent")
    if agent:
        body["agent"] = agent
    return body


async def _create_session(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> str:
    title = values.get("title") or "gatekeeper"
    payload = await client.request(
        "session_create", body={"title": title}, max_output_bytes=max_output_bytes
    )
    session_id = _session_id_of(payload)
    if not session_id:
        raise _OpencodeError(
            "opencode created a session but returned no usable session id."
        )
    client.session_id = check_session_id(session_id)
    return client.session_id


async def _op_ask(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> dict[str, Any]:
    session_id = values.get("session_id") or await _create_session(
        client, values, max_output_bytes
    )
    client.session_id = session_id
    payload = await client.request(
        "session_message",
        session_id=session_id,
        body=_prompt_body(values),
        max_output_bytes=max_output_bytes,
    )
    summary: dict[str, Any] = {
        "operation": "ask",
        "session_id": session_id,
        "answer": _message_text(payload),
    }
    return _summarise(summary, payload, "answer")


async def _op_fire(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> dict[str, Any]:
    session_id = values.get("session_id") or await _create_session(
        client, values, max_output_bytes
    )
    client.session_id = session_id
    await client.request(
        "session_prompt_async",
        session_id=session_id,
        body=_prompt_body(values),
        max_output_bytes=max_output_bytes,
    )
    return {
        "operation": "fire",
        "session_id": session_id,
        "status": "dispatched",
        "next": (
            "The task runs in the background. Call the check operation with "
            f"session_id={session_id!r} for progress."
        ),
    }


async def _op_run(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> dict[str, Any]:
    """fire, then poll until the session stops working.

    A timeout here is deliberately not a failure of the task: the prompt
    has reached opencode and the session keeps running on the other side.
    The `TimeoutError` propagates to `run()`, which reports
    `OUTCOME_UNKNOWN` for a non-idempotent tool -- with the session id, so
    the follow-up is `check`, not a retry that would start the work twice.
    """
    session_id = values.get("session_id") or await _create_session(
        client, values, max_output_bytes
    )
    client.session_id = session_id
    await client.request(
        "session_prompt_async",
        session_id=session_id,
        body=_prompt_body(values),
        max_output_bytes=max_output_bytes,
    )

    session: Any = None
    while True:
        session = await client.request(
            "session_get", session_id=session_id, max_output_bytes=max_output_bytes
        )
        if _session_is_done(session):
            break
        remaining = client.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        await asyncio.sleep(min(_POLL_INTERVAL_SECONDS, remaining))

    summary = await _report(client, session_id, session, max_output_bytes)
    summary["operation"] = "run"
    return summary


async def _op_check(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> dict[str, Any]:
    session_id = check_session_id(values.get("session_id", ""))
    client.session_id = session_id
    session = await client.request(
        "session_get", session_id=session_id, max_output_bytes=max_output_bytes
    )
    summary = await _report(client, session_id, session, max_output_bytes)
    summary["operation"] = "check"
    return summary


async def _report(
    client: _Client, session_id: str, session: Any, max_output_bytes: int
) -> dict[str, Any]:
    """The shared progress report behind `run` and `check`.

    The todo and diff requests are best-effort: a session that has not
    produced either yet answers 404, and that is a normal state, not a
    failed operation.
    """
    summary: dict[str, Any] = {
        "session_id": session_id,
        "status": _session_status(session),
        "done": _session_is_done(session),
    }
    error = _first(session, "error")
    if error is not None:
        summary["error"] = _cap_json(error, limit=50, budget=[50])

    # `TimeoutError` is caught here alongside `_OpencodeError`: by this
    # point the session's own status is already known, and letting a
    # spent budget propagate would report a *finished* run as an
    # outcome-unknown timeout. A summary without the todo list is the
    # honest answer; "we don't know whether it ran" is not.
    try:
        todo_payload = await client.request(
            "session_todo", session_id=session_id, max_output_bytes=max_output_bytes
        )
        todos = _todos(todo_payload)
        if todos:
            summary["todos"] = todos[:_SUMMARY_ITEMS]
    except (_OpencodeError, TimeoutError):
        pass

    try:
        diff_payload = await client.request(
            "session_diff", session_id=session_id, max_output_bytes=max_output_bytes
        )
        files = _files_changed(diff_payload)
        summary["files_changed"] = [f["path"] for f in files][:_SUMMARY_ITEMS]
    except (_OpencodeError, TimeoutError):
        pass

    text = _message_text(session)
    if text:
        summary["last_message"] = text
    return summary


async def _op_review_changes(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> dict[str, Any]:
    session_id = check_session_id(values.get("session_id", ""))
    client.session_id = session_id
    payload = await client.request(
        "session_diff", session_id=session_id, max_output_bytes=max_output_bytes
    )
    files = _files_changed(payload)
    summary: dict[str, Any] = {
        "operation": "review_changes",
        "session_id": session_id,
        "files": files[:_SUMMARY_ITEMS],
        "totals": {
            "files": len(files),
            "added": sum(f.get("added", 0) for f in files),
            "removed": sum(f.get("removed", 0) for f in files),
        },
    }
    return _summarise(summary, payload, "files")


async def _op_abort(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> dict[str, Any]:
    session_id = check_session_id(values.get("session_id", ""))
    client.session_id = session_id
    payload = await client.request(
        "session_abort", session_id=session_id, max_output_bytes=max_output_bytes
    )
    return {
        "operation": "abort",
        "session_id": session_id,
        "aborted": True,
        "response": _cap_json(payload, limit=50, budget=[50]) if payload else None,
    }


async def _op_providers(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> dict[str, Any]:
    payload = await client.request("providers", max_output_bytes=max_output_bytes)
    summary: dict[str, Any] = {
        "operation": "providers",
        "providers": _providers(payload)[:_SUMMARY_ITEMS],
    }
    return _summarise(summary, payload, "providers")


async def _op_health(
    client: _Client, values: dict[str, str], max_output_bytes: int
) -> dict[str, Any]:
    payload = await client.request("health", max_output_bytes=max_output_bytes)
    version = _first(payload, "version", "app_version", "appVersion")
    summary: dict[str, Any] = {"operation": "health", "healthy": True}
    if version is not None:
        summary["version"] = str(version)
    return summary


_OPERATIONS = {
    "ask": _op_ask,
    "run": _op_run,
    "fire": _op_fire,
    "check": _op_check,
    "review_changes": _op_review_changes,
    "abort": _op_abort,
    "providers": _op_providers,
    "health": _op_health,
}


# -- Entry point -------------------------------------------------------------


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
    """Runs one opencode operation and returns its compact summary as JSON.

    `values` are the already-validated parameter values (`validate.
    resolve_parameters`); this module reads the fixed names each
    operation declares in `catalog.OPENCODE_OPERATION_PARAMS` and nothing
    else -- the same way `execute_file.py` reads `path`/`content`.
    """
    assert toolkit.base_url is not None
    started = time.monotonic()
    deadline = started + timeout_seconds

    def _elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    def _denied(denial: Denied) -> Result:
        # Same reasoning as `execute_http._denied`: a rejection here
        # happens after `service.call()`'s validation try/except has
        # closed, so it is reported as a Result and stays inside the
        # normal audit bookkeeping rather than escaping unaudited.
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=None,
            stdout="",
            stderr=denial.agent_message,
            truncated=False,
            duration_ms=_elapsed(),
        )

    # Defensive re-check: `operation` is fixed per tool and not
    # agent-suppliable, so this can only fail on a programming error --
    # kept for the same reason `build_argv` re-checks `check_binary`.
    if not toolkit.allows_opencode_operation(operation):
        return _denied(
            Denied(
                DenialReason.TIER1_VIOLATION,
                f"Opencode operation {operation!r} is not allowed for this toolkit.",
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

    directory = values.get("directory") or None
    try:
        if directory:
            check_directory(directory, toolkit)
    except Denied as denial:
        return _denied(denial)

    client: _Client | None = None
    try:
        async with httpx.AsyncClient(verify=True) as http_client:
            client = _Client(
                toolkit=toolkit,
                credential=credential,
                directory=directory,
                client=http_client,
                deadline=deadline,
            )
            summary = await _OPERATIONS[operation](client, values, max_output_bytes)
    except Denied as denial:
        return _denied(denial)
    except TimeoutError:
        # A timeout on `run`/`fire`/`ask` means the prompt reached
        # opencode and the session is still working -- the classic
        # "outcome unknown" a retry would make worse (FR-9.4).
        return Result(
            outcome=OUTCOME_FAILED if idempotent else OUTCOME_UNKNOWN,
            exit_code=None,
            stdout="",
            stderr=_timeout_message(
                operation,
                timeout_seconds,
                (client.session_id if client else None) or values.get("session_id", ""),
                idempotent,
            ),
            truncated=False,
            duration_ms=_elapsed(),
            external_untrusted=True,
        )
    except _OpencodeError as exc:
        return Result(
            outcome=OUTCOME_FAILED,
            exit_code=exc.status,
            stdout="",
            stderr=redact(exc.message) if redact is not None else exc.message,
            truncated=False,
            duration_ms=_elapsed(),
            external_untrusted=True,
        )

    stdout = json.dumps(
        _cap_json(summary, limit=MAX_JSON_ITEMS, budget=[MAX_JSON_ITEMS]),
        ensure_ascii=False,
    )
    encoded = stdout.encode("utf-8")
    truncated = len(encoded) > max_output_bytes
    if truncated:
        stdout = encoded[:max_output_bytes].decode("utf-8", errors="replace")
    if redact is not None:
        stdout = redact(stdout)

    return Result(
        outcome=OUTCOME_OK,
        exit_code=client.last_status if client is not None else None,
        stdout=stdout,
        stderr="",
        truncated=truncated,
        duration_ms=_elapsed(),
        external_untrusted=True,
    )


def _timeout_message(
    operation: str, timeout_seconds: int, session_id: str, idempotent: bool
) -> str:
    base = f"Timeout of {timeout_seconds}s exceeded."
    if idempotent:
        return base
    hint = (
        f" Call the check operation with session_id={session_id!r} instead."
        if session_id
        else " Use the check operation on the session instead."
    )
    return (
        f"{base} The outcome is UNKNOWN: opencode has the prompt and the "
        f"session may still be working. Do not retry the {operation} "
        f"operation -- that would start the work a second time.{hint}"
    )


async def probe(toolkit: Toolkit) -> bool:
    """TCP-connect only, for /health/ready -- `execute_http.probe` verbatim.

    Same transport, same `base_url`/`allowed_cidrs`, so the same probe:
    resolving the host, checking the IP, and opening a socket is exactly
    what that function does, and a second copy here would be a second
    thing to keep in step. `GET /global/health` is deliberately *not*
    issued -- it is available to an agent as the `health` operation,
    where its answer is audited like any other call.
    """
    return await execute_http.probe(toolkit)
