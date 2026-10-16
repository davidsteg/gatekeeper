"""Console read model behind the JSON API (`/api/v1`).

The functions here turn the live stores into plain, JSON-serialisable
structures -- no HTML, no request objects. `api/app.py` and
`api/extras.py` hand them to Pydantic response models, and the React
console at `/app` renders those. `admin_service` reuses some of them for
the `admin.*` read actions, so the console and `/admin/mcp` compute the
same numbers.

Nothing in this module writes, with one deliberate exception inherited
from the console: `pending_view` sweeps vanished pending items before
listing, exactly like `admin.pending_list` does (see
`admin_service.sweep_vanished_pendings`).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
from datetime import datetime, timedelta
from typing import Any

import yaml

from ..identity import UI_ROLES
from ..pending import STALE_TAKEN_REASON, STALE_VANISHED_REASON, PendingStore
from ..tier1 import Destination, Toolkit
from ..toolkit_proposals import ToolkitProposalStore

#: Read at most this many bytes from the end of the log file. The log may grow to 32 MB;
#: parsing it in full would make the page unusable.
AUDIT_READ_BYTES = 2 * 1024 * 1024
AUDIT_DEFAULT_LIMIT = 200

#: `read_audit` walks the log backwards in chunks of this size and stops as
#: soon as it has enough records, so a 200-row page costs one chunk instead
#: of a full 2 MiB decode. `AUDIT_READ_BYTES` stays the hard floor.
AUDIT_CHUNK_BYTES = 256 * 1024

# -- Reading the audit log -------------------------------------------------------


def read_audit(
    path: str,
    *,
    limit: int = AUDIT_DEFAULT_LIMIT,
    identity: str = "",
    tool: str = "",
    outcome: str = "",
    since: datetime | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Reads the most recent entries of the current log file.

    `since` stops the walk at the first record older than it: the log is
    append-only, so everything before that one is older too. Stats use it
    to read exactly their window instead of a fixed number of records.

    Returns `(entries, truncated)`. `truncated` indicates that older
    material exists that is not visible here -- either because the file
    is longer than `AUDIT_READ_BYTES` or because rotation has already occurred. The UI
    points this out so that nobody takes the absence of an entry as
    proof.

    The file is walked **backwards** from EOF in `AUDIT_CHUNK_BYTES` chunks
    and the walk stops as soon as enough records are in hand -- the page
    wants the newest 200 of a log that may hold tens of thousands, and
    decoding the whole 2 MiB window to throw away 98 % of it was the single
    most expensive thing any console page did. Two details carry the
    correctness:

    * a chunk boundary cuts a record in half, so the first line of every
      chunk is held back and prepended to the chunk read next (the one
      *before* it in the file) -- without that, one record per boundary
      would vanish silently;
    * one record more than `limit` is collected, purely so `truncated`
      still means exactly what it meant before: "more matching entries
      exist in this window than are shown".
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return [], False

    floor = max(0, size - AUDIT_READ_BYTES)
    # One past `limit` is enough to know whether anything is being hidden.
    wanted = max(1, limit) + 1
    records: list[dict[str, Any]] = []
    carry = b""  # Start of the line that straddles the boundary, held back.
    pos = size
    reached_since = False

    with open(path, "rb") as handle:
        while pos > floor and len(records) < wanted and not reached_since:
            chunk_start = max(floor, pos - AUDIT_CHUNK_BYTES)
            handle.seek(chunk_start)
            blob = handle.read(pos - chunk_start) + carry
            pos = chunk_start
            lines = blob.split(b"\n")
            if pos > floor:
                # Incomplete: it continues into the chunk not yet read.
                carry = lines.pop(0)
            elif floor > 0:
                # At the window floor mid-file: the first line was cut by
                # the window itself and is not valid JSON. Drop it, as the
                # forward reader did.
                carry = b""
                lines.pop(0)
            else:
                carry = b""
            for line in reversed(lines):  # Newest first, within the chunk.
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                if since is not None:
                    stamp = _parse_ts(record.get("ts"))
                    if stamp is not None and stamp < since:
                        reached_since = True
                        break
                if identity and record.get("identity") != identity:
                    continue
                if tool and record.get("tool") != tool:
                    continue
                if outcome and record.get("outcome") != outcome:
                    continue
                records.append(record)
                if len(records) >= wanted:
                    break

    # Reaching `since` means the whole asked-for span was read, however
    # long the file is.
    truncated = (floor > 0 and not reached_since) or len(records) > limit
    return records[:limit], truncated


def _parse_ts(value: Any) -> datetime | None:
    try:
        return datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S%z")
    except (ValueError, TypeError):
        return None


def _local_now() -> datetime:
    """Current time in the container's local timezone.

    The audit log stores timestamps with a timezone offset (via
    `time.strftime("%Y-%m-%dT%H:%M:%S%z")`), so `_parse_ts` can convert
    them back. The UI displays them in local time -- the operator reads
    their own wall clock, not UTC. All chart bucketing and axis labels
    use this instead of `datetime.now(UTC)`.
    """
    return datetime.now().astimezone()


def _to_local(stamp: datetime) -> datetime:
    """Converts a parsed timestamp to local time for display."""
    return stamp.astimezone()


def _bucket_calls(
    records: list[dict[str, Any]], hours: int = 12, *, now: datetime | None = None
) -> list[tuple[int, int]]:
    """Calls per hour slot as `(succeeded, not succeeded)`.

    Both sides are rounded down to the full hour before computing.
    Rounding down only the present would be a silent bug: an entry from the
    current hour would then lie *after* the rounded-down present, get a
    negative age, and fall out of every slot -- the chart would
    stay empty even though calls just took place.
    """
    current = (now or _local_now()).replace(
        minute=0, second=0, microsecond=0
    )
    buckets = [(0, 0) for _ in range(hours)]
    for record in records:
        if record.get("kind") != "call":
            continue
        stamp = _parse_ts(record.get("ts"))
        if stamp is None:
            continue
        hour = _to_local(stamp).replace(
            minute=0, second=0, microsecond=0
        )
        age = int((current - hour).total_seconds() // 3600)
        if 0 <= age < hours:
            slot = hours - 1 - age
            ok, bad = buckets[slot]
            if record.get("outcome") == "ok":
                buckets[slot] = (ok + 1, bad)
            else:
                buckets[slot] = (ok, bad + 1)
    return buckets



def _target(obj: Toolkit | Destination) -> str:
    """The one target field that's actually set on a Toolkit or a

    Destination -- both carry the same three mutually-exclusive
    per-executor fields (FR-8.3g: a Destination mirrors Toolkit's own
    target fields), so picking "whichever one is set" is exactly the same
    one-liner for either type.
    """
    return obj.docker_host or obj.base_url or obj.ws_url or ""



def _call_stats(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Counts calls per identity: {id: {ok, denied, failed, total}}."""
    stats: dict[str, dict[str, int]] = {}
    for record in records:
        if record.get("kind") != "call":
            continue
        ident = record.get("identity") or ""
        if not ident:
            continue
        bucket = stats.setdefault(ident, {"ok": 0, "denied": 0, "failed": 0, "total": 0})
        outcome = record.get("outcome") or "unknown"
        if outcome == "ok":
            bucket["ok"] += 1
        elif outcome == "denied":
            bucket["denied"] += 1
        elif outcome == "failed":
            bucket["failed"] += 1
        bucket["total"] += 1
    return stats


def _tool_call_stats(
    records: list[dict[str, Any]], tools_by_kit: dict[str, set[str]],
) -> dict[str, dict[str, int]]:
    """Counts calls per toolkit by resolving the tool ID.

    ``{toolkit: {ok, denied, failed, total}}``. A call whose tool is in
    no known toolkit is grouped under ``_unknown``.
    """
    tool_to_kit: dict[str, str] = {}
    for kit, tool_ids in tools_by_kit.items():
        for tid in tool_ids:
            tool_to_kit[tid] = kit
    stats: dict[str, dict[str, int]] = {}
    for record in records:
        if record.get("kind") != "call":
            continue
        tool_id = record.get("tool") or ""
        kit = tool_to_kit.get(tool_id, "_unknown")
        bucket = stats.setdefault(kit, {"ok": 0, "denied": 0, "failed": 0, "total": 0})
        outcome = record.get("outcome") or "unknown"
        if outcome == "ok":
            bucket["ok"] += 1
        elif outcome == "denied":
            bucket["denied"] += 1
        elif outcome == "failed":
            bucket["failed"] += 1
        bucket["total"] += 1
    return stats


def _pair_call_stats(
    records: list[dict[str, Any]], tools_by_kit: dict[str, set[str]],
) -> dict[tuple[str, str], dict[str, int]]:
    """Counts calls per (identity, toolkit) pair -- the access map's edges.

    Without a hub node in the middle, each edge is a direct claim ("this
    identity called into this toolkit this many times"), so the stat it
    needs is per-pair, not per-identity and per-toolkit separately.
    """
    tool_to_kit: dict[str, str] = {}
    for kit, tool_ids in tools_by_kit.items():
        for tid in tool_ids:
            tool_to_kit[tid] = kit
    stats: dict[tuple[str, str], dict[str, int]] = {}
    for record in records:
        if record.get("kind") != "call":
            continue
        ident = record.get("identity") or ""
        kit = tool_to_kit.get(record.get("tool") or "")
        if not ident or not kit:
            continue
        bucket = stats.setdefault((ident, kit), {"ok": 0, "denied": 0, "failed": 0, "total": 0})
        outcome = record.get("outcome") or "unknown"
        if outcome == "ok":
            bucket["ok"] += 1
        elif outcome == "denied":
            bucket["denied"] += 1
        elif outcome == "failed":
            bucket["failed"] += 1
        bucket["total"] += 1
    return stats



def _outcome_totals(records: list[dict[str, Any]]) -> dict[str, int]:
    """Flat outcome totals and error rate across all call records."""
    ok = denied = failed = 0
    for record in records:
        if record.get("kind") != "call":
            continue
        outcome = record.get("outcome") or "unknown"
        if outcome == "ok":
            ok += 1
        elif outcome == "denied":
            denied += 1
        elif outcome == "failed":
            failed += 1
    total = ok + denied + failed
    error_rate = int((denied + failed) / total * 100) if total else 0
    return {
        "ok": ok, "denied": denied, "failed": failed,
        "total": total, "error_rate": error_rate,
    }



def _request_pending_counts(
    pending: PendingStore | None, toolkit_proposals: ToolkitProposalStore | None
) -> tuple[int, int]:
    change_n = sum(1 for i in pending.list() if i.status == "pending") if pending is not None else 0
    toolkit_n = (
        sum(1 for i in toolkit_proposals.list() if i.status == "pending")
        if toolkit_proposals is not None else 0
    )
    return change_n, toolkit_n


# -- Read model builders --------------------------------------------------


def toolkit_summary(name: str, tk: Toolkit) -> dict[str, Any]:
    """One live Tier 1 toolkit as plain data -- `admin.toolkit_list` and
    `GET /api/v1/toolkits` both report exactly this shape. Names only: a
    toolkit's `credential` is the credential's name, never its value.
    """
    return {
        "name": name,
        "executor": tk.executor,
        "binaries": list(tk.binaries),
        "denied_args": list(tk.denied_args),
        "path_roots": list(tk.path_roots),
        "protected_resources": list(tk.protected_resources),
        "max_timeout_seconds": tk.max_timeout_seconds,
        "max_output_bytes": tk.max_output_bytes,
        "destinations": list(tk.destinations),
        # Where this toolkit connects to, and which credential it
        # references -- not previously reported here, which read
        # as "not configured" when it was actually just missing
        # from this report. `credential` is the name only (e.g.
        # "bazarr-api-key"), never its value -- the credential
        # store stays write-only (FR-10.2) regardless.
        "target": _target(tk),
        "credential": tk.credential,
        # `file` executor only; `None` on every other toolkit and
        # on any `file` toolkit that never declared it -- reported
        # plainly rather than omitted, for the same reason as
        # `target`/`credential` above: a field that exists on
        # `Toolkit` but is missing from this dict reads as "not
        # configured", which for `run_as` means an approved
        # toolkit_update proposal looking like it never took effect.
        "run_as": tk.run_as,
        # `agent` executor only, reported for the same reason as
        # `run_as` above: an `agent` toolkit has no `target`, so
        # without these two it would read as a toolkit that
        # reaches nothing and may do nothing.
        "mailbox_path": tk.mailbox_path,
        "allowed_agent_operations": list(tk.allowed_agent_operations),
        # `http`/`opencode` only: where this toolkit may connect. Reported
        # so a toolkit_update proposal changing them shows the values it
        # replaces next to the proposed ones.
        "allowed_hosts": list(tk.allowed_hosts),
        "allowed_cidrs": list(tk.allowed_cidrs),
    }


def toolkit_summaries(tier1: Any) -> list[dict[str, Any]]:
    return [toolkit_summary(name, tk) for name, tk in sorted(tier1.toolkits.items())]


def credential_summaries(credentials: Any, tier1: Any) -> list[dict[str, Any]]:
    """Credential metadata, never a value (FR-10.2).

    Built field by field from `CredentialMeta`, which itself has no value
    field -- so there is nothing here that could carry a secret even by
    accident. `used_by` comes from `Tier1.credential_references()`, the one
    walk over toolkits *and* destinations (AGENTS.md: do not hand-roll a
    second one).
    """
    used_by = tier1.credential_references()
    return [
        {
            "name": meta.name,
            "kind": meta.kind,
            "header": meta.header,
            "header_format": meta.header_format,
            "created_at": meta.created_at,
            "rotated_at": meta.rotated_at,
            "in_overlap": meta.in_overlap,
            "used_by": list(meta.used_by),
            "probe_url": meta.probe_url,
            "probe_status": meta.probe_status,
            "probe_checked_at": meta.probe_checked_at,
            "suspect_status": meta.suspect_status,
            "suspect_at": meta.suspect_at,
        }
        for meta in credentials.names(used_by=used_by)
    ]


def _zero() -> dict[str, int]:
    return {"ok": 0, "denied": 0, "failed": 0, "total": 0}


def audit_path(service: Any) -> str:
    return os.path.join(service.tier1.audit_dir, "audit.jsonl")


def _matrix_identities(identities: Any) -> list[Any]:
    """The rows of the access map: agents, plus console identities that actually hold a grant --
    and, on a deployment with nothing but console identities, all of them.
    """
    everyone = identities.identities.values()
    return sorted(
        (i for i in everyone if i.role not in UI_ROLES or i.tools), key=lambda i: i.id
    ) or sorted(everyone, key=lambda i: i.id)


def access_matrix(
    service: Any, identities: Any, records: list[dict[str, Any]]
) -> dict[str, Any]:
    """Identity x toolkit grants with per-pair call counts.

    A cell lists the granted tool IDs of that toolkit and the calls this
    identity made into it within the audit window. `hot_threshold` is the
    heat-map cut-off (75th percentile of pair totals, at least 3).
    """
    toolkits = sorted(service.tier1.toolkits.items())
    tools_by_kit: dict[str, set[str]] = {name: set() for name, _ in toolkits}
    for tool in service.catalog.tools.values():
        tools_by_kit.setdefault(tool.toolkit, set()).add(tool.id)
    pair_stats = _pair_call_stats(records, tools_by_kit)
    totals = sorted(s["total"] for s in pair_stats.values())
    hot_threshold = max(totals[int(len(totals) * 0.75)] if totals else 0, 3)
    rows = []
    for ident in _matrix_identities(identities):
        cells = []
        for name, _tk in toolkits:
            granted = sorted(ident.tools & tools_by_kit.get(name, set()))
            cells.append({
                "toolkit": name,
                "granted": granted,
                "calls": pair_stats.get((ident.id, name), _zero()) if granted else _zero(),
            })
        rows.append({
            "identity": ident.id, "role": ident.role,
            "tool_count": len(ident.tools), "cells": cells,
        })
    return {
        "toolkits": [{"name": n, "executor": tk.executor} for n, tk in toolkits],
        "rows": rows,
        "hot_threshold": hot_threshold,
    }


def overview_view(
    service: Any, identities: Any, store: Any,
    pending: PendingStore | None, toolkit_proposals: ToolkitProposalStore | None,
    *, now: datetime | None = None,
) -> dict[str, Any]:
    """Everything the console's overview page (`/app/`) shows, as data: posture, the 12 h activity series,
    the most recent events and the access matrix."""
    catalog = service.catalog
    records, _ = read_audit(audit_path(service), limit=400)
    change_n, toolkit_n = _request_pending_counts(pending, toolkit_proposals)
    totals = _outcome_totals(records)
    current = (now or _local_now()).replace(minute=0, second=0, microsecond=0)
    buckets = _bucket_calls(records, 12, now=now)
    activity = [
        {
            "hour": (current - timedelta(hours=len(buckets) - 1 - i)).isoformat(),
            "ok": ok, "not_ok": bad,
        }
        for i, (ok, bad) in enumerate(buckets)
    ]
    unwritable = (
        sorted(name for name, ok in store.writability().items() if not ok)
        if store is not None else []
    )
    return {
        "stats": {
            "tools_active": sum(1 for t in catalog.tools.values() if t.enabled),
            "identities": len(identities.identities),
            "protected_resources": len(
                {r for tk in service.tier1.toolkits.values() for r in tk.protected_resources}
            ),
            "tools_disabled": len(catalog.disabled_by_tier1),
        },
        "outcomes": {
            **totals,
            "success_pct": int(totals["ok"] / totals["total"] * 100) if totals["total"] else 0,
        },
        "events_logged": len(records),
        "activity": activity,
        "recent": records[:20],
        "notices": {
            "unwritable": unwritable,
            "disabled_by_tier1": list(catalog.disabled_by_tier1),
            "pending_changes": change_n,
            "pending_toolkits": toolkit_n,
            "no_toolkits": not service.tier1.toolkits,
            "empty_catalog": bool(service.tier1.toolkits) and not catalog.tools,
        },
        "access": access_matrix(service, identities, records),
    }


def _parameter(p: Any) -> dict[str, Any]:
    return {
        "name": p.name,
        "type": p.type,
        "description": p.description,
        "required": p.required,
        "derived": p.derived,
        "pattern": p.pattern_source,
        "values": list(p.values),
        "minimum": p.minimum,
        "maximum": p.maximum,
    }


def tool_summary(tool: Any, identities: Any) -> dict[str, Any]:
    return {
        "id": tool.id,
        "toolkit": tool.toolkit,
        "destination": tool.destination,
        "version": tool.version,
        "title": tool.title,
        "description": tool.description,
        "category": tool.category,
        "idempotent": tool.idempotent,
        "enabled": tool.enabled,
        "required_scopes": list(tool.required_scopes),
        "timeout_seconds": tool.timeout_seconds,
        "max_output_bytes": tool.max_output_bytes,
        "parameters": [_parameter(p) for _, p in sorted(tool.parameters.items())],
        "grantees": sorted(
            i.id for i in identities.identities.values() if tool.id in i.tools
        ),
    }


def tools_view(service: Any, identities: Any) -> dict[str, Any]:
    catalog = service.catalog
    return {
        "tools": [
            tool_summary(t, identities)
            for t in sorted(catalog.tools.values(), key=lambda t: t.id)
        ],
        "rejected": [
            {"id": str(spec.get("id", "?")), "reason": str(reason)}
            for spec, reason in catalog.rejected
        ],
        "disabled_by_tier1": list(catalog.disabled_by_tier1),
        "toolkits": [
            {"name": n, "executor": tk.executor}
            for n, tk in sorted(service.tier1.toolkits.items())
        ],
    }


def tool_detail(service: Any, identities: Any, tool_id: str) -> dict[str, Any] | None:
    """One definition as the editor shows it: the flat spec and its YAML.

    `tool_id` is the definition's own ID (what `tools.yaml` names), which
    for a multi-destination toolkit is the base ID, not `id@destination`.
    """
    from ..catalog import normalize_tool_entry
    from ..store import tool_to_yaml

    spec = service.catalog.flat_spec_of(tool_id)
    raw = service.catalog.raw_of(tool_id)
    if spec is None or raw is None:
        return None
    entry = normalize_tool_entry(raw)
    expanded = [
        tool_summary(t, identities)
        for t in sorted(service.catalog.tools.values(), key=lambda t: t.id)
        if t.id == tool_id or t.id.startswith(tool_id + "@")
    ]
    return {
        "id": tool_id,
        "enabled": entry["enabled"],
        "current_version": entry["current_version"],
        "versions": [
            {k: v.get(k) for k in ("version", "created_at", "created_by", "superseded")}
            for v in entry["versions"]
        ],
        "spec": spec,
        "yaml": tool_to_yaml(spec),
        "tools": expanded,
    }


def identities_view(service: Any, identities: Any) -> list[dict[str, Any]]:
    """Identities without a single hash: role, grants, scopes, and which of
    the two credentials (API token, console password) it can use."""
    known = set(service.catalog.tools)
    out = []
    for ident in sorted(identities.identities.values(), key=lambda i: i.id):
        if ident.role in UI_ROLES:
            console = "access" if ident.can_sign_in else "no_password"
        else:
            console = "api_only"
        out.append({
            "id": ident.id,
            "role": ident.role,
            "tools": sorted(ident.tools),
            "scopes": list(ident.scopes),
            "console": console,
            "unknown_tools": sorted(ident.tools - known),
        })
    return out


def _sweep(store: Any, pending: PendingStore, credentials: Any) -> None:
    # Lazy: `admin_service` imports this module for its own read actions.
    from ..admin_service import sweep_vanished_pendings

    if store is not None:
        sweep_vanished_pendings(store, pending, credentials=credentials)


def _pending_spec(item: Any, store: Any) -> dict[str, Any]:
    spec = item.to_spec()
    spec["review"] = pending_review(item, store)
    return spec


def pending_view(
    store: Any, pending: PendingStore | None, status: str | None, credentials: Any = None,
) -> list[dict[str, Any]]:
    if pending is None:
        return []
    _sweep(store, pending, credentials)
    return [_pending_spec(item, store) for item in pending.list(status=status)]


def _encode_cursor(key: tuple[str, int]) -> str:
    return base64.urlsafe_b64encode(json.dumps(list(key)).encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[str, int]:
    """Raises `ValueError` on anything this module did not write."""
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        key = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid cursor") from exc
    if not (
        isinstance(key, list) and len(key) == 2
        and isinstance(key[0], str) and type(key[1]) is int
    ):
        raise ValueError("invalid cursor")
    return key[0], key[1]


def decided_pending_page(
    store: Any, pending: PendingStore | None, *, limit: int, cursor: str | None,
    credentials: Any = None,
) -> dict[str, Any]:
    """Decided proposals (anything not `pending`), newest decision first,
    `limit` at a time. The cursor is the sort key of the last item served,
    not an offset, so a decision made between two pages does not repeat
    an item on the next one. Timestamps have second resolution, so the
    key's second half is the item's position in the queue, which only
    ever grows at the end. Raises `ValueError` for a bad cursor."""
    if pending is None:
        return {"entries": [], "next_cursor": None, "total": 0}
    _sweep(store, pending, credentials)
    decided = sorted(
        (
            ((item.decided_at or item.created_at, pos), item)
            for pos, item in enumerate(pending.list())
            if item.status != "pending"
        ),
        key=lambda pair: pair[0], reverse=True,
    )
    total = len(decided)
    if cursor:
        after = _decode_cursor(cursor)
        decided = [pair for pair in decided if pair[0] < after]
    page = decided[:limit]
    more = len(decided) > limit
    return {
        "entries": [_pending_spec(item, store) for _key, item in page],
        "next_cursor": _encode_cursor(page[-1][0]) if more and page else None,
        "total": total,
    }


def _review_tool(store: Any, tool_id: str, marker: str = "") -> dict[str, Any]:
    """One tool a proposal names, resolved against the live catalog, so a
    reviewer sees whether it exists and what it is now -- a grant on a tool
    that was never created is a right to nothing."""
    flat = store.service.catalog.flat_spec_of(tool_id) if store is not None else None
    if flat is None:
        return {"id": tool_id, "marker": marker, "state": "missing", "title": "", "category": ""}
    return {
        "id": tool_id, "marker": marker,
        "state": "enabled" if flat.get("enabled") else "disabled",
        "title": str(flat.get("title") or tool_id),
        "category": str(flat.get("category", "")),
    }


def pending_review(item: Any, store: Any) -> dict[str, Any]:
    """What a reviewer needs to judge one proposal, as plain data: a
    one-line headline and the tools it touches; the full payload stays in
    `payload`.

    A `grant_set` is a full replacement, so it is diffed against the
    `prev_tools` snapshot taken at propose time and only the added and
    removed tools are listed -- plus any unchanged grant that is missing
    or disabled, which stays a live concern."""
    payload = item.payload
    tools: list[dict[str, Any]] = []
    unchanged = 0
    action = item.action
    if action in ("tool_enable", "tool_disable", "tool_delete"):
        headline = f"{action.replace('tool_', '')} tool {payload.get('id', '')}"
        tools.append(_review_tool(store, str(payload.get("id", ""))))
    elif action in ("tool_create", "tool_update"):
        spec = payload.get("spec") or {}
        target = payload.get("replaces") or spec.get("id", "")
        headline = (
            f"tool {target}: category {spec.get('category', '')}, "
            f"enabled={spec.get('enabled', False)}"
        )
    elif action == "grant_set":
        identity_id = payload.get("identity_id", "")
        proposed_ids = payload.get("tools") or []
        prev = payload.get("prev_tools")
        if prev is None:
            headline = f"identity {identity_id}: {len(proposed_ids)} tool grant(s)"
            tools = [_review_tool(store, t) for t in sorted(proposed_ids)]
        else:
            catalog = store.service.catalog if store is not None else None

            def _normalize(ids: Any) -> set[str]:
                found: set[str] = set()
                for tid in ids:
                    resolved = catalog.grantable_ids(tid) if catalog is not None else []
                    found.update(resolved or [tid])
                return found

            proposed, previous = _normalize(proposed_ids), _normalize(prev)
            added, removed = sorted(proposed - previous), sorted(previous - proposed)
            kept = sorted(proposed & previous)
            unchanged = len(kept)
            headline = (
                f"identity {identity_id}: +{len(added)} -{len(removed)}, "
                f"{unchanged} unchanged"
            )
            tools = [_review_tool(store, t, "+") for t in added]
            tools += [_review_tool(store, t, "-") for t in removed]
            tools += [
                r for r in (_review_tool(store, t) for t in kept) if r["state"] != "enabled"
            ]
    elif action == "cred_propose":
        header = payload.get("header")
        headline = (
            f"credential {payload.get('name', '')}: kind {payload.get('kind', '')}"
            + (f", header {header}" if header else "")
            + (
                f", value format {payload.get('header_format')}"
                if payload.get("header_format") else ""
            )
            + " (no value: typed by a human on approval)"
        )
    elif action == "cred_update":
        prev = payload.get("prev") or {}
        changes = []
        if payload.get("new_name"):
            changes.append(f"rename to {payload.get('new_name')}")
        for field in ("kind", "header", "header_format", "probe_url"):
            if prev.get(field) != payload.get(field):
                before, after = prev.get(field) or "none", payload.get(field) or "none"
                changes.append(f"{field.replace('_', ' ')} {before} -> {after}")
        headline = (
            f"credential {payload.get('name', '')}: "
            + (", ".join(changes) or "no change")
            + " (stored value kept)"
        )
    elif action == "role_set":
        identity_id = payload.get("identity_id", "")
        new_role = payload.get("role", "")
        current = store.identities.identities.get(identity_id) if store is not None else None
        if current is not None and current.role != new_role:
            headline = f"identity {identity_id}: role {current.role} -> {new_role}"
        else:
            headline = f"identity {identity_id}: role {new_role}"
    else:
        headline = json.dumps(payload, default=str)
    stale = None
    if item.status == "stale":
        if item.reason == STALE_VANISHED_REASON:
            stale = "What this proposal targeted no longer exists, so there is nothing to apply it to."
        elif item.reason == STALE_TAKEN_REASON:
            stale = (
                f"A credential named {payload.get('new_name') or payload.get('name', '')} "
                "was created after this was "
                "proposed. Ask the agent for a new name, or rotate the existing credential."
            )
        else:
            stale = (
                "The configuration it referred to changed after it was proposed; "
                "ask the agent to re-propose from the current state."
            )
    return {"headline": headline, "tools": tools, "unchanged": unchanged, "stale": stale}


def toolkit_proposals_view(
    service: Any, toolkit_proposals: ToolkitProposalStore | None, status: str | None
) -> list[dict[str, Any]]:
    """Each proposal plus the live toolkit it would replace or extend, so a
    reviewer can diff the two without a second request."""
    if toolkit_proposals is None:
        return []
    out = []
    for item in toolkit_proposals.list(status=status):
        spec = item.to_spec()
        live = service.tier1.toolkits.get(item.name)
        spec["current"] = toolkit_summary(item.name, live) if live is not None else None
        # What deploying writes, as the review card shows it: a create as a
        # complete `name: {...}` block, an update as just the changed fields.
        spec["spec_yaml"] = (
            "" if item.kind in ("delete", "bind")
            else yaml.safe_dump(
                item.spec if item.kind == "update" else {item.name: item.spec},
                sort_keys=False, allow_unicode=True,
            )
        )
        out.append(spec)
    return out


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int:
    """Opaque to clients; raises `ValueError` on anything this did not issue."""
    if not cursor:
        return 0
    padded = cursor + "=" * (-len(cursor) % 4)
    data = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    offset = data["o"] if isinstance(data, dict) else None
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("bad cursor")
    return offset


def audit_page(
    service: Any, *, limit: int, cursor: str | None,
    identity: str = "", tool: str = "", outcome: str = "",
) -> dict[str, Any]:
    """A page of the audit log, newest first, filtered.

    Paginates over the tail window `read_audit` reads
    (`AUDIT_READ_BYTES`); the cursor is an offset into the filtered,
    newest-first sequence. Stage 1 moves the audit index to SQLite, and
    the cursor -- opaque on purpose -- can then become a row key without
    a client change. `window_truncated` keeps the page honest:
    older records exist that this window does not reach.
    """
    offset = decode_cursor(cursor)
    records, truncated = read_audit(
        audit_path(service), limit=offset + limit + 1,
        identity=identity, tool=tool, outcome=outcome,
    )
    page = records[offset:offset + limit]
    more = len(records) > offset + limit
    return {
        "entries": page,
        "next_cursor": encode_cursor(offset + limit) if more else None,
        "window_truncated": truncated and not more,
    }


def toolkit_reference_view() -> list[dict[str, Any]]:
    """Copy-pasteable Tier 1 YAML per executor. Text for a human to paste
    into toolkits.yaml by hand -- nothing here writes it (FR-4.11)."""
    from ..toolkit_reference import REFERENCES

    return [
        {
            "key": it.key, "display_name": it.display_name,
            "notes": it.notes, "toolkit_yaml": it.toolkit_yaml,
        }
        for it in REFERENCES.values()
    ]


# -- Shared by the write paths of /api/v1 -------------------------------------------


def _tool_scaffold(service: Any) -> str:
    """Scaffold for a new definition, built from the real Tier 1.

    This used to contain a finished Docker tool with foreign paths. That was
    doubly wrong: it looked like a finished tool, and on a system
    without this toolkit it could not even be saved. The scaffold now
    takes the first configured toolkit and its actual values -- it
    is thus a valid starting point on every deployment.
    """
    name, toolkit = next(iter(sorted(service.tier1.toolkits.items())))
    binary = toolkit.binaries[0]
    lines = [
        f"id: {name}.CHANGEME",
        f"toolkit: {name}",
        f"binary: {binary}",
        "version: 1",
        "title: CHANGEME",
        "description: What this does, in one sentence for the agent.",
        "category: read            # read | write | write_external",
        "idempotent: true",
        "enabled: true",
        "",
        "# Every element becomes exactly one argument. A parameter value can",
        "# never produce a second one (FR-5.4).",
        'argv: ["--help"]',
        "",
        "# Every string parameter needs a pattern -- unvalidated free text is",
        "# not permitted (FR-5.7). Paths are derived by the server, never",
        "# supplied by the agent.",
        "parameters: {}",
        "",
        "required_scopes: []",
        f"timeout_seconds: {min(30, toolkit.max_timeout_seconds)}",
        f"max_output_bytes: {min(65536, toolkit.max_output_bytes)}",
    ]
    if toolkit.path_roots:
        lines.insert(
            -3,
            "# This toolkit allows derived paths under: "
            + ", ".join(toolkit.path_roots),
        )
    return "\n".join(lines) + "\n"


def _schedule_credential_probe(credentials: Any, name: str) -> None:
    async def _run() -> None:
        try:
            await credentials.probe_credential(name)
        except Exception:
            # A probe is detection-only and save is fail-open; the credential
            # has already been written and must not be rolled back by metadata.
            pass

    asyncio.create_task(_run())


def drop_sessions_after_identity_update(
    sessions: Any, *, replaces: str, new_id: str, role: str, password_set: bool,
    actor: str, current_sid: str | None,
) -> None:
    """Which console sessions survive an identity edit -- one rule for both
    console surfaces (moved out of `ui.identity_update`).

    Renamed, or moved to a role without console access: every session of
    the old identity ends. A new password ends them too -- a taken-over
    session must not stay open exactly when an admin is closing it -- except
    the editor's own session when they set their own password.
    """
    locked_out = new_id != replaces or role not in UI_ROLES
    if locked_out or password_set:
        keep = current_sid if (not locked_out and replaces == actor) else None
        sessions.drop_identity(replaces, keep=keep)


# -- Stats and docs ------------------------------------------------------------------

#: `src/gatekeeper`, the package directory -- the doc lookup below is
#: written relative to it.
_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_ADMIN_VERBS = {
    "tool_create": "created tool",
    "tool_update": "updated tool",
    "tool_delete": "deleted tool",
    "tool_enable": "enabled tool",
    "tool_disable": "disabled tool",
    "identity_create": "created identity",
    "identity_update": "updated identity",
    "identity_delete": "deleted identity",
    "token_rotate": "rotated the API token of",
    "password_set": "set the console password of",
}

def _bucket_calls_by_day(
    records: list[dict[str, Any]], days: int = 7, *, now: datetime | None = None,
) -> list[tuple[int, int]]:
    """Calls per day slot as ``(succeeded, not succeeded)``.

    Same shape and rounding-down-before-diffing approach as ``_bucket_calls``,
    but day-granularity for the 7d/30d chart on the Stats page.
    """
    current = (now or _local_now()).replace(
        hour=0, minute=0, second=0, microsecond=0,
    )
    buckets = [(0, 0) for _ in range(days)]
    for record in records:
        if record.get("kind") != "call":
            continue
        stamp = _parse_ts(record.get("ts"))
        if stamp is None:
            continue
        day = _to_local(stamp).replace(
            hour=0, minute=0, second=0, microsecond=0,
        )
        age = int((current - day).total_seconds() // 86400)
        if 0 <= age < days:
            slot = days - 1 - age
            ok, bad = buckets[slot]
            if record.get("outcome") == "ok":
                buckets[slot] = (ok + 1, bad)
            else:
                buckets[slot] = (ok, bad + 1)
    return buckets



def _admin_action_stats(records: list[dict[str, Any]]) -> dict[str, int]:
    """Counts ``admin_change`` records by action, using ``_ADMIN_VERBS`` labels."""
    stats: dict[str, int] = {}
    for record in records:
        if record.get("kind") != "admin_change":
            continue
        action = record.get("action", "")
        label = _ADMIN_VERBS.get(action, action or "admin_change")
        stats[label] = stats.get(label, 0) + 1
    return dict(sorted(stats.items(), key=lambda kv: (-kv[1], kv[0])))



def _duration_stats(
    records: list[dict[str, Any]], tools_by_kit: dict[str, set[str]] | None = None,
) -> dict[str, dict[str, float]]:
    """Average and p95 duration per toolkit, plus overall."""
    tool_to_kit: dict[str, str] = {}
    if tools_by_kit:
        for kit, tool_ids in tools_by_kit.items():
            for tid in tool_ids:
                tool_to_kit[tid] = kit
    per_kit: dict[str, list[int]] = {}
    all_durations: list[int] = []
    for record in records:
        if record.get("kind") != "call":
            continue
        dur = record.get("duration_ms")
        if dur is None:
            continue
        try:
            dur = int(dur)
        except (TypeError, ValueError):
            continue
        all_durations.append(dur)
        kit = tool_to_kit.get(record.get("tool") or "", "_unknown")
        per_kit.setdefault(kit, []).append(dur)

    def _pct(values: list[int], pct: float) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        idx = max(0, min(len(s) - 1, int(len(s) * pct) - 1))
        return float(s[idx])

    result: dict[str, dict[str, float]] = {}
    for kit, durations in per_kit.items():
        result[kit] = {
            "avg": sum(durations) / len(durations) if durations else 0.0,
            "p95": _pct(durations, 0.95),
            "count": float(len(durations)),
        }
    result["_overall"] = {
        "avg": sum(all_durations) / len(all_durations) if all_durations else 0.0,
        "p95": _pct(all_durations, 0.95),
        "count": float(len(all_durations)),
    }
    return result



_DOCS_DIR_CANDIDATES = (
    "/opt/gatekeeper-docs",
    os.path.join(_PACKAGE_DIR, "..", ".."),
    "/opt/data/gatekeeper",
    ".",
)


def _read_doc_file(name: str) -> str:
    """Read a doc file from the repo root, best-effort.

    The source tree lives next to the package; in the container the docs
    are bundled at /opt/gatekeeper-docs by the Dockerfile.  Returns empty
    string if not found.
    """
    for base in _DOCS_DIR_CANDIDATES:
        candidate = os.path.join(base, name)
        try:
            with open(candidate, encoding="utf-8") as fh:
                return fh.read()
        except (OSError, FileNotFoundError):
            continue
    return ""



_DOC_FILES = (
    ("readme", "README", "README.md"),
    ("requirements", "Requirements", "REQUIREMENTS.md"),
    ("agents", "AGENTS", "AGENTS.md"),
    ("release", "Release Notes", "RELEASE.md"),
)


_STATS_WINDOWS = (("24h", "Last 24 hours", 24), ("7d", "Last 7 days", 7), ("30d", "Last 30 days", 30))

#: Not a sample size: stats read their whole time window, and the
#: `AUDIT_READ_BYTES` floor is what bounds the work. This only keeps
#: `read_audit`'s "one more than asked" bookkeeping finite.
_STATS_MAX_RECORDS = 1_000_000


def stats_view(service: Any, window: str) -> dict[str, Any]:
    """The Stats page as data: tiles, an activity series (hourly for 24 h,
    daily otherwise), and per-toolkit, per-identity, latency and admin
    tables. Best-effort over the tail of the current audit log."""
    spec = next((w for w in _STATS_WINDOWS if w[0] == window), _STATS_WINDOWS[0])
    key, label, span = spec
    # The window itself, not the newest N records: "Last 24 hours" counted
    # only the latest 200 calls before, and the 7- and 30-day windows took
    # in records older than they claimed to cover.
    now = _local_now()
    start = (
        now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=span - 1)
        if key == "24h"
        else now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=span - 1)
    )
    records, truncated = read_audit(audit_path(service), limit=_STATS_MAX_RECORDS, since=start)
    tools_by_kit: dict[str, set[str]] = {name: set() for name in service.tier1.toolkits}
    for tool in service.catalog.tools.values():
        tools_by_kit.setdefault(tool.toolkit, set()).add(tool.id)
    totals = _outcome_totals(records)
    idents = _call_stats(records)
    kits = _tool_call_stats(records, tools_by_kit)
    admin = _admin_action_stats(records)
    durations = _duration_stats(records, tools_by_kit)
    if key == "24h":
        now = _local_now().replace(minute=0, second=0, microsecond=0)
        series = [
            {"start": (now - timedelta(hours=span - 1 - i)).isoformat(), "ok": ok, "not_ok": bad}
            for i, (ok, bad) in enumerate(_bucket_calls(records, hours=span))
        ]
    else:
        today = _local_now().replace(hour=0, minute=0, second=0, microsecond=0)
        series = [
            {"start": (today - timedelta(days=span - 1 - i)).isoformat(), "ok": ok, "not_ok": bad}
            for i, (ok, bad) in enumerate(_bucket_calls_by_day(records, days=span))
        ]

    def _rows(stats: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
        return [
            {"name": name, **{k: v[k] for k in ("total", "ok", "denied", "failed")}}
            for name, v in sorted(stats.items(), key=lambda kv: (-kv[1]["total"], kv[0]))
            if v["total"] > 0
        ]

    return {
        "window": key,
        "label": label,
        "windows": [{"key": w[0], "label": w[1]} for w in _STATS_WINDOWS],
        "truncated": truncated,
        "totals": {k: totals[k] for k in ("ok", "denied", "failed", "total", "error_rate")},
        "success_rate": int(totals["ok"] / totals["total"] * 100) if totals["total"] else 0,
        "active_identities": len(idents),
        "active_toolkits": sum(1 for k, v in kits.items() if v["total"] > 0 and k != "_unknown"),
        "admin_total": sum(admin.values()),
        "series": series,
        "toolkits": _rows(kits),
        "identities": _rows(idents),
        "admin": [{"action": a, "count": n} for a, n in admin.items()],
        "latency": [
            {"toolkit": kit, "avg_ms": int(v["avg"]), "p95_ms": int(v["p95"]), "count": int(v["count"])}
            for kit, v in sorted(durations.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
            if v["count"] > 0
        ],
    }


def docs_index() -> list[dict[str, Any]]:
    return [
        {"slug": slug, "label": label, "available": bool(_read_doc_file(filename))}
        for slug, label, filename in _DOC_FILES
    ]


def doc_text(slug: str) -> dict[str, str] | None:
    """One bundled document as Markdown source. The slug picks from a
    fixed list, so no path from a request ever reaches the filesystem."""
    for known, label, filename in _DOC_FILES:
        if known == slug:
            return {"slug": slug, "label": label, "text": _read_doc_file(filename)}
    return None
