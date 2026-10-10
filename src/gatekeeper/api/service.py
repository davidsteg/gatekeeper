"""Console read model, shared by the legacy `/ui` and the JSON API.

The functions here turn the live stores into plain, JSON-serialisable
structures -- no HTML, no request objects. `ui.py` renders them into its
f-string pages; `api/app.py` hands them to Pydantic response models. The
first batch (`read_audit`, the call-stat counters, `_target`) moved here
from `ui.py` unchanged so both surfaces compute the same numbers; the
`*_view` builders below are new and feed only the API so far.

Nothing in this module writes, with one deliberate exception inherited
from the console: `pending_view` sweeps vanished pending items before
listing, exactly like `/ui/requests` and `admin.pending_list` do (see
`admin_service.sweep_vanished_pendings`).
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta
from typing import Any

from ..identity import UI_ROLES
from ..pending import PendingStore
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
) -> tuple[list[dict[str, Any]], bool]:
    """Reads the most recent entries of the current log file.

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

    with open(path, "rb") as handle:
        while pos > floor and len(records) < wanted:
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
                if identity and record.get("identity") != identity:
                    continue
                if tool and record.get("tool") != tool:
                    continue
                if outcome and record.get("outcome") != outcome:
                    continue
                records.append(record)
                if len(records) >= wanted:
                    break

    truncated = floor > 0 or len(records) > limit
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
    """The rows of the access map, chosen the same way `ui._access_matrix`
    does: agents, plus console identities that actually hold a grant --
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

    The same numbers the legacy access map renders as an HTML table: a
    cell lists the granted tool IDs of that toolkit and the calls this
    identity made into it within the audit window. `hot_threshold` is the
    legacy heat-map cut-off (75th percentile of pair totals, at least 3).
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
    """Everything `/ui/` shows, as data: posture, the 12 h activity series,
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


def pending_view(store: Any, pending: PendingStore | None, status: str | None) -> list[dict[str, Any]]:
    # Lazy: `admin_service` imports this module for its own read actions.
    from ..admin_service import sweep_vanished_pendings

    if pending is None:
        return []
    if store is not None:
        sweep_vanished_pendings(store, pending)
    return [item.to_spec() for item in pending.list(status=status)]


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

    Paginates over the same tail window `read_audit` reads for `/ui/audit`
    (`AUDIT_READ_BYTES`); the cursor is an offset into the filtered,
    newest-first sequence. Stage 1 moves the audit index to SQLite, and
    the cursor -- opaque on purpose -- can then become a row key without
    a client change. `window_truncated` keeps the legacy page's honesty:
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


def integrations_view(service: Any) -> list[dict[str, Any]]:
    from ..integrations import INTEGRATIONS

    configured = set(service.tier1.toolkits)
    return [
        {
            "key": it.key,
            "display_name": it.display_name,
            "notes": it.notes,
            "credential_kind": it.credential_kind,
            "toolkit_configured": it.key in configured,
            "tools": [
                {
                    "id": str(spec["id"]),
                    "category": str(spec.get("category", "")),
                    "description": str(spec.get("description", "")),
                    "exists": service.catalog.raw_of(spec["id"]) is not None,
                }
                for spec in it.tool_specs
            ],
        }
        for it in sorted(INTEGRATIONS.values(), key=lambda i: i.display_name)
    ]


def toolkit_reference_view() -> list[dict[str, Any]]:
    """Copy-pasteable Tier 1 YAML per integration. Text for a human to paste
    into toolkits.yaml by hand -- nothing here writes it (FR-4.11)."""
    from ..integrations import INTEGRATIONS

    return [
        {
            "key": it.key, "display_name": it.display_name,
            "notes": it.notes, "toolkit_yaml": it.toolkit_yaml,
        }
        for it in sorted(INTEGRATIONS.values(), key=lambda i: i.display_name)
    ]
