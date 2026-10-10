"""Gatekeeper recovery adapter -- Hermes plugin half.

Implements the in-process side of Gatekeeper's Hermes adapter contract v1.1
(docs/HERMES_ADAPTER.md in the same Gatekeeper commit). It only uses documented
plugin surfaces: `register_hook` and `register_tool`. It never edits
Hermes's own databases; all state goes to the adapter journal (journal.py),
which the sidecar shares.

What it does:
* `pre_tool_call`: overwrite `_hermes_recovery` on every Gatekeeper MCP call
  (the model's own value never passes; `null` for an unbound session).
* `pre_llm_call`: advance the durable per-session `turn_seq`; record
  `started` for a continuation turn before the first model call, or mark a
  superseded continuation `lost` and tell the turn to do nothing.
* `post_tool_call`: a successful Kanban write to the bound task is progress.
* `on_session_end`: map the turn exit to a contract reason (versioned
  mapping layer) and enqueue `turn_stopped`; finish a continuation record.
* `kanban_task_completed`: enqueue `task_completed` for exactly that task.
* tool `gatekeeper_recovery_bind_task`: the explicit task binding.

Wake mode (GATEKEEPER_RECOVERY_DELIVERY=wake) delivers an accepted
continuation as an ordinary queued message through the documented
`ctx.inject_message(session_key=...)`, so the turn runs in the session's own
gateway chat/thread. Hermes cannot refuse a turn once it is queued, so the
plugin makes every turn it cannot match to a live continuation *inert*
instead: `pre_tool_call` blocks every tool in that turn and
`transform_llm_output` replaces its reply with a fixed notice. This covers a
superseded, stopped, duplicate or timed-out wake (docs/HERMES_TELEGRAM_SUPPORT.md).
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from typing import Any

try:
    from . import journal
except ImportError:  # loaded as a plain module rather than a package
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import journal  # type: ignore[no-redef]

logger = logging.getLogger("gatekeeper_recovery")

#: Hermes names MCP tools `mcp__<server>__<tool>`.
GATEKEEPER_PREFIX = "mcp__" + os.environ.get("GATEKEEPER_RECOVERY_MCP_SERVER", "gatekeeper") + "__"
RESERVED = "_hermes_recovery"
MARKER_RE = re.compile(r"\[gatekeeper-continuation ([A-Za-z0-9_.:@-]{1,128})\]")
PROFILE = os.environ.get("HERMES_PROFILE") or os.environ.get("GATEKEEPER_RECOVERY_PROFILE") or "default"
KANBAN_PROGRESS_TOOLS = frozenset({
    "kanban_comment", "kanban_heartbeat", "kanban_complete", "kanban_attach",
    "kanban_attach_url", "kanban_request_review",
})
_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")

#: "runs" (sidecar -> POST /v1/runs) or "wake" (this plugin -> ctx.inject_message).
DELIVERY = os.environ.get("GATEKEEPER_RECOVERY_DELIVERY", "runs").strip().lower()
#: An injected wake that has not started after this long while its session is
#: idle is given up as `lost`; it is never injected a second time.
WAKE_START_GRACE = float(os.environ.get("GATEKEEPER_RECOVERY_WAKE_GRACE", "180"))
WAKE_POLL_SECONDS = 2.0
WAKE_TEXT = (
    "{marker}\n"
    "Für diesen noch offenen Auftrag liegt ein Recovery-Hinweis vor. Lies den aktuellen "
    "Task-/Operationszustand und entscheide, ob und wie weitergearbeitet werden darf. "
    "Wiederhole keine Aktion, deren Ergebnis unbekannt ist, bevor der Zustand geprüft ist.\n\n"
    "{guidance}"
)
#: States in which a continuation's marker may start its turn, per delivery mode.
STARTABLE = {"runs": ("accepted", "admitted"), "wake": ("injecting", "injected")}
OPEN_WAKE = ("accepted", "injecting", "injected")
INERT_REPLY = ("[gatekeeper-recovery] Recovery-Hinweis verworfen ({reason}). "
               "In diesem Turn wurde nichts ausgeführt.")

#: Turns that must not act: session_id -> (turn_id, reason). In memory on
#: purpose: a turn never outlives the gateway process.
_inert: dict[str, tuple[str, str]] = {}
_inert_lock = threading.Lock()


def _set_inert(session_id: str, turn_id: Any, reason: str) -> None:
    with _inert_lock:
        _inert[session_id] = (str(turn_id or ""), reason)


def _inert_reason(session_id: str, turn_id: Any) -> str | None:
    with _inert_lock:
        entry = _inert.get(session_id)
    if entry is None:
        return None
    marked, reason = entry
    return reason if not marked or not turn_id or marked == str(turn_id) else None


def _gateway_route() -> dict[str, str] | None:
    """The messaging-chat route of the turn running in this thread, or None
    outside a gateway chat (CLI, API server, Kanban worker). Read-only use of
    Hermes's session context variables."""
    try:
        from gateway.session_context import NON_MESSAGING_SESSION_SURFACES, get_session_env
    except Exception:
        return None
    key = get_session_env("HERMES_SESSION_KEY", "")
    if not key or get_session_env("HERMES_SESSION_PLATFORM", "") in NON_MESSAGING_SESSION_SURFACES:
        return None
    return {"session_key": key, "origin_platform": get_session_env("HERMES_SESSION_PLATFORM", ""),
            "origin_chat_id": get_session_env("HERMES_SESSION_CHAT_ID", ""),
            "origin_thread_id": get_session_env("HERMES_SESSION_THREAD_ID", "")}


# -- Versioned mapping layer: Hermes exit -> contract reason (§2.1) -----------------

def map_exit_v0_21(*, completed: bool, failed: bool, interrupted: bool,
                   turn_exit_reason: Any, user_stop_observed: bool) -> str:
    """Hermes v0.21.x `on_session_end` -> contract stop reason (§2.1).

    Anything this table does not know is `unmapped` -- accepted by
    Gatekeeper and never continued. An interruption whose origin the adapter
    did not observe is neither provably `interrupted` nor provably
    `user_stopped`, so it is `unmapped` too.
    """
    reason = str(turn_exit_reason or "")
    if interrupted:
        return "user_stopped" if user_stop_observed else "unmapped"
    if reason.startswith("max_iterations_reached("):
        return "exhausted"      # real loop exit point: agent/turn_finalizer.py
    if failed:
        return "error"
    if reason.startswith("text_response("):
        return "final_reply"
    logger.warning("gatekeeper-recovery: unmapped turn exit %r -> unmapped", reason)
    return "unmapped"


#: Hermes v0.21.x MCP circuit breaker (tools/mcp_tool.py): opens after this
#: many consecutive failed calls to one server and pauses that server for
#: this many seconds (then half-open). Mirrored from documented
#: post_tool_call outcomes -- the breaker's own state is private.
BREAKER_V0_21 = {"threshold": 3, "cooldown_seconds": 60.0}
_SERVER = GATEKEEPER_PREFIX[len("mcp__"):-2]


def breaker_cooldown_until(conn) -> float | None:
    b = journal.row(conn, "SELECT * FROM breaker WHERE server=?", _SERVER)
    if not b or b["consecutive"] < BREAKER_V0_21["threshold"] or not b["opened_at"]:
        return None
    until = b["opened_at"] + BREAKER_V0_21["cooldown_seconds"] + 1.0
    return until if until > time.time() else None


def _is_gateway_process() -> bool:
    return any("gateway" in a for a in sys.argv[1:3])


# -- Hooks ------------------------------------------------------------------

def _correlation(conn, session_id: str, tool_call_id: Any, turn_id: Any) -> dict[str, Any] | None:
    s = journal.row(conn, "SELECT * FROM sessions WHERE session_id = ?", session_id)
    if s is None:
        return None
    call = str(tool_call_id or f"{time.time_ns()}")
    corr = {
        "session_id": session_id, "board_id": s["board_id"], "task_id": s["task_id"],
        "task_generation": s["task_generation"], "turn_seq": s["turn_seq"],
        "turn_id": str(s["active_turn_id"] or turn_id or f"t{s['turn_seq']}")[:128],
        "event_id": re.sub(r"[^A-Za-z0-9_.:@-]", "_", f"call-{session_id}-{call}")[:128],
        "profile": s["profile"],
    }
    if s["active_continuation_id"]:
        corr["continuation_id"] = s["active_continuation_id"]
    until = breaker_cooldown_until(conn)
    if until:
        corr["cooldown_until"] = until
    return corr


def pre_tool_call(tool_name: str = "", args: Any = None, session_id: str = "",
                  tool_call_id: Any = None, turn_id: Any = None, **_: Any) -> Any:
    reason = _inert_reason(session_id, turn_id) if session_id else None
    if reason is not None:
        # Any tool, not only Gatekeeper's: this turn must not act at all.
        return {"action": "block", "message": INERT_REPLY.format(reason=reason)}
    if not str(tool_name).startswith(GATEKEEPER_PREFIX):
        return None
    try:
        with journal.connect(immediate=True) as conn:
            corr = _correlation(conn, session_id, tool_call_id, turn_id) if session_id else None
            if corr is not None:
                # Every attempt counts, also one Hermes's breaker then blocks.
                conn.execute("UPDATE sessions SET turn_gk_attempts = turn_gk_attempts + 1 "
                             "WHERE session_id=?", (session_id,))
    except Exception:
        logger.exception("gatekeeper-recovery: correlation lookup failed; sending null")
        corr = None
    # Always overwrite: a model-written value never reaches Gatekeeper.
    return {"action": "modify", "args": {RESERVED: corr}}


def pre_llm_call(session_id: str = "", turn_id: Any = None, user_message: Any = None, **_: Any) -> Any:
    if not session_id:
        return None
    text = user_message if isinstance(user_message, str) else json.dumps(user_message, default=str)
    match = MARKER_RE.search(text or "")
    with _inert_lock:
        _inert.pop(session_id, None)
    now = time.time()
    route = _gateway_route()
    inert = None
    with journal.connect(immediate=True) as conn:
        s = journal.row(conn, "SELECT * FROM sessions WHERE session_id = ?", session_id)
        if s is None:
            if match:
                # A marker can only be ours in a bound session.
                logger.warning("gatekeeper-recovery: continuation marker in unbound session %s", session_id)
                inert = "unbound_session"
            if inert:
                _set_inert(session_id, turn_id, inert)
                return {"context": _inert_note(inert)}
            return None
        seq = s["turn_seq"] + 1
        cid = None
        stop_at = s["stop_requested_at"]
        if match:
            c = journal.row(conn, "SELECT * FROM continuations WHERE continuation_id = ? AND session_id = ?",
                            match.group(1), session_id)
            bound = c is not None and (c["board_id"], c["task_id"], c["task_generation"]) == (
                s["board_id"], s["task_id"], s["task_generation"])
            mode = (c["mode"] if c is not None else None) or "runs"
            if c is None or not bound:
                # The text marker alone proves nothing (§5): no matching
                # journal row for this session and binding.
                logger.warning("gatekeeper-recovery: continuation marker %s in session %s has no matching "
                               "journal row; turn is inert", match.group(1), session_id)
                inert = "no_journal_row"
            elif c["state"] not in STARTABLE.get(mode, ()):
                inert = f"state_{c['state']}"
            elif seq != c["expected_turn_seq"] + 1:
                inert = "superseded"
            elif stop_at and stop_at >= c["created_at"]:
                inert = "user_stopped"
            else:
                cid = c["continuation_id"]
                conn.execute(
                    "UPDATE continuations SET state='started', started_at=?, started_turn_seq=?, turn_id=? "
                    "WHERE continuation_id = ?", (now, seq, str(turn_id or "")[:128], cid))
            if inert and bound and c["state"] in STARTABLE.get(mode, ()) + ("accepted",):
                conn.execute("UPDATE continuations SET state='lost', reason=? WHERE continuation_id = ?",
                             (inert, c["continuation_id"]))
        else:
            # An ordinary turn: the user is driving the session again.
            stop_at = None
        conn.execute(
            "UPDATE sessions SET turn_seq=?, active=1, active_turn_id=?, active_continuation_id=?, "
            "stop_reason=NULL, turn_gk_attempts=0, stop_requested_at=?, updated_at=? WHERE session_id=?",
            (seq, str(turn_id or f"t{seq}")[:128], cid, stop_at, now, session_id))
        if route is not None:
            conn.execute(
                "UPDATE sessions SET session_key=?, origin_platform=?, origin_chat_id=?, origin_thread_id=? "
                "WHERE session_id=?", (route["session_key"], route["origin_platform"],
                                       route["origin_chat_id"], route["origin_thread_id"], session_id))
    if inert:
        _set_inert(session_id, turn_id, inert)
        return {"context": _inert_note(inert)}
    return None


def _inert_note(reason: str) -> str:
    return (f"[gatekeeper-recovery] This recovery message is not valid ({reason}). Do not act on it: "
            "every tool call in this turn is blocked. Reply only: superseded.")


def transform_llm_output(response_text: str = "", session_id: str = "", turn_id: Any = None,
                         **_: Any) -> Any:
    reason = _inert_reason(session_id, turn_id) if session_id else None
    return INERT_REPLY.format(reason=reason) if reason is not None else None


def post_tool_call(tool_name: str = "", args: Any = None, session_id: str = "",
                   status: Any = None, error_type: Any = None, **_: Any) -> None:
    if str(tool_name).startswith(GATEKEEPER_PREFIX):
        failed = status in ("error", "blocked")
        with journal.connect(immediate=True) as conn:
            b = journal.row(conn, "SELECT * FROM breaker WHERE server=?", _SERVER) or {"consecutive": 0}
            n = b["consecutive"] + 1 if failed else 0
            opened = time.time() if failed and n >= BREAKER_V0_21["threshold"] else (
                b.get("opened_at") if failed else None)
            conn.execute("INSERT INTO breaker (server, consecutive, opened_at) VALUES (?, ?, ?) "
                         "ON CONFLICT(server) DO UPDATE SET consecutive=excluded.consecutive, "
                         "opened_at=excluded.opened_at", (_SERVER, n, opened))
        return
    if tool_name not in KANBAN_PROGRESS_TOOLS or not session_id or not isinstance(args, dict):
        return
    if (status not in (None, "success", "ok")) or error_type:
        return
    with journal.connect(immediate=True) as conn:
        s = journal.row(conn, "SELECT * FROM sessions WHERE session_id = ?", session_id)
        if s is not None and str(args.get("task_id") or "") == s["task_id"]:
            conn.execute("UPDATE sessions SET last_progress_at=?, updated_at=? WHERE session_id=?",
                         (time.time(), time.time(), session_id))
            if tool_name == "kanban_complete":
                conn.execute("UPDATE sessions SET task_state='completed' WHERE session_id=?", (session_id,))


_user_stops: set[str] = set()


def agent_loop_stopped(session_key: Any = None, reason: Any = None, **_: Any) -> None:
    """Gateway `/stop` and TUI interrupts: an observed, user-initiated stop."""
    if session_key:
        _user_stops.add(str(session_key))
        _record_user_stop("session_key=?", (str(session_key),))


def _record_user_stop(where: str, args: tuple) -> None:
    """Durable: no open wake of these sessions may start after the stop."""
    now = time.time()
    with journal.connect(immediate=True) as conn:
        for s in conn.execute(f"SELECT session_id FROM sessions WHERE {where}", args).fetchall():
            conn.execute("UPDATE sessions SET stop_requested_at=? WHERE session_id=?", (now, s["session_id"]))
            conn.execute("UPDATE continuations SET state='lost', reason='user_stopped' WHERE session_id=? "
                         f"AND mode='wake' AND state IN {OPEN_WAKE!r}", (s["session_id"],))


def pre_gateway_dispatch(event: Any = None, **_: Any) -> None:
    """Observe a `/stop` typed while no turn runs (the running-turn `/stop`
    reaches agent_loop_stopped instead). Never alters the event."""
    try:
        command = event.get_command() if hasattr(event, "get_command") else None
        if command is None:
            text = str(getattr(event, "text", "") or "").strip()
            command = text[1:].split()[0].split("@")[0] if text.startswith("/") and len(text) > 1 else None
        if str(command or "").lower() != "stop":
            return None
        src = event.source
        platform = getattr(getattr(src, "platform", None), "value", None) or str(getattr(src, "platform", ""))
        _record_user_stop("origin_platform=? AND origin_chat_id=? AND COALESCE(origin_thread_id,'')=?",
                          (platform, str(src.chat_id or ""), str(getattr(src, "thread_id", None) or "")))
    except Exception:
        logger.exception("gatekeeper-recovery: could not record /stop")
    return None


def on_session_end(session_id: str = "", turn_id: Any = None, completed: Any = False,
                   failed: Any = False, interrupted: Any = False, turn_exit_reason: Any = None,
                   **_: Any) -> None:
    if not session_id or turn_exit_reason is None and completed is False and failed is False:
        return  # reduced CLI exit shapes: nothing canonical to report
    now = time.time()
    with journal.connect(immediate=True) as conn:
        s = journal.row(conn, "SELECT * FROM sessions WHERE session_id = ?", session_id)
        if s is None:
            return
        reason = map_exit_v0_21(completed=bool(completed), failed=bool(failed), interrupted=bool(interrupted),
                                turn_exit_reason=turn_exit_reason,
                                user_stop_observed=(s["session_key"] in _user_stops
                                                    or any(session_id in k for k in _user_stops)))
        if s["active_continuation_id"]:
            conn.execute("UPDATE continuations SET state='finished', ended_at=?, exit_reason=? "
                         "WHERE continuation_id=? AND state='started'",
                         (now, reason or "unknown", s["active_continuation_id"]))
        conn.execute("UPDATE sessions SET active=0, active_continuation_id=NULL, stop_reason=?, "
                     "updated_at=? WHERE session_id=?", (reason, now, session_id))
        if reason is not None:
            journal.enqueue(conn, f"stop-{session_id}-{s['turn_seq']}"[:128], {
                "type": "turn_stopped", "profile": s["profile"], "session_id": session_id,
                "board_id": s["board_id"], "task_id": s["task_id"],
                "task_generation": s["task_generation"], "turn_seq": s["turn_seq"], "reason": reason,
                # Hermes's own breaker for Gatekeeper is pausing: continuing
                # now would run straight into it (observed live).
                "cooldown_until": breaker_cooldown_until(conn),
                "gatekeeper_attempts": s["turn_gk_attempts"],
            })


def kanban_task_completed(task_id: Any = None, board: Any = None, **_: Any) -> None:
    if not task_id:
        return
    with journal.connect(immediate=True) as conn:
        for s in conn.execute("SELECT * FROM sessions WHERE task_id=? AND board_id=?",
                              (str(task_id), str(board or "default"))).fetchall():
            conn.execute("UPDATE sessions SET task_state='completed' WHERE session_id=?", (s["session_id"],))
            journal.enqueue(conn, f"done-{s['board_id']}-{s['task_id']}-{s['task_generation']}"[:128], {
                "type": "task_completed", "profile": s["profile"], "board_id": s["board_id"],
                "task_id": s["task_id"], "task_generation": s["task_generation"],
            })


# -- Explicit task binding -------------------------------------------------

BIND_SCHEMA = {
    "name": "gatekeeper_recovery_bind_task",
    "description": (
        "Declare the Kanban task this session is accountable for (as an orchestrator: the "
        "parent task you were asked to handle). Required for Gatekeeper recovery to resume "
        "this session if it gets stuck. Call once when you take the task on."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "board_id": {"type": "string", "description": "Kanban board slug"},
            "task_id": {"type": "string", "description": "Kanban task id"},
            "objective": {"type": "string", "description": "One-line objective (no secrets)"},
        },
        "required": ["board_id", "task_id"],
    },
}


def bind_task(args: dict, session_id: str = "", **_: Any) -> str:
    board, task = str(args.get("board_id") or ""), str(args.get("task_id") or "")
    if not (session_id and _ID_RE.fullmatch(board) and _ID_RE.fullmatch(task)):
        return json.dumps({"success": False, "error": "board_id/task_id invalid or no session"})
    now = time.time()
    with journal.connect(immediate=True) as conn:
        s = journal.row(conn, "SELECT * FROM sessions WHERE session_id=?", session_id)
        if s is not None and (s["board_id"], s["task_id"]) != (board, task):
            return json.dumps({"success": False, "error":
                               f"session already bound to {s['board_id']}/{s['task_id']}"})
        if s is None:
            # The turn calling this has already started: it counts as turn 1.
            conn.execute(
                "INSERT INTO sessions (session_id, profile, board_id, task_id, objective, turn_seq, "
                "active, updated_at) VALUES (?, ?, ?, ?, ?, 1, 1, ?)",
                (session_id, PROFILE, board, task, str(args.get("objective") or "")[:300], now))
        route = _gateway_route()
        if route is not None:
            conn.execute(
                "UPDATE sessions SET session_key=?, origin_platform=?, origin_chat_id=?, origin_thread_id=? "
                "WHERE session_id=?", (route["session_key"], route["origin_platform"],
                                       route["origin_chat_id"], route["origin_thread_id"], session_id))
    return json.dumps({"success": True, "session_id": session_id, "board_id": board, "task_id": task})


def _startup_reconcile() -> None:
    """Gateway start: turns the journal shows as active died with the last
    process -- a certain technical interruption."""
    now = time.time()
    with journal.connect(immediate=True) as conn:
        # Hermes's breaker state is per process: a new gateway starts closed.
        conn.execute("DELETE FROM breaker")
        # A wake handed to the previous gateway died with its in-memory queue,
        # or ran and was recorded 'started'. Either way: never inject again.
        conn.execute("UPDATE continuations SET state='lost', reason='gateway_restart' "
                     "WHERE mode='wake' AND state IN ('injecting', 'injected')")
        for s in conn.execute("SELECT * FROM sessions WHERE active=1").fetchall():
            conn.execute("UPDATE continuations SET state='finished', ended_at=?, exit_reason='interrupted' "
                         "WHERE continuation_id=? AND state='started'", (now, s["active_continuation_id"]))
            conn.execute("UPDATE sessions SET active=0, active_continuation_id=NULL, "
                         "stop_reason='interrupted', updated_at=? WHERE session_id=?", (now, s["session_id"]))
            journal.enqueue(conn, f"stop-{s['session_id']}-{s['turn_seq']}"[:128], {
                "type": "turn_stopped", "profile": s["profile"], "session_id": s["session_id"],
                "board_id": s["board_id"], "task_id": s["task_id"],
                "task_generation": s["task_generation"], "turn_seq": s["turn_seq"],
                "reason": "interrupted", "gatekeeper_attempts": s["turn_gk_attempts"],
            })


# -- Wake delivery (GATEKEEPER_RECOVERY_DELIVERY=wake) ----------------------------

def wake_once(ctx: Any) -> None:
    """Inject each accepted wake at most once, and give up injected wakes
    that never started. A wake whose state is no longer startable when its
    turn begins runs inert (pre_llm_call), so every race here fails closed."""
    now = time.time()
    with journal.connect(immediate=True) as conn:
        conn.execute(
            "UPDATE continuations SET state='lost', reason='not_started' WHERE mode='wake' "
            "AND state IN ('injecting','injected') AND COALESCE(injected_at, created_at) < ? AND session_id IN "
            "(SELECT session_id FROM sessions WHERE active=0)", (now - WAKE_START_GRACE,))
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM continuations WHERE mode='wake' AND state='accepted' ORDER BY created_at").fetchall()]
    for c in rows:
        with journal.connect(immediate=True) as conn:
            fresh = journal.row(conn, "SELECT * FROM continuations WHERE continuation_id=?", c["continuation_id"])
            s = journal.row(conn, "SELECT * FROM sessions WHERE session_id=?", c["session_id"])
            if fresh is None or fresh["state"] != "accepted" or s is None:
                continue
            reason = None
            if not s["session_key"]:
                reason = "no_gateway_route"
            elif s["stop_requested_at"] and s["stop_requested_at"] >= c["created_at"]:
                reason = "user_stopped"
            elif s["turn_seq"] != c["expected_turn_seq"]:
                reason = "superseded"
            elif s["active"]:
                continue  # wait for idle: a wake queued behind a turn would survive its /stop
            if reason:
                conn.execute("UPDATE continuations SET state='lost', reason=? WHERE continuation_id=?",
                             (reason, c["continuation_id"]))
                continue
            # Durable before the call: a crash from here on is never re-injected.
            conn.execute("UPDATE continuations SET state='injecting', deliveries=deliveries+1 "
                         "WHERE continuation_id=?", (c["continuation_id"],))
            session_key = s["session_key"]
        text = WAKE_TEXT.format(marker=f"[gatekeeper-continuation {c['continuation_id']}]",
                                guidance=c["guidance"])
        try:
            ok = bool(ctx.inject_message(text, role="user", session_key=session_key))
        except Exception:
            logger.exception("gatekeeper-recovery: inject_message raised; wake %s left unconfirmed",
                             c["continuation_id"])
            continue
        with journal.connect(immediate=True) as conn:
            if ok:
                conn.execute("UPDATE continuations SET state='injected', injected_at=? "
                             "WHERE continuation_id=? AND state='injecting'", (time.time(), c["continuation_id"]))
            else:
                # False: no host accepted it, nothing was scheduled.
                conn.execute("UPDATE continuations SET state='lost', reason='not_scheduled' "
                             "WHERE continuation_id=? AND state='injecting'", (c["continuation_id"],))
        logger.info("gatekeeper-recovery: wake %s session_key=%s scheduled=%s",
                    c["continuation_id"], session_key, ok)


def _wake_loop(ctx: Any) -> None:
    while True:
        try:
            wake_once(ctx)
        except Exception:
            logger.exception("gatekeeper-recovery: wake pass failed")
        time.sleep(WAKE_POLL_SECONDS)


def register(ctx: Any) -> None:
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("on_session_end", on_session_end)
    ctx.register_hook("agent_loop_stopped", agent_loop_stopped)
    ctx.register_hook("pre_gateway_dispatch", pre_gateway_dispatch)
    ctx.register_hook("transform_llm_output", transform_llm_output)
    ctx.register_hook("kanban_task_completed", kanban_task_completed)
    ctx.register_tool(name="gatekeeper_recovery_bind_task", toolset="gatekeeper_recovery",
                      schema=BIND_SCHEMA, handler=bind_task)
    if _is_gateway_process():
        try:
            _startup_reconcile()
        except Exception:
            logger.exception("gatekeeper-recovery: startup reconcile failed")
        if DELIVERY == "wake":
            threading.Thread(target=_wake_loop, args=(ctx,), name="gatekeeper-recovery-wake",
                             daemon=True).start()
    logger.info("gatekeeper-recovery plugin loaded (id %s, delivery %s, journal %s, prefix %s)",
                getattr(ctx, "plugin_id", "?"), DELIVERY, journal.path(), GATEKEEPER_PREFIX)
