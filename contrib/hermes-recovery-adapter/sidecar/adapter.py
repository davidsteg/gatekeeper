"""Gatekeeper recovery adapter -- sidecar half (contract v1.1, docs/HERMES_ADAPTER.md).

Serves the signed adapter endpoints Gatekeeper calls (/status, /continue,
/continuation), delivers the plugin's outbox to Gatekeeper's
/recovery/events, and reconciles continuations that were journaled but never
started. Talks to Hermes only through its documented Runs API
(`POST /v1/runs` with `session_id` + `Idempotency-Key`, `GET /v1/runs/{id}`).

In wake mode (ADAPTER_DELIVERY=wake) the sidecar only journals the
accepted continuation; the plugin inside the gateway delivers it through
`ctx.inject_message`, so the turn answers in the session's own chat. The
Runs API is not used and HERMES_API_KEY is not needed.

Standard library only. Configuration (env):
  ADAPTER_LISTEN        host:port to serve on            (default 0.0.0.0:8650)
  ADAPTER_INSTALLATION  Gatekeeper installation name     (required)
  ADAPTER_SECRET        HMAC secret shared with Gatekeeper (required)
  GATEKEEPER_URL        e.g. http://host.docker.internal:18780 (required)
  GATEKEEPER_TOKEN      the installation identity's bearer token (required)
  HERMES_API_URL        default http://127.0.0.1:8642
  HERMES_API_KEY        Hermes API_SERVER_KEY (required in runs mode)
  ADAPTER_DELIVERY      runs (default) | wake
  GATEKEEPER_RECOVERY_JOURNAL  journal path (shared with the plugin)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugin",
                                "gatekeeper-recovery"))
sys.path.insert(0, os.environ.get("ADAPTER_PLUGIN_DIR", "/opt/data/plugins/gatekeeper-recovery"))
import journal  # noqa: E402

log = logging.getLogger("gatekeeper-recovery-sidecar")

INSTALLATION = os.environ.get("ADAPTER_INSTALLATION", "")
SECRET = os.environ.get("ADAPTER_SECRET", "").encode()
GK_URL = os.environ.get("GATEKEEPER_URL", "").rstrip("/")
GK_TOKEN = os.environ.get("GATEKEEPER_TOKEN", "")
HERMES_URL = os.environ.get("HERMES_API_URL", "http://127.0.0.1:8642").rstrip("/")
HERMES_KEY = os.environ.get("HERMES_API_KEY", "")
DELIVERY = os.environ.get("ADAPTER_DELIVERY", "runs").strip().lower()
MARKER = "[gatekeeper-continuation {cid}]"
#: Wake-mode delivery states, reported to Gatekeeper as 'accepted'.
WAKE_PENDING = ("injecting", "injected")
MAX_DELIVERIES = 2
OUTBOX_GIVE_UP_SECONDS = 24 * 3600


def log_event(event: str, **fields) -> None:
    log.info(json.dumps({"event": event, **fields}, sort_keys=True, default=str))


# -- Hermes Runs API ------------------------------------------------------------

def _hermes(method: str, path: str, body: dict | None = None, headers: dict | None = None,
            timeout: float = 15) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(HERMES_URL + path, data=data, method=method, headers={
        "Authorization": f"Bearer {HERMES_KEY}", "Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def _admit(row: dict) -> tuple[str, str | None]:
    """Start the continuation turn through the documented Runs API.

    Returns ("admitted", run_id) | ("rejected", reason) | ("ambiguous", None).
    The Hermes Idempotency-Key is derived from the contract key and the
    delivery number, so a retry of the same delivery never starts a second run.
    """
    text = MARKER.format(cid=row["continuation_id"]) + "\n" + row["guidance"]
    idem = f"gk-{row['idempotency_key']}#{row['deliveries'] + 1}"
    try:
        status, body = _hermes("POST", "/v1/runs", {"input": text, "session_id": row["session_id"]},
                               {"Idempotency-Key": idem})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log_event("admit_ambiguous", continuation_id=row["continuation_id"], error=type(exc).__name__)
        return "ambiguous", None
    if status in (200, 201, 202) and body.get("run_id"):
        return "admitted", str(body["run_id"])
    if status == 429 or status >= 500:
        return "ambiguous", None
    return "rejected", f"not_admitted:{status}"


# -- Ownership and status -------------------------------------------------------

def _owned_session(conn, ref: dict) -> tuple[dict | None, int]:
    """The adapter's authoritative check of the reference (§6.5)."""
    if ref.get("installation") != INSTALLATION:
        return None, 409
    s = journal.row(conn, "SELECT * FROM sessions WHERE session_id = ?", str(ref.get("session_id") or ""))
    if s is None:
        return None, 404
    if (s["board_id"], s["task_id"], s["task_generation"]) != (
            ref.get("board_id"), ref.get("task_id"), int(ref.get("task_generation") or 0)):
        return None, 409
    if ref.get("profile") is not None and ref.get("profile") != s["profile"]:
        return None, 409
    return s, 200


def _status(conn, s: dict) -> dict:
    last = journal.row(conn, "SELECT * FROM continuations WHERE session_id=? ORDER BY created_at DESC LIMIT 1",
                       s["session_id"])
    turn = "active" if s["active"] else ("exhausted" if s["stop_reason"] == "exhausted" else "stopped")
    return {
        "session_id": s["session_id"], "board_id": s["board_id"], "task_id": s["task_id"],
        "task_generation": s["task_generation"], "turn": turn, "turn_seq": s["turn_seq"],
        "stop_reason": s["stop_reason"], "task": s["task_state"],
        "last_progress_at": s["last_progress_at"],
        "continuation_id": s["active_continuation_id"] if s["active"] else None,
        "last_continuation": None if last is None else {
            k: last[k] for k in ("continuation_id", "state", "started_at", "started_turn_seq",
                                 "ended_at", "exit_reason")},
        # Orchestrator sessions are the Gatekeeper case; this adapter binds no
        # dispatcher-owned worker sessions, so Hermes-internal recovery never
        # owns a bound session here (§3).
        "recovery_owner": None, "recovery_until": None,
        "objective": s["objective"], "acceptance_criteria": "", "task_state": "",
    }


def _continuation_view(c: dict | None) -> dict:
    if c is None:
        return {"state": "none"}
    view = {k: c[k] for k in ("state", "continuation_id", "reason", "started_at", "started_turn_seq",
                              "ended_at", "exit_reason")}
    if c["state"] in WAKE_PENDING:
        view.update(state="accepted", delivery_state=c["state"])
    return view


# -- /continue ------------------------------------------------------------------

_continue_lock = threading.Lock()


def handle_continue(req: dict) -> tuple[int, dict]:
    key = str(req.get("idempotency_key") or "")
    if not key:
        return 400, {"error": "idempotency_key required"}
    with _continue_lock:
        with journal.connect(immediate=True) as conn:
            existing = journal.row(conn, "SELECT * FROM continuations WHERE idempotency_key=?", key)
            if existing is not None:
                return 200, _answer(existing)
            s, code = _owned_session(conn, req)
            if s is None:
                return code, {"error": "reference does not match an owned session"}
            reason = None
            if s["task_state"] != "open":
                reason = "task_closed"
            elif s["active"]:
                reason = "turn_active"
            elif s["turn_seq"] != int(req.get("expected_turn_seq", -1)):
                reason = "turn_seq_mismatch"
            elif DELIVERY == "wake":
                if s["stop_requested_at"]:
                    reason = "user_stopped"
                elif not s["session_key"]:
                    reason = "no_gateway_route"
                elif journal.row(conn, "SELECT 1 AS x FROM continuations WHERE session_id=? AND state IN "
                                 "('accepted','admitted','injecting','injected','started')", s["session_id"]):
                    reason = "superseded"  # one open continuation per session
            cid = "cont-" + uuid.uuid4().hex[:16]
            # Acceptance (or the rejection) is durable before anything starts.
            conn.execute(
                "INSERT INTO continuations (idempotency_key, continuation_id, incident_id, session_id, "
                "board_id, task_id, task_generation, expected_turn_seq, guidance, state, reason, created_at, mode) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (key, cid, str(req.get("incident_id") or ""), s["session_id"], s["board_id"], s["task_id"],
                 s["task_generation"], int(req.get("expected_turn_seq", -1)),
                 str(req.get("guidance") or "")[:4000], "rejected" if reason else "accepted", reason,
                 time.time(), "wake" if DELIVERY == "wake" else "runs"))
        log_event("continue_journaled", continuation_id=cid, session_id=s["session_id"],
                  idempotency_key=key, state="rejected" if reason else "accepted", reason=reason)
        if reason:
            return 200, {"accepted": False, "reason": reason}
        if DELIVERY == "wake":
            # The plugin in the gateway injects it (wake_once); nothing to start here.
            with journal.connect() as conn:
                return 200, _answer(journal.row(conn, "SELECT * FROM continuations WHERE idempotency_key=?", key))
        _deliver(key)
        with journal.connect() as conn:
            return 200, _answer(journal.row(conn, "SELECT * FROM continuations WHERE idempotency_key=?", key))


def _answer(c: dict) -> dict:
    if c["state"] in ("rejected", "lost"):
        return {"accepted": False, "reason": c["reason"] or c["state"]}
    return {"accepted": True, "continuation_id": c["continuation_id"]}


def _deliver(key: str) -> None:
    with journal.connect() as conn:
        row = journal.row(conn, "SELECT * FROM continuations WHERE idempotency_key=?", key)
    outcome, value = _admit(row)
    with journal.connect(immediate=True) as conn:
        if outcome == "admitted":
            conn.execute("UPDATE continuations SET state=CASE WHEN state='accepted' THEN 'admitted' ELSE state END, "
                         "run_id=?, admitted_at=?, deliveries=deliveries+1 WHERE idempotency_key=?",
                         (value, time.time(), key))
        elif outcome == "rejected":
            conn.execute("UPDATE continuations SET state='rejected', reason=? WHERE idempotency_key=? "
                         "AND state='accepted'", (value, key))
    log_event("continue_delivery", idempotency_key=key, outcome=outcome, run_id=value)


# -- Background: reconcile journaled-but-not-started continuations -------------

def reconcile_once() -> None:
    with journal.connect() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM continuations WHERE state IN ('accepted','admitted') AND mode='runs'").fetchall()]
    for c in rows:
        if c["state"] == "accepted":
            # Admission never confirmed: retry the SAME delivery (same Hermes key).
            _deliver(c["idempotency_key"])
            continue
        status, run = _hermes("GET", f"/v1/runs/{c['run_id']}")
        run_state = run.get("status") if status == 200 else "unknown"
        if run_state in ("queued", "running", "started", "stopping", "waiting_for_approval"):
            continue
        with journal.connect(immediate=True) as conn:
            fresh = journal.row(conn, "SELECT * FROM continuations WHERE idempotency_key=?", c["idempotency_key"])
            if fresh is None or fresh["state"] != "admitted":
                continue  # started meanwhile (plugin) or already settled
            s = journal.row(conn, "SELECT * FROM sessions WHERE session_id=?", c["session_id"])
            idle = s is not None and not s["active"] and s["turn_seq"] == c["expected_turn_seq"]
            if fresh["deliveries"] < MAX_DELIVERIES and idle:
                conn.execute("UPDATE continuations SET state='accepted' WHERE idempotency_key=?",
                             (c["idempotency_key"],))
                redeliver = True
            else:
                conn.execute("UPDATE continuations SET state='lost', reason=? WHERE idempotency_key=?",
                             ("turn_active" if s is not None and s["active"] else "superseded",
                              c["idempotency_key"]))
                redeliver = False
        log_event("continuation_reconciled", idempotency_key=c["idempotency_key"], run_state=run_state,
                  redeliver=redeliver)
        if redeliver:
            _deliver(c["idempotency_key"])


# -- Background: outbox -> Gatekeeper /recovery/events ---------------------------

def outbox_once() -> None:
    now = time.time()
    with journal.connect() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM outbox WHERE sent_at IS NULL AND dropped IS NULL AND next_at <= ? ORDER BY id LIMIT 20",
            (now,)).fetchall()]
    for ev in rows:
        payload = {**json.loads(ev["payload"]), "installation": INSTALLATION}
        req = urllib.request.Request(GK_URL + "/recovery/events", data=json.dumps(payload).encode(),
                                     method="POST", headers={"Authorization": f"Bearer {GK_TOKEN}",
                                                             "Content-Type": "application/json"})
        code, body = 0, {}
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                code, body = r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            code = e.code
        except (urllib.error.URLError, TimeoutError, OSError):
            code = 0
        with journal.connect(immediate=True) as conn:
            if code == 200:
                conn.execute("UPDATE outbox SET sent_at=?, attempts=attempts+1 WHERE id=?", (time.time(), ev["id"]))
            elif code in (400, 403) or now - ev["created_at"] > OUTBOX_GIVE_UP_SECONDS:
                conn.execute("UPDATE outbox SET dropped=?, attempts=attempts+1 WHERE id=?",
                             (f"http {code}", ev["id"]))
            else:
                delay = min(300.0, 2.0 ** min(ev["attempts"], 9))
                conn.execute("UPDATE outbox SET attempts=attempts+1, next_at=? WHERE id=?",
                             (time.time() + delay, ev["id"]))
        log_event("outbox_send", event_id=ev["event_id"], http=code, action=body.get("action"))


def loop(fn, every: float) -> None:
    while True:
        try:
            fn()
        except Exception:
            log.exception("%s failed", fn.__name__)
        time.sleep(every)


# -- HTTP -----------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _reply(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        ts = self.headers.get("X-Webhook-Timestamp", "")
        sig = self.headers.get("X-Webhook-Signature-V2", "")
        expected = hmac.new(SECRET, ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
        if not (ts.isdigit() and abs(time.time() - int(ts)) <= 300 and hmac.compare_digest(expected, sig)):
            return self._reply(401, {"error": "bad signature"})
        try:
            req = json.loads(raw)
        except ValueError:
            return self._reply(400, {"error": "not json"})
        path = self.path.rstrip("/").rsplit("/", 1)[-1]
        if path == "continue":
            code, body = handle_continue(req)
            return self._reply(code, body)
        with journal.connect() as conn:
            s, code = _owned_session(conn, req)
            if s is None:
                return self._reply(code, {"error": "reference does not match an owned session"})
            if path == "status":
                return self._reply(200, _status(conn, s))
            if path == "continuation":
                c = journal.row(conn, "SELECT * FROM continuations WHERE idempotency_key=? AND session_id=?",
                                str(req.get("idempotency_key") or ""), s["session_id"])
                return self._reply(200, _continuation_view(c))
        return self._reply(404, {"error": "unknown endpoint"})


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", stream=sys.stdout)
    if DELIVERY not in ("runs", "wake"):
        sys.exit(f"ADAPTER_DELIVERY must be runs or wake, not {DELIVERY!r}")
    required = [("ADAPTER_INSTALLATION", INSTALLATION), ("ADAPTER_SECRET", SECRET),
                ("GATEKEEPER_URL", GK_URL), ("GATEKEEPER_TOKEN", GK_TOKEN)]
    if DELIVERY == "runs":
        required.append(("HERMES_API_KEY", HERMES_KEY))
    missing = [n for n, v in required if not v]
    if missing:
        sys.exit(f"missing config: {', '.join(missing)}")
    host, _, port = os.environ.get("ADAPTER_LISTEN", "0.0.0.0:8650").rpartition(":")
    threading.Thread(target=loop, args=(outbox_once, 2.0), daemon=True).start()
    threading.Thread(target=loop, args=(reconcile_once, 5.0), daemon=True).start()
    log_event("sidecar_started", listen=f"{host}:{port}", installation=INSTALLATION, journal=journal.path(),
              delivery=DELIVERY)
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()


if __name__ == "__main__":
    main()
