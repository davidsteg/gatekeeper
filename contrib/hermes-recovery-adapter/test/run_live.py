"""Live acceptance driver against the isolated test instance.

  python run_live.py first      failure -> stopped turn -> continue -> exactly one new turn
                                in the same session -> executed call with continuation_id
                                -> recorded progress
  python run_live.py evidence <session>   dump all evidence for a session

Evidence comes from four independent places: the adapter journal (inside
the container), Gatekeeper's incident store + audit log (host), the Hermes
session transcript (API), and the fake model's request log.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
SECRETS = json.load(open(os.path.join(OUT, "secrets.json"), encoding="utf-8"))
HERMES = "http://127.0.0.1:18642"
BOARD = "default"


def new_task(title):
    """A fresh Kanban task per scenario: the recovery budget is per task."""
    out = subprocess.run(["docker", "exec", "-u", "hermes", "hermes-test", "hermes", "kanban", "create", title,
                          "--initial-status", "blocked", "--json"], capture_output=True, text=True, check=True).stdout
    return json.loads(out[out.index("{"):])["id"]


def hermes(method, path, body=None, headers=None, timeout=60):
    req = urllib.request.Request(HERMES + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {SECRETS['hermes_api_key']}",
                                          "Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def run(session, text, key=None):
    code, body = hermes("POST", "/v1/runs", {"input": text, "session_id": session},
                        {"Idempotency-Key": key} if key else None)
    print(f"POST /v1/runs session={session} -> {code} {body}")
    return body.get("run_id")


def wait_run(run_id, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, body = hermes("GET", f"/v1/runs/{run_id}")
        if body.get("status") in ("completed", "failed", "cancelled", "interrupted"):
            return body
        time.sleep(1)
    raise TimeoutError(run_id)


def journal(sql):
    code = ("import sqlite3,json,sys; c=sqlite3.connect('/opt/data/gatekeeper-recovery/journal.db'); "
            "c.row_factory=sqlite3.Row; print(json.dumps([dict(r) for r in c.execute(sys.argv[1])]))")
    out = subprocess.run(["docker", "exec", "hermes-test", "python3", "-c", code, sql],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def incidents():
    p = os.path.join(OUT, "gk", "recovery.yaml")
    if not os.path.exists(p):
        return []
    return list((yaml.safe_load(open(p, encoding="utf-8")) or {}).get("incidents", {}).values())


def audit_recovery():
    p = os.path.join(OUT, "gk", "logs", "audit.jsonl")
    if not os.path.exists(p):
        return []
    return [json.loads(x) for x in open(p, encoding="utf-8") if '"kind": "recovery"' in x
            or '"kind":"recovery"' in x]


def messages(session):
    _, body = hermes("GET", f"/api/sessions/{session}/messages")
    return body.get("data") or body.get("messages") or []


def wait_for(pred, what, timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = pred()
        if v:
            print(f"  ok: {what}")
            return v
        time.sleep(2)
    raise TimeoutError(what)


def evidence(session):
    msgs = messages(session)
    users = [m for m in msgs if m.get("role") == "user"]
    return {
        "journal_session": journal(f"SELECT * FROM sessions WHERE session_id='{session}'"),
        "journal_continuations": journal(f"SELECT idempotency_key, continuation_id, state, reason, run_id, "
                                         f"deliveries, expected_turn_seq, started_turn_seq, started_at, ended_at, "
                                         f"exit_reason FROM continuations WHERE session_id='{session}'"),
        "journal_outbox": journal("SELECT event_id, attempts, sent_at IS NOT NULL AS sent, dropped FROM outbox"),
        "gatekeeper_incidents": [{k: i.get(k) for k in ("id", "session_id", "task_id", "status", "outcome",
                                                        "last_turn_seq")} | {"continuation": i["continuation"]}
                                 for i in incidents() if i.get("session_id") == session],
        "gatekeeper_audit_recovery": [{k: r.get(k) for k in ("event", "incident_id", "continuation_id",
                                                             "action", "outcome", "trigger", "tool_id")}
                                      for r in audit_recovery()],
        "hermes_user_messages": [str(m.get("content"))[:120] for m in users],
        "hermes_continuation_inputs": sum("[gatekeeper-continuation" in str(m.get("content")) for m in users),
    }


def first():
    session = f"orch-{int(time.time())}"
    task = new_task("Orchestrate: first live round trip")
    print("kanban task", task)
    rid = run(session, f"START {BOARD} {task}")
    r1 = wait_run(rid)
    print(f"turn 1 run: status={r1.get('status')} output={str(r1.get('output'))[:100]!r}")
    wait_for(lambda: any(i.get("session_id") == session and i["continuation"].get("status") == "accepted"
                         or i.get("session_id") == session and i.get("status") in ("active", "recovered")
                         for i in incidents()), "Gatekeeper accepted a continuation")
    wait_for(lambda: any(i.get("session_id") == session and i.get("outcome") == "recovered"
                         for i in incidents()), "incident recovered (owner-reported progress)")
    ev = evidence(session)
    path = os.path.join(OUT, f"evidence-first-{session}.json")
    json.dump(ev, open(path, "w", encoding="utf-8"), indent=2, default=str)
    print(json.dumps(ev, indent=2, default=str))
    print("evidence:", path)
    return session



def signed_sidecar(path, payload):
    import hashlib
    import hmac
    body = json.dumps(payload, sort_keys=True).encode()
    ts = str(int(time.time()))
    sig = hmac.new(SECRETS["adapter_secret"].encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(f"http://127.0.0.1:18790/recovery/{path}", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-Webhook-Timestamp": ts,
                                          "X-Webhook-Signature-V2": sig})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def gk_event(payload):
    req = urllib.request.Request("http://127.0.0.1:18780/recovery/events", data=json.dumps(payload).encode(),
                                 method="POST", headers={"Content-Type": "application/json",
                                                         "Authorization": f"Bearer {SECRETS['gatekeeper_token']}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def runs_for(session):
    return journal(f"SELECT * FROM continuations WHERE session_id='{session}'")


def seq(session):
    return journal(f"SELECT turn_seq FROM sessions WHERE session_id='{session}'")[0]["turn_seq"]


def duplicate(session):
    """Replay the same /continue (same key) and the same stop event after recovery."""
    [c] = runs_for(session)
    s0 = seq(session)
    s = journal(f"SELECT * FROM sessions WHERE session_id='{session}'")[0]
    ref = {"installation": "test", "profile": s["profile"], "session_id": session, "board_id": s["board_id"],
           "task_id": s["task_id"], "task_generation": s["task_generation"]}
    answers = [signed_sidecar("continue", {**ref, "incident_id": c["incident_id"],
                                           "idempotency_key": c["idempotency_key"],
                                           "expected_turn_seq": c["expected_turn_seq"], "guidance": "replay"})
               for _ in range(3)]
    ev = json.loads(journal(f"SELECT payload FROM outbox WHERE event_id='stop-{session}-1'")[0]["payload"])
    replayed = [gk_event({**ev, "installation": "test"}) for _ in range(2)]
    time.sleep(8)
    result = {
        "continue_replays": answers,
        "event_replays": replayed,
        "continuations_after": [{k: x[k] for k in ("continuation_id", "state", "deliveries", "run_id")}
                                for x in runs_for(session)],
        "turn_seq_before": s0, "turn_seq_after": seq(session),
        "continuation_inputs_in_transcript": evidence(session)["hermes_continuation_inputs"],
    }
    assert all(a == {"accepted": True, "continuation_id": c["continuation_id"]} for a in answers), answers
    assert all(r.get("duplicate") for r in replayed), replayed
    assert len(result["continuations_after"]) == 1 and result["continuations_after"][0]["deliveries"] == 1
    assert result["turn_seq_after"] == s0 and result["continuation_inputs_in_transcript"] == 1
    return result


def competing():
    """A user message lands in the session while Gatekeeper waits out the cooldown."""
    session = f"orch-{int(time.time())}"
    task = new_task("Orchestrate: competing user message")
    wait_run(run(session, f"START {BOARD} {task}"))
    wait_for(lambda: any(i.get("session_id") == session and i.get("status") == "cooling" for i in incidents()),
             "incident cooling (breaker pause)")
    user = wait_run(run(session, "Actually, what is the status? (user message)"))
    print("user turn:", user.get("status"), str(user.get("output"))[:60])
    wait_for(lambda: any(i.get("session_id") == session and i.get("status") != "cooling"
                         for i in incidents()), "cooldown check done", timeout=150)
    time.sleep(5)
    inc = [i for i in incidents() if i.get("session_id") == session][0]
    result = {"session": session, "incident_status": inc["status"], "incident_outcome": inc["outcome"],
              "continuations": runs_for(session), "turn_seq": seq(session),
              "continuation_inputs_in_transcript": evidence(session)["hermes_continuation_inputs"],
              "audit": [a["event"] for a in audit_recovery() if a.get("incident_id") == inc["id"]]}
    assert result["continuations"] == [] and result["continuation_inputs_in_transcript"] == 0, result
    return result


def restart():
    """Restart Gatekeeper, the Hermes gateway and the sidecar while the incident cools down."""
    session = f"orch-{int(time.time())}"
    task = new_task("Orchestrate: restart during cooldown")
    wait_run(run(session, f"START {BOARD} {task}"))
    inc = wait_for(lambda: [i for i in incidents() if i.get("session_id") == session and i.get("status") == "cooling"],
                   "incident cooling")[0]
    for cmd in (["python", "restart_all.py"],):
        subprocess.run([sys.executable, os.path.join(HERE, "restart_all.py")], check=True)
    wait_for(lambda: any(i.get("session_id") == session and i.get("outcome") == "recovered" for i in incidents()),
             "recovered after restarts", timeout=300)
    after = [i for i in incidents() if i.get("session_id") == session][0]
    result = {"session": session, "cooldown_until_before": inc["cooldown_until"],
              "cooldown_until_after": after["cooldown_until"], "outcome": after["outcome"],
              "continuations": [{k: x[k] for k in ("continuation_id", "state", "deliveries")}
                                for x in runs_for(session)],
              "continuation_inputs_in_transcript": evidence(session)["hermes_continuation_inputs"]}
    assert len(result["continuations"]) == 1 and result["continuation_inputs_in_transcript"] == 1, result
    assert result["cooldown_until_before"] == result["cooldown_until_after"]
    return result


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "first":
        first()
    elif cmd == "evidence":
        print(json.dumps(evidence(sys.argv[2]), indent=2, default=str))
    else:
        res = {"duplicate": lambda: duplicate(sys.argv[2]), "competing": competing, "restart": restart}[cmd]()
        path = os.path.join(OUT, f"evidence-{cmd}.json")
        json.dump(res, open(path, "w", encoding="utf-8"), indent=2, default=str)
        print(json.dumps(res, indent=2, default=str))
        print("evidence:", path)
