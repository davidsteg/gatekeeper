"""Durable journal shared by the Hermes plugin (in the gateway process) and
the adapter sidecar. Contract: Gatekeeper docs/HERMES_ADAPTER.md v1.1.

SQLite in WAL mode with synchronous=FULL: a committed row survives a crash
of either process. This is the adapter's own store -- it never touches
Hermes's state.db or kanban.db.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Iterator

DEFAULT_PATH = os.path.join(
    os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes")),
    "gatekeeper-recovery", "journal.db",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id        TEXT PRIMARY KEY,
    profile           TEXT NOT NULL,
    board_id          TEXT NOT NULL,
    task_id           TEXT NOT NULL,
    task_generation   INTEGER NOT NULL DEFAULT 0,
    objective         TEXT NOT NULL DEFAULT '',
    turn_seq          INTEGER NOT NULL DEFAULT 0,
    active            INTEGER NOT NULL DEFAULT 0,
    active_turn_id    TEXT,
    active_continuation_id TEXT,
    stop_reason       TEXT,
    task_state        TEXT NOT NULL DEFAULT 'open',
    last_progress_at  REAL NOT NULL DEFAULT 0,
    updated_at        REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS continuations (
    idempotency_key   TEXT PRIMARY KEY,
    continuation_id   TEXT NOT NULL UNIQUE,
    incident_id       TEXT,
    session_id        TEXT NOT NULL,
    board_id          TEXT NOT NULL,
    task_id           TEXT NOT NULL,
    task_generation   INTEGER NOT NULL,
    expected_turn_seq INTEGER NOT NULL,
    guidance          TEXT NOT NULL,
    state             TEXT NOT NULL,
    reason            TEXT,
    run_id            TEXT,
    deliveries        INTEGER NOT NULL DEFAULT 0,
    created_at        REAL NOT NULL,
    admitted_at       REAL,
    started_at        REAL,
    started_turn_seq  INTEGER,
    turn_id           TEXT,
    ended_at          REAL,
    exit_reason       TEXT
);
CREATE TABLE IF NOT EXISTS breaker (
    server       TEXT PRIMARY KEY,
    consecutive  INTEGER NOT NULL DEFAULT 0,
    opened_at    REAL
);
CREATE TABLE IF NOT EXISTS outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL UNIQUE,
    payload     TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL,
    next_at     REAL NOT NULL,
    sent_at     REAL,
    dropped     TEXT
);
"""

_init_lock = threading.Lock()
_initialized: set[str] = set()


def path() -> str:
    return os.environ.get("GATEKEEPER_RECOVERY_JOURNAL", DEFAULT_PATH)


@contextlib.contextmanager
def connect(immediate: bool = False) -> Iterator[sqlite3.Connection]:
    """One short-lived connection per unit of work; `immediate` takes the
    write lock up front (BEGIN IMMEDIATE), which serializes check-then-write
    sequences across both processes."""
    p = path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    conn = sqlite3.connect(p, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        with _init_lock:
            if p not in _initialized:
                for attempt in range(50):
                    try:
                        conn.execute("PRAGMA journal_mode=WAL")
                        conn.executescript(SCHEMA)
                        cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
                        if "turn_gk_attempts" not in cols:
                            conn.execute("ALTER TABLE sessions ADD COLUMN turn_gk_attempts "
                                         "INTEGER NOT NULL DEFAULT 0")
                        break
                    except sqlite3.OperationalError:
                        if attempt == 49:
                            raise
                        time.sleep(0.2)
                _initialized.add(p)
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
    finally:
        conn.close()


def row(conn: sqlite3.Connection, sql: str, *args: Any) -> dict[str, Any] | None:
    r = conn.execute(sql, args).fetchone()
    return dict(r) if r is not None else None


def enqueue(conn: sqlite3.Connection, event_id: str, payload: dict[str, Any]) -> None:
    """At-least-once delivery: the event is durable before anything is sent."""
    now = time.time()
    conn.execute(
        "INSERT OR IGNORE INTO outbox (event_id, payload, created_at, next_at) VALUES (?, ?, ?, ?)",
        (event_id, json.dumps({**payload, "event_id": event_id}), now, now),
    )
