"""Event storage for the receiver.

Originally a bounded, volatile in-memory store that was rebuilt from the full
Windows logs at every launch.  It is now, by default, a SQLite file in the
Griffendo data folder (WAL mode), so collection can resume after a restart
instead of re-reading everything, and the 7-day timeline, detections and
counts survive restarts.  GRIFFENDO_STORAGE=memory restores the old
behaviour.

Rows are pruned by event time (GRIFFENDO_RETENTION_DAYS, default 14) and
capped at LOGPLATFORM_MAX_MEMORY_EVENTS rows, oldest inserted first.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .parser import parse_event
from . import settings

MAX_IN_MEMORY_EVENTS = max(1, int(os.getenv("LOGPLATFORM_MAX_MEMORY_EVENTS", "2000000")))
_DATABASE_URI = "file:griffendo_receiver?mode=memory&cache=shared"
_DATABASE_LOCK = threading.RLock()
_KEEPER: sqlite3.Connection | None = None
_DISK_PATH: Path | None = None
_LAST_PRUNE = 0.0
DIAGNOSTICS_KEPT = 500


def database_path() -> Path | None:
    """The on-disk database file, or None in memory mode."""
    return _DISK_PATH


def _open() -> sqlite3.Connection:
    if _DISK_PATH is not None:
        connection = sqlite3.connect(str(_DISK_PATH), timeout=30, check_same_thread=False)
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA cache_size=-65536")
    else:
        connection = sqlite3.connect(_DATABASE_URI, uri=True, timeout=10, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def _configure() -> None:
    """Choose memory or disk once, on first use (called with the lock held)."""
    global _KEEPER, _DISK_PATH
    if _KEEPER is not None:
        return
    _DISK_PATH = None
    if settings.storage_mode() == "disk":
        folder = settings.state_dir()
        try:
            folder.mkdir(parents=True, exist_ok=True)
            _DISK_PATH = folder / "griffendo.db"
        except OSError:
            _DISK_PATH = None   # fall back to memory; summary() reports the storage mode
    _KEEPER = _open()
    if _DISK_PATH is not None:
        _KEEPER.execute("PRAGMA journal_mode=WAL")


@contextmanager
def connect():
    # One keeper connection holds the database open (required for the shared
    # in-memory database; harmless for the file).  All access is serialised by
    # the lock, as in the original design.
    with _DATABASE_LOCK:
        _configure()
        connection = _open()
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


@contextmanager
def read():
    """Read-only access that does not wait for the shared lock (v5.1).

    The disk store runs in WAL mode, where readers never block the writer or each other, so the
    dashboard's queries no longer queue behind a long write or the detection engine's reads (in
    v5.0 one slow read could hold every page for seconds).  The in-memory store has no WAL and keeps
    using the lock.  Nothing may be written through this connection (query_only is set).
    """
    with _DATABASE_LOCK:
        _configure()
        path = _DISK_PATH
    if path is None:
        with connect() as connection:
            yield connection
        return
    connection = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA cache_size=-16384")
        connection.row_factory = sqlite3.Row
        yield connection
    finally:
        connection.close()


def reset_memory() -> None:
    """Close the store (data on disk is kept); used during shutdown and isolated tests."""
    global _KEEPER, _DISK_PATH
    with _DATABASE_LOCK:
        if _KEEPER is not None:
            _KEEPER.close()
            _KEEPER = None
        _DISK_PATH = None


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def initialize() -> None:
    with connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                channel TEXT NOT NULL,
                record_id INTEGER,
                raw_xml TEXT NOT NULL,
                normalized_json TEXT NOT NULL,
                timestamp TEXT,
                provider TEXT,
                event_id INTEGER,
                severity TEXT,
                username TEXT,
                process_name TEXT,
                process_path TEXT,
                pid INTEGER,
                parent_process_name TEXT,
                parent_pid INTEGER,
                command_line TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_host_time ON events(hostname, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_process ON events(process_name);
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                os_name TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS ingest_diagnostics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                agent_id TEXT,
                hostname TEXT,
                channel TEXT,
                record_id INTEGER,
                problem TEXT NOT NULL,
                sample TEXT
            );
            """
        )
        # Columns added in v3.  ALTER keeps databases created by older builds usable.
        existing = _columns(connection, "events")
        for column, kind in (("event_time", "TEXT"), ("collected_at", "TEXT"), ("phase", "TEXT")):
            if column not in existing:
                connection.execute(f"ALTER TABLE events ADD COLUMN {column} {kind}")
        # A new id whenever the store is new (first run, deleted file, memory mode): collectors use it
        # to tell that they must re-send history instead of resuming from their saved cursors.
        connection.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('store_id', ?)", (uuid.uuid4().hex,))
        connection.executescript(
            """
            UPDATE events SET event_time = received_at WHERE event_time IS NULL;
            CREATE INDEX IF NOT EXISTS idx_events_event_time ON events(event_time, id);
            CREATE INDEX IF NOT EXISTS idx_events_channel_time ON events(channel, event_time);
            CREATE INDEX IF NOT EXISTS idx_events_eid_channel ON events(event_id, channel);
            DROP INDEX IF EXISTS idx_events_id;   -- covered by idx_events_eid_channel; one less index per insert
            """
        )
        _aggregates(connection)


# v5: small aggregate tables kept exact by triggers (inserts, retention pruning and the row cap all go
# through them), so the Overview and Endpoint pages read a few hundred rows instead of scanning every
# stored event (measured: 4.8 s and 5.4 s at 1M events in v4).
AGGREGATE_SQL = """
CREATE TABLE IF NOT EXISTS agg_host (agent_id TEXT NOT NULL, hostname TEXT NOT NULL, n INTEGER NOT NULL,
    PRIMARY KEY (agent_id, hostname)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_event_id (channel TEXT NOT NULL, event_id INTEGER NOT NULL, n INTEGER NOT NULL,
    PRIMARY KEY (channel, event_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_process (process_name TEXT NOT NULL PRIMARY KEY, n INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_channel_hour (channel TEXT NOT NULL, hour TEXT NOT NULL, n INTEGER NOT NULL,
    PRIMARY KEY (channel, hour)) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS trg_events_agg_insert AFTER INSERT ON events BEGIN
    INSERT INTO agg_host(agent_id, hostname, n) VALUES (NEW.agent_id, NEW.hostname, 1)
        ON CONFLICT(agent_id, hostname) DO UPDATE SET n = n + 1;
    INSERT INTO agg_event_id(channel, event_id, n) SELECT NEW.channel, NEW.event_id, 1 WHERE NEW.event_id IS NOT NULL
        ON CONFLICT(channel, event_id) DO UPDATE SET n = n + 1;
    INSERT INTO agg_process(process_name, n) SELECT NEW.process_name, 1 WHERE NEW.process_name IS NOT NULL
        ON CONFLICT(process_name) DO UPDATE SET n = n + 1;
    INSERT INTO agg_channel_hour(channel, hour, n) VALUES (NEW.channel, substr(NEW.event_time, 1, 13), 1)
        ON CONFLICT(channel, hour) DO UPDATE SET n = n + 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_events_agg_delete AFTER DELETE ON events BEGIN
    UPDATE agg_host SET n = n - 1 WHERE agent_id = OLD.agent_id AND hostname = OLD.hostname;
    UPDATE agg_event_id SET n = n - 1 WHERE channel = OLD.channel AND event_id = OLD.event_id;
    UPDATE agg_process SET n = n - 1 WHERE process_name = OLD.process_name;
    UPDATE agg_channel_hour SET n = n - 1 WHERE channel = OLD.channel AND hour = substr(OLD.event_time, 1, 13);
END;
CREATE INDEX IF NOT EXISTS idx_events_host_etime ON events(hostname, event_time);
"""


def _aggregates(connection: sqlite3.Connection) -> None:
    built = connection.execute("SELECT value FROM meta WHERE key = 'aggregates_v5'").fetchone()
    connection.executescript(AGGREGATE_SQL)
    if not built:
        # Existing store (created by v4 or older): build the aggregates once from the stored events.
        connection.executescript(
            """
            DELETE FROM agg_host; DELETE FROM agg_event_id; DELETE FROM agg_process; DELETE FROM agg_channel_hour;
            INSERT INTO agg_host SELECT agent_id, hostname, COUNT(*) FROM events GROUP BY agent_id, hostname;
            INSERT INTO agg_event_id SELECT channel, event_id, COUNT(*) FROM events WHERE event_id IS NOT NULL
                GROUP BY channel, event_id;
            INSERT INTO agg_process SELECT process_name, COUNT(*) FROM events WHERE process_name IS NOT NULL
                GROUP BY process_name;
            INSERT INTO agg_channel_hour SELECT channel, substr(event_time, 1, 13), COUNT(*) FROM events
                GROUP BY channel, substr(event_time, 1, 13);
            INSERT OR REPLACE INTO meta(key, value) VALUES ('aggregates_v5', '1');
            """
        )


def _diagnostic(connection, agent_id, hostname, event, problem) -> None:
    connection.execute(
        "INSERT INTO ingest_diagnostics(at, agent_id, hostname, channel, record_id, problem, sample) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (settings.iso(settings.utc_now()), agent_id, hostname, event.get("channel"), event.get("record_id"), problem,
         None),   # never store event content in diagnostics
    )


def store_batch(agent_id: str, hostname: str, os_name: str, events: list[dict[str, Any]]) -> int:
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    rows = []
    problems = []
    for event in events:
        normalized = parse_event(event["xml"])
        event_time = settings.normalize_time(normalized.get("timestamp"))
        if normalized.get("parse_error"):
            problems.append((event, normalized["parse_error"]))
        elif normalized.get("event_id") is None:
            problems.append((event, "No numeric EventID in the event XML"))
        if event_time is None and not normalized.get("parse_error"):
            problems.append((event, "Missing or unreadable TimeCreated; receive time used for ordering"))
        rows.append((
            event["id"], now, agent_id, hostname, event["channel"], event.get("record_id"), event["xml"],
            json.dumps(normalized, separators=(",", ":")), normalized.get("timestamp"), normalized.get("provider"),
            normalized.get("event_id"), normalized.get("level"), normalized.get("user"), normalized.get("process_name"),
            normalized.get("process_path"), normalized.get("pid"), normalized.get("parent_process_name"),
            normalized.get("parent_pid"), normalized.get("command_line"),
            event_time or settings.iso(now_dt), event.get("collected_at"), event.get("phase"),
        ))
    with connect() as connection:
        connection.execute(
            """INSERT INTO agents(agent_id, hostname, os_name, last_seen)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET
                   hostname=excluded.hostname, os_name=excluded.os_name, last_seen=excluded.last_seen""",
            (agent_id, hostname, os_name, now),
        )
        cursor = connection.executemany(
            """INSERT OR IGNORE INTO events(
                id, received_at, agent_id, hostname, channel, record_id, raw_xml,
                normalized_json, timestamp, provider, event_id, severity, username,
                process_name, process_path, pid, parent_process_name, parent_pid, command_line,
                event_time, collected_at, phase
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        # cursor.rowcount = rows this statement inserted (sqlite3_changes excludes the aggregate triggers' writes).
        inserted = max(cursor.rowcount, 0)
        for event, problem in problems:
            _diagnostic(connection, agent_id, hostname, event, problem)
        if problems:
            connection.execute(
                "DELETE FROM ingest_diagnostics WHERE id <= (SELECT MAX(id) FROM ingest_diagnostics) - ?",
                (DIAGNOSTICS_KEPT,))
        _prune(connection)
    return inserted


def _prune(connection: sqlite3.Connection, force: bool = False) -> None:
    """Retention by event time (at most once a minute) and the row cap (every batch)."""
    global _LAST_PRUNE
    if not force and time.monotonic() - _LAST_PRUNE < 30:
        return
    _LAST_PRUNE = time.monotonic()
    days = settings.retention_days()
    if days:
        cutoff = settings.iso(datetime.now(timezone.utc) - timedelta(days=days))
        connection.execute("DELETE FROM events WHERE event_time < ?", (cutoff,))
        connection.execute("DELETE FROM agg_channel_hour WHERE n <= 0")
    overflow = connection.execute("SELECT COUNT(*) - ? FROM events", (MAX_IN_MEMORY_EVENTS,)).fetchone()[0]
    if overflow > 0:
        connection.execute(
            "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY rowid LIMIT ?)",
            (overflow,),
        )


def store_id() -> str:
    with connect() as connection:
        row = connection.execute("SELECT value FROM meta WHERE key = 'store_id'").fetchone()
    return row[0] if row else ""


def diagnostics(limit: int = 50) -> dict[str, Any]:
    with connect() as connection:
        total = connection.execute("SELECT COUNT(*) FROM ingest_diagnostics").fetchone()[0]
        rows = connection.execute(
            "SELECT at, hostname, channel, record_id, problem FROM ingest_diagnostics ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return {"recent_total": total, "items": [dict(row) for row in rows]}


def row_to_event(row: sqlite3.Row, include_raw: bool = False) -> dict[str, Any]:
    event = {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "received_at": row["received_at"],
        "hostname": row["hostname"],
        "channel": row["channel"],
        "provider": row["provider"],
        "event_id": row["event_id"],
        "severity": row["severity"],
        "username": row["username"],
        "process_name": row["process_name"],
        "process_path": row["process_path"],
        "pid": row["pid"],
        "parent_process_name": row["parent_process_name"],
        "parent_pid": row["parent_pid"],
        "command_line": row["command_line"],
        "fields": json.loads(row["normalized_json"]).get("fields", {}),
    }
    keys = row.keys()
    for extra in ("record_id", "event_time", "collected_at"):
        if extra in keys:
            event[extra] = row[extra]
    if include_raw:
        event["raw_xml"] = row["raw_xml"]
    return event
