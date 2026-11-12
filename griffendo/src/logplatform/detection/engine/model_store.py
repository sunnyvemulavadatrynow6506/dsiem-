"""Model store: the host's learned baseline, first-seen terms and analyst-driven model changes.

Kept in ``model.db`` in Griffendo's data folder (in memory when GRIFFENDO_STORAGE=memory),
separate from the event database so that resetting the baseline never touches
detections, and resetting the event store never loses what the model learned.

Tables
  kv(key, value_json, updated_at)            behaviour-model state (one JSON document), config overrides
  terms(rule_id, term, first_time, last_time, signal_id)   first-seen values for new-terms / if_fts rules
  audit(id, at, action, detail_json)         every learned change made from analyst feedback, resets, promotions
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable

from ...settings import iso, utc_now


class ModelStore:
    def __init__(self, folder: Path | None):
        target = ":memory:"
        self.path = None
        if folder is not None:
            try:
                folder.mkdir(parents=True, exist_ok=True)
                self.path = folder / "model.db"
                target = str(self.path)
            except OSError:
                self.path = None
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(target, check_same_thread=False, timeout=10)
        self.connection.row_factory = sqlite3.Row
        with self.connection:
            self.connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS terms(rule_id TEXT NOT NULL, term TEXT NOT NULL, first_time REAL NOT NULL,
                    last_time REAL NOT NULL, signal_id TEXT, PRIMARY KEY(rule_id, term));
                CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
                    action TEXT NOT NULL, detail_json TEXT);
                """
            )

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def get(self, key: str) -> Any:
        with self.lock:
            row = self.connection.execute("SELECT value_json FROM kv WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, value: Any) -> None:
        with self.lock, self.connection:
            self.connection.execute(
                "INSERT INTO kv(key, value_json, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                (key, json.dumps(value, separators=(",", ":")), iso(utc_now())))

    def delete(self, key: str) -> None:
        with self.lock, self.connection:
            self.connection.execute("DELETE FROM kv WHERE key = ?", (key,))

    def audit(self, action: str, detail: dict[str, Any]) -> None:
        with self.lock, self.connection:
            self.connection.execute("INSERT INTO audit(at, action, detail_json) VALUES (?, ?, ?)",
                                    (iso(utc_now()), action, json.dumps(detail, separators=(",", ":"), default=str)))
            self.connection.execute("DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - 5000")

    def audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute("SELECT at, action, detail_json FROM audit ORDER BY id DESC LIMIT ?",
                                           (limit,)).fetchall()
        return [{"at": row["at"], "action": row["action"], "detail": json.loads(row["detail_json"] or "{}")}
                for row in rows]


class TermStore:
    """First-seen bookkeeping for new-terms rules (time-order independent)."""

    def __init__(self, store: ModelStore, coverage: Callable[[float], bool] | None = None):
        self.store = store
        self.coverage = coverage or (lambda since: True)
        self.cache: dict[tuple[str, str], list[Any]] = {}
        self.dirty: set[tuple[str, str]] = set()

    def _row(self, rule_id: str, term: str) -> list[Any] | None:
        key = (rule_id, term)
        if key in self.cache:
            return self.cache[key]
        with self.store.lock:
            row = self.store.connection.execute(
                "SELECT first_time, last_time, signal_id FROM terms WHERE rule_id = ? AND term = ?", key).fetchone()
        value = [row[0], row[1], row[2]] if row else None
        if value is not None:
            self.cache[key] = value
            if len(self.cache) > 200000:
                self.cache.clear()
        return value

    def check(self, rule_id: str, term: str, t: float, history: float) -> dict[str, Any]:
        row = self._row(rule_id, term)
        key = (rule_id, term)
        covered = self.coverage(t - history)
        if row is None:
            self.cache[key] = [t, t, None]
            self.dirty.add(key)
            return {"new": True, "covered": covered}
        first, last, signal = row
        if t < first:
            row[0] = t
            self.dirty.add(key)
            if first - t <= history:
                # An earlier occurrence arrived late: the later "first sighting" was not new after all.
                return {"new": True, "covered": covered, "retract": signal}
            return {"new": True, "covered": covered}
        if t > last:
            row[1] = t
            self.dirty.add(key)
            if t - last > history:
                return {"new": True, "covered": covered}
        return {"new": False, "covered": covered}

    def remember_signal(self, rule_id: str, term: str, signal_id: str) -> None:
        key = (rule_id, term)
        row = self.cache.get(key) or self._row(rule_id, term)
        if row is not None:
            row[2] = signal_id
            self.dirty.add(key)

    def flush(self) -> None:
        if not self.dirty:
            return
        rows = [(rule_id, term, *self.cache[(rule_id, term)]) for rule_id, term in self.dirty
                if (rule_id, term) in self.cache]
        with self.store.lock, self.store.connection:
            self.store.connection.executemany(
                "INSERT INTO terms(rule_id, term, first_time, last_time, signal_id) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(rule_id, term) DO UPDATE SET first_time = excluded.first_time, "
                "last_time = excluded.last_time, signal_id = excluded.signal_id", rows)
        self.dirty.clear()

    def forget_rule(self, rule_id: str) -> None:
        with self.store.lock, self.store.connection:
            self.store.connection.execute("DELETE FROM terms WHERE rule_id = ?", (rule_id,))
        self.cache = {k: v for k, v in self.cache.items() if k[0] != rule_id}
        self.dirty = {k for k in self.dirty if k[0] != rule_id}
