"""Small persistent store for analyst state: investigation statuses and rule configuration.

Kept in its own SQLite file (triage.db in the Griffendo data folder) so it
survives restarts even when events are kept in memory only.  Every write is a
transaction; a failed write raises, so the UI never shows a setting that was
not saved.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from .settings import iso, utc_now


class StateStore:
    def __init__(self, folder: Path | None):
        self.path: Path | None = None
        self.error: str | None = None
        self._lock = threading.RLock()
        target = ":memory:"
        if folder is not None:
            try:
                folder.mkdir(parents=True, exist_ok=True)
                target = str(folder / "triage.db")
                self.path = folder / "triage.db"
            except OSError as error:
                self.error = f"Cannot create {folder}: {error}. Statuses and rule settings are kept in memory only."
        try:
            self._connection = sqlite3.connect(target, check_same_thread=False, timeout=10)
        except sqlite3.Error as error:
            self.error = f"Cannot open {target}: {error}. Statuses and rule settings are kept in memory only."
            self.path = None
            self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS triage(
                    detection_id TEXT PRIMARY KEY, status TEXT NOT NULL, note TEXT,
                    updated_at TEXT NOT NULL, rule_id TEXT, event_id INTEGER, hostname TEXT
                );
                CREATE TABLE IF NOT EXISTS triage_history(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, detection_id TEXT NOT NULL,
                    old_status TEXT, new_status TEXT NOT NULL, note TEXT, changed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_triage_history ON triage_history(detection_id, id);
                CREATE TABLE IF NOT EXISTS rule_overrides(
                    rule_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, modified_at TEXT NOT NULL, enabled_at TEXT
                );
                CREATE TABLE IF NOT EXISTS custom_rules(
                    rule_id TEXT PRIMARY KEY, definition_json TEXT NOT NULL, enabled INTEGER NOT NULL,
                    created_at TEXT NOT NULL, modified_at TEXT NOT NULL, enabled_at TEXT, deleted_at TEXT
                );
                CREATE TABLE IF NOT EXISTS verdicts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, detection_id TEXT NOT NULL, verdict TEXT NOT NULL,
                    note TEXT, at TEXT NOT NULL, applied_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_verdicts ON verdicts(detection_id, id);
                CREATE TABLE IF NOT EXISTS suppressions(
                    id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, fingerprint TEXT NOT NULL, fields_json TEXT NOT NULL,
                    reason TEXT NOT NULL, detection_id TEXT, created_at TEXT NOT NULL, revoked_at TEXT,
                    matches INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_suppressions ON suppressions(rule_id, fingerprint);
                CREATE TABLE IF NOT EXISTS rule_changes(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, change TEXT NOT NULL,
                    detail TEXT, at TEXT NOT NULL
                );
                """
            )

    @property
    def persistent(self) -> bool:
        return self.path is not None

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    # ------------------------------------------------------------------ triage
    def get_many(self, ids: Iterable[str]) -> dict[str, sqlite3.Row]:
        ids = list(ids)
        result: dict[str, sqlite3.Row] = {}
        with self._lock:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                marks = ",".join("?" for _ in chunk)
                for row in self._connection.execute(f"SELECT * FROM triage WHERE detection_id IN ({marks})", chunk):
                    result[row["detection_id"]] = row
        return result

    def history(self, detection_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT old_status, new_status, note, changed_at FROM triage_history WHERE detection_id = ? ORDER BY id",
                (detection_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def set(self, detection_id: str, status: str, note: str | None, rule_id: str, event_id: int, hostname: str) -> str:
        now = iso(utc_now())
        with self._lock, self._connection:
            previous = self._connection.execute(
                "SELECT status FROM triage WHERE detection_id = ?", (detection_id,)
            ).fetchone()
            self._connection.execute(
                """INSERT INTO triage(detection_id, status, note, updated_at, rule_id, event_id, hostname)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(detection_id) DO UPDATE SET status=excluded.status, note=excluded.note,
                       updated_at=excluded.updated_at""",
                (detection_id, status, note, now, rule_id, event_id, hostname),
            )
            self._connection.execute(
                "INSERT INTO triage_history(detection_id, old_status, new_status, note, changed_at) VALUES (?, ?, ?, ?, ?)",
                (detection_id, previous["status"] if previous else "New", status, note, now),
            )
        return now

    # ------------------------------------------------------------------ rules
    def overrides(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {row["rule_id"]: dict(row) for row in self._connection.execute("SELECT * FROM rule_overrides")}

    def custom_rules(self, include_deleted: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM custom_rules" + ("" if include_deleted else " WHERE deleted_at IS NULL") + " ORDER BY created_at"
        with self._lock:
            rows = self._connection.execute(sql).fetchall()
        result = []
        for row in rows:
            definition = json.loads(row["definition_json"])
            definition.update(rule_id=row["rule_id"], enabled=bool(row["enabled"]), created_at=row["created_at"],
                              modified_at=row["modified_at"], enabled_at=row["enabled_at"], deleted_at=row["deleted_at"])
            result.append(definition)
        return result

    def custom_rule(self, rule_id: str, include_deleted: bool = True) -> dict[str, Any] | None:
        for rule in self.custom_rules(include_deleted=include_deleted):
            if rule["rule_id"] == rule_id:
                return rule
        return None

    def _log(self, rule_id: str, change: str, detail: str | None, at: str) -> None:
        self._connection.execute("INSERT INTO rule_changes(rule_id, change, detail, at) VALUES (?, ?, ?, ?)",
                                 (rule_id, change, detail, at))

    def set_builtin_enabled(self, rule_id: str, enabled: bool) -> str:
        now = iso(utc_now())
        with self._lock, self._connection:
            previous = self._connection.execute("SELECT enabled_at FROM rule_overrides WHERE rule_id = ?", (rule_id,)).fetchone()
            enabled_at = now if enabled else (previous["enabled_at"] if previous else None)
            self._connection.execute(
                """INSERT INTO rule_overrides(rule_id, enabled, modified_at, enabled_at) VALUES (?, ?, ?, ?)
                   ON CONFLICT(rule_id) DO UPDATE SET enabled=excluded.enabled, modified_at=excluded.modified_at,
                       enabled_at=excluded.enabled_at""",
                (rule_id, int(enabled), now, enabled_at),
            )
            self._log(rule_id, "enabled" if enabled else "disabled", None, now)
        return now

    def create_custom(self, rule_id: str, definition: dict[str, Any], enabled: bool) -> str:
        now = iso(utc_now())
        with self._lock, self._connection:
            if self._connection.execute("SELECT 1 FROM custom_rules WHERE rule_id = ?", (rule_id,)).fetchone():
                raise KeyError(rule_id)
            self._connection.execute(
                "INSERT INTO custom_rules(rule_id, definition_json, enabled, created_at, modified_at, enabled_at) VALUES (?, ?, ?, ?, ?, ?)",
                (rule_id, json.dumps(definition, separators=(",", ":")), int(enabled), now, now, now if enabled else None),
            )
            self._log(rule_id, "created", json.dumps({"enabled": enabled}), now)
        return now

    def update_custom(self, rule_id: str, definition: dict[str, Any]) -> str:
        now = iso(utc_now())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE custom_rules SET definition_json = ?, modified_at = ? WHERE rule_id = ? AND deleted_at IS NULL",
                (json.dumps(definition, separators=(",", ":")), now, rule_id),
            )
            if not cursor.rowcount:
                raise KeyError(rule_id)
            self._log(rule_id, "edited", None, now)
        return now

    def set_custom_enabled(self, rule_id: str, enabled: bool) -> str:
        now = iso(utc_now())
        with self._lock, self._connection:
            if enabled:
                cursor = self._connection.execute(
                    "UPDATE custom_rules SET enabled = 1, modified_at = ?, enabled_at = ? WHERE rule_id = ? AND deleted_at IS NULL",
                    (now, now, rule_id))
            else:
                cursor = self._connection.execute(
                    "UPDATE custom_rules SET enabled = 0, modified_at = ? WHERE rule_id = ? AND deleted_at IS NULL",
                    (now, rule_id))
            if not cursor.rowcount:
                raise KeyError(rule_id)
            self._log(rule_id, "enabled" if enabled else "disabled", None, now)
        return now

    def delete_custom(self, rule_id: str) -> str:
        """Soft delete: the definition stays so historical detections keep their rule metadata."""
        now = iso(utc_now())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE custom_rules SET deleted_at = ?, enabled = 0, modified_at = ? WHERE rule_id = ? AND deleted_at IS NULL",
                (now, now, rule_id))
            if not cursor.rowcount:
                raise KeyError(rule_id)
            self._log(rule_id, "deleted", None, now)
        return now

    def rule_changes(self, rule_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT change, detail, at FROM rule_changes WHERE rule_id = ? ORDER BY id", (rule_id,)).fetchall()
        return [dict(row) for row in rows]


    # ------------------------------------------------------------------ v5: verdicts and suppressions
    def add_verdict(self, detection_id: str, verdict: str, note: str | None, applied: dict[str, Any] | None) -> str:
        now = iso(utc_now())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO verdicts(detection_id, verdict, note, at, applied_json) VALUES (?, ?, ?, ?, ?)",
                (detection_id, verdict, note, now, json.dumps(applied or {}, default=str)))
        return now

    def verdicts(self, detection_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT verdict, note, at, applied_json FROM verdicts WHERE detection_id = ? ORDER BY id",
                (detection_id,)).fetchall()
        return [{"verdict": r["verdict"], "note": r["note"], "at": r["at"],
                 "applied": json.loads(r["applied_json"] or "{}")} for r in rows]

    def latest_verdicts(self, ids: Iterable[str]) -> dict[str, str]:
        ids = list(ids)
        result: dict[str, str] = {}
        with self._lock:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                marks = ",".join("?" for _ in chunk)
                for row in self._connection.execute(
                        f"SELECT detection_id, verdict FROM verdicts WHERE id IN (SELECT MAX(id) FROM verdicts "
                        f"WHERE detection_id IN ({marks}) GROUP BY detection_id)", chunk):
                    result[row["detection_id"]] = row["verdict"]
        return result

    def add_suppression(self, suppression_id: str, rule_id: str, fingerprint: str, fields: dict[str, Any],
                        reason: str, detection_id: str | None) -> str:
        now = iso(utc_now())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT OR IGNORE INTO suppressions(id, rule_id, fingerprint, fields_json, reason, detection_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (suppression_id, rule_id, fingerprint, json.dumps(fields, default=str), reason, detection_id, now))
            self._log(rule_id, "suppression-added", json.dumps({"id": suppression_id, "reason": reason}), now)
        return now

    def revoke_suppression(self, suppression_id: str) -> bool:
        now = iso(utc_now())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE suppressions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (now, suppression_id))
            return bool(cursor.rowcount)

    def suppressions(self, include_revoked: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM suppressions" + ("" if include_revoked else " WHERE revoked_at IS NULL") + \
              " ORDER BY created_at DESC"
        with self._lock:
            rows = self._connection.execute(sql).fetchall()
        return [{**dict(r), "fields": json.loads(r["fields_json"])} for r in rows]

    def count_suppression_matches(self, counts: dict[str, int]) -> None:
        if not counts:
            return
        with self._lock, self._connection:
            self._connection.executemany("UPDATE suppressions SET matches = matches + ? WHERE id = ?",
                                         [(n, key) for key, n in counts.items()])


TriageStore = StateStore   # v2 name, kept for compatibility
