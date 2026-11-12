"""Detection persistence (same SQLite database as the events, so evidence links stay local).

    det_signals     one row per rule/chain/behaviour match (idempotent id: rule + revision + evidence events)
    det_detections  signals grouped per entity and time bucket (aggregator.py) with score, severity, decision
    det_event_index event key -> detection, so a later rule match on the same event joins the same detection
    det_meta        processing checkpoint and counters

Raw Windows events stay in ``events``; detections only reference them (event keys) and keep a
compact field snapshot so a detection stays explainable after the event ages out of retention.
"""
from __future__ import annotations

from ... import db

SCHEMA = """
CREATE TABLE IF NOT EXISTS det_signals (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_rev TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    first_time TEXT NOT NULL,
    last_time TEXT NOT NULL,
    detection_id TEXT,
    entity_key TEXT,
    score REAL NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    decision TEXT NOT NULL,
    suppression_id TEXT,
    event_keys TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    details_json TEXT NOT NULL,
    origin TEXT NOT NULL,
    created_at TEXT NOT NULL,
    correlation_key TEXT,
    occurrences INTEGER NOT NULL DEFAULT 1,
    episode_bucket INTEGER,
    expires_at TEXT
);
-- v5.1: covering index, so the Rules page's per-rule counts never read the wide signal rows
-- (8.5 s cold at 540,000 signals before, and it replaces idx_det_signals_rule).
CREATE INDEX IF NOT EXISTS idx_det_signals_rule_cover ON det_signals(rule_id, last_time, first_time, decision, origin);
DROP INDEX IF EXISTS idx_det_signals_rule;
CREATE INDEX IF NOT EXISTS idx_det_signals_detection ON det_signals(detection_id);
CREATE INDEX IF NOT EXISTS idx_det_signals_decision ON det_signals(decision, last_time);
CREATE TABLE IF NOT EXISTS det_detections (
    id TEXT PRIMARY KEY,
    entity_key TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    hostname TEXT,
    det_time TEXT NOT NULL,
    last_time TEXT NOT NULL,
    title TEXT NOT NULL,
    primary_rule_id TEXT NOT NULL,
    rule_ids TEXT NOT NULL,
    signal_rules TEXT NOT NULL DEFAULT '[]',
    event_ids TEXT NOT NULL,
    channels TEXT NOT NULL,
    category TEXT,
    mitre TEXT NOT NULL,
    score REAL NOT NULL,
    severity TEXT NOT NULL,
    severity_rank INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    active INTEGER NOT NULL,
    decision TEXT NOT NULL,
    signal_count INTEGER NOT NULL,
    event_count INTEGER NOT NULL,
    user_name TEXT,
    process_name TEXT,
    summary TEXT,
    explanation TEXT,
    sources TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    verdict TEXT,
    status_updated_at TEXT,
    suppression_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    correlation_key TEXT,
    episode_bucket INTEGER,
    base_score REAL,
    escalation_json TEXT NOT NULL DEFAULT '{}',
    occurrence_count INTEGER NOT NULL DEFAULT 0,
    source_mix TEXT NOT NULL DEFAULT '[]',
    assigned_to TEXT
);
CREATE INDEX IF NOT EXISTS idx_det_active_time ON det_detections(active, det_time);
CREATE INDEX IF NOT EXISTS idx_det_active_sev ON det_detections(active, severity_rank, det_time);
CREATE INDEX IF NOT EXISTS idx_det_time ON det_detections(det_time, id);
CREATE INDEX IF NOT EXISTS idx_det_rule ON det_detections(primary_rule_id, det_time);
CREATE INDEX IF NOT EXISTS idx_det_updated ON det_detections(updated_at);
CREATE INDEX IF NOT EXISTS idx_det_decision_time ON det_detections(decision, det_time, severity_rank);
CREATE TABLE IF NOT EXISTS det_event_index (
    event_key TEXT NOT NULL,
    detection_id TEXT NOT NULL,
    PRIMARY KEY (event_key, detection_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS det_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


# ---------------------------------------------------------------------------- v6 migration
# Columns added by the v6 correlation engine.  Existing rows keep their data; the new
# columns are filled by `backfill_v6` so historical detections stay queryable and keep
# their original, already computed score (nothing is recomputed or deleted).
V6_SIGNAL_COLUMNS = (("correlation_key", "TEXT"), ("occurrences", "INTEGER NOT NULL DEFAULT 1"),
                     ("episode_bucket", "INTEGER"), ("expires_at", "TEXT"))
V6_DETECTION_COLUMNS = (("correlation_key", "TEXT"), ("episode_bucket", "INTEGER"), ("base_score", "REAL"),
                        ("escalation_json", "TEXT NOT NULL DEFAULT '{}'"),
                        ("occurrence_count", "INTEGER NOT NULL DEFAULT 0"),
                        ("source_mix", "TEXT NOT NULL DEFAULT '[]'"), ("assigned_to", "TEXT"))


def _columns(connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def migrate(connection) -> list[str]:
    """Add the v6 columns to an existing store.  Idempotent; never drops or rewrites rows."""
    added = []
    for table, columns in (("det_signals", V6_SIGNAL_COLUMNS), ("det_detections", V6_DETECTION_COLUMNS)):
        existing = _columns(connection, table)
        for name, kind in columns:
            if name not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {kind}")
                added.append(f"{table}.{name}")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_det_corr ON det_detections(correlation_key, det_time)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_det_escalation ON det_detections(occurrence_count, det_time)")
    if added:
        # Mark the migrated rows so the service knows the replay must rebuild episode state.
        meta_set(connection, "engine_version", "6")
        meta_set(connection, "migrated_at", __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat())
    return added


def backfill_v6(connection) -> int:
    """Give pre-v6 detections their episode columns, so pages and filters treat them uniformly.

    The historical score is preserved as-is (it was computed by the v5 scorer and shown to
    analysts then); only the new descriptive columns are derived from data already stored.
    """
    changed = 0
    rows = connection.execute(
        "SELECT id, entity_key, bucket, score, signal_count FROM det_detections "
        "WHERE correlation_key IS NULL OR base_score IS NULL").fetchall()
    for row in rows:
        count = connection.execute("SELECT COUNT(*) FROM det_signals WHERE detection_id = ?",
                                   (row["id"],)).fetchone()[0]
        basis = connection.execute(
            "SELECT COUNT(DISTINCT rule_id), COUNT(*) FROM det_signals WHERE detection_id = ? "
            "AND decision NOT IN ('learn_only', 'shadow', 'retracted')", (row["id"],)).fetchone()
        connection.execute(
            "UPDATE det_detections SET correlation_key = COALESCE(correlation_key, entity_key), "
            "episode_bucket = COALESCE(episode_bucket, bucket), base_score = COALESCE(base_score, score), "
            "occurrence_count = ?, source_mix = ? WHERE id = ?",
            (basis[1] or count or 0,
             __import__("json").dumps(["legacy-v5"]), row["id"]))
        changed += 1
    return changed


def initialize(tables_only: bool = False) -> None:
    """Create the detection tables (and, unless tables_only, their indexes).

    The server creates the tables before it starts serving, so every page can query them at once;
    index creation on an existing store can take seconds and runs with the engine start-up instead.
    """
    with db.connect() as connection:
        if tables_only:
            statements = [s for s in SCHEMA.split(";") if s.strip().upper().startswith("CREATE TABLE")]
            connection.executescript(";\n".join(statements) + ";")
        else:
            connection.executescript(SCHEMA)
        # A store created by v5 (or earlier) is upgraded in place; its rows are kept.
        migrate(connection)


def meta_get(key: str, default: str | None = None) -> str | None:
    with db.connect() as connection:
        row = connection.execute("SELECT value FROM det_meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(connection, key: str, value: str) -> None:
    connection.execute("INSERT INTO det_meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                       (key, value))
