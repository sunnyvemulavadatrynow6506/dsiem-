"""Event-ID anomaly detection for collected Windows events.

Detection contract (unchanged since v2)
---------------------------------------
An event is an anomaly for a rule when (a) the rule is enabled, (b) the event's
channel and numeric Event ID match the rule (and its provider, only when the
rule asks for an exact provider match) and (c) the event time falls inside the
rolling analysis window.  Nothing else is evaluated: no thresholds, no
correlation, no field values.  Event fields are copied only for the analyst.

Overlap policy (v3)
-------------------
Several enabled rules may target the same channel + Event ID (for example a
built-in rule and a user's custom rule with a different severity).  None is
discarded: each enabled matching rule records its own detection for the event,
keyed by (event, rule).  "Detections" therefore counts event x rule records and
"event occurrences" counts distinct events; both are shown.  The rule editor
warns about overlaps and requires explicit confirmation to create one.

Rules come from the bundled catalog (verified, built-in) plus user-defined
rules stored in the state database.  Built-in rules can be switched on/off but
not edited or deleted; custom rules can be created, edited, toggled and
(soft-)deleted.

Active vs. stored detections (v4)
---------------------------------
Rule configuration, raw events and detection records are separate data.
Detection records are never deleted when a rule changes.  "Active" views
(the anomaly list, counts, severity cards, dashboard widgets and the timeline)
show only detections whose rule is currently enabled AND whose stored
channel / Event ID (and provider, for exact-provider rules) still match the
rule's current definition; they all use the same join (_active_cte /
ACTIVE_JOIN).  The History view shows every stored detection with the rule's
current state.  Switching a rule on (or creating / editing an enabled custom
rule) runs a targeted re-evaluation of the last N days for that rule only:
stored detections become visible again and events that were never checked
for the rule (for example while it was off) are evaluated, without
duplicates (detections are keyed by event + rule).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from . import db, settings
from .settings import iso, parse_time, utc_now, state_dir  # noqa: F401  (re-exported for callers/tests)
from .state import StateStore, TriageStore  # noqa: F401

STATUSES = ("New", "Investigating", "Resolved", "False Positive")
DEFAULT_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Optional"]
CUSTOM_SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
BASE_CHANNELS = ("System", "Security", "Setup", "Application")
FUTURE_TOLERANCE = timedelta(minutes=5)
CHANNEL_NAME = re.compile(r"^[A-Za-z0-9 ._()/\-]{1,255}$")
RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{2,63}$")
PROVIDER_NAME = re.compile(r"^[A-Za-z0-9 ._()/\-]{1,255}$")
FIELD_NAME = re.compile(r"^[A-Za-z0-9 _.\-]{1,80}$")
MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")
ADDRESS_FIELDS = ("IpAddress", "SourceAddress", "SourceIp", "ClientAddress", "ClientIPAddress", "Source Network Address")
_PLACEHOLDERS = {"", "-", "--", "n/a", "(null)", "null", "none", "unknown"}

_CATALOG_LOCK = threading.RLock()
_CATALOG: dict[str, Any] | None = None
_STATE: StateStore | None = None
_LAST_SCAN: dict[str, Any] = {}
_CACHE: dict[str, tuple[float, Any]] = {}


def _cached(key: str, producer, ttl: float | None = None):
    """Short-lived cache for whole-table aggregates so dashboard refreshes don't rescan the store each time."""
    ttl = settings.stats_cache_seconds() if ttl is None else ttl
    hit = _CACHE.get(key)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    value = producer()
    if len(_CACHE) > 64:
        _CACHE.clear()
    _CACHE[key] = (time.monotonic(), value)
    return value


_DATA_KEYED = ("rule-stats-", "channel-aggregates-", "summary-sql-")


def invalidate_cache(keep_data_keyed: bool = False) -> None:
    """Drop cached aggregates.  Entries keyed by data_version() stay valid when only collector health changed."""
    if not keep_data_keyed:
        _CACHE.clear()
        return
    for key in [key for key in _CACHE if not key.startswith(_DATA_KEYED)]:
        _CACHE.pop(key, None)


def data_version() -> str:
    """Changes whenever events or detections are added; cheap (rowid lookups)."""
    with db.read() as connection:
        events = connection.execute("SELECT MAX(rowid) FROM events").fetchone()[0] or 0
        detections = connection.execute("SELECT MAX(rowid) FROM anomalies").fetchone()[0] or 0
    return f"{events}.{detections}"


# --------------------------------------------------------------------------- state store
def state_store() -> StateStore:
    global _STATE
    with _CATALOG_LOCK:
        if _STATE is None:
            _STATE = StateStore(state_dir())
        return _STATE


triage_store = state_store   # v2 name


# --------------------------------------------------------------------------- catalog
def _bundle_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parents[2]


def catalog_candidates() -> list[tuple[str, Path]]:
    candidates = []
    if os.getenv("GRIFFENDO_CATALOG"):
        candidates.append(("GRIFFENDO_CATALOG", Path(os.environ["GRIFFENDO_CATALOG"])))
    folder = state_dir()
    if folder is not None:
        candidates.append(("user override", folder / "anomaly_catalog.json"))
    candidates.append(("bundled default", _bundle_dir() / "catalog" / "anomaly_catalog.json"))
    return candidates


def _validate_rule(raw: dict[str, Any], severities: list[str]) -> tuple[dict[str, Any] | None, str | None]:
    try:
        event_id = int(raw["event_id"])
        channel = str(raw["channel"]).strip()
        name = str(raw["name"]).strip()
        severity = str(raw["severity"]).strip()
    except (KeyError, TypeError, ValueError) as error:
        return None, f"rule {raw.get('rule_id', '?')}: missing or invalid field ({error})"
    if not 0 <= event_id <= 65535:
        return None, f"rule {raw.get('rule_id', event_id)}: Event ID out of range"
    if not CHANNEL_NAME.match(channel):
        return None, f"rule {raw.get('rule_id', event_id)}: unsupported channel name {channel!r}"
    if severity not in severities:
        return None, f"rule {raw.get('rule_id', event_id)}: unknown severity {severity!r}"
    if not name:
        return None, f"rule {raw.get('rule_id', event_id)}: empty name"
    rule = dict(raw)
    rule.update(
        event_id=event_id, channel=channel, name=name, severity=severity,
        rule_id=str(raw.get("rule_id") or f"{channel}-{event_id}"),
        category=str(raw.get("category") or "Uncategorized"),
        enabled=bool(raw.get("enabled", True)),
        details=[str(item) for item in raw.get("details") or []],
        expected_provider=raw.get("expected_provider"),
        provider_match=raw.get("provider_match") if raw.get("provider_match") in ("any", "exact") else "any",
    )
    return rule, None


def load_catalog(force: bool = False) -> dict[str, Any]:
    """Bundled catalog + persisted on/off overrides + user-defined rules."""
    global _CATALOG
    with _CATALOG_LOCK:
        if _CATALOG is not None and not force:
            return _CATALOG
        errors: list[str] = []
        document, source = None, None
        for label, path in catalog_candidates():
            if not path.is_file():
                continue
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
                source = f"{label}: {path}"
                break
            except (OSError, ValueError) as error:
                errors.append(f"{label} {path} could not be read: {error}")
        if document is None:
            document = {"catalog_version": "unavailable", "rules": []}
            errors.append("No anomaly catalog was found; only user-defined rules are active.")
        severities = list(document.get("severity_order") or DEFAULT_SEVERITY_ORDER)
        store = state_store()
        try:
            overrides = store.overrides()
            custom = store.custom_rules(include_deleted=True)
        except sqlite3.Error as error:
            overrides, custom = {}, []
            errors.append(f"Rule settings could not be read ({error}); catalog defaults are in effect.")
        rules: list[dict[str, Any]] = []
        deleted: dict[str, dict[str, Any]] = {}
        seen: set[str] = set()
        for raw in document.get("rules") or []:
            rule, problem = _validate_rule(raw, severities)
            if problem:
                errors.append(problem)
                continue
            if rule["rule_id"] in seen:
                errors.append(f"rule {rule['rule_id']}: duplicate rule id ignored")
                continue
            seen.add(rule["rule_id"])
            rule["origin_kind"] = "built-in"
            rule["default_enabled"] = rule["enabled"]
            override = overrides.get(rule["rule_id"])
            rule["modified_at"] = None
            rule["enabled_at"] = None
            if override:
                rule["enabled"] = bool(override["enabled"])
                rule["modified_at"] = override["modified_at"]
                rule["enabled_at"] = override["enabled_at"]
            rule.setdefault("description", rule.get("notes") or rule["name"])
            rules.append(rule)
        for raw in custom:
            raw = dict(raw, origin="custom")
            rule, problem = _validate_rule(raw, severities)
            if problem:
                errors.append(f"custom {problem}")
                continue
            rule["origin_kind"] = "custom"
            rule["verification"] = "User-defined rule - not verified by the Griffendo catalog"
            rule["reference"] = raw.get("source_url") or ""
            if raw.get("deleted_at"):
                deleted[rule["rule_id"]] = rule
                continue
            if rule["rule_id"] in seen:
                errors.append(f"custom rule {rule['rule_id']}: id collides with a built-in rule; ignored")
                continue
            seen.add(rule["rule_id"])
            rules.append(rule)
        index: dict[tuple[str, int], list[dict[str, Any]]] = {}
        for rule in rules:
            if rule["enabled"]:
                index.setdefault((rule["channel"].lower(), rule["event_id"]), []).append(rule)
        try:
            window_days = max(1, int(document.get("window_days", 7)))
        except (TypeError, ValueError):
            window_days = 7
        _CATALOG = {
            "version": str(document.get("catalog_version", "unversioned")),
            "source": source, "window_days": window_days, "severity_order": severities,
            "rules": rules, "deleted_rules": deleted, "index": index, "errors": errors,
            "reviewed_not_included": document.get("reviewed_not_included") or [],
            "loaded_at": iso(utc_now()),
        }
        invalidate_cache()
        return _CATALOG


def severity_rank(severity: str) -> int:
    order = load_catalog()["severity_order"]
    return order.index(severity) if severity in order else len(order)


def matching_rules(channel: str | None, event_id: Any, provider: str | None = None) -> list[dict[str, Any]]:
    """The only detection decision: enabled rules for this channel + Event ID (+ provider when a rule demands it)."""
    if channel is None or event_id is None:
        return []
    try:
        key = (str(channel).lower(), int(event_id))
    except (TypeError, ValueError):
        return []
    result = []
    for rule in load_catalog()["index"].get(key, []):
        if rule["provider_match"] == "exact" and (provider or "").lower() != str(rule.get("expected_provider") or "").lower():
            continue
        result.append(rule)
    return result


def match_rule(channel: str | None, event_id: Any) -> dict[str, Any] | None:
    rules = matching_rules(channel, event_id)
    return rules[0] if rules else None


def find_rule(rule_id: str) -> dict[str, Any] | None:
    catalog = load_catalog()
    for rule in catalog["rules"]:
        if rule["rule_id"] == rule_id:
            return rule
    return catalog["deleted_rules"].get(rule_id)


def rule_name(channel: str | None, event_id: Any) -> str | None:
    if channel is None or event_id is None:
        return None
    for rule in load_catalog()["rules"]:
        if rule["origin_kind"] == "built-in" and rule["channel"].lower() == str(channel).lower() and rule["event_id"] == event_id:
            return rule["name"]
    return None


# v5: the detection engine registers a callable returning {channel: enabled rule count}; channel
# health, collector configuration and accepted channels then follow the engine's rules.
RULE_CHANNELS = None


def _rule_channel_counts() -> dict[str, int]:
    if RULE_CHANNELS is not None:
        return RULE_CHANNELS()
    counts: dict[str, int] = {}
    for rule in load_catalog()["rules"]:
        if rule["enabled"]:
            counts[rule["channel"]] = counts.get(rule["channel"], 0) + 1
    return counts


def required_channels() -> list[str]:
    return list(_rule_channel_counts())


def collector_channels() -> list[str]:
    channels = list(BASE_CHANNELS)
    for channel in required_channels():
        if channel.lower() not in {item.lower() for item in channels}:
            channels.append(channel)
    return channels


_ACCEPTED: tuple[Any, set[str]] | None = None
RULE_VERSION = None   # set by app.start_detection: the detection registry's version (changes with any rule switch)


def accepted_channels() -> set[str]:
    """Channels the receiver stores.  Called for every incoming event, so the result is kept until the
    catalog, the detection rules or the channel settings change (v5.0 recomputed it per event)."""
    global _ACCEPTED
    key = (id(load_catalog()), RULE_CHANNELS is not None, RULE_VERSION() if RULE_VERSION is not None else None,
           os.getenv("LOGPLATFORM_EXTRA_CHANNELS", ""), os.getenv("WINLOG_CHANNELS", ""))
    cached = _ACCEPTED
    if cached is not None and cached[0] == key:
        return cached[1]
    names = _accepted_channels()
    _ACCEPTED = (key, names)
    return names


def _accepted_channels() -> set[str]:
    names = set(BASE_CHANNELS)
    names.update(rule["channel"] for rule in load_catalog()["rules"])
    if RULE_CHANNELS is not None:
        names.update(RULE_CHANNELS())
    extra = os.getenv("LOGPLATFORM_EXTRA_CHANNELS", "") + ";" + os.getenv("WINLOG_CHANNELS", "")
    names.update(item.strip() for item in extra.split(";") if CHANNEL_NAME.match(item.strip()))
    return names


def window(now: datetime | None = None) -> tuple[datetime, datetime]:
    end = now or utc_now()
    return end - timedelta(days=load_catalog()["window_days"]), end


# --------------------------------------------------------------------------- active detections (shared filter)
ACTIVE_COLUMNS = ("rule_id", "event_id", "channel", "provider", "name", "category", "severity", "severity_rank", "origin")
# A stored detection is "active" when its rule is enabled now and it still matches the rule's current definition.
ACTIVE_JOIN = ("JOIN active_rules r ON a.rule_id = r.rule_id AND a.event_id = r.event_id AND lower(a.channel) = r.channel "
               "AND (r.provider IS NULL OR lower(IFNULL(a.provider, '')) = r.provider)")


def active_rules(severities: Iterable[str] | None = None, categories: Iterable[str] | None = None) -> list[dict[str, Any]]:
    wanted_severities = {item for item in severities or [] if item}
    wanted_categories = {item for item in categories or [] if item}
    return [rule for rule in load_catalog()["rules"]
            if rule["enabled"] and not rule.get("deleted_at")
            and (not wanted_severities or rule["severity"] in wanted_severities)
            and (not wanted_categories or rule["category"] in wanted_categories)]


def _active_cte(rules: list[dict[str, Any]] | None = None) -> tuple[str, list[Any]]:
    """'active_rules(...) AS (VALUES ...)' for a WITH clause, plus its parameters."""
    rules = active_rules() if rules is None else rules
    columns = ", ".join(ACTIVE_COLUMNS)
    if not rules:
        return f"active_rules({columns}) AS (SELECT {', '.join('NULL' for _ in ACTIVE_COLUMNS)} WHERE 0)", []
    params: list[Any] = []
    for rule in rules:
        exact = rule.get("provider_match") == "exact" and rule.get("expected_provider")
        params += [rule["rule_id"], rule["event_id"], rule["channel"].lower(),
                   str(rule["expected_provider"]).lower() if exact else None, rule["name"], rule["category"],
                   rule["severity"], severity_rank(rule["severity"]), rule["origin_kind"]]
    row = "(" + ", ".join("?" for _ in ACTIVE_COLUMNS) + ")"
    return f"active_rules({columns}) AS (VALUES {', '.join(row for _ in rules)})", params


def rules_version() -> str:
    """Changes whenever any rule setting changes (the catalog is reloaded on every rule change)."""
    return load_catalog()["loaded_at"]


# --------------------------------------------------------------------------- schema
def initialize() -> None:
    load_catalog(force=True)
    with db.connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS anomalies (
                id TEXT PRIMARY KEY,
                event_key TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                record_id INTEGER,
                event_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                severity_rank INTEGER NOT NULL,
                provider TEXT,
                expected_provider TEXT,
                provider_match INTEGER,
                channel TEXT NOT NULL,
                hostname TEXT NOT NULL,
                agent_id TEXT,
                event_time TEXT NOT NULL,
                event_time_source TEXT NOT NULL,
                raw_timestamp TEXT,
                username TEXT,
                source_address TEXT,
                details_json TEXT NOT NULL,
                fields_json TEXT NOT NULL,
                raw_xml TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                status_note TEXT,
                status_updated_at TEXT,
                catalog_version TEXT NOT NULL,
                UNIQUE(event_key, rule_id)
            );
            CREATE INDEX IF NOT EXISTS idx_anomalies_time ON anomalies(event_time);
            CREATE INDEX IF NOT EXISTS idx_anomalies_rule_host ON anomalies(rule_id, hostname);
            CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity_rank, event_time);
            CREATE TABLE IF NOT EXISTS collector_agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                backend TEXT,
                version TEXT,
                mode TEXT,
                started_at TEXT,
                interval_seconds REAL,
                last_heartbeat TEXT NOT NULL,
                spool_size INTEGER,
                last_delivery_at TEXT,
                last_error TEXT,
                last_error_at TEXT,
                stats_json TEXT
            );
            CREATE TABLE IF NOT EXISTS collector_channels (
                agent_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                channel TEXT NOT NULL,
                state TEXT NOT NULL,
                detail TEXT,
                watermark INTEGER,
                collected INTEGER,
                lookback_hours INTEGER,
                reported_at TEXT NOT NULL,
                PRIMARY KEY (agent_id, channel)
            );
            """
        )
        existing = db._columns(connection, "anomalies")
        for column, kind in (("detection_source", "TEXT DEFAULT 'ingest'"), ("rule_origin", "TEXT")):
            if column not in existing:
                connection.execute(f"ALTER TABLE anomalies ADD COLUMN {column} {kind}")
        # v4: covering index for the active-detection join (rule + time range + the columns the join checks),
        # so counts and per-rule statistics never touch the large detection rows.  Replaces idx_anomalies_rule_time.
        connection.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_rule_cover "
                           "ON anomalies(rule_id, event_time, event_id, channel, provider, hostname, event_key)")
        connection.execute("DROP INDEX IF EXISTS idx_anomalies_rule_time")
        # v4 timeline order (oldest first, stable for equal timestamps).
        connection.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_timeline "
                           "ON anomalies(event_time, IFNULL(record_id, -1), event_key)")
        existing = db._columns(connection, "collector_channels")
        for column, kind in (("last_success_at", "TEXT"), ("last_error_at", "TEXT"), ("last_error", "TEXT"),
                             ("backfill", "TEXT"), ("backfill_reached", "TEXT"), ("live_cursor", "INTEGER"),
                             ("records_lost", "INTEGER"), ("lost_detail", "TEXT"), ("log_json", "TEXT"),
                             ("latency_json", "TEXT")):
            if column not in existing:
                connection.execute(f"ALTER TABLE collector_channels ADD COLUMN {column} {kind}")
    state_store()


def shutdown() -> None:
    global _STATE
    with _CATALOG_LOCK:
        if _STATE is not None:
            _STATE.close()
            _STATE = None
        invalidate_cache()


# --------------------------------------------------------------------------- detection
def _meaningful(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() not in _PLACEHOLDERS


def _source_address(fields: dict[str, Any], rule: dict[str, Any]) -> str | None:
    names = list(ADDRESS_FIELDS)
    if rule.get("address_field"):
        names.insert(0, rule["address_field"])
    if rule["rule_id"] == "RDP-1149":
        names.insert(0, "Param3")
    lowered = {str(key).lower(): value for key, value in fields.items()}
    for name in names:
        value = lowered.get(name.lower())
        if _meaningful(value):
            return value.strip()
    return None


def process_events(event_keys: Iterable[str] | None = None, now: datetime | None = None,
                   rule_ids: Iterable[str] | None = None, source: str | None = None) -> dict[str, Any]:
    """Flag stored events that match enabled rules inside the window.

    event_keys: only these events (used at ingest, so new events are flagged at once).
    rule_ids:   only these rules (a per-rule historical rescan).
    Neither:    a full rescan.  Existing detections are never duplicated.
    """
    catalog = load_catalog()
    start, end = window(now)
    latest_allowed = end + FUTURE_TOLERANCE
    detected_at = iso(utc_now())
    wanted_rules = set(rule_ids) if rule_ids is not None else None
    source = source or ("ingest" if event_keys is not None else "rescan")
    ids = sorted({rule["event_id"] for rules in catalog["index"].values() for rule in rules
                  if wanted_rules is None or rule["rule_id"] in wanted_rules})
    stats = {"examined": 0, "matched": 0, "inserted": 0, "already_recorded": 0,
             "outside_window": 0, "future_dated": 0, "time_from_receipt": 0}
    if not ids:
        stats.update(window_start=iso(start), window_end=iso(end), scope=source, completed_at=iso(utc_now()))
        _LAST_SCAN.update(stats)
        return stats
    store = state_store()
    id_marks = ",".join("?" for _ in ids)
    key_list = list(dict.fromkeys(event_keys)) if event_keys is not None else None
    batches = [key_list[i:i + 500] for i in range(0, len(key_list), 500)] if key_list is not None else [None]
    inserted_ids: list[str] = []
    with db.connect() as connection:
        for chunk in batches:
            if chunk is not None and not chunk:
                continue
            # With a list of event keys, look the events up by key: '+event_id' stops SQLite from scanning every
            # stored event with a rule's Event ID instead (226 ms vs 11 ms per 2,000 keys at 1M events, measured).
            column = "+event_id" if chunk is not None else "event_id"
            sql = ("SELECT id, agent_id, hostname, channel, record_id, raw_xml, normalized_json, timestamp, received_at, "
                   f"provider, event_id, username FROM events WHERE {column} IN ({id_marks})")
            params: list[Any] = list(ids)
            if chunk is not None:
                sql += f" AND id IN ({','.join('?' for _ in chunk)})"
                params.extend(chunk)
            else:
                sql += " AND event_time >= ?"
                params.append(iso(start))
            for row in connection.execute(sql, params).fetchall():
                stats["examined"] += 1
                rules = [rule for rule in matching_rules(row["channel"], row["event_id"], row["provider"])
                         if wanted_rules is None or rule["rule_id"] in wanted_rules]
                if not rules:
                    continue
                stats["matched"] += 1
                occurred = parse_time(row["timestamp"])
                time_source = "event"
                if occurred is None:
                    occurred = parse_time(row["received_at"])
                    time_source = "received"
                    stats["time_from_receipt"] += 1
                if occurred is None or occurred < start:
                    stats["outside_window"] += 1
                    continue
                if occurred > latest_allowed:
                    stats["future_dated"] += 1
                    continue
                try:
                    fields = json.loads(row["normalized_json"]).get("fields") or {}
                except (TypeError, ValueError):
                    fields = {}
                lowered = {str(key).lower(): value for key, value in fields.items()}
                for rule in rules:
                    details = {name: lowered.get(name.lower()) for name in rule["details"]}
                    detection_id = hashlib.sha256(f"{row['id']}|{rule['rule_id']}".encode("utf-8")).hexdigest()
                    expected = rule.get("expected_provider")
                    provider_match = None if not expected or not row["provider"] else int(
                        str(row["provider"]).lower() == str(expected).lower())
                    cursor = connection.execute(
                        """INSERT OR IGNORE INTO anomalies(
                            id, event_key, rule_id, record_id, event_id, name, category, severity, severity_rank,
                            provider, expected_provider, provider_match, channel, hostname, agent_id, event_time,
                            event_time_source, raw_timestamp, username, source_address, details_json, fields_json,
                            raw_xml, detected_at, status, catalog_version, detection_source, rule_origin
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'New', ?, ?, ?)""",
                        (
                            detection_id, row["id"], rule["rule_id"], row["record_id"], row["event_id"], rule["name"],
                            rule["category"], rule["severity"], severity_rank(rule["severity"]), row["provider"],
                            expected, provider_match, row["channel"], row["hostname"], row["agent_id"], iso(occurred),
                            time_source, row["timestamp"], row["username"], _source_address(fields, rule),
                            json.dumps(details, separators=(",", ":")), json.dumps(fields, separators=(",", ":")),
                            row["raw_xml"], detected_at, catalog["version"], source, rule["origin_kind"],
                        ),
                    )
                    if cursor.rowcount:
                        stats["inserted"] += 1
                        inserted_ids.append(detection_id)
                    else:
                        stats["already_recorded"] += 1
        if inserted_ids:
            for detection_id, triage in store.get_many(inserted_ids).items():
                connection.execute(
                    "UPDATE anomalies SET status = ?, status_note = ?, status_updated_at = ? WHERE id = ?",
                    (triage["status"], triage["note"], triage["updated_at"], detection_id))
    stats.update(window_start=iso(start), window_end=iso(end), scope=source, completed_at=iso(utc_now()))
    if wanted_rules is not None:
        stats["rules"] = sorted(wanted_rules)
    _LAST_SCAN.update(stats)
    if stats["inserted"]:
        invalidate_cache()
    return stats


def last_scan() -> dict[str, Any]:
    return dict(_LAST_SCAN)


# --------------------------------------------------------------------------- per-rule re-evaluation (v4)
_EVAL_LOCK = threading.Lock()
_EVALUATIONS: dict[str, dict[str, Any]] = {}
_RULE_CHANGE_LOCK = threading.RLock()


def _eval_chunk() -> int:
    return max(100, settings.env_int("GRIFFENDO_EVAL_CHUNK", 2000))


def _eval_wait_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("GRIFFENDO_EVAL_WAIT_SECONDS", "2")))
    except ValueError:
        return 2.0


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in job.items() if not key.startswith("_")}


def evaluation_status(rule_id: str) -> dict[str, Any] | None:
    job = _EVALUATIONS.get(rule_id)
    return _public_job(job) if job else None


def evaluations() -> list[dict[str, Any]]:
    with _EVAL_LOCK:
        jobs = list(_EVALUATIONS.values())
    return sorted((_public_job(job) for job in jobs), key=lambda job: job["started_at"], reverse=True)[:50]


def _rule_window_counts(rule_id: str, now: datetime | None = None) -> dict[str, int]:
    start, end = window(now)
    rule = find_rule(rule_id)
    cte, cte_values = _active_cte([rule] if rule and rule["enabled"] and not rule.get("deleted_at") else [])
    with db.connect() as connection:
        stored = connection.execute(
            "SELECT COUNT(*) FROM anomalies WHERE rule_id = ? AND event_time >= ? AND event_time <= ?",
            (rule_id, iso(start), iso(end + FUTURE_TOLERANCE))).fetchone()[0]
        active = connection.execute(
            f"WITH {cte} SELECT COUNT(*) FROM anomalies a {ACTIVE_JOIN} WHERE a.event_time >= ? AND a.event_time <= ?",
            [*cte_values, iso(start), iso(end + FUTURE_TOLERANCE)]).fetchone()[0]
    return {"stored_in_window": stored, "active_in_window": active}


def _run_evaluation(job: dict[str, Any]) -> None:
    """Targeted re-evaluation of one rule over the analysis window, in small chunks.

    Only events of the rule's channel + Event ID that have no detection for this rule yet are examined, so
    switching a rule back on is cheap when nothing was missed.  Each chunk takes the database lock briefly, so
    collection and the dashboard keep working during a large evaluation.  The job stops if the rule is switched
    off or deleted meanwhile, and runs again if the rule changes while it is running.
    """
    rule_id = job["rule_id"]
    try:
        while True:
            job["_rerun"] = False
            rule = find_rule(rule_id)
            if rule is None or rule.get("deleted_at") or not rule["enabled"]:
                job.update(state="cancelled", detail="Rule switched off or deleted before the evaluation finished.")
                return
            now = utc_now()
            start, end = window(now)
            counts = _rule_window_counts(rule_id, now)
            job["restored"] = counts["active_in_window"]
            with db.connect() as connection:
                keys = [row[0] for row in connection.execute(
                    """SELECT e.id FROM events e
                       WHERE e.event_id = ? AND lower(e.channel) = ? AND e.event_time >= ? AND e.event_time <= ?
                         AND NOT EXISTS (SELECT 1 FROM anomalies a WHERE a.event_key = e.id AND a.rule_id = ?)
                       ORDER BY e.event_time, e.id""",
                    (rule["event_id"], rule["channel"].lower(), iso(start), iso(end + FUTURE_TOLERANCE), rule_id))]
            job.update(candidates=len(keys), examined=0, window_start=iso(start), window_end=iso(end))
            chunk = _eval_chunk()
            for offset in range(0, len(keys), chunk):
                current = find_rule(rule_id)
                if current is None or current.get("deleted_at") or not current["enabled"]:
                    job.update(state="cancelled", detail="Rule switched off or deleted during the evaluation.")
                    return
                if job["_rerun"]:
                    break
                stats = process_events(event_keys=keys[offset:offset + chunk], now=now, rule_ids=[rule_id],
                                       source="reevaluation")
                job["inserted"] += stats["inserted"]
                job["examined"] += min(chunk, len(keys) - offset)
                time.sleep(0)   # let other threads take the database lock between chunks
            if not job["_rerun"]:
                break
        job.update(state="done", detail=None)
    except Exception as error:   # reported in the UI; detections already written stay valid
        job.update(state="failed", detail=f"{type(error).__name__}: {error}")
    finally:
        job["finished_at"] = iso(utc_now())
        job["seconds"] = round(time.monotonic() - job["_started"], 3)
        if job["inserted"]:
            invalidate_cache()


def evaluate_rule_history(rule_id: str, reason: str, wait: float | None = None) -> dict[str, Any]:
    """Start (or join) the re-evaluation of one rule and wait up to `wait` seconds for it to finish."""
    with _EVAL_LOCK:
        job = _EVALUATIONS.get(rule_id)
        if job and job["state"] == "running":
            job["_rerun"] = True     # the rule changed again: evaluate once more with the new definition
            job["reason"] = reason
        else:
            job = {"rule_id": rule_id, "reason": reason, "state": "running", "started_at": iso(utc_now()),
                   "finished_at": None, "seconds": None, "candidates": None, "examined": 0, "inserted": 0,
                   "restored": None, "detail": None, "_started": time.monotonic(), "_rerun": False}
            job["_thread"] = threading.Thread(target=_run_evaluation, args=(job,), name=f"evaluate-{rule_id}",
                                              daemon=True)
            _EVALUATIONS[rule_id] = job
            job["_thread"].start()
    job["_thread"].join(_eval_wait_seconds() if wait is None else wait)
    return _public_job(job)


# --------------------------------------------------------------------------- collector health
CHANNEL_FIELDS = ("state", "detail", "watermark", "collected", "lookback_hours", "last_success_at", "last_error_at",
                  "last_error", "backfill", "backfill_reached", "live_cursor", "records_lost", "lost_detail")


def record_collector_status(report: dict[str, Any]) -> int:
    """Store an agent heartbeat and its per-channel state (v2 agents send channels only)."""
    now = iso(utc_now())
    agent_id, hostname = report["agent_id"], report["hostname"]
    with db.connect() as connection:
        connection.execute(
            """INSERT INTO collector_agents(agent_id, hostname, backend, version, mode, started_at, interval_seconds,
                   last_heartbeat, spool_size, last_delivery_at, last_error, last_error_at, stats_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET hostname=excluded.hostname, backend=excluded.backend,
                   version=excluded.version, mode=excluded.mode, started_at=excluded.started_at,
                   interval_seconds=excluded.interval_seconds, last_heartbeat=excluded.last_heartbeat,
                   spool_size=excluded.spool_size, last_delivery_at=excluded.last_delivery_at,
                   last_error=excluded.last_error, last_error_at=excluded.last_error_at, stats_json=excluded.stats_json""",
            (agent_id, hostname, report.get("backend"), report.get("version"), report.get("mode") or "snapshot",
             report.get("started_at"), report.get("interval_seconds"), now, report.get("spool_size"),
             report.get("last_delivery_at"), report.get("last_error"), report.get("last_error_at"),
             json.dumps(report.get("stats") or {}, separators=(",", ":"))),
        )
        for item in report.get("channels") or []:
            values = [item.get(field) for field in CHANNEL_FIELDS]
            connection.execute(
                f"""INSERT INTO collector_channels(agent_id, hostname, channel, {', '.join(CHANNEL_FIELDS)},
                        log_json, latency_json, reported_at)
                    VALUES (?, ?, ?, {', '.join('?' for _ in CHANNEL_FIELDS)}, ?, ?, ?)
                    ON CONFLICT(agent_id, channel) DO UPDATE SET hostname=excluded.hostname, state=excluded.state,
                        detail=excluded.detail, watermark=COALESCE(excluded.watermark, collector_channels.watermark),
                        collected=COALESCE(excluded.collected, collector_channels.collected),
                        lookback_hours=excluded.lookback_hours,
                        last_success_at=COALESCE(excluded.last_success_at, collector_channels.last_success_at),
                        last_error_at=COALESCE(excluded.last_error_at, collector_channels.last_error_at),
                        last_error=COALESCE(excluded.last_error, collector_channels.last_error),
                        backfill=excluded.backfill, backfill_reached=excluded.backfill_reached,
                        live_cursor=excluded.live_cursor, records_lost=excluded.records_lost,
                        lost_detail=excluded.lost_detail,
                        log_json=COALESCE(excluded.log_json, collector_channels.log_json),
                        latency_json=COALESCE(excluded.latency_json, collector_channels.latency_json),
                        reported_at=excluded.reported_at""",
                [agent_id, hostname, item["channel"], *values,
                 json.dumps(item["log"]) if item.get("log") else None,
                 json.dumps(item["latency"]) if item.get("latency") else None, now],
            )
    invalidate_cache(keep_data_keyed=True)
    return len(report.get("channels") or [])


def record_channel_status(agent_id: str, hostname: str, channels: list[dict[str, Any]]) -> int:
    """v2 entry point (channels only)."""
    return record_collector_status({"agent_id": agent_id, "hostname": hostname, "channels": channels})


STATE_LABELS = {
    "ok": "Collected",
    "empty": "Log empty or disabled",
    "unavailable": "Channel not present",
    "access_denied": "Access denied",
    "error": "Collection error",
    "not_reported": "Not reported by a collector",
    "not_configured": "Not in collector's channel list",
}
COVERAGE_LABELS = {
    "verified": "Coverage verified for the available monitoring period",
    "partial": "Partial coverage",
    "unknown": "Coverage unknown",
    "unavailable": "Required channel unavailable",
    "no_data": "No data collected yet",
}


def collector_health(now: datetime | None = None) -> dict[str, Any]:
    now = now or utc_now()
    with db.read() as connection:
        agents = [dict(row) for row in connection.execute("SELECT * FROM collector_agents ORDER BY last_heartbeat DESC")]
        last_event = connection.execute("SELECT (SELECT received_at FROM events WHERE rowid = (SELECT MAX(rowid) FROM events))").fetchone()[0]
    result = []
    for agent in agents:
        interval = agent["interval_seconds"] or 0
        heartbeat = parse_time(agent["last_heartbeat"])
        age = (now - heartbeat).total_seconds() if heartbeat else None
        if agent["mode"] != "continuous":
            state = "snapshot"
            label = "Snapshot collector (runs once per launch)"
        elif age is not None and age <= max(60, interval * 4):
            state, label = "running", "Running"
        else:
            state, label = "stale", f"Not reporting for {int(age or 0)} s"
        try:
            stats = json.loads(agent.pop("stats_json") or "{}")
        except ValueError:
            stats = {}
        result.append({**agent, "stats": stats, "state": state, "state_label": label,
                       "heartbeat_age_seconds": round(age, 1) if age is not None else None})
    return {"agents": result, "last_event_received_at": last_event,
            "refresh_seconds": settings.ui_refresh_seconds()}


def _channel_aggregates(start: datetime) -> dict[str, dict[str, Any]]:
    """Per-channel counts for the window (v5: from the hourly aggregate table plus index seeks, no table scan)."""
    def produce():
        start_text = iso(start)
        next_hour = iso(start.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))
        with db.read() as connection:
            hours = connection.execute(
                "SELECT channel, SUM(n) AS n FROM agg_channel_hour WHERE hour >= ? AND n > 0 GROUP BY channel",
                (next_hour[:13],)).fetchall()
            channels = [row[0] for row in connection.execute("SELECT DISTINCT channel FROM agg_channel_hour WHERE n > 0")]
            result: dict[str, dict[str, Any]] = {}
            counts = {row["channel"]: row["n"] for row in hours}
            for channel in channels:
                partial = connection.execute(
                    "SELECT COUNT(*) FROM events WHERE channel = ? AND event_time >= ? AND event_time < ?",
                    (channel, start_text, next_hour)).fetchone()[0]
                earliest_any = connection.execute("SELECT MIN(event_time) FROM events WHERE channel = ?",
                                                  (channel,)).fetchone()[0]
                earliest = connection.execute("SELECT MIN(event_time) FROM events WHERE channel = ? AND event_time >= ?",
                                              (channel, start_text)).fetchone()[0]
                latest = connection.execute("SELECT MAX(event_time) FROM events WHERE channel = ?",
                                            (channel,)).fetchone()[0]
                item = result.setdefault(channel.lower(), {})
                item["earliest_any"] = earliest_any
                total = counts.get(channel, 0) + partial
                if total:
                    item.update(events=total, earliest=earliest, latest=latest)
            cleared = connection.execute(
                "SELECT channel, event_id, event_time, normalized_json FROM events "
                # Unary + keeps SQLite on the (event_id, channel) index; via the time index this scanned
                # every event in the window (2.8 s at 1M events, measured).
                "WHERE event_id IN (1102, 104) AND channel IN ('Security', 'System') AND +event_time >= ? "
                "AND ((channel = 'Security' AND event_id = 1102) OR (channel = 'System' AND event_id = 104))",
                (start_text,)).fetchall()
        for row in cleared:
            target = "security"
            if row["event_id"] == 104:
                try:
                    fields = json.loads(row["normalized_json"]).get("fields") or {}
                except ValueError:
                    fields = {}
                target = str(fields.get("Channel") or "").lower()
            result.setdefault(target, {}).setdefault("cleared", []).append(row["event_time"])
        return result
    # Short TTL instead of a data-version key: with continuous collection the data version changes every
    # few seconds, which made this cache useless (v4).
    return _cached(f"channel-aggregates-{iso(start)[:15]}", produce, ttl=15)


def channel_status(now: datetime | None = None) -> list[dict[str, Any]]:
    """Availability, health and window coverage for every channel the collector should read."""
    now = now or utc_now()
    start, end = window(now)
    wanted = collector_channels()
    rule_counts = _rule_channel_counts()
    with db.read() as connection:
        reports = connection.execute("SELECT * FROM collector_channels").fetchall()
        agents = {row["agent_id"]: dict(row) for row in connection.execute("SELECT * FROM collector_agents")}
    stats = _channel_aggregates(start)
    health = {agent["agent_id"]: agent for agent in collector_health(now)["agents"]}
    by_channel: dict[str, list[sqlite3.Row]] = {}
    for row in reports:
        by_channel.setdefault(row["channel"].lower(), []).append(row)
    reporting_agents = {row["agent_id"] for row in reports}
    result = []
    for channel in wanted:
        key = channel.lower()
        reported = by_channel.get(key, [])
        data = stats.get(key, {})
        count = data.get("events", 0)
        earliest = parse_time(data.get("earliest"))
        latest = parse_time(data.get("latest"))
        earliest_any = parse_time(data.get("earliest_any"))
        states = sorted({row["state"] for row in reported})
        if reported:
            state = "ok" if "ok" in states else states[0]
            detail = "; ".join(sorted({f"{row['hostname']}: {row['detail']}" for row in reported if row["detail"]})) or None
        elif count:
            state, detail = "ok", "Events present; no channel report received (older collector)."
        elif reporting_agents:
            state, detail = "not_configured", "A collector reported, but not for this channel."
        else:
            state, detail = "not_reported", ("No collector has reported yet. Collection runs only on Windows; "
                                             "on other systems the dashboard shows previously received data only.")
        logs = []
        for row in reported:
            try:
                logs.append(json.loads(row["log_json"])) if row["log_json"] else None
            except ValueError:
                pass
        reasons: list[str] = []
        if state != "ok":
            coverage = "unavailable" if reported or state == "not_configured" else "unknown"
            reasons.append(STATE_LABELS.get(state, state) + ".")
        else:
            coverage = "verified"
            backfills = {row["backfill"] for row in reported if row["backfill"]}
            if backfills & {"pending", "running"}:
                coverage = "partial"
                reached = [row["backfill_reached"] for row in reported if row["backfill_reached"]]
                reasons.append("Historical backfill still running" + (f" (reached back to {min(reached)})" if reached else "") + ".")
            lost = sum(row["records_lost"] or 0 for row in reported)
            if lost:
                coverage = "partial"
                reasons.append(f"{lost} record(s) were overwritten or cleared before Griffendo read them "
                               f"({'; '.join(row['lost_detail'] for row in reported if row['lost_detail'])}).")
            for when in data.get("cleared", []):
                coverage = "partial"
                reasons.append(f"The log was cleared at {when}; events before that moment are gone.")
            if earliest_any is None or earliest_any > start:
                oldest_numbers = [log.get("oldest_record") for log in logs if log.get("oldest_record") is not None]
                full = any(log.get("is_full") for log in logs)
                if not reported:
                    coverage = "partial" if coverage == "verified" else coverage
                    reasons.append("No collector report, so retention cannot be checked.")
                elif oldest_numbers and min(oldest_numbers) <= 1 and not full and not lost and not data.get("cleared"):
                    reasons.append("The log still holds its first record (never wrapped or cleared), so no earlier events existed.")
                elif oldest_numbers or full:
                    coverage = "partial"
                    first = iso(earliest_any) if earliest_any else "the earliest stored event"
                    reasons.append(f"The Windows log no longer holds records before {first} (it wrapped or was cleared).")
                else:
                    coverage = "partial"
                    reasons.append("Stored events start after the window start and the log's retention could not be confirmed.")
            stale = [health[row["agent_id"]] for row in reported if row["agent_id"] in health
                     and health[row["agent_id"]]["state"] == "stale"]
            if stale:
                coverage = "partial"
                reasons.append(f"Collector on {stale[0]['hostname']} has not reported since {stale[0]['last_heartbeat']}; "
                               "newer events may be missing.")
            if coverage == "verified":
                reasons.append("Readable, no record gaps detected, and retention reaches the window start or nothing was lost.")
        successes = [row["last_success_at"] for row in reported if row["last_success_at"]]
        errors = [(row["last_error_at"], row["last_error"]) for row in reported if row["last_error_at"]]
        latency = None
        for row in reported:
            if row["latency_json"]:
                try:
                    latency = json.loads(row["latency_json"])
                except ValueError:
                    pass
        result.append({
            "channel": channel,
            "base_channel": channel in BASE_CHANNELS,
            "enabled_rules": rule_counts.get(channel, 0),
            "state": state,
            "state_label": STATE_LABELS.get(state, state),
            "detail": detail,
            "events_stored": count,
            "earliest_event": iso(earliest) if earliest else None,
            "latest_event": iso(latest) if latest else None,
            "earliest_retained": iso(earliest_any) if earliest_any else None,
            "coverage": coverage,
            "coverage_label": COVERAGE_LABELS[coverage],
            "coverage_note": " ".join(reasons),
            "coverage_reasons": reasons,
            "lookback_hours": max((row["lookback_hours"] or 0 for row in reported), default=0) or None,
            "last_success_at": max(successes) if successes else None,
            "last_error_at": max(errors)[0] if errors else None,
            "last_error": max(errors)[1] if errors else None,
            "backfill": sorted({row["backfill"] for row in reported if row["backfill"]}),
            "records_lost": sum(row["records_lost"] or 0 for row in reported),
            "log": logs[0] if logs else None,
            "latency": latency,
            "reports": [{"hostname": row["hostname"], "state": row["state"], "detail": row["detail"],
                         "collected": row["collected"], "reported_at": row["reported_at"],
                         "agent_mode": agents.get(row["agent_id"], {}).get("mode")} for row in reported],
            "monitored": state == "ok",
        })
    return result


def coverage_overview(now: datetime | None = None, channels: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    now = now or utc_now()
    start, end = window(now)
    channels = channels if channels is not None else channel_status(now)
    required = [item for item in channels if item["enabled_rules"]]
    with db.connect() as connection:
        events_stored = connection.execute("SELECT COUNT(*) FROM (SELECT 1 FROM events LIMIT 1)").fetchone()[0]
    unavailable = [item["channel"] for item in required if item["coverage"] == "unavailable"]
    unknown = [item["channel"] for item in required if item["coverage"] == "unknown"]
    partial = [item["channel"] for item in required if item["coverage"] == "partial"]
    if not events_stored and not any(item["reports"] for item in channels):
        state = "no_data"
    elif unavailable:
        state = "unavailable"
    elif unknown:
        state = "unknown"
    elif partial:
        state = "partial"
    else:
        state = "verified"
    earliest = [parse_time(item["earliest_event"]) for item in required if item["earliest_event"]]
    latest = [parse_time(item["latest_event"]) for item in required if item["latest_event"]]
    successes = [item["last_success_at"] for item in channels if item["last_success_at"]]
    health = collector_health(now)
    running = [agent for agent in health["agents"] if agent["state"] == "running"]
    if not health["agents"]:
        health_state, health_label = "unknown", "No collector has reported"
    elif running:
        health_state, health_label = "running", f"{len(running)} collector(s) running"
    elif any(agent["state"] == "snapshot" for agent in health["agents"]):
        health_state, health_label = "snapshot", "Snapshot collector only (no live collection)"
    else:
        health_state, health_label = "stale", "Collector not reporting"
    missing = []
    for item in required:
        if item["coverage"] != "verified":
            missing.append({"channel": item["channel"], "coverage": item["coverage"], "reasons": item["coverage_reasons"]})
    return {
        "state": state,
        "label": COVERAGE_LABELS[state],
        "window": {"start": iso(start), "end": iso(end)},
        "available": {"earliest": iso(min(earliest)) if earliest else None, "latest": iso(max(latest)) if latest else None},
        # legacy keys used by v2 clients/tests
        "start": iso(max(start, max(earliest))) if earliest else None,
        "end": iso(end),
        "unavailable_channels": unavailable,
        "partial_channels": partial,
        "unknown_channels": unknown,
        "events_stored": events_stored,
        "health": {"state": health_state, "label": health_label, "agents": health["agents"]},
        "last_successful_collection": max(successes) if successes else None,
        "last_event_received_at": health["last_event_received_at"],
        "missing": missing,
        "explanation": {
            "measures": ("Whether each channel used by an enabled rule could be read, whether its retained events reach "
                         "back to the start of the analysis window, and whether any records were lost (log wrapped, "
                         "cleared, or skipped between collections)."),
            "does_not_prove": ("That every event that happened was logged. Audit policy may not record an action at all, "
                               "and a quiet log looks the same as an idle system. A percentage is not shown because the "
                               "span between the oldest and newest event does not prove completeness."),
            "channels": [item["channel"] for item in required],
        },
    }


# --------------------------------------------------------------------------- queries
FILTER_COLUMNS = {"event_id": "event_id", "channel": "channel", "host": "hostname", "status": "status",
                  "rule_id": "rule_id"}


def _filters(params: dict[str, Any], start: datetime | None, end: datetime, alias: str = "",
             active: bool = False) -> tuple[str, list[Any]]:
    """WHERE clause for detection queries.  With active=True, severity and category refer to the rule's
    current definition (the 'r' alias from ACTIVE_JOIN); otherwise to the values stored at detection time."""
    a = f"{alias}." if alias else ""
    clauses, values = [], []
    if start is not None:
        clauses += [f"{a}event_time >= ?", f"{a}event_time <= ?"]
        values += [iso(start), iso(end + FUTURE_TOLERANCE)]
    since = parse_time(params.get("since")) if params.get("since") else None
    until = parse_time(params.get("until")) if params.get("until") else None
    if since:
        clauses.append(f"{a}event_time >= ?")
        values.append(iso(since))
    if until:
        clauses.append(f"{a}event_time <= ?")
        values.append(iso(until))
    meta = "r." if active else a
    severities = [item for item in (params.get("severity") or "").split(",") if item]
    if severities:
        clauses.append(f"{meta}severity IN ({','.join('?' for _ in severities)})")
        values.extend(severities)
    if params.get("category"):
        clauses.append(f"{meta}category = ?")
        values.append(params["category"])
    for key, column in FILTER_COLUMNS.items():
        value = params.get(key)
        if value is None or value == "":
            continue
        clauses.append(f"{a}{column} = ?")
        values.append(value)
    if params.get("q"):
        name = "r.name" if active else f"{a}name"
        clauses.append(f"({name} LIKE ? OR {a}username LIKE ? OR {a}source_address LIKE ? OR {a}details_json LIKE ? "
                       f"OR {a}hostname LIKE ?)")
        values.extend([f"%{params['q']}%"] * 5)
    return " AND ".join(clauses) or "1=1", values


def _rule_state(rule_id: str, event_id: Any = None, channel: str | None = None, provider: str | None = None) -> str:
    rule = find_rule(rule_id)
    if rule is None:
        return "Rule no longer in catalog - hidden from active views"
    if rule.get("deleted_at"):
        return "Rule deleted - hidden from active views"
    if not rule["enabled"]:
        return "Rule disabled - hidden from active views"
    if event_id is not None and (int(event_id) != rule["event_id"] or str(channel or "").lower() != rule["channel"].lower()):
        return "Rule changed since detection - hidden from active views"
    if (event_id is not None and rule.get("provider_match") == "exact" and rule.get("expected_provider")
            and str(provider or "").lower() != str(rule["expected_provider"]).lower()):
        return "Rule now requires another provider - hidden from active views"
    return "Rule enabled - shown in active views"


def _row(row: sqlite3.Row, include_evidence: bool = False) -> dict[str, Any]:
    keys = row.keys()
    item = {
        "id": row["id"], "event_key": row["event_key"], "rule_id": row["rule_id"], "record_id": row["record_id"],
        "event_id": row["event_id"], "name": row["name"], "category": row["category"], "severity": row["severity"],
        "provider": row["provider"], "expected_provider": row["expected_provider"],
        "provider_match": None if row["provider_match"] is None else bool(row["provider_match"]),
        "channel": row["channel"], "hostname": row["hostname"], "event_time": row["event_time"],
        "event_time_source": row["event_time_source"], "raw_timestamp": row["raw_timestamp"],
        "username": row["username"], "source_address": row["source_address"],
        "details": json.loads(row["details_json"]), "detected_at": row["detected_at"], "status": row["status"],
        "status_note": row["status_note"], "status_updated_at": row["status_updated_at"],
        "catalog_version": row["catalog_version"], "detection_basis": "Event ID match",
        "detection_source": row["detection_source"] if "detection_source" in keys else "ingest",
        "rule_origin": row["rule_origin"] if "rule_origin" in keys else None,
        "rule_state": _rule_state(row["rule_id"], row["event_id"], row["channel"], row["provider"]),
        # What the rule said when this detection was recorded (the active views show the rule's current values).
        "name_at_detection": row["name"], "severity_at_detection": row["severity"],
    }
    item["active"] = item["rule_state"].startswith("Rule enabled")
    if "now_name" in keys and row["now_name"] is not None:
        item.update(name=row["now_name"], severity=row["now_severity"], category=row["now_category"])
    if include_evidence:
        item["fields"] = json.loads(row["fields_json"])
        item["raw_xml"] = row["raw_xml"]
    return item


ACTIVE_SELECT = "a.*, r.name AS now_name, r.severity AS now_severity, r.category AS now_category"


def list_anomalies(params: dict[str, Any], limit: int = 100, offset: int = 0, now: datetime | None = None,
                   scope: str = "window") -> dict[str, Any]:
    """scope='window' (default): active detections in the last N days - only enabled rules, matching their
    current definition.  scope='all': every stored detection (History), including disabled and deleted rules."""
    start, end = window(now)
    with db.connect() as connection:
        if scope == "all":
            where, values = _filters(params, None, end)
            total = connection.execute(f"SELECT COUNT(*) FROM anomalies WHERE {where}", values).fetchone()[0]
            rows = connection.execute(
                f"SELECT * FROM anomalies WHERE {where} ORDER BY event_time DESC, id DESC LIMIT ? OFFSET ?",
                [*values, limit, offset]).fetchall()
        else:
            cte, cte_values = _active_cte()
            where, values = _filters(params, start, end, alias="a", active=True)
            total = connection.execute(f"WITH {cte} SELECT COUNT(*) FROM anomalies a {ACTIVE_JOIN} WHERE {where}",
                                       [*cte_values, *values]).fetchone()[0]
            # Pick the page from the covering index first (small sort), then read only those rows.
            page = [row[0] for row in connection.execute(
                f"WITH {cte} SELECT a.rowid FROM anomalies a {ACTIVE_JOIN} WHERE {where} "
                f"ORDER BY a.event_time DESC, a.rowid DESC LIMIT ? OFFSET ?", [*cte_values, *values, limit, offset])]
            rows = []
            if page:
                found = {row["rowid_"]: row for row in connection.execute(
                    f"WITH {cte} SELECT a.rowid AS rowid_, {ACTIVE_SELECT} FROM anomalies a {ACTIVE_JOIN} "
                    f"WHERE a.rowid IN ({','.join('?' for _ in page)})", [*cte_values, *page])}
                rows = [found[rowid] for rowid in page if rowid in found]
    return {"items": [_row(row) for row in rows], "total": total, "limit": limit, "offset": offset, "scope": scope,
            "window_start": iso(start), "window_end": iso(end)}


def grouped_anomalies(params: dict[str, Any], limit: int = 100, offset: int = 0, now: datetime | None = None,
                      scope: str = "window") -> dict[str, Any]:
    start, end = window(now)
    if scope == "all":
        cte, cte_values, join = "", [], ""
        where, values = _filters(params, None, end, alias="a")
        meta = "a"
    else:
        cte, cte_values = _active_cte()
        cte, join, meta = f"WITH {cte} ", ACTIVE_JOIN, "r"
        where, values = _filters(params, start, end, alias="a", active=True)
    sql = f"""SELECT a.rule_id, a.hostname, MIN({meta}.name) AS name, MIN({meta}.category) AS category,
                     MIN({meta}.severity) AS severity, MIN({meta}.severity_rank) AS severity_rank,
                     MIN(a.event_id) AS event_id, MIN(a.channel) AS channel,
                     COUNT(*) AS occurrences, MIN(a.event_time) AS first_seen, MAX(a.event_time) AS last_seen,
                     SUM(a.status = 'New') AS new, SUM(a.status = 'Investigating') AS investigating,
                     SUM(a.status = 'Resolved') AS resolved, SUM(a.status = 'False Positive') AS false_positive
              FROM anomalies a {join} WHERE {where} GROUP BY a.rule_id, a.hostname"""
    with db.connect() as connection:
        total = connection.execute(f"{cte}SELECT COUNT(*) FROM ({sql})", [*cte_values, *values]).fetchone()[0]
        rows = connection.execute(f"{cte}{sql} ORDER BY severity_rank, last_seen DESC LIMIT ? OFFSET ?",
                                  [*cte_values, *values, limit, offset]).fetchall()
    return {"items": [dict(row) for row in rows], "total": total, "limit": limit, "offset": offset, "scope": scope,
            "window_start": iso(start), "window_end": iso(end)}


def rule_stats(now: datetime | None = None) -> dict[str, dict[str, Any]]:
    """Per-rule counts: stored detection records (history) and what the active views show now."""
    start, end = window(now)
    catalog = load_catalog()
    enabled_at = [(rule["rule_id"], rule["enabled_at"]) for rule in catalog["rules"] if rule.get("enabled_at")]

    def produce():
        with db.connect() as connection:
            rows = connection.execute(
                """SELECT rule_id, COUNT(*) AS detections, COUNT(DISTINCT event_key) AS occurrences,
                          COUNT(DISTINCT hostname) AS groups, MIN(event_time) AS first_detected,
                          MAX(event_time) AS last_detected, SUM(event_time >= ?) AS window_count,
                          SUM(detection_source <> 'ingest') AS from_rescan,
                          SUM(detection_source = 'reevaluation') AS from_reevaluation, MAX(detected_at) AS last_processed
                   FROM anomalies GROUP BY rule_id""", (iso(start),)).fetchall()
            # What the active views show for each rule right now (enabled + matching the current definition).
            cte, cte_values = _active_cte()
            active = {row["rule_id"]: dict(row) for row in connection.execute(
                f"""WITH {cte} SELECT a.rule_id, COUNT(*) AS n, MIN(a.event_time) AS first_active,
                           MAX(a.event_time) AS last_active
                    FROM anomalies a {ACTIVE_JOIN} WHERE a.event_time >= ? AND a.event_time <= ? GROUP BY a.rule_id""",
                [*cte_values, iso(start), iso(end + FUTURE_TOLERANCE)])}
            since = {}
            if enabled_at:
                values = ",".join("(?, ?)" for _ in enabled_at)
                params = [item for pair in enabled_at for item in pair]
                for row in connection.execute(
                        f"""WITH e(rule_id, enabled_at) AS (VALUES {values})
                            SELECT a.rule_id, COUNT(*) AS n FROM anomalies a JOIN e ON a.rule_id = e.rule_id
                            WHERE a.detected_at >= e.enabled_at GROUP BY a.rule_id""", params):
                    since[row["rule_id"]] = row["n"]
        result = {row["rule_id"]: {**dict(row), "since_enabled": since.get(row["rule_id"])} for row in rows}
        for rule_id, row in active.items():
            result.setdefault(rule_id, {}).update(active_in_window=row["n"], first_active=row["first_active"],
                                                  last_active=row["last_active"])
        return result
    return _cached(f"rule-stats-{iso(start)[:16]}-{data_version()}-{rules_version()}", produce)


def _reliability(rule: dict[str, Any], channel: dict[str, Any] | None, stats: dict[str, Any] | None) -> tuple[str, str]:
    if rule.get("deleted_at"):
        return "deleted", "Deleted (history kept)"
    if not rule["enabled"]:
        return "disabled", "Disabled"
    if channel is None or channel["state"] in ("not_reported", "not_configured"):
        return "unconfirmed", "Enabled - source not confirmed"
    if channel["state"] != "ok":
        return "unavailable", f"Enabled - source unavailable ({channel['state_label']})"
    if stats and stats.get("detections"):
        return "triggered", "Operational - has triggered"
    return "never_triggered", "Operational - never triggered"


def rules_with_status(now: datetime | None = None) -> dict[str, Any]:
    catalog = load_catalog()
    channels = {item["channel"].lower(): item for item in channel_status(now)}
    stats = rule_stats(now)
    overlap: dict[tuple[str, int], list[str]] = {}
    for rule in catalog["rules"]:
        if rule["enabled"]:
            overlap.setdefault((rule["channel"].lower(), rule["event_id"]), []).append(rule["rule_id"])
    items = []
    for rule in [*catalog["rules"], *catalog["deleted_rules"].values()]:
        channel = channels.get(rule["channel"].lower())
        rule_stats_row = stats.get(rule["rule_id"]) or {}
        reliability, label = _reliability(rule, channel, rule_stats_row)
        if not rule["enabled"]:
            monitoring = "Rule disabled"
        elif channel is None:
            monitoring = "Channel not collected"
        else:
            monitoring = "Active" if channel["monitored"] else channel["state_label"]
        others = [rid for rid in overlap.get((rule["channel"].lower(), rule["event_id"]), []) if rid != rule["rule_id"]]
        items.append({
            **{key: value for key, value in rule.items()},
            "monitoring": monitoring,
            "channel_state": channel["state_label"] if channel else "Not collected",
            "reliability": reliability, "reliability_label": label,
            "detections_total": rule_stats_row.get("detections", 0),
            "occurrences_total": rule_stats_row.get("occurrences", 0),
            "groups_total": rule_stats_row.get("groups", 0),
            "detections_in_window": rule_stats_row.get("window_count", 0) or 0,
            "detections_since_enabled": rule_stats_row.get("since_enabled"),
            "detections_from_rescan": rule_stats_row.get("from_rescan", 0) or 0,
            "detections_from_reevaluation": rule_stats_row.get("from_reevaluation", 0) or 0,
            "first_detected": rule_stats_row.get("first_detected"),
            "last_detected": rule_stats_row.get("last_detected"),
            # Shown in the active Anomalies view / timeline right now (0 while the rule is off).
            "active_in_window": rule_stats_row.get("active_in_window", 0) or 0,
            "active_last_detected": rule_stats_row.get("last_active"),
            "hidden_in_window": max(0, (rule_stats_row.get("window_count", 0) or 0)
                                    - (rule_stats_row.get("active_in_window", 0) or 0)),
            "evaluation": evaluation_status(rule["rule_id"]),
            "overlaps_with": others,
        })
    return {"version": catalog["version"], "source": catalog["source"], "errors": catalog["errors"],
            "rules": items, "reviewed_not_included": catalog["reviewed_not_included"],
            "severity_order": catalog["severity_order"], "window_days": catalog["window_days"],
            "overlap_policy": ("Every enabled rule matching an event records its own detection; overlapping rules are "
                               "never discarded. Detections = event x rule records; occurrences = distinct events."),
            "toggle_policy": ("Switching a rule off hides its detections from the active views and counts; nothing is "
                              f"deleted. Switching it on re-evaluates the last {catalog['window_days']} days for that rule "
                              "only: earlier detections reappear and events not yet checked are evaluated, without "
                              "duplicates.")}


def _summary_sql(start: datetime, end: datetime):
    """Active detection aggregates for the summary (cached by the caller; keyed by data and rule versions)."""
    where, values = _filters({}, start, end, alias="a", active=True)
    cte, cte_values = _active_cte()
    with db.connect() as connection:
        by_severity = connection.execute(
            f"""WITH {cte} SELECT r.severity AS severity, COUNT(*) AS records,
                       COUNT(DISTINCT a.rule_id || '|' || a.hostname) AS groups
                FROM anomalies a {ACTIVE_JOIN} WHERE {where} GROUP BY r.severity""", [*cte_values, *values]).fetchall()
        totals = connection.execute(
            f"""WITH {cte} SELECT COUNT(*) AS records, COUNT(DISTINCT a.rule_id || '|' || a.hostname) AS groups,
                       COUNT(DISTINCT a.event_key) AS occurrences,
                       COUNT(DISTINCT a.event_id) AS event_ids, COUNT(DISTINCT a.hostname) AS hosts,
                       SUM(a.status = 'New') AS new, SUM(a.event_time_source = 'received') AS time_from_receipt,
                       SUM(a.provider_match = 0) AS provider_mismatch
                FROM anomalies a {ACTIVE_JOIN} WHERE {where}""", [*cte_values, *values]).fetchone()
        stored_where, stored_values = _filters({}, start, end)
        stored_in_window = connection.execute(f"SELECT COUNT(*) FROM anomalies WHERE {stored_where}",
                                              stored_values).fetchone()[0]
        older = connection.execute("SELECT COUNT(*) FROM anomalies WHERE event_time < ?", (iso(start),)).fetchone()[0]
        last_detection = connection.execute("SELECT MAX(detected_at) FROM anomalies").fetchone()[0]
        hosts = [row[0] for row in connection.execute("SELECT DISTINCT hostname FROM anomalies ORDER BY hostname")]
    categories = sorted({rule["category"] for rule in active_rules()})
    totals = dict(totals)
    totals["hidden_in_window"] = max(0, stored_in_window - (totals["records"] or 0))
    return ([dict(row) for row in by_severity], totals, older, last_detection, hosts, categories)


def summary(now: datetime | None = None) -> dict[str, Any]:
    catalog = load_catalog()
    start, end = window(now)
    by_severity, totals, older, last_detection, hosts, categories = _cached(
        f"summary-sql-{iso(start)[:16]}-{data_version()}-{rules_version()}", lambda: _summary_sql(start, end))
    counts = {severity: {"records": 0, "groups": 0} for severity in catalog["severity_order"]}
    for row in by_severity:
        counts[row["severity"]] = {"records": row["records"], "groups": row["groups"]}
    channels = channel_status(now)
    coverage = coverage_overview(now, channels)
    rules = rules_with_status(now)["rules"]
    live_rules = [rule for rule in rules if rule["reliability"] != "deleted"]
    enabled = [rule for rule in live_rules if rule["enabled"]]
    triggered = [rule for rule in live_rules if rule["detections_total"]]
    # Dashboard widgets use the active counts, so they agree with the list, the severity cards and the timeline.
    top = sorted((rule for rule in enabled if rule["active_in_window"]),
                 key=lambda rule: (-rule["active_in_window"], severity_rank(rule["severity"])))[:8]
    recent = sorted((rule for rule in enabled if rule["active_last_detected"]),
                    key=lambda rule: rule["active_last_detected"], reverse=True)[:8]
    brief = lambda rule: {key: rule[key] for key in ("rule_id", "name", "event_id", "severity", "enabled",  # noqa: E731
                                                       "detections_in_window", "detections_total", "last_detected",
                                                       "first_detected", "reliability_label", "active_in_window",
                                                       "active_last_detected")}
    store = state_store()
    return {
        "generated_at": iso(utc_now()),
        "window": {
            "days": catalog["window_days"], "start": iso(start), "end": iso(end),
            "convention": (f"Rolling {catalog['window_days']} days ending now; start and end inclusive; UTC; "
                           "compared on each event's own time (receive time only when the event has none)."),
        },
        "counts_by_severity": counts,
        "totals": {key: (totals[key] or 0) for key in totals.keys()},
        "older_detections_retained": older,
        "coverage": coverage,
        "channels": channels,
        "rules_overview": {
            "enabled": len(enabled), "disabled": len(live_rules) - len(enabled),
            "custom": sum(rule["origin_kind"] == "custom" for rule in live_rules),
            "triggered": len(triggered),
            "never_triggered": sum(1 for rule in enabled if not rule["detections_total"]),
            "disabled_with_hidden_detections": sum(1 for rule in live_rules if not rule["enabled"] and rule["hidden_in_window"]),
            "evaluations_running": [job for job in evaluations() if job["state"] == "running"],
            "enabled_source_unavailable": sum(rule["reliability"] == "unavailable" for rule in enabled),
            "enabled_source_unconfirmed": sum(rule["reliability"] == "unconfirmed" for rule in enabled),
            "top": [brief(rule) for rule in top], "recent": [brief(rule) for rule in recent],
        },
        "last_detection_at": last_detection,
        "catalog": {
            "version": catalog["version"], "source": catalog["source"], "rules": len(live_rules),
            "enabled_rules": len(enabled), "errors": catalog["errors"], "loaded_at": catalog["loaded_at"],
        },
        "persistence": {"persistent": store.persistent, "path": str(store.path) if store.path else None,
                        "error": store.error, "storage": "disk" if db.database_path() else "memory",
                        "database": str(db.database_path()) if db.database_path() else None},
        "filters": {"hosts": hosts, "categories": categories, "statuses": list(STATUSES),
                    "severities": catalog["severity_order"]},
        "last_scan": last_scan(),
    }


def get_anomaly(detection_id: str) -> dict[str, Any] | None:
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM anomalies WHERE id = ?", (detection_id,)).fetchone()
    if row is None:
        return None
    item = _row(row, include_evidence=True)
    catalog = load_catalog()
    rule = find_rule(row["rule_id"])
    item["rule"] = dict(rule) if rule else None
    item["rule_current_catalog_version"] = catalog["version"]
    item["channel_status"] = next((entry for entry in channel_status() if entry["channel"].lower() == row["channel"].lower()), None)
    item["status_history"] = state_store().history(detection_id)
    explanation = [
        f"Flagged because Event ID {row['event_id']} on the {row['channel']} channel matches "
        f"{'user-defined' if item['rule_origin'] == 'custom' else 'catalog'} rule {row['rule_id']} ('{row['name']}'). "
        "No other field, threshold or related event was required.",
        "A flag means the configured Event ID occurred; it is not proof of malicious activity, and the activity may be legitimate.",
    ]
    if item["detection_source"] == "rescan":
        explanation.append("This detection was created by a historical rescan requested by a user, not at collection time.")
    elif item["detection_source"] == "reevaluation":
        explanation.append("This detection was created by the 7-day re-evaluation that runs when the rule is switched on, "
                           "created or edited - the event was collected while the rule was off or did not exist yet.")
    if not item["active"]:
        explanation.append(f"{item['rule_state']}: this stored detection is kept for history and auditing but is not "
                           "counted in the active Anomalies view, the dashboard or the timeline.")
    if row["event_time_source"] == "received":
        explanation.append("This event had no usable timestamp, so its receive time was used to place it in the window.")
    if row["provider_match"] == 0:
        explanation.append(
            f"The event's provider ({row['provider']}) differs from the provider this rule expects "
            f"({row['expected_provider']}). The ID still matched and was flagged; verify the event's meaning before acting.")
    if rule and rule.get("action"):
        explanation.append(f"Recommended action (guidance only, never executed): {rule['action']}")
    item["explanation"] = explanation
    return item


def set_status(detection_id: str, status: str, note: str | None) -> dict[str, Any] | None:
    if status not in STATUSES:
        raise ValueError(f"Status must be one of: {', '.join(STATUSES)}")
    with db.connect() as connection:
        row = connection.execute("SELECT id, rule_id, event_id, hostname FROM anomalies WHERE id = ?", (detection_id,)).fetchone()
    if row is None:
        return None
    updated_at = state_store().set(detection_id, status, note, row["rule_id"], row["event_id"], row["hostname"])
    with db.connect() as connection:
        connection.execute("UPDATE anomalies SET status = ?, status_note = ?, status_updated_at = ? WHERE id = ?",
                           (status, note, updated_at, detection_id))
    invalidate_cache()
    return get_anomaly(detection_id)


# --------------------------------------------------------------------------- rule management
class RuleError(ValueError):
    def __init__(self, errors: dict[str, str], status: int = 422, extra: dict[str, Any] | None = None):
        super().__init__("; ".join(f"{key}: {value}" for key, value in errors.items()))
        self.errors, self.status, self.extra = errors, status, extra or {}


def _text(payload, key, errors, *, required, maximum, minimum=1):
    value = payload.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            errors[key] = "Required."
        return None
    if not isinstance(value, str):
        errors[key] = "Must be text."
        return None
    value = value.strip()
    if len(value) < minimum:
        errors[key] = f"At least {minimum} characters."
    elif len(value) > maximum:
        errors[key] = f"At most {maximum} characters."
    return value


def validate_custom_rule(payload: dict[str, Any], *, existing_id: str | None = None) -> dict[str, Any]:
    errors: dict[str, str] = {}
    definition: dict[str, Any] = {}
    definition["name"] = _text(payload, "name", errors, required=True, maximum=120, minimum=3)
    raw_id = payload.get("event_id")
    try:
        if isinstance(raw_id, bool) or raw_id is None or str(raw_id).strip() == "":
            raise ValueError
        event_id = int(str(raw_id).strip())
        if str(event_id) != str(raw_id).strip() or not 0 <= event_id <= 65535:
            raise ValueError
        definition["event_id"] = event_id
    except (TypeError, ValueError):
        errors["event_id"] = "Event ID must be a whole number between 0 and 65535."
    definition["category"] = _text(payload, "category", errors, required=True, maximum=60, minimum=2)
    severity = payload.get("severity")
    if severity not in CUSTOM_SEVERITIES:
        errors["severity"] = f"Choose one of: {', '.join(CUSTOM_SEVERITIES)}."
    definition["severity"] = severity
    provider = _text(payload, "provider", errors, required=True, maximum=255)
    if provider and not PROVIDER_NAME.match(provider):
        errors["provider"] = "Letters, digits, spaces and . _ - / ( ) only."
    definition["expected_provider"] = provider
    channel = _text(payload, "channel", errors, required=True, maximum=255)
    if channel and not CHANNEL_NAME.match(channel):
        errors["channel"] = "Use the exact log name, e.g. System or Microsoft-Windows-Sysmon/Operational."
    definition["channel"] = channel
    definition["description"] = _text(payload, "description", errors, required=True, maximum=2000, minimum=5)
    definition["relevance"] = _text(payload, "relevance", errors, required=True, maximum=2000, minimum=5)
    definition["action"] = _text(payload, "action", errors, required=True, maximum=2000, minimum=5)
    if not isinstance(payload.get("enabled"), bool):
        errors["enabled"] = "Choose enabled or disabled."
    match = payload.get("provider_match") or "any"
    if match not in ("any", "exact"):
        errors["provider_match"] = "Use 'any' or 'exact'."
    definition["provider_match"] = match
    tags = payload.get("tags") or []
    if isinstance(tags, str):
        tags = [item.strip() for item in tags.split(",") if item.strip()]
    if not isinstance(tags, list) or len(tags) > 20 or any(not isinstance(t, str) or len(t) > 40 for t in tags):
        errors["tags"] = "Up to 20 tags, 40 characters each."
    definition["tags"] = tags if isinstance(tags, list) else []
    definition["author"] = _text(payload, "author", errors, required=False, maximum=100)
    definition["notes"] = _text(payload, "notes", errors, required=False, maximum=2000)
    mitre = payload.get("mitre") or []
    if isinstance(mitre, str):
        mitre = [item.strip().upper() for item in mitre.split(",") if item.strip()]
    if not isinstance(mitre, list) or any(not isinstance(m, str) or not MITRE.match(m) for m in mitre):
        errors["mitre"] = "ATT&CK technique IDs like T1543 or T1543.003, comma-separated."
    definition["mitre"] = mitre if isinstance(mitre, list) else []
    url = _text(payload, "source_url", errors, required=False, maximum=500)
    if url and not re.match(r"^https?://[^\s<>\"']+$", url):
        errors["source_url"] = "Must be an http(s) URL."
    definition["source_url"] = url
    definition["display_label"] = _text(payload, "display_label", errors, required=False, maximum=120)
    fields = payload.get("display_fields") or []
    if isinstance(fields, str):
        fields = [item.strip() for item in fields.split(",") if item.strip()]
    if not isinstance(fields, list) or len(fields) > 30 or any(not isinstance(f, str) or not FIELD_NAME.match(f) for f in fields):
        errors["display_fields"] = "Up to 30 event field names (letters, digits, space, _ . -)."
    definition["details"] = fields if isinstance(fields, list) else []
    if existing_id is None:
        rule_id = payload.get("rule_id")
        if rule_id not in (None, ""):
            if not isinstance(rule_id, str) or not RULE_ID.match(rule_id):
                errors["rule_id"] = "3-64 characters: letters, digits, _ . - (starting with a letter or digit)."
            elif find_rule(rule_id) is not None or state_store().custom_rule(rule_id) is not None:
                errors["rule_id"] = f"Rule ID {rule_id} already exists (including deleted rules); choose another."
        definition["rule_id"] = rule_id or None
    if errors:
        raise RuleError(errors)
    definition["category"] = definition["category"]
    return definition


def _overlaps(channel: str, event_id: int, ignore: str | None = None) -> list[dict[str, Any]]:
    return [{"rule_id": rule["rule_id"], "name": rule["name"], "severity": rule["severity"], "origin": rule["origin_kind"],
             "enabled": rule["enabled"]}
            for rule in load_catalog()["rules"]
            if rule["channel"].lower() == channel.lower() and rule["event_id"] == event_id and rule["rule_id"] != ignore]


def _new_rule_id(channel: str, event_id: int) -> str:
    prefix = "CUSTOM-" + (re.sub(r"[^A-Za-z0-9]+", "", channel.split("/")[0].replace("Microsoft-Windows-", ""))[:12] or "LOG")
    base = f"{prefix}-{event_id}"
    candidate, n = base, 2
    while find_rule(candidate) is not None or state_store().custom_rule(candidate) is not None:
        candidate, n = f"{base}-{n}", n + 1
    return candidate


def create_custom_rule(payload: dict[str, Any]) -> dict[str, Any]:
    definition = validate_custom_rule(payload)
    overlaps = _overlaps(definition["channel"], definition["event_id"])
    if overlaps and not payload.get("allow_overlap"):
        raise RuleError({"event_id": "Another rule already targets this channel and Event ID. Confirm the overlap to "
                                     "create both; each will record its own detection."}, status=409,
                        extra={"overlaps": overlaps})
    rule_id = definition.pop("rule_id") or _new_rule_id(definition["channel"], definition["event_id"])
    with _RULE_CHANGE_LOCK:
        try:
            state_store().create_custom(rule_id, definition, payload["enabled"])
        except KeyError:
            raise RuleError({"rule_id": f"Rule ID {rule_id} already exists."}, status=409)
        load_catalog(force=True)
    evaluation = evaluate_rule_history(rule_id, "created") if payload["enabled"] else None
    return dict(rule_detail(rule_id), evaluation=evaluation)


def update_custom_rule(rule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    rule = find_rule(rule_id)
    if rule is None or rule.get("deleted_at"):
        raise RuleError({"rule_id": "Rule not found."}, status=404)
    if rule["origin_kind"] != "custom":
        raise RuleError({"rule_id": "Built-in rules cannot be edited; you can switch them on or off, or create a custom "
                                    "rule for the same Event ID."}, status=403)
    payload = dict(payload, enabled=rule["enabled"])
    definition = validate_custom_rule(payload, existing_id=rule_id)
    overlaps = _overlaps(definition["channel"], definition["event_id"], ignore=rule_id)
    changed_target = (definition["channel"].lower(), definition["event_id"]) != (rule["channel"].lower(), rule["event_id"])
    if overlaps and changed_target and not payload.get("allow_overlap"):
        raise RuleError({"event_id": "Another rule already targets this channel and Event ID. Confirm the overlap."},
                        status=409, extra={"overlaps": overlaps})
    definition.pop("rule_id", None)
    with _RULE_CHANGE_LOCK:
        try:
            state_store().update_custom(rule_id, definition)
        except KeyError:
            raise RuleError({"rule_id": "Rule not found."}, status=404)
        load_catalog(force=True)
    # Earlier detections keep their rule id and stored values; those that no longer match the edited definition
    # stay in History ("rule changed since detection") and leave the active views.  An enabled rule is
    # re-evaluated so events matching the new definition in the window are flagged.
    evaluation = evaluate_rule_history(rule_id, "edited") if rule["enabled"] else None
    return dict(rule_detail(rule_id), evaluation=evaluation)


def set_rule_enabled(rule_id: str, enabled: bool) -> dict[str, Any]:
    rule = find_rule(rule_id)
    if rule is None or rule.get("deleted_at"):
        raise RuleError({"rule_id": "Rule not found."}, status=404)
    store = state_store()
    with _RULE_CHANGE_LOCK:
        before = _rule_window_counts(rule_id)
        if rule["origin_kind"] == "custom":
            store.set_custom_enabled(rule_id, enabled)
        else:
            store.set_builtin_enabled(rule_id, enabled)
        load_catalog(force=True)
    if enabled:
        # Targeted, rule-only re-evaluation of the window (earlier detections reappear; missed events are checked).
        evaluation = evaluate_rule_history(rule_id, "enabled")
        hidden = 0
    else:
        evaluation = None
        hidden = before["active_in_window"]
    return dict(rule_detail(rule_id), evaluation=evaluation, hidden_now=hidden)


def delete_custom_rule(rule_id: str) -> dict[str, Any]:
    rule = find_rule(rule_id)
    if rule is None or rule.get("deleted_at"):
        raise RuleError({"rule_id": "Rule not found."}, status=404)
    if rule["origin_kind"] != "custom":
        raise RuleError({"rule_id": "Built-in rules cannot be deleted. Switch the rule off instead."}, status=403)
    with _RULE_CHANGE_LOCK:
        state_store().delete_custom(rule_id)
        load_catalog(force=True)
    return rule_detail(rule_id)


def rule_detail(rule_id: str) -> dict[str, Any]:
    for item in rules_with_status()["rules"]:
        if item["rule_id"] == rule_id:
            item = dict(item)
            item["changes"] = state_store().rule_changes(rule_id)
            item["overlaps"] = _overlaps(item["channel"], item["event_id"], ignore=rule_id)
            return item
    raise RuleError({"rule_id": "Rule not found."}, status=404)
